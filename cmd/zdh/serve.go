package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"

	"zerodeps/zdh/internal/certgen"
	"zerodeps/zdh/internal/exchange"
	"zerodeps/zdh/internal/flow"
	"zerodeps/zdh/internal/hpack"
	"zerodeps/zdh/internal/response"
	"zerodeps/zdh/internal/server"
	"zerodeps/zdh/internal/static"
	"zerodeps/zdh/internal/stream"
)

// This file is where the eleven packages under internal/ become one program,
// and it is deliberately the only place in the module that knows the shape of
// the whole. Every package below declares the interfaces it needs rather than
// importing the package that satisfies them, which is what keeps the dependency
// arrows pointing one way — and it means somebody has to hold the pieces at
// once and connect them. That somebody is a command, not a library.

// streamHandler is the connection's stream half as internal/server needs it.
//
// The stream table is almost the whole of it, and is embedded rather than
// wrapped so that the eight methods that are its own stay its own. What the
// table does not do is end the request layer, and that is not an omission: a
// handler can be parked on either of two things — an upload it is reading, or
// the send credit to answer with — and those two waits live in two packages
// that do not know about each other. Whoever built the connection is the only
// party holding both, so ending both is this type's one job.
type streamHandler struct {
	*stream.Table
	reqs *exchange.Requests
}

// The interface this file exists to satisfy, checked at compile time rather
// than at the first connection.
var _ server.StreamHandler = streamHandler{}

// Close ends both halves of one connection's teardown.
//
// The table first, so that no handler can park for send credit after this
// returns: flow control's reason is sticky, so a handler woken from a body wait
// by the second call finds the credit already refused rather than parking for
// it. The reverse order also terminates — Sender.Close wakes whoever parked in
// the gap — but it leaves a window in which a goroutine blocks on a connection
// that is over, and a window nobody needs is a window not worth having.
func (h streamHandler) Close(err error) {
	h.Table.Close(err)
	h.reqs.Close(err)
}

// newConn returns the per-connection factory internal/server is built with: one
// call per accepted connection, given that connection's write half.
//
// Everything it builds is one connection's and must not be shared with another.
// The two HPACK codecs are the sharpest case, and the reason there are two: the
// dynamic table is a history of what was sent on this connection in one
// direction, so the codec decoding the peer's requests and the codec encoding
// our responses hold different tables with different contents at every index.
// One codec driven by both directions would answer each one's index lookups
// with the other's entries, and the symptom would be header fields nobody sent
// — on the tenth request of a long connection, not the first.
//
// The order is fixed by what needs what. The Sender is made before the request
// layer because that is what a response reserves credit through; the request
// layer before the table because the table delivers to it; and the table's
// identifier back into the request layer afterwards, with Attach, because a
// finished response has to report the stream it finished. That last edge is
// what makes this a cycle rather than a chain, and Attach is where it closes.
//
// Priorities is the only optional field among any of these, and it is filled in
// because a server that reads the Priority header field and then drops it is one
// whose scheduler hears half of what its clients say — the frame but not the
// request. exchange.Config carries the argument for why nil is allowed at all;
// nothing about this process wants it, so there is a test in this package that
// the value is really passed.
func newConn(h exchange.Handler, errLog *log.Logger) func(server.ConnWriter) server.StreamHandler {
	return func(w server.ConnWriter) server.StreamHandler {
		enc := response.NewEncoder(hpack.New(), w)
		sender := flow.NewSender()

		reqs := exchange.New(exchange.Config{
			Handler:    h,
			Encoder:    enc,
			Credit:     sender,
			Priorities: w,
			Log:        errLog,
		})

		// MaxConcurrent is left at its default on purpose. §5.1.2 lets a peer
		// open exactly as many streams as it was promised, so the number the
		// table enforces has to be the number the connection advertised — and
		// both default to limits.MaxConcurrentStreams, so naming it here would
		// add a third place for the same value to be wrong in.
		tab := stream.New(stream.Config{
			Codec:    hpack.New(),
			Requests: reqs,
			Encoder:  enc,
			Sender:   sender,
			Writer:   w,
		})
		reqs.Attach(tab)

		return streamHandler{Table: tab, reqs: reqs}
	}
}

// binding is one listening socket and what a reader needs to know about it.
type binding struct {
	l net.Listener

	// tlsCfg is nil for a cleartext listener, which serves h2c by prior
	// knowledge (§3.3): the peer sends the connection preface immediately and
	// there is no upgrade to negotiate.
	tlsCfg *tls.Config

	url  string // what to type into a browser or a curl command
	note string // what that URL speaks, for the startup lines
}

// serve runs the server until ctx is done or an accept loop fails.
//
// The context is the interrupt, and it arrives as an argument rather than being
// installed here: what a process does about a signal is the process's business,
// and a function that reached for signal.NotifyContext itself could only be
// tested by sending a signal to the test binary.
func serve(ctx context.Context, o *options, out io.Writer) error {
	h, err := static.New(static.Config{Dir: o.dir})
	if err != nil {
		return err
	}
	// The handler outlives every connection, so this is the process ending and
	// not a request. Responses in flight hold their own file handles.
	defer h.Close()

	// Two logs, one destination, and the prefixes are how a judge tells them
	// apart in a terminal: a connection that ended badly is the server's, and a
	// handler that panicked is a bug in this program.
	connLog := log.New(os.Stderr, "zdh conn: ", log.LstdFlags)
	handlerLog := log.New(os.Stderr, "zdh handler: ", log.LstdFlags)

	var tlsCfg *tls.Config
	if o.tlsAddr != "" {
		cert, how, err := certgen.LoadOrCreate(o.certPath, o.keyPath,
			certgen.Config{Hosts: certHosts(o.tlsAddr, o.hosts)})
		if err != nil {
			return err
		}
		tlsCfg = server.TLSConfig(cert)
		fmt.Fprintf(out, "certificate  %s\n", how)
	}

	// Every socket is bound before anything is served, so a port already in use
	// is a non-zero exit and not a server that half works: a process listening
	// on one of two ports, having printed both, is worse than one that did not
	// start.
	bs, err := bind(o, tlsCfg)
	if err != nil {
		return err
	}

	srv := server.New(newConn(h, handlerLog), server.Config{
		MaxConns: o.maxConns,
		ErrorLog: connLog,
	})

	fmt.Fprintf(out, "serving      %s\n", h.Dir())
	for _, b := range bs {
		fmt.Fprintf(out, "listening    %s  (%s)\n", b.url, b.note)
	}

	// Buffered to the number of listeners, so a goroutine reporting a failure
	// nobody is left to read never blocks and never leaks.
	errs := make(chan error, len(bs))
	var wg sync.WaitGroup
	for _, b := range bs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var err error
			if b.tlsCfg != nil {
				err = srv.ServeTLS(b.l, b.tlsCfg)
			} else {
				err = srv.Serve(b.l)
			}
			if err != nil && !errors.Is(err, server.ErrServerClosed) {
				errs <- err
			}
		}()
	}

	var serveErr error
	select {
	case serveErr = <-errs:
	case <-ctx.Done():
		fmt.Fprintln(out, "shutting down: GOAWAY sent; a second interrupt exits at once")
	}

	// Unconditional, and that is the point of doing it here rather than in the
	// interrupt arm: one accept loop failing leaves the other listener and every
	// live connection running, and this is a program that stops when it stops
	// working.
	shutErr := srv.Shutdown()
	wg.Wait()
	close(errs)

	// An accept loop that failed is the fault; anything after it is a
	// consequence. So the first error wins whichever channel it arrived on.
	if serveErr != nil {
		return serveErr
	}
	for err := range errs {
		return err
	}

	// A grace period that ran out is not a failure of this program: an operator
	// asked it to stop, and it stopped. It is worth a line, because the streams
	// that were still running were cut off and their peers will say so.
	if errors.Is(shutErr, server.ErrShutdownGraceExpired) {
		fmt.Fprintln(out, "shutdown: the grace period expired; the remaining connections were closed")
		return nil
	}
	return shutErr
}

// bind opens the listeners o asks for. On the first failure every socket
// already opened is closed again, so a half-bound server is never returned.
func bind(o *options, tlsCfg *tls.Config) ([]binding, error) {
	var bs []binding

	fail := func(err error) ([]binding, error) {
		for _, b := range bs {
			b.l.Close()
		}
		return nil, err
	}

	if o.tlsAddr != "" {
		l, err := net.Listen("tcp", o.tlsAddr)
		if err != nil {
			return fail(err)
		}
		bs = append(bs, binding{
			l:      l,
			tlsCfg: tlsCfg,
			url:    "https://" + browserHost(l.Addr()) + "/",
			note:   `h2 over TLS, ALPN "` + server.ALPNProtocol + `"`,
		})
	}

	if o.h2cAddr != "" {
		l, err := net.Listen("tcp", o.h2cAddr)
		if err != nil {
			return fail(err)
		}
		bs = append(bs, binding{
			l:    l,
			url:  "http://" + browserHost(l.Addr()) + "/",
			note: "h2c by prior knowledge — curl needs --http2-prior-knowledge",
		})
	}

	return bs, nil
}

// browserHost is a listening address as the authority of a URL somebody can
// type. A wildcard address becomes "localhost", because "[::]:8443" is not a
// URL and localhost is where a demonstration is actually reached.
func browserHost(a net.Addr) string {
	host, port, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	if wildcard(host) {
		host = "localhost"
	}
	return net.JoinHostPort(host, port)
}

// certHosts is the SAN list for a generated certificate: the three names a
// local demonstration is reached at, the address it was told to listen on if
// that names a host, and whatever -host added.
//
// The three defaults are not interchangeable. A client checks the DNS list or
// the IP list and never both, so a certificate carrying only "localhost" fails
// for https://127.0.0.1 with a message about names — and "127.0.0.1" and "::1"
// are two addresses, because a machine with IPv6 resolves localhost to the
// second one and a certificate for the first is a handshake error that looks
// like a server bug.
func certHosts(addr, extra string) []string {
	hosts := []string{"localhost", "127.0.0.1", "::1"}

	if host, _, err := net.SplitHostPort(addr); err == nil && !wildcard(host) {
		hosts = append(hosts, host)
	}
	for _, h := range strings.Split(extra, ",") {
		if h = strings.TrimSpace(h); h != "" {
			hosts = append(hosts, h)
		}
	}

	// Deduplicated because a repeated SAN is a certificate that says the same
	// thing twice, and -host localhost is the obvious thing to type.
	out := make([]string, 0, len(hosts))
	seen := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		if !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	return out
}

// wildcard reports whether host is an every-interface address rather than a
// name. The empty string is the host of ":8443", which is the default.
func wildcard(host string) bool {
	return host == "" || host == "0.0.0.0" || host == "::"
}
