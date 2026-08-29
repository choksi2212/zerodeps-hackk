package server

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"zerodeps/zdh/internal/frame"
	"zerodeps/zdh/internal/h2"
	"zerodeps/zdh/internal/limits"
)

// settleWait is how long a negative assertion waits before believing itself.
//
// "The server did not accept a third connection" cannot be proved by looking once,
// and the wait is the honest version of the claim. It is only ever a source of false
// passes, never false failures, which is why every negative assertion here is paired
// with a positive one — the bound is shown to hold, and then shown to lift.
const settleWait = 150 * time.Millisecond

// backoffWait is long enough for the accept backoff to climb to its ceiling. The
// pauses before the last one total minAcceptDelay*(2^8-1), a little over a second,
// and a loaded machine adds to that.
const backoffWait = 8 * time.Second

// serverTimeouts is testTimeouts with every per-connection deadline out of reach.
//
// The accept layer's tests are about connections that stay alive until the test ends
// them for a reason it chose. A deadline that fired on its own would end them for a
// different reason and most assertions would still pass — having tested the timeout
// instead of the shutdown.
//
// ShutdownGrace is the exception and is left generous rather than long: it is the one
// deadline these tests wait on, and the two that want it to expire shorten it
// themselves.
func serverTimeouts() limits.Timeouts {
	to := testTimeouts()
	to.Preface = longTimeout
	to.Idle = longTimeout
	to.Write = longTimeout
	to.SettingsAck = longTimeout
	to.ShutdownGrace = 500 * time.Millisecond
	return to
}

// --- a listener under the test's control --------------------------------------

// testAddr is a listener address for an error message.
type testAddr string

func (a testAddr) Network() string { return "test" }
func (a testAddr) String() string  { return string(a) }

// testListener is a net.Listener whose every Accept is scripted.
//
// The accept layer's interesting behaviour is almost all about what Accept does
// wrong — failing transiently, failing for good, being closed behind the server's
// back — and none of that is arrangeable through a real listener. Descriptor
// exhaustion in particular cannot be provoked in a test that other tests share a
// process with.
//
// Connections come from net.Pipe rather than a loopback socket because a pipe end
// supports deadlines and is a socket the test wholly owns: no port, no backlog, and
// no kernel buffer to make a stalled peer look like a working one.
type testListener struct {
	addr net.Addr

	// noDrain hands out connections whose peer never reads. See stalled.
	noDrain bool

	// closeErr is what Close reports on its first call. See unclosable.
	closeErr error

	mu     sync.Mutex
	steps  []error
	calls  int
	peers  []*peerConn
	closes int
	closed bool

	// closedc releases an Accept that has run out of script, which is what a real
	// listener with no client waiting does.
	closedc   chan struct{}
	closeOnce sync.Once
}

// newTestListener returns a listener whose nth Accept fails with steps[n] or, where
// that is nil, hands out a connection. Past the end of the script Accept blocks
// until the listener is closed.
func newTestListener(steps ...error) *testListener {
	return &testListener{
		addr:    testAddr("127.0.0.1:0/test"),
		steps:   steps,
		closedc: make(chan struct{}),
	}
}

// stalled makes every connection this listener hands out go to a peer that never
// reads.
//
// It is the worst case for the write half, and it is not exotic: net.Pipe is
// unbuffered, so the connection's writer goroutine blocks on the very first frame of
// the server preface and stays there. A real peer arranges the same thing by
// connecting, letting the kernel buffers fill, and never calling read.
func (l *testListener) stalled() *testListener {
	l.noDrain = true
	return l
}

// unclosable makes the listener's Close fail, which a listener's Close can: it is a
// syscall on a descriptor, and on an unlinked Unix socket or a device that has gone
// away it returns an error like anything else.
func (l *testListener) unclosable(err error) *testListener {
	l.closeErr = err
	return l
}

func (l *testListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, net.ErrClosed
	}
	l.calls++
	i := l.calls - 1
	var step error
	scripted := i < len(l.steps)
	if scripted {
		step = l.steps[i]
	}
	l.mu.Unlock()

	switch {
	case !scripted:
		<-l.closedc
		return nil, net.ErrClosed
	case step != nil:
		return nil, step
	}

	sock, client := net.Pipe()
	p := newPeerConn(client, !l.noDrain)
	l.mu.Lock()
	l.peers = append(l.peers, p)
	l.mu.Unlock()
	return sock, nil
}

// Close reports an error on every call after the first, which is what a real
// listener does and what onceListener exists to keep out of the log.
func (l *testListener) Close() error {
	l.mu.Lock()
	l.closes++
	n := l.closes
	l.closed = true
	l.mu.Unlock()

	l.closeOnce.Do(func() { close(l.closedc) })
	if n > 1 {
		return fmt.Errorf("testListener: close number %d: %w", n, net.ErrClosed)
	}
	return l.closeErr
}

func (l *testListener) Addr() net.Addr { return l.addr }

func (l *testListener) acceptCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls
}

func (l *testListener) closeCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closes
}

func (l *testListener) peerCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.peers)
}

// peer is the client end of the nth connection this listener handed out.
func (l *testListener) peer(t *testing.T, n int) *peerConn {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	if n >= len(l.peers) {
		t.Fatalf("the test asked for connection %d but the listener has handed out %d", n, len(l.peers))
	}
	return l.peers[n]
}

// --- the peer at the other end ------------------------------------------------

// peerConn is the client end of one connection, with a goroutine reading it.
//
// The reading matters. net.Pipe is unbuffered, so a write blocks until the other end
// reads: a peer that is not reading is a peer that stalls the connection's writer
// goroutine until its write deadline expires, which would turn every test here into
// a test of that deadline. A real peer's kernel buffers hide this, and hiding it is
// exactly what the stalled variant declines to do.
type peerConn struct {
	net.Conn

	mu   sync.Mutex
	read []byte

	// done closes when this end sees the connection go, which is the moment
	// everything the server sent has arrived.
	done chan struct{}
}

func newPeerConn(c net.Conn, drain bool) *peerConn {
	p := &peerConn{Conn: c, done: make(chan struct{})}
	if !drain {
		return p
	}
	go func() {
		defer close(p.done)
		buf := make([]byte, 4096)
		for {
			n, err := c.Read(buf)
			if n > 0 {
				p.mu.Lock()
				p.read = append(p.read, buf[:n]...)
				p.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	return p
}

// send writes octets to the server, under a deadline so that a server which has
// stopped reading fails the test by name instead of hanging the suite.
func (p *peerConn) send(t *testing.T, b []byte) {
	t.Helper()
	if err := p.SetWriteDeadline(time.Now().Add(gateWait)); err != nil {
		t.Fatalf("setting the peer's write deadline: %v", err)
	}
	if _, err := p.Write(b); err != nil {
		t.Fatalf("sending %d octets to the server: %v", len(b), err)
	}
}

func (p *peerConn) octets() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]byte(nil), p.read...)
}

// frames decodes what this peer has received, ignoring a trailing partial frame.
//
// Tolerating the partial frame is what makes polling possible: octets arrive in
// whatever sizes the transport chose, so a decode that failed on a half-arrived
// frame would fail at random. A frame that never completes shows up as a poll that
// times out, which is the failure worth reporting.
//
// That tolerance is also why this is not framesWritten. There the octets are all
// there by the time anything looks, so a short read is a writer that truncated a
// frame and must fail the test; here it is the ordinary state of a socket being read
// while it is still being written.
func (p *peerConn) frames(t *testing.T) []frame.Frame {
	t.Helper()
	r := frame.NewReader(bytes.NewReader(p.octets()), frame.ReaderConfig{})
	var got []frame.Frame
	for {
		f, err := r.ReadFrame()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return got
			}
			t.Fatalf("decoding what the server sent: %v (after %d frames)", err, len(got))
		}
		got = append(got, f)
	}
}

// --- a log the test can read --------------------------------------------------

// logRecorder is an io.Writer behind a log.Logger, locked because the lines are
// written from connection goroutines and read from the test's own.
type logRecorder struct {
	mu sync.Mutex
	b  []byte
}

func (r *logRecorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	r.b = append(r.b, p...)
	r.mu.Unlock()
	return len(p), nil
}

func (r *logRecorder) text() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return string(r.b)
}

// --- running a server ---------------------------------------------------------

// testServer returns a server logging into a recorder. A nil factory gets
// rejectingHandler, which fails the test if any frame reaches the stream layer.
func testServer(t *testing.T, cfg Config, newHandler func(ConnWriter) StreamHandler) (*Server, *logRecorder) {
	t.Helper()
	rec := &logRecorder{}
	cfg.ErrorLog = log.New(rec, "", 0)
	if newHandler == nil {
		newHandler = func(ConnWriter) StreamHandler { return rejectingHandler(t) }
	}
	return New(newHandler, cfg), rec
}

// serverInBackground starts Serve and returns the channel its result arrives on.
func serverInBackground(s *Server, l net.Listener) chan error {
	done := make(chan error, 1)
	go func() { done <- s.Serve(l) }()
	return done
}

func assertServerClosed(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrServerClosed) {
		t.Errorf("Serve returned %v, want ErrServerClosed: a caller waiting on Serve has no other way "+
			"to tell a requested stop from a listener that broke", err)
	}
}

// awaitAccepts waits until Accept has been called at least n times.
func awaitAccepts(t *testing.T, l *testListener, n int) {
	t.Helper()
	poll(t, gateWait, func() bool { return l.acceptCount() >= n }, func() string {
		return fmt.Sprintf("the server called Accept %d times, want at least %d", l.acceptCount(), n)
	})
}

// awaitPeers waits until n connections have been handed out.
//
// Separate from awaitAccepts because the count rises when Accept is entered and the
// connection exists only when it returns: a test that read peer n-1 off an accept
// count of n would find it missing about as often as the scheduler felt like it.
func awaitPeers(t *testing.T, l *testListener, n int) {
	t.Helper()
	poll(t, gateWait, func() bool { return l.peerCount() >= n }, func() string {
		return fmt.Sprintf("the listener handed out %d connections, want at least %d", l.peerCount(), n)
	})
}

// awaitPeerFrames waits until the peer has received n whole frames and returns them.
func awaitPeerFrames(t *testing.T, p *peerConn, n int) []frame.Frame {
	t.Helper()
	poll(t, gateWait, func() bool { return len(p.frames(t)) >= n }, func() string {
		return fmt.Sprintf("the peer received %s, want at least %d frames",
			describe(p.frames(t)), n)
	})
	return p.frames(t)
}

// awaitPeerGone waits until the peer's end of the connection is finished, which is
// when everything the server sent has arrived.
func awaitPeerGone(t *testing.T, p *peerConn) {
	t.Helper()
	select {
	case <-p.done:
	case <-time.After(gateWait):
		t.Fatalf("the connection was still open at the peer after %v; it had received %s",
			gateWait, describe(p.frames(t)))
	}
}

func awaitLog(t *testing.T, rec *logRecorder, want string, within time.Duration) {
	t.Helper()
	poll(t, within, func() bool { return strings.Contains(rec.text(), want) }, func() string {
		return fmt.Sprintf("the log never mentioned %q; it says:\n%s", want, rec.text())
	})
}

func assertLogged(t *testing.T, rec *logRecorder, want string) {
	t.Helper()
	if !strings.Contains(rec.text(), want) {
		t.Errorf("the log does not mention %q; it says:\n%s", want, rec.text())
	}
}

// assertLoggedLines checks the log has exactly n lines in it.
//
// A count rather than a substring, because one of the things that can go wrong on a
// refused connection is *extra* correctness-shaped noise. A runConn that logs the
// refusal and then carries on into Serve produces a second line — the connection
// failing on a socket it has already closed — and every substring assertion in the
// suite still holds, because the line it was looking for is there. What changed is
// that the server did more work on a connection it had decided to drop.
//
// Call it after the server has stopped. Before that the count is a race: the line is
// written by the connection's own goroutine.
func assertLoggedLines(t *testing.T, rec *logRecorder, n int) {
	t.Helper()
	text := rec.text()
	got := strings.Count(text, "\n")
	if got != n {
		t.Errorf("the log has %d lines, want exactly %d:\n%s", got, n, text)
	}
}

// poll waits for cond, failing with why if it has not come true within limit.
func poll(t *testing.T, limit time.Duration, cond func() bool, why func() string) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s (waited %v)", why(), limit)
		}
		time.Sleep(time.Millisecond)
	}
}

// http1Preface is the first 24 octets of an HTTP/1.1 request — the same count as
// the HTTP/2 preface, so the server has everything it needs to decide.
//
// It is exactly 24 and not one more because the server does not read a byte past the
// point where the connection is doomed, which is right: a peer that has already
// failed does not get to make this process buffer for it. On a real socket the rest
// of the request lands in a kernel buffer and is discarded with the descriptor; on
// net.Pipe there is no buffer, so a longer request would leave the peer's own write
// blocked on a reader that has correctly stopped reading.
const http1Preface = "GET /index.html HTTP/1.1"

// --- a whole connection over a real socket ------------------------------------

// TestServerServesARealSocket is the one test here that uses the network, and it is
// the only place the whole stack is proved to work on the thing it ships against.
//
// Everything else in this file drives net.Pipe, which is a socket in every way the
// accept layer cares about and in no way the operating system cares about. A
// net.Conn that did not satisfy connSocket, a deadline the kernel applies
// differently, an address type that panicked when logged — none of those are
// reachable through a pipe, and all of them are outages.
func TestServerServesARealSocket(t *testing.T) {
	baseline := goroutineBaseline()

	s, rec := testServer(t, Config{Timeouts: serverTimeouts()}, nil)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening on loopback: %v", err)
	}
	done := serverInBackground(s, l)

	nc, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("dialling %v: %v", l.Addr(), err)
	}
	p := newPeerConn(nc, true)

	p.send(t, clientHello(t))
	p.send(t, encodeFrames(t, ping(0x0102030405060708)))

	// Our SETTINGS, the acknowledgement of theirs, and the answer to the PING.
	got := awaitPeerFrames(t, p, 3)
	if _, ok := got[0].(frame.SettingsFrame); !ok {
		t.Fatalf("the first frame off a real socket was %s, want SETTINGS (RFC 9113 §3.4); the peer "+
			"received %s", got[0].Type(), describe(got))
	}
	if pf, ok := got[2].(frame.PingFrame); !ok || !pf.Ack || pf.Data != ping(0x0102030405060708).Data {
		t.Errorf("the third frame was %#v, want a PING acknowledgement carrying the peer's own octets; "+
			"the peer received %s", got[2], describe(got))
	}

	if err := s.Shutdown(); err != nil {
		t.Errorf("Shutdown over a real socket returned %v, want nil", err)
	}
	assertServerClosed(t, awaitServe(t, done))

	awaitPeerGone(t, p)
	assertGracefulGoAway(t, p.frames(t))
	if rec.text() != "" {
		t.Errorf("a clean connection over a real socket logged something:\n%s", rec.text())
	}
	assertNoGoroutineLeak(t, baseline)
}

// --- the connection bound -----------------------------------------------------

// TestServerBoundsConcurrentConnections is limits.MaxConns enforced the way its
// comment says it is: by not accepting.
//
// The negative half — no third accept — cannot stand alone, because a server that
// had stopped accepting for any reason at all would pass it. The positive half, one
// connection ending and the third accept happening at once, is what makes it an
// assertion about the bound rather than about the server being broken.
func TestServerBoundsConcurrentConnections(t *testing.T) {
	baseline := goroutineBaseline()

	s, _ := testServer(t, Config{Timeouts: serverTimeouts(), MaxConns: 2}, nil)
	l := newTestListener(nil, nil, nil)
	done := serverInBackground(s, l)

	awaitPeers(t, l, 2)
	time.Sleep(settleWait)
	if got := l.acceptCount(); got != 2 {
		t.Fatalf("the server called Accept %d times with MaxConns = 2 and two connections live, want 2: "+
			"accepting past the bound spends a descriptor to tell a peer it has a connection it does not",
			got)
	}

	l.peer(t, 0).Close()
	awaitPeers(t, l, 3)

	if err := s.Shutdown(); err != nil {
		t.Errorf("Shutdown: %v", err)
	}
	assertServerClosed(t, awaitServe(t, done))
	assertNoGoroutineLeak(t, baseline)
}

// TestServerFillsUnsetConfig checks the two defaults a caller gets for leaving the
// config empty, because both are security-relevant and both fail silently: an
// unbounded connection count and a set of zero deadlines that expire immediately.
func TestServerFillsUnsetConfig(t *testing.T) {
	s := New(func(ConnWriter) StreamHandler { return rejectingHandler(t) }, Config{})

	if got := cap(s.slots); got != limits.MaxConns {
		t.Errorf("an empty Config gives room for %d connections, want limits.MaxConns = %d",
			got, limits.MaxConns)
	}
	if want := limits.DefaultTimeouts(); !reflect.DeepEqual(s.timeouts, want) {
		t.Errorf("an empty Config gives timeouts %+v, want the defaults %+v", s.timeouts, want)
	}
	if s.log != nil {
		t.Errorf("an empty Config gives a logger; nil is what discards, and logf checks for it")
	}

	// The nil logger on the path that uses it most: a server with no log must not
	// panic when there is something to say.
	s.logf("into the void: %d", 1)
}

// TestServerNewRequiresAHandlerFactory pins the panic. A server built without one
// would start, listen, accept, and then panic on the first connection, with a peer's
// traffic in the stack trace and the fault a hundred milliseconds from its cause.
func TestServerNewRequiresAHandlerFactory(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("New(nil, Config{}) returned a server; want a panic at construction")
		}
		if got, ok := r.(string); !ok || !strings.Contains(got, "handler factory") {
			t.Errorf("New(nil, Config{}) panicked with %v, want a message naming the handler factory", r)
		}
	}()
	New(nil, Config{})
}

// taggedHandler is a handler two of which can be told apart. handlerFunc cannot:
// it is a func type, and comparing two interface values holding funcs panics instead
// of answering.
type taggedHandler struct {
	StreamHandler
	w ConnWriter
}

// TestServerBuildsAHandlerPerConnection is the claim on Server.newHandler, and it is
// the one thing about the factory a single-connection test cannot see.
//
// Calling it once and reusing the handler would work, right up to the second
// concurrent connection: §5.1.1 numbers streams per connection, so two peers both
// opening stream 1 would meet in one table and one of them would get the other's
// request. The write half settles it even where the identifiers happen not to
// collide — it is bound to one socket, so a handler carried over from a previous
// connection answers this peer down somebody else's.
//
// Distinct handlers and distinct enqueuers are therefore both asserted. Either alone
// passes for a server that got the other wrong.
func TestServerBuildsAHandlerPerConnection(t *testing.T) {
	baseline := goroutineBaseline()

	var mu sync.Mutex
	var handlers []*taggedHandler
	newHandler := func(w ConnWriter) StreamHandler {
		h := &taggedHandler{StreamHandler: rejectingHandler(t), w: w}
		mu.Lock()
		handlers = append(handlers, h)
		mu.Unlock()
		return h
	}
	built := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(handlers)
	}

	l := newTestListener(nil, nil)
	s, _ := testServer(t, Config{Timeouts: serverTimeouts()}, newHandler)
	done := serverInBackground(s, l)
	awaitPeers(t, l, 2)
	poll(t, gateWait, func() bool { return built() >= 2 }, func() string {
		return fmt.Sprintf("the server built %d handlers for 2 connections", built())
	})

	func() {
		mu.Lock()
		defer mu.Unlock()
		if handlers[0] == handlers[1] {
			t.Errorf("both connections were served by the same handler, so two peers share one stream table")
		}
		if handlers[0].w == handlers[1].w {
			t.Errorf("both handlers were given the same write half, so one peer's response can be " +
				"written to the other's socket")
		}
		for i, h := range handlers {
			if h.w == nil {
				t.Errorf("connection %d's handler was given no write half, so it cannot answer a request", i)
			}
		}
	}()

	if err := s.Shutdown(); err != nil {
		t.Errorf("Shutdown: %v", err)
	}
	assertServerClosed(t, awaitServe(t, done))
	assertNoGoroutineLeak(t, baseline)
}

// --- accept failures ----------------------------------------------------------

// TestServerBacksOffOnAnAcceptFailure covers the failure that actually happens in
// production: the process is out of file descriptors.
//
// It is transient by nature, which fixes both wrong answers. A server that exited
// would turn a load spike into an outage; one that retried without pausing would
// spin a core while the condition clears, making it last longer. The pause has to
// grow, and the loop has to come back.
func TestServerBacksOffOnAnAcceptFailure(t *testing.T) {
	baseline := goroutineBaseline()

	boom := errors.New("accept: too many open files")
	l := newTestListener(boom, boom, boom, nil)
	s, rec := testServer(t, Config{Timeouts: serverTimeouts()}, nil)

	start := time.Now()
	done := serverInBackground(s, l)
	awaitAccepts(t, l, 4)
	elapsed := time.Since(start)

	// The three pauses between the four attempts: 5ms, then 10ms, then 20ms.
	const wantAtLeast = 7 * minAcceptDelay
	if elapsed < wantAtLeast {
		t.Errorf("four accept attempts took %v, want at least %v: the pause is not growing, so a "+
			"listener that keeps failing spins a core instead of waiting", elapsed, wantAtLeast)
	}

	// The connection after the failures is served, which is the half that says the
	// loop recovered rather than merely survived.
	awaitPeers(t, l, 1)
	awaitPeerFrames(t, l.peer(t, 0), 1)

	// One accept per failure, one for the connection, and one more now blocked with
	// the script exhausted. Anything above that is a spin.
	if got := l.acceptCount(); got > 5 {
		t.Errorf("the server called Accept %d times for three failures and one connection, want 5", got)
	}

	assertLogged(t, rec, "retrying in")
	assertLogged(t, rec, boom.Error())

	if err := s.Shutdown(); err != nil {
		t.Errorf("Shutdown: %v", err)
	}
	assertServerClosed(t, awaitServe(t, done))
	assertNoGoroutineLeak(t, baseline)
}

// TestServerAcceptDelayResetsAfterASuccess is the difference between a server that
// recovers from a rough patch and one that carries it for the rest of its life.
//
// Without the reset the pause only ever grows. A port that hits its descriptor limit
// for a few seconds once an hour would ratchet up to the ceiling and stay there, so
// every connection for the rest of the week waits a second to be accepted — a
// permanent latency floor caused by a transient fault that cleared days ago, and
// nothing in the log to connect the two.
//
// Measured through the log rather than the clock, because the log records the pause
// the server chose and the clock only records how long the machine took.
func TestServerAcceptDelayResetsAfterASuccess(t *testing.T) {
	baseline := goroutineBaseline()

	boom := errors.New("accept: too many open files")
	// Three failures to climb, a connection to reset on, then one failure more.
	l := newTestListener(boom, boom, boom, nil, boom, nil)
	s, rec := testServer(t, Config{Timeouts: serverTimeouts()}, nil)
	done := serverInBackground(s, l)

	awaitPeers(t, l, 2)

	first := "retrying in " + minAcceptDelay.String()
	if got := strings.Count(rec.text(), first); got != 2 {
		t.Errorf("the server paused for the opening %v %d times across two runs of failures, want 2; "+
			"the log says:\n%s", minAcceptDelay, got, rec.text())
	}

	if err := s.Shutdown(); err != nil {
		t.Errorf("Shutdown: %v", err)
	}
	assertServerClosed(t, awaitServe(t, done))
	assertNoGoroutineLeak(t, baseline)
}

// TestServerAcceptBackoffIsInterruptedByShutdown is the other half of retrying for
// ever: a shutdown must not have to wait out the pause.
//
// The measurement is fair because of where the log line is written — immediately
// before the pause — so the line naming the ceiling means a full second of waiting
// has just begun. Without that anchor this would be a race against whichever pause
// happened to be running.
func TestServerAcceptBackoffIsInterruptedByShutdown(t *testing.T) {
	baseline := goroutineBaseline()

	boom := errors.New("accept: too many open files")
	steps := make([]error, 32)
	for i := range steps {
		steps[i] = boom
	}
	l := newTestListener(steps...)
	s, rec := testServer(t, Config{Timeouts: serverTimeouts()}, nil)
	done := serverInBackground(s, l)

	awaitLog(t, rec, "retrying in "+maxAcceptDelay.String(), backoffWait)

	start := time.Now()
	if err := s.Shutdown(); err != nil {
		t.Errorf("Shutdown during an accept pause returned %v, want nil", err)
	}
	assertServerClosed(t, awaitServe(t, done))

	if elapsed := time.Since(start); elapsed > maxAcceptDelay/2 {
		t.Errorf("Serve took %v to return from inside a %v accept pause, want well under it: a shutdown "+
			"that waits out the backoff is a deployment that appears to hang", elapsed, maxAcceptDelay)
	}
	assertNoGoroutineLeak(t, baseline)
}

// TestServerForgetsAListenerThatStopped is about a server that outlives one of its
// listeners, which is the ordinary case rather than an odd one: a port is reopened
// when a certificate is replaced, and a server that serves for months serves more
// listeners than it holds.
//
// The set is what Shutdown walks. Every entry left in it after Serve returned is a
// listener the shutdown closes again for no reason, and a reference the garbage
// collector cannot drop — a slow leak of exactly the object whose whole purpose was
// to be released.
func TestServerForgetsAListenerThatStopped(t *testing.T) {
	baseline := goroutineBaseline()

	l := newTestListener()
	s, _ := testServer(t, Config{Timeouts: serverTimeouts()}, nil)
	done := serverInBackground(s, l)
	awaitAccepts(t, l, 1)

	if err := l.Close(); err != nil {
		t.Fatalf("closing the listener: %v", err)
	}
	if err := awaitServe(t, done); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Serve returned %v, want an error wrapping net.ErrClosed", err)
	}

	s.mu.Lock()
	left := len(s.listeners)
	s.mu.Unlock()
	if left != 0 {
		t.Errorf("the server still holds %d listeners after Serve returned, want 0", left)
	}

	if err := s.Close(); err != nil {
		t.Errorf("Close after a listener stopped on its own returned %v, want nil", err)
	}
	assertNoGoroutineLeak(t, baseline)
}

// TestServerShutdownReportsAListenerThatWillNotClose covers the descriptor that does
// not go away when asked.
//
// It has to be reported rather than logged and forgotten, because it is the one
// listener failure that outlives the process's intentions: the port may still be
// bound, and a supervisor about to start a replacement needs to know that binding it
// is going to fail. The address is in the message for the same reason — a server with
// two ports and one error is half a diagnosis.
func TestServerShutdownReportsAListenerThatWillNotClose(t *testing.T) {
	baseline := goroutineBaseline()

	boom := errors.New("close: input/output error")
	l := newTestListener().unclosable(boom)
	s, _ := testServer(t, Config{Timeouts: serverTimeouts()}, nil)
	done := serverInBackground(s, l)
	awaitAccepts(t, l, 1)

	err := s.Shutdown()
	if !errors.Is(err, boom) {
		t.Errorf("Shutdown returned %v, want it to carry the listener's own error: a port that is still "+
			"bound after the shutdown is the next deployment's failure to bind", err)
	}
	if got := fmt.Sprint(err); !strings.Contains(got, l.Addr().String()) {
		t.Errorf("Shutdown said %q, want it to name the listener's address; a server with two ports and "+
			"an unaddressed error is half a diagnosis", got)
	}

	assertServerClosed(t, awaitServe(t, done))
	assertNoGoroutineLeak(t, baseline)
}

// TestServerStopsAcceptingOnAClosedListener is the accept failure that must not be
// retried: a listener closed by something other than this server.
//
// Retrying would spin, and reporting ErrServerClosed would be worse — a supervisor
// waiting on Serve would read a listener that died as an orderly stop and would not
// restart it.
func TestServerStopsAcceptingOnAClosedListener(t *testing.T) {
	baseline := goroutineBaseline()

	l := newTestListener() // no script: Accept blocks until the listener closes
	s, _ := testServer(t, Config{Timeouts: serverTimeouts()}, nil)
	done := serverInBackground(s, l)
	awaitAccepts(t, l, 1)

	if err := l.Close(); err != nil {
		t.Fatalf("closing the listener behind the server's back: %v", err)
	}

	err := awaitServe(t, done)
	if errors.Is(err, ErrServerClosed) {
		t.Errorf("Serve returned ErrServerClosed for a listener closed behind its back; a caller cannot " +
			"tell that from a requested stop and will leave the port unserved")
	}
	if !errors.Is(err, net.ErrClosed) {
		t.Errorf("Serve returned %v, want an error wrapping net.ErrClosed", err)
	}

	if err := s.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	assertNoGoroutineLeak(t, baseline)
}

// TestNextAcceptDelay pins the backoff schedule, including both ends of it.
//
// The ceiling is the part worth a test: without it the delay doubles until it
// overflows, and a listener that has been broken for a few minutes retries once a
// century.
func TestNextAcceptDelay(t *testing.T) {
	cases := []struct {
		from, want time.Duration
	}{
		{0, minAcceptDelay},
		{-time.Second, minAcceptDelay},
		{minAcceptDelay, 2 * minAcceptDelay},
		{100 * time.Millisecond, 200 * time.Millisecond},
		{maxAcceptDelay / 2, maxAcceptDelay},
		{maxAcceptDelay, maxAcceptDelay},
		{time.Hour, maxAcceptDelay},
	}
	for _, tc := range cases {
		if got := nextAcceptDelay(tc.from); got != tc.want {
			t.Errorf("nextAcceptDelay(%v) = %v, want %v", tc.from, got, tc.want)
		}
	}

	// The schedule reaches the ceiling rather than approaching it, and does so in a
	// bounded number of steps. A doubling that stopped one halving short would leave
	// the server retrying twice a second for ever.
	d := time.Duration(0)
	for i := 0; i < 64; i++ {
		d = nextAcceptDelay(d)
		if d > maxAcceptDelay {
			t.Fatalf("the backoff reached %v after %d failures, above the ceiling of %v",
				d, i+1, maxAcceptDelay)
		}
	}
	if d != maxAcceptDelay {
		t.Errorf("the backoff settled at %v after 64 failures, want the ceiling of %v", d, maxAcceptDelay)
	}
}

// --- shutdown -----------------------------------------------------------------

// TestServerShutdownSendsGoAwayToEveryConnection is the difference between a
// deployment and an outage.
//
// A client that sees a socket close cannot tell a restart from a crash, so it must
// assume its unanswered requests may have been acted on and cannot safely retry
// them. A GOAWAY carrying NO_ERROR and a last stream identifier says exactly which
// requests were untouched, and every one of them can go to the next server.
func TestServerShutdownSendsGoAwayToEveryConnection(t *testing.T) {
	baseline := goroutineBaseline()

	const conns = 3
	l := newTestListener(make([]error, conns)...)
	s, _ := testServer(t, Config{Timeouts: serverTimeouts()}, nil)
	done := serverInBackground(s, l)
	awaitPeers(t, l, conns)

	// Every peer completes the handshake first, so each connection is parked in a
	// read when the shutdown arrives — which is the state a live server is in.
	for i := 0; i < conns; i++ {
		p := l.peer(t, i)
		p.send(t, clientHello(t))
		awaitPeerFrames(t, p, 2)
	}

	if err := s.Shutdown(); err != nil {
		t.Errorf("Shutdown returned %v, want nil: every connection was parked in a read and had "+
			"nothing to finish", err)
	}
	assertServerClosed(t, awaitServe(t, done))

	for i := 0; i < conns; i++ {
		p := l.peer(t, i)
		awaitPeerGone(t, p)
		assertGracefulGoAway(t, p.frames(t))
	}
	assertNoGoroutineLeak(t, baseline)
}

// TestServerCloseStopsWithoutAGoAway pins the other half of the pair. Close is the
// second Ctrl-C: the sockets go and the peers are told nothing, which is the point —
// an operator who has run out of patience should not be made to wait for a courtesy.
func TestServerCloseStopsWithoutAGoAway(t *testing.T) {
	baseline := goroutineBaseline()

	l := newTestListener(nil)
	s, _ := testServer(t, Config{Timeouts: serverTimeouts()}, nil)
	done := serverInBackground(s, l)
	awaitPeers(t, l, 1)

	p := l.peer(t, 0)
	p.send(t, clientHello(t))
	awaitPeerFrames(t, p, 2)

	if err := s.Close(); err != nil {
		t.Errorf("Close returned %v, want nil", err)
	}
	assertServerClosed(t, awaitServe(t, done))

	awaitPeerGone(t, p)
	noGoAwayIn(t, p.frames(t))
	assertNoGoroutineLeak(t, baseline)
}

// TestServerShutdownForcesAStalledConnectionPastTheGrace is the peer that opens a
// connection and never reads: a slowloris with none of the effort.
//
// Its connection cannot be shut down gracefully, and not because of anything the
// connection layer got wrong. The writer goroutine is blocked writing the server
// preface into a socket nobody is draining, so the GOAWAY it is asked to send cannot
// go out and the connection cannot end. Only closing the socket reaches it, and the
// operator has to be told that it came to that.
func TestServerShutdownForcesAStalledConnectionPastTheGrace(t *testing.T) {
	baseline := goroutineBaseline()

	to := serverTimeouts()
	to.ShutdownGrace = shortTimeout
	l := newTestListener(nil).stalled()
	s, _ := testServer(t, Config{Timeouts: to}, nil)
	done := serverInBackground(s, l)
	awaitPeers(t, l, 1)

	err := s.Shutdown()
	if !errors.Is(err, ErrShutdownGraceExpired) {
		t.Fatalf("Shutdown returned %v, want it to wrap ErrShutdownGraceExpired: a connection was cut "+
			"mid-flight and a deployment that does not know that cannot decide to wait longer", err)
	}
	if got := fmt.Sprint(err); !strings.Contains(got, "mid-flight") {
		t.Errorf("Shutdown said %q, want it to say the connections were cut mid-flight rather than "+
			"that they would not stop; the two call for different responses", got)
	}
	assertServerClosed(t, awaitServe(t, done))
	assertNoGoroutineLeak(t, baseline)
}

// wedgedHandler returns a handler factory whose first frame never returns, together
// with a channel closed when the handler has been reached and a function that lets it
// go.
//
// It is the connection that nothing in this package can stop. The quit channel is not
// watched from inside a handler, and closing the socket does not reach a goroutine
// that is not blocked on the socket. Both Shutdown and Close have to give up on it and
// say so, which is what the two tests below check — and it is not a contrived state:
// any handler that waits on a backend, a lock, or a disk can be in it.
func wedgedHandler() (newHandler func(ConnWriter) StreamHandler, entered <-chan struct{}, release func()) {
	in := make(chan struct{})
	out := make(chan struct{})
	var once sync.Once
	factory := func(ConnWriter) StreamHandler {
		return handlerFunc(func(frame.Frame) error {
			once.Do(func() { close(in) })
			<-out
			return nil
		})
	}
	return factory, in, func() { close(out) }
}

// awaitWedged completes the handshake, sends the frame that reaches the handler, and
// waits until it is in there.
func awaitWedged(t *testing.T, p *peerConn, entered <-chan struct{}) {
	t.Helper()
	p.send(t, clientHello(t))
	p.send(t, encodeFrames(t, frame.RSTStreamFrame{StreamID: 1, ErrCode: h2.Cancel}))
	select {
	case <-entered:
	case <-time.After(gateWait):
		t.Fatalf("the handler was not reached within %v, so nothing is wedged and this test is not "+
			"testing what it says", gateWait)
	}
}

// TestServerShutdownReportsAConnectionThatWillNotStop is the case where closing the
// socket is not enough either, because the goroutine is not blocked on the socket at
// all — it is inside a handler.
//
// Shutdown must still return. A process that hangs on the way down is worse than one
// that reports what it could not stop: the operator's next move is a kill, and they
// need to know that is what it will take.
func TestServerShutdownReportsAConnectionThatWillNotStop(t *testing.T) {
	baseline := goroutineBaseline()

	handler, entered, release := wedgedHandler()
	to := serverTimeouts()
	to.ShutdownGrace = shortTimeout
	l := newTestListener(nil)
	s, _ := testServer(t, Config{Timeouts: to}, handler)
	done := serverInBackground(s, l)
	awaitPeers(t, l, 1)
	awaitWedged(t, l.peer(t, 0), entered)

	err := s.Shutdown()
	if !errors.Is(err, ErrShutdownGraceExpired) {
		t.Errorf("Shutdown returned %v, want it to wrap ErrShutdownGraceExpired", err)
	}
	if got := fmt.Sprint(err); !strings.Contains(got, "did not stop") {
		t.Errorf("Shutdown said %q, want it to say the connection did not stop even after being closed: "+
			"that is the one outcome a kill is the answer to", got)
	}

	release()
	assertServerClosed(t, awaitServe(t, done))
	assertNoGoroutineLeak(t, baseline)
}

// TestServerCloseReportsAConnectionThatWillNotStop is the impatient path making the
// same promise: it comes back.
//
// Close is what an operator reaches for when the graceful shutdown has already been
// waiting longer than they are willing to, so it is the last call that may hang. It
// has closed every socket by then and that was not enough, which leaves it nothing to
// do but say so.
func TestServerCloseReportsAConnectionThatWillNotStop(t *testing.T) {
	baseline := goroutineBaseline()

	handler, entered, release := wedgedHandler()
	to := serverTimeouts()
	to.ShutdownGrace = shortTimeout
	l := newTestListener(nil)
	s, _ := testServer(t, Config{Timeouts: to}, handler)
	done := serverInBackground(s, l)
	awaitPeers(t, l, 1)
	awaitWedged(t, l.peer(t, 0), entered)

	if err := s.Close(); !errors.Is(err, ErrShutdownGraceExpired) {
		t.Errorf("Close returned %v, want it to wrap ErrShutdownGraceExpired: the caller has just closed "+
			"every socket underneath its connections and is owed the news that one survived it", err)
	}

	release()
	assertServerClosed(t, awaitServe(t, done))
	assertNoGoroutineLeak(t, baseline)
}

// TestServerShutdownIsIdempotent covers the call as it is actually made: from a
// signal handler, from a test's cleanup, and from a supervisor, all at once and again
// afterwards.
//
// Exactly one GOAWAY per connection is the sharp end of it. Eight shutdowns that each
// sent a farewell would be a server sending frames after announcing it would send no
// more, which §6.8 forbids and which a strict client answers by closing the
// connection.
func TestServerShutdownIsIdempotent(t *testing.T) {
	baseline := goroutineBaseline()

	to := serverTimeouts()
	to.ShutdownGrace = time.Second
	l := newTestListener(nil)
	s, _ := testServer(t, Config{Timeouts: to}, nil)
	done := serverInBackground(s, l)
	awaitPeers(t, l, 1)

	p := l.peer(t, 0)
	p.send(t, clientHello(t))
	awaitPeerFrames(t, p, 2)

	const callers = 8
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- s.Shutdown()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("one of %d concurrent Shutdown calls returned %v, want nil", callers, err)
		}
	}

	assertServerClosed(t, awaitServe(t, done))
	awaitPeerGone(t, p)
	assertGracefulGoAway(t, p.frames(t))

	// And again once everything has stopped, which is what a supervisor does to a
	// server that ended a microsecond before it looked.
	if err := s.Shutdown(); err != nil {
		t.Errorf("Shutdown on a stopped server returned %v, want nil", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("Close after Shutdown returned %v, want nil", err)
	}
	assertNoGoroutineLeak(t, baseline)
}

// TestServerShutdownClosesEachListenerOnce is why onceListener exists.
//
// Shutdown closes the listener to break Accept, and Serve closes the listener it was
// handed on its way out; both happen on every shutdown, in an order neither controls.
// Closing a descriptor twice is not merely untidy — between the two closes the number
// can be reissued to something else, and the second close then belongs to a
// connection that had nothing to do with any of this.
func TestServerShutdownClosesEachListenerOnce(t *testing.T) {
	baseline := goroutineBaseline()

	l := newTestListener()
	s, rec := testServer(t, Config{Timeouts: serverTimeouts()}, nil)
	done := serverInBackground(s, l)
	awaitAccepts(t, l, 1)

	if err := s.Shutdown(); err != nil {
		t.Errorf("Shutdown returned %v, want nil: the second close of a listener reports only which of "+
			"two callers arrived first, which is not a shutdown failure", err)
	}
	assertServerClosed(t, awaitServe(t, done))

	if got := l.closeCount(); got != 1 {
		t.Errorf("the listener's Close ran %d times, want 1", got)
	}
	if strings.Contains(rec.text(), "closing listener") {
		t.Errorf("the shutdown logged a listener close failure:\n%s", rec.text())
	}
	assertNoGoroutineLeak(t, baseline)
}

// TestServerServeAfterShutdownDoesNotAccept covers a caller that starts a listener
// as the server is going down — a second port coming up while the first signal is
// being handled.
//
// The listener still has to be closed. Serve is the only thing that knows about it,
// the shutdown has already been round the set, and a listening socket nobody closes
// is a port that stays bound until the process exits.
func TestServerServeAfterShutdownDoesNotAccept(t *testing.T) {
	l := newTestListener(nil)
	s, _ := testServer(t, Config{Timeouts: serverTimeouts()}, nil)
	if err := s.Shutdown(); err != nil {
		t.Fatalf("Shutdown on a server with nothing running: %v", err)
	}

	if err := s.Serve(l); !errors.Is(err, ErrServerClosed) {
		t.Errorf("Serve on a stopped server returned %v, want ErrServerClosed", err)
	}
	if got := l.acceptCount(); got != 0 {
		t.Errorf("Serve on a stopped server called Accept %d times, want 0", got)
	}
	if got := l.closeCount(); got != 1 {
		t.Errorf("Serve on a stopped server closed the listener %d times, want 1: nothing else will ever "+
			"look at it again, so a port stays bound for the life of the process", got)
	}
}

// TestServerShutdownReachesAConnectionAcceptedInTheRace covers the connection that
// was already accepted when the shutdown went past.
//
// It is in no set and nothing is waiting for it, so if it were simply served it would
// sit in a read until its idle timeout — a minute of a stopped server still holding a
// socket. It gets the same goodbye as every other connection, immediately.
//
// serveConn is called directly because the window is a few instructions wide and
// arranging for a real accept to land inside it would be a test of the scheduler. The
// slot is taken by hand for the same reason Serve takes one before every accept.
func TestServerShutdownReachesAConnectionAcceptedInTheRace(t *testing.T) {
	baseline := goroutineBaseline()

	s, _ := testServer(t, Config{Timeouts: serverTimeouts()}, nil)
	if err := s.Shutdown(); err != nil {
		t.Fatalf("Shutdown on a server with nothing running: %v", err)
	}

	sock, client := net.Pipe()
	p := newPeerConn(client, true)
	s.slots <- struct{}{}
	s.serveConn(sock)

	awaitPeerGone(t, p)
	assertGracefulGoAway(t, p.frames(t))
	assertNoGoroutineLeak(t, baseline)
}

// --- containment --------------------------------------------------------------

// TestServerRecoversFromAPanickingHandler is the blast radius of a bug in this
// server reached through a peer's input.
//
// Unrecovered, one malformed header block takes down every other connection in the
// process, which makes a crash bug into a remote denial of service against everyone
// sharing the port. The panic has to end the connection it happened on and nothing
// else, and it has to be logged with its stack — a contained panic nobody can see is
// a bug that stays in for months.
func TestServerRecoversFromAPanickingHandler(t *testing.T) {
	baseline := goroutineBaseline()

	handler := func(ConnWriter) StreamHandler {
		return handlerFunc(func(frame.Frame) error {
			panic("a bug reached through a peer's frame")
		})
	}
	l := newTestListener(nil, nil)
	s, rec := testServer(t, Config{Timeouts: serverTimeouts()}, handler)
	done := serverInBackground(s, l)
	awaitPeers(t, l, 2)

	p := l.peer(t, 0)
	p.send(t, clientHello(t))
	p.send(t, encodeFrames(t, frame.RSTStreamFrame{StreamID: 1, ErrCode: h2.Cancel}))

	awaitLog(t, rec, "panicked", gateWait)
	assertLogged(t, rec, "a bug reached through a peer's frame")
	// Every stack dump opens with this. Without one, the log line says a bug exists
	// and nothing about where.
	assertLogged(t, rec, "goroutine")

	// The connection that panicked is over.
	awaitPeerGone(t, p)

	// The one beside it is not, and that is the whole assertion: a second peer is
	// still served after the first one's frame crashed a goroutine.
	q := l.peer(t, 1)
	q.send(t, clientHello(t))
	awaitPeerFrames(t, q, 2)

	if err := s.Shutdown(); err != nil {
		t.Errorf("Shutdown: %v", err)
	}
	assertServerClosed(t, awaitServe(t, done))
	assertNoGoroutineLeak(t, baseline)
}

// TestServerLogsWhyAConnectionEnded covers the log line for an ordinary protocol
// error, using the failure that actually reaches a public port: an HTTP/1.1 request.
//
// The peer's address is in the line on purpose. A protocol error with no address is
// unactionable — the whole question an operator has is which client is doing it.
func TestServerLogsWhyAConnectionEnded(t *testing.T) {
	baseline := goroutineBaseline()

	l := newTestListener(nil)
	s, rec := testServer(t, Config{Timeouts: serverTimeouts()}, nil)
	done := serverInBackground(s, l)
	awaitPeers(t, l, 1)

	p := l.peer(t, 0)
	p.send(t, []byte(http1Preface))
	awaitPeerGone(t, p)

	awaitLog(t, rec, "HTTP/1.1", gateWait)
	assertLogged(t, rec, "connection from")

	// And the peer is told, rather than just dropped: a misconfigured client that
	// gets a GOAWAY naming the problem is a five-minute fix.
	ga := goAwayIn(t, p.frames(t))
	if ga.ErrCode != h2.ProtocolError {
		t.Errorf("an HTTP/1.1 request got GOAWAY %s, want PROTOCOL_ERROR (RFC 9113 §3.4)", ga.ErrCode)
	}

	if err := s.Shutdown(); err != nil {
		t.Errorf("Shutdown: %v", err)
	}
	assertServerClosed(t, awaitServe(t, done))
	assertNoGoroutineLeak(t, baseline)
}

// TestServerWithNoLogDiscardsEveryLine is the nil-logger path exercised where it
// would actually be reached, rather than by calling logf directly.
//
// A nil *log.Logger panics on Printf, and every one of these call sites is on a
// failure path — an accept that failed, a connection that ended badly, a panic that
// was contained. A nil check that was wrong would turn each of them into a second,
// worse failure, and only in the deployment that left ErrorLog unset.
func TestServerWithNoLogDiscardsEveryLine(t *testing.T) {
	baseline := goroutineBaseline()

	boom := errors.New("accept: too many open files")
	l := newTestListener(boom, nil)
	s := New(func(ConnWriter) StreamHandler { return rejectingHandler(t) }, Config{Timeouts: serverTimeouts()})
	done := serverInBackground(s, l)

	awaitPeers(t, l, 1)
	p := l.peer(t, 0)
	p.send(t, []byte(http1Preface))
	awaitPeerGone(t, p)

	if err := s.Shutdown(); err != nil {
		t.Errorf("Shutdown: %v", err)
	}
	assertServerClosed(t, awaitServe(t, done))
	assertNoGoroutineLeak(t, baseline)
}

// --- more than one listener ---------------------------------------------------

// TestServerServesTwoListeners is the arrangement this server actually ships in: a
// TLS port and an h2c port, one server, one connection bound shared between them.
//
// Two servers would be simpler and wrong. The bound exists to keep the process
// inside its descriptor limit, and two servers each holding half a limit they cannot
// see is a limit neither of them enforces.
func TestServerServesTwoListeners(t *testing.T) {
	baseline := goroutineBaseline()

	first, second := newTestListener(nil), newTestListener(nil)
	s, _ := testServer(t, Config{Timeouts: serverTimeouts()}, nil)
	firstDone := serverInBackground(s, first)
	secondDone := serverInBackground(s, second)

	for _, l := range []*testListener{first, second} {
		awaitPeers(t, l, 1)
		p := l.peer(t, 0)
		p.send(t, clientHello(t))
		awaitPeerFrames(t, p, 2)
	}

	if err := s.Shutdown(); err != nil {
		t.Errorf("Shutdown with two listeners returned %v, want nil", err)
	}
	assertServerClosed(t, awaitServe(t, firstDone))
	assertServerClosed(t, awaitServe(t, secondDone))

	for i, l := range []*testListener{first, second} {
		if got := l.closeCount(); got != 1 {
			t.Errorf("listener %d was closed %d times, want 1", i, got)
		}
		p := l.peer(t, 0)
		awaitPeerGone(t, p)
		assertGracefulGoAway(t, p.frames(t))
	}
	assertNoGoroutineLeak(t, baseline)
}

// TestServerBoundIsSharedAcrossListeners is the claim above, tested: two listeners
// and one slot, and only one of them gets to accept.
func TestServerBoundIsSharedAcrossListeners(t *testing.T) {
	baseline := goroutineBaseline()

	first, second := newTestListener(nil), newTestListener(nil)
	s, _ := testServer(t, Config{Timeouts: serverTimeouts(), MaxConns: 1}, nil)
	firstDone := serverInBackground(s, first)
	secondDone := serverInBackground(s, second)

	// Which listener wins the single slot is a race, and the point is that only one
	// of them can: two connections at MaxConns = 1 is the bound not existing.
	poll(t, gateWait, func() bool { return first.peerCount()+second.peerCount() >= 1 }, func() string {
		return "neither listener accepted a connection"
	})
	time.Sleep(settleWait)
	if got := first.peerCount() + second.peerCount(); got != 1 {
		t.Errorf("two listeners accepted %d connections between them with MaxConns = 1, want 1", got)
	}

	if err := s.Shutdown(); err != nil {
		t.Errorf("Shutdown: %v", err)
	}
	assertServerClosed(t, awaitServe(t, firstDone))
	assertServerClosed(t, awaitServe(t, secondDone))
	assertNoGoroutineLeak(t, baseline)
}
