package server

import (
	"errors"
	"fmt"
	"log"
	"net"
	"runtime/debug"
	"sync"
	"time"

	"zerodeps/zdh/internal/limits"
)

// ErrServerClosed is what Serve returns once the server has been stopped. It is
// the ending a caller is waiting for, not a failure, and it is a sentinel so that
// a caller can tell "we asked it to stop" from "the listener broke".
var ErrServerClosed = errors.New("server: closed")

// ErrShutdownGraceExpired is returned by Shutdown when connections were still
// running when the grace period ran out and had to be closed underneath whatever
// they were doing.
//
// It is worth a sentinel because it is the one shutdown outcome an operator has to
// know about: a deployment that returns this cut requests off mid-flight, and the
// next one should either wait longer or find out what would not stop.
var ErrShutdownGraceExpired = errors.New("server: shutdown grace period expired")

// The pause after a failed Accept, doubling from the first to the second.
//
// These live here rather than in internal/limits deliberately. That package holds
// the numbers a peer is held to — what it may send, how much of it, how fast — and
// each one is defended there against an attack. These two bound nothing a peer
// does: they are how long this server waits before retrying a syscall.
const (
	minAcceptDelay = 5 * time.Millisecond
	maxAcceptDelay = time.Second
)

// Config is a server's policy.
type Config struct {
	// Timeouts are the per-connection deadlines. Unset fields take their defaults;
	// see limits.Timeouts.
	Timeouts limits.Timeouts

	// MaxConns bounds how many connections are served at once. Zero or negative
	// takes limits.MaxConns.
	MaxConns int

	// ErrorLog receives one line for every connection that ended in an error,
	// every accept that failed, and every panic that was contained. Nil discards
	// them, which is right for a test and wrong for a deployment: a contained panic
	// that nobody logs is a bug that never gets fixed.
	ErrorLog *log.Logger
}

// Server accepts connections on one or more listeners and serves HTTP/2 on each.
//
// It owns exactly three things a single connection cannot: how many connections
// exist at once, what happens when accept fails, and how the whole set of them is
// brought down. Everything about one connection is conn's.
type Server struct {
	// newHandler makes the stream handler for one connection, given that
	// connection's write half. Called once per accepted connection and never shared
	// between two, because a stream table belongs to exactly one connection: §5.1.1
	// numbers streams per connection, and a table shared between two would let one
	// peer's identifiers collide with another's. The enqueuer settles it even where
	// the table would not — it writes to one socket, so a handler kept from a
	// previous connection would answer this peer's requests down someone else's.
	newHandler func(FrameEnqueuer) StreamHandler

	timeouts limits.Timeouts
	log      *log.Logger

	// slots is the connection bound, held as a buffered channel because a slot has
	// to be taken *before* Accept. See limits.MaxConns: a connection refused by not
	// accepting waits in the kernel's backlog, where it costs this process nothing
	// and is either served a moment later or fails at the client as a connection
	// that was never established. Accept-then-close spends a descriptor and a TLS
	// handshake to tell the peer the same thing less honestly.
	slots chan struct{}

	// quit is closed once, by whichever of Shutdown or Close runs first.
	quit     chan struct{}
	quitOnce sync.Once

	mu        sync.Mutex
	listeners map[*onceListener]struct{}
	conns     map[*conn]struct{}
	closed    bool

	// connWG counts connections only, not accept loops. A grace period is about
	// requests in flight; an accept loop stops the moment its listener closes and
	// has nothing to finish.
	//
	// Every Add happens in track, under mu and behind the same check of closed, and
	// that pairing is what makes waiting on it safe. stop sets closed while holding
	// mu, so by the time it returns no further Add can happen — and an Add racing a
	// Wait that has just seen zero is not a lost connection, it is a runtime panic.
	connWG sync.WaitGroup
}

// New returns a server that serves each accepted connection with a handler from
// newHandler, built against that connection's write half.
//
// A nil factory panics, for the same reason newConn does: the alternative is a
// server that starts, listens, accepts, and then panics on the first connection
// with a peer's traffic in the stack trace.
func New(newHandler func(FrameEnqueuer) StreamHandler, cfg Config) *Server {
	if newHandler == nil {
		panic("server: New requires a handler factory")
	}
	max := cfg.MaxConns
	if max <= 0 {
		max = limits.MaxConns
	}
	return &Server{
		newHandler: newHandler,
		timeouts:   cfg.Timeouts.WithDefaults(),
		log:        cfg.ErrorLog,
		slots:      make(chan struct{}, max),
		quit:       make(chan struct{}),
		listeners:  make(map[*onceListener]struct{}),
		conns:      make(map[*conn]struct{}),
	}
}

// Serve accepts connections on l until the server is stopped, serving each in its
// own goroutine. It returns ErrServerClosed after Shutdown or Close, and closes l
// on the way out.
//
// It may be called on several listeners at once — a plaintext port and a TLS port
// are one server with two listeners, sharing the connection bound between them,
// which is the only arrangement in which that bound means anything.
func (s *Server) Serve(l net.Listener) error {
	ol := &onceListener{Listener: l}
	if !s.addListener(ol) {
		// Stopped before this listener was registered, so nothing else will ever
		// close it: Shutdown has already been round the set. Closing it here is what
		// keeps a caller that raced Shutdown from leaking a listening socket.
		if err := ol.Close(); err != nil {
			s.logf("closing a listener the server was too late to accept on: %v", err)
		}
		return ErrServerClosed
	}
	defer s.removeListener(ol)

	var delay time.Duration
	for {
		// The slot comes before the accept, and blocking here is the bound doing its
		// job: at MaxConns this loop stops calling Accept and the connections the
		// kernel has queued stay queued.
		if !s.acquire() {
			return ErrServerClosed
		}

		nc, err := ol.Accept()
		if err != nil {
			s.release()
			switch {
			case s.stopping():
				return ErrServerClosed
			case errors.Is(err, net.ErrClosed):
				// Closed by someone other than Shutdown. Nothing will ever be
				// accepted on it again, so the retry below would be a spin, and the
				// caller is owed the reason rather than a clean ending.
				return fmt.Errorf("server: accept on a closed listener: %w", err)
			}

			// Everything else is retried, for ever, with a growing pause.
			//
			// net.Error.Temporary would be the obvious thing to ask here, and it is
			// deprecated precisely because no two platforms agreed on the answer.
			// What is left is a choice about the failure that actually happens:
			// descriptor exhaustion, which is transient by nature. A server that
			// exited on it would turn a load spike into an outage, and one that
			// retried without pausing would spin a core while the condition clears.
			// So: pause, log, stay up. A listener that is broken for good ends up
			// retrying once a second, which is visible in the log rather than fatal
			// in production.
			delay = nextAcceptDelay(delay)
			s.logf("accept on %v failed, retrying in %v: %v", ol.Addr(), delay, err)
			if !s.pause(delay) {
				return ErrServerClosed
			}
			continue
		}

		delay = 0
		s.serveConn(nc)
	}
}

// serveConn starts one connection's goroutine and hands the socket to it.
//
// It takes over the slot its caller acquired, and the connection's goroutine is what
// releases it. The pair is split across two functions because the acquire has to
// happen before Accept and the release cannot happen until the connection is over.
func (s *Server) serveConn(nc net.Conn) {
	c := newConn(nc, s.newHandler, s.timeouts)

	tracked := s.track(c)
	if !tracked {
		// The server stopped between the accept and here, so this connection is in
		// nobody's set and the shutdown has already been past. It is still served —
		// saying goodbye costs one frame — but it is told to stop immediately, and
		// nothing waits for it.
		c.Shutdown()
	}

	go func() {
		defer s.release()
		if tracked {
			defer s.finish(c)
		}
		s.runConn(c, nc)
	}()
}

// runConn negotiates TLS if there is any, serves one connection to completion, and is
// where a panic stops.
//
// A panic on this goroutine is a bug in this server reached through a peer's input,
// and the peer's other victims would be the several hundred connections that go down
// with the process. The recovery is here rather than deeper because this goroutine is
// the one that runs the handler: everything a peer sends is parsed and dispatched
// below this frame, including — once internal/hpack is wired in — the HPACK decoder,
// which is the most hostile input in the protocol.
//
// The writer goroutine is deliberately not wrapped the same way. It encodes frames
// this server built, never a structure a peer chose, and a panic there is a bug for
// the frame package's own tests and fuzzers to catch.
func (s *Server) runConn(c *conn, nc net.Conn) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		// The stack is the whole value of this line. A contained panic with no stack
		// is a bug that gets logged for months and never found.
		s.logf("connection from %v panicked, closing it: %v\n%s", nc.RemoteAddr(), r, debug.Stack())

		// Serve's own deferred close ran as the panic went past it, so the socket is
		// gone; its wait for the writer did not, so that goroutine is still there.
		c.w.Close()
		if err := c.w.Wait(); err != nil {
			s.logf("connection from %v: stopping the writer after the panic: %v", nc.RemoteAddr(), err)
		}
	}()

	// TLS first, on this goroutine, before anything is written. A connection that does
	// not get through this is closed without a frame: there is no protocol on it to
	// send one over. See handshake for why the accept loop is the wrong place for it.
	if err := s.handshake(nc); err != nil {
		s.logf("connection from %v: %v", nc.RemoteAddr(), err)
		if derr := c.discard(); derr != nil {
			s.logf("connection from %v: closing it after the failed handshake: %v", nc.RemoteAddr(), derr)
		}
		return
	}

	if err := c.Serve(); err != nil {
		s.logf("connection from %v: %v", nc.RemoteAddr(), err)
	}
}

// Shutdown stops the server gracefully and returns when it has stopped.
//
// The listeners close first, so nothing new is accepted; then every live connection
// is asked to stop, which sends each peer a GOAWAY carrying NO_ERROR — the frame that
// tells a client this server is leaving and that its unanswered requests can be
// retried elsewhere. Connections still running after Timeouts.ShutdownGrace are
// closed underneath whatever they were doing, and the error is
// ErrShutdownGraceExpired.
//
// Safe to call more than once and from any goroutine, including concurrently with
// Close.
func (s *Server) Shutdown() error {
	errs := s.closeListeners(s.stop())
	s.shutdownConns()

	if s.awaitConns(s.timeouts.ShutdownGrace) {
		return errors.Join(errs...)
	}

	// The grace period is up. Closing the socket is the only thing that reaches a
	// connection which is not cooperating: a goroutine wedged in a handler is not
	// watching its quit channel, and a peer that has stopped reading can hold the
	// writer until its own deadline expires.
	forced := s.closeConns()

	// A second grace period, and a bounded one on purpose. A connection whose socket
	// has been closed under it ends at once unless something is genuinely wedged, and
	// a Shutdown that waits for ever for the one wedged connection is worse than one
	// that reports it: the process is stopping, and the operator needs the answer
	// more than the last goroutine needs to finish.
	if !s.awaitConns(s.timeouts.ShutdownGrace) {
		errs = append(errs, fmt.Errorf("%w: %d connections did not stop even after being closed",
			ErrShutdownGraceExpired, forced))
		return errors.Join(errs...)
	}

	// forced can be zero even though the grace expired, when the last connections
	// finished between the wait giving up and the set being copied. Nothing was cut,
	// so there is nothing to report: the sentinel means requests were lost, and
	// returning it for a shutdown that merely finished late would teach an operator
	// to ignore it.
	if forced > 0 {
		errs = append(errs, fmt.Errorf("%w: %d connections were closed mid-flight",
			ErrShutdownGraceExpired, forced))
	}
	return errors.Join(errs...)
}

// Close stops the server now, without the courtesy Shutdown extends.
//
// The listeners close, every connection's socket closes under it, and no GOAWAY is
// sent: a peer sees the connection vanish. It is the second Ctrl-C — the one after
// the graceful shutdown has been waiting longer than the operator is willing to.
//
// Safe to call more than once, and after or during Shutdown.
func (s *Server) Close() error {
	errs := s.closeListeners(s.stop())
	s.closeConns()

	// Bounded for the same reason Shutdown's second wait is: this is the impatient
	// path, and it must not be the one that hangs.
	if !s.awaitConns(s.timeouts.ShutdownGrace) {
		errs = append(errs, ErrShutdownGraceExpired)
	}
	return errors.Join(errs...)
}

// stop marks the server closed and returns the listeners that were still
// registered, so that the closing itself happens outside the lock.
//
// Idempotent: a second caller gets the same set, and closing a listener twice is
// what onceListener is for. Closing anything while holding mu would be a deadlock
// waiting for a maintainer, because a close ends goroutines that call back into
// finish and release.
func (s *Server) stop() []*onceListener {
	s.quitOnce.Do(func() { close(s.quit) })

	s.mu.Lock()
	defer s.mu.Unlock()

	s.closed = true
	listeners := make([]*onceListener, 0, len(s.listeners))
	for l := range s.listeners {
		listeners = append(listeners, l)
	}
	return listeners
}

// closeListeners closes each listener and collects what went wrong.
func (s *Server) closeListeners(listeners []*onceListener) []error {
	var errs []error
	for _, l := range listeners {
		if err := l.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing listener %v: %w", l.Addr(), err))
		}
	}
	return errs
}

// shutdownConns asks every live connection to stop and say goodbye.
func (s *Server) shutdownConns() {
	for _, c := range s.liveConns() {
		c.Shutdown()
	}
}

// closeConns closes every live connection's socket and returns how many there were.
func (s *Server) closeConns() int {
	conns := s.liveConns()
	for _, c := range conns {
		if err := c.Close(); err != nil {
			// Expected, and logged rather than counted. A connection that finished
			// between the set being copied and this call has already closed its own
			// socket, and the second close reports only that ordering. One line on a
			// path that is already noteworthy beats a silent discard that would also
			// hide a real failure.
			s.logf("forcing a connection closed: %v", err)
		}
	}
	return len(conns)
}

// liveConns copies the set of connections currently being served.
//
// A copy, so that callers act on connections without holding mu; the set may be
// shorter by the time they do, which is the normal case and not a problem — a
// connection that finished on its own needs nothing done to it.
func (s *Server) liveConns() []*conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	conns := make([]*conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	return conns
}

// awaitConns waits up to grace for every connection to finish, reporting whether
// they did.
func (s *Server) awaitConns(grace time.Duration) bool {
	done := make(chan struct{})
	go func() {
		s.connWG.Wait()
		close(done)
	}()

	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		// The goroutine above outlives this call, still blocked on connWG. It ends
		// when the last connection does, which the caller is about to force.
		return false
	}
}

// acquire takes a connection slot, waiting for one if the server is at MaxConns. It
// reports false if the server stopped instead.
func (s *Server) acquire() bool {
	// Checked before the select rather than only in it: with both cases ready a
	// select chooses at random, so a stopping server would take a slot half the time
	// and accept one more connection. That connection is still handled correctly —
	// track refuses it and it is told to stop — but a shutdown should not depend on
	// a coin toss for whether it happens at all.
	if s.stopping() {
		return false
	}
	select {
	case s.slots <- struct{}{}:
		return true
	case <-s.quit:
		return false
	}
}

// release gives back the slot one connection held. It is called by that
// connection's goroutine, and pairs with the acquire that ran before its accept.
func (s *Server) release() { <-s.slots }

// pause waits for d, or until the server stops. It reports false if the server
// stopped, so that a shutdown does not have to wait out an accept backoff.
func (s *Server) pause(d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-s.quit:
		return false
	}
}

// stopping reports whether Shutdown or Close has been called.
func (s *Server) stopping() bool {
	select {
	case <-s.quit:
		return true
	default:
		return false
	}
}

// addListener registers l, reporting false if the server has already stopped.
func (s *Server) addListener(l *onceListener) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.listeners[l] = struct{}{}
	return true
}

// removeListener deregisters l and closes it, which Serve does on every path out.
func (s *Server) removeListener(l *onceListener) {
	s.mu.Lock()
	delete(s.listeners, l)
	s.mu.Unlock()

	// onceListener is what makes this safe next to Shutdown, which has closed it
	// already: both get the same answer, and the descriptor is closed once.
	if err := l.Close(); err != nil {
		s.logf("closing listener %v: %v", l.Addr(), err)
	}
}

// track registers c and counts it, reporting false if the server has already
// stopped — in which case the caller, not the shutdown, has to end it.
func (s *Server) track(c *conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.conns[c] = struct{}{}

	// Counted here, under the same lock and behind the same check, because that is
	// what stops an Add from racing Shutdown's Wait. See the field's comment.
	s.connWG.Add(1)
	return true
}

// finish deregisters c and releases the shutdown's wait for it. Called only for a
// connection that track accepted.
func (s *Server) finish(c *conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
	s.connWG.Done()
}

// logf writes one line, or nothing at all if the server has no log.
func (s *Server) logf(format string, args ...any) {
	if s.log == nil {
		return
	}
	s.log.Printf(format, args...)
}

// nextAcceptDelay doubles d, starting at minAcceptDelay and stopping at
// maxAcceptDelay.
func nextAcceptDelay(d time.Duration) time.Duration {
	switch {
	case d <= 0:
		return minAcceptDelay
	case d >= maxAcceptDelay/2:
		return maxAcceptDelay
	default:
		return 2 * d
	}
}

// onceListener closes at most once, and reports the same result to every caller.
//
// Both Shutdown and Serve's own deferred close run on every shutdown, in an order
// neither controls. Without this, one of the two would report an error describing
// nothing but which of them got there first — and that error would go into a log as
// a shutdown failure.
type onceListener struct {
	net.Listener
	once sync.Once
	err  error
}

func (l *onceListener) Close() error {
	l.once.Do(func() { l.err = l.Listener.Close() })
	return l.err
}
