package server

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"zerodeps/zdh/internal/frame"
	"zerodeps/zdh/internal/h2"
	"zerodeps/zdh/internal/limits"
)

// connSocket is one connection: both halves, both deadlines, and the close.
// *tls.Conn and net.Conn both satisfy it.
//
// It is an interface for the same reason writeTarget is. A connection's
// interesting behaviour is almost entirely about what the socket does wrong — a
// peer that connects and says nothing, one that stops reading, one that vanishes
// mid-frame — and through a real socket those are arranged and hoped for rather
// than tested.
type connSocket interface {
	io.Reader
	writeTarget
	SetReadDeadline(t time.Time) error
	Close() error
}

// streamHandler receives the frames that belong to a stream rather than to the
// connection.
//
// The split is the whole design of this file. SETTINGS, PING, GOAWAY and a
// stream-0 WINDOW_UPDATE are the connection's own business and are answered here;
// DATA, HEADERS, PRIORITY, RST_STREAM and CONTINUATION are about one stream out of
// many and belong to the package that owns the stream table. Keeping the boundary
// in the type system rather than in a comment is what stops the connection from
// growing a stream table by accident, one special case at a time.
//
// Implementations are called from the connection's reader goroutine, in frame
// arrival order, and must not block indefinitely: this goroutine is also the one
// answering the peer's PINGs and noticing its GOAWAY.
type streamHandler interface {
	HandleFrame(f frame.Frame) error
}

// The four ways a connection ends with nobody at fault.
//
// Each is a distinct sentinel rather than a plain nil return, because the endings
// are not interchangeable in what they permit us to do next: a peer that closed
// its socket cannot be sent a GOAWAY, a peer that sent one has already said
// goodbye and is owed the courtesy of a reply, an idle connection is being closed
// by us and has to be told so it can retry elsewhere, and a connection we are
// shutting down owes the peer the same courtesy for a different reason.
// Collapsing them to nil would make Serve guess.
var (
	errPeerClosed   = errors.New("peer closed the connection")
	errPeerGoAway   = errors.New("peer sent GOAWAY")
	errIdle         = errors.New("connection idle")
	errShuttingDown = errors.New("server shutting down")
)

// readDeadlineKind says which of the connection's read deadlines the current read
// is running under.
//
// It is recorded when the deadline is set rather than worked out when the read
// fails, and that is not a micro-optimisation. Deciding afterwards means comparing
// the current time against the deadlines, and by then the clock has moved past
// both: a read that timed out on the SETTINGS-ack deadline is also, a moment
// later, past nothing in particular, and the comparison becomes a race whose
// wrong answer is the wrong error code on the wire.
type readDeadlineKind int

const (
	deadlinePreface readDeadlineKind = iota
	deadlineIdle
	deadlineSettingsAck
)

// conn is one HTTP/2 connection.
//
// The concurrency model is one reader goroutine — this one, running Serve — one
// writer goroutine owned by frameWriter, and, once internal/stream lands, one
// goroutine per open stream. This goroutine never writes to the socket; it
// enqueues.
type conn struct {
	sock    connSocket
	r       *frame.Reader
	w       *frameWriter
	handler streamHandler

	timeouts limits.Timeouts

	// settingsAckDue is when the peer's acknowledgement of our SETTINGS stops
	// being late and becomes a SETTINGS_TIMEOUT (§6.5.3). Zero means none is
	// outstanding.
	settingsAckDue time.Time

	// deadlineKind is which deadline the read in progress is running under.
	deadlineKind readDeadlineKind

	// gotSettings records that the peer's first frame was its SETTINGS, which
	// §3.4 requires before anything else.
	gotSettings bool

	// lastStreamID is the highest stream identifier this connection has
	// dispatched, which is what a GOAWAY has to carry: §6.8 makes it the promise
	// that everything above it was untouched and can be retried on a new
	// connection. Recorded at dispatch rather than on completion, because the
	// promise is about what we may have acted on, not what we finished.
	lastStreamID uint32

	// quit is closed by Shutdown to ask the read loop to stop. Every field above
	// belongs to the reader goroutine alone; these two are the only shared state
	// on the connection, because Shutdown is the only thing another goroutine
	// calls. See Shutdown for what deadlineMu orders and why nothing else here
	// needs a lock.
	quit     chan struct{}
	quitOnce sync.Once

	// deadlineMu orders the read deadline's two writers — the reader goroutine
	// arming the next one, and Shutdown bringing it forward — against each other.
	deadlineMu sync.Mutex
}

// newConn returns a connection over sock, with h receiving the stream-bearing
// frames. Unset timeouts take their defaults.
//
// A nil handler panics, deliberately and at construction. The alternative is a
// nil method call on the first HEADERS frame of the first request, which is the
// same bug reported later, from a goroutine further away, with a peer's traffic
// mixed into the stack trace.
func newConn(sock connSocket, h streamHandler, t limits.Timeouts) *conn {
	if h == nil {
		panic("server: newConn requires a stream handler")
	}
	t = t.WithDefaults()
	return &conn{
		sock:     sock,
		r:        frame.NewReader(sock, readerConfig()),
		w:        startFrameWriter(sock, t.Write),
		handler:  h,
		timeouts: t,
		quit:     make(chan struct{}),
	}
}

// readerConfig is the frame reader's bounds, taken from internal/limits.
//
// Every field is set explicitly even where the reader's own default matches,
// because the reader documents its defaults as fallbacks for a zero-valued config
// rather than as this server's policy. TestReaderConfigSetsEveryField fails if a
// field is added to frame.ReaderConfig and not wired up here, which is the
// failure this function exists to make loud: a new bound left at its fallback is
// a security decision made by omission.
func readerConfig() frame.ReaderConfig {
	return frame.ReaderConfig{
		MaxFrameSize:          limits.MaxFrameSize,
		MaxHeaderBlockSize:    limits.MaxHeaderBlockSize,
		MaxContinuationFrames: limits.MaxContinuationFrames,
	}
}

// initialSettings is the server connection preface (§3.4): the SETTINGS frame
// that must be the first thing this server sends.
//
// MAX_FRAME_SIZE is sent even though limits.MaxFrameSize is the protocol's
// initial value and therefore already in force. Stating it costs six octets once
// per connection and makes the advertised bound visible to a conformance suite
// and to a packet capture, which is worth more than the octets; and if the limit
// is ever raised, the frame that carries it is already here rather than being the
// thing someone forgot.
func initialSettings() frame.SettingsFrame {
	return frame.SettingsFrame{Settings: []frame.Setting{
		{ID: frame.SettingMaxFrameSize, Value: limits.MaxFrameSize},
		{ID: frame.SettingMaxConcurrentStreams, Value: limits.MaxConcurrentStreams},

		// This server does not push. §8.4 makes a PUSH_PROMISE from a client a
		// connection error regardless, so this is not the defence — it is the
		// statement that no promise from us will ever arrive, which lets a client
		// stop reserving anything for one.
		{ID: frame.SettingEnablePush, Value: 0},
	}}
}

// Serve runs the connection to completion and returns the reason it ended.
//
// It always closes the socket. It is the only exported entry point, because a
// connection is not a thing a caller drives frame by frame: it is handed a socket
// and given back the reason the socket is gone.
func (c *conn) Serve() error {
	defer c.sock.Close()

	err := c.run()

	// sendErr is a failure to deliver the final GOAWAY, kept apart from err
	// because it is a consequence of the ending rather than the ending itself.
	var sendErr error

	// gone records that the peer left before we did, which changes what a failure
	// to write the connection's last frames means. See the errPeerClosed case.
	var gone bool

	var ce h2.ConnError
	switch {
	case errors.Is(err, errPeerClosed):
		// No GOAWAY: there is nothing left to explain to a peer that has finished.
		// But what is already queued still goes out, and that is Shutdown rather
		// than Close for a reason. Those frames are answers to frames the peer
		// already sent — the acknowledgement of its SETTINGS, the reply to its PING
		// — and a peer that has closed only its sending half is still reading and
		// still owed them. Dropping them would also make the acknowledgement §6.5
		// requires depend on whether the peer's close arrived before or after the
		// writer got to it, which is not a thing the protocol should be decided by.
		c.w.Shutdown()
		gone = true
		err = nil

	case errors.Is(err, errPeerGoAway):
		// The peer's debug data is deliberately not echoed back. It is
		// peer-controlled, and reflecting untrusted octets to their sender is a
		// habit worth not having even where this one is harmless.
		sendErr = c.farewell(h2.NoError, "")
		err = nil

	case errors.Is(err, errIdle):
		sendErr = c.farewell(h2.NoError, "idle timeout")
		err = nil

	case errors.Is(err, errShuttingDown):
		// §6.8's graceful shutdown, minus the two-stage GOAWAY it recommends. A
		// server with streams in flight should send a first GOAWAY naming stream
		// 2^31-1, wait for the requests already on the wire to arrive, and only then
		// send the real last stream identifier; sending only the second one races
		// the client and loses whatever it had in flight. There are no streams on
		// this branch, so the last identifier is final the moment the read loop
		// stops and there is nothing for a first GOAWAY to hold open.
		// internal/stream owns the first one.
		sendErr = c.farewell(h2.NoError, "server shutting down")
		err = nil

	case errors.As(err, &ce):
		sendErr = c.farewell(ce.Code, ce.Reason)

	default:
		// A transport failure: the socket is broken, so there is no GOAWAY to
		// send and no point starting one.
		c.w.Close()
	}

	// The writer is always waited for, on every path, and that is what makes the
	// goroutine per connection bounded: Wait returns when the writer has stopped,
	// and the write deadline guarantees it stops.
	werr := c.w.Wait()
	switch {
	case err != nil:
		return err
	case sendErr != nil:
		return sendErr
	case gone:
		// The queued frames were flushed into a socket the peer had already closed,
		// so a failure to write them describes the peer's departure and not a fault
		// of this server's. Reporting it would mean logging an error for every
		// health check, load-balancer probe and port scan that connects and hangs
		// up, which is the one event on a public port that carries no information.
		return nil
	default:
		return werr
	}
}

// farewell enqueues the final GOAWAY and asks the writer to flush what is queued
// and stop.
//
// Shutdown is called whether or not the GOAWAY was accepted: if Enqueue failed
// the writer has already stopped and this is a no-op, and if it succeeded this is
// what gets the frame onto the wire before the socket closes.
func (c *conn) farewell(code h2.ErrCode, reason string) error {
	err := c.w.Enqueue(frame.GoAwayFrame{
		LastStreamID: c.lastStreamID,
		ErrCode:      code,
		Debug:        []byte(reason),
	})
	c.w.Shutdown()
	return err
}

// Shutdown asks the connection to stop serving. Serve then returns nil, having
// sent a GOAWAY with NO_ERROR: the difference between this and closing the socket
// is the difference between a server that says goodbye and one that looks crashed.
//
// It is safe to call from any goroutine, more than once, and after Serve has
// already returned — the accept layer calls it on every live connection at once,
// and cannot know which of them ended a microsecond earlier by itself.
//
// The reader goroutine is almost always parked in a socket read when this is
// called, and a channel it is not selecting on will not wake it. Bringing the read
// deadline forward will: the read fails with os.ErrDeadlineExceeded, and readError
// turns that into errShuttingDown rather than a timeout because the flag is set.
// That is what deadlineMu orders. Without it, this call could land between the
// loop's check of the flag and the loop arming its own deadline, and the reader
// would overwrite our interrupt with a deadline a full idle timeout away —
// a shutdown that returns in a minute instead of at once.
func (c *conn) Shutdown() {
	c.quitOnce.Do(func() { close(c.quit) })

	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if err := c.sock.SetReadDeadline(time.Now()); err != nil {
		// Nothing to do and nothing to report: a socket rejects a deadline once it
		// is closed, which is the state this call is asking for. The read it would
		// have interrupted has already finished.
		return
	}
}

// stopping reports whether Shutdown has been called.
func (c *conn) stopping() bool {
	select {
	case <-c.quit:
		return true
	default:
		return false
	}
}

// run is the connection's read loop. It returns the reason it stopped, which is
// one of the four sentinels above, an h2.ConnError, or a transport error.
func (c *conn) run() error {
	// Our SETTINGS goes out before the client's preface is read, not after.
	// §3.4 requires only that it be the first frame we send, and sending it
	// immediately lets a client that has already pipelined its requests learn our
	// limits without a round trip — and, less obviously, it means a peer that
	// never sends a preface can still be told why we hung up.
	if err := c.w.Enqueue(initialSettings()); err != nil {
		return err
	}

	if err := c.setReadDeadline(deadlinePreface); err != nil {
		return err
	}
	if err := c.r.ReadPreface(); err != nil {
		return c.readError(err)
	}

	// The §6.5.3 clock starts here and not next to the Enqueue above, because a
	// peer cannot acknowledge our SETTINGS before it has sent its own preface, so
	// there is nothing to measure until the preface is in. Starting it earlier
	// would also be actively wrong: the two defaults are both ten seconds, so a
	// peer that sent nothing at all would be told SETTINGS_TIMEOUT or
	// PROTOCOL_ERROR depending on which of two calls to time.Now ran first.
	c.settingsAckDue = time.Now().Add(c.timeouts.SettingsAck)

	for {
		// Checked before the read, not only after it. Shutdown's interrupt works on
		// a read that blocks, and a read does not block when the peer's octets are
		// already in the socket's receive buffer — which on a busy connection is the
		// usual case. Without this, a shutdown would serve however many frames the
		// kernel had already buffered before noticing.
		if c.stopping() {
			return errShuttingDown
		}
		if err := c.setReadDeadline(deadlineIdle); err != nil {
			return err
		}
		f, err := c.r.ReadFrame()
		if err != nil {
			return c.readError(err)
		}
		if err := c.dispatch(f); err != nil {
			var se h2.StreamError
			if !errors.As(err, &se) {
				return err
			}
			// A stream error takes one stream down and leaves the connection
			// serving the others (§5.4.2). Getting this wrong in the safe-looking
			// direction — treating it as fatal — turns one malformed PRIORITY
			// frame into a dropped connection and every other request on it.
			if err := c.w.Enqueue(frame.RSTStreamFrame{
				StreamID: se.StreamID,
				ErrCode:  se.Code,
			}); err != nil {
				return err
			}
		}
	}
}

// setReadDeadline sets the deadline for the next read and records which one it
// was.
//
// want is the deadline the loop is asking for; an outstanding SETTINGS
// acknowledgement can only bring it forward, never push it out. Two deadlines
// competing for one blocking read is the whole reason this is a function: the
// earlier of the two wins, and no timer goroutine is needed to enforce a deadline
// the socket is already enforcing.
func (c *conn) setReadDeadline(want readDeadlineKind) error {
	kind, deadline := want, c.deadlineFor(want)
	if !c.settingsAckDue.IsZero() {
		if due := c.deadlineFor(deadlineSettingsAck); due.Before(deadline) {
			kind, deadline = deadlineSettingsAck, due
		}
	}
	c.deadlineKind = kind

	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if c.stopping() {
		// Shutdown has already brought the deadline forward and this call would push
		// it back out. Deciding inside the lock is what makes the two orderings
		// equivalent: either Shutdown's deadline lands after ours and wins, or it
		// landed before and this branch repeats it.
		deadline = time.Now()
	}
	return c.sock.SetReadDeadline(deadline)
}

// deadlineFor is when a read running under kind expires.
//
// A function rather than three expressions inline, so that the acknowledgement
// deadline is computed the same way whether it was asked for or arrived by the
// comparison above.
func (c *conn) deadlineFor(kind readDeadlineKind) time.Time {
	switch kind {
	case deadlinePreface:
		return time.Now().Add(c.timeouts.Preface)
	case deadlineSettingsAck:
		return c.settingsAckDue
	default:
		return time.Now().Add(c.timeouts.Idle)
	}
}

// readError turns a failed read into the reason the connection ended.
func (c *conn) readError(err error) error {
	switch {
	case errors.Is(err, io.EOF):
		// Exactly at a frame boundary: the peer finished and left. Impolite
		// without a GOAWAY, but not an error. io.ErrUnexpectedEOF is deliberately
		// not folded in here — that is a frame cut in half, which is a broken
		// connection and gets reported as one.
		return errPeerClosed

	case errors.Is(err, os.ErrDeadlineExceeded):
		// An expired deadline on a connection that has been asked to stop is this
		// server's own interrupt arriving, not the peer being slow. Checked before
		// the kind, because the kind still names whichever deadline the loop last
		// armed — a shutdown would otherwise be reported as a preface timeout or an
		// idle one, and the peer would be told PROTOCOL_ERROR for our decision.
		if c.stopping() {
			return errShuttingDown
		}
		switch c.deadlineKind {
		case deadlineSettingsAck:
			// §6.5.3 names this specific failure and gives it its own code, which
			// is why the connection has to know which deadline expired rather
			// than just that one did.
			return h2.ConnErrorf(h2.SettingsTimeout,
				"no SETTINGS acknowledgement within %v (RFC 9113 §6.5.3)",
				c.timeouts.SettingsAck)
		case deadlinePreface:
			// §3.4 makes the preface mandatory but names no error code for its
			// absence, because a peer that has not sent it is not yet speaking
			// HTTP/2. PROTOCOL_ERROR is the closest honest description, and it is
			// worth sending: connect-and-say-nothing is the cheapest attack there
			// is, and a client hitting this for a legitimate reason — a proxy that
			// opened the socket early — gets told what was missing.
			return h2.ConnErrorf(h2.ProtocolError,
				"no connection preface within %v (RFC 9113 §3.4)", c.timeouts.Preface)
		default:
			return fmt.Errorf("%w: no frame within %v", errIdle, c.timeouts.Idle)
		}
	}
	return err
}

// dispatch routes one frame.
func (c *conn) dispatch(f frame.Frame) error {
	// §3.4: the client's preface is the 24 octets followed by a SETTINGS frame,
	// so the first frame on the connection is SETTINGS or the connection is not
	// an HTTP/2 connection.
	//
	// The ACK flag is not additionally forbidden here. Strictly the preface
	// SETTINGS carries the client's own parameters and an acknowledgement is a
	// different thing, but the RFC constrains the frame type and refusing the
	// flag would be a stricter reading with an interop cost and no defensive
	// gain: an ACK-flagged first frame is answered by the SETTINGS-ack clock
	// still running out, which is the same outcome by a better-specified route.
	if !c.gotSettings {
		if f.Type() != frame.TypeSettings {
			return h2.ConnErrorf(h2.ProtocolError,
				"first frame on the connection is %s, but RFC 9113 §3.4 requires SETTINGS",
				f.Type())
		}
		c.gotSettings = true
	}

	switch f := f.(type) {
	case frame.SettingsFrame:
		return c.handleSettings(f)

	case frame.PingFrame:
		return c.handlePing(f)

	case frame.GoAwayFrame:
		// Wrapped rather than returned bare so the log says what the peer said.
		// Debug is peer-controlled, so it is quoted rather than interpolated raw:
		// a peer must not be able to put control characters or forged lines into
		// our output.
		return fmt.Errorf("%w: %s: %q", errPeerGoAway, f.ErrCode, f.Debug)

	case frame.PushPromiseFrame:
		// §8.4: a client cannot push, so a server must treat a PUSH_PROMISE as a
		// connection error. Our own SETTINGS_ENABLE_PUSH of 0 says the same thing
		// from the other direction. This is a connection-level role violation
		// rather than anything to do with the promised stream, which is why it is
		// answered here and not by the stream table.
		return h2.ConnErrorf(h2.ProtocolError,
			"PUSH_PROMISE received on stream %d: a client cannot push (RFC 9113 §8.4)",
			f.Stream())

	case frame.WindowUpdateFrame:
		if f.StreamID == 0 {
			return c.handleConnectionWindowUpdate(f)
		}
	}

	return c.handleStreamFrame(f)
}

// handleSettings applies the peer's parameters and acknowledges them, or absorbs
// the peer's acknowledgement of ours.
func (c *conn) handleSettings(f frame.SettingsFrame) error {
	if f.Ack {
		// This is what stops the §6.5.3 clock. An acknowledgement with none
		// outstanding is not made an error: the RFC does not name one, and this
		// is already a no-op, so refusing it would be inventing a way to break a
		// connection.
		c.settingsAckDue = time.Time{}
		return nil
	}

	// §6.5 requires the values to be in force before the acknowledgement is sent,
	// because the acknowledgement is the peer's licence to assume they are. Hence
	// the loop before the Enqueue, and not the other way round.
	for _, s := range f.Settings {
		c.applySetting(s)
	}
	return c.w.Enqueue(frame.SettingsFrame{Ack: true})
}

// applySetting puts one of the peer's parameters into force.
//
// Every identifier §11.3 defines is named, including the ones there is nothing to
// do about, so that "ignored" is a decision on the record rather than a gap.
// TestApplySettingNamesEverySettingID fails if an identifier is added to the
// frame package and not accounted for here. An unknown identifier is ignored, as
// §6.5.2 requires — the extension mechanism depends on it.
func (c *conn) applySetting(s frame.Setting) {
	switch s.ID {
	case frame.SettingMaxFrameSize:
		// The largest payload we may send from now on. Safe to set while the
		// writer goroutine is mid-burst; see frame.Writer.SetMaxFrameSize.
		c.w.SetMaxFrameSize(s.Value)

	case frame.SettingEnablePush, frame.SettingMaxConcurrentStreams:
		// Nothing to apply. Both bound what a server that initiates streams may
		// do, and this server initiates none: it does not push, and says so in
		// its own SETTINGS. A client that sets ENABLE_PUSH to 1 gets no pushes
		// anyway, which is permitted — the setting is a ceiling, not a request.

	case frame.SettingHeaderTableSize, frame.SettingMaxHeaderListSize:
		// Both belong to the HPACK encoder, which does not exist on this branch
		// yet. HEADER_TABLE_SIZE reaches it through
		// h2.HeaderCodec.SetMaxDynamicTableSize; MAX_HEADER_LIST_SIZE bounds the
		// decoded size of a response's header list and has to be enforced where
		// the list is built. Both are internal/hpack's, and neither can be
		// obeyed or disobeyed until this connection sends a response.

	case frame.SettingInitialWindowSize:
		// internal/flow's, and it is the awkward one: §6.9.2 requires the change
		// to be applied to every open stream's window as a delta, not just to
		// streams opened afterwards, and a change that pushes a window negative
		// is legal and must be tolerated. There are no streams and no windows on
		// this branch, so there is nothing to adjust yet.
	}
}

// handlePing answers the peer's PING. This is matrix row 24.
//
// A flood needs no rate limiter of its own, and that is worth stating because the
// absence looks like an omission next to the reset bucket. Each reply is enqueued
// on the writer's bounded queue, and Enqueue blocks when that queue is full —
// which stops this goroutine, which is the same goroutine that reads the flood.
// The peer's own PINGs therefore throttle themselves to the rate we can write,
// and the write deadline bounds how long a peer that has stopped reading can hold
// us there. A token bucket would add a second, weaker bound underneath a
// sufficient one.
func (c *conn) handlePing(f frame.PingFrame) error {
	if f.Ack {
		// A reply to a PING we sent, and we send none. Not an error: a peer is
		// entitled to have sent one before we decided that, and §6.7 gives no
		// code for an unsolicited acknowledgement.
		return nil
	}
	// §6.7: the same eight octets back, with ACK set. PingFrame.Data is an array,
	// so this copies rather than aliasing the reader's scratch buffer — which
	// matters, because that buffer is overwritten by the next frame.
	return c.w.Enqueue(frame.PingFrame{Ack: true, Data: f.Data})
}

// handleConnectionWindowUpdate credits the connection-level flow-control window.
//
// The window itself is internal/flow's, and so are matrix rows 30 and 31: a
// WINDOW_UPDATE that takes a window above 2^31-1 is a FLOW_CONTROL_ERROR, at the
// connection level for stream 0 and at the stream level otherwise. Nothing on this
// branch sends DATA, so there is no window yet to credit or to overflow, and
// tracking one here would mean two packages owning the same counter — the version
// that is never spent looks maintained and is not.
//
// The parameter is unused and named so, rather than the routing being left out
// until there is a window: a stream-0 frame has no stream to hand it to, and the
// alternative to absorbing it here is the stream layer growing a special case for
// stream zero, which is where flow control gets tangled up with the stream table
// in every implementation that has done it that way.
func (c *conn) handleConnectionWindowUpdate(_ frame.WindowUpdateFrame) error {
	return nil
}

// handleStreamFrame hands a frame to the stream layer.
func (c *conn) handleStreamFrame(f frame.Frame) error {
	if id := f.Stream(); id > c.lastStreamID {
		c.lastStreamID = id
	}
	return c.handler.HandleFrame(f)
}
