package stream

import (
	"time"

	"zerodeps/zdh/internal/flow"
	"zerodeps/zdh/internal/frame"
	"zerodeps/zdh/internal/h2"
	"zerodeps/zdh/internal/limits"
)

// Config configures a Table. Codec and Requests are required; everything else
// takes a documented default.
type Config struct {
	// Codec is the connection's HPACK decoder for the peer's direction. It is
	// driven in strict frame arrival order and must not be shared with another
	// connection — see h2.HeaderCodec.
	Codec h2.HeaderCodec

	// Requests receives the decoded requests.
	Requests Requests

	// MaxConcurrent is the SETTINGS_MAX_CONCURRENT_STREAMS this connection
	// advertised. Zero takes limits.MaxConcurrentStreams.
	//
	// It has to be the advertised value and not merely a bound we like, because
	// §5.1.2 lets a peer open exactly as many streams as it was promised: a table
	// enforcing a lower number would refuse streams the peer was entitled to open
	// and had no way to know were unwelcome.
	MaxConcurrent uint32

	// Now is the clock the RST_STREAM rate limit runs on. Nil takes time.Now.
	//
	// Injected because the alternative for testing a rate limit is a test that
	// sleeps, and a test that sleeps is a test that is either slow or flaky
	// depending on the machine.
	Now func() time.Time
}

// Table is the stream table for one connection.
//
// It satisfies internal/server's stream-handler interface: HandleFrame for the
// frames that name a stream, and ConnWindowUpdate and SetInitialWindowSize for
// the two connection-level frames whose effect is entirely on streams.
type Table struct {
	codec h2.HeaderCodec
	reqs  Requests
	now   func() time.Time

	maxConcurrent uint32

	// streams holds every stream that is neither idle nor closed, which is
	// exactly the set §5.1.2 counts against SETTINGS_MAX_CONCURRENT_STREAMS. So
	// there is no separate counter to keep in step with the map, and len is the
	// answer to the concurrency question by construction rather than by
	// maintenance.
	streams map[uint32]*Stream

	// highestRemote is the largest stream identifier the peer has opened.
	//
	// This one field is the whole of §5.1.1's bookkeeping. It rejects an
	// identifier that is not increasing, and it is what lets StateOf tell a
	// closed stream from an idle one without storing closed streams: below it,
	// absent from the map, means closed — either it ran its course or it was one
	// of the identifiers the peer skipped, which §5.1.1 closes implicitly.
	highestRemote uint32

	// connRecv is the connection's receive window, debited by every DATA frame
	// that arrives. connSend is the peer's grant to us, credited by a stream-0
	// WINDOW_UPDATE and spent by response bodies.
	//
	// The connection windows live here rather than on the connection because this
	// is where DATA is seen and where the streams that spend the send window are.
	// internal/server holds neither and forwards the stream-0 WINDOW_UPDATE.
	connRecv *flow.Window
	connSend *flow.Window

	// peerInitialWindow is the peer's current SETTINGS_INITIAL_WINDOW_SIZE, which
	// sizes the send window of every stream opened from now on. §6.9.2 applies a
	// change to existing streams as a delta and to new ones as their starting
	// size, so both the value and the deltas have to be kept.
	peerInitialWindow uint32

	// resets rate-limits RST_STREAM (CVE-2023-44487).
	resets *limits.Bucket

	// assembling is the header block being reassembled from a HEADERS frame and
	// the CONTINUATION frames after it, or nil.
	//
	// One pointer is enough for the whole connection because §6.10 forbids any
	// other frame between them, and frame.Reader enforces that before anything
	// reaches here. A table that kept a partial block per stream would be
	// modelling a state the protocol does not have.
	assembling *block
}

// block is a header block under reassembly.
type block struct {
	id uint32

	// s is the stream a trailer section belongs to, and nil for the block that
	// opens a request. It doubles as the flag for which of the two this is,
	// because a lookup deferred to the end of the block is a lookup that has to
	// handle a stream that vanished in between — which cannot happen, and so
	// would be an unreachable branch carried for ever.
	s *Stream

	buf []byte

	// endStream is the END_STREAM flag of the HEADERS frame that began the block.
	// It is on the first frame, not the last, so it has to be carried.
	//
	// Read only for a block that opens a request. A trailer section ends its
	// stream by §8.1 whatever the flag says, and beginTrailers has already made
	// one without END_STREAM a stream error, so completeBlock does not consult
	// this for a trailer block. It is recorded for both kinds all the same: a
	// field that is true of one kind and false-by-omission of the other is a
	// field every reader has to go and check the constructor for.
	endStream bool

	// verdict is a stream-level error found when the block opened and held until
	// it closes. See Table.headers.
	verdict error
}

// New returns a stream table.
//
// A missing codec or Requests panics, at construction. Both are dereferenced on
// the first request of the connection, so the alternative is the same bug
// reported later, from the reader goroutine, with a peer's traffic in the stack
// trace.
func New(cfg Config) *Table {
	if cfg.Codec == nil {
		panic("stream: New requires a header codec")
	}
	if cfg.Requests == nil {
		panic("stream: New requires a Requests")
	}
	if cfg.MaxConcurrent == 0 {
		cfg.MaxConcurrent = limits.MaxConcurrentStreams
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Table{
		codec:         cfg.Codec,
		reqs:          cfg.Requests,
		now:           cfg.Now,
		maxConcurrent: cfg.MaxConcurrent,
		streams:       make(map[uint32]*Stream),
		connRecv:      flow.NewConnWindow(),
		connSend:      flow.NewConnWindow(),

		// The protocol's initial value, which both ends must assume until a
		// SETTINGS frame says otherwise (§6.9.2). Not configurable, because the
		// peer's setting arrives on the wire and ours governs the other direction.
		peerInitialWindow: flow.InitialWindowSize,

		resets: limits.NewResetBucket(cfg.Now()),
	}
}

// Len is how many streams count toward SETTINGS_MAX_CONCURRENT_STREAMS (§5.1.2):
// those open or in either half-closed state.
func (t *Table) Len() int { return len(t.streams) }

// SendWindow is the connection's send window, which every response body is
// debited from in addition to its own stream's (§6.9).
func (t *Table) SendWindow() *flow.Window { return t.connSend }

// RecvWindow is the connection's receive window, which every DATA frame that
// arrives has already been debited from.
func (t *Table) RecvWindow() *flow.Window { return t.connRecv }

// StateOf is the state of stream id (§5.1).
//
// It is the one place the three-way distinction between a live stream, a closed
// one and an idle one is made, and the reason it can be made at all without
// remembering closed streams:
//
//   - in the map: whatever state it says.
//   - even-numbered: idle, always. §5.1.1 reserves even identifiers for the
//     server, and this server never opens one, so no even stream is ever anything
//     else for the life of the connection.
//   - above the highest identifier the peer has used: idle, not yet used.
//   - at or below it, and absent from the map: closed. Either it finished, or it
//     was skipped, and §5.1.1 makes a skipped identifier closed the moment a
//     higher one is used.
func (t *Table) StateOf(id uint32) State {
	if s := t.streams[id]; s != nil {
		return s.state
	}
	if id%2 == 0 {
		return StateIdle
	}
	if id > t.highestRemote {
		return StateIdle
	}
	return StateClosed
}

// Stream is the live stream with identifier id, or nil if it is idle or closed.
func (t *Table) Stream(id uint32) *Stream { return t.streams[id] }

// SendEnd records that this server has sent END_STREAM on s, which is the other
// half of §5.1's two-sided close.
//
// On the Table rather than on the Stream, and not for symmetry: a stream that
// closes has to leave the table, and only the table can remove it. Leaving that
// to the caller would make the concurrency limit depend on every response path
// remembering to do it, and the symptom of one that forgot is a connection that
// refuses new streams after exactly SETTINGS_MAX_CONCURRENT_STREAMS requests,
// however long ago they finished.
//
// It takes the Stream rather than an identifier because the caller is the
// goroutine writing that stream's response and already holds it, and because an
// identifier would have to be looked up and found absent — which is not an error
// worth a return value on a method whose whole job is bookkeeping.
func (t *Table) SendEnd(s *Stream) {
	if s.state == StateHalfClosedRemote {
		// The peer had already finished, so this closes the stream outright.
		s.state = StateClosed
		t.retire(s)
		return
	}
	s.state = StateHalfClosedLocal
}

// HandleFrame dispatches one frame that names a stream.
//
// Every error returned carries its own scope, as h2.StreamError or h2.ConnError,
// which is what lets internal/server answer one with RST_STREAM and the other
// with GOAWAY without knowing a single protocol rule.
func (t *Table) HandleFrame(f frame.Frame) error {
	switch v := f.(type) {
	case frame.HeadersFrame:
		return t.headers(v)
	case frame.ContinuationFrame:
		return t.continuation(v)
	case frame.DataFrame:
		return t.data(v)
	case frame.RSTStreamFrame:
		return t.rstStream(v)
	case frame.PriorityFrame:
		return t.priority(v)
	case frame.WindowUpdateFrame:
		return t.windowUpdate(v)
	default:
		// Not reachable from internal/server, which answers SETTINGS, PING,
		// GOAWAY, PUSH_PROMISE and the stream-0 WINDOW_UPDATE itself, and from a
		// reader that discards unknown frame types (§4.1). So this is our own
		// dispatch having grown a hole rather than anything a peer can provoke,
		// and INTERNAL_ERROR says exactly that. Silently returning nil would make
		// a frame type added to internal/frame and forgotten here into a frame
		// the server accepts and ignores.
		return h2.ConnErrorf(h2.InternalError,
			"frame type %s on stream %d reached the stream table", f.Type(), f.Stream())
	}
}

// ConnWindowUpdate applies a stream-0 WINDOW_UPDATE to the connection's send
// window (§6.9).
//
// The frame is read by internal/server, which owns the connection's own frames,
// and forwarded here because the window it credits is spent by streams. An
// increment that would take the window above 2^31-1 is a connection error of type
// FLOW_CONTROL_ERROR, and internal/flow returns it at that scope because it is the
// connection's window — this method adds nothing to the decision.
func (t *Table) ConnWindowUpdate(increment uint32) error {
	return t.connSend.Increase(increment)
}

// SetInitialWindowSize applies the peer's SETTINGS_INITIAL_WINDOW_SIZE (§6.9.2).
//
// §6.9.2 makes the change a delta on every stream that is already open and the
// starting size for every stream opened afterwards, so both happen here. The
// alternative — recording the value and letting each stream notice — is the bug
// the RFC spends a paragraph warning about: a stream that applied the new size as
// an assignment would hand itself back the credit it had already spent.
func (t *Table) SetInitialWindowSize(n uint32) error {
	for _, s := range t.streams {
		if err := s.send.SetInitialSize(n); err != nil {
			// Connection-scoped, from internal/flow, because the fault is in a
			// SETTINGS frame. The streams iterated before this one keep the new
			// size while the rest do not, and that is not worth unwinding: the
			// connection is ending, and a map's iteration order makes "the rest"
			// undefined anyway. peerInitialWindow below is left alone for the same
			// reason — tidiness, not a guard, since no stream can be opened after
			// a connection error to be sized from it.
			return err
		}
	}
	t.peerInitialWindow = n
	return nil
}

// headers begins a header block, either opening a stream or starting a trailer
// section.
//
// Nothing is delivered here. A HEADERS frame without END_HEADERS is the front of
// a block that continues in CONTINUATION frames, so the decision this frame
// implies cannot be acted on until the block is complete — and, more than that, a
// stream-level fault found here cannot even be *reported* here. §5.1 requires the
// header compression state to be updated for a block whose stream is gone, so a
// refused stream's block still has to be decoded, and returning the stream error
// now would abandon the octets and desynchronise the HPACK table for every
// request after it. The verdict is therefore recorded on the block and returned
// when the block closes, after the decode. Connection-level faults are returned
// immediately, because a connection error means there is no request after it to
// desynchronise.
func (t *Table) headers(f frame.HeadersFrame) error {
	if t.assembling != nil {
		// Not reachable through frame.Reader, which enforces §6.10's continuity
		// rule and refuses any frame but a CONTINUATION on the same stream while
		// a block is open. Named rather than trusted, because the alternative if
		// that ever changes is two requests' fragments concatenated into one
		// block, which HPACK decodes into a request neither peer sent.
		return h2.ConnErrorf(h2.ProtocolError,
			"HEADERS on stream %d while stream %d's header block is open (RFC 9113 §6.10)",
			f.StreamID, t.assembling.id)
	}
	if s := t.streams[f.StreamID]; s != nil {
		return t.beginTrailers(f, s)
	}
	return t.openStream(f)
}

// openStream begins the block of a request on a stream that is not yet live.
func (t *Table) openStream(f frame.HeadersFrame) error {
	// §5.1.1's two rules about the identifier, both connection errors, and both
	// checked before the state is consulted because they are the more specific
	// reading of the same fault. An even identifier is not an idle stream the
	// client may open; it is a stream only this server could open, and this
	// server does not push.
	if f.StreamID%2 == 0 {
		return h2.ConnErrorf(h2.ProtocolError,
			"HEADERS on even-numbered stream %d, which only a server may open (RFC 9113 §5.1.1)",
			f.StreamID)
	}
	if f.StreamID <= t.highestRemote {
		return h2.ConnErrorf(h2.ProtocolError,
			"HEADERS on stream %d, which is not above stream %d already used by the peer (RFC 9113 §5.1.1)",
			f.StreamID, t.highestRemote)
	}

	// Recorded now, before the stream is admitted and whether or not it is. The
	// promise §5.1.1 makes is about identifiers the peer has used, not about
	// streams that went on to succeed: a peer that has a stream refused does not
	// reuse the number, and every lower idle identifier is closed from here on
	// whatever this stream's fate.
	t.highestRemote = f.StreamID

	t.assembling = &block{
		id:        f.StreamID,
		endStream: f.EndStream,
		verdict:   t.admit(f),
	}
	return t.extend(f.Fragment, f.EndHeaders)
}

// admit is the stream-level verdict on a new stream: nil to accept it, or the
// error to answer the completed block with.
func (t *Table) admit(f frame.HeadersFrame) error {
	// §5.3.1 of RFC 7540: a stream cannot depend on itself. RFC 9113 withdrew the
	// scheme without replacing the rule, and this server keeps the stricter
	// reading — the frame is malformed either way, conformance suites still test
	// it, and accepting it costs nothing but is one more nonsense a peer learns is
	// tolerated.
	//
	// It is enforced here rather than in internal/frame, which is the one priority
	// rule that parser deliberately leaves alone: rejecting the frame there means
	// discarding its header block fragment, and §5.4.2 requires the compression
	// state to be maintained even for a stream that is about to be reset. So the
	// check belongs where the block survives the verdict, which is here.
	if f.Priority && f.StreamDependency == f.StreamID {
		return h2.StreamErrorf(f.StreamID, h2.ProtocolError,
			"stream %d depends on itself (RFC 7540 §5.3.1)", f.StreamID)
	}

	// §5.1.2. REFUSED_STREAM rather than PROTOCOL_ERROR, of the two the RFC
	// offers, because they mean different things to the client: §8.7 makes
	// REFUSED_STREAM the code that promises the request was not processed, so a
	// client may retry it safely even if it was not idempotent. PROTOCOL_ERROR
	// would tell a well-behaved client its request was malformed, when in truth
	// this server was simply full.
	if uint32(len(t.streams)) >= t.maxConcurrent {
		return h2.StreamErrorf(f.StreamID, h2.RefusedStream,
			"stream %d would exceed the %d concurrent streams advertised (RFC 9113 §5.1.2)",
			f.StreamID, t.maxConcurrent)
	}
	return nil
}

// beginTrailers begins the block of a trailer section on a live stream (§8.1).
func (t *Table) beginTrailers(f frame.HeadersFrame, s *Stream) error {
	var verdict error
	switch {
	case s.peerDone():
		verdict = h2.StreamErrorf(f.StreamID, h2.StreamClosed,
			"HEADERS on stream %d in state %s (RFC 9113 §5.1)", f.StreamID, s.state)

	case !f.EndStream:
		// §8.1: the trailer section is the last thing on a stream, so the frame
		// that carries it must end the stream. Without END_STREAM this is a third
		// header block waiting to happen, and there is no such thing in HTTP/2.
		verdict = h2.StreamErrorf(f.StreamID, h2.ProtocolError,
			"trailers on stream %d without END_STREAM (RFC 9113 §8.1)", f.StreamID)
	}

	t.assembling = &block{
		id:        f.StreamID,
		s:         s,
		endStream: f.EndStream,
		verdict:   verdict,
	}
	return t.extend(f.Fragment, f.EndHeaders)
}

// continuation extends the open block (§6.10).
func (t *Table) continuation(f frame.ContinuationFrame) error {
	if t.assembling == nil {
		// Not reachable through frame.Reader, which refuses a CONTINUATION with
		// no block open. Named for the same reason as its counterpart in headers:
		// a fragment decoded on its own is a corrupt dynamic table, and every
		// request after it on the connection is then decoded into something the
		// peer did not send.
		return h2.ConnErrorf(h2.ProtocolError,
			"CONTINUATION on stream %d with no header block open (RFC 9113 §6.10)",
			f.StreamID)
	}
	if f.StreamID != t.assembling.id {
		// Also the reader's rule and also named here. It matters more than the
		// case above: the fragments would concatenate into a block that decodes
		// cleanly, so the failure would be a request assembled from two, with no
		// symptom until something downstream disagreed about it.
		return h2.ConnErrorf(h2.ProtocolError,
			"CONTINUATION on stream %d while stream %d's header block is open (RFC 9113 §6.10)",
			f.StreamID, t.assembling.id)
	}
	return t.extend(f.Fragment, f.EndHeaders)
}

// extend appends a fragment to the open block and completes it on END_HEADERS.
//
// There is no size bound here, and that is not an omission. The bound is on the
// whole block, and frame.Reader holds the running total across the HEADERS frame
// and every CONTINUATION after it — limits.MaxHeaderBlockSize and
// limits.MaxContinuationFrames, the pair that answers CVE-2023-45288. A second
// bound here would be a second number to keep in step with the first, and the
// symptom of them disagreeing is a block the reader accepted and the table threw
// away.
func (t *Table) extend(fragment []byte, endHeaders bool) error {
	t.assembling.buf = append(t.assembling.buf, fragment...)
	if !endHeaders {
		return nil
	}
	return t.completeBlock()
}

// completeBlock decodes the assembled block and delivers it, or returns the
// verdict recorded when it opened.
func (t *Table) completeBlock() error {
	b := t.assembling

	// Cleared before anything that can fail. Every path out of here is either a
	// delivered request or an error, and none of them leaves a block open — an
	// error that left one would make the next HEADERS frame on the connection
	// report the unreachable case in headers instead of the real fault.
	t.assembling = nil

	// The decode comes before the verdict, and that ordering is the reason the
	// verdict was deferred at all. §5.1 requires header compression state to be
	// updated even for a stream that is closed or about to be, so a block whose
	// stream was refused is still decoded and its dynamic table updates still
	// applied. Returning b.verdict first would skip the decode and leave the
	// table one insertion behind the peer's, which is not a recoverable state:
	// every later block on the connection decodes into different header fields.
	fields, err := t.codec.Decode(b.buf)
	if err != nil {
		// §4.3, and the one error in this file whose scope is not a judgement
		// call: a block that cannot be decoded leaves the dynamic table in an
		// unknown state, so there is no way to carry on with the connection at
		// all, whatever happens to the stream.
		return h2.ConnErrorf(h2.CompressionError,
			"HPACK decoding failed on stream %d: %v (RFC 9113 §4.3)", b.id, err)
	}
	if b.verdict != nil {
		return b.verdict
	}

	if b.s != nil {
		// Trailers, and they always end the request: beginTrailers made a block
		// without END_STREAM a stream error, so reaching here with a live verdict
		// of nil means the flag was set.
		b.s.recvEnd()
		t.retire(b.s)
		return t.reqs.Trailers(b.s, fields)
	}

	s := &Stream{
		id:    b.id,
		state: StateOpen,

		// Our grant to the peer, at the initial size §6.9.2 makes both ends
		// assume. This server never sends SETTINGS_INITIAL_WINDOW_SIZE, so there
		// is no other value it could be, and
		// TestInitialSettingsDoesNotSetTheInitialWindowSize in internal/server
		// fails if that ever stops being true without this following it.
		recv: flow.NewStreamWindow(b.id, flow.InitialWindowSize),

		// The peer's grant to us, at whatever it last advertised.
		send: flow.NewStreamWindow(b.id, t.peerInitialWindow),
	}
	t.streams[b.id] = s

	// The state is settled before the request is delivered, so that a handler
	// asking whether the body is finished gets the answer the wire gave rather
	// than the one that was true a moment ago. It is not retired even when it is
	// half-closed: §5.1.2 counts a half-closed stream against the concurrency
	// limit, because this server still owes it a response.
	if b.endStream {
		s.recvEnd()
	}
	return t.reqs.Headers(s, fields, b.endStream)
}

// data applies one DATA frame: flow control first, then the stream's state.
func (t *Table) data(f frame.DataFrame) error {
	// The connection window is debited before anything else is known about the
	// frame, and §6.9.1 is explicit that this is required rather than convenient:
	// "A receiver that receives a flow-controlled frame MUST always account for
	// its contribution against the connection flow-control window, unless the
	// receiver treats this as a connection error." A frame dropped without being
	// counted leaves the two ends disagreeing about the connection's credit by
	// its length, permanently, and the symptom is a transfer that stalls much
	// later for no visible reason.
	//
	// PayloadLen rather than len(f.Data), because §6.1 counts the padding and the
	// Pad Length octet too. The peer's own accounting is of the frame as it was
	// sent, and a receiver that counted only the body would drift by the padding.
	n := f.PayloadLen()
	if err := t.connRecv.Consume(n); err != nil {
		return err
	}

	s := t.streams[f.StreamID]
	if s == nil {
		return t.absent("DATA", f.StreamID)
	}
	if s.peerDone() {
		return h2.StreamErrorf(f.StreamID, h2.StreamClosed,
			"DATA on stream %d in state %s (RFC 9113 §5.1)", f.StreamID, s.state)
	}
	if err := s.recv.Consume(n); err != nil {
		return err
	}

	if f.EndStream {
		s.recvEnd()
		t.retire(s)
	}
	return t.reqs.Data(s, f.Data, f.EndStream)
}

// rstStream ends a stream at the peer's request (§6.4).
func (t *Table) rstStream(f frame.RSTStreamFrame) error {
	if t.StateOf(f.StreamID) == StateIdle {
		// §6.4 in as many words: "RST_STREAM frames MUST NOT be sent for a stream
		// in the 'idle' state. If a RST_STREAM frame identifying an idle stream is
		// received, the recipient MUST treat this as a connection error of type
		// PROTOCOL_ERROR." This is frame-layer matrix row 13, which internal/frame
		// defers here because deciding it needs the stream table.
		//
		// Checked before the rate limit below so that one malformed frame is
		// reported as the protocol violation it is rather than as a flood.
		return h2.ConnErrorf(h2.ProtocolError,
			"RST_STREAM on idle stream %d (RFC 9113 §6.4)", f.StreamID)
	}

	// CVE-2023-44487. A stream reset immediately after its HEADERS costs this
	// server a request's work and costs the peer nothing, and frees the
	// concurrency slot at once — so SETTINGS_MAX_CONCURRENT_STREAMS bounds how
	// many requests are in flight but not how many arrive per second. The token
	// bucket bounds the rate, and the burst is what a browser cancelling a page
	// of subresources legitimately needs.
	//
	// It is counted for a reset of an already-closed stream as well as a live one.
	// Those cost less, but they still cost a frame's processing, and a limiter
	// with a free case is a limiter with a way around it.
	if !t.resets.Allow(t.now()) {
		return h2.ConnErrorf(h2.EnhanceYourCalm,
			"more than %d stream resets in a burst (CVE-2023-44487)", t.resets.Burst())
	}

	s := t.streams[f.StreamID]
	if s == nil {
		// Closed already, which §5.1 anticipates rather than punishes: we may have
		// reset it ourselves a moment ago, and §6.4 tells the sender of a
		// RST_STREAM to "be prepared to receive and process additional frames" for
		// exactly the same reason in the other direction. There is nobody left to
		// tell and nothing to do.
		return nil
	}

	s.state = StateClosed
	t.retire(s)
	t.reqs.Canceled(s, f.ErrCode)
	return nil
}

// priority accepts a PRIORITY frame and does nothing with it.
//
// §5.3 withdrew the dependency-tree scheme this frame carries and RFC 9218
// replaces it with a mechanism this server does not implement, so there is
// nothing to record. internal/frame has already rejected the two ways the frame
// can be malformed — stream 0, and a self-dependency — which is why there is not
// even a validation left here.
//
// Nothing about the stream table is touched, and in particular the identifier is
// not recorded as used. §5.1 keeps PRIORITY legal "in any stream state" and does
// not make it open a stream, so a PRIORITY frame on an idle stream leaves it
// idle: treating it as a use of the identifier would make the HEADERS frame that
// arrives next look like a reused one and be refused under §5.1.1.
func (t *Table) priority(frame.PriorityFrame) error { return nil }

// windowUpdate credits a stream's send window (§6.9).
func (t *Table) windowUpdate(f frame.WindowUpdateFrame) error {
	s := t.streams[f.StreamID]
	if s == nil {
		if t.StateOf(f.StreamID) == StateIdle {
			return h2.ConnErrorf(h2.ProtocolError,
				"WINDOW_UPDATE on idle stream %d (RFC 9113 §5.1)", f.StreamID)
		}
		// §6.9 exempts this case by name: a WINDOW_UPDATE may arrive on a stream
		// in the half-closed (remote) or closed state, because the peer sent it
		// before it knew the stream was over, and "a receiver MUST NOT treat this
		// as an error". There is no window left to credit.
		return nil
	}
	return s.send.Increase(f.Increment)
}

// absent is the error for a frame naming a stream that is not live: a connection
// error if the identifier has never been used, a stream error if it is over.
//
// The split is §5.1's, and the lenient half of it is a deliberate choice. §5.1
// permits a connection error of type STREAM_CLOSED for a frame on a closed
// stream, and this server answers with a stream error instead, because it cannot
// tell the two reasons apart: a stream we reset a moment ago and a stream that
// finished cleanly are both simply absent from the table, and the peer's DATA was
// already on the wire when we reset it. Ending the connection over that would be
// ending it over a race this server started.
func (t *Table) absent(kind string, id uint32) error {
	if t.StateOf(id) == StateIdle {
		return h2.ConnErrorf(h2.ProtocolError,
			"%s on idle stream %d (RFC 9113 §5.1)", kind, id)
	}
	return h2.StreamErrorf(id, h2.StreamClosed,
		"%s on closed stream %d (RFC 9113 §5.1)", kind, id)
}

// retire drops a stream from the table once it has closed.
//
// Called wherever a state changes rather than folded into the state change,
// because two of the transitions to closed are not state changes at all: a
// RST_STREAM sets the state directly, and recvEnd only reaches closed from
// half-closed (local). Keeping the removal at the call sites is what makes the
// map's invariant — nothing closed, nothing idle — one line to check.
func (t *Table) retire(s *Stream) {
	if s.state == StateClosed {
		delete(t.streams, s.id)
	}
}
