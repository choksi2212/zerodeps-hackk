// Package stream owns a connection's streams: the identifier rules of RFC 9113
// §5.1.1, the state machine of §5.1, the concurrency limit of §5.1.2, the
// reassembly of header blocks split across CONTINUATION frames, and the
// per-stream half of flow control.
//
// It sits between internal/server, which owns the socket and the frames that
// belong to the connection as a whole, and the layer that turns a decoded header
// block into a response. Table satisfies the server's stream-handler interface,
// so the connection hands it every frame that names a stream and never learns
// what a stream is.
//
// # What is not here
//
// There are no reserved states. §5.1 defines "reserved (local)" and "reserved
// (remote)" for server push, and this server does not push: it advertises
// SETTINGS_ENABLE_PUSH 0, and §8.4 makes a PUSH_PROMISE from a client a
// connection error, which internal/server rejects before anything reaches here.
// So no stream can enter either state on any connection this server serves, and
// the two states are absent rather than present and unreachable. An unreachable
// state is a branch no test can cover and every reader has to reason about.
//
// There is no prioritisation. §5.3 withdrew RFC 7540's dependency tree and
// RFC 9218 replaces it with a scheme this server does not implement, so PRIORITY
// frames are accepted, validated by internal/frame, and then affect nothing.
//
// # Why the table decodes HPACK
//
// Decoding looks like the business of the layer above, and it is not. §5.1
// requires an endpoint to "minimally process and then discard" frames on a
// closed stream, and says what that means: "updating header compression state
// for HEADERS and PUSH_PROMISE frames". A header block whose stream has been
// reset must still be decoded, because the HPACK dynamic table is
// connection-scoped and order-dependent — skipping one block desynchronises
// every block after it. So the decode belongs to the layer that knows a stream
// is gone, which is this one, and the layer above is handed fields rather than
// octets.
//
// The same rule is why a stream-level fault discovered on a HEADERS frame is not
// reported from that frame. See Table.headers.
//
// # Concurrency
//
// A Table's streams are not safe for concurrent use and are not behind a lock. Every
// method but one is called from the connection's single reader goroutine, in frame
// arrival order, which is the only order the HPACK codec can be driven in at all (see
// h2.HeaderCodec). The per-stream goroutines that write responses do not touch the
// table; they are handed their own stream, and they spend send-side flow control
// through the *flow.Sender the table exposes, which is the one part of this package's
// state that is shared and locked.
//
// The exception is Table.ReportSendEnd, and it is arranged so as not to be one. A
// response finishes on its own goroutine, and the state change that fact causes has to
// happen on the reader's, so the identifier is put on a list behind a mutex that guards
// nothing else and the next frame the reader handles applies it. No stream, window or
// map entry is reachable from another goroutine even there.
package stream

import (
	"zerodeps/zdh/internal/flow"
	"zerodeps/zdh/internal/h2"
)

// State is a stream's state (RFC 9113 §5.1).
type State int

const (
	// StateIdle is a stream that has never been used. Every identifier starts
	// here and most stay here for ever: §5.1.1 lets a peer skip identifiers, and
	// a skipped one is never idle again.
	StateIdle State = iota

	// StateOpen is a stream whose request has begun and not finished, in either
	// direction.
	StateOpen

	// StateHalfClosedRemote is a stream the peer has finished sending on. It has
	// sent END_STREAM; we have not.
	StateHalfClosedRemote

	// StateHalfClosedLocal is a stream we have finished sending on. We have sent
	// END_STREAM; the peer has not.
	StateHalfClosedLocal

	// StateClosed is a stream that is over, whether it ended by END_STREAM in
	// both directions, by RST_STREAM, or by never having been used after a
	// higher identifier went past it (§5.1.1).
	StateClosed
)

// String names the state as §5.1's figure does, because these strings end up in
// protocol error messages and a reader diagnosing one has the RFC open.
func (s State) String() string {
	switch s {
	case StateIdle:
		return "idle"
	case StateOpen:
		return "open"
	case StateHalfClosedRemote:
		return "half-closed (remote)"
	case StateHalfClosedLocal:
		return "half-closed (local)"
	case StateClosed:
		return "closed"
	}
	return "unknown"
}

// Stream is one stream that is neither idle nor closed.
//
// Only those exist as objects. An idle stream is an identifier nobody has used
// and a closed stream is one nobody may use again, and neither needs to be
// stored: Table.StateOf tells the two apart from the highest identifier seen, so
// a connection that serves a million requests holds a million-entry map at no
// point. That matters more than it looks — a table that remembered closed streams
// would be a memory footprint a peer controls, which is the shape of every
// HTTP/2 denial-of-service advisory there has been.
type Stream struct {
	id    uint32
	state State

	// recv is the window we grant this stream: credit the peer spends by sending
	// DATA. It is debited from the reader goroutine, in frame arrival order, like
	// everything else in this package.
	//
	// The window in the other direction — the peer's grant to us, which this
	// stream's response body is spent from — is deliberately not here. It is held
	// by the connection's *flow.Sender, keyed by identifier, because it is spent by
	// a different goroutine from the one that receives the credit for it. A pointer
	// to it on this struct would be a *flow.Window crossing a goroutine boundary,
	// and flow.Window has no lock.
	recv *flow.Window
}

// ID is the stream identifier.
func (s *Stream) ID() uint32 { return s.id }

// State is the stream's current state.
func (s *Stream) State() State { return s.state }

// RecvWindow is the flow-control window this stream's request body is debited
// from, which is our grant to the peer.
func (s *Stream) RecvWindow() *flow.Window { return s.recv }

// recvEnd applies a peer END_STREAM: the peer has finished sending.
//
// A method rather than an assignment at each of the two call sites, because the
// transition depends on what we have already sent and §5.1 spells that out
// twice: from open it is half-closed (remote), and from half-closed (local) —
// where our own END_STREAM has already gone — it is closed. A caller that
// assigned StateHalfClosedRemote directly would resurrect a stream we had
// finished with.
func (s *Stream) recvEnd() {
	if s.state == StateHalfClosedLocal {
		s.state = StateClosed
		return
	}
	s.state = StateHalfClosedRemote
}

// peerDone reports whether the peer has already sent END_STREAM on this stream.
//
// It is the test for both of the frames a peer may not send afterwards. §5.1's
// half-closed (remote) state permits WINDOW_UPDATE, PRIORITY and RST_STREAM and
// gives everything else — DATA and a further HEADERS alike — a stream error of
// type STREAM_CLOSED, so one predicate serves both call sites rather than each
// spelling out the same comparison.
//
// A comparison against one state rather than two is exact because a Stream only
// exists in three of them: Table.retire removes a stream the moment it closes,
// and an idle stream has no Stream at all. That is the invariant
// TestTheTableOnlyHoldsStreamsThatCountAsConcurrent pins.
func (s *Stream) peerDone() bool { return s.state == StateHalfClosedRemote }

// Requests is the layer above the stream table: what a request is handed to once
// its header block has been decoded.
//
// Every method is called from the connection's reader goroutine, in arrival
// order, and must not block indefinitely — that goroutine is also the one
// answering the peer's PING frames and noticing its GOAWAY. An implementation
// that wants to do work per request starts its own goroutine for it. The
// goroutine boundary is deliberately not here, because where the goroutines are
// is a decision for the layer that owns them, and this one owns none.
//
// A returned error is the stream table's error to report, so its type decides the
// scope exactly as it does everywhere else: h2.StreamError resets the stream and
// keeps the connection, h2.ConnError ends the connection. Anything else is
// treated by internal/server as a connection failure without a GOAWAY, which is
// the right answer for an error that is not about the protocol at all.
type Requests interface {
	// Headers delivers a request's header block. endStream reports that the
	// request has no body, so no Data or Trailers call will follow.
	//
	// fields is not retained by the table and may be retained by the callee.
	Headers(s *Stream, fields []h2.Field, endStream bool) error

	// Data delivers one DATA frame's payload, padding already removed.
	// endStream reports that this is the last of the body.
	//
	// b aliases the frame, which internal/frame has already copied out of the
	// read buffer, so it is safe to retain.
	Data(s *Stream, b []byte, endStream bool) error

	// Trailers delivers a second header block on a stream (§8.1), which always
	// ends the request.
	Trailers(s *Stream, fields []h2.Field) error

	// Canceled reports that the peer abandoned the stream with RST_STREAM, so
	// that a response in progress can stop. It returns nothing: the stream is
	// already gone, and there is nothing left to report an error about.
	Canceled(s *Stream, code h2.ErrCode)
}
