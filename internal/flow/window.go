// Package flow implements the RFC 9113 §6.9 flow-control windows: the
// credit-based counters that bound how much DATA may be in flight before the
// sender has to wait to be told there is room.
//
// Only DATA is flow-controlled (§5.2.1), and the whole payload counts, including
// the Pad Length field and the padding itself (§6.1). Everything else — SETTINGS,
// PING, HEADERS, the WINDOW_UPDATE frames that do the crediting — travels
// regardless of how empty a window is, which is what stops flow control from
// being able to deadlock the connection's own housekeeping.
//
// One Window is one window: the connection's, or one stream's, in one direction.
// A connection therefore holds four kinds at once — our receive window and the
// peer's, per stream and for the connection as a whole — and they are separate
// objects because they move independently and because two of them are the peer's
// property and two are ours.
//
// # Whose fault an error is
//
// The scope of a flow-control error is not a property of what went wrong; it is a
// property of which window it went wrong on. §6.9 spells the same arithmetic
// fault two ways: on a stream it resets that stream, on the connection it ends the
// connection. So a Window knows its own stream identifier and returns
// h2.StreamError or h2.ConnError accordingly, rather than returning a sentinel for
// the caller to classify. The classification has exactly one correct answer per
// window and no caller should be in a position to get it wrong.
//
// # Concurrency
//
// A Window is not safe for concurrent use, and it has no lock on purpose. Which
// goroutine owns which window is a decision for the layer above: the receive
// windows belong to the connection's reader goroutine, which is the only thing
// that sees a DATA frame arrive, and the send windows belong to whatever
// serialises writes. A mutex here would make every window individually safe and
// the pair of them still racy, because reserving credit on the connection and on
// a stream has to be one atomic decision or neither.
//
// The blocking half of the send side — a stream goroutine that wants to write a
// body larger than its credit and must park until a WINDOW_UPDATE arrives — is
// Sender, in the next file. It sits on top of this type rather than inside it: the
// arithmetic and the RFC's error scoping are worth testing without a scheduler
// involved, and the parking is worth testing without the arithmetic.
//
// The receive side has no counterpart here and deliberately so. Deciding when to
// give credit back is policy rather than arithmetic — how much a receiver is willing
// to have in flight, and how many frames it will spend saying so — and it needs to
// know what a handler has read, which is a fact from a third goroutine that no
// window can see. internal/stream owns that decision; see Table.ReportConsumed. What
// arrives here is only the result, through Increase, from the goroutine that owns the
// window.
package flow

import "zerodeps/zdh/internal/h2"

const (
	// InitialWindowSize is what every window starts at, for the connection and
	// for each new stream, until a SETTINGS frame says otherwise (§6.9.2).
	//
	// It is also the value an endpoint must assume before it has seen the peer's
	// SETTINGS, which is why it is a constant rather than configuration: both
	// ends have to agree on it without having exchanged anything.
	//
	// TestWindowConstantsAgreeWithTheFrameLayer pins this to
	// frame.DefaultInitialWindowSize, for the same reason MaxWindowSize is pinned
	// below.
	InitialWindowSize = 1<<16 - 1

	// MaxWindowSize is the largest a window may become (§6.9.1). A WINDOW_UPDATE
	// that would push one past this is a FLOW_CONTROL_ERROR.
	//
	// TestWindowConstantsAgreeWithTheFrameLayer pins this to frame.MaxWindowSize,
	// which the SETTINGS validator uses for the same protocol constant. Two
	// packages naming the same number is deliberate — the production code here
	// does not import frame, so the window arithmetic can be tested without the
	// wire format — but two packages *disagreeing* about it would be a
	// split-brain server, accepting a SETTINGS value it then could not honour, so
	// the test fails the build rather than leaving it to a code review.
	MaxWindowSize = 1<<31 - 1
)

// Window is one flow-control window.
//
// The zero value is not usable: a window with no identifier cannot report an
// error at the right scope, and one starting at zero credit would stall the first
// frame. Use NewConnWindow or NewStreamWindow.
type Window struct {
	// streamID is 0 for the connection's window, or the stream this one belongs
	// to. It is stored rather than passed to each call because it decides the
	// scope of every error returned here, and a value passed in per call is a
	// value that can be passed in wrongly.
	streamID uint32

	// initial is the SETTINGS_INITIAL_WINDOW_SIZE this window was last told
	// about. §6.9.2 defines a change as a delta against the previous value, so
	// applying one needs the previous value; keeping it here rather than at the
	// call site is what stops a stale copy of it from being subtracted.
	initial int64

	// n is the credit remaining. Signed and 64-bit, and both matter.
	//
	// Signed because a window is allowed to be negative: §6.9.2 permits a
	// SETTINGS change that shrinks the initial size below what a stream has
	// already spent, and requires the sender to track the deficit rather than
	// clamp it, because the credit later granted has to fill the hole before it
	// pays for anything new.
	//
	// 64-bit because every bound in §6.9 is a check against 2^31-1 performed on
	// a sum that can reach 2^32-2, which does not fit in the int32 the window
	// nominally is. In int32 that sum wraps to a negative number, and a negative
	// window reads as a peer that is owed credit rather than one that has just
	// broken the protocol — the overflow check would license exactly what it
	// exists to refuse.
	n int64
}

// NewConnWindow returns the connection's window, at the initial size.
//
// There is no size argument because there is nothing to pass: §6.9.2 makes
// SETTINGS_INITIAL_WINDOW_SIZE a per-stream setting and says the connection
// window can only be changed by WINDOW_UPDATE. A connection window that could be
// constructed at some other size would invite a caller to apply the peer's
// SETTINGS to it, which is the most common way to get flow control wrong: the two
// ends then disagree about the connection's credit by the difference, for ever,
// and the symptom is a transfer that stalls at a size that depends on the peer.
func NewConnWindow() *Window {
	return &Window{streamID: 0, initial: InitialWindowSize, n: InitialWindowSize}
}

// NewStreamWindow returns a window for stream id, starting at initial octets.
//
// initial is whichever SETTINGS_INITIAL_WINDOW_SIZE governs this direction: the
// peer's advertised value for a window we spend, our own for one we grant.
//
// Both arguments panic when they cannot be right, rather than being corrected or
// carried. A stream window with identifier 0 would report every error at
// connection scope and take down the connection over one stream's arithmetic; a
// size above the maximum is a SETTINGS value the frame layer is required to have
// rejected already (§6.5.2), so seeing one here means the validation was skipped
// and every later bound in this file is being computed from a number the protocol
// does not permit.
func NewStreamWindow(id uint32, initial uint32) *Window {
	if id == 0 {
		panic("flow: NewStreamWindow requires a non-zero stream identifier; use NewConnWindow")
	}
	if int64(initial) > MaxWindowSize {
		panic("flow: NewStreamWindow initial size is above the maximum window")
	}
	return &Window{streamID: id, initial: int64(initial), n: int64(initial)}
}

// Available is the credit remaining, which may be negative.
//
// int64 rather than int32, matching the field: a caller comparing this against a
// frame's length is comparing it against a uint32, and a signed 32-bit result
// would make that comparison the one place the conversion could go wrong.
func (w *Window) Available() int64 { return w.n }

// StreamID is the stream this window belongs to, or 0 for the connection's.
func (w *Window) StreamID() uint32 { return w.streamID }

// Consume debits n octets for one DATA frame, and reports whether the frame fits.
//
// n is the frame's whole payload length, padding included (§6.1). On the
// receiving side a refusal means the peer overran the credit it was given; on the
// sending side it means this server was about to, which is the one case §6.9.1
// puts squarely on the sender.
//
// A refusal leaves the window untouched, and that is deliberate rather than
// merely convenient. §6.9.1 requires a receiver to account for a frame against
// the *connection* window even when the frame is in error, because a receiver that
// silently drops the octets leaves the two ends permanently disagreeing about the
// connection's credit. It does not require the same of the stream window, and a
// stream that is about to be reset has no further use for one. So the caller
// debits the connection window first and the stream window second: if the
// connection window refuses, the connection is ending and the accounting is moot;
// if the stream window refuses, the connection window has already been debited
// and the requirement is met.
func (w *Window) Consume(n uint32) error {
	// An empty frame always passes, however empty the window is. §6.9.1 says so
	// in as many words: a zero-length DATA frame with END_STREAM MAY be sent when
	// there is no space in either window. It is how a sender closes a stream it
	// has no more body for, and making that wait for credit would park a stream
	// that is already finished behind a WINDOW_UPDATE nobody has a reason to send.
	//
	// A separate branch rather than a `n > 0 &&` clause on the comparison below,
	// and not because the clause would be wrong. It would not, and that was
	// measured rather than assumed: `&&` short-circuits, so `n > 0 && int64(n) >
	// w.n` never evaluates the comparison for an empty frame and admits it on any
	// window, negative included. The two forms are exactly equivalent, and
	// scripts/break-flow.py records that no test in this package can tell them
	// apart, because there is nothing to tell apart. The branch is here because a
	// conjunct on the way to a size comparison reads as a micro-optimisation,
	// while this is a protocol rule with a sentence of the RFC behind it.
	//
	// What the zero case must not become is the comparison on its own. int64(0) >
	// w.n is true whenever the window is negative, so dropping this branch without
	// putting the condition somewhere refuses the empty frame on precisely the
	// windows §6.9.1 wrote the exemption for. That break is in the campaign and it
	// fires.
	if n == 0 {
		return nil
	}

	if int64(n) > w.n {
		return w.errorf(h2.FlowControlError,
			"DATA of %d octets on a flow-control window of %d (RFC 9113 §6.9.1)", n, w.n)
	}
	w.n -= int64(n)
	return nil
}

// Increase credits n octets from a WINDOW_UPDATE, and reports an overflow.
//
// This is the enforcement of frame-layer matrix rows 30 and 31, which
// internal/frame defers here because the rule needs the window's current value
// and the frame carries only the increment. The two halves of §6.9's
// WINDOW_UPDATE validation therefore live in two packages: a zero increment is
// rejected by parseWindowUpdate, which needs nothing but the frame, and an
// increment that overflows is rejected here.
//
// A zero increment reaching this method is not an error and not a no-op worth
// reporting — it is simply nothing, and it cannot arrive from the wire, because
// the frame layer refuses it first. Nothing is asserted about it here so that
// there is exactly one place in the server that decides what a zero increment
// means.
func (w *Window) Increase(n uint32) error {
	// The sum, not the operands. w.n is at most 2^31-1 and n is at most 2^31-1,
	// so this reaches 2^32-2: it needs the 64 bits, and a check written against
	// either operand alone would pass a pair that overflows together.
	if w.n+int64(n) > MaxWindowSize {
		return w.errorf(h2.FlowControlError,
			"WINDOW_UPDATE of %d takes a window of %d above the maximum %d (RFC 9113 §6.9.1)",
			n, w.n, int64(MaxWindowSize))
	}
	w.n += int64(n)
	return nil
}

// SetInitialSize applies a new SETTINGS_INITIAL_WINDOW_SIZE to this window.
//
// §6.9.2 makes this a delta and not an assignment, and the difference is the
// whole reason this method exists rather than a field being set. A peer that
// raises the initial size from 64 KiB to 1 MiB is granting every open stream
// another 960 KiB on top of whatever each has left, not resetting them all to
// 1 MiB — a stream that had spent 60 KiB is owed the increase as well, and an
// assignment would hand it back the 60 KiB it already used.
//
// The result may be negative, which is legal and must be carried rather than
// clamped: a peer that lowers the initial size below what a stream has already
// spent has taken back credit that was already used, and the stream owes the
// difference before it may send anything more. Clamping to zero would let it send
// that much again.
func (w *Window) SetInitialSize(n uint32) error {
	if w.streamID == 0 {
		// Not reachable from a correct caller, and named rather than ignored.
		// §6.9.2 confines this setting to stream windows and gives WINDOW_UPDATE
		// as the only way to change the connection's, so a server that applies a
		// peer's SETTINGS to the connection window has desynchronised the
		// connection's credit by the delta with nothing to resynchronise it.
		// Silently returning nil would make that a stalled transfer weeks later
		// instead of a failure here.
		return h2.ConnErrorf(h2.InternalError,
			"SETTINGS_INITIAL_WINDOW_SIZE applied to the connection window, "+
				"which only WINDOW_UPDATE may change (RFC 9113 §6.9.2)")
	}

	next := w.n + (int64(n) - w.initial)
	if next > MaxWindowSize {
		// Connection-scoped even though the window is one stream's, and that is
		// not the usual rule. Elsewhere in this file the scope follows the window;
		// here the fault is in a SETTINGS frame, which is the connection's, and
		// one frame can push any number of streams over at once. Resetting the
		// streams it happened to overflow would leave the connection running on a
		// setting the peer is not allowed to have sent.
		return h2.ConnErrorf(h2.FlowControlError,
			"SETTINGS_INITIAL_WINDOW_SIZE of %d takes stream %d's window of %d "+
				"above the maximum %d (RFC 9113 §6.9.2)",
			n, w.streamID, w.n, int64(MaxWindowSize))
	}

	// Both, or neither. The delta is computed against initial, so a window whose
	// credit moved without initial following it would apply the next change
	// against a value the peer never sent, and the error above leaves both
	// untouched for the same reason.
	w.initial = int64(n)
	w.n = next
	return nil
}

// errorf builds the error for this window at the scope §6.9 gives it: a stream
// error for a stream's window, a connection error for the connection's.
func (w *Window) errorf(code h2.ErrCode, format string, args ...any) error {
	if w.streamID == 0 {
		return h2.ConnErrorf(code, format, args...)
	}
	return h2.StreamErrorf(w.streamID, code, format, args...)
}
