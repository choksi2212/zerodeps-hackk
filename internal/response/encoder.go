// Package response turns a handler's reply into frames: a header section into
// HEADERS and CONTINUATION, a body into DATA against the stream's flow-control
// credit, and a trailer section into the HEADERS frame that ends the stream.
//
// It is the mirror of internal/request. That package holds a peer's field list to
// RFC 9113 §8 and produces either a Request or the stream error that says why there
// is none; this one holds our own field list to the response half of §8 and produces
// either frames or the error that says why there are none. The asymmetry is in who
// is at fault, and it runs through every decision here: a malformed request is the
// peer's mistake and is answered on the wire, whereas a malformed response is this
// server's own and must never reach the wire at all.
//
// # Two scopes, because HPACK and flow control have different ones
//
// Encoder is per connection and Writer is per stream, and that is not a layering
// preference. The HPACK encoding context is connection-scoped and order-dependent —
// §4.3 of RFC 7541 — so every header block on a connection has to be encoded, and
// then *enqueued*, in one order by one holder of one lock. Flow control is the
// opposite: §6.9.1 gives every stream its own window and expects the streams to
// spend them concurrently, which is what makes a response body a per-stream object
// with no lock of its own.
//
// So one Encoder is shared by every stream goroutine on a connection, and each
// stream has a Writer of its own that borrows it for the two moments it needs a
// header block. A Writer is used by exactly one goroutine and holds no lock; every
// piece of shared state on the connection is behind the Encoder's.
//
// # What is not here
//
// Server push (§8.4). SETTINGS_ENABLE_PUSH is 0 on every connection this server
// serves and it sends no PUSH_PROMISE, so there is no promised-request header block
// to encode.
//
// Priority (§5.3, RFC 9218). Nothing here sets the PRIORITY flag on a HEADERS frame
// or sends PRIORITY_UPDATE, so a response carries no priority signal.
//
// The 1xx rule that a client must tolerate several of them, and the 100-continue
// handshake of §10.1.1 of RFC 9110. WriteHeader will send as many informational
// responses as a handler asks for and holds each to §8.3.2; deciding whether one is
// warranted is the handler's, because it is the only party that has read the
// request.
package response

import (
	"bytes"
	"errors"
	"fmt"
	"sync"

	"zerodeps/zdh/internal/frame"
	"zerodeps/zdh/internal/h2"
)

// Transport is the connection's write half as this package needs it: somewhere to
// put a frame, and the largest payload the peer will accept.
//
// Declared here rather than imported, which is the Go convention and is also the
// only option that keeps the dependency pointing the right way: internal/server
// builds the connection and would have to know about this package to hand it an
// interface of its own. Its ConnWriter is this method set exactly, so a
// *server.frameWriter satisfies this by construction and neither package imports
// the other.
type Transport interface {
	// Enqueue hands f to the connection's writer goroutine. It returns when the
	// frame is queued rather than when it reaches the wire, and it blocks while
	// the queue is full — which is the backpressure a peer that has stopped
	// reading applies to the goroutine writing to it.
	Enqueue(f frame.Frame) error

	// MaxFrameSize is the peer's SETTINGS_MAX_FRAME_SIZE, never below §6.5.2's
	// 16384.
	MaxFrameSize() uint32
}

// fieldOverhead is what §6.5.2 charges for a field line on top of its name and
// value: "an overhead of 32 octets for each field line", which stands for the space
// an implementation needs to hold the field rather than for anything on the wire. It
// is the reason SETTINGS_MAX_HEADER_LIST_SIZE cannot be checked against the encoded
// block — the number the peer advertised is about a list, not about octets we send.
const fieldOverhead = 32

// noHeaderListLimit is maxList when the peer has advertised no
// SETTINGS_MAX_HEADER_LIST_SIZE.
//
// A sentinel rather than the largest uint32, because 0 is a legal value for that
// setting and "unlimited" and "no fields at all" have to be distinguishable: a peer
// that advertises 0 has said something absurd but has said it, and treating the
// absence of the setting as the same thing would make every response on every
// connection too large to send.
const noHeaderListLimit = -1

// ErrHeaderListTooLarge is returned by WriteHeaders when a field list is larger,
// under §6.5.2's accounting, than the SETTINGS_MAX_HEADER_LIST_SIZE the peer
// advertised.
//
// It is separated from the other refusals because it is the one that is nobody's
// mistake: the fields are valid, this server would send them, and the peer has said
// it will not read a list that big. The stream layer can answer it — with a shorter
// response, or with RST_STREAM — and cannot answer a malformed field the same way.
var ErrHeaderListTooLarge = errors.New("response: header list exceeds the peer's SETTINGS_MAX_HEADER_LIST_SIZE")

// Encoder is one connection's HPACK encoding context and its route to the wire.
//
// # Why the lock covers the enqueue and not only the encode
//
// HPACK is a shared, ordered, mutable table on both ends of the connection, and the
// order that matters is the order the blocks *arrive*. Encoding under a lock and
// enqueuing outside it would keep our table consistent and still break the peer's:
// two stream goroutines could encode blocks A then B, be descheduled, and enqueue B
// then A, at which point every reference A made to the dynamic table means something
// different than it did when we wrote it. The symptom is not a failed response but
// header fields nobody sent, on every later request of the connection, which is why
// §4.3 of RFC 7541 states the requirement as being about a decoder processing blocks
// "in the same order in which they were encoded".
//
// §4.3 adds a second reason on top of the first, and it applies even to a connection
// with one stream: a field block "MUST be transmitted as a contiguous sequence of
// frames, with no interleaved frames of any other type or from any other stream", and
// §6.10 makes a receiver treat anything that does interleave as a connection error of
// type PROTOCOL_ERROR. The whole burst is therefore enqueued under this lock, so that
// no other stream's DATA can land in the middle of it.
//
// The cost is that a stream whose Enqueue blocks — a peer that has stopped reading,
// with the writer's queue full — holds up every other stream's header section for as
// long as it blocks. That is not a deadlock and it is not unbounded: the writer's
// socket deadline fails the stalled write within the connection's write timeout,
// which stops the writer, which releases every blocked Enqueue with an error. And a
// connection whose peer is not reading has nothing useful for the other streams to be
// doing in the meantime.
type Encoder struct {
	// mu orders the whole of an encode-and-enqueue, and guards every mutable field
	// below. t is the exception and is documented as one.
	mu sync.Mutex

	// codec is this connection's encoding direction. It is not safe for concurrent
	// use — h2.HeaderCodec says so — and this lock is what makes it safe here.
	//
	// One direction. The decoding context is a different table with a different
	// history, driven by the connection's reader goroutine, and sharing one codec
	// between the two would make our encoder's idea of the table depend on what the
	// client happened to send us.
	codec h2.HeaderCodec

	// t is set by NewEncoder and never written again, which is why it is the one
	// field mu does not guard: splitAt reads the peer's frame size through it from a
	// stream goroutine that holds no lock, and frameWriter.MaxFrameSize is documented
	// as safe from any goroutine. Enqueue is called under the lock, but for the order
	// of the frames rather than for the safety of the call.
	t Transport

	// maxList is the peer's SETTINGS_MAX_HEADER_LIST_SIZE, or noHeaderListLimit.
	//
	// Held as an int64 so that the comparison against a list's size is done in one
	// type: the size is a sum of lengths plus 32 per field, which is an int64 for
	// exactly the same reason.
	maxList int64
}

// NewEncoder returns the response-encoding half of one connection.
//
// A nil codec or transport panics, at construction. Both are dereferenced on the
// first response of the connection rather than here, so the alternative is a nil
// method call from a stream goroutine, several frames into a peer's traffic, with
// nothing in the stack trace to say which of the two was missing.
func NewEncoder(codec h2.HeaderCodec, t Transport) *Encoder {
	if codec == nil {
		panic("response: NewEncoder requires a header codec")
	}
	if t == nil {
		panic("response: NewEncoder requires a transport")
	}
	return &Encoder{codec: codec, t: t, maxList: noHeaderListLimit}
}

// SetMaxDynamicTableSize applies the peer's SETTINGS_HEADER_TABLE_SIZE to the
// encoding context (§6.5.2, and §4.2 of RFC 7541).
//
// Called from the connection's reader goroutine, and under the same lock as an
// encode for the same reason an encode is: the codec is not safe for concurrent use,
// and resizing the table is a mutation of exactly the state a concurrent Encode is
// reading and writing.
//
// The table size actually used is the codec's business, not this method's. §4.2 makes
// the peer's value a maximum that an encoder may sit below, and RFC 7541 requires the
// encoder to signal whatever it chooses with a dynamic table size update at the front
// of the next block — which is a thing only the codec can emit.
func (e *Encoder) SetMaxDynamicTableSize(n int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.codec.SetMaxDynamicTableSize(n)
}

// SetMaxHeaderListSize applies the peer's SETTINGS_MAX_HEADER_LIST_SIZE (§6.5.2):
// from now on, a field list larger than n by that section's accounting is refused
// rather than sent.
//
// Called from the connection's reader goroutine. §6.5.2 makes this "advisory" and
// permits a sender to exceed it, so refusing is a choice — and it is the better half
// of the choice, because the alternative is a response the peer is entitled to answer
// with a 431 or a RST_STREAM after we have spent the bandwidth on it. A handler that
// hits this gets an error it can act on; a handler that does not is not slowed down by
// the check, which is a sum over a list that is about to be encoded anyway.
func (e *Encoder) SetMaxHeaderListSize(n uint32) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.maxList = int64(n)
}

// WriteHeaders encodes fields as a header section on stream id and enqueues it as a
// HEADERS frame followed by as many CONTINUATION frames as the peer's maximum frame
// size requires.
//
// The fields are held to §8.3.2 and §8.2 first: this is a response this server built,
// so an invalid field line is a bug on this side and the point of finding it is to
// find it before it is on the wire. See checkSection.
//
// endStream marks a response with no body — or, with a trailer section, the end of
// one. It is the flag rather than a separate frame because §6.1's empty DATA frame
// costs nine octets to say what a flag already says.
//
// Stream 0 panics. §6.2 makes HEADERS on the connection a connection error, so the
// frame could not be sent even if it were built, and the identifier comes from this
// server's own stream table rather than from the peer — the same reasoning that makes
// flow.NewStreamWindow panic on it.
func (e *Encoder) WriteHeaders(id uint32, fields []h2.Field, endStream bool) error {
	if id == 0 {
		panic("response: WriteHeaders requires a stream identifier")
	}
	if err := checkSection(sectionHeader, fields); err != nil {
		return err
	}
	return e.writeSection(id, fields, endStream)
}

// WriteTrailers encodes fields as a trailer section on stream id and enqueues it,
// always with END_STREAM: a trailer section is by definition the last thing on a
// stream, and §8.1 gives no way to send one and carry on.
//
// The fields are held to the trailer half of §8.3 — no pseudo-header fields at all —
// as well as to §8.2. See checkSection.
func (e *Encoder) WriteTrailers(id uint32, fields []h2.Field) error {
	if id == 0 {
		panic("response: WriteTrailers requires a stream identifier")
	}
	if err := checkSection(sectionTrailer, fields); err != nil {
		return err
	}
	return e.writeSection(id, fields, true)
}

// writeSection is the encode-and-enqueue both sections share. Everything above it is
// which rules the field list was held to.
func (e *Encoder) writeSection(id uint32, fields []h2.Field, endStream bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Before Encode, not after. Encode mutates the dynamic table, and a list refused
	// afterwards would have already changed the encoding context that every later
	// response on the connection depends on — so the refusal would corrupt the
	// connection it was trying to protect.
	if err := e.checkListSize(fields); err != nil {
		return err
	}

	block := e.codec.Encode(fields)

	max := e.splitAt()

	// A HEADERS frame goes out even for an empty block. §6.2 does not require a
	// fragment, the flags are the message — END_STREAM on a response with no body —
	// and a field list this short has already been refused by checkSection, which
	// requires a ":status". The case is here because "encode produced nothing" must
	// not silently become "no response".
	n := min(len(block), max)
	if err := e.t.Enqueue(frame.HeadersFrame{
		StreamID:   id,
		EndStream:  endStream,
		EndHeaders: n == len(block),
		Fragment:   fragment(block[:n]),
	}); err != nil {
		return err
	}

	rest := block[n:]
	for len(rest) > 0 {
		n = min(len(rest), max)
		if err := e.t.Enqueue(frame.ContinuationFrame{
			StreamID:   id,
			EndHeaders: n == len(rest),
			Fragment:   fragment(rest[:n]),
		}); err != nil {
			// The HEADERS frame is already queued, and this stream's header block
			// therefore ends without END_HEADERS. That is not a stream this server
			// can rescue: §6.10 forbids sending anything else until the block is
			// finished, and the reason a frame was refused is that the write half
			// has stopped, so nothing further will be sent on this connection at
			// all. Reporting it is the whole of the remedy.
			return err
		}
		rest = rest[n:]
	}
	return nil
}

// enqueue puts one frame on the connection under the same lock a header burst is
// enqueued under.
//
// This exists for Writer, and the lock is the whole of the reason it does. A DATA
// frame needs no HPACK context and no ordering against other streams' bodies, so a
// Writer with a Transport of its own would send correct DATA — right up to the first
// frame that landed between a HEADERS and its last CONTINUATION, which §4.3 forbids
// and §6.10 makes a connection error of type PROTOCOL_ERROR. Every frame this package
// sends therefore goes out under this mutex, and a stream's body waits behind another
// stream's header section rather than interleaving it.
//
// The wait is short by construction. Reserving flow-control credit is the part of
// writing a body that blocks for as long as a peer wants it to, and it happens before
// this is called; what is inside the lock is one queue send.
func (e *Encoder) enqueue(f frame.Frame) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.t.Enqueue(f)
}

// splitAt is the largest fragment a frame of this burst may carry.
//
// Read once for the whole block rather than once per frame. A peer's SETTINGS may
// land between two frames of this burst, and both values are legal for the whole
// block — §6.5.3 makes the acknowledgement the point from which a new value binds,
// and the acknowledgement is enqueued by the reader goroutine behind this lock's
// holder. What must not happen is a split computed against two different numbers,
// which is how a fragment ends up one octet over a limit nobody applied to it.
//
// That argument is about one field block and does not reach a body, which is why
// Writer calls this once per DATA frame and takes no lock to do it: consecutive DATA
// frames are independent, so a peer that raises its frame size mid-body should have
// the larger frames it asked for and one that lowers it should have the smaller ones.
//
// Floored at §6.5.2's initial value rather than trusted, exactly as
// frame.Writer.SetMaxFrameSize floors it and for a sharper version of the same
// reason: a Transport reporting zero would not merely make frames unsendable, it
// would make the loop above split a block into fragments of nothing and never
// finish. A transport that reports below the floor has broken its own documented
// contract, and the useful response to that is a connection that keeps working.
//
// §6.5.2 also makes the floor safe against a peer that wants smaller frames than
// 16384: the value an endpoint advertises "MUST be between this initial value and the
// maximum allowed frame size", so there is no legitimate cap below it to respect.
func (e *Encoder) splitAt() int {
	max := int(e.t.MaxFrameSize())
	if max < frame.DefaultMaxFrameSize {
		return frame.DefaultMaxFrameSize
	}
	return max
}

// checkListSize holds fields to the peer's SETTINGS_MAX_HEADER_LIST_SIZE. The caller
// holds the lock.
//
// The accounting is §6.5.2's and is deliberately not the size of the encoded block:
// the setting is about the list a receiver has to hold in memory, so a response that
// compresses to nothing because every field is already in the dynamic table still
// costs the peer the full uncompressed list plus 32 octets a field.
func (e *Encoder) checkListSize(fields []h2.Field) error {
	if e.maxList == noHeaderListLimit {
		return nil
	}
	var size int64
	for _, f := range fields {
		// int64 throughout. Each term is bounded by a Go string's length, so the sum
		// of a list a handler could actually build cannot overflow one — and doing
		// the arithmetic in uint32, the type the setting arrives in, could.
		size += int64(len(f.Name)) + int64(len(f.Value)) + fieldOverhead
	}
	if size > e.maxList {
		// The count and the two sizes, and no field names: the diagnosis is that the
		// list is too long, and a message that named the fields would put a
		// response's whole header section in a log line.
		return fmt.Errorf("%w: %d fields totalling %d octets, limit %d",
			ErrHeaderListTooLarge, len(fields), size, e.maxList)
	}
	return nil
}

// fragment copies one frame's slice of a header block.
//
// The copy is not paranoia about our own code but about the seam. h2.HeaderCodec is
// the frozen contract between this module's two halves, and it does not promise that
// the slice Encode returns is freshly allocated — an encoder that reused a scratch
// buffer across calls would satisfy every word of it. These fragments are handed to
// the connection's writer goroutine and are read after this call has returned, so
// aliasing would be a data race whose two ends are owned by different authors and
// whose symptom is one response's header block appearing inside another's.
//
// Per fragment rather than one copy of the block, which costs the same octets in total
// and lets each frame be freed as it is written instead of keeping the whole block
// alive until the last CONTINUATION leaves the queue.
//
// An empty b gives a nil, which is what a HEADERS frame carrying no fragment wants,
// and bytes.Clone is where that behaviour is documented rather than something this
// function has to arrange.
func fragment(b []byte) []byte {
	return bytes.Clone(b)
}
