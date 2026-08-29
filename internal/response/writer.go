package response

import (
	"bytes"
	"errors"
	"strings"

	"zerodeps/zdh/internal/frame"
	"zerodeps/zdh/internal/h2"
)

// Credit is one connection's send-side flow control as this package needs it: a way to
// be granted octets for a stream, or told that the stream will never get any.
//
// Declared here rather than imported, for the same reason Transport is. *flow.Sender is
// this method set exactly, so it satisfies this by construction and neither package
// imports the other — and a test can grant credit in a pattern no real window would
// produce, which is most of how the split below is checked.
type Credit interface {
	// Reserve blocks until at least one octet is available on both the stream's send
	// window and the connection's, and returns how many of want it took. The octets
	// are debited before it returns: the caller has been granted them and there is no
	// way to give them back.
	//
	// A returned error is the end of writing on this stream rather than a smaller
	// reservation to retry — the stream was reset, or the connection ended.
	Reserve(id uint32, want int) (int, error)
}

// The refusals a Writer makes about its own state. Each is a handler that has called
// these methods out of the order §8.1 puts them in, which is a bug on this side of the
// connection and never something the peer can cause.
//
// Sentinel values rather than one error with a string, because the stream layer treats
// them differently: ErrDone is very often benign — a handler that wrote its response and
// returned, and a teardown path that calls Close on everything — while the other three
// are a handler that cannot have done what it thought it was doing.
var (
	// ErrNoHeader is returned by Write, Close and Trailers before any header section
	// has been written. §8.1 makes the header section the first thing in a message, so
	// a body or a trailer section without one is not a response the peer could parse.
	ErrNoHeader = errors.New("response: no header section has been written")

	// ErrHeaderWritten is returned by WriteHeader and WriteBodylessHeader once a final
	// header section has been written. §8.1: "An endpoint that receives a HEADERS frame
	// without the END_STREAM flag set after receiving the HEADERS frame that opens a
	// request or after receiving a final (non-informational) status code MUST treat the
	// corresponding request or response as malformed."
	//
	// Informational responses are the exception and are not counted, which is what
	// WriteHeader's doc is about.
	ErrHeaderWritten = errors.New("response: the header section has already been written")

	// ErrDone is returned by every method that would add to a response whose last frame
	// has already been enqueued, by Close, WriteBodylessHeader or Trailers.
	//
	// Close is the exception: it returns nil, because "make sure this stream is
	// finished" is a request that has been satisfied.
	ErrDone = errors.New("response: the response has already been ended")

	// ErrInformationalEnd is returned by WriteBodylessHeader for a 1xx status code.
	// §8.1: "A HEADERS frame with the END_STREAM flag set that carries an informational
	// status code is malformed", because §8.1 also has a server following an interim
	// response with a final one and a stream that ended cannot carry it.
	ErrInformationalEnd = errors.New("response: an informational response cannot end the stream")
)

// Writer is one stream's response: a header section, a body against that stream's
// flow-control credit, and either an END_STREAM or a trailer section to end it.
//
// # Used by one goroutine, and therefore unlocked
//
// A Writer has no mutex and none of its fields is atomic, which is deliberate and is
// the whole reason this type is separate from Encoder. It belongs to the goroutine
// running one request's handler, its state is a three-value answer to "what has this
// response sent so far", and every piece of state that is genuinely shared between
// streams — the HPACK context, the order frames reach the wire, the connection's window
// — lives behind a lock in Encoder or in the Credit implementation.
//
// Two goroutines writing one response concurrently would interleave a body with its own
// header section, which is not a race this type could fix by locking: the result would
// still be a response whose frames are in an order §8.1 does not allow. So the rule is
// that a Writer is used by one goroutine, and the race detector runs over this package's
// tests to say whether the rule was kept.
//
// # The order §8.1 fixes
//
// §8.1 makes an HTTP message "one HEADERS frame [...] containing the header section,
// [...] zero or more DATA frames containing the message content, and [...] optionally,
// one HEADERS frame [...] containing the trailer section". The methods here are that
// sequence, and the errors above are what enforces it — a body before a header section,
// a second final header section, anything at all after END_STREAM.
//
// The one part of the order that is not a straight line is the informational response:
// §8.1 says "For a response only, a server MAY send any number of interim responses
// before the HEADERS frame containing a final response", so WriteHeader may be called
// repeatedly with 1xx codes and once more with the final one.
type Writer struct {
	enc    *Encoder
	credit Credit

	// id is the stream, and is never 0: see NewWriter.
	id uint32

	// wroteHeader records that a *final* header section has gone out, which is what
	// makes a body legal and a second header section not. An interim response leaves it
	// alone.
	wroteHeader bool

	// closed records that a frame with END_STREAM has been enqueued. Nothing may follow
	// it — not a DATA frame, not a trailer section — and the stream is the peer's to
	// read and ours to forget.
	closed bool
}

// NewWriter returns the response writer for one stream.
//
// All three arguments are checked, at construction, because all three are dereferenced
// later and from a different goroutine: a nil Encoder or Credit surfaces as a nil method
// call somewhere inside a handler's first write, and a zero id surfaces as a HEADERS
// frame on the connection, which §6.2 makes a connection error — one broken response
// would take down every other stream with it.
func NewWriter(enc *Encoder, credit Credit, id uint32) *Writer {
	if enc == nil {
		panic("response: NewWriter requires an encoder")
	}
	if credit == nil {
		panic("response: NewWriter requires a source of flow-control credit")
	}
	if id == 0 {
		panic("response: NewWriter requires a stream identifier")
	}
	return &Writer{enc: enc, credit: credit, id: id}
}

// WriteHeader sends fields as this response's header section, without ending the stream.
// A body, a trailer section or Close must follow it.
//
// fields is the whole field list, ":status" included, rather than a status code and a
// map. That is the shape §8.3 describes — an ordered list in which the pseudo-header
// fields come first — and it is the shape h2.HeaderCodec encodes; a map would lose the
// order and would make two fields of the same name unrepresentable, which is how a
// response with two Set-Cookie fields turns into a response with one.
//
// An informational (1xx) status code may be sent repeatedly and does not count as the
// header section: §8.1 says "For a response only, a server MAY send any number of
// interim responses before the HEADERS frame containing a final response". So a handler
// may send 103 twice and then 200, and only the 200 makes a body legal. It follows that
// a handler which sends nothing but 1xx has not written a response, and Write will still
// say so.
//
// Whether an interim response is warranted is not this type's judgement. §8.1 permits
// any number of them and the handler is the only party that has read the request.
func (w *Writer) WriteHeader(fields []h2.Field) error {
	return w.writeHeader(fields, false)
}

// WriteBodylessHeader sends fields as a header section that also ends the stream, which
// is the whole of a response with no content — a 204, a 304, the answer to a HEAD.
//
// END_STREAM on the HEADERS frame rather than a HEADERS frame followed by an empty DATA
// frame. Both are legal and the flag is nine octets cheaper, but the reason to prefer it
// is that it cannot be got wrong: an empty DATA frame is a second frame that a slow
// handler can fail to send, and §8.1's exchange is not finished until something bears
// END_STREAM.
//
// A 1xx status code is refused with ErrInformationalEnd. §8.1 makes a HEADERS frame with
// END_STREAM carrying an informational status code malformed, and the reason is
// structural rather than arbitrary — an interim response is by definition followed by a
// final one.
func (w *Writer) WriteBodylessHeader(fields []h2.Field) error {
	return w.writeHeader(fields, true)
}

// writeHeader is both header methods. The difference between them is one flag and the
// question that flag makes worth asking.
func (w *Writer) writeHeader(fields []h2.Field, endStream bool) error {
	switch {
	case w.closed:
		return ErrDone
	case w.wroteHeader:
		return ErrHeaderWritten
	}

	// checkSection and writeSection rather than Encoder.WriteHeaders, which is the two
	// of them in that order. The informational test below has to happen after the field
	// list has been validated — otherwise a list with two ":status" fields is reported
	// as an informational response that cannot end the stream, when what is wrong with
	// it is that it has two ":status" fields — and before anything is enqueued, because
	// a refusal after the HEADERS frame is on the queue is not a refusal. There is no
	// arrangement of one call that puts a decision between those two steps.
	if err := checkSection(sectionHeader, fields); err != nil {
		return err
	}

	interim := informational(fields)
	if endStream && interim {
		return ErrInformationalEnd
	}

	// Latched before the enqueue and regardless of what it returns. writeSection can
	// fail with a HEADERS frame already on the queue and its CONTINUATION frames not —
	// §6.10 makes that stream unfinishable, and this server's response to a failed
	// enqueue is to stop rather than to retry. A Writer that let the same handler call
	// WriteHeader again would put a second header section behind the first one's
	// fragments, which is a connection error rather than a second chance.
	w.wroteHeader = !interim
	w.closed = endStream

	return w.enc.writeSection(w.id, fields, endStream)
}

// Write sends p as DATA frames on this stream, blocking until the peer's flow-control
// windows have room for all of it.
//
// This is io.Writer's contract and it is met: the count returned is the octets that
// reached the connection's queue, it is short only when the error is non-nil, and p is
// not retained. A caller may therefore hand a Writer to io.Copy, which is what serving
// a file is.
//
// # Three separate limits, and they are not the same limit
//
// Every DATA frame this sends is bounded by the peer's SETTINGS_MAX_FRAME_SIZE, because
// §4.2 says "An endpoint MUST send an error code of FRAME_SIZE_ERROR if a frame exceeds
// the size defined in SETTINGS_MAX_FRAME_SIZE", and by what Credit grants, because
// §6.9.1 forbids sending more than either flow-control window has room for. The two are
// unrelated numbers — a peer may advertise a 16 MB frame size and a 64 KB window, or the
// reverse — so each chunk is cut to the frame size first and then offered to Credit,
// which may grant less again.
//
// Which means the frames a body arrives in are the peer's shape and not the caller's: a
// single 1 MB Write becomes as many frames as its two limits require. §4.2 expects that
// much and says "Endpoints are not obligated to use all available space in a frame".
//
// Only the content is reserved. §6.9.1: "For flow-control calculations, the 9-octet
// frame header is not counted", so a chunk of n octets costs exactly n and the frames
// this makes are free.
//
// # Why the frame size is re-read for every frame
//
// A peer's SETTINGS may land between two DATA frames of one body, and both values are
// legal — consecutive DATA frames are independent, so a peer that raises its frame size
// mid-body should get the larger frames it asked for and one that lowers it should get
// the smaller ones. That is the opposite of a header block, where the whole burst must
// be split against one number; Encoder.splitAt explains the difference.
//
// # A zero-length p sends nothing
//
// Not a zero-length DATA frame. Without END_STREAM such a frame says nothing at all, and
// it would cost a reservation Credit is entitled to refuse to answer: §6.9.1's exemption
// is written for "Frames with zero length with the END_STREAM flag set", which is Close's
// frame and not this one. io.Copy on an empty file therefore enqueues nothing, and the
// stream is ended by Close as it would have been anyway.
func (w *Writer) Write(p []byte) (int, error) {
	switch {
	case w.closed:
		return 0, ErrDone
	case !w.wroteHeader:
		return 0, ErrNoHeader
	}

	sent := 0
	for len(p) > 0 {
		n, err := w.credit.Reserve(w.id, min(len(p), w.enc.splitAt()))
		if err != nil {
			// Short and honest. The octets already enqueued are on their way and the
			// caller is entitled to know how many; the ones Reserve was asked for are
			// not coming, on this stream, ever — see Credit.Reserve.
			return sent, err
		}

		// Copied, because this frame outlives the call. It is handed to the connection's
		// writer goroutine and serialised there, while p belongs to the caller and is
		// very often one buffer being refilled by an io.Copy — so aliasing it would put
		// the next chunk of the file into the frame carrying this one, if the writer had
		// not got to it yet, and would be a data race whether or not it did.
		if err := w.enc.enqueue(frame.DataFrame{
			StreamID: w.id,
			Data:     bytes.Clone(p[:n]),
		}); err != nil {
			return sent, err
		}

		sent += n
		p = p[n:]
	}
	return sent, nil
}

// Close ends the stream, sending an empty DATA frame with END_STREAM if nothing else has
// ended it yet.
//
// Idempotent, and returns nil the second time. This is the method a stream teardown path
// calls on every response it holds, without knowing which of them a handler already
// finished, and "the stream is ended" is the outcome both callers wanted. Trailers and
// WriteBodylessHeader end it too, so a Close after either is the same no-op.
//
// The empty DATA frame is exempt from flow control and is not reserved for. §6.9.1:
// "Frames with zero length with the END_STREAM flag set (that is, an empty DATA frame)
// MAY be sent if there is no available space in either flow-control window". Reserving
// would be worse than unnecessary: a stream whose window is exhausted would park here
// until the peer sent a WINDOW_UPDATE it has no reason to send, because the response is
// complete and there is nothing further for the credit to carry.
//
// ErrNoHeader if no header section was written. A handler that panicked before writing
// anything leaves a stream with no response on it at all, and the answer to that is a
// 500 or a RST_STREAM from the layer above — not a DATA frame that tells the peer an
// empty response has finished.
func (w *Writer) Close() error {
	if w.closed {
		return nil
	}
	if !w.wroteHeader {
		return ErrNoHeader
	}
	w.closed = true

	// The frame is §6.1's own suggestion, in a note whose wording did not survive
	// editing intact: there is no STREAM frame in HTTP/2, and §6.1 is the section that
	// defines DATA. §6.1: "An endpoint that learns of stream closure after sending all
	// data can close a stream by sending a STREAM frame with a zero-length Data field
	// and the END_STREAM flag set."
	return w.enc.enqueue(frame.DataFrame{StreamID: w.id, EndStream: true})
}

// Trailers sends fields as this response's trailer section, which ends the stream.
//
// Always with END_STREAM, because §8.1 leaves no other possibility: "Trailer fields are
// carried in a field block that also terminates the stream." A trailer section is the
// last thing on a stream by definition, so there is no argument for a flag here and no
// way to send one and carry on.
//
// The fields are held to the trailer half of §8.3, which forbids every pseudo-header
// field — including ":status". A trailer section arrives after the peer has acted on the
// response, so a status code in one would be a second answer to a settled question.
//
// A response may have a body or not; a trailer section needs neither. What it needs is a
// header section, because §8.1's order is header, content, trailers and a trailer
// section is the third of those.
func (w *Writer) Trailers(fields []h2.Field) error {
	switch {
	case w.closed:
		return ErrDone
	case !w.wroteHeader:
		return ErrNoHeader
	}

	// Validated before the stream is marked closed, and marked closed before the
	// enqueue, which is not the same thing twice. A malformed trailer section sends
	// nothing, so the response is unfinished and the handler may still end it — with a
	// corrected list, or with Close. A trailer section that was half enqueued has
	// already put END_STREAM on the wire, so nothing may follow it whether the rest of
	// the burst made it or not.
	if err := checkSection(sectionTrailer, fields); err != nil {
		return err
	}
	w.closed = true

	return w.enc.writeSection(w.id, fields, true)
}

// informational reports whether fields carry a 1xx status code.
//
// The caller has already run checkSection, so there is exactly one ":status" and its
// value is three digits — but this makes no use of either fact. A prefix test cannot
// index past the end of a short value, and the guard a length check would add is a
// branch no test in this package can reach.
func informational(fields []h2.Field) bool {
	for _, f := range fields {
		if f.Name == pseudoStatus {
			return strings.HasPrefix(f.Value, "1")
		}
	}
	return false
}
