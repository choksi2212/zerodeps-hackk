package frame

import (
	"errors"
	"io"
	"strings"

	"zerodeps/zdh/internal/h2"
)

// ClientPreface is the 24-octet sequence a client sends before anything else
// (RFC 9113 §3.4). It is deliberately chosen to be an invalid HTTP/1.1 request,
// so an HTTP/1.1 server that received it by mistake would reject it rather than
// try to serve it.
const ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// parsers maps a frame type to its payload parser, and is what FrameType.known
// consults: a type with an entry here is one this package implements, and a type
// without one is discarded on receipt.
//
// A table rather than a switch, for two reasons. Indexed by FrameType it is total
// over the types this package implements by construction, and a test can walk it
// and fail if any of them is missing — TestFrameTypeTablesAgree does, against a
// hand-written list of the types, where a switch could only be checked by reading
// it. And a switch would need a default branch that cannot be reached, which is
// either a panic in a server handling hostile input or an error return that no
// test can cover.
//
// The table is sparse: PRIORITY_UPDATE is 0x10 and CONTINUATION is 0x9, so the
// six entries between them are nil. That is the point of asking the table rather
// than a range — a nil entry answers "unknown" for exactly the types that have no
// parser to call.
var parsers = [...]func(Header, []byte) (Frame, error){
	TypeData:           parseData,
	TypeHeaders:        parseHeaders,
	TypePriority:       parsePriority,
	TypeRSTStream:      parseRSTStream,
	TypeSettings:       parseSettings,
	TypePushPromise:    parsePushPromise,
	TypePing:           parsePing,
	TypeGoAway:         parseGoAway,
	TypeWindowUpdate:   parseWindowUpdate,
	TypeContinuation:   parseContinuation,
	TypePriorityUpdate: parsePriorityUpdate,
}

// ReaderConfig bounds what a Reader will accept. Every field is a defence
// against a peer that is not merely wrong but hostile, so each one says what it
// stops. A zero field takes the default.
type ReaderConfig struct {
	// MaxFrameSize is the largest payload we will read, and must be the value we
	// advertise as SETTINGS_MAX_FRAME_SIZE. Defaults to DefaultMaxFrameSize.
	MaxFrameSize uint32

	// MaxHeaderBlockSize bounds the total compressed octets of one header block
	// across its HEADERS and CONTINUATION frames. Without it a peer can hold a
	// block open and stream fragments into a buffer that grows without limit,
	// having opened one stream (CVE-2023-45288). Defaults to
	// DefaultMaxHeaderBlockSize, and is raised to MaxFrameSize if it is below it.
	MaxHeaderBlockSize uint32

	// MaxContinuationFrames bounds how many CONTINUATION frames one block may be
	// spread over. MaxHeaderBlockSize alone does not cover this: a zero-length
	// CONTINUATION is legal and adds no octets, so a flood of empty ones costs
	// nine octets each to send and is unbounded work to receive. Defaults to
	// DefaultMaxContinuationFrames.
	MaxContinuationFrames int
}

// Defaults for ReaderConfig.
//
// These are fallbacks, not the policy. internal/limits owns the numbers a server
// runs with, and the server passes them in explicitly; these exist so that a
// zero-valued ReaderConfig is safe and so this package can be tested without
// importing a policy package. A test in internal/limits asserts the two agree,
// because a bound that differs between the value enforced and the value tested is
// worse than either value alone.
const (
	// DefaultMaxHeaderBlockSize is generous next to any real request — a large
	// cookie jar compresses to a few kilobytes — while still being a bound.
	DefaultMaxHeaderBlockSize = 1 << 17 // 131072

	// DefaultMaxContinuationFrames allows a block to be split across a
	// reasonable number of frames at the default frame size and no more.
	DefaultMaxContinuationFrames = 32
)

// Reader reads frames from a byte stream.
//
// It is used by exactly one goroutine per connection, so it holds no lock. That
// is not an omission to be fixed later: HPACK decoding must happen in frame
// arrival order, so a second goroutine reading frames from the same connection
// would desynchronise the dynamic table however well the reads were locked.
//
// The reader owns one scratch buffer, reused for every frame. Every parser in
// this package therefore copies whatever it retains, and the tests for each one
// prove it by overwriting the buffer afterwards.
type Reader struct {
	r   io.Reader
	hdr [HeaderLen]byte
	buf []byte

	maxFrameSize       uint32
	maxHeaderBlockSize uint32
	maxContinuations   int

	// blockStream is the stream whose header block is open — that is, a HEADERS
	// or PUSH_PROMISE frame arrived without END_HEADERS and no CONTINUATION has
	// closed it yet. Zero means no block is open, which is unambiguous because
	// HEADERS and PUSH_PROMISE are illegal on stream 0 and rejected before they
	// get here.
	blockStream uint32

	// blockSize is the compressed octets accumulated in the open block, and
	// continuations the number of CONTINUATION frames it has been spread over.
	//
	// blockSize is wider than the limit it is compared against so that the sum
	// cannot wrap: a uint32 counter would need only a hostile configuration and a
	// long enough flood to overflow back under the limit, and a bound that can be
	// crossed by wrapping is not a bound.
	blockSize     uint64
	continuations int
}

// NewReader returns a Reader over r.
//
// MaxFrameSize is fixed for the life of the reader, deliberately. This server
// advertises one value in its initial SETTINGS and never changes it, so there is
// no window during which the reader's bound and the peer's understanding of it
// disagree — and no way for a mishandled SETTINGS exchange to widen the bound.
func NewReader(r io.Reader, cfg ReaderConfig) *Reader {
	if cfg.MaxFrameSize == 0 {
		cfg.MaxFrameSize = DefaultMaxFrameSize
	}
	if cfg.MaxHeaderBlockSize == 0 {
		cfg.MaxHeaderBlockSize = DefaultMaxHeaderBlockSize
	}
	if cfg.MaxContinuationFrames == 0 {
		cfg.MaxContinuationFrames = DefaultMaxContinuationFrames
	}
	// A block limit below one frame would refuse a header block the peer is
	// entitled to send in a single frame of the size we advertised, so it is
	// raised to meet it. The two bounds are not the same kind of thing: the frame
	// size limits one frame, the block limit bounds reassembly across frames, and
	// a block limit under the frame size would only be a second, stricter frame
	// size limit wearing the wrong error code.
	if cfg.MaxHeaderBlockSize < cfg.MaxFrameSize {
		cfg.MaxHeaderBlockSize = cfg.MaxFrameSize
	}
	return &Reader{
		r:                  r,
		buf:                make([]byte, cfg.MaxFrameSize),
		maxFrameSize:       cfg.MaxFrameSize,
		maxHeaderBlockSize: cfg.MaxHeaderBlockSize,
		maxContinuations:   cfg.MaxContinuationFrames,
	}
}

// ReadPreface reads and checks the client connection preface (RFC 9113 §3.4).
//
// A mismatch is a connection error of type PROTOCOL_ERROR. The most common cause
// in practice is not an attack but an HTTP/1.1 client on an h2c port, so that
// case is named in the error: it is the difference between a diagnosable
// misconfiguration and a bare protocol error.
func (rd *Reader) ReadPreface() error {
	var got [len(ClientPreface)]byte
	if _, err := io.ReadFull(rd.r, got[:]); err != nil {
		return err
	}
	if string(got[:]) == ClientPreface {
		return nil
	}

	// The preface is peer-controlled, so it is reported with %q rather than
	// interpolated raw: a peer must not be able to put control characters or
	// forged lines into our log.
	if method, ok := looksLikeHTTP1(got[:]); ok {
		return connErrf(h2.ProtocolError,
			"connection preface is an HTTP/1.1 %s request, not the HTTP/2 preface; "+
				"this port speaks HTTP/2 only (RFC 9113 §3.4): %q",
			method, got[:])
	}
	return connErrf(h2.ProtocolError,
		"invalid connection preface (RFC 9113 §3.4): %q", got[:])
}

// http1Methods are the request methods worth recognising in a failed preface.
// They exist only to turn a protocol error into a diagnosis, so the list is the
// common ones rather than the complete registry.
var http1Methods = []string{
	"GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH",
}

// looksLikeHTTP1 reports whether b opens with an HTTP/1.x request line.
func looksLikeHTTP1(b []byte) (string, bool) {
	for _, m := range http1Methods {
		if strings.HasPrefix(string(b), m+" ") {
			return m, true
		}
	}
	return "", false
}

// ReadFrame reads the next frame.
//
// Frames of unknown type are discarded and the next frame read, as §4.1
// requires, so ReadFrame never returns one and a caller cannot forget to handle
// them.
//
// The error is one of three kinds, and the caller must tell them apart:
// io.EOF means the peer closed cleanly at a frame boundary; io.ErrUnexpectedEOF
// or another I/O error means it did not; an h2.ConnError or h2.StreamError means
// the peer broke the protocol. The I/O errors are returned unwrapped so that
// errors.Is on io.EOF works, and so a clean close is never mistaken for a
// protocol violation to send GOAWAY about.
func (rd *Reader) ReadFrame() (Frame, error) {
	for {
		if _, err := io.ReadFull(rd.r, rd.hdr[:]); err != nil {
			return nil, err
		}
		h := ParseHeader(rd.hdr[:])

		// The size check comes first because it decides whether the payload can
		// be read at all.
		//
		// It is a connection error for every frame type, which is stricter than
		// §4.2 requires — a frame size error on a DATA frame could be answered
		// with RST_STREAM and the connection kept. Escalating is a deliberate
		// choice: resynchronising the frame stream would mean reading and
		// discarding a payload we already know is illegal, up to 16 MB of it, at
		// the peer's choosing. That is the amplification an attacker wants, and it
		// buys a peer nothing it could not get by opening a new connection.
		if h.Length > rd.maxFrameSize {
			return nil, connErrf(h2.FrameSizeError,
				"%s frame declares %d octets, above the %d we advertised as "+
					"SETTINGS_MAX_FRAME_SIZE (RFC 9113 §4.2)",
				h.Type, h.Length, rd.maxFrameSize)
		}

		// Checked before the payload is read, and before an unknown type is
		// discarded: an unknown frame in the middle of a header block is exactly
		// as fatal as a known one, and discarding it silently would let a peer
		// interleave anything it liked between HEADERS and END_HEADERS.
		if err := rd.checkContinuity(h); err != nil {
			return nil, err
		}

		payload := rd.buf[:h.Length]
		if _, err := io.ReadFull(rd.r, payload); err != nil {
			// A peer that closes after sending a frame header has not closed at a
			// frame boundary: it promised octets it never sent. io.ReadFull reports
			// a plain EOF when it read none of them at all, which would be
			// indistinguishable from a clean shutdown — and this package's contract
			// is that io.EOF means exactly that. So it is reported as the truncation
			// it is.
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			return nil, err
		}

		if !h.Type.known() {
			// §4.1: ignore and discard. The payload has already been consumed, so
			// the frame stream stays synchronised.
			continue
		}

		f, err := parsers[h.Type](h, payload)
		if err != nil {
			return nil, err
		}
		if err := rd.trackBlock(f); err != nil {
			return nil, err
		}
		return f, nil
	}
}

// checkContinuity enforces RFC 9113 §6.10: once a header block is open, the only
// frame that may arrive on the connection is a CONTINUATION on the same stream.
//
// This is the one rule in this package that no single frame can decide, which is
// why it lives on the Reader. It is also the rule that makes header blocks safe
// to reassemble at all: without it a peer could interleave frames from other
// streams into a block, and the HPACK decoder — which must see blocks whole and
// in order — would have no way to tell.
func (rd *Reader) checkContinuity(h Header) error {
	if rd.blockStream != 0 {
		if h.Type != TypeContinuation {
			return connErrf(h2.ProtocolError,
				"%s frame arrived while the header block on stream %d was still open; "+
					"only CONTINUATION may follow (RFC 9113 §6.10)",
				h.Type, rd.blockStream)
		}
		if h.StreamID != rd.blockStream {
			return connErrf(h2.ProtocolError,
				"CONTINUATION on stream %d while the open header block belongs to stream %d "+
					"(RFC 9113 §6.10)",
				h.StreamID, rd.blockStream)
		}
		return nil
	}
	if h.Type == TypeContinuation {
		return connErrf(h2.ProtocolError,
			"CONTINUATION on stream %d with no header block open (RFC 9113 §6.10)",
			h.StreamID)
	}
	return nil
}

// trackBlock updates the open-block state after a frame has parsed, and applies
// the two bounds that keep a header block from being a resource attack.
//
// The type switch is exhaustive over the frames that can affect a block. The
// others cannot reach here while one is open, because checkContinuity rejected
// them.
func (rd *Reader) trackBlock(f Frame) error {
	switch f := f.(type) {
	case HeadersFrame:
		return rd.beginBlock(f.StreamID, len(f.Fragment), f.EndHeaders)
	case PushPromiseFrame:
		return rd.beginBlock(f.StreamID, len(f.Fragment), f.EndHeaders)
	case ContinuationFrame:
		return rd.extendBlock(len(f.Fragment), f.EndHeaders)
	}
	return nil
}

// beginBlock records the header block a HEADERS or PUSH_PROMISE frame starts.
//
// The bounds are applied before END_HEADERS is acted on, not after. Clearing the
// state first and checking second would exempt the frame that closes a block
// from the limit entirely — so a peer could stay one octet under the bound for
// the whole flood and then hand over another frame's worth on the way out, and
// the caller would be given more than the limit it was promised.
func (rd *Reader) beginBlock(stream uint32, fragment int, endHeaders bool) error {
	rd.blockStream = stream
	rd.blockSize = uint64(fragment)
	rd.continuations = 0
	return rd.finishFrame(endHeaders)
}

// extendBlock records a CONTINUATION frame's contribution to the open block.
func (rd *Reader) extendBlock(fragment int, endHeaders bool) error {
	rd.blockSize += uint64(fragment)
	rd.continuations++
	return rd.finishFrame(endHeaders)
}

// finishFrame applies the bounds and then closes the block if this frame ended
// it. The error is computed before the state is cleared, because the message
// names the stream.
func (rd *Reader) finishFrame(endHeaders bool) error {
	err := rd.checkBlockLimits()
	if endHeaders {
		rd.blockStream, rd.blockSize, rd.continuations = 0, 0, 0
	}
	return err
}

// checkBlockLimits refuses a header block that is being used as a resource
// attack rather than to carry headers.
//
// Neither bound is in RFC 9113. They exist because the protocol as specified
// permits a peer to hold a block open indefinitely, and every frame in that
// flood is individually valid — no per-frame check can see it (CVE-2023-45288).
// ENHANCE_YOUR_CALM is the right code: §7 defines it for a peer generating
// excessive load, which is precisely the accusation, and unlike PROTOCOL_ERROR it
// does not claim the peer sent something malformed.
func (rd *Reader) checkBlockLimits() error {
	if rd.blockSize > uint64(rd.maxHeaderBlockSize) {
		return connErrf(h2.EnhanceYourCalm,
			"header block on stream %d has reached %d compressed octets, above the %d limit "+
				"(RFC 9113 §7, CVE-2023-45288)",
			rd.blockStream, rd.blockSize, rd.maxHeaderBlockSize)
	}
	if rd.continuations > rd.maxContinuations {
		return connErrf(h2.EnhanceYourCalm,
			"header block on stream %d has been spread over %d CONTINUATION frames, "+
				"above the %d limit (RFC 9113 §7, CVE-2023-45288)",
			rd.blockStream, rd.continuations, rd.maxContinuations)
	}
	return nil
}

// BlockOpen reports the stream whose header block is still open, or 0 if none
// is. A connection that ends with a block open ended mid-block, which is worth
// saying in a log rather than leaving as a silent truncation.
func (rd *Reader) BlockOpen() uint32 { return rd.blockStream }
