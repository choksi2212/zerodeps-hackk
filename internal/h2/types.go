// Package h2 holds the vocabulary shared by both halves of this server: the
// header field type, the HPACK codec interface, and the RFC 9113 §7 error
// codes.
//
// It imports nothing from this module, so no import cycle is possible between
// the framing half and the HPACK half.
//
// This file is a frozen contract. Both halves compile against it, so changing
// a signature here breaks the other author's build; changes require agreement
// from both of us.
package h2

import "fmt"

// Field is one HTTP/2 header field: the output of HPACK decoding and the input
// to HPACK encoding.
//
// The codec treats Name and Value as opaque byte strings. Every HTTP-level
// rule about them — lowercase names, valid token characters, pseudo-header
// ordering (RFC 9113 §8.2) — is enforced by the server, not by the codec.
type Field struct {
	Name  string
	Value string

	// Sensitive marks a field that must never be entered into the HPACK
	// dynamic table and must be encoded as a never-indexed literal
	// (RFC 7541 §6.2.3), so that a compression oracle cannot recover it by
	// observing encoded sizes across requests.
	Sensitive bool
}

// HeaderCodec is an HPACK (RFC 7541) codec for one direction of one
// connection.
//
// Implementations are not safe for concurrent use, and that is deliberate.
// The HPACK dynamic table is connection-scoped and order-dependent: every
// header block on a connection must be decoded in the exact order it arrived,
// from a single goroutine. Two goroutines sharing a codec desynchronise the
// table and silently corrupt every later request on that connection.
type HeaderCodec interface {
	// Encode compresses fields into one header block fragment. The caller
	// splits the result across HEADERS and CONTINUATION frames if it exceeds
	// the peer's SETTINGS_MAX_FRAME_SIZE.
	Encode(fields []Field) []byte

	// Decode expands one complete header block: the HEADERS frame payload
	// concatenated with the payloads of any CONTINUATION frames that followed
	// it. A non-nil error is always fatal to the connection
	// (COMPRESSION_ERROR) — the dynamic table cannot be resynchronised after
	// a malformed block.
	Decode(block []byte) ([]Field, error)

	// SetMaxDynamicTableSize applies a peer SETTINGS_HEADER_TABLE_SIZE value,
	// evicting entries as needed to fit (RFC 7541 §4.3).
	SetMaxDynamicTableSize(n int)
}

// ErrCode is an RFC 9113 §7 error code, as carried in RST_STREAM and GOAWAY.
type ErrCode uint32

// The error codes defined by RFC 9113 §7. Codes outside this set are legal on
// the wire; a receiver must treat an unknown code as InternalError rather than
// rejecting the frame.
const (
	NoError            ErrCode = 0x0
	ProtocolError      ErrCode = 0x1
	InternalError      ErrCode = 0x2
	FlowControlError   ErrCode = 0x3
	SettingsTimeout    ErrCode = 0x4
	StreamClosed       ErrCode = 0x5
	FrameSizeError     ErrCode = 0x6
	RefusedStream      ErrCode = 0x7
	Cancel             ErrCode = 0x8
	CompressionError   ErrCode = 0x9
	ConnectError       ErrCode = 0xa
	EnhanceYourCalm    ErrCode = 0xb
	InadequateSecurity ErrCode = 0xc
	HTTP11Required     ErrCode = 0xd
)

// errCodeNames is indexed by error code. The spellings are the RFC's, because
// these strings are read side by side with h2spec output.
var errCodeNames = [...]string{
	"NO_ERROR",
	"PROTOCOL_ERROR",
	"INTERNAL_ERROR",
	"FLOW_CONTROL_ERROR",
	"SETTINGS_TIMEOUT",
	"STREAM_CLOSED",
	"FRAME_SIZE_ERROR",
	"REFUSED_STREAM",
	"CANCEL",
	"COMPRESSION_ERROR",
	"CONNECT_ERROR",
	"ENHANCE_YOUR_CALM",
	"INADEQUATE_SECURITY",
	"HTTP_1_1_REQUIRED",
}

// String returns the RFC 9113 spelling of the code, or a hex form for the
// unassigned codes a peer is allowed to send.
func (c ErrCode) String() string {
	if int(c) < len(errCodeNames) {
		return errCodeNames[c]
	}
	return fmt.Sprintf("UNKNOWN_ERROR(0x%x)", uint32(c))
}

// ConnError is a connection error (RFC 9113 §5.4.1): the server sends GOAWAY
// carrying the highest stream ID it processed, then closes the TCP connection.
//
// Whether a violation is a ConnError or a StreamError is per-frame-type and
// exhaustively specified; keeping the two in the type system is what stops the
// distinction from being decided by accident at the call site.
type ConnError struct {
	Code   ErrCode
	Reason string
}

func (e ConnError) Error() string {
	return "http2: connection error: " + e.Code.String() + ": " + e.Reason
}

// StreamError is a stream error (RFC 9113 §5.4.2): the server sends RST_STREAM
// on that one stream and the connection carries on serving the others.
type StreamError struct {
	StreamID uint32
	Code     ErrCode
	Reason   string
}

func (e StreamError) Error() string {
	return fmt.Sprintf("http2: stream error: stream %d: %s: %s",
		e.StreamID, e.Code.String(), e.Reason)
}

// ConnErrorf builds a ConnError with a formatted reason.
func ConnErrorf(code ErrCode, format string, args ...any) ConnError {
	return ConnError{Code: code, Reason: fmt.Sprintf(format, args...)}
}

// StreamErrorf builds a StreamError with a formatted reason.
func StreamErrorf(id uint32, code ErrCode, format string, args ...any) StreamError {
	return StreamError{StreamID: id, Code: code, Reason: fmt.Sprintf(format, args...)}
}
