package frame

import (
	"encoding/binary"
	"fmt"
)

// Header is the 9-octet frame header (RFC 9113 §4.1):
//
//	+-----------------------------------------------+
//	|                 Length (24)                   |
//	+---------------+---------------+---------------+
//	|   Type (8)    |   Flags (8)   |
//	+-+-------------+---------------+---------------+
//	|R|                 Stream Identifier (31)      |
//	+=+=============================================+
//	|                   Payload (0..Length)       ...
//	+-----------------------------------------------+
//
// All fields are big-endian.
type Header struct {
	Length   uint32 // 24 bits on the wire
	Type     FrameType
	Flags    Flags
	StreamID uint32 // 31 bits on the wire; the reserved bit is not represented
}

// ParseHeader decodes the 9-octet header in b. It panics if b is shorter than
// HeaderLen; callers read the header with io.ReadFull, so a short buffer is a
// bug in this package rather than hostile input.
//
// The reserved bit of the stream identifier is masked off rather than reported.
// RFC 9113 §4.1 requires a receiver to ignore it, and h2spec sends a frame with
// it set to check that an implementation does not reject the frame — so
// "ignore" has to mean discarding the bit, not tolerating it in a field nobody
// looks at.
//
// No field can fail to parse: every 9-byte sequence is a syntactically valid
// frame header. Length, Type, Flags and StreamID are validated against each
// other by the per-type parsers, which is why this returns no error.
func ParseHeader(b []byte) Header {
	return Header{
		Length:   uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2]),
		Type:     FrameType(b[3]),
		Flags:    Flags(b[4]),
		StreamID: binary.BigEndian.Uint32(b[5:HeaderLen]) & streamIDMask,
	}
}

// AppendTo appends the wire form of h to dst. The reserved bit is always
// written as zero, as required by §4.1.
//
// Length must not exceed MaxLength and StreamID must not exceed streamIDMask;
// both fields are truncated to their wire width rather than reported, because
// there is no useful way for a nine-byte serialiser to fail. Writer enforces
// both bounds before calling this, since it is the layer that knows the peer's
// SETTINGS_MAX_FRAME_SIZE.
func (h Header) AppendTo(dst []byte) []byte {
	return append(dst,
		byte(h.Length>>16), byte(h.Length>>8), byte(h.Length),
		byte(h.Type),
		byte(h.Flags),
		byte(h.StreamID>>24)&0x7f, byte(h.StreamID>>16), byte(h.StreamID>>8), byte(h.StreamID),
	)
}

func (h Header) String() string {
	return fmt.Sprintf("[%s len=%d flags=0x%02x stream=%d]", h.Type, h.Length, uint8(h.Flags), h.StreamID)
}

// HeaderOf returns the header that would be written for f. The length is
// derived from the payload rather than stored on the frame, so a frame cannot
// carry a length that disagrees with its own contents.
func HeaderOf(f Frame) Header {
	return Header{
		Length:   f.PayloadLen(),
		Type:     f.Type(),
		Flags:    f.Flags(),
		StreamID: f.StreamID(),
	}
}
