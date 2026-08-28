package frame

import "zerodeps/zdh/internal/h2"

// PriorityFrame is a PRIORITY frame (RFC 9113 §6.3).
//
// Prioritization is deprecated. RFC 9113 §5.3 withdrew the dependency-tree
// scheme that RFC 7540 defined, and RFC 9218 replaces it with a different
// mechanism this server does not implement. So PRIORITY frames are parsed,
// validated, and then deliberately ignored: the contents affect nothing.
//
// That is the specified behaviour rather than an omission, and it is matrix
// row 10. A receiver still has to accept a well-formed PRIORITY frame, still has
// to reject a malformed one with the right error at the right scope, and the
// frame still has to be consumed so the connection stays byte-synchronised.
type PriorityFrame struct {
	StreamID uint32

	// Exclusive is the E bit of the priority block.
	Exclusive bool

	// StreamDependency is the 31-bit dependency. The E bit is not part of it.
	StreamDependency uint32

	// Weight is the weight octet exactly as it appears on the wire. §6.3
	// defines the effective weight as Weight+1, in the range 1..256, but the
	// raw octet is stored so that a frame round-trips byte for byte.
	Weight uint8
}

func (f PriorityFrame) Type() FrameType    { return TypePriority }
func (f PriorityFrame) Flags() Flags       { return 0 }
func (f PriorityFrame) Stream() uint32     { return f.StreamID }
func (f PriorityFrame) PayloadLen() uint32 { return priorityLen }

func (f PriorityFrame) appendPayload(dst []byte) []byte {
	return appendPriorityBlock(dst, f.Exclusive, f.StreamDependency, f.Weight)
}

// parsePriority parses a PRIORITY frame payload.
//
// Note the ordering: the stream identifier is checked before the length. A
// PRIORITY frame on stream 0 with a wrong length violates both rules, and they
// disagree about scope — stream 0 kills the connection, a bad length only kills
// the stream. The connection-level rule has to win, or a peer can provoke us
// into keeping a connection we are required to close.
func parsePriority(h Header, payload []byte) (Frame, error) {
	if h.StreamID == 0 {
		return nil, connErrf(h2.ProtocolError,
			"PRIORITY on stream 0 (RFC 9113 §6.3)")
	}
	if h.Length != priorityLen {
		// The only length rule in the protocol that spares the connection.
		// §6.3: "A PRIORITY frame with a length other than 5 octets MUST be
		// treated as a stream error of type FRAME_SIZE_ERROR."
		return nil, streamErrf(h.StreamID, h2.FrameSizeError,
			"PRIORITY length %d, want %d (RFC 9113 §6.3)", h.Length, priorityLen)
	}

	exclusive, dep, weight := parsePriorityBlock(payload)
	if dep == h.StreamID {
		// RFC 7540 §5.3.1: a stream cannot depend on itself, and doing so is a
		// stream error of type PROTOCOL_ERROR. RFC 9113 dropped the rule along
		// with the rest of the priority scheme without declaring the frame
		// valid, so the older, stricter reading is kept: it costs three lines,
		// it matches what Go's own HTTP/2 implementation does, and h2spec still
		// tests for it.
		return nil, streamErrf(h.StreamID, h2.ProtocolError,
			"PRIORITY: stream %d depends on itself (RFC 7540 §5.3.1)", h.StreamID)
	}

	return PriorityFrame{
		StreamID:         h.StreamID,
		Exclusive:        exclusive,
		StreamDependency: dep,
		Weight:           weight,
	}, nil
}

// parsePriorityBlock decodes the 5-octet priority block that appears in a
// PRIORITY frame and, when the PRIORITY flag is set, at the front of a HEADERS
// payload. b must be at least priorityLen long.
//
// The E bit shares an octet with the top of the stream dependency, so the
// dependency is masked for the same reason the frame header's stream identifier
// is: a flag bit read as part of a number turns stream 1 into stream 2147483649.
func parsePriorityBlock(b []byte) (exclusive bool, dep uint32, weight uint8) {
	exclusive = b[0]&0x80 != 0
	dep = (uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])) & streamIDMask
	weight = b[4]
	return exclusive, dep, weight
}

// appendPriorityBlock appends the 5-octet priority block to dst.
func appendPriorityBlock(dst []byte, exclusive bool, dep uint32, weight uint8) []byte {
	hi := byte(dep>>24) & 0x7f
	if exclusive {
		hi |= 0x80
	}
	return append(dst, hi, byte(dep>>16), byte(dep>>8), byte(dep), weight)
}
