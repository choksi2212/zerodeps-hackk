package frame

import (
	"encoding/binary"

	"zerodeps/zdh/internal/h2"
)

// priorityUpdateFixedLen is the size of the fixed part of a PRIORITY_UPDATE
// payload: one reserved bit and a 31-bit Prioritized Stream ID (RFC 9218 §7.1).
// The Priority Field Value follows it with no length of its own, running to the
// end of the frame — which is why this is a minimum and not the payload size.
const priorityUpdateFixedLen = 4

// PriorityUpdateFrame is a PRIORITY_UPDATE frame (RFC 9218 §7.1).
//
// It is the frame that replaces the one this server ignores. RFC 9113 §5.3
// withdrew RFC 7540's dependency trees, and RFC 9218 puts an extensible priority
// signal in their place: a stream identifier and a structured field value naming
// the parameters, sent on the connection rather than on the stream it is about.
// That last part is what makes it useful — a client can reprioritize a response
// it has already requested, and can signal a priority before the stream exists.
//
// There is no StreamID field, for the same reason SETTINGS and PING have none:
// §7.1 requires the frame header's stream identifier to be zero, so a
// PRIORITY_UPDATE on a stream is not a mistake to catch later — it cannot be
// built. The identifier that matters is in the payload, and it is a different
// field with a different rule.
//
// This frame is only ever received. §7.1 of RFC 9218: "Servers MUST NOT send
// PRIORITY_UPDATE frames." It is still serialisable, because the round-trip tests
// are what prove the parser reads what a client writes, and because internal/attack
// builds client-side frames from this package.
type PriorityUpdateFrame struct {
	// PrioritizedStreamID is the stream the signal applies to. It is never zero:
	// §7.1 makes a zero there a connection error, and the parser enforces it, so
	// no PriorityUpdateFrame with a zero here can come off the wire.
	//
	// The reserved bit that shares its first octet is not represented, for the
	// same reason the frame header's is not: it must be ignored on receipt and
	// sent as zero (§4.1 of RFC 9113).
	PrioritizedStreamID uint32

	// Field is the Priority Field Value: the priority parameters as a structured
	// field Dictionary in ASCII, the same text the Priority header field carries
	// (§7.1). An empty Field is legal and means every parameter takes its default.
	//
	// It is held as written, not parsed. Two reasons. This layer decides whether a
	// frame is well formed, and §7.1 puts no syntax rule on these octets — the
	// grammar belongs to RFC 9651, and §7 makes failing to parse it a MAY, so
	// which response to take is a policy decision this layer must not make for its
	// caller. And it keeps the frame layer from importing a parser, which would
	// put structured-field syntax on the path of every frame read.
	//
	// A string rather than a []byte, because that is what a parser takes and
	// because converting from the reader's buffer copies — the reader reuses that
	// buffer for the next frame, and a frame that aliased it would change under
	// its owner.
	Field string
}

func (f PriorityUpdateFrame) Type() FrameType { return TypePriorityUpdate }
func (f PriorityUpdateFrame) Flags() Flags    { return 0 }

// Stream is always 0: this frame is a connection-level signal about a stream, not
// a frame on one (§7.1). The stream it is about is PrioritizedStreamID, and the
// two are deliberately not the same accessor — a caller that confused them would
// credit the wrong stream, or the connection.
func (f PriorityUpdateFrame) Stream() uint32 { return 0 }

func (f PriorityUpdateFrame) PayloadLen() uint32 {
	return priorityUpdateFixedLen + uint32(len(f.Field))
}

func (f PriorityUpdateFrame) appendPayload(dst []byte) []byte {
	// The reserved bit is sent as zero (§4.1 of RFC 9113), which is what the mask
	// guarantees for a caller that put a full 32-bit value in the field.
	dst = binary.BigEndian.AppendUint32(dst, f.PrioritizedStreamID&streamIDMask)
	return append(dst, f.Field...)
}

// parsePriorityUpdate parses a PRIORITY_UPDATE frame payload.
//
// All three failures are connection errors, so unlike parsePriority the order of
// the checks does not decide the connection's fate — it decides which diagnosis
// is reported. They are ordered from the outside in for that reason: the frame
// header's stream identifier is decidable without looking at the payload, the
// length decides whether the payload can be read at all, and only then is the
// identifier inside it worth naming.
func parsePriorityUpdate(h Header, payload []byte) (Frame, error) {
	if h.StreamID != 0 {
		// §7.1 of RFC 9218: "The Stream Identifier field (see Section 5.1.1 of
		// [HTTP/2]) in the PRIORITY_UPDATE frame header MUST be zero (0x0)."
		return nil, connErrf(h2.ProtocolError,
			"PRIORITY_UPDATE on stream %d, must be on the connection (RFC 9218 §7.1)",
			h.StreamID)
	}
	if h.Length < priorityUpdateFixedLen {
		// RFC 9218 names no error for a payload too short to hold the identifier
		// it requires, so this is the general rule: §4.2 of RFC 9113 makes a frame
		// too small to contain a mandatory field a FRAME_SIZE_ERROR, and one at
		// connection scope, because a frame this malformed leaves nothing to reset
		// a stream about.
		return nil, connErrf(h2.FrameSizeError,
			"PRIORITY_UPDATE length %d, want at least the %d octets of the prioritized "+
				"stream identifier (RFC 9113 §4.2)",
			h.Length, priorityUpdateFixedLen)
	}

	id := binary.BigEndian.Uint32(payload[:priorityUpdateFixedLen]) & streamIDMask
	if id == 0 {
		// §7.1 of RFC 9218: "If a PRIORITY_UPDATE frame is received with a
		// prioritized stream ID of 0x0, the recipient MUST respond with a connection
		// error of type PROTOCOL_ERROR." Note that this is the payload's identifier,
		// where the rule above is the header's: zero is required in one field and
		// forbidden in the other, four octets apart.
		return nil, connErrf(h2.ProtocolError,
			"PRIORITY_UPDATE names prioritized stream 0, which is the connection and "+
				"cannot have a priority (RFC 9218 §7.1)")
	}

	return PriorityUpdateFrame{
		PrioritizedStreamID: id,
		// Sliced to the declared length, not to the end of the buffer: the scratch
		// slice a parser is handed may be longer than the frame, and reading to its
		// end would splice the next frame's octets into this one's priority field.
		// The conversion also copies, which is required for the same reason —
		// payload is that scratch buffer, and the next frame overwrites it.
		Field: string(payload[priorityUpdateFixedLen:h.Length]),
	}, nil
}
