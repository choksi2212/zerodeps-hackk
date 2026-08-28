package frame

import "zerodeps/zdh/internal/h2"

// padOverhead is the single pad-length octet that a padded frame carries in
// front of its content (RFC 9113 §6.1).
const padOverhead = 1

// maxPadLen is the largest padding a frame can declare, since the pad-length
// field is one octet.
const maxPadLen = 255

// zeroPad is the source of every padding octet we write. §6.1 requires padding
// to be zero, and maxPadLen is the most the one-octet field can express, so one
// shared read-only array serves every frame we send without allocating.
var zeroPad [maxPadLen]byte

// splitPadding removes the padding envelope from a frame payload and returns
// the content inside it.
//
// Padding is the outermost layer of a padded payload, so it has to come off
// before anything within can be located: in a HEADERS frame carrying both
// PADDED and PRIORITY, the priority block sits after the pad-length octet and
// before the padding, and neither boundary is known until the pad length is
// read.
//
// payload may be longer than the frame — the reader hands parsers a slice of a
// buffer it reuses — so every bound here is taken from h.Length rather than from
// len(payload).
//
// The padding octets themselves are discarded. §6.1 permits a receiver to ignore
// them, and retaining up to 255 octets per frame that nothing ever reads would
// be a cost paid on every frame to no end. padLen is returned instead, which is
// all a caller needs: the frame's on-wire length has to stay reproducible
// because §6.9.1 counts padding against the flow-control window.
func splitPadding(h Header, payload []byte, name string) (content []byte, padLen uint8, err error) {
	if !h.Flags.has(FlagPadded) {
		return payload[:h.Length], 0, nil
	}
	if h.Length < padOverhead {
		return nil, 0, connErrf(h2.FrameSizeError,
			"%s has the PADDED flag but is %d octets, too short for the pad-length field (RFC 9113 §6.1)",
			name, h.Length)
	}

	padLen = payload[0]

	// The pad length counts the octets after the pad-length field, so the field
	// plus the padding must leave room for the frame's own content — even if
	// that content is empty. Stated as the RFC states it: padding as long as the
	// payload or longer is a connection error.
	//
	// The subtraction below underflows without this check, and on a uint32 that
	// is not a panic but a slice bound near four billion.
	if uint32(padLen) >= h.Length {
		return nil, 0, connErrf(h2.ProtocolError,
			"%s declares %d octets of padding in a %d-octet payload (RFC 9113 §6.1)",
			name, padLen, h.Length)
	}

	return payload[padOverhead : h.Length-uint32(padLen)], padLen, nil
}

// paddedLen is the on-wire payload length of a frame whose content is
// contentLen octets.
func paddedLen(padded bool, padLen uint8, contentLen int) uint32 {
	n := uint32(contentLen)
	if padded {
		n += padOverhead + uint32(padLen)
	}
	return n
}

// appendPadded writes content wrapped in its padding envelope.
func appendPadded(dst []byte, padded bool, padLen uint8, content []byte) []byte {
	if !padded {
		return append(dst, content...)
	}
	dst = append(dst, padLen)
	dst = append(dst, content...)
	return append(dst, zeroPad[:padLen]...)
}
