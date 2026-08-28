package frame

import "zerodeps/zdh/internal/h2"

// HeadersFrame is a HEADERS frame (RFC 9113 §6.2): the start of a request, and
// the first fragment of an HPACK header block.
//
// Its payload has up to four parts in a fixed order — pad length, priority
// block, header block fragment, padding — and which of them are present depends
// on the flags.
type HeadersFrame struct {
	StreamID uint32

	// EndStream marks a request with no body.
	EndStream bool

	// EndHeaders marks the header block as complete. When it is clear, the block
	// continues in CONTINUATION frames, and until it ends the connection may
	// carry nothing else at all (§6.10). That continuity rule is the reader's,
	// not this frame's: one frame cannot see what came before it.
	EndHeaders bool

	// Fragment is this frame's slice of the HPACK header block, with padding and
	// the priority block already removed. It is a private copy.
	//
	// It is not decoded here. HPACK is stateful across a whole connection, so a
	// block can only be decoded in arrival order by the one goroutine that owns
	// the codec; a parser that decoded would be the wrong place and, for a block
	// spread over CONTINUATION frames, would also be decoding a fragment of a
	// block rather than a block.
	Fragment []byte

	// Priority reports whether the PRIORITY flag was set, and the block's fields
	// if so. RFC 9218 deprecates the scheme, but the octets still arrive and are
	// still part of the frame's length, so they are still parsed.
	Priority         bool
	Exclusive        bool
	StreamDependency uint32
	Weight           uint8

	// Padded and PadLen carry the padding envelope, for the reason set out on
	// DataFrame: the frame has to be able to reproduce its own on-wire length.
	Padded bool
	PadLen uint8
}

func (f HeadersFrame) Type() FrameType { return TypeHeaders }

func (f HeadersFrame) Flags() Flags {
	return Flags(0).
		set(FlagEndStream, f.EndStream).
		set(FlagEndHeaders, f.EndHeaders).
		set(FlagPadded, f.Padded).
		set(FlagPriority, f.Priority)
}

func (f HeadersFrame) Stream() uint32 { return f.StreamID }

func (f HeadersFrame) PayloadLen() uint32 {
	n := len(f.Fragment)
	if f.Priority {
		n += priorityLen
	}
	return paddedLen(f.Padded, f.PadLen, n)
}

func (f HeadersFrame) appendPayload(dst []byte) []byte {
	// The priority block sits inside the padding envelope, so it is assembled
	// with the fragment and the pair is wrapped together.
	if !f.Priority {
		return appendPadded(dst, f.Padded, f.PadLen, f.Fragment)
	}

	// One allocation is the price of not writing the padding envelope out twice.
	// It happens only for a frame that both carries a priority block and is
	// padded, which is a frame we never send.
	content := make([]byte, 0, priorityLen+len(f.Fragment))
	content = appendPriorityBlock(content, f.Exclusive, f.StreamDependency, f.Weight)
	content = append(content, f.Fragment...)
	return appendPadded(dst, f.Padded, f.PadLen, content)
}

// parseHeaders parses a HEADERS frame payload.
//
// A self-dependency in the priority block is deliberately not rejected here,
// even though RFC 7540 §5.3.1 makes it a stream error and h2spec tests for it.
// Reporting it would mean returning no frame, which would discard the header
// block fragment — and §5.4.2 requires the HPACK state to be maintained even for
// a stream that is being reset, because the dynamic table is connection-scoped
// and cannot be resynchronised after a skipped block. The check therefore belongs
// to internal/stream, which resets the stream after the block has been handed to
// the codec. A standalone PRIORITY frame carries no such state, which is why
// parsePriority does reject it.
func parseHeaders(h Header, payload []byte) (Frame, error) {
	if h.StreamID == 0 {
		return nil, connErrf(h2.ProtocolError,
			"HEADERS on the connection, must be on a stream (RFC 9113 §6.2)")
	}

	content, padLen, err := splitPadding(h, payload, "HEADERS")
	if err != nil {
		return nil, err
	}

	f := HeadersFrame{
		StreamID:   h.StreamID,
		EndStream:  h.Flags.has(FlagEndStream),
		EndHeaders: h.Flags.has(FlagEndHeaders),
		Priority:   h.Flags.has(FlagPriority),
		Padded:     h.Flags.has(FlagPadded),
		PadLen:     padLen,
	}

	if f.Priority {
		// A frame size error in HEADERS is fatal to the connection rather than to
		// the stream: the header block it carries cannot be decoded, so the HPACK
		// table is left desynchronised and every later request on the connection
		// would decode to nonsense (§4.2).
		if len(content) < priorityLen {
			return nil, connErrf(h2.FrameSizeError,
				"HEADERS has the PRIORITY flag but only %d octets after padding, want at least %d (RFC 9113 §6.2)",
				len(content), priorityLen)
		}
		f.Exclusive, f.StreamDependency, f.Weight = parsePriorityBlock(content[:priorityLen])
		content = content[priorityLen:]
	}

	if len(content) > 0 {
		// Copied, not aliased. The fragment outlives this call by definition: a
		// block spread over CONTINUATION frames is accumulated across several
		// reads of the same buffer.
		f.Fragment = append([]byte(nil), content...)
	}
	return f, nil
}
