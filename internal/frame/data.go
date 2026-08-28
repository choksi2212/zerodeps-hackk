package frame

import "zerodeps/zdh/internal/h2"

// DataFrame is a DATA frame (RFC 9113 §6.1): request or response body octets.
type DataFrame struct {
	StreamID uint32

	// EndStream marks the last DATA frame of the stream, half-closing it.
	EndStream bool

	// Data is the frame's content with any padding already removed. It is a
	// private copy, not a view into the reader's buffer.
	Data []byte

	// Padded records that the PADDED flag was set, and PadLen how many padding
	// octets followed the content.
	//
	// Two fields rather than one, because the wire has two things to say and a
	// padded frame with zero padding octets is legal and distinct from an
	// unpadded frame: the pad-length field itself occupies an octet. That octet
	// is not bookkeeping — §6.9.1 counts the whole payload including padding
	// against the flow-control window, so a frame that could not reproduce its
	// own on-wire length would make the connection's window drift away from the
	// peer's until one side stalled.
	//
	// PadLen is only meaningful when Padded is set. Padded governs, exactly as
	// Ack governs on SETTINGS, so a struct with PadLen set and Padded clear
	// serialises as an unpadded frame rather than as something the peer must
	// reject.
	Padded bool
	PadLen uint8
}

func (f DataFrame) Type() FrameType { return TypeData }

func (f DataFrame) Flags() Flags {
	return Flags(0).
		set(FlagEndStream, f.EndStream).
		set(FlagPadded, f.Padded)
}

func (f DataFrame) Stream() uint32 { return f.StreamID }

func (f DataFrame) PayloadLen() uint32 {
	return paddedLen(f.Padded, f.PadLen, len(f.Data))
}

func (f DataFrame) appendPayload(dst []byte) []byte {
	return appendPadded(dst, f.Padded, f.PadLen, f.Data)
}

// parseData parses a DATA frame payload.
//
// Flow control is not applied here. A DATA frame that overruns the receiver's
// window is a well-formed frame that arrived at the wrong time, which is a
// judgement only the connection's window state can make; it lives in
// internal/flow. The same goes for DATA on a stream that is closed or idle,
// which belongs to internal/stream.
func parseData(h Header, payload []byte) (Frame, error) {
	if h.StreamID == 0 {
		return nil, connErrf(h2.ProtocolError,
			"DATA on the connection, must be on a stream (RFC 9113 §6.1)")
	}

	content, padLen, err := splitPadding(h, payload, "DATA")
	if err != nil {
		return nil, err
	}

	f := DataFrame{
		StreamID:  h.StreamID,
		EndStream: h.Flags.has(FlagEndStream),
		Padded:    h.Flags.has(FlagPadded),
		PadLen:    padLen,
	}
	if len(content) > 0 {
		// Copied, not aliased: content points into the reader's scratch buffer,
		// which the next frame overwrites. This frame is about to be handed to a
		// stream goroutine, so aliasing would be a data race that only sometimes
		// reproduces — and a body that silently changes under the application.
		f.Data = append([]byte(nil), content...)
	}
	return f, nil
}
