package frame

import (
	"encoding/binary"

	"zerodeps/zdh/internal/h2"
)

// windowUpdateLen is the fixed payload size of a WINDOW_UPDATE frame: one
// reserved bit and a 31-bit increment (RFC 9113 §6.9).
const windowUpdateLen = 4

// WindowUpdateFrame is a WINDOW_UPDATE frame (RFC 9113 §6.9).
//
// Unlike every other frame, this one is legal both on the connection and on a
// stream, and the two mean different things: stream 0 credits the connection
// window, a non-zero stream credits that stream's window. So there is no
// stream-identifier rule to enforce here — only the increment matters, and even
// then only its scope decides how badly a zero is punished.
type WindowUpdateFrame struct {
	// StreamID is 0 for the connection-level window, or the stream being
	// credited.
	StreamID uint32

	// Increment is the 31-bit credit. The reserved bit is not represented.
	Increment uint32
}

func (f WindowUpdateFrame) Type() FrameType    { return TypeWindowUpdate }
func (f WindowUpdateFrame) Flags() Flags       { return 0 }
func (f WindowUpdateFrame) Stream() uint32     { return f.StreamID }
func (f WindowUpdateFrame) PayloadLen() uint32 { return windowUpdateLen }

func (f WindowUpdateFrame) appendPayload(dst []byte) []byte {
	// The reserved bit is always sent as zero (§6.9).
	return binary.BigEndian.AppendUint32(dst, f.Increment&streamIDMask)
}

// parseWindowUpdate parses a WINDOW_UPDATE frame payload.
//
// A zero increment is an error whose scope depends on where it arrived: on the
// connection it is fatal, on a stream it only resets that stream (§6.9). Getting
// that backwards means either killing connections a peer is entitled to keep, or
// keeping a connection the protocol says must die.
//
// The increment overflowing a window past 2^31-1 is also a FLOW_CONTROL_ERROR,
// at the same two scopes, but that needs the current window value. It is
// enforced in internal/flow, which owns the window.
func parseWindowUpdate(h Header, payload []byte) (Frame, error) {
	if h.Length != windowUpdateLen {
		return nil, connErrf(h2.FrameSizeError,
			"WINDOW_UPDATE length %d, want %d (RFC 9113 §6.9)", h.Length, windowUpdateLen)
	}

	// The reserved bit is masked rather than rejected: a receiver must ignore
	// it, and an increment read with that bit included is off by 2^31.
	inc := binary.BigEndian.Uint32(payload[:windowUpdateLen]) & streamIDMask

	if inc == 0 {
		if h.StreamID == 0 {
			return nil, connErrf(h2.ProtocolError,
				"WINDOW_UPDATE with a zero increment on the connection (RFC 9113 §6.9)")
		}
		return nil, streamErrf(h.StreamID, h2.ProtocolError,
			"WINDOW_UPDATE with a zero increment on stream %d (RFC 9113 §6.9)", h.StreamID)
	}

	return WindowUpdateFrame{StreamID: h.StreamID, Increment: inc}, nil
}
