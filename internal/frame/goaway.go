package frame

import (
	"encoding/binary"

	"zerodeps/zdh/internal/h2"
)

// goAwayMinLen is the smallest legal GOAWAY payload: a 31-bit last-stream
// identifier and a 32-bit error code, with debug data optional (RFC 9113 §6.8).
const goAwayMinLen = 8

// GoAwayFrame is a GOAWAY frame (RFC 9113 §6.8): the connection is shutting
// down.
//
// There is no StreamID field; GOAWAY is only ever valid on the connection.
type GoAwayFrame struct {
	// LastStreamID is the highest-numbered stream the sender may have acted on.
	// Anything above it can be safely retried on a new connection, which is the
	// whole point of the frame.
	LastStreamID uint32

	// ErrCode says why. NO_ERROR means a graceful shutdown.
	ErrCode h2.ErrCode

	// Debug is opaque diagnostic data. §6.8 permits any content and requires a
	// receiver not to act on it, so it is only ever logged.
	//
	// It arrives from the peer, so it is untrusted: it must never be
	// interpolated into anything that parses it, and it is logged with %q so a
	// peer cannot inject terminal escapes or forge log lines.
	Debug []byte
}

func (f GoAwayFrame) Type() FrameType { return TypeGoAway }
func (f GoAwayFrame) Flags() Flags    { return 0 }
func (f GoAwayFrame) Stream() uint32  { return 0 }
func (f GoAwayFrame) PayloadLen() uint32 {
	return goAwayMinLen + uint32(len(f.Debug))
}

func (f GoAwayFrame) appendPayload(dst []byte) []byte {
	// The reserved bit of the last-stream identifier is always sent as zero.
	dst = binary.BigEndian.AppendUint32(dst, f.LastStreamID&streamIDMask)
	dst = binary.BigEndian.AppendUint32(dst, uint32(f.ErrCode))
	return append(dst, f.Debug...)
}

// parseGoAway parses a GOAWAY frame payload.
//
// The error code is not validated against the assigned set: §7 requires an
// unknown code to be treated as INTERNAL_ERROR rather than rejected, and that
// belongs to the layer shutting the connection down.
func parseGoAway(h Header, payload []byte) (Frame, error) {
	if h.StreamID != 0 {
		return nil, connErrf(h2.ProtocolError,
			"GOAWAY on stream %d, must be on the connection (RFC 9113 §6.8)", h.StreamID)
	}
	if h.Length < goAwayMinLen {
		return nil, connErrf(h2.FrameSizeError,
			"GOAWAY length %d, want at least %d (RFC 9113 §6.8)", h.Length, goAwayMinLen)
	}

	f := GoAwayFrame{
		// Masked for the same reason as everywhere else: a reserved bit read as
		// part of a number turns stream 1 into stream 2147483649.
		LastStreamID: binary.BigEndian.Uint32(payload[0:4]) & streamIDMask,
		ErrCode:      h2.ErrCode(binary.BigEndian.Uint32(payload[4:8])),
	}
	if h.Length > goAwayMinLen {
		// Copied, not aliased: payload points into the reader's scratch buffer,
		// which the next frame overwrites.
		f.Debug = append([]byte(nil), payload[goAwayMinLen:h.Length]...)
	}
	return f, nil
}
