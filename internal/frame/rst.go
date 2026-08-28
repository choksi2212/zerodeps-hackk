package frame

import (
	"encoding/binary"

	"zerodeps/zdh/internal/h2"
)

// rstStreamLen is the fixed payload size of a RST_STREAM frame: one 32-bit
// error code (RFC 9113 §6.4).
const rstStreamLen = 4

// RSTStreamFrame is a RST_STREAM frame (RFC 9113 §6.4): an abrupt termination
// of one stream.
//
// This is the frame at the centre of CVE-2023-44487, "Rapid Reset". A peer can
// open a stream and immediately reset it, over and over: each cycle costs the
// server a HPACK decode, a stream allocation and a handler dispatch, but the
// stream closes at once so it never counts against SETTINGS_MAX_CONCURRENT_STREAMS.
// A concurrency limit alone does not defend against it. The rate limit lives in
// internal/limits, because it is a property of the connection over time rather
// than of any single frame.
type RSTStreamFrame struct {
	StreamID uint32
	ErrCode  h2.ErrCode
}

func (f RSTStreamFrame) Type() FrameType    { return TypeRSTStream }
func (f RSTStreamFrame) Flags() Flags       { return 0 }
func (f RSTStreamFrame) Stream() uint32     { return f.StreamID }
func (f RSTStreamFrame) PayloadLen() uint32 { return rstStreamLen }

func (f RSTStreamFrame) appendPayload(dst []byte) []byte {
	return binary.BigEndian.AppendUint32(dst, uint32(f.ErrCode))
}

// parseRSTStream parses a RST_STREAM frame payload.
//
// A RST_STREAM naming a stream that has never been opened is also a connection
// error (§6.4), but that needs the stream registry to detect, so it is enforced
// in internal/stream rather than here.
//
// The error code is not validated against the assigned set. §7 requires unknown
// error codes to be treated as INTERNAL_ERROR rather than rejected, and that
// interpretation belongs to the layer acting on the reset, not to the parser.
func parseRSTStream(h Header, payload []byte) (Frame, error) {
	if h.StreamID == 0 {
		return nil, connErrf(h2.ProtocolError,
			"RST_STREAM on stream 0 (RFC 9113 §6.4)")
	}
	if h.Length != rstStreamLen {
		return nil, connErrf(h2.FrameSizeError,
			"RST_STREAM length %d, want %d (RFC 9113 §6.4)", h.Length, rstStreamLen)
	}
	return RSTStreamFrame{
		StreamID: h.StreamID,
		ErrCode:  h2.ErrCode(binary.BigEndian.Uint32(payload[:rstStreamLen])),
	}, nil
}
