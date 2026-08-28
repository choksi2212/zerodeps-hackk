package frame

import "zerodeps/zdh/internal/h2"

// pingLen is the fixed payload size of a PING frame: 8 octets of opaque data
// (RFC 9113 §6.7).
const pingLen = 8

// PingFrame is a PING frame (RFC 9113 §6.7).
//
// There is no StreamID field. PING is only ever valid on the connection, so a
// PING on a stream is unrepresentable rather than being a mistake to catch.
//
// Data is a fixed array rather than a slice, so echoing a PING back allocates
// nothing. That matters: PING is the cheapest frame a peer can flood us with,
// and every reply we send must be cheaper than the request that provoked it.
type PingFrame struct {
	// Ack distinguishes a reply from a request. A PING without it must be
	// answered by a PING with it, carrying the same 8 octets unchanged.
	Ack bool

	// Data is the opaque payload. Its contents are meaningless to us; the only
	// requirement is that a reply reproduces them exactly.
	Data [pingLen]byte
}

func (f PingFrame) Type() FrameType    { return TypePing }
func (f PingFrame) Flags() Flags       { return Flags(0).set(FlagAck, f.Ack) }
func (f PingFrame) Stream() uint32     { return 0 }
func (f PingFrame) PayloadLen() uint32 { return pingLen }

func (f PingFrame) appendPayload(dst []byte) []byte {
	return append(dst, f.Data[:]...)
}

// parsePing parses a PING frame payload.
//
// Sending the reply is not done here — a parser that answered frames would be
// writing to the socket from the reader goroutine, and exactly one goroutine
// owns the write half of the connection. The connection loop replies, so matrix
// row 24 is enforced in internal/server.
func parsePing(h Header, payload []byte) (Frame, error) {
	if h.StreamID != 0 {
		return nil, connErrf(h2.ProtocolError,
			"PING on stream %d, must be on the connection (RFC 9113 §6.7)", h.StreamID)
	}
	if h.Length != pingLen {
		return nil, connErrf(h2.FrameSizeError,
			"PING length %d, want %d (RFC 9113 §6.7)", h.Length, pingLen)
	}

	f := PingFrame{Ack: h.Flags.has(FlagAck)}
	// Copied into the array rather than aliased: payload points into the
	// reader's scratch buffer, which the next frame overwrites.
	copy(f.Data[:], payload[:pingLen])
	return f, nil
}
