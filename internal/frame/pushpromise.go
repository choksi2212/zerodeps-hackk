package frame

import (
	"encoding/binary"

	"zerodeps/zdh/internal/h2"
)

// promisedIDLen is the size of the reserved bit plus the 31-bit promised stream
// identifier that opens a PUSH_PROMISE payload (RFC 9113 §6.6).
const promisedIDLen = 4

// PushPromiseFrame is a PUSH_PROMISE frame (RFC 9113 §6.6): a sender announcing
// a stream it is about to push.
//
// This server never sends one — it advertises SETTINGS_ENABLE_PUSH of 0 — and a
// client is forbidden from sending one at all (§8.4). The type exists anyway, for
// two reasons. The frame type is registered, so a reader that could not name it
// would have to route it through the unknown-type path and silently discard a
// frame it is required to reject. And both of the rules that reject it —
// "we disabled push" and "you are a client" — are statements about connection
// state and peer role, not about these octets; a parser that hard-coded either
// would be encoding an assumption it cannot check.
//
// So the frame is parsed for what it structurally is, and the connection layer
// refuses it, which is also where the RFC puts the error: receipt of a
// PUSH_PROMISE when push is disabled is a connection error of type PROTOCOL_ERROR.
type PushPromiseFrame struct {
	// StreamID is the stream the promise arrived on, not the stream promised.
	StreamID uint32

	// PromisedID is the stream being promised. §5.1.1 reserves even identifiers
	// for the server, so a legal value here is always even; whether it is also in
	// range and unused is a question about connection state, answered by the
	// connection layer.
	PromisedID uint32

	// EndHeaders marks the header block complete; otherwise CONTINUATION frames
	// follow.
	EndHeaders bool

	// Fragment is this frame's slice of the HPACK header block, as a private
	// copy.
	Fragment []byte

	// Padded and PadLen carry the padding envelope, for the reason set out on
	// DataFrame.
	Padded bool
	PadLen uint8
}

func (f PushPromiseFrame) Type() FrameType { return TypePushPromise }

func (f PushPromiseFrame) Flags() Flags {
	return Flags(0).
		set(FlagEndHeaders, f.EndHeaders).
		set(FlagPadded, f.Padded)
}

func (f PushPromiseFrame) Stream() uint32 { return f.StreamID }

func (f PushPromiseFrame) PayloadLen() uint32 {
	return paddedLen(f.Padded, f.PadLen, promisedIDLen+len(f.Fragment))
}

func (f PushPromiseFrame) appendPayload(dst []byte) []byte {
	// The promised identifier sits inside the padding envelope, so it is
	// assembled with the fragment and the pair wrapped together.
	content := make([]byte, 0, promisedIDLen+len(f.Fragment))
	content = binary.BigEndian.AppendUint32(content, f.PromisedID&streamIDMask)
	content = append(content, f.Fragment...)
	return appendPadded(dst, f.Padded, f.PadLen, content)
}

// parsePushPromise parses a PUSH_PROMISE frame payload.
func parsePushPromise(h Header, payload []byte) (Frame, error) {
	if h.StreamID == 0 {
		return nil, connErrf(h2.ProtocolError,
			"PUSH_PROMISE on the connection, must be on a stream (RFC 9113 §6.6)")
	}

	content, padLen, err := splitPadding(h, payload, "PUSH_PROMISE")
	if err != nil {
		return nil, err
	}

	// Fatal to the connection rather than to the stream, for the same reason as
	// HEADERS: the header block cannot be decoded, so the HPACK table is left
	// desynchronised (§4.2).
	if len(content) < promisedIDLen {
		return nil, connErrf(h2.FrameSizeError,
			"PUSH_PROMISE is %d octets after padding, want at least %d for the promised identifier (RFC 9113 §6.6)",
			len(content), promisedIDLen)
	}

	f := PushPromiseFrame{
		StreamID: h.StreamID,
		// Masked: a reserved bit read as part of the number turns stream 2 into
		// stream 2147483650.
		PromisedID: binary.BigEndian.Uint32(content[:promisedIDLen]) & streamIDMask,
		EndHeaders: h.Flags.has(FlagEndHeaders),
		Padded:     h.Flags.has(FlagPadded),
		PadLen:     padLen,
	}
	if f.PromisedID == 0 {
		return nil, connErrf(h2.ProtocolError,
			"PUSH_PROMISE promises stream 0, which is not a stream (RFC 9113 §6.6)")
	}

	content = content[promisedIDLen:]
	if len(content) > 0 {
		// Copied, not aliased.
		f.Fragment = append([]byte(nil), content...)
	}
	return f, nil
}
