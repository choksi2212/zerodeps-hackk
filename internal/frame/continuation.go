package frame

import "zerodeps/zdh/internal/h2"

// ContinuationFrame is a CONTINUATION frame (RFC 9113 §6.10): the rest of a
// header block that did not fit in the HEADERS or PUSH_PROMISE frame that opened
// it.
//
// The payload is nothing but header block fragment. There is no padding and no
// priority block, so there is no envelope to strip and no length rule beyond the
// reader's maximum frame size.
//
// The dangerous property of this frame is not in its own octets but in how many
// of them may arrive. Between a HEADERS frame without END_HEADERS and the
// CONTINUATION that sets it, the connection is in a state where a peer may send
// an unbounded number of these — each one legal, each one growing the buffer the
// block is accumulated in, and none of them opening a stream that any concurrency
// limit would count. That is CVE-2023-45288, and no per-frame check can see it:
// each frame in the flood is individually valid. The cap on the accumulated block
// size and on the number of continuations is policy, so the numbers are
// limits.MaxHeaderBlockSize and limits.MaxContinuationFrames; they are applied
// here, by the reader that holds the running total, through ReaderConfig.
type ContinuationFrame struct {
	StreamID uint32

	// EndHeaders marks the header block complete.
	EndHeaders bool

	// Fragment is this frame's slice of the HPACK header block, as a private
	// copy.
	Fragment []byte
}

func (f ContinuationFrame) Type() FrameType { return TypeContinuation }

func (f ContinuationFrame) Flags() Flags {
	return Flags(0).set(FlagEndHeaders, f.EndHeaders)
}

func (f ContinuationFrame) Stream() uint32 { return f.StreamID }

func (f ContinuationFrame) PayloadLen() uint32 { return uint32(len(f.Fragment)) }

func (f ContinuationFrame) appendPayload(dst []byte) []byte {
	return append(dst, f.Fragment...)
}

// parseContinuation parses a CONTINUATION frame payload.
//
// The rule that a CONTINUATION must follow a HEADERS, PUSH_PROMISE or
// CONTINUATION that did not set END_HEADERS, on the same stream, is the reader's:
// it is a statement about what came before, and a single frame cannot see that.
// A CONTINUATION arriving out of turn is a connection error of type
// PROTOCOL_ERROR, raised in internal/frame's reader where the continuity state
// lives.
func parseContinuation(h Header, payload []byte) (Frame, error) {
	if h.StreamID == 0 {
		return nil, connErrf(h2.ProtocolError,
			"CONTINUATION on the connection, must be on a stream (RFC 9113 §6.10)")
	}

	f := ContinuationFrame{
		StreamID:   h.StreamID,
		EndHeaders: h.Flags.has(FlagEndHeaders),
	}
	if h.Length > 0 {
		// Copied, not aliased: the fragment is appended to a block that outlives
		// the buffer it arrived in.
		f.Fragment = append([]byte(nil), payload[:h.Length]...)
	}
	return f, nil
}
