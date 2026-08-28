package frame

import (
	"encoding/binary"

	"zerodeps/zdh/internal/h2"
)

// settingLen is the size of one SETTINGS entry: a 16-bit identifier followed by
// a 32-bit value (RFC 9113 §6.5.1).
const settingLen = 6

// Setting is one identifier/value pair from a SETTINGS frame.
type Setting struct {
	ID    SettingID
	Value uint32
}

// SettingsFrame is a SETTINGS frame (RFC 9113 §6.5).
//
// There is no StreamID field: SETTINGS is only ever valid on the connection, so
// a SETTINGS frame on a stream cannot be constructed.
//
// Every pair that arrives is retained, including identifiers we do not
// recognise. §6.5.2 requires unknown identifiers to be ignored, but ignoring
// them at parse time would mean a frame could not be reproduced byte for byte,
// which costs the round-trip property the whole layer is tested on. The
// connection layer decides which pairs to apply; this layer only decides whether
// the frame is well formed.
type SettingsFrame struct {
	// Ack marks an acknowledgement. §6.5 requires an acknowledgement to carry no
	// payload, so Ack and Settings are mutually exclusive and Ack wins: an
	// acknowledgement can never be serialised with a payload, whatever is in
	// Settings.
	Ack bool

	// Settings is the pairs in the order they arrived. Duplicates are legal and
	// preserved; the last occurrence of an identifier is the effective one.
	Settings []Setting
}

func (f SettingsFrame) Type() FrameType { return TypeSettings }
func (f SettingsFrame) Flags() Flags    { return Flags(0).set(FlagAck, f.Ack) }
func (f SettingsFrame) Stream() uint32  { return 0 }

func (f SettingsFrame) PayloadLen() uint32 {
	if f.Ack {
		return 0
	}
	return uint32(len(f.Settings)) * settingLen
}

func (f SettingsFrame) appendPayload(dst []byte) []byte {
	if f.Ack {
		return dst
	}
	for _, s := range f.Settings {
		dst = binary.BigEndian.AppendUint16(dst, uint16(s.ID))
		dst = binary.BigEndian.AppendUint32(dst, s.Value)
	}
	return dst
}

// Get returns the effective value of id, and whether it was present. When a
// frame contains an identifier more than once — which is legal — the last
// occurrence wins, because the pairs are applied in order.
func (f SettingsFrame) Get(id SettingID) (uint32, bool) {
	value, found := uint32(0), false
	for _, s := range f.Settings {
		if s.ID == id {
			value, found = s.Value, true
		}
	}
	return value, found
}

// parseSettings parses a SETTINGS frame payload.
//
// The order of the three framing checks is forced by what each one needs to be
// true. The stream identifier is checked first because it is decidable from the
// header alone. The acknowledgement check comes next because an ACK with a
// 6-octet payload passes the multiple-of-six test and would otherwise be
// accepted as a settings-carrying acknowledgement, which §6.5 forbids. Only then
// is the payload divided into pairs.
func parseSettings(h Header, payload []byte) (Frame, error) {
	if h.StreamID != 0 {
		return nil, connErrf(h2.ProtocolError,
			"SETTINGS on stream %d, must be on the connection (RFC 9113 §6.5)", h.StreamID)
	}
	if h.Flags.has(FlagAck) && h.Length != 0 {
		return nil, connErrf(h2.FrameSizeError,
			"SETTINGS with ACK carries a %d-octet payload, must be empty (RFC 9113 §6.5)",
			h.Length)
	}
	if h.Length%settingLen != 0 {
		return nil, connErrf(h2.FrameSizeError,
			"SETTINGS length %d is not a multiple of %d (RFC 9113 §6.5)", h.Length, settingLen)
	}

	f := SettingsFrame{Ack: h.Flags.has(FlagAck)}

	count := int(h.Length / settingLen)
	if count > 0 {
		// Bounded by the reader's max-frame-size check, which runs before the
		// payload is read: the length cannot exceed what we advertised.
		f.Settings = make([]Setting, 0, count)
	}
	for i := 0; i < count; i++ {
		b := payload[i*settingLen : (i+1)*settingLen]
		s := Setting{
			ID:    SettingID(binary.BigEndian.Uint16(b[:2])),
			Value: binary.BigEndian.Uint32(b[2:]),
		}
		if err := validateSetting(s); err != nil {
			return nil, err
		}
		f.Settings = append(f.Settings, s)
	}

	return f, nil
}

// validateSetting applies the per-identifier range rules of RFC 9113 §6.5.2.
//
// Only three identifiers have a legal range, and each violation has a different
// error code — one of them is a FLOW_CONTROL_ERROR rather than the
// PROTOCOL_ERROR that would be the natural guess. Unknown identifiers have no
// rules at all and must not be rejected.
func validateSetting(s Setting) error {
	switch s.ID {
	case SettingEnablePush:
		if s.Value > 1 {
			return connErrf(h2.ProtocolError,
				"SETTINGS_ENABLE_PUSH is %d, must be 0 or 1 (RFC 9113 §6.5.2)", s.Value)
		}
	case SettingInitialWindowSize:
		if s.Value > MaxWindowSize {
			return connErrf(h2.FlowControlError,
				"SETTINGS_INITIAL_WINDOW_SIZE is %d, above the maximum window %d (RFC 9113 §6.5.2)",
				s.Value, uint32(MaxWindowSize))
		}
	case SettingMaxFrameSize:
		if s.Value < DefaultMaxFrameSize || s.Value > MaxLength {
			return connErrf(h2.ProtocolError,
				"SETTINGS_MAX_FRAME_SIZE is %d, must be between %d and %d (RFC 9113 §6.5.2)",
				s.Value, uint32(DefaultMaxFrameSize), uint32(MaxLength))
		}
	}
	return nil
}
