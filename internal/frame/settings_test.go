package frame

import (
	"bytes"
	"reflect"
	"testing"

	"zerodeps/zdh/internal/h2"
)

// settingsPayload builds a SETTINGS payload from pairs, so the tests below can
// state what they mean rather than counting octets.
func settingsPayload(pairs ...Setting) []byte {
	b := make([]byte, 0, len(pairs)*settingLen)
	for _, p := range pairs {
		b = append(b,
			byte(uint16(p.ID)>>8), byte(uint16(p.ID)),
			byte(p.Value>>24), byte(p.Value>>16), byte(p.Value>>8), byte(p.Value))
	}
	return b
}

func TestParseSettingsValid(t *testing.T) {
	tests := []struct {
		name  string
		flags Flags
		pairs []Setting
		want  SettingsFrame
	}{
		{
			// Matrix row 41: an empty SETTINGS frame is legal, and it is the
			// first frame of every connection.
			name: "empty",
			want: SettingsFrame{},
		},
		{
			name:  "acknowledgement",
			flags: FlagAck,
			want:  SettingsFrame{Ack: true},
		},
		{
			name:  "one pair",
			pairs: []Setting{{SettingMaxConcurrentStreams, 100}},
			want:  SettingsFrame{Settings: []Setting{{SettingMaxConcurrentStreams, 100}}},
		},
		{
			name: "every defined identifier at a legal value",
			pairs: []Setting{
				{SettingHeaderTableSize, 4096},
				{SettingEnablePush, 0},
				{SettingMaxConcurrentStreams, 250},
				{SettingInitialWindowSize, 65535},
				{SettingMaxFrameSize, 16384},
				{SettingMaxHeaderListSize, 8192},
			},
			want: SettingsFrame{Settings: []Setting{
				{SettingHeaderTableSize, 4096},
				{SettingEnablePush, 0},
				{SettingMaxConcurrentStreams, 250},
				{SettingInitialWindowSize, 65535},
				{SettingMaxFrameSize, 16384},
				{SettingMaxHeaderListSize, 8192},
			}},
		},
		{
			// Matrix row 20: §6.5.2 requires an unknown identifier to be
			// ignored, not rejected. Erroring on it is the instinctive thing to
			// do and it is wrong; it is also one of the easiest h2spec cases to
			// lose.
			name:  "unknown identifier is retained rather than rejected",
			pairs: []Setting{{SettingID(0xffff), 0xdeadbeef}},
			want:  SettingsFrame{Settings: []Setting{{SettingID(0xffff), 0xdeadbeef}}},
		},
		{
			name: "unknown identifiers interleaved with known ones",
			pairs: []Setting{
				{SettingID(0x0), 1},
				{SettingMaxFrameSize, 16385},
				{SettingID(0x7), 2},
				{SettingEnablePush, 1},
			},
			want: SettingsFrame{Settings: []Setting{
				{SettingID(0x0), 1},
				{SettingMaxFrameSize, 16385},
				{SettingID(0x7), 2},
				{SettingEnablePush, 1},
			}},
		},
		{
			name:  "identifier 0x0 has no rules and is not special",
			pairs: []Setting{{SettingID(0), 0xffffffff}},
			want:  SettingsFrame{Settings: []Setting{{SettingID(0), 0xffffffff}}},
		},
		{
			name: "duplicates are legal and preserved in order",
			pairs: []Setting{
				{SettingMaxConcurrentStreams, 1},
				{SettingMaxConcurrentStreams, 2},
				{SettingMaxConcurrentStreams, 3},
			},
			want: SettingsFrame{Settings: []Setting{
				{SettingMaxConcurrentStreams, 1},
				{SettingMaxConcurrentStreams, 2},
				{SettingMaxConcurrentStreams, 3},
			}},
		},
		{
			name:  "boundary values that are legal",
			pairs: []Setting{{SettingInitialWindowSize, MaxWindowSize}, {SettingMaxFrameSize, MaxLength}},
			want: SettingsFrame{Settings: []Setting{
				{SettingInitialWindowSize, MaxWindowSize},
				{SettingMaxFrameSize, MaxLength},
			}},
		},
		{
			name:  "header table size has no upper bound",
			pairs: []Setting{{SettingHeaderTableSize, 0xffffffff}, {SettingHeaderTableSize, 0}},
			want: SettingsFrame{Settings: []Setting{
				{SettingHeaderTableSize, 0xffffffff},
				{SettingHeaderTableSize, 0},
			}},
		},
		{
			name:  "max concurrent streams and max header list size have no upper bound",
			pairs: []Setting{{SettingMaxConcurrentStreams, 0xffffffff}, {SettingMaxHeaderListSize, 0xffffffff}},
			want: SettingsFrame{Settings: []Setting{
				{SettingMaxConcurrentStreams, 0xffffffff},
				{SettingMaxHeaderListSize, 0xffffffff},
			}},
		},
		{
			// Only bit 0x1 is defined on SETTINGS; the rest are undefined and
			// must be ignored (§4.1) rather than treated as an error.
			name:  "undefined flags are ignored",
			flags: 0xfe,
			pairs: []Setting{{SettingEnablePush, 1}},
			want:  SettingsFrame{Settings: []Setting{{SettingEnablePush, 1}}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := settingsPayload(tt.pairs...)
			h := Header{
				Length:   uint32(len(payload)),
				Type:     TypeSettings,
				Flags:    tt.flags,
				StreamID: 0,
			}
			f, err := parseSettings(h, payload)
			wantNoErr(t, err)
			got, ok := f.(SettingsFrame)
			if !ok {
				t.Fatalf("parseSettings returned %T, want SettingsFrame", f)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("\n got %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

// TestParseSettingsNonZeroStream is matrix row 15.
func TestParseSettingsNonZeroStream(t *testing.T) {
	for _, stream := range []uint32{1, 2, 0x7fffffff} {
		h := Header{Length: 0, Type: TypeSettings, StreamID: stream}
		_, err := parseSettings(h, nil)
		wantConnErr(t, err, h2.ProtocolError)
	}
}

// TestParseSettingsAckWithPayload is matrix row 16. The interesting case is a
// 6-octet payload: it passes the multiple-of-six test, so a parser that checks
// the divisibility rule first accepts an acknowledgement carrying settings, which
// §6.5 forbids.
func TestParseSettingsAckWithPayload(t *testing.T) {
	for _, length := range []uint32{1, 5, 6, 12, MaxLength} {
		h := Header{Length: length, Type: TypeSettings, Flags: FlagAck, StreamID: 0}
		_, err := parseSettings(h, settingsPayload(Setting{SettingEnablePush, 1}))
		wantConnErr(t, err, h2.FrameSizeError)
	}
}

// TestParseSettingsBadLength is matrix row 14.
func TestParseSettingsBadLength(t *testing.T) {
	for _, length := range []uint32{1, 2, 3, 4, 5, 7, 11, 13, MaxLength} {
		h := Header{Length: length, Type: TypeSettings, StreamID: 0}
		_, err := parseSettings(h, make([]byte, 2*settingLen))
		wantConnErr(t, err, h2.FrameSizeError)
	}
}

// TestParseSettingsStreamBeatsEverything pins the validation order: the stream
// identifier is decidable from the header alone, so it is diagnosed first even
// when the payload is also malformed.
func TestParseSettingsStreamBeatsEverything(t *testing.T) {
	h := Header{Length: 5, Type: TypeSettings, Flags: FlagAck, StreamID: 3}
	_, err := parseSettings(h, make([]byte, settingLen))
	wantConnErr(t, err, h2.ProtocolError)
}

// TestParseSettingsValueRanges is matrix rows 17, 18 and 19. Three identifiers
// have a legal range and the codes are not uniform: an out-of-range
// INITIAL_WINDOW_SIZE is a FLOW_CONTROL_ERROR, not the PROTOCOL_ERROR that would
// be the natural guess.
func TestParseSettingsValueRanges(t *testing.T) {
	tests := []struct {
		name string
		pair Setting
		want h2.ErrCode
	}{
		{"ENABLE_PUSH 2", Setting{SettingEnablePush, 2}, h2.ProtocolError},
		{"ENABLE_PUSH 3", Setting{SettingEnablePush, 3}, h2.ProtocolError},
		{"ENABLE_PUSH max", Setting{SettingEnablePush, 0xffffffff}, h2.ProtocolError},
		{
			"INITIAL_WINDOW_SIZE one above the maximum window",
			Setting{SettingInitialWindowSize, MaxWindowSize + 1},
			h2.FlowControlError,
		},
		{
			"INITIAL_WINDOW_SIZE max uint32",
			Setting{SettingInitialWindowSize, 0xffffffff},
			h2.FlowControlError,
		},
		{
			"MAX_FRAME_SIZE one below the minimum",
			Setting{SettingMaxFrameSize, DefaultMaxFrameSize - 1},
			h2.ProtocolError,
		},
		{"MAX_FRAME_SIZE zero", Setting{SettingMaxFrameSize, 0}, h2.ProtocolError},
		{
			"MAX_FRAME_SIZE one above the maximum",
			Setting{SettingMaxFrameSize, MaxLength + 1},
			h2.ProtocolError,
		},
		{
			"MAX_FRAME_SIZE max uint32",
			Setting{SettingMaxFrameSize, 0xffffffff},
			h2.ProtocolError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := settingsPayload(tt.pair)
			h := Header{Length: uint32(len(payload)), Type: TypeSettings, StreamID: 0}
			_, err := parseSettings(h, payload)
			wantConnErr(t, err, tt.want)
		})
	}
}

// TestParseSettingsRejectsABadPairAnywhere makes sure the range checks are not
// applied only to the first pair. A peer that puts the illegal value last is the
// obvious way to slip past an implementation that stops looking.
func TestParseSettingsRejectsABadPairAnywhere(t *testing.T) {
	bad := Setting{SettingEnablePush, 99}
	good := Setting{SettingMaxConcurrentStreams, 1}
	positions := [][]Setting{
		{bad, good, good},
		{good, bad, good},
		{good, good, bad},
	}
	for i, pairs := range positions {
		payload := settingsPayload(pairs...)
		h := Header{Length: uint32(len(payload)), Type: TypeSettings, StreamID: 0}
		_, err := parseSettings(h, payload)
		if err == nil {
			t.Errorf("position %d: no error for an illegal ENABLE_PUSH", i)
			continue
		}
		wantConnErr(t, err, h2.ProtocolError)
	}
}

func TestSettingsGetLastWins(t *testing.T) {
	f := SettingsFrame{Settings: []Setting{
		{SettingMaxConcurrentStreams, 1},
		{SettingInitialWindowSize, 1000},
		{SettingMaxConcurrentStreams, 2},
		{SettingMaxConcurrentStreams, 3},
	}}
	if got, ok := f.Get(SettingMaxConcurrentStreams); !ok || got != 3 {
		t.Errorf("Get(MAX_CONCURRENT_STREAMS) = %d, %v; want 3, true (the last occurrence wins)",
			got, ok)
	}
	if got, ok := f.Get(SettingInitialWindowSize); !ok || got != 1000 {
		t.Errorf("Get(INITIAL_WINDOW_SIZE) = %d, %v; want 1000, true", got, ok)
	}
	if got, ok := f.Get(SettingMaxFrameSize); ok || got != 0 {
		t.Errorf("Get(MAX_FRAME_SIZE) = %d, %v; want 0, false for an absent identifier", got, ok)
	}
	if got, ok := (SettingsFrame{}).Get(SettingEnablePush); ok || got != 0 {
		t.Errorf("Get on an empty frame = %d, %v; want 0, false", got, ok)
	}
}

func TestSettingsFrameShape(t *testing.T) {
	f := SettingsFrame{Settings: []Setting{{SettingEnablePush, 0}, {SettingMaxFrameSize, 16384}}}
	if f.Type() != TypeSettings {
		t.Errorf("Type = %s, want SETTINGS", f.Type())
	}
	if f.Flags() != 0 {
		t.Errorf("Flags = 0x%02x, want 0x00", uint8(f.Flags()))
	}
	// SETTINGS has no StreamID field: a SETTINGS frame on a stream cannot be
	// built.
	if f.Stream() != 0 {
		t.Errorf("Stream = %d, want 0", f.Stream())
	}
	if f.PayloadLen() != 2*settingLen {
		t.Errorf("PayloadLen = %d, want %d", f.PayloadLen(), 2*settingLen)
	}

	ack := SettingsFrame{Ack: true}
	if ack.Flags() != FlagAck {
		t.Errorf("ack Flags = 0x%02x, want 0x%02x", uint8(ack.Flags()), uint8(FlagAck))
	}
	if ack.PayloadLen() != 0 {
		t.Errorf("ack PayloadLen = %d, want 0", ack.PayloadLen())
	}
}

// TestSettingsAckNeverSerialisesAPayload is the structural half of the §6.5 rule
// that an acknowledgement carries no payload. Ack wins over Settings, so a caller
// that sets both cannot put us in violation of a rule we enforce on our peers.
func TestSettingsAckNeverSerialisesAPayload(t *testing.T) {
	f := SettingsFrame{Ack: true, Settings: []Setting{{SettingEnablePush, 1}}}
	if f.PayloadLen() != 0 {
		t.Errorf("PayloadLen = %d, want 0", f.PayloadLen())
	}
	wire := serializeFrame(f)
	want := []byte{0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00}
	if !bytes.Equal(wire, want) {
		t.Errorf("wire form\n got % x\nwant % x", wire, want)
	}
	// And it parses back as a legal acknowledgement rather than tripping the
	// rule we enforce on peers.
	f2, err := parseSettings(ParseHeader(wire), wire[HeaderLen:])
	wantNoErr(t, err)
	if got := f2.(SettingsFrame); !got.Ack || len(got.Settings) != 0 {
		t.Errorf("reparsed as %+v, want an empty acknowledgement", got)
	}
}

func TestSettingsByteExact(t *testing.T) {
	f := SettingsFrame{Settings: []Setting{
		{SettingMaxConcurrentStreams, 100},
		{SettingInitialWindowSize, 65535},
	}}
	want := []byte{
		0x00, 0x00, 0x0c, // length 12
		0x04,                   // SETTINGS
		0x00,                   // no flags
		0x00, 0x00, 0x00, 0x00, // stream 0
		0x00, 0x03, 0x00, 0x00, 0x00, 0x64, // MAX_CONCURRENT_STREAMS = 100
		0x00, 0x04, 0x00, 0x00, 0xff, 0xff, // INITIAL_WINDOW_SIZE = 65535
	}
	if got := serializeFrame(f); !bytes.Equal(got, want) {
		t.Errorf("wire form\n got % x\nwant % x", got, want)
	}
}

func TestSettingsRoundTrip(t *testing.T) {
	frames := []SettingsFrame{
		{},
		{Ack: true},
		{Settings: []Setting{{SettingEnablePush, 0}}},
		{Settings: []Setting{
			{SettingHeaderTableSize, 0},
			{SettingEnablePush, 1},
			{SettingMaxConcurrentStreams, 0xffffffff},
			{SettingInitialWindowSize, MaxWindowSize},
			{SettingMaxFrameSize, MaxLength},
			{SettingMaxHeaderListSize, 0xffffffff},
		}},
		{Settings: []Setting{{SettingID(0xffff), 0xdeadbeef}, {SettingID(0), 0}}},
		{Settings: []Setting{
			{SettingMaxConcurrentStreams, 1},
			{SettingMaxConcurrentStreams, 2},
		}},
	}
	for _, want := range frames {
		wire := serializeFrame(want)
		h := ParseHeader(wire)
		if h.Length != want.PayloadLen() {
			t.Fatalf("header length %d, want %d for %+v", h.Length, want.PayloadLen(), want)
		}
		f, err := parseSettings(h, wire[HeaderLen:])
		wantNoErr(t, err)
		if got := f.(SettingsFrame); !reflect.DeepEqual(got, want) {
			t.Errorf("round trip\n got %+v\nwant %+v", got, want)
		}
	}
}

// TestSettingsMaxPairsInADefaultFrame is the allocation bound. A SETTINGS frame
// at the default maximum frame size holds 2730 pairs, so the slice the parser
// allocates is bounded by the reader's length check rather than by anything a
// peer chooses. Without that ordering, a 9-octet header claiming 16 MB would
// allocate 16 MB before a single payload byte arrived.
func TestSettingsMaxPairsInADefaultFrame(t *testing.T) {
	const count = DefaultMaxFrameSize / settingLen // 2730
	pairs := make([]Setting, count)
	for i := range pairs {
		pairs[i] = Setting{SettingMaxConcurrentStreams, uint32(i)}
	}
	payload := settingsPayload(pairs...)
	h := Header{Length: uint32(len(payload)), Type: TypeSettings, StreamID: 0}
	f, err := parseSettings(h, payload)
	wantNoErr(t, err)
	got := f.(SettingsFrame)
	if len(got.Settings) != count {
		t.Fatalf("parsed %d pairs, want %d", len(got.Settings), count)
	}
	if v, ok := got.Get(SettingMaxConcurrentStreams); !ok || v != count-1 {
		t.Errorf("last pair value = %d, %v; want %d, true", v, ok, count-1)
	}
}
