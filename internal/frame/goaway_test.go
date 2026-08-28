package frame

import (
	"bytes"
	"testing"

	"zerodeps/zdh/internal/h2"
)

// goAwayPayload builds a GOAWAY payload so the tests below state intent rather
// than octets.
func goAwayPayload(lastStreamID uint32, code h2.ErrCode, debug []byte) []byte {
	b := []byte{
		byte(lastStreamID >> 24), byte(lastStreamID >> 16),
		byte(lastStreamID >> 8), byte(lastStreamID),
		byte(uint32(code) >> 24), byte(uint32(code) >> 16),
		byte(uint32(code) >> 8), byte(uint32(code)),
	}
	return append(b, debug...)
}

func TestParseGoAwayValid(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		want    GoAwayFrame
	}{
		{
			// Matrix row 26's boundary from the legal side: eight octets exactly,
			// no debug data.
			name:    "graceful shutdown with no debug data",
			payload: goAwayPayload(0, h2.NoError, nil),
			want:    GoAwayFrame{LastStreamID: 0, ErrCode: h2.NoError},
		},
		{
			name:    "last stream identifier is big-endian",
			payload: goAwayPayload(0x01020304, h2.ProtocolError, nil),
			want:    GoAwayFrame{LastStreamID: 0x01020304, ErrCode: h2.ProtocolError},
		},
		{
			name:    "maximum last stream identifier",
			payload: goAwayPayload(0x7fffffff, h2.EnhanceYourCalm, nil),
			want:    GoAwayFrame{LastStreamID: 0x7fffffff, ErrCode: h2.EnhanceYourCalm},
		},
		{
			// §6.8 reserves the top bit of the last-stream identifier. Read as part
			// of the number it turns stream 1 into stream 2147483649, and every
			// stream the peer may safely retry is then misjudged.
			name:    "reserved bit of the last stream identifier is ignored",
			payload: []byte{0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00},
			want:    GoAwayFrame{LastStreamID: 1, ErrCode: h2.NoError},
		},
		{
			name:    "reserved bit set with the maximum identifier",
			payload: []byte{0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x0d},
			want:    GoAwayFrame{LastStreamID: 0x7fffffff, ErrCode: h2.HTTP11Required},
		},
		{
			name:    "debug data is carried through",
			payload: goAwayPayload(7, h2.InternalError, []byte("something went wrong")),
			want: GoAwayFrame{
				LastStreamID: 7,
				ErrCode:      h2.InternalError,
				Debug:        []byte("something went wrong"),
			},
		},
		{
			name:    "a single octet of debug data",
			payload: goAwayPayload(1, h2.NoError, []byte{0x00}),
			want:    GoAwayFrame{LastStreamID: 1, ErrCode: h2.NoError, Debug: []byte{0x00}},
		},
		{
			// §6.8 places no constraint on the content, so it may be arbitrary
			// binary rather than text. Anything that assumed UTF-8 would be wrong.
			name:    "debug data may be arbitrary binary",
			payload: goAwayPayload(1, h2.NoError, []byte{0xff, 0xfe, 0x00, 0x80, 0x7f}),
			want: GoAwayFrame{
				LastStreamID: 1,
				ErrCode:      h2.NoError,
				Debug:        []byte{0xff, 0xfe, 0x00, 0x80, 0x7f},
			},
		},
		{
			// The point of logging Debug with %q. A peer that could get this
			// through a naive logger would be able to forge log lines.
			name: "debug data containing control characters and quotes",
			payload: goAwayPayload(1, h2.NoError,
				[]byte("line1\r\nERROR: forged\x1b[31m\"quoted\"")),
			want: GoAwayFrame{
				LastStreamID: 1,
				ErrCode:      h2.NoError,
				Debug:        []byte("line1\r\nERROR: forged\x1b[31m\"quoted\""),
			},
		},
		{
			// §7 requires an unrecognised code to be treated as INTERNAL_ERROR by
			// the layer acting on it, not rejected here. The parser preserves what
			// arrived so the log records the truth.
			name:    "unknown error code is preserved rather than rejected",
			payload: goAwayPayload(3, h2.ErrCode(0xffffffff), nil),
			want:    GoAwayFrame{LastStreamID: 3, ErrCode: h2.ErrCode(0xffffffff)},
		},
		{
			name:    "error code just above the assigned range",
			payload: goAwayPayload(0, h2.ErrCode(0xe), nil),
			want:    GoAwayFrame{LastStreamID: 0, ErrCode: h2.ErrCode(0xe)},
		},
		{
			// GOAWAY defines no flags, so every bit is undefined and must be
			// ignored (§4.1) rather than rejected.
			name:    "undefined flags are ignored",
			payload: goAwayPayload(1, h2.NoError, nil),
			want:    GoAwayFrame{LastStreamID: 1, ErrCode: h2.NoError},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := Header{
				Length:   uint32(len(tt.payload)),
				Type:     TypeGoAway,
				Flags:    0xff,
				StreamID: 0,
			}
			f, err := parseGoAway(h, tt.payload)
			wantNoErr(t, err)
			got, ok := f.(GoAwayFrame)
			if !ok {
				t.Fatalf("parseGoAway returned %T, want GoAwayFrame", f)
			}
			if got.LastStreamID != tt.want.LastStreamID {
				t.Errorf("LastStreamID = %d, want %d", got.LastStreamID, tt.want.LastStreamID)
			}
			if got.ErrCode != tt.want.ErrCode {
				t.Errorf("ErrCode = %s, want %s", got.ErrCode, tt.want.ErrCode)
			}
			if !bytes.Equal(got.Debug, tt.want.Debug) {
				t.Errorf("Debug = %q, want %q", got.Debug, tt.want.Debug)
			}
		})
	}
}

// TestParseGoAwayNoDebugDataIsNil distinguishes absent debug data from empty
// debug data, so a frame with none round-trips to exactly what it started as.
func TestParseGoAwayNoDebugDataIsNil(t *testing.T) {
	payload := goAwayPayload(0, h2.NoError, nil)
	h := Header{Length: goAwayMinLen, Type: TypeGoAway, StreamID: 0}
	f, err := parseGoAway(h, payload)
	wantNoErr(t, err)
	if got := f.(GoAwayFrame).Debug; got != nil {
		t.Errorf("Debug = %q (len %d), want nil for a frame with no debug data", got, len(got))
	}
}

// TestParseGoAwayNonZeroStream is matrix row 25.
func TestParseGoAwayNonZeroStream(t *testing.T) {
	for _, stream := range []uint32{1, 2, 3, 0x7fffffff} {
		h := Header{Length: goAwayMinLen, Type: TypeGoAway, StreamID: stream}
		_, err := parseGoAway(h, goAwayPayload(0, h2.NoError, nil))
		wantConnErr(t, err, h2.ProtocolError)
	}
}

// TestParseGoAwayShortPayload is matrix row 26. Eight octets is the floor: the
// identifier and the code are both mandatory.
func TestParseGoAwayShortPayload(t *testing.T) {
	for _, length := range []uint32{0, 1, 4, 7} {
		h := Header{Length: length, Type: TypeGoAway, StreamID: 0}
		_, err := parseGoAway(h, make([]byte, goAwayMinLen))
		wantConnErr(t, err, h2.FrameSizeError)
	}
}

// TestParseGoAwayStreamBeatsShortPayload pins the validation order: both rules
// are connection-fatal, but the stream identifier is decidable from the header
// alone and is the more specific diagnosis.
func TestParseGoAwayStreamBeatsShortPayload(t *testing.T) {
	h := Header{Length: 4, Type: TypeGoAway, StreamID: 1}
	_, err := parseGoAway(h, make([]byte, goAwayMinLen))
	wantConnErr(t, err, h2.ProtocolError)
}

// TestParseGoAwayUsesOnlyTheDeclaredLength guards the reader's buffer contract.
// The scratch slice handed to a parser may be longer than the frame; reading to
// the end of the slice instead of to h.Length would splice the next frame's
// octets into this frame's debug data.
func TestParseGoAwayUsesOnlyTheDeclaredLength(t *testing.T) {
	payload := goAwayPayload(1, h2.NoError, []byte("mine"))
	payload = append(payload, []byte("NOTMINE")...)

	h := Header{Length: goAwayMinLen + 4, Type: TypeGoAway, StreamID: 0}
	f, err := parseGoAway(h, payload)
	wantNoErr(t, err)
	if got := f.(GoAwayFrame).Debug; !bytes.Equal(got, []byte("mine")) {
		t.Errorf("Debug = %q, want %q; the parser read past the declared length", got, "mine")
	}
}

// TestParseGoAwayCopiesItsDebugData is the ownership test at the reader
// boundary. payload aliases a buffer the next frame overwrites, so a retained
// slice would see its contents mutate underneath it.
func TestParseGoAwayCopiesItsDebugData(t *testing.T) {
	payload := goAwayPayload(9, h2.CompressionError, []byte("hpack broke"))
	h := Header{Length: uint32(len(payload)), Type: TypeGoAway, StreamID: 0}
	f, err := parseGoAway(h, payload)
	wantNoErr(t, err)

	// Simulate the reader reusing the buffer for the next frame.
	for i := range payload {
		payload[i] = 0xff
	}

	got := f.(GoAwayFrame)
	if !bytes.Equal(got.Debug, []byte("hpack broke")) {
		t.Errorf("Debug = %q after the source buffer was reused, want %q; "+
			"the payload was aliased rather than copied", got.Debug, "hpack broke")
	}
	if got.LastStreamID != 9 || got.ErrCode != h2.CompressionError {
		t.Errorf("got {LastStreamID:%d ErrCode:%s}, want {9 COMPRESSION_ERROR}",
			got.LastStreamID, got.ErrCode)
	}
}

// TestParseGoAwayLargeDebugData checks the one payload in the frame layer whose
// size a peer chooses freely. The bound comes from the reader's max-frame-size
// check rather than from anything here, so this only asserts a frame at that
// bound is handled without truncation.
func TestParseGoAwayLargeDebugData(t *testing.T) {
	debug := make([]byte, DefaultMaxFrameSize-goAwayMinLen)
	for i := range debug {
		debug[i] = byte(i)
	}
	payload := goAwayPayload(1, h2.NoError, debug)
	if len(payload) != DefaultMaxFrameSize {
		t.Fatalf("payload is %d octets, want %d", len(payload), DefaultMaxFrameSize)
	}
	h := Header{Length: uint32(len(payload)), Type: TypeGoAway, StreamID: 0}
	f, err := parseGoAway(h, payload)
	wantNoErr(t, err)
	if got := f.(GoAwayFrame).Debug; !bytes.Equal(got, debug) {
		t.Errorf("Debug is %d octets, want %d, and the contents must match",
			len(got), len(debug))
	}
}

func TestGoAwayFrameShape(t *testing.T) {
	f := GoAwayFrame{LastStreamID: 5, ErrCode: h2.ProtocolError}
	if f.Type() != TypeGoAway {
		t.Errorf("Type = %s, want GOAWAY", f.Type())
	}
	if f.Flags() != 0 {
		t.Errorf("Flags = 0x%02x, want 0x00; GOAWAY defines no flags", uint8(f.Flags()))
	}
	// GOAWAY has no StreamID field: a GOAWAY on a stream cannot be built.
	if f.Stream() != 0 {
		t.Errorf("Stream = %d, want 0", f.Stream())
	}
	if f.PayloadLen() != goAwayMinLen {
		t.Errorf("PayloadLen = %d, want %d", f.PayloadLen(), goAwayMinLen)
	}

	withDebug := GoAwayFrame{ErrCode: h2.NoError, Debug: []byte("bye")}
	if withDebug.PayloadLen() != goAwayMinLen+3 {
		t.Errorf("PayloadLen with 3 debug octets = %d, want %d",
			withDebug.PayloadLen(), goAwayMinLen+3)
	}
}

// TestGoAwayAppendMasksReservedBit asserts we never send the reserved bit set,
// even from a struct whose LastStreamID somehow has it. §4.1 requires it to be
// written as zero.
func TestGoAwayAppendMasksReservedBit(t *testing.T) {
	f := GoAwayFrame{LastStreamID: 0xffffffff, ErrCode: h2.NoError}
	got := f.appendPayload(nil)
	want := []byte{0x7f, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("appendPayload\n got % x\nwant % x", got, want)
	}
}

func TestGoAwayByteExact(t *testing.T) {
	f := GoAwayFrame{LastStreamID: 3, ErrCode: h2.EnhanceYourCalm, Debug: []byte("slow down")}
	want := []byte{
		0x00, 0x00, 0x11, // length 17: 8 + 9 debug octets
		0x07,                   // GOAWAY
		0x00,                   // no flags
		0x00, 0x00, 0x00, 0x00, // stream 0
		0x00, 0x00, 0x00, 0x03, // last stream 3
		0x00, 0x00, 0x00, 0x0b, // ENHANCE_YOUR_CALM
		's', 'l', 'o', 'w', ' ', 'd', 'o', 'w', 'n',
	}
	if got := serializeFrame(f); !bytes.Equal(got, want) {
		t.Errorf("wire form\n got % x\nwant % x", got, want)
	}
}

func TestGoAwayRoundTrip(t *testing.T) {
	frames := []GoAwayFrame{
		{},
		{LastStreamID: 0x7fffffff, ErrCode: h2.HTTP11Required},
		{LastStreamID: 1, ErrCode: h2.NoError, Debug: []byte("graceful")},
		{LastStreamID: 0, ErrCode: h2.ErrCode(0xffffffff), Debug: []byte{0x00, 0xff}},
		{LastStreamID: 42, ErrCode: h2.CompressionError, Debug: bytes.Repeat([]byte{0xab}, 300)},
	}
	for _, want := range frames {
		wire := serializeFrame(want)
		h := ParseHeader(wire)
		if h.Length != want.PayloadLen() {
			t.Fatalf("header length %d, want %d", h.Length, want.PayloadLen())
		}
		f, err := parseGoAway(h, wire[HeaderLen:])
		wantNoErr(t, err)
		got := f.(GoAwayFrame)
		if got.LastStreamID != want.LastStreamID || got.ErrCode != want.ErrCode {
			t.Errorf("round trip\n got {%d %s}\nwant {%d %s}",
				got.LastStreamID, got.ErrCode, want.LastStreamID, want.ErrCode)
		}
		if !bytes.Equal(got.Debug, want.Debug) {
			t.Errorf("round trip Debug\n got %q\nwant %q", got.Debug, want.Debug)
		}
	}
}
