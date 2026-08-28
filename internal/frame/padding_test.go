package frame

import (
	"bytes"
	"strings"
	"testing"

	"zerodeps/zdh/internal/h2"
)

// TestSplitPaddingUnpadded records that without the PADDED flag the whole
// declared payload is content, and that the bound comes from the header rather
// than from the length of the buffer handed in.
func TestSplitPaddingUnpadded(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03, 0xff, 0xff}
	h := Header{Length: 3, Type: TypeData, StreamID: 1}
	content, padLen, err := splitPadding(h, payload, "DATA")
	wantNoErr(t, err)
	if !bytes.Equal(content, []byte{0x01, 0x02, 0x03}) {
		t.Errorf("content = % x, want 01 02 03", content)
	}
	if padLen != 0 {
		t.Errorf("padLen = %d, want 0 for an unpadded frame", padLen)
	}
}

func TestSplitPaddingValid(t *testing.T) {
	tests := []struct {
		name        string
		length      uint32
		payload     []byte
		wantContent []byte
		wantPadLen  uint8
	}{
		{
			name:        "one octet of content, no padding octets",
			length:      2,
			payload:     []byte{0x00, 0xaa},
			wantContent: []byte{0xaa},
			wantPadLen:  0,
		},
		{
			// The pad-length field on its own. Legal, and the smallest padded
			// frame there is: one octet of overhead, no padding, no content.
			name:        "pad-length field only",
			length:      1,
			payload:     []byte{0x00},
			wantContent: []byte{},
			wantPadLen:  0,
		},
		{
			name:        "content followed by padding",
			length:      6,
			payload:     []byte{0x02, 0xaa, 0xbb, 0xcc, 0x00, 0x00},
			wantContent: []byte{0xaa, 0xbb, 0xcc},
			wantPadLen:  2,
		},
		{
			// The boundary from the legal side: padding one octet shorter than
			// the payload leaves exactly zero octets of content.
			name:        "padding fills everything but the pad-length field",
			length:      5,
			payload:     []byte{0x04, 0x00, 0x00, 0x00, 0x00},
			wantContent: []byte{},
			wantPadLen:  4,
		},
		{
			name:        "maximum padding",
			length:      maxPadLen + 1,
			payload:     append([]byte{maxPadLen}, make([]byte, maxPadLen)...),
			wantContent: []byte{},
			wantPadLen:  maxPadLen,
		},
		{
			// §6.1 says padding SHOULD be zero and permits a receiver not to
			// check. We do not check, so non-zero padding is accepted and
			// discarded rather than becoming a spurious error on a peer that is
			// merely sloppy.
			name:        "non-zero padding octets are accepted and discarded",
			length:      5,
			payload:     []byte{0x03, 0xaa, 0xff, 0xfe, 0xfd},
			wantContent: []byte{0xaa},
			wantPadLen:  3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := Header{Length: tt.length, Type: TypeData, Flags: FlagPadded, StreamID: 1}
			content, padLen, err := splitPadding(h, tt.payload, "DATA")
			wantNoErr(t, err)
			if !bytes.Equal(content, tt.wantContent) {
				t.Errorf("content = % x, want % x", content, tt.wantContent)
			}
			if padLen != tt.wantPadLen {
				t.Errorf("padLen = %d, want %d", padLen, tt.wantPadLen)
			}
		})
	}
}

// TestSplitPaddingNoRoomForPadLength is matrix row 3: the PADDED flag promises an
// octet that a zero-length payload does not contain.
func TestSplitPaddingNoRoomForPadLength(t *testing.T) {
	h := Header{Length: 0, Type: TypeData, Flags: FlagPadded, StreamID: 1}
	_, _, err := splitPadding(h, []byte{0xff}, "DATA")
	wantConnErr(t, err, h2.FrameSizeError)
}

// TestSplitPaddingOverruns is matrix row 4, and the arithmetic that has to be
// right for the rest of the layer to be safe. h.Length is a uint32, so
// h.Length-padLen without the guard does not panic — it wraps to something near
// four billion and becomes a slice bound.
func TestSplitPaddingOverruns(t *testing.T) {
	tests := []struct {
		name    string
		length  uint32
		payload []byte
	}{
		{"padding exactly as long as the payload", 1, []byte{0x01}},
		{"padding one longer than the payload", 5, []byte{0x05, 0, 0, 0, 0}},
		{"padding far longer than the payload", 2, []byte{0xff, 0x00}},
		{
			"maximum padding in a one-octet payload",
			1,
			[]byte{maxPadLen},
		},
		{
			"padding equal to a payload that is all padding",
			maxPadLen,
			append([]byte{maxPadLen}, make([]byte, maxPadLen-1)...),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := Header{Length: tt.length, Type: TypeData, Flags: FlagPadded, StreamID: 1}
			_, _, err := splitPadding(h, tt.payload, "DATA")
			wantConnErr(t, err, h2.ProtocolError)
		})
	}
}

// TestSplitPaddingIgnoresTheTailOfTheBuffer guards the reader's contract. The
// scratch slice may hold the beginning of the next frame; content must be bounded
// by the declared length, not by the slice.
func TestSplitPaddingIgnoresTheTailOfTheBuffer(t *testing.T) {
	// A 4-octet frame: pad length 1, two octets of content, one of padding. The
	// rest of the buffer belongs to whatever comes next.
	payload := []byte{0x01, 0xaa, 0xbb, 0x00, 'N', 'O', 'T', 'M', 'I', 'N', 'E'}
	h := Header{Length: 4, Type: TypeData, Flags: FlagPadded, StreamID: 1}
	content, padLen, err := splitPadding(h, payload, "DATA")
	wantNoErr(t, err)
	if !bytes.Equal(content, []byte{0xaa, 0xbb}) {
		t.Errorf("content = % x, want aa bb; the parser read past the declared length", content)
	}
	if padLen != 1 {
		t.Errorf("padLen = %d, want 1", padLen)
	}
}

// TestSplitPaddingNamesTheFrameInItsError checks that the shared helper reports
// which frame type was at fault. Three frame types use it, and an error that said
// only "padding" would send whoever reads the log to the wrong parser.
func TestSplitPaddingNamesTheFrameInItsError(t *testing.T) {
	for _, name := range []string{"DATA", "HEADERS", "PUSH_PROMISE"} {
		h := Header{Length: 1, Type: TypeData, Flags: FlagPadded, StreamID: 1}
		_, _, err := splitPadding(h, []byte{0x01}, name)
		if err == nil {
			t.Fatalf("%s: no error", name)
		}
		var reason string
		if ce, ok := err.(h2.ConnError); ok {
			reason = ce.Reason
		}
		if !strings.Contains(reason, name) {
			t.Errorf("error for %s does not name the frame type: %q", name, reason)
		}
		wantRFCCitation(t, reason)
	}
}

func TestPaddedLen(t *testing.T) {
	tests := []struct {
		padded  bool
		padLen  uint8
		content int
		want    uint32
	}{
		{false, 0, 0, 0},
		{false, 0, 10, 10},
		// PadLen is ignored when the frame is not padded, so a struct that has
		// one without the flag cannot claim a length it will not write.
		{false, 200, 10, 10},
		{true, 0, 0, 1},
		{true, 0, 10, 11},
		{true, 8, 10, 19},
		{true, maxPadLen, 0, maxPadLen + 1},
	}
	for _, tt := range tests {
		if got := paddedLen(tt.padded, tt.padLen, tt.content); got != tt.want {
			t.Errorf("paddedLen(%v, %d, %d) = %d, want %d",
				tt.padded, tt.padLen, tt.content, got, tt.want)
		}
	}
}

// TestAppendPaddedWritesZeroPadding is the send-side half of §6.1: padding
// octets we write are zero, whatever the frame's content is.
func TestAppendPaddedWritesZeroPadding(t *testing.T) {
	got := appendPadded(nil, true, 3, []byte{0xaa, 0xbb})
	want := []byte{0x03, 0xaa, 0xbb, 0x00, 0x00, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("appendPadded\n got % x\nwant % x", got, want)
	}
}

// TestAppendPaddedNeverMutatesTheZeroSource is the one shared mutable-looking
// thing in the package. zeroPad is appended from on every padded frame we send;
// if anything ever wrote through it the padding of every later frame would carry
// whatever was left there.
func TestAppendPaddedNeverMutatesTheZeroSource(t *testing.T) {
	buf := appendPadded(nil, true, maxPadLen, []byte{0xaa})
	for i := range buf {
		buf[i] = 0xff
	}
	for i, b := range zeroPad {
		if b != 0 {
			t.Fatalf("zeroPad[%d] = 0x%02x after a padded frame was written and its "+
				"buffer overwritten; the padding source was aliased into the output", i, b)
		}
	}
}

func TestAppendPaddedUnpadded(t *testing.T) {
	// Not padded: no pad-length octet, and PadLen is ignored rather than written.
	got := appendPadded(nil, false, 9, []byte{0xaa, 0xbb})
	want := []byte{0xaa, 0xbb}
	if !bytes.Equal(got, want) {
		t.Errorf("appendPadded\n got % x\nwant % x", got, want)
	}
}

// TestAppendPaddedRoundTripsThroughSplitPadding closes the loop over every pad
// length the one-octet field can express, which is the whole input space of the
// two functions taken together.
func TestAppendPaddedRoundTripsThroughSplitPadding(t *testing.T) {
	content := []byte{0xde, 0xad, 0xbe, 0xef}
	for pad := 0; pad <= maxPadLen; pad++ {
		payload := appendPadded(nil, true, uint8(pad), content)
		h := Header{
			Length:   paddedLen(true, uint8(pad), len(content)),
			Type:     TypeData,
			Flags:    FlagPadded,
			StreamID: 1,
		}
		if int(h.Length) != len(payload) {
			t.Fatalf("pad %d: paddedLen says %d, appendPadded wrote %d",
				pad, h.Length, len(payload))
		}
		gotContent, gotPad, err := splitPadding(h, payload, "DATA")
		wantNoErr(t, err)
		if !bytes.Equal(gotContent, content) {
			t.Errorf("pad %d: content = % x, want % x", pad, gotContent, content)
		}
		if int(gotPad) != pad {
			t.Errorf("pad %d: padLen = %d", pad, gotPad)
		}
	}
}
