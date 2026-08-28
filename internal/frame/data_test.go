package frame

import (
	"bytes"
	"testing"

	"zerodeps/zdh/internal/h2"
)

func TestParseDataValid(t *testing.T) {
	tests := []struct {
		name    string
		flags   Flags
		stream  uint32
		length  uint32
		payload []byte
		want    DataFrame
	}{
		{
			name:    "body octets",
			stream:  1,
			length:  5,
			payload: []byte("hello"),
			want:    DataFrame{StreamID: 1, Data: []byte("hello")},
		},
		{
			// Matrix row 1: a zero-length DATA frame is legal, and a DATA frame
			// with END_STREAM and no octets is the normal way to close a stream
			// whose body has already been sent.
			name:   "empty",
			stream: 1,
			length: 0,
			want:   DataFrame{StreamID: 1},
		},
		{
			name:   "empty with END_STREAM",
			flags:  FlagEndStream,
			stream: 1,
			length: 0,
			want:   DataFrame{StreamID: 1, EndStream: true},
		},
		{
			name:    "body with END_STREAM",
			flags:   FlagEndStream,
			stream:  3,
			length:  2,
			payload: []byte{0xaa, 0xbb},
			want:    DataFrame{StreamID: 3, EndStream: true, Data: []byte{0xaa, 0xbb}},
		},
		{
			// The trailing octet is beyond the declared length: it belongs to
			// whatever the reader read next, and must not become body or padding.
			name:    "padded",
			flags:   FlagPadded,
			stream:  1,
			length:  7,
			payload: []byte{0x02, 'b', 'o', 'd', 'y', 0x00, 0x00, 0xff},
			want: DataFrame{
				StreamID: 1,
				Data:     []byte("body"),
				Padded:   true,
				PadLen:   2,
			},
		},
		{
			// A padded frame that declares zero padding octets. It differs from an
			// unpadded frame by the one octet of the pad-length field, and that
			// octet counts against the flow-control window (§6.9.1), so the
			// distinction has to survive parsing.
			name:    "padded with zero padding octets",
			flags:   FlagPadded,
			stream:  1,
			length:  3,
			payload: []byte{0x00, 0xaa, 0xbb},
			want: DataFrame{
				StreamID: 1,
				Data:     []byte{0xaa, 0xbb},
				Padded:   true,
				PadLen:   0,
			},
		},
		{
			name:    "padded, END_STREAM, and nothing but padding",
			flags:   FlagPadded | FlagEndStream,
			stream:  1,
			length:  4,
			payload: []byte{0x03, 0x00, 0x00, 0x00},
			want: DataFrame{
				StreamID:  1,
				EndStream: true,
				Padded:    true,
				PadLen:    3,
			},
		},
		{
			name:    "maximum stream identifier",
			stream:  0x7fffffff,
			length:  1,
			payload: []byte{0xaa},
			want:    DataFrame{StreamID: 0x7fffffff, Data: []byte{0xaa}},
		},
		{
			// DATA defines only END_STREAM and PADDED. Every other bit is
			// undefined and must be ignored (§4.1) rather than rejected, and in
			// particular 0x4 and 0x20 must not be mistaken for END_HEADERS and
			// PRIORITY, which mean nothing on this frame type.
			name:    "undefined flags are ignored",
			flags:   FlagEndHeaders | FlagPriority | 0x40 | 0x80,
			stream:  1,
			length:  1,
			payload: []byte{0xaa},
			want:    DataFrame{StreamID: 1, Data: []byte{0xaa}},
		},
		{
			name:    "body may be arbitrary binary including NUL",
			stream:  1,
			length:  4,
			payload: []byte{0x00, 0xff, 0x00, 0x80},
			want:    DataFrame{StreamID: 1, Data: []byte{0x00, 0xff, 0x00, 0x80}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := Header{Length: tt.length, Type: TypeData, Flags: tt.flags, StreamID: tt.stream}
			f, err := parseData(h, tt.payload)
			wantNoErr(t, err)
			got, ok := f.(DataFrame)
			if !ok {
				t.Fatalf("parseData returned %T, want DataFrame", f)
			}
			if got.StreamID != tt.want.StreamID {
				t.Errorf("StreamID = %d, want %d", got.StreamID, tt.want.StreamID)
			}
			if got.EndStream != tt.want.EndStream {
				t.Errorf("EndStream = %v, want %v", got.EndStream, tt.want.EndStream)
			}
			if got.Padded != tt.want.Padded {
				t.Errorf("Padded = %v, want %v", got.Padded, tt.want.Padded)
			}
			if got.PadLen != tt.want.PadLen {
				t.Errorf("PadLen = %d, want %d", got.PadLen, tt.want.PadLen)
			}
			if !bytes.Equal(got.Data, tt.want.Data) {
				t.Errorf("Data = % x, want % x", got.Data, tt.want.Data)
			}
		})
	}
}

// TestParseDataStreamZero is matrix row 2. DATA belongs to a stream; on the
// connection it has no meaning at all.
func TestParseDataStreamZero(t *testing.T) {
	h := Header{Length: 3, Type: TypeData, StreamID: 0}
	_, err := parseData(h, []byte("abc"))
	wantConnErr(t, err, h2.ProtocolError)
}

// TestParseDataStreamZeroBeatsBadPadding pins the validation order: the stream
// identifier is decidable from the header alone, so it is diagnosed before the
// payload is inspected at all.
func TestParseDataStreamZeroBeatsBadPadding(t *testing.T) {
	h := Header{Length: 1, Type: TypeData, Flags: FlagPadded, StreamID: 0}
	_, err := parseData(h, []byte{0xff})
	wantConnErr(t, err, h2.ProtocolError)
	// And with no payload at all to read from, so a parser that looked at the
	// pad-length octet first would index out of range.
	h = Header{Length: 0, Type: TypeData, Flags: FlagPadded, StreamID: 0}
	_, err = parseData(h, nil)
	wantConnErr(t, err, h2.ProtocolError)
}

// TestParseDataPaddingErrors is matrix rows 3 and 4 seen through DATA, which is
// the frame type h2spec exercises them on.
func TestParseDataPaddingErrors(t *testing.T) {
	t.Run("PADDED with no room for the pad-length octet", func(t *testing.T) {
		h := Header{Length: 0, Type: TypeData, Flags: FlagPadded, StreamID: 1}
		_, err := parseData(h, nil)
		wantConnErr(t, err, h2.FrameSizeError)
	})
	t.Run("padding as long as the payload", func(t *testing.T) {
		h := Header{Length: 5, Type: TypeData, Flags: FlagPadded, StreamID: 1}
		_, err := parseData(h, []byte{0x05, 0x00, 0x00, 0x00, 0x00})
		wantConnErr(t, err, h2.ProtocolError)
	})
	t.Run("padding longer than the payload", func(t *testing.T) {
		h := Header{Length: 2, Type: TypeData, Flags: FlagPadded, StreamID: 1}
		_, err := parseData(h, []byte{0xff, 0x00})
		wantConnErr(t, err, h2.ProtocolError)
	})
}

// TestParseDataEmptyBodyIsNil keeps absent body octets distinguishable from an
// empty slice, so an empty DATA frame round-trips to exactly what it was.
func TestParseDataEmptyBodyIsNil(t *testing.T) {
	h := Header{Length: 0, Type: TypeData, StreamID: 1}
	f, err := parseData(h, nil)
	wantNoErr(t, err)
	if got := f.(DataFrame).Data; got != nil {
		t.Errorf("Data = % x (len %d), want nil for a zero-length frame", got, len(got))
	}
}

// TestParseDataUsesOnlyTheDeclaredLength guards the reader's buffer contract:
// reading to the end of the scratch slice instead of to h.Length would splice the
// next frame's octets into this stream's body.
func TestParseDataUsesOnlyTheDeclaredLength(t *testing.T) {
	payload := []byte("mineNOTMINE")
	h := Header{Length: 4, Type: TypeData, StreamID: 1}
	f, err := parseData(h, payload)
	wantNoErr(t, err)
	if got := f.(DataFrame).Data; !bytes.Equal(got, []byte("mine")) {
		t.Errorf("Data = %q, want %q; the parser read past the declared length", got, "mine")
	}
}

// TestParseDataCopiesItsBody is the ownership test at the reader boundary, and
// the one that matters most: a DATA frame is handed to a stream goroutine while
// the reader goroutine moves on to fill the same buffer with the next frame. An
// aliased body would be a data race the detector catches only sometimes, and a
// request body that changes while the application reads it.
func TestParseDataCopiesItsBody(t *testing.T) {
	payload := []byte("original body")
	h := Header{Length: uint32(len(payload)), Type: TypeData, StreamID: 1}
	f, err := parseData(h, payload)
	wantNoErr(t, err)

	// Simulate the reader reusing the buffer for the next frame.
	for i := range payload {
		payload[i] = 0xff
	}

	if got := f.(DataFrame).Data; !bytes.Equal(got, []byte("original body")) {
		t.Errorf("Data = %q after the source buffer was reused, want %q; "+
			"the body was aliased rather than copied", got, "original body")
	}
}

// TestParseDataCopiesItsPaddedBody is the same test through the padding path,
// where the content is a subslice of a subslice and the aliasing is easier to
// reintroduce by accident.
func TestParseDataCopiesItsPaddedBody(t *testing.T) {
	payload := []byte{0x02, 'b', 'o', 'd', 'y', 0x00, 0x00}
	h := Header{Length: uint32(len(payload)), Type: TypeData, Flags: FlagPadded, StreamID: 1}
	f, err := parseData(h, payload)
	wantNoErr(t, err)

	for i := range payload {
		payload[i] = 0xff
	}

	if got := f.(DataFrame).Data; !bytes.Equal(got, []byte("body")) {
		t.Errorf("Data = %q after the source buffer was reused, want %q", got, "body")
	}
}

func TestDataFrameShape(t *testing.T) {
	f := DataFrame{StreamID: 7, Data: []byte("abc")}
	if f.Type() != TypeData {
		t.Errorf("Type = %s, want DATA", f.Type())
	}
	if f.Flags() != 0 {
		t.Errorf("Flags = 0x%02x, want 0x00", uint8(f.Flags()))
	}
	if f.Stream() != 7 {
		t.Errorf("Stream = %d, want 7", f.Stream())
	}
	if f.PayloadLen() != 3 {
		t.Errorf("PayloadLen = %d, want 3", f.PayloadLen())
	}

	both := DataFrame{StreamID: 1, EndStream: true, Padded: true, PadLen: 4, Data: []byte("ab")}
	if got, want := both.Flags(), FlagEndStream|FlagPadded; got != want {
		t.Errorf("Flags = 0x%02x, want 0x%02x", uint8(got), uint8(want))
	}
	if got, want := both.PayloadLen(), uint32(1+2+4); got != want {
		t.Errorf("PayloadLen = %d, want %d", got, want)
	}
}

// TestDataPadLenIgnoredWithoutTheFlag is the structural guarantee that mirrors
// SETTINGS: the flag governs, so a struct with a pad length but no PADDED flag
// serialises as an unpadded frame rather than as a frame whose declared length
// disagrees with its octets — which is the one mistake a peer cannot recover
// from, since it desynchronises the frame stream.
func TestDataPadLenIgnoredWithoutTheFlag(t *testing.T) {
	f := DataFrame{StreamID: 1, PadLen: 200, Data: []byte("ab")}
	if f.Flags().has(FlagPadded) {
		t.Error("PADDED flag set on a frame whose Padded field is false")
	}
	if got := f.PayloadLen(); got != 2 {
		t.Errorf("PayloadLen = %d, want 2", got)
	}
	wire := serializeFrame(f)
	want := []byte{0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 'a', 'b'}
	if !bytes.Equal(wire, want) {
		t.Errorf("wire form\n got % x\nwant % x", wire, want)
	}
}

// TestDataDeclaredLengthMatchesWhatIsWritten is the invariant the whole framing
// layer rests on: if PayloadLen ever disagreed with appendPayload, the header
// would promise one thing and the socket carry another, and the peer's frame
// stream would be desynchronised from that byte onward with no way back.
func TestDataDeclaredLengthMatchesWhatIsWritten(t *testing.T) {
	bodies := [][]byte{nil, {}, []byte("a"), bytes.Repeat([]byte{0xaa}, 1000)}
	for _, body := range bodies {
		for _, padded := range []bool{false, true} {
			for _, pad := range []uint8{0, 1, 7, maxPadLen} {
				f := DataFrame{StreamID: 1, Data: body, Padded: padded, PadLen: pad}
				wire := serializeFrame(f)
				if got, want := len(wire)-HeaderLen, int(f.PayloadLen()); got != want {
					t.Fatalf("body %d padded=%v pad=%d: wrote %d payload octets, declared %d",
						len(body), padded, pad, got, want)
				}
				if h := ParseHeader(wire); h.Length != f.PayloadLen() {
					t.Fatalf("header length %d, want %d", h.Length, f.PayloadLen())
				}
			}
		}
	}
}

func TestDataByteExact(t *testing.T) {
	f := DataFrame{StreamID: 1, EndStream: true, Data: []byte("hello")}
	want := []byte{
		0x00, 0x00, 0x05, // length 5
		0x00,                   // DATA
		0x01,                   // END_STREAM
		0x00, 0x00, 0x00, 0x01, // stream 1
		'h', 'e', 'l', 'l', 'o',
	}
	if got := serializeFrame(f); !bytes.Equal(got, want) {
		t.Errorf("wire form\n got % x\nwant % x", got, want)
	}

	padded := DataFrame{StreamID: 1, Data: []byte("hi"), Padded: true, PadLen: 3}
	wantPadded := []byte{
		0x00, 0x00, 0x06, // length 6: 1 + 2 + 3
		0x00,                   // DATA
		0x08,                   // PADDED
		0x00, 0x00, 0x00, 0x01, // stream 1
		0x03, // pad length
		'h', 'i',
		0x00, 0x00, 0x00, // padding
	}
	if got := serializeFrame(padded); !bytes.Equal(got, wantPadded) {
		t.Errorf("padded wire form\n got % x\nwant % x", got, wantPadded)
	}
}

func TestDataRoundTrip(t *testing.T) {
	frames := []DataFrame{
		{StreamID: 1},
		{StreamID: 1, EndStream: true},
		{StreamID: 1, Data: []byte("hello")},
		{StreamID: 0x7fffffff, EndStream: true, Data: bytes.Repeat([]byte{0xaa}, 300)},
		{StreamID: 3, Data: []byte("body"), Padded: true, PadLen: 7},
		{StreamID: 3, Padded: true, PadLen: 0},
		{StreamID: 3, Padded: true, PadLen: maxPadLen, Data: []byte{0x00}},
		{StreamID: 5, EndStream: true, Data: []byte{0x00, 0xff}, Padded: true, PadLen: 1},
	}
	for _, want := range frames {
		wire := serializeFrame(want)
		h := ParseHeader(wire)
		f, err := parseData(h, wire[HeaderLen:])
		wantNoErr(t, err)
		got := f.(DataFrame)
		if got.StreamID != want.StreamID || got.EndStream != want.EndStream ||
			got.Padded != want.Padded || got.PadLen != want.PadLen {
			t.Errorf("round trip\n got %+v\nwant %+v", got, want)
		}
		if !bytes.Equal(got.Data, want.Data) {
			t.Errorf("round trip Data\n got % x\nwant % x", got.Data, want.Data)
		}
	}
}

// TestDataMaxSizeBody checks a frame at the default maximum frame size, which is
// the largest DATA frame a peer may send before we have raised the limit. The
// bound is the reader's; this only asserts nothing here truncates at it.
func TestDataMaxSizeBody(t *testing.T) {
	body := make([]byte, DefaultMaxFrameSize)
	for i := range body {
		body[i] = byte(i)
	}
	h := Header{Length: DefaultMaxFrameSize, Type: TypeData, StreamID: 1}
	f, err := parseData(h, body)
	wantNoErr(t, err)
	if got := f.(DataFrame).Data; !bytes.Equal(got, body) {
		t.Errorf("Data is %d octets, want %d, with matching contents", len(got), len(body))
	}
}
