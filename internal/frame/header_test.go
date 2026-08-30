package frame

import (
	"bytes"
	"testing"
)

// stubFrame exists only to exercise HeaderOf. Frame has an unexported method,
// so the interface can be satisfied inside this package and nowhere else; that
// is what makes a type switch over the real frame types exhaustive.
type stubFrame struct {
	typ      FrameType
	flags    Flags
	streamID uint32
	payload  []byte
}

func (f stubFrame) Type() FrameType                 { return f.typ }
func (f stubFrame) Flags() Flags                    { return f.flags }
func (f stubFrame) Stream() uint32                  { return f.streamID }
func (f stubFrame) PayloadLen() uint32              { return uint32(len(f.payload)) }
func (f stubFrame) appendPayload(dst []byte) []byte { return append(dst, f.payload...) }

var _ Frame = stubFrame{}

func TestParseHeaderByteExact(t *testing.T) {
	// Hand-written wire bytes, not bytes produced by AppendTo: a test that only
	// checks a round-trip through our own serialiser will happily agree with
	// itself about a little-endian length field.
	tests := []struct {
		name string
		wire []byte
		want Header
	}{
		{
			name: "DATA len 5 END_STREAM stream 1",
			wire: []byte{0x00, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01},
			want: Header{Length: 5, Type: TypeData, Flags: FlagEndStream, StreamID: 1},
		},
		{
			name: "empty SETTINGS on the connection",
			wire: []byte{0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00},
			want: Header{Length: 0, Type: TypeSettings, Flags: 0, StreamID: 0},
		},
		{
			name: "SETTINGS ACK",
			wire: []byte{0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00},
			want: Header{Length: 0, Type: TypeSettings, Flags: FlagAck, StreamID: 0},
		},
		{
			name: "length is big-endian across all three octets",
			wire: []byte{0x01, 0x02, 0x03, 0x01, 0x25, 0x00, 0x00, 0x00, 0x0f},
			want: Header{
				Length:   0x010203,
				Type:     TypeHeaders,
				Flags:    FlagEndStream | FlagEndHeaders | FlagPriority,
				StreamID: 15,
			},
		},
		{
			name: "maximum 24-bit length",
			wire: []byte{0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			want: Header{Length: MaxLength, Type: TypeData, Flags: 0, StreamID: 1},
		},
		{
			name: "stream id is big-endian across all four octets",
			wire: []byte{0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x02, 0x03, 0x04},
			want: Header{Length: 0, Type: TypeRSTStream, Flags: 0, StreamID: 0x01020304},
		},
		{
			name: "maximum stream id",
			wire: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff},
			want: Header{Length: 0, Type: TypeData, Flags: 0, StreamID: 1<<31 - 1},
		},
		{
			name: "all zero",
			wire: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			want: Header{Length: 0, Type: TypeData, Flags: 0, StreamID: 0},
		},
		{
			name: "all ones: unknown type, every flag, reserved bit set",
			wire: []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			want: Header{
				Length:   MaxLength,
				Type:     FrameType(0xff),
				Flags:    Flags(0xff),
				StreamID: 1<<31 - 1,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseHeader(tt.wire); got != tt.want {
				t.Errorf("ParseHeader(% x)\n got %+v\nwant %+v", tt.wire, got, tt.want)
			}
		})
	}
}

func TestParseHeaderIgnoresReservedBit(t *testing.T) {
	// RFC 9113 §4.1: the reserved bit is undefined on receive and must be
	// ignored. h2spec generic/4.1 sends a frame with it set and fails an
	// implementation that rejects the frame or mis-reads the stream id.
	tests := []struct {
		name string
		wire []byte
		want uint32
	}{
		{"reserved set, stream 1", []byte{0, 0, 0, 0, 0, 0x80, 0x00, 0x00, 0x01}, 1},
		{"reserved set, stream 0", []byte{0, 0, 0, 4, 0, 0x80, 0x00, 0x00, 0x00}, 0},
		{"reserved set, max stream", []byte{0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff}, 1<<31 - 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseHeader(tt.wire).StreamID; got != tt.want {
				t.Errorf("StreamID = %d (0x%08x), want %d; the reserved bit was not masked",
					got, got, tt.want)
			}
		})
	}
}

func TestParseHeaderIgnoresTrailingBytes(t *testing.T) {
	// The reader hands ParseHeader a scratch buffer that may be longer than the
	// header. Anything past octet 9 is payload and must not leak into a field.
	wire := []byte{0x00, 0x00, 0x08, 0x06, 0x01, 0x00, 0x00, 0x00, 0x00,
		0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef}
	want := Header{Length: 8, Type: TypePing, Flags: FlagAck, StreamID: 0}
	if got := ParseHeader(wire); got != want {
		t.Errorf("ParseHeader with trailing payload\n got %+v\nwant %+v", got, want)
	}
}

func TestAppendToByteExact(t *testing.T) {
	tests := []struct {
		name string
		h    Header
		want []byte
	}{
		{
			name: "DATA len 5 END_STREAM stream 1",
			h:    Header{Length: 5, Type: TypeData, Flags: FlagEndStream, StreamID: 1},
			want: []byte{0x00, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01},
		},
		{
			name: "empty SETTINGS",
			h:    Header{Type: TypeSettings},
			want: []byte{0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name: "length is written big-endian",
			h:    Header{Length: 0x010203, Type: TypeHeaders, Flags: FlagEndHeaders, StreamID: 15},
			want: []byte{0x01, 0x02, 0x03, 0x01, 0x04, 0x00, 0x00, 0x00, 0x0f},
		},
		{
			name: "maximum length and maximum stream id",
			h:    Header{Length: MaxLength, Type: TypeContinuation, StreamID: 1<<31 - 1},
			want: []byte{0xff, 0xff, 0xff, 0x09, 0x00, 0x7f, 0xff, 0xff, 0xff},
		},
		{
			name: "reserved bit is always written as zero",
			h:    Header{Type: TypeData, StreamID: 0xffffffff},
			want: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff},
		},
		{
			name: "an unknown type serialises as itself",
			h:    Header{Length: 1, Type: FrameType(0xef), Flags: Flags(0xbe), StreamID: 3},
			want: []byte{0x00, 0x00, 0x01, 0xef, 0xbe, 0x00, 0x00, 0x00, 0x03},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.h.AppendTo(nil)
			if len(got) != HeaderLen {
				t.Fatalf("AppendTo wrote %d octets, want %d", len(got), HeaderLen)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("AppendTo(%+v)\n got % x\nwant % x", tt.h, got, tt.want)
			}
		})
	}
}

func TestAppendToAppends(t *testing.T) {
	// The writer builds a frame into one buffer: header first, then payload, so
	// AppendTo must extend dst rather than replace it.
	prefix := []byte{0xaa, 0xbb}
	h := Header{Length: 1, Type: TypeWindowUpdate, StreamID: 7}
	got := h.AppendTo(prefix)
	want := []byte{0xaa, 0xbb, 0x00, 0x00, 0x01, 0x08, 0x00, 0x00, 0x00, 0x00, 0x07}
	if !bytes.Equal(got, want) {
		t.Errorf("AppendTo to a non-empty buffer\n got % x\nwant % x", got, want)
	}
	if len(got) != len(prefix)+HeaderLen {
		t.Errorf("AppendTo produced %d octets, want %d", len(got), len(prefix)+HeaderLen)
	}
	if !bytes.Equal(prefix, []byte{0xaa, 0xbb}) {
		t.Errorf("AppendTo modified the caller's prefix: % x", prefix)
	}
}

func TestHeaderRoundTrip(t *testing.T) {
	headers := []Header{
		{Length: 0, Type: TypeSettings, Flags: FlagAck, StreamID: 0},
		{Length: 5, Type: TypeData, Flags: FlagEndStream, StreamID: 1},
		{Length: 8, Type: TypePing, Flags: FlagAck, StreamID: 0},
		{Length: 4, Type: TypeRSTStream, StreamID: 0x7ffffffe},
		{Length: MaxLength, Type: TypeContinuation, Flags: FlagEndHeaders, StreamID: 1<<31 - 1},
		{Length: 0x010203, Type: TypeHeaders, Flags: 0xff, StreamID: 0x01020304},
		{Length: 1, Type: FrameType(0xff), Flags: 0, StreamID: 0},
	}
	for _, h := range headers {
		if got := ParseHeader(h.AppendTo(nil)); got != h {
			t.Errorf("round trip\n got %+v\nwant %+v", got, h)
		}
	}
}

func TestHeaderOfDerivesLengthFromPayload(t *testing.T) {
	// Frames do not store their own length; it is computed from the payload when
	// the frame is written. That is what makes it impossible to send a frame
	// whose length field disagrees with its contents — a bug that a peer sees as
	// a desynchronised connection rather than as a bad frame.
	tests := []struct {
		name string
		f    stubFrame
		want Header
	}{
		{
			name: "empty payload",
			f:    stubFrame{typ: TypeSettings, streamID: 0},
			want: Header{Length: 0, Type: TypeSettings, Flags: 0, StreamID: 0},
		},
		{
			name: "payload length is used verbatim",
			f: stubFrame{
				typ:      TypeData,
				flags:    FlagEndStream,
				streamID: 1,
				payload:  []byte("hello"),
			},
			want: Header{Length: 5, Type: TypeData, Flags: FlagEndStream, StreamID: 1},
		},
		{
			name: "a payload larger than the default max frame size is still described",
			f:    stubFrame{typ: TypeData, streamID: 3, payload: make([]byte, DefaultMaxFrameSize+1)},
			want: Header{Length: DefaultMaxFrameSize + 1, Type: TypeData, StreamID: 3},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HeaderOf(tt.f); got != tt.want {
				t.Errorf("HeaderOf\n got %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

func TestHeaderString(t *testing.T) {
	tests := []struct {
		h    Header
		want string
	}{
		{
			Header{Length: 5, Type: TypeData, Flags: FlagEndStream, StreamID: 1},
			"[DATA len=5 flags=0x01 stream=1]",
		},
		{
			Header{Length: 0, Type: TypeSettings, Flags: 0, StreamID: 0},
			"[SETTINGS len=0 flags=0x00 stream=0]",
		},
		{
			Header{Length: MaxLength, Type: FrameType(0x0a), Flags: 0xff, StreamID: 1<<31 - 1},
			"[UNKNOWN_FRAME_TYPE(0xa) len=16777215 flags=0xff stream=2147483647]",
		},
	}
	for _, tt := range tests {
		if got := tt.h.String(); got != tt.want {
			t.Errorf("String()\n got %q\nwant %q", got, tt.want)
		}
	}
}

// FuzzHeaderRoundTrip asserts the one exact invariant the header layer has: for
// any nine octets, re-serialising the parsed header reproduces those octets with
// the reserved bit cleared. Nothing else may be lost, reordered or invented.
//
// This is the property the rest of the frame layer is built on. If the header
// codec loses a bit, every per-type parser above it is validating the wrong
// numbers.
func FuzzHeaderRoundTrip(f *testing.F) {
	f.Add([]byte{0x00, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{0x00, 0x00, 0x00, 0x04, 0x01, 0x80, 0x00, 0x00, 0x00})

	f.Fuzz(func(t *testing.T, b []byte) {
		// ParseHeader documents that it panics below HeaderLen: the reader only
		// ever calls it after io.ReadFull of exactly nine octets, so a short
		// buffer is out of contract rather than hostile input.
		if len(b) < HeaderLen {
			return
		}
		b = b[:HeaderLen]
		orig := append([]byte(nil), b...)

		want := append([]byte(nil), b...)
		want[5] &= 0x7f // the reserved bit is discarded, by design

		got := ParseHeader(b).AppendTo(nil)
		if !bytes.Equal(got, want) {
			t.Fatalf("round trip lost information\n  in % x\n out % x\nwant % x", orig, got, want)
		}
		// ParseHeader reads from a buffer the reader reuses, so it must not
		// write to it.
		if !bytes.Equal(b, orig) {
			t.Fatalf("ParseHeader modified its input\n  was % x\n now % x", orig, b)
		}
	})
}
