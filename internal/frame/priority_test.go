package frame

import (
	"bytes"
	"testing"

	"zerodeps/zdh/internal/h2"
)

func TestParsePriorityValid(t *testing.T) {
	tests := []struct {
		name    string
		stream  uint32
		payload []byte
		want    PriorityFrame
	}{
		{
			name:    "non-exclusive dependency on stream 0",
			stream:  3,
			payload: []byte{0x00, 0x00, 0x00, 0x00, 0x0f},
			want:    PriorityFrame{StreamID: 3, Exclusive: false, StreamDependency: 0, Weight: 0x0f},
		},
		{
			name:    "exclusive bit set",
			stream:  3,
			payload: []byte{0x80, 0x00, 0x00, 0x01, 0x10},
			want:    PriorityFrame{StreamID: 3, Exclusive: true, StreamDependency: 1, Weight: 0x10},
		},
		{
			name:    "dependency is big-endian across all four octets",
			stream:  0x7fffffff,
			payload: []byte{0x01, 0x02, 0x03, 0x04, 0xff},
			want: PriorityFrame{
				StreamID:         0x7fffffff,
				StreamDependency: 0x01020304,
				Weight:           0xff,
			},
		},
		{
			name:    "weight 0 is legal: the effective weight is 1",
			stream:  1,
			payload: []byte{0x00, 0x00, 0x00, 0x02, 0x00},
			want:    PriorityFrame{StreamID: 1, StreamDependency: 2, Weight: 0},
		},
		{
			name:    "weight 255 is legal: the effective weight is 256",
			stream:  1,
			payload: []byte{0x00, 0x00, 0x00, 0x02, 0xff},
			want:    PriorityFrame{StreamID: 1, StreamDependency: 2, Weight: 255},
		},
		{
			name:    "maximum dependency with the exclusive bit",
			stream:  1,
			payload: []byte{0xff, 0xff, 0xff, 0xff, 0x07},
			want: PriorityFrame{
				StreamID:         1,
				Exclusive:        true,
				StreamDependency: 1<<31 - 1,
				Weight:           7,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := Header{Length: priorityLen, Type: TypePriority, StreamID: tt.stream}
			f, err := parsePriority(h, tt.payload)
			wantNoErr(t, err)
			got, ok := f.(PriorityFrame)
			if !ok {
				t.Fatalf("parsePriority returned %T, want PriorityFrame", f)
			}
			if got != tt.want {
				t.Errorf("\n got %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

// TestParsePriorityStreamZero is matrix row 9: PRIORITY on stream 0 is a
// connection error.
func TestParsePriorityStreamZero(t *testing.T) {
	h := Header{Length: priorityLen, Type: TypePriority, StreamID: 0}
	_, err := parsePriority(h, []byte{0, 0, 0, 1, 0})
	wantConnErr(t, err, h2.ProtocolError)
}

// TestParsePriorityBadLength is matrix row 8: a wrong length is a *stream*
// error, the only length rule in the protocol that spares the connection.
func TestParsePriorityBadLength(t *testing.T) {
	for _, length := range []uint32{0, 1, 4, 6, 7, 100, MaxLength} {
		h := Header{Length: length, Type: TypePriority, StreamID: 5}
		// A payload long enough that a parser ignoring the length check would
		// read garbage rather than panic — the failure has to come from the
		// length rule, not from a bounds check.
		_, err := parsePriority(h, make([]byte, priorityLen))
		wantStreamErr(t, err, 5, h2.FrameSizeError)
	}
}

// TestParsePriorityStreamZeroBeatsBadLength pins the validation order. Both
// rules are violated and they disagree about scope; the connection-level rule
// has to win, or a peer can provoke us into keeping a connection we are required
// to close.
func TestParsePriorityStreamZeroBeatsBadLength(t *testing.T) {
	h := Header{Length: 4, Type: TypePriority, StreamID: 0}
	_, err := parsePriority(h, make([]byte, priorityLen))
	wantConnErr(t, err, h2.ProtocolError)
}

func TestParsePrioritySelfDependency(t *testing.T) {
	tests := []struct {
		name    string
		stream  uint32
		payload []byte
	}{
		{"stream 1 depends on itself", 1, []byte{0x00, 0x00, 0x00, 0x01, 0x00}},
		{"exclusive self-dependency", 1, []byte{0x80, 0x00, 0x00, 0x01, 0x00}},
		{
			name:    "self-dependency hidden behind the exclusive bit",
			stream:  1,
			payload: []byte{0x80, 0x00, 0x00, 0x01, 0x00},
		},
		{
			name:    "maximum stream depends on itself",
			stream:  1<<31 - 1,
			payload: []byte{0x7f, 0xff, 0xff, 0xff, 0x00},
		},
		{
			name:    "maximum stream depends on itself with the exclusive bit set",
			stream:  1<<31 - 1,
			payload: []byte{0xff, 0xff, 0xff, 0xff, 0x00},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := Header{Length: priorityLen, Type: TypePriority, StreamID: tt.stream}
			_, err := parsePriority(h, tt.payload)
			wantStreamErr(t, err, tt.stream, h2.ProtocolError)
		})
	}
}

// TestParsePriorityBlockMasksExclusiveBit is the reason the self-dependency
// cases above set the top bit: a parser that reads the E bit as part of the
// dependency turns a dependency on stream 1 into one on stream 2147483649, and
// then never detects a self-dependency at all.
func TestParsePriorityBlockMasksExclusiveBit(t *testing.T) {
	exclusive, dep, weight := parsePriorityBlock([]byte{0x80, 0x00, 0x00, 0x01, 0x2a})
	if !exclusive {
		t.Error("exclusive = false, want true")
	}
	if dep != 1 {
		t.Errorf("dependency = %d (0x%08x), want 1; the E bit leaked into the number", dep, dep)
	}
	if weight != 0x2a {
		t.Errorf("weight = 0x%02x, want 0x2a", weight)
	}
}

func TestPriorityFrameShape(t *testing.T) {
	f := PriorityFrame{StreamID: 7, Exclusive: true, StreamDependency: 3, Weight: 200}
	if f.Type() != TypePriority {
		t.Errorf("Type = %s, want PRIORITY", f.Type())
	}
	// PRIORITY defines no flags, so the wire flags are always zero regardless of
	// what a peer sent us.
	if f.Flags() != 0 {
		t.Errorf("Flags = 0x%02x, want 0x00", uint8(f.Flags()))
	}
	if f.Stream() != 7 {
		t.Errorf("Stream = %d, want 7", f.Stream())
	}
	if f.PayloadLen() != priorityLen {
		t.Errorf("PayloadLen = %d, want %d", f.PayloadLen(), priorityLen)
	}
}

func TestPriorityRoundTrip(t *testing.T) {
	frames := []PriorityFrame{
		{StreamID: 1, StreamDependency: 0, Weight: 0},
		{StreamID: 3, Exclusive: true, StreamDependency: 1, Weight: 15},
		{StreamID: 0x7fffffff, StreamDependency: 0x01020304, Weight: 255},
		{StreamID: 5, Exclusive: true, StreamDependency: 1<<31 - 1, Weight: 128},
	}
	for _, want := range frames {
		wire := serializeFrame(want)
		if len(wire) != HeaderLen+priorityLen {
			t.Fatalf("serialised %d octets, want %d", len(wire), HeaderLen+priorityLen)
		}
		h := ParseHeader(wire)
		if h.Length != priorityLen || h.Type != TypePriority || h.StreamID != want.StreamID {
			t.Fatalf("header round trip: got %+v for %+v", h, want)
		}
		f, err := parsePriority(h, wire[HeaderLen:])
		wantNoErr(t, err)
		if got := f.(PriorityFrame); got != want {
			t.Errorf("round trip\n got %+v\nwant %+v", got, want)
		}
	}
}

func TestAppendPriorityBlockByteExact(t *testing.T) {
	tests := []struct {
		exclusive bool
		dep       uint32
		weight    uint8
		want      []byte
	}{
		{false, 0, 0, []byte{0x00, 0x00, 0x00, 0x00, 0x00}},
		{true, 0, 0, []byte{0x80, 0x00, 0x00, 0x00, 0x00}},
		{false, 1, 0x0f, []byte{0x00, 0x00, 0x00, 0x01, 0x0f}},
		{true, 1<<31 - 1, 0xff, []byte{0xff, 0xff, 0xff, 0xff, 0xff}},
		{false, 0x01020304, 0x2a, []byte{0x01, 0x02, 0x03, 0x04, 0x2a}},
		// A dependency with the top bit set cannot happen — stream identifiers
		// are 31 bits — but if it did, the E bit must come from the boolean and
		// not from the number.
		{false, 0xffffffff, 0x00, []byte{0x7f, 0xff, 0xff, 0xff, 0x00}},
	}
	for _, tt := range tests {
		got := appendPriorityBlock(nil, tt.exclusive, tt.dep, tt.weight)
		if !bytes.Equal(got, tt.want) {
			t.Errorf("appendPriorityBlock(%v, 0x%08x, 0x%02x)\n got % x\nwant % x",
				tt.exclusive, tt.dep, tt.weight, got, tt.want)
		}
	}
}
