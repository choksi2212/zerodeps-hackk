package frame

import (
	"bytes"
	"testing"

	"zerodeps/zdh/internal/h2"
)

func TestParseWindowUpdateValid(t *testing.T) {
	tests := []struct {
		name    string
		stream  uint32
		payload []byte
		want    WindowUpdateFrame
	}{
		{
			name:    "minimum increment on the connection",
			stream:  0,
			payload: []byte{0x00, 0x00, 0x00, 0x01},
			want:    WindowUpdateFrame{StreamID: 0, Increment: 1},
		},
		{
			name:    "minimum increment on a stream",
			stream:  1,
			payload: []byte{0x00, 0x00, 0x00, 0x01},
			want:    WindowUpdateFrame{StreamID: 1, Increment: 1},
		},
		{
			name:    "increment is big-endian across all four octets",
			stream:  3,
			payload: []byte{0x01, 0x02, 0x03, 0x04},
			want:    WindowUpdateFrame{StreamID: 3, Increment: 0x01020304},
		},
		{
			name:    "the default initial window as an increment",
			stream:  0,
			payload: []byte{0x00, 0x00, 0xff, 0xff},
			want:    WindowUpdateFrame{StreamID: 0, Increment: DefaultInitialWindowSize},
		},
		{
			name:    "maximum legal increment",
			stream:  1,
			payload: []byte{0x7f, 0xff, 0xff, 0xff},
			want:    WindowUpdateFrame{StreamID: 1, Increment: MaxWindowSize},
		},
		{
			// RFC 9113 §6.9 reserves the top bit and requires a receiver to
			// ignore it. An increment read with that bit included is off by
			// 2^31, which credits a window past its legal maximum and turns a
			// valid frame into a spurious FLOW_CONTROL_ERROR.
			name:    "reserved bit set alongside a real increment",
			stream:  1,
			payload: []byte{0x80, 0x00, 0x00, 0x01},
			want:    WindowUpdateFrame{StreamID: 1, Increment: 1},
		},
		{
			name:    "reserved bit set alongside the maximum increment",
			stream:  0,
			payload: []byte{0xff, 0xff, 0xff, 0xff},
			want:    WindowUpdateFrame{StreamID: 0, Increment: MaxWindowSize},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := Header{Length: windowUpdateLen, Type: TypeWindowUpdate, StreamID: tt.stream}
			f, err := parseWindowUpdate(h, tt.payload)
			wantNoErr(t, err)
			got, ok := f.(WindowUpdateFrame)
			if !ok {
				t.Fatalf("parseWindowUpdate returned %T, want WindowUpdateFrame", f)
			}
			if got != tt.want {
				t.Errorf("\n got %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

// TestParseWindowUpdateBadLength is matrix row 27.
func TestParseWindowUpdateBadLength(t *testing.T) {
	for _, length := range []uint32{0, 1, 3, 5, 6, 8, MaxLength} {
		for _, stream := range []uint32{0, 1} {
			h := Header{Length: length, Type: TypeWindowUpdate, StreamID: stream}
			_, err := parseWindowUpdate(h, make([]byte, windowUpdateLen))
			wantConnErr(t, err, h2.FrameSizeError)
		}
	}
}

// TestParseWindowUpdateZeroIncrement is matrix rows 28 and 29: the same
// malformed frame is fatal on the connection and survivable on a stream. Getting
// the scope backwards means either killing connections a peer is entitled to
// keep, or keeping one the protocol says must die.
func TestParseWindowUpdateZeroIncrement(t *testing.T) {
	t.Run("on the connection it is fatal", func(t *testing.T) {
		h := Header{Length: windowUpdateLen, Type: TypeWindowUpdate, StreamID: 0}
		_, err := parseWindowUpdate(h, []byte{0x00, 0x00, 0x00, 0x00})
		wantConnErr(t, err, h2.ProtocolError)
	})
	t.Run("on a stream only the stream dies", func(t *testing.T) {
		for _, stream := range []uint32{1, 3, 0x7fffffff} {
			h := Header{Length: windowUpdateLen, Type: TypeWindowUpdate, StreamID: stream}
			_, err := parseWindowUpdate(h, []byte{0x00, 0x00, 0x00, 0x00})
			wantStreamErr(t, err, stream, h2.ProtocolError)
		}
	})
}

// TestParseWindowUpdateReservedBitOnlyIsZeroIncrement is the adversarial case
// the two rules above combine into: 0x80000000 masks down to an increment of
// zero. A parser that forgot to mask reads it as 2147483648 and accepts a frame
// the protocol forbids.
func TestParseWindowUpdateReservedBitOnlyIsZeroIncrement(t *testing.T) {
	t.Run("on the connection", func(t *testing.T) {
		h := Header{Length: windowUpdateLen, Type: TypeWindowUpdate, StreamID: 0}
		_, err := parseWindowUpdate(h, []byte{0x80, 0x00, 0x00, 0x00})
		wantConnErr(t, err, h2.ProtocolError)
	})
	t.Run("on a stream", func(t *testing.T) {
		h := Header{Length: windowUpdateLen, Type: TypeWindowUpdate, StreamID: 7}
		_, err := parseWindowUpdate(h, []byte{0x80, 0x00, 0x00, 0x00})
		wantStreamErr(t, err, 7, h2.ProtocolError)
	})
}

// TestParseWindowUpdateBadLengthBeatsZeroIncrement pins the validation order.
// The length has to be checked first: with fewer than four octets there is no
// increment to inspect at all.
func TestParseWindowUpdateBadLengthBeatsZeroIncrement(t *testing.T) {
	h := Header{Length: 3, Type: TypeWindowUpdate, StreamID: 1}
	_, err := parseWindowUpdate(h, []byte{0x00, 0x00, 0x00, 0x00})
	wantConnErr(t, err, h2.FrameSizeError)
}

// TestParseWindowUpdateAcceptsStreamZero records that WINDOW_UPDATE is the one
// frame legal both on the connection and on a stream, so there is deliberately
// no stream-identifier rule to enforce.
func TestParseWindowUpdateAcceptsStreamZero(t *testing.T) {
	h := Header{Length: windowUpdateLen, Type: TypeWindowUpdate, StreamID: 0}
	f, err := parseWindowUpdate(h, []byte{0x00, 0x00, 0x10, 0x00})
	wantNoErr(t, err)
	if got := f.(WindowUpdateFrame); got.StreamID != 0 || got.Increment != 0x1000 {
		t.Errorf("got %+v, want {StreamID:0 Increment:4096}", got)
	}
}

func TestWindowUpdateFrameShape(t *testing.T) {
	f := WindowUpdateFrame{StreamID: 5, Increment: 1024}
	if f.Type() != TypeWindowUpdate {
		t.Errorf("Type = %s, want WINDOW_UPDATE", f.Type())
	}
	if f.Flags() != 0 {
		t.Errorf("Flags = 0x%02x, want 0x00; WINDOW_UPDATE defines no flags", uint8(f.Flags()))
	}
	if f.Stream() != 5 {
		t.Errorf("Stream = %d, want 5", f.Stream())
	}
	if f.PayloadLen() != windowUpdateLen {
		t.Errorf("PayloadLen = %d, want %d", f.PayloadLen(), windowUpdateLen)
	}
}

// TestWindowUpdateAppendMasksReservedBit asserts we never send the reserved bit
// set, even from a struct whose Increment somehow has it. §6.9 requires it to be
// written as zero.
func TestWindowUpdateAppendMasksReservedBit(t *testing.T) {
	f := WindowUpdateFrame{StreamID: 1, Increment: 0xffffffff}
	got := f.appendPayload(nil)
	want := []byte{0x7f, 0xff, 0xff, 0xff}
	if !bytes.Equal(got, want) {
		t.Errorf("appendPayload\n got % x\nwant % x", got, want)
	}
}

func TestWindowUpdateRoundTrip(t *testing.T) {
	frames := []WindowUpdateFrame{
		{StreamID: 0, Increment: 1},
		{StreamID: 1, Increment: DefaultInitialWindowSize},
		{StreamID: 0x7fffffff, Increment: MaxWindowSize},
		{StreamID: 3, Increment: 0x01020304},
	}
	for _, want := range frames {
		wire := serializeFrame(want)
		if len(wire) != HeaderLen+windowUpdateLen {
			t.Fatalf("serialised %d octets, want %d", len(wire), HeaderLen+windowUpdateLen)
		}
		h := ParseHeader(wire)
		f, err := parseWindowUpdate(h, wire[HeaderLen:])
		wantNoErr(t, err)
		if got := f.(WindowUpdateFrame); got != want {
			t.Errorf("round trip\n got %+v\nwant %+v", got, want)
		}
	}
}
