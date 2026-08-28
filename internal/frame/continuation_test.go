package frame

import (
	"bytes"
	"testing"

	"zerodeps/zdh/internal/h2"
)

func TestParseContinuationValid(t *testing.T) {
	tests := []struct {
		name    string
		flags   Flags
		stream  uint32
		length  uint32
		payload []byte
		want    ContinuationFrame
	}{
		{
			name:    "final fragment",
			flags:   FlagEndHeaders,
			stream:  1,
			length:  2,
			payload: []byte{0x82, 0x86},
			want: ContinuationFrame{
				StreamID:   1,
				EndHeaders: true,
				Fragment:   []byte{0x82, 0x86},
			},
		},
		{
			name:    "middle fragment",
			stream:  1,
			length:  1,
			payload: []byte{0x84},
			want:    ContinuationFrame{StreamID: 1, Fragment: []byte{0x84}},
		},
		{
			// A zero-length CONTINUATION is legal. It is also the cheapest frame a
			// flood can be built out of: nine octets of header and nothing else,
			// each one extending a header block that no concurrency limit is
			// counting. See the type's doc comment and internal/limits.
			name:   "empty",
			stream: 1,
			length: 0,
			want:   ContinuationFrame{StreamID: 1},
		},
		{
			name:   "empty with END_HEADERS",
			flags:  FlagEndHeaders,
			stream: 1,
			length: 0,
			want:   ContinuationFrame{StreamID: 1, EndHeaders: true},
		},
		{
			// CONTINUATION defines only END_HEADERS. END_STREAM, PADDED and
			// PRIORITY are undefined on it and must be ignored (§4.1) — and in
			// particular PADDED must not cause the first octet of the fragment to
			// be eaten as a pad length, which would corrupt the header block and
			// with it the connection's HPACK table.
			name:    "PADDED and PRIORITY are undefined here and ignored",
			flags:   FlagEndHeaders | FlagPadded | FlagPriority | FlagEndStream,
			stream:  1,
			length:  3,
			payload: []byte{0x04, 0x82, 0x86},
			want: ContinuationFrame{
				StreamID:   1,
				EndHeaders: true,
				Fragment:   []byte{0x04, 0x82, 0x86},
			},
		},
		{
			name:    "maximum stream identifier",
			flags:   FlagEndHeaders,
			stream:  0x7fffffff,
			length:  1,
			payload: []byte{0x82},
			want: ContinuationFrame{
				StreamID:   0x7fffffff,
				EndHeaders: true,
				Fragment:   []byte{0x82},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := Header{
				Length:   tt.length,
				Type:     TypeContinuation,
				Flags:    tt.flags,
				StreamID: tt.stream,
			}
			f, err := parseContinuation(h, tt.payload)
			wantNoErr(t, err)
			got, ok := f.(ContinuationFrame)
			if !ok {
				t.Fatalf("parseContinuation returned %T, want ContinuationFrame", f)
			}
			if got.StreamID != tt.want.StreamID {
				t.Errorf("StreamID = %d, want %d", got.StreamID, tt.want.StreamID)
			}
			if got.EndHeaders != tt.want.EndHeaders {
				t.Errorf("EndHeaders = %v, want %v", got.EndHeaders, tt.want.EndHeaders)
			}
			if !bytes.Equal(got.Fragment, tt.want.Fragment) {
				t.Errorf("Fragment = % x, want % x", got.Fragment, tt.want.Fragment)
			}
		})
	}
}

// TestParseContinuationStreamZero is matrix row 32.
func TestParseContinuationStreamZero(t *testing.T) {
	h := Header{Length: 1, Type: TypeContinuation, Flags: FlagEndHeaders, StreamID: 0}
	_, err := parseContinuation(h, []byte{0x82})
	wantConnErr(t, err, h2.ProtocolError)
}

// TestParseContinuationHasNoLengthRule records the absence of one. CONTINUATION
// carries nothing but fragment, so there is no minimum length and no fixed size:
// any length up to the negotiated maximum frame size is well formed, and the only
// bound is the reader's.
func TestParseContinuationHasNoLengthRule(t *testing.T) {
	for _, length := range []uint32{0, 1, 2, 100, DefaultMaxFrameSize} {
		payload := make([]byte, length)
		h := Header{Length: length, Type: TypeContinuation, StreamID: 1}
		f, err := parseContinuation(h, payload)
		wantNoErr(t, err)
		if got := f.(ContinuationFrame).Fragment; uint32(len(got)) != length {
			t.Errorf("length %d: Fragment is %d octets", length, len(got))
		}
	}
}

func TestParseContinuationEmptyFragmentIsNil(t *testing.T) {
	h := Header{Length: 0, Type: TypeContinuation, StreamID: 1}
	f, err := parseContinuation(h, nil)
	wantNoErr(t, err)
	if got := f.(ContinuationFrame).Fragment; got != nil {
		t.Errorf("Fragment = % x (len %d), want nil", got, len(got))
	}
}

// TestParseContinuationUsesOnlyTheDeclaredLength guards the reader's buffer
// contract. On this frame type the whole payload is header block, so reading past
// the length appends the next frame's octets straight onto an HPACK block — which
// desynchronises the dynamic table for the rest of the connection.
func TestParseContinuationUsesOnlyTheDeclaredLength(t *testing.T) {
	payload := []byte{0x82, 0x86, 'N', 'O', 'T', 'M', 'I', 'N', 'E'}
	h := Header{Length: 2, Type: TypeContinuation, StreamID: 1}
	f, err := parseContinuation(h, payload)
	wantNoErr(t, err)
	if got := f.(ContinuationFrame).Fragment; !bytes.Equal(got, []byte{0x82, 0x86}) {
		t.Errorf("Fragment = % x, want 82 86; the parser read past the declared length", got)
	}
}

// TestParseContinuationCopiesItsFragment is the ownership test. Fragments are
// accumulated across frames by definition here, so this is the one frame type
// where an aliased payload would be certain, not merely likely, to be overwritten
// before it was used.
func TestParseContinuationCopiesItsFragment(t *testing.T) {
	payload := []byte{0x82, 0x86, 0x84}
	h := Header{Length: uint32(len(payload)), Type: TypeContinuation, StreamID: 1}
	f, err := parseContinuation(h, payload)
	wantNoErr(t, err)

	for i := range payload {
		payload[i] = 0xff
	}

	if got := f.(ContinuationFrame).Fragment; !bytes.Equal(got, []byte{0x82, 0x86, 0x84}) {
		t.Errorf("Fragment = % x after the source buffer was reused, want 82 86 84; "+
			"the fragment was aliased rather than copied", got)
	}
}

func TestContinuationFrameShape(t *testing.T) {
	f := ContinuationFrame{StreamID: 9, EndHeaders: true, Fragment: []byte{0x82, 0x86}}
	if f.Type() != TypeContinuation {
		t.Errorf("Type = %s, want CONTINUATION", f.Type())
	}
	if got := f.Flags(); got != FlagEndHeaders {
		t.Errorf("Flags = 0x%02x, want 0x%02x", uint8(got), uint8(FlagEndHeaders))
	}
	if f.Stream() != 9 {
		t.Errorf("Stream = %d, want 9", f.Stream())
	}
	if f.PayloadLen() != 2 {
		t.Errorf("PayloadLen = %d, want 2", f.PayloadLen())
	}

	mid := ContinuationFrame{StreamID: 9}
	if mid.Flags() != 0 {
		t.Errorf("Flags = 0x%02x, want 0x00 without END_HEADERS", uint8(mid.Flags()))
	}
	if mid.PayloadLen() != 0 {
		t.Errorf("PayloadLen = %d, want 0", mid.PayloadLen())
	}
}

func TestContinuationByteExact(t *testing.T) {
	f := ContinuationFrame{StreamID: 1, EndHeaders: true, Fragment: []byte{0x88, 0x0f}}
	want := []byte{
		0x00, 0x00, 0x02, // length 2
		0x09,                   // CONTINUATION
		0x04,                   // END_HEADERS
		0x00, 0x00, 0x00, 0x01, // stream 1
		0x88, 0x0f,
	}
	if got := serializeFrame(f); !bytes.Equal(got, want) {
		t.Errorf("wire form\n got % x\nwant % x", got, want)
	}
}

func TestContinuationRoundTrip(t *testing.T) {
	frames := []ContinuationFrame{
		{StreamID: 1},
		{StreamID: 1, EndHeaders: true},
		{StreamID: 1, Fragment: []byte{0x82}},
		{StreamID: 0x7fffffff, EndHeaders: true, Fragment: bytes.Repeat([]byte{0x86}, 600)},
		{StreamID: 3, Fragment: []byte{0x00, 0xff, 0x80}},
	}
	for _, want := range frames {
		wire := serializeFrame(want)
		h := ParseHeader(wire)
		if h.Length != want.PayloadLen() {
			t.Fatalf("header length %d, want %d", h.Length, want.PayloadLen())
		}
		f, err := parseContinuation(h, wire[HeaderLen:])
		wantNoErr(t, err)
		got := f.(ContinuationFrame)
		if got.StreamID != want.StreamID || got.EndHeaders != want.EndHeaders {
			t.Errorf("round trip\n got %+v\nwant %+v", got, want)
		}
		if !bytes.Equal(got.Fragment, want.Fragment) {
			t.Errorf("round trip Fragment\n got % x\nwant % x", got.Fragment, want.Fragment)
		}
	}
}

// TestContinuationFloodIsIndividuallyValid is the shape of CVE-2023-45288 stated
// as a test: a thousand CONTINUATION frames, none of which any per-frame check can
// object to. It exists to make the point that the defence cannot live in this
// file — the parser is doing its job correctly on every one of these frames — and
// to fail loudly if someone later "fixes" the vulnerability by making a lone
// CONTINUATION invalid, which would break every large header block instead.
func TestContinuationFloodIsIndividuallyValid(t *testing.T) {
	const frames = 1000
	total := 0
	for i := 0; i < frames; i++ {
		h := Header{Length: 0, Type: TypeContinuation, StreamID: 1}
		f, err := parseContinuation(h, nil)
		wantNoErr(t, err)
		total += int(f.(ContinuationFrame).PayloadLen())
	}
	if total != 0 {
		t.Fatalf("accumulated %d payload octets from %d empty frames", total, frames)
	}
	// Nine octets each on the wire, no payload, no stream opened, no limit in
	// this package that could see it. internal/limits caps the accumulated block
	// size and the continuation count; the reader applies it.
}
