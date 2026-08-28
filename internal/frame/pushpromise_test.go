package frame

import (
	"bytes"
	"testing"

	"zerodeps/zdh/internal/h2"
)

func TestParsePushPromiseValid(t *testing.T) {
	tests := []struct {
		name    string
		flags   Flags
		stream  uint32
		length  uint32
		payload []byte
		want    PushPromiseFrame
	}{
		{
			name:    "promise with a fragment",
			flags:   FlagEndHeaders,
			stream:  1,
			length:  6,
			payload: []byte{0x00, 0x00, 0x00, 0x02, 0x82, 0x86},
			want: PushPromiseFrame{
				StreamID:   1,
				PromisedID: 2,
				EndHeaders: true,
				Fragment:   []byte{0x82, 0x86},
			},
		},
		{
			// The promised identifier and nothing else: four octets exactly.
			name:    "promise with no fragment",
			flags:   FlagEndHeaders,
			stream:  1,
			length:  promisedIDLen,
			payload: []byte{0x00, 0x00, 0x00, 0x02},
			want: PushPromiseFrame{
				StreamID:   1,
				PromisedID: 2,
				EndHeaders: true,
			},
		},
		{
			// §6.6 reserves the top bit of the promised identifier. Read as part of
			// the number it turns stream 2 into stream 2147483650.
			name:    "reserved bit of the promised identifier is ignored",
			flags:   FlagEndHeaders,
			stream:  1,
			length:  promisedIDLen,
			payload: []byte{0x80, 0x00, 0x00, 0x02},
			want: PushPromiseFrame{
				StreamID:   1,
				PromisedID: 2,
				EndHeaders: true,
			},
		},
		{
			name:    "maximum promised identifier",
			flags:   FlagEndHeaders,
			stream:  1,
			length:  promisedIDLen,
			payload: []byte{0xff, 0xff, 0xff, 0xff},
			want: PushPromiseFrame{
				StreamID:   1,
				PromisedID: 0x7fffffff,
				EndHeaders: true,
			},
		},
		{
			// Without END_HEADERS the block continues in CONTINUATION frames, on
			// the stream the promise arrived on rather than the one promised.
			name:    "fragment continued in CONTINUATION",
			stream:  3,
			length:  5,
			payload: []byte{0x00, 0x00, 0x00, 0x04, 0x82},
			want: PushPromiseFrame{
				StreamID:   3,
				PromisedID: 4,
				Fragment:   []byte{0x82},
			},
		},
		{
			name:    "padded",
			flags:   FlagEndHeaders | FlagPadded,
			stream:  1,
			length:  1 + promisedIDLen + 1 + 2,
			payload: []byte{0x02, 0x00, 0x00, 0x00, 0x06, 0x82, 0x00, 0x00, 0xff},
			want: PushPromiseFrame{
				StreamID:   1,
				PromisedID: 6,
				EndHeaders: true,
				Fragment:   []byte{0x82},
				Padded:     true,
				PadLen:     2,
			},
		},
		{
			// Padded with the padding consuming everything after the promised
			// identifier, so the fragment is empty.
			name:    "padded with an empty fragment",
			flags:   FlagPadded,
			stream:  1,
			length:  1 + promisedIDLen + 3,
			payload: []byte{0x03, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00},
			want: PushPromiseFrame{
				StreamID:   1,
				PromisedID: 8,
				Padded:     true,
				PadLen:     3,
			},
		},
		{
			// PUSH_PROMISE defines only END_HEADERS and PADDED. END_STREAM and
			// PRIORITY are undefined on it and must be ignored (§4.1).
			name:    "undefined flags are ignored",
			flags:   FlagEndHeaders | FlagEndStream | FlagPriority | 0x40,
			stream:  1,
			length:  promisedIDLen,
			payload: []byte{0x00, 0x00, 0x00, 0x02},
			want: PushPromiseFrame{
				StreamID:   1,
				PromisedID: 2,
				EndHeaders: true,
			},
		},
		{
			// An odd promised identifier is illegal — §5.1.1 reserves even
			// identifiers for the server — but that is a judgement about the peer's
			// role and the connection's stream numbering, not about these octets.
			// The connection layer refuses it, along with the whole frame, since a
			// client may not push at all.
			name:    "an odd promised identifier parses and is refused elsewhere",
			flags:   FlagEndHeaders,
			stream:  1,
			length:  promisedIDLen,
			payload: []byte{0x00, 0x00, 0x00, 0x03},
			want: PushPromiseFrame{
				StreamID:   1,
				PromisedID: 3,
				EndHeaders: true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := Header{
				Length:   tt.length,
				Type:     TypePushPromise,
				Flags:    tt.flags,
				StreamID: tt.stream,
			}
			f, err := parsePushPromise(h, tt.payload)
			wantNoErr(t, err)
			got, ok := f.(PushPromiseFrame)
			if !ok {
				t.Fatalf("parsePushPromise returned %T, want PushPromiseFrame", f)
			}
			if got.StreamID != tt.want.StreamID {
				t.Errorf("StreamID = %d, want %d", got.StreamID, tt.want.StreamID)
			}
			if got.PromisedID != tt.want.PromisedID {
				t.Errorf("PromisedID = %d, want %d", got.PromisedID, tt.want.PromisedID)
			}
			if got.EndHeaders != tt.want.EndHeaders {
				t.Errorf("EndHeaders = %v, want %v", got.EndHeaders, tt.want.EndHeaders)
			}
			if got.Padded != tt.want.Padded {
				t.Errorf("Padded = %v, want %v", got.Padded, tt.want.Padded)
			}
			if got.PadLen != tt.want.PadLen {
				t.Errorf("PadLen = %d, want %d", got.PadLen, tt.want.PadLen)
			}
			if !bytes.Equal(got.Fragment, tt.want.Fragment) {
				t.Errorf("Fragment = % x, want % x", got.Fragment, tt.want.Fragment)
			}
		})
	}
}

// TestParsePushPromiseStreamZero is matrix row 21. A promise is made on an
// existing stream; on the connection it has nothing to attach to.
func TestParsePushPromiseStreamZero(t *testing.T) {
	h := Header{Length: promisedIDLen, Type: TypePushPromise, StreamID: 0}
	_, err := parsePushPromise(h, []byte{0x00, 0x00, 0x00, 0x02})
	wantConnErr(t, err, h2.ProtocolError)
}

// TestParsePushPromiseStreamZeroBeatsEverything pins the validation order. The
// second case has no payload, so a parser that read the pad length first would
// index out of range.
func TestParsePushPromiseStreamZeroBeatsEverything(t *testing.T) {
	h := Header{Length: 1, Type: TypePushPromise, Flags: FlagPadded, StreamID: 0}
	_, err := parsePushPromise(h, []byte{0xff})
	wantConnErr(t, err, h2.ProtocolError)

	h = Header{Length: 0, Type: TypePushPromise, Flags: FlagPadded, StreamID: 0}
	_, err = parsePushPromise(h, nil)
	wantConnErr(t, err, h2.ProtocolError)
}

// TestParsePushPromiseShortPayload is matrix row 22 for this frame type: the
// promised identifier is mandatory, so fewer than four octets is a frame size
// error — fatal to the connection, because the header block it carries cannot be
// decoded and the HPACK table would be left desynchronised (§4.2).
func TestParsePushPromiseShortPayload(t *testing.T) {
	for _, length := range []uint32{0, 1, 2, 3} {
		h := Header{Length: length, Type: TypePushPromise, StreamID: 1}
		_, err := parsePushPromise(h, make([]byte, promisedIDLen))
		wantConnErr(t, err, h2.FrameSizeError)
	}
}

// TestParsePushPromiseShortPayloadAfterPadding measures the same rule where it
// has to be measured: a frame long enough overall can still have fewer than four
// octets left once the padding envelope comes off.
func TestParsePushPromiseShortPayloadAfterPadding(t *testing.T) {
	// Eight octets: one pad length, five padding, two left for a field of four.
	payload := []byte{0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	h := Header{
		Length:   uint32(len(payload)),
		Type:     TypePushPromise,
		Flags:    FlagPadded,
		StreamID: 1,
	}
	_, err := parsePushPromise(h, payload)
	wantConnErr(t, err, h2.FrameSizeError)
}

// TestParsePushPromisePaddingBeatsShortPayload pins the order of the two
// envelopes: padding is the outer one, and its length is what says where the
// promised identifier ends.
func TestParsePushPromisePaddingBeatsShortPayload(t *testing.T) {
	h := Header{Length: 2, Type: TypePushPromise, Flags: FlagPadded, StreamID: 1}
	_, err := parsePushPromise(h, []byte{0xff, 0x00})
	wantConnErr(t, err, h2.ProtocolError)
}

// TestParsePushPromiseStreamZeroPromise is the one rule §6.6 states outright
// about the identifier's value: stream 0 is the connection, so promising it is
// not a promise about anything.
func TestParsePushPromiseStreamZeroPromise(t *testing.T) {
	h := Header{Length: promisedIDLen, Type: TypePushPromise, StreamID: 1}
	_, err := parsePushPromise(h, []byte{0x00, 0x00, 0x00, 0x00})
	wantConnErr(t, err, h2.ProtocolError)
}

// TestParsePushPromiseReservedBitOnlyPromisesStreamZero is the adversarial case
// the masking and the zero check combine into: 0x80000000 masks down to zero. A
// parser that skipped the mask would read 2147483648 and accept a promise the
// protocol forbids.
func TestParsePushPromiseReservedBitOnlyPromisesStreamZero(t *testing.T) {
	h := Header{Length: promisedIDLen, Type: TypePushPromise, StreamID: 1}
	_, err := parsePushPromise(h, []byte{0x80, 0x00, 0x00, 0x00})
	wantConnErr(t, err, h2.ProtocolError)
}

// TestParsePushPromiseShortPayloadBeatsZeroPromise pins the last ordering pair:
// with fewer than four octets there is no identifier to judge.
func TestParsePushPromiseShortPayloadBeatsZeroPromise(t *testing.T) {
	h := Header{Length: 3, Type: TypePushPromise, StreamID: 1}
	_, err := parsePushPromise(h, []byte{0x00, 0x00, 0x00, 0x00})
	wantConnErr(t, err, h2.FrameSizeError)
}

func TestParsePushPromiseEmptyFragmentIsNil(t *testing.T) {
	h := Header{Length: promisedIDLen, Type: TypePushPromise, StreamID: 1}
	f, err := parsePushPromise(h, []byte{0x00, 0x00, 0x00, 0x02})
	wantNoErr(t, err)
	if got := f.(PushPromiseFrame).Fragment; got != nil {
		t.Errorf("Fragment = % x (len %d), want nil", got, len(got))
	}
}

// TestParsePushPromiseUsesOnlyTheDeclaredLength guards the reader's buffer
// contract.
func TestParsePushPromiseUsesOnlyTheDeclaredLength(t *testing.T) {
	payload := []byte{0x00, 0x00, 0x00, 0x02, 0x82, 'N', 'O', 'T', 'M', 'I', 'N', 'E'}
	h := Header{Length: 5, Type: TypePushPromise, StreamID: 1}
	f, err := parsePushPromise(h, payload)
	wantNoErr(t, err)
	if got := f.(PushPromiseFrame).Fragment; !bytes.Equal(got, []byte{0x82}) {
		t.Errorf("Fragment = % x, want 82; the parser read past the declared length", got)
	}
}

// TestParsePushPromiseCopiesItsFragment is the ownership test at the reader
// boundary.
func TestParsePushPromiseCopiesItsFragment(t *testing.T) {
	payload := []byte{0x00, 0x00, 0x00, 0x02, 0x82, 0x86}
	h := Header{Length: uint32(len(payload)), Type: TypePushPromise, StreamID: 1}
	f, err := parsePushPromise(h, payload)
	wantNoErr(t, err)

	for i := range payload {
		payload[i] = 0xff
	}

	got := f.(PushPromiseFrame)
	if !bytes.Equal(got.Fragment, []byte{0x82, 0x86}) {
		t.Errorf("Fragment = % x after the source buffer was reused, want 82 86; "+
			"the fragment was aliased rather than copied", got.Fragment)
	}
	if got.PromisedID != 2 {
		t.Errorf("PromisedID = %d, want 2", got.PromisedID)
	}
}

func TestPushPromiseFrameShape(t *testing.T) {
	f := PushPromiseFrame{StreamID: 1, PromisedID: 2, EndHeaders: true, Fragment: []byte{0x82}}
	if f.Type() != TypePushPromise {
		t.Errorf("Type = %s, want PUSH_PROMISE", f.Type())
	}
	if got := f.Flags(); got != FlagEndHeaders {
		t.Errorf("Flags = 0x%02x, want 0x%02x", uint8(got), uint8(FlagEndHeaders))
	}
	if f.Stream() != 1 {
		t.Errorf("Stream = %d, want 1; Stream is the promising stream, not the promised one",
			f.Stream())
	}
	if got, want := f.PayloadLen(), uint32(promisedIDLen+1); got != want {
		t.Errorf("PayloadLen = %d, want %d", got, want)
	}

	padded := PushPromiseFrame{StreamID: 1, PromisedID: 2, Padded: true, PadLen: 3}
	if got, want := padded.Flags(), FlagPadded; got != want {
		t.Errorf("Flags = 0x%02x, want 0x%02x", uint8(got), uint8(want))
	}
	if got, want := padded.PayloadLen(), uint32(1+promisedIDLen+3); got != want {
		t.Errorf("PayloadLen = %d, want %d", got, want)
	}
}

// TestPushPromiseAppendMasksReservedBit asserts we never send the reserved bit
// set, even from a struct whose PromisedID has it (§4.1).
func TestPushPromiseAppendMasksReservedBit(t *testing.T) {
	f := PushPromiseFrame{StreamID: 1, PromisedID: 0xffffffff}
	got := f.appendPayload(nil)
	want := []byte{0x7f, 0xff, 0xff, 0xff}
	if !bytes.Equal(got, want) {
		t.Errorf("appendPayload\n got % x\nwant % x", got, want)
	}
}

// TestPushPromiseDeclaredLengthMatchesWhatIsWritten sweeps the optional parts.
func TestPushPromiseDeclaredLengthMatchesWhatIsWritten(t *testing.T) {
	fragments := [][]byte{nil, {0x82}, bytes.Repeat([]byte{0x86}, 400)}
	for _, frag := range fragments {
		for _, padded := range []bool{false, true} {
			for _, pad := range []uint8{0, 1, maxPadLen} {
				f := PushPromiseFrame{
					StreamID:   1,
					PromisedID: 2,
					Fragment:   frag,
					Padded:     padded,
					PadLen:     pad,
				}
				wire := serializeFrame(f)
				if got, want := len(wire)-HeaderLen, int(f.PayloadLen()); got != want {
					t.Fatalf("frag %d padded=%v pad=%d: wrote %d, declared %d",
						len(frag), padded, pad, got, want)
				}
			}
		}
	}
}

func TestPushPromiseByteExact(t *testing.T) {
	f := PushPromiseFrame{StreamID: 1, PromisedID: 2, EndHeaders: true, Fragment: []byte{0x88}}
	want := []byte{
		0x00, 0x00, 0x05, // length 5: 4 + 1
		0x05,                   // PUSH_PROMISE
		0x04,                   // END_HEADERS
		0x00, 0x00, 0x00, 0x01, // stream 1
		0x00, 0x00, 0x00, 0x02, // promised stream 2
		0x88,
	}
	if got := serializeFrame(f); !bytes.Equal(got, want) {
		t.Errorf("wire form\n got % x\nwant % x", got, want)
	}
}

func TestPushPromiseRoundTrip(t *testing.T) {
	frames := []PushPromiseFrame{
		{StreamID: 1, PromisedID: 2},
		{StreamID: 1, PromisedID: 2, EndHeaders: true, Fragment: []byte{0x82, 0x86}},
		{StreamID: 0x7fffffff, PromisedID: 0x7ffffffe, EndHeaders: true},
		{StreamID: 3, PromisedID: 4, Padded: true, PadLen: maxPadLen, Fragment: []byte{0x82}},
		{StreamID: 3, PromisedID: 4, Padded: true, PadLen: 0},
		{StreamID: 5, PromisedID: 6, EndHeaders: true, Fragment: bytes.Repeat([]byte{0x00}, 300)},
	}
	for _, want := range frames {
		wire := serializeFrame(want)
		h := ParseHeader(wire)
		if h.Length != want.PayloadLen() {
			t.Fatalf("header length %d, want %d", h.Length, want.PayloadLen())
		}
		f, err := parsePushPromise(h, wire[HeaderLen:])
		wantNoErr(t, err)
		got := f.(PushPromiseFrame)
		if got.StreamID != want.StreamID || got.PromisedID != want.PromisedID ||
			got.EndHeaders != want.EndHeaders || got.Padded != want.Padded ||
			got.PadLen != want.PadLen {
			t.Errorf("round trip\n got %+v\nwant %+v", got, want)
		}
		if !bytes.Equal(got.Fragment, want.Fragment) {
			t.Errorf("round trip Fragment\n got % x\nwant % x", got.Fragment, want.Fragment)
		}
	}
}
