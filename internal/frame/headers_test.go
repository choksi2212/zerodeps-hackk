package frame

import (
	"bytes"
	"testing"

	"zerodeps/zdh/internal/h2"
)

func TestParseHeadersValid(t *testing.T) {
	tests := []struct {
		name    string
		flags   Flags
		stream  uint32
		length  uint32
		payload []byte
		want    HeadersFrame
	}{
		{
			name:    "bare fragment",
			flags:   FlagEndHeaders,
			stream:  1,
			length:  3,
			payload: []byte{0x82, 0x86, 0x84},
			want: HeadersFrame{
				StreamID:   1,
				EndHeaders: true,
				Fragment:   []byte{0x82, 0x86, 0x84},
			},
		},
		{
			// Matrix row 5: a HEADERS frame with an empty fragment is
			// structurally legal here. It decodes to no fields, which the HPACK
			// layer will reject for having no pseudo-headers — but that is a
			// judgement about the decoded block, not about the frame.
			name:   "empty fragment",
			flags:  FlagEndHeaders,
			stream: 1,
			length: 0,
			want:   HeadersFrame{StreamID: 1, EndHeaders: true},
		},
		{
			name:    "request with no body",
			flags:   FlagEndHeaders | FlagEndStream,
			stream:  1,
			length:  1,
			payload: []byte{0x82},
			want: HeadersFrame{
				StreamID:   1,
				EndStream:  true,
				EndHeaders: true,
				Fragment:   []byte{0x82},
			},
		},
		{
			// Without END_HEADERS the block continues in CONTINUATION frames. The
			// frame itself is complete and valid; only the reader knows whether
			// the continuation ever arrives.
			name:    "fragment continued in CONTINUATION",
			stream:  1,
			length:  2,
			payload: []byte{0x82, 0x86},
			want: HeadersFrame{
				StreamID:   1,
				EndHeaders: false,
				Fragment:   []byte{0x82, 0x86},
			},
		},
		{
			name:    "with a priority block",
			flags:   FlagEndHeaders | FlagPriority,
			stream:  3,
			length:  7,
			payload: []byte{0x00, 0x00, 0x00, 0x01, 0x0f, 0x82, 0x86},
			want: HeadersFrame{
				StreamID:         3,
				EndHeaders:       true,
				Priority:         true,
				StreamDependency: 1,
				Weight:           0x0f,
				Fragment:         []byte{0x82, 0x86},
			},
		},
		{
			// The exclusive bit shares the first octet of the dependency. Read as
			// part of the number it turns a dependency on stream 1 into one on
			// stream 2147483649.
			name:    "priority block with the exclusive bit set",
			flags:   FlagPriority | FlagEndHeaders,
			stream:  3,
			length:  6,
			payload: []byte{0x80, 0x00, 0x00, 0x01, 0xff, 0x82},
			want: HeadersFrame{
				StreamID:         3,
				EndHeaders:       true,
				Priority:         true,
				Exclusive:        true,
				StreamDependency: 1,
				Weight:           0xff,
				Fragment:         []byte{0x82},
			},
		},
		{
			// The priority block with nothing after it: five octets exactly, and
			// an empty fragment.
			name:    "priority block and no fragment",
			flags:   FlagPriority | FlagEndHeaders,
			stream:  1,
			length:  priorityLen,
			payload: []byte{0x00, 0x00, 0x00, 0x00, 0x00},
			want: HeadersFrame{
				StreamID:   1,
				EndHeaders: true,
				Priority:   true,
			},
		},
		{
			name:    "padded",
			flags:   FlagEndHeaders | FlagPadded,
			stream:  1,
			length:  5,
			payload: []byte{0x02, 0x82, 0x86, 0x00, 0x00, 0xff},
			want: HeadersFrame{
				StreamID:   1,
				EndHeaders: true,
				Fragment:   []byte{0x82, 0x86},
				Padded:     true,
				PadLen:     2,
			},
		},
		{
			// Every optional part at once, which is the layout the RFC diagram
			// shows and the one an implementation is most likely to assemble in
			// the wrong order: pad length, then priority block, then fragment,
			// then padding.
			name:   "padded, prioritised, END_STREAM and END_HEADERS together",
			flags:  FlagPadded | FlagPriority | FlagEndHeaders | FlagEndStream,
			stream: 5,
			length: 1 + priorityLen + 2 + 3,
			payload: []byte{
				0x03,                         // pad length
				0x80, 0x00, 0x00, 0x07, 0x10, // exclusive dependency on stream 7, weight 16
				0x82, 0x86, // fragment
				0x00, 0x00, 0x00, // padding
			},
			want: HeadersFrame{
				StreamID:         5,
				EndStream:        true,
				EndHeaders:       true,
				Priority:         true,
				Exclusive:        true,
				StreamDependency: 7,
				Weight:           0x10,
				Fragment:         []byte{0x82, 0x86},
				Padded:           true,
				PadLen:           3,
			},
		},
		{
			// Padded and prioritised with the padding consuming everything after
			// the priority block, so the fragment is empty. The two envelopes have
			// to be peeled in the right order for this to come out at all.
			name:    "padded and prioritised with an empty fragment",
			flags:   FlagPadded | FlagPriority,
			stream:  1,
			length:  1 + priorityLen + 2,
			payload: []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			want: HeadersFrame{
				StreamID: 1,
				Priority: true,
				Padded:   true,
				PadLen:   2,
			},
		},
		{
			// Only 0x1, 0x4, 0x8 and 0x20 are defined on HEADERS. 0x2, 0x10, 0x40
			// and 0x80 are undefined and must be ignored (§4.1); in particular
			// 0x10 must not be confused with anything, since PRIORITY is 0x20.
			name:    "undefined flags are ignored",
			flags:   FlagEndHeaders | 0x02 | 0x10 | 0x40 | 0x80,
			stream:  1,
			length:  1,
			payload: []byte{0x82},
			want: HeadersFrame{
				StreamID:   1,
				EndHeaders: true,
				Fragment:   []byte{0x82},
			},
		},
		{
			name:    "maximum stream identifier",
			flags:   FlagEndHeaders,
			stream:  0x7fffffff,
			length:  1,
			payload: []byte{0x82},
			want: HeadersFrame{
				StreamID:   0x7fffffff,
				EndHeaders: true,
				Fragment:   []byte{0x82},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := Header{Length: tt.length, Type: TypeHeaders, Flags: tt.flags, StreamID: tt.stream}
			f, err := parseHeaders(h, tt.payload)
			wantNoErr(t, err)
			got, ok := f.(HeadersFrame)
			if !ok {
				t.Fatalf("parseHeaders returned %T, want HeadersFrame", f)
			}
			if got.StreamID != tt.want.StreamID {
				t.Errorf("StreamID = %d, want %d", got.StreamID, tt.want.StreamID)
			}
			if got.EndStream != tt.want.EndStream {
				t.Errorf("EndStream = %v, want %v", got.EndStream, tt.want.EndStream)
			}
			if got.EndHeaders != tt.want.EndHeaders {
				t.Errorf("EndHeaders = %v, want %v", got.EndHeaders, tt.want.EndHeaders)
			}
			if got.Priority != tt.want.Priority {
				t.Errorf("Priority = %v, want %v", got.Priority, tt.want.Priority)
			}
			if got.Exclusive != tt.want.Exclusive {
				t.Errorf("Exclusive = %v, want %v", got.Exclusive, tt.want.Exclusive)
			}
			if got.StreamDependency != tt.want.StreamDependency {
				t.Errorf("StreamDependency = %d, want %d",
					got.StreamDependency, tt.want.StreamDependency)
			}
			if got.Weight != tt.want.Weight {
				t.Errorf("Weight = %d, want %d", got.Weight, tt.want.Weight)
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

// TestParseHeadersStreamZero is matrix row 6.
func TestParseHeadersStreamZero(t *testing.T) {
	h := Header{Length: 1, Type: TypeHeaders, Flags: FlagEndHeaders, StreamID: 0}
	_, err := parseHeaders(h, []byte{0x82})
	wantConnErr(t, err, h2.ProtocolError)
}

// TestParseHeadersStreamZeroBeatsEverything pins the validation order. The
// second case has no payload at all, so a parser that read the pad-length octet
// before checking the stream would index out of range.
func TestParseHeadersStreamZeroBeatsEverything(t *testing.T) {
	h := Header{Length: 1, Type: TypeHeaders, Flags: FlagPadded | FlagPriority, StreamID: 0}
	_, err := parseHeaders(h, []byte{0xff})
	wantConnErr(t, err, h2.ProtocolError)

	h = Header{Length: 0, Type: TypeHeaders, Flags: FlagPadded, StreamID: 0}
	_, err = parseHeaders(h, nil)
	wantConnErr(t, err, h2.ProtocolError)
}

// TestParseHeadersShortPriorityBlock is matrix row 7. A frame size error in
// HEADERS is fatal to the connection, not to the stream: the header block cannot
// be decoded, so the HPACK dynamic table is left desynchronised and every later
// request on the connection would decode to something other than what was sent.
func TestParseHeadersShortPriorityBlock(t *testing.T) {
	for _, length := range []uint32{0, 1, 2, 3, 4} {
		h := Header{Length: length, Type: TypeHeaders, Flags: FlagPriority, StreamID: 1}
		_, err := parseHeaders(h, make([]byte, priorityLen))
		wantConnErr(t, err, h2.FrameSizeError)
	}
}

// TestParseHeadersShortPriorityBlockAfterPadding is the same rule measured after
// the padding envelope comes off, which is where it has to be measured: a frame
// long enough overall can still have fewer than five octets left inside.
func TestParseHeadersShortPriorityBlockAfterPadding(t *testing.T) {
	// Ten octets on the wire, of which one is the pad length and six are padding,
	// leaving three for a block that needs five.
	payload := []byte{0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	h := Header{
		Length:   uint32(len(payload)),
		Type:     TypeHeaders,
		Flags:    FlagPadded | FlagPriority,
		StreamID: 1,
	}
	_, err := parseHeaders(h, payload)
	wantConnErr(t, err, h2.FrameSizeError)
}

// TestParseHeadersPaddingBeatsShortPriorityBlock pins the order of the two
// envelopes. Padding is the outer one, so an impossible pad length is diagnosed
// before the priority block is looked for — and it has to be, because the pad
// length is what says where the block ends.
func TestParseHeadersPaddingBeatsShortPriorityBlock(t *testing.T) {
	h := Header{Length: 3, Type: TypeHeaders, Flags: FlagPadded | FlagPriority, StreamID: 1}
	_, err := parseHeaders(h, []byte{0xff, 0x00, 0x00})
	wantConnErr(t, err, h2.ProtocolError)
}

// TestParseHeadersPaddingErrors is matrix rows 3 and 4 through HEADERS.
func TestParseHeadersPaddingErrors(t *testing.T) {
	t.Run("PADDED with no room for the pad-length octet", func(t *testing.T) {
		h := Header{Length: 0, Type: TypeHeaders, Flags: FlagPadded, StreamID: 1}
		_, err := parseHeaders(h, nil)
		wantConnErr(t, err, h2.FrameSizeError)
	})
	t.Run("padding as long as the payload", func(t *testing.T) {
		h := Header{Length: 4, Type: TypeHeaders, Flags: FlagPadded, StreamID: 1}
		_, err := parseHeaders(h, []byte{0x04, 0x00, 0x00, 0x00})
		wantConnErr(t, err, h2.ProtocolError)
	})
}

// TestParseHeadersSelfDependencyIsDeferred records a rule this layer
// deliberately does not enforce. A priority block that makes a stream depend on
// itself is a stream error under RFC 7540 §5.3.1, and h2spec tests for it — but
// reporting it here would mean returning no frame, and the header block would be
// lost. §5.4.2 requires the HPACK state to be maintained even for a stream that
// is being reset, because the dynamic table is connection-scoped and cannot be
// resynchronised after a block is skipped. So the frame parses, the fragment
// reaches the codec, and internal/stream resets the stream afterwards.
//
// parsePriority does reject it, because a standalone PRIORITY frame carries no
// compression state to preserve. This test exists so the asymmetry is a recorded
// decision rather than something that looks like an oversight.
func TestParseHeadersSelfDependencyIsDeferred(t *testing.T) {
	payload := []byte{0x00, 0x00, 0x00, 0x05, 0x10, 0x82}
	h := Header{
		Length:   uint32(len(payload)),
		Type:     TypeHeaders,
		Flags:    FlagPriority | FlagEndHeaders,
		StreamID: 5,
	}
	f, err := parseHeaders(h, payload)
	wantNoErr(t, err)
	got := f.(HeadersFrame)
	if got.StreamDependency != got.StreamID {
		t.Fatalf("StreamDependency = %d, want %d; the test no longer builds a self-dependency",
			got.StreamDependency, got.StreamID)
	}
	if !bytes.Equal(got.Fragment, []byte{0x82}) {
		t.Errorf("Fragment = % x, want 82; the header block must survive so HPACK "+
			"can stay synchronised", got.Fragment)
	}
}

func TestParseHeadersEmptyFragmentIsNil(t *testing.T) {
	h := Header{Length: 0, Type: TypeHeaders, Flags: FlagEndHeaders, StreamID: 1}
	f, err := parseHeaders(h, nil)
	wantNoErr(t, err)
	if got := f.(HeadersFrame).Fragment; got != nil {
		t.Errorf("Fragment = % x (len %d), want nil", got, len(got))
	}
}

// TestParseHeadersUsesOnlyTheDeclaredLength guards the reader's buffer contract.
// Splicing the next frame's octets onto a header block would not merely corrupt
// one request: HPACK is stateful, so a corrupted block poisons the dynamic table
// for the rest of the connection.
func TestParseHeadersUsesOnlyTheDeclaredLength(t *testing.T) {
	payload := []byte{0x82, 0x86, 'N', 'O', 'T', 'M', 'I', 'N', 'E'}
	h := Header{Length: 2, Type: TypeHeaders, Flags: FlagEndHeaders, StreamID: 1}
	f, err := parseHeaders(h, payload)
	wantNoErr(t, err)
	if got := f.(HeadersFrame).Fragment; !bytes.Equal(got, []byte{0x82, 0x86}) {
		t.Errorf("Fragment = % x, want 82 86; the parser read past the declared length", got)
	}
}

// TestParseHeadersCopiesItsFragment is the ownership test at the reader
// boundary. A fragment is accumulated across several frames, so it outlives the
// buffer it arrived in by construction.
func TestParseHeadersCopiesItsFragment(t *testing.T) {
	payload := []byte{0x03, 0x82, 0x86, 0x84, 0x00, 0x00, 0x00}
	h := Header{
		Length:   uint32(len(payload)),
		Type:     TypeHeaders,
		Flags:    FlagPadded | FlagEndHeaders,
		StreamID: 1,
	}
	f, err := parseHeaders(h, payload)
	wantNoErr(t, err)

	for i := range payload {
		payload[i] = 0xff
	}

	if got := f.(HeadersFrame).Fragment; !bytes.Equal(got, []byte{0x82, 0x86, 0x84}) {
		t.Errorf("Fragment = % x after the source buffer was reused, want 82 86 84; "+
			"the fragment was aliased rather than copied", got)
	}
}

func TestHeadersFrameShape(t *testing.T) {
	f := HeadersFrame{StreamID: 1, EndHeaders: true, Fragment: []byte{0x82}}
	if f.Type() != TypeHeaders {
		t.Errorf("Type = %s, want HEADERS", f.Type())
	}
	if got := f.Flags(); got != FlagEndHeaders {
		t.Errorf("Flags = 0x%02x, want 0x%02x", uint8(got), uint8(FlagEndHeaders))
	}
	if f.Stream() != 1 {
		t.Errorf("Stream = %d, want 1", f.Stream())
	}
	if f.PayloadLen() != 1 {
		t.Errorf("PayloadLen = %d, want 1", f.PayloadLen())
	}

	all := HeadersFrame{
		StreamID:   1,
		EndStream:  true,
		EndHeaders: true,
		Priority:   true,
		Padded:     true,
		PadLen:     4,
		Fragment:   []byte{0x82, 0x86},
	}
	wantFlags := FlagEndStream | FlagEndHeaders | FlagPadded | FlagPriority
	if got := all.Flags(); got != wantFlags {
		t.Errorf("Flags = 0x%02x, want 0x%02x", uint8(got), uint8(wantFlags))
	}
	if got, want := all.PayloadLen(), uint32(1+priorityLen+2+4); got != want {
		t.Errorf("PayloadLen = %d, want %d", got, want)
	}
}

// TestHeadersDeclaredLengthMatchesWhatIsWritten sweeps the whole cross product of
// optional parts. PayloadLen and appendPayload compute the same thing by
// different routes, and if they ever disagreed the header would promise one
// length and the socket carry another — which desynchronises the peer's frame
// stream permanently.
func TestHeadersDeclaredLengthMatchesWhatIsWritten(t *testing.T) {
	fragments := [][]byte{nil, {0x82}, bytes.Repeat([]byte{0x86}, 500)}
	for _, frag := range fragments {
		for _, priority := range []bool{false, true} {
			for _, padded := range []bool{false, true} {
				for _, pad := range []uint8{0, 1, maxPadLen} {
					f := HeadersFrame{
						StreamID:  1,
						Priority:  priority,
						Padded:    padded,
						PadLen:    pad,
						Fragment:  frag,
						Exclusive: true,
						Weight:    200,
					}
					wire := serializeFrame(f)
					if got, want := len(wire)-HeaderLen, int(f.PayloadLen()); got != want {
						t.Fatalf("frag %d priority=%v padded=%v pad=%d: wrote %d, declared %d",
							len(frag), priority, padded, pad, got, want)
					}
				}
			}
		}
	}
}

func TestHeadersByteExact(t *testing.T) {
	f := HeadersFrame{
		StreamID:   1,
		EndStream:  true,
		EndHeaders: true,
		Fragment:   []byte{0x88},
	}
	want := []byte{
		0x00, 0x00, 0x01, // length 1
		0x01,                   // HEADERS
		0x05,                   // END_STREAM | END_HEADERS
		0x00, 0x00, 0x00, 0x01, // stream 1
		0x88,
	}
	if got := serializeFrame(f); !bytes.Equal(got, want) {
		t.Errorf("wire form\n got % x\nwant % x", got, want)
	}

	full := HeadersFrame{
		StreamID:         3,
		EndHeaders:       true,
		Priority:         true,
		Exclusive:        true,
		StreamDependency: 1,
		Weight:           15,
		Fragment:         []byte{0x88},
		Padded:           true,
		PadLen:           2,
	}
	wantFull := []byte{
		0x00, 0x00, 0x09, // length 9: 1 + 5 + 1 + 2
		0x01,                   // HEADERS
		0x2c,                   // END_HEADERS | PADDED | PRIORITY
		0x00, 0x00, 0x00, 0x03, // stream 3
		0x02,                         // pad length
		0x80, 0x00, 0x00, 0x01, 0x0f, // exclusive dependency on stream 1, weight 15
		0x88,       // fragment
		0x00, 0x00, // padding
	}
	if got := serializeFrame(full); !bytes.Equal(got, wantFull) {
		t.Errorf("full wire form\n got % x\nwant % x", got, wantFull)
	}
}

func TestHeadersRoundTrip(t *testing.T) {
	frames := []HeadersFrame{
		{StreamID: 1},
		{StreamID: 1, EndHeaders: true, Fragment: []byte{0x82, 0x86, 0x84}},
		{StreamID: 1, EndStream: true, EndHeaders: true},
		{StreamID: 0x7fffffff, EndHeaders: true, Fragment: bytes.Repeat([]byte{0x00}, 400)},
		{
			StreamID:         3,
			Priority:         true,
			Exclusive:        true,
			StreamDependency: 0x7fffffff,
			Weight:           255,
			Fragment:         []byte{0x82},
		},
		{StreamID: 3, Priority: true, StreamDependency: 0, Weight: 0},
		{StreamID: 5, Padded: true, PadLen: maxPadLen, Fragment: []byte{0x82}},
		{StreamID: 5, Padded: true, PadLen: 0},
		{
			StreamID:         7,
			EndStream:        true,
			EndHeaders:       true,
			Priority:         true,
			Exclusive:        true,
			StreamDependency: 9,
			Weight:           16,
			Padded:           true,
			PadLen:           11,
			Fragment:         []byte{0x82, 0x86, 0x84, 0x41},
		},
	}
	for _, want := range frames {
		wire := serializeFrame(want)
		h := ParseHeader(wire)
		if h.Length != want.PayloadLen() {
			t.Fatalf("header length %d, want %d", h.Length, want.PayloadLen())
		}
		f, err := parseHeaders(h, wire[HeaderLen:])
		wantNoErr(t, err)
		got := f.(HeadersFrame)
		if got.StreamID != want.StreamID || got.EndStream != want.EndStream ||
			got.EndHeaders != want.EndHeaders || got.Priority != want.Priority ||
			got.Exclusive != want.Exclusive || got.StreamDependency != want.StreamDependency ||
			got.Weight != want.Weight || got.Padded != want.Padded || got.PadLen != want.PadLen {
			t.Errorf("round trip\n got %+v\nwant %+v", got, want)
		}
		if !bytes.Equal(got.Fragment, want.Fragment) {
			t.Errorf("round trip Fragment\n got % x\nwant % x", got.Fragment, want.Fragment)
		}
	}
}
