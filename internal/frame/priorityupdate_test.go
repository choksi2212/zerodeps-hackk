package frame

import (
	"bytes"
	"strings"
	"testing"

	"zerodeps/zdh/internal/h2"
)

// priorityUpdatePayload builds a PRIORITY_UPDATE payload: the 31-bit prioritized
// stream identifier, then the priority field value.
//
// id is written unmasked, so a test can set the reserved bit and check that the
// parser ignores it rather than reading it as part of the number.
func priorityUpdatePayload(id uint32, field string) []byte {
	p := []byte{byte(id >> 24), byte(id >> 16), byte(id >> 8), byte(id)}
	return append(p, field...)
}

func TestParsePriorityUpdateValid(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		want    PriorityUpdateFrame
	}{
		{
			name:    "no field value: every parameter takes its default",
			payload: priorityUpdatePayload(1, ""),
			want:    PriorityUpdateFrame{PrioritizedStreamID: 1, Field: ""},
		},
		{
			name:    "the urgency and incremental parameters",
			payload: priorityUpdatePayload(3, "u=2, i"),
			want:    PriorityUpdateFrame{PrioritizedStreamID: 3, Field: "u=2, i"},
		},
		{
			// §4.1 of RFC 9113 requires the reserved bit to be ignored on receipt.
			// A parser that read it as part of the identifier would turn stream 1
			// into stream 2147483649 — and would then never see a prioritized
			// stream identifier of zero, because the top bit would carry it out of
			// range of the one rule that matters.
			name:    "the reserved bit is ignored, not read as part of the identifier",
			payload: priorityUpdatePayload(0x80000001, "u=0"),
			want:    PriorityUpdateFrame{PrioritizedStreamID: 1, Field: "u=0"},
		},
		{
			name:    "the identifier is big-endian across all four octets",
			payload: priorityUpdatePayload(0x01020304, ""),
			want:    PriorityUpdateFrame{PrioritizedStreamID: 0x01020304},
		},
		{
			name:    "the largest stream identifier",
			payload: priorityUpdatePayload(1<<31-1, "u=7, i=?0"),
			want:    PriorityUpdateFrame{PrioritizedStreamID: 1<<31 - 1, Field: "u=7, i=?0"},
		},
		{
			name:    "the largest stream identifier with the reserved bit set too",
			payload: priorityUpdatePayload(0xffffffff, ""),
			want:    PriorityUpdateFrame{PrioritizedStreamID: 1<<31 - 1},
		},
		{
			// The field value is peer-controlled text this layer does not parse, so
			// nothing about its contents can make a frame malformed. A structured
			// field this broken is a matter for whoever reads it; what matters here
			// is that the frame is accepted and the octets survive unaltered, since
			// a parser that sanitised them would be deciding a question §7 leaves
			// to its caller.
			name:    "a field value that is not a structured field at all",
			payload: priorityUpdatePayload(1, "u=\x00\r\n\xff, ((("),
			want:    PriorityUpdateFrame{PrioritizedStreamID: 1, Field: "u=\x00\r\n\xff, ((("},
		},
		{
			name:    "a field value that is one octet long",
			payload: priorityUpdatePayload(1, "i"),
			want:    PriorityUpdateFrame{PrioritizedStreamID: 1, Field: "i"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := Header{
				Length:   uint32(len(tt.payload)),
				Type:     TypePriorityUpdate,
				StreamID: 0,
			}
			f, err := parsePriorityUpdate(h, tt.payload)
			wantNoErr(t, err)
			got, ok := f.(PriorityUpdateFrame)
			if !ok {
				t.Fatalf("parsePriorityUpdate returned %T, want PriorityUpdateFrame", f)
			}
			if got != tt.want {
				t.Errorf("\n got %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

// TestParsePriorityUpdateOnAStream is the rule that inverts the usual one: this
// frame is about a stream but is not sent on one, so a non-zero header stream
// identifier is a connection error.
//
// §7.1 of RFC 9218: "The Stream Identifier field (see Section 5.1.1 of [HTTP/2])
// in the PRIORITY_UPDATE frame header MUST be zero (0x0)."
func TestParsePriorityUpdateOnAStream(t *testing.T) {
	for _, stream := range []uint32{1, 2, 3, 100, 1<<31 - 1} {
		h := Header{Length: 4, Type: TypePriorityUpdate, StreamID: stream}
		_, err := parsePriorityUpdate(h, priorityUpdatePayload(1, ""))
		wantConnErr(t, err, h2.ProtocolError)
	}
}

// TestParsePriorityUpdateShortPayload covers a payload too small to hold the
// identifier the frame is required to carry. RFC 9218 names no error for it, so
// the general rule applies: §4.2 of RFC 9113 makes a frame that cannot contain a
// mandatory field a FRAME_SIZE_ERROR, and this one is at connection scope because
// there is no stream to reset — the frame was supposed to name one and did not.
func TestParsePriorityUpdateShortPayload(t *testing.T) {
	for _, length := range []uint32{0, 1, 2, 3} {
		// A payload long enough that a parser ignoring the length check would read
		// a plausible identifier rather than panic: the failure has to come from
		// the length rule, not from a bounds check that happened to fire.
		_, err := parsePriorityUpdate(
			Header{Length: length, Type: TypePriorityUpdate},
			priorityUpdatePayload(1, "u=3"),
		)
		wantConnErr(t, err, h2.FrameSizeError)
	}
}

// TestParsePriorityUpdatePrioritizedStreamZero is the payload's own rule, and it
// is the opposite of the header's four octets earlier: zero is required there and
// forbidden here.
//
// §7.1 of RFC 9218: "If a PRIORITY_UPDATE frame is received with a prioritized
// stream ID of 0x0, the recipient MUST respond with a connection error of type
// PROTOCOL_ERROR."
func TestParsePriorityUpdatePrioritizedStreamZero(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
	}{
		{"a bare zero", priorityUpdatePayload(0, "")},
		{"zero with a field value", priorityUpdatePayload(0, "u=3, i")},
		{
			// The mask has to be applied before the check, not after. A parser that
			// tested the raw octets would see 0x80000000, decide it was not zero,
			// and hand the connection layer a prioritized stream of zero anyway.
			name:    "zero hidden behind the reserved bit",
			payload: priorityUpdatePayload(0x80000000, "u=0"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := Header{Length: uint32(len(tt.payload)), Type: TypePriorityUpdate}
			_, err := parsePriorityUpdate(h, tt.payload)
			wantConnErr(t, err, h2.ProtocolError)
		})
	}
}

// TestParsePriorityUpdateValidationOrder pins which diagnosis a frame that breaks
// more than one rule is reported as.
//
// Unlike PRIORITY, where the order decides whether the connection survives, all
// three of these rules are connection errors — so nothing about the outcome
// depends on the order and only the message does. That is worth a test anyway: a
// reordering that is harmless today stops being harmless the moment one of these
// rules is given a different scope, and a frame reported as the wrong violation is
// a diagnosis nobody can act on.
func TestParsePriorityUpdateValidationOrder(t *testing.T) {
	tests := []struct {
		name    string
		header  Header
		payload []byte
		code    h2.ErrCode
		says    string
	}{
		{
			name:    "a stream identifier and a short payload: the header wins",
			header:  Header{Length: 2, Type: TypePriorityUpdate, StreamID: 5},
			payload: priorityUpdatePayload(1, ""),
			code:    h2.ProtocolError,
			says:    "on stream 5",
		},
		{
			name:    "a stream identifier and a prioritized zero: the header wins",
			header:  Header{Length: 4, Type: TypePriorityUpdate, StreamID: 5},
			payload: priorityUpdatePayload(0, ""),
			code:    h2.ProtocolError,
			says:    "on stream 5",
		},
		{
			name:    "a short payload and a prioritized zero: the length wins",
			header:  Header{Length: 3, Type: TypePriorityUpdate},
			payload: priorityUpdatePayload(0, ""),
			code:    h2.FrameSizeError,
			says:    "length 3",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parsePriorityUpdate(tt.header, tt.payload)
			wantConnErr(t, err, tt.code)
			if !strings.Contains(err.Error(), tt.says) {
				t.Errorf("error %q does not say %q, so it is reporting a different rule "+
					"than the one this frame is supposed to have broken", err, tt.says)
			}
		})
	}
}

// TestParsePriorityUpdateUsesOnlyTheDeclaredLength guards the reader's buffer
// contract. The scratch slice handed to a parser may be longer than the frame, and
// this frame's field value has no length of its own — it runs to the end of the
// frame, which is exactly the case where reading to the end of the slice instead
// would splice the next frame's octets into it.
func TestParsePriorityUpdateUsesOnlyTheDeclaredLength(t *testing.T) {
	payload := priorityUpdatePayload(7, "u=1")
	declared := uint32(len(payload))
	payload = append(payload, []byte("NOTMINE")...)

	h := Header{Length: declared, Type: TypePriorityUpdate}
	f, err := parsePriorityUpdate(h, payload)
	wantNoErr(t, err)
	if got := f.(PriorityUpdateFrame).Field; got != "u=1" {
		t.Errorf("Field = %q, want %q; the parser read past the declared length", got, "u=1")
	}
}

// TestParsePriorityUpdateCopiesItsFieldValue is the ownership test at the reader
// boundary. payload aliases a buffer the next frame overwrites, so a retained
// reference would see its contents change underneath it.
func TestParsePriorityUpdateCopiesItsFieldValue(t *testing.T) {
	payload := priorityUpdatePayload(9, "u=5, i")
	h := Header{Length: uint32(len(payload)), Type: TypePriorityUpdate}
	f, err := parsePriorityUpdate(h, payload)
	wantNoErr(t, err)

	// Simulate the reader reusing the buffer for the next frame.
	for i := range payload {
		payload[i] = 0xff
	}

	got := f.(PriorityUpdateFrame)
	if got.Field != "u=5, i" {
		t.Errorf("Field = %q after the source buffer was reused, want %q; the payload was "+
			"aliased rather than copied", got.Field, "u=5, i")
	}
	if got.PrioritizedStreamID != 9 {
		t.Errorf("PrioritizedStreamID = %d, want 9", got.PrioritizedStreamID)
	}
}

// TestParsePriorityUpdateLargeFieldValue checks a field value the size of the
// largest frame we accept. The bound comes from the reader's max-frame-size check
// rather than from anything here, so this only asserts that a frame at that bound
// is handled without truncation — a peer is entitled to send one.
func TestParsePriorityUpdateLargeFieldValue(t *testing.T) {
	field := strings.Repeat("a=1, ", (DefaultMaxFrameSize-priorityUpdateFixedLen)/5)
	payload := priorityUpdatePayload(1, field)
	h := Header{Length: uint32(len(payload)), Type: TypePriorityUpdate}
	f, err := parsePriorityUpdate(h, payload)
	wantNoErr(t, err)
	if got := f.(PriorityUpdateFrame).Field; got != field {
		t.Errorf("field value survived as %d octets, want %d", len(got), len(field))
	}
}

func TestPriorityUpdateFrameShape(t *testing.T) {
	f := PriorityUpdateFrame{PrioritizedStreamID: 7, Field: "u=3"}
	if f.Type() != TypePriorityUpdate {
		t.Errorf("Type = %s, want PRIORITY_UPDATE", f.Type())
	}
	// PRIORITY_UPDATE defines no flags. §7.1 calls the field "Unused Flags", so the
	// wire flags are zero whatever a peer sent us.
	if f.Flags() != 0 {
		t.Errorf("Flags = 0x%02x, want 0x00", uint8(f.Flags()))
	}
	// The frame is about stream 7 and is sent on the connection. These are
	// different questions with different answers, and conflating them would credit
	// the priority to the wrong stream — or write the frame onto one, which §7.1
	// forbids.
	if f.Stream() != 0 {
		t.Errorf("Stream = %d, want 0: PRIORITY_UPDATE is sent on the connection", f.Stream())
	}
	if f.PrioritizedStreamID != 7 {
		t.Errorf("PrioritizedStreamID = %d, want 7", f.PrioritizedStreamID)
	}
	if got, want := f.PayloadLen(), uint32(priorityUpdateFixedLen+3); got != want {
		t.Errorf("PayloadLen = %d, want %d", got, want)
	}
	if got := (PriorityUpdateFrame{PrioritizedStreamID: 1}).PayloadLen(); got != priorityUpdateFixedLen {
		t.Errorf("PayloadLen with no field value = %d, want %d", got, priorityUpdateFixedLen)
	}
}

// TestPriorityUpdateSerialisesTheReservedBitAsZero is §4.1 of RFC 9113 from the
// sending side. Nothing in this server sets the top bit of the identifier, but a
// frame built with a full 32-bit value must not put it on the wire — the peer
// would mask it off and read a different stream than the one we named.
func TestPriorityUpdateSerialisesTheReservedBitAsZero(t *testing.T) {
	wire := serializeFrame(PriorityUpdateFrame{PrioritizedStreamID: 0xffffffff})
	if got := wire[HeaderLen]; got&0x80 != 0 {
		t.Errorf("the first payload octet is 0x%02x; the reserved bit must be sent as zero", got)
	}
	if !bytes.Equal(wire[HeaderLen:], []byte{0x7f, 0xff, 0xff, 0xff}) {
		t.Errorf("payload = % x, want 7f ff ff ff", wire[HeaderLen:])
	}
}

func TestPriorityUpdateRoundTrip(t *testing.T) {
	frames := []PriorityUpdateFrame{
		{PrioritizedStreamID: 1},
		{PrioritizedStreamID: 1, Field: "u=0"},
		{PrioritizedStreamID: 3, Field: "u=5, i"},
		{PrioritizedStreamID: 1<<31 - 1, Field: "u=7, i=?0, unknown=(1 2 3)"},
		{PrioritizedStreamID: 0x01020304, Field: strings.Repeat("x", 1000)},
		// Not a structured field, and not this layer's problem: the round trip has
		// to survive octets nobody can parse, because the frame layer is the part
		// that must not decide what they mean.
		{PrioritizedStreamID: 5, Field: "\x00\x01\x02 \xff"},
	}
	for _, want := range frames {
		wire := serializeFrame(want)
		if got, want := len(wire), HeaderLen+int(want.PayloadLen()); got != want {
			t.Fatalf("serialised %d octets, want %d", got, want)
		}
		h := ParseHeader(wire)
		if h.Type != TypePriorityUpdate {
			t.Fatalf("header type = %s, want PRIORITY_UPDATE", h.Type)
		}
		if h.StreamID != 0 {
			t.Fatalf("header names stream %d, want 0 (RFC 9218 §7.1)", h.StreamID)
		}
		if h.Length != want.PayloadLen() {
			t.Fatalf("header length = %d, want %d", h.Length, want.PayloadLen())
		}
		f, err := parsePriorityUpdate(h, wire[HeaderLen:])
		wantNoErr(t, err)
		if got := f.(PriorityUpdateFrame); got != want {
			t.Errorf("round trip\n got %+v\nwant %+v", got, want)
		}
	}
}

// TestReadPriorityUpdateThroughTheReader is the end-to-end path: a PRIORITY_UPDATE
// on the wire between two frames, read by a Reader. It is here because the frame
// occupies a type outside RFC 9113's range, and the thing most likely to go wrong
// with it is not the parser but the dispatch — a hole in the tables one index away
// would have this frame discarded as unknown, silently, with the connection still
// working and the priority signal simply gone.
func TestReadPriorityUpdateThroughTheReader(t *testing.T) {
	sent := []Frame{
		SettingsFrame{Settings: []Setting{{ID: SettingNoRFC7540Priorities, Value: 1}}},
		PriorityUpdateFrame{PrioritizedStreamID: 1, Field: "u=1, i"},
		PingFrame{Data: [pingLen]byte{9}},
	}
	rd := readerOver(frameBytes(sent...), ReaderConfig{})
	got := mustReadFrames(t, rd, len(sent))

	pu, ok := got[1].(PriorityUpdateFrame)
	if !ok {
		t.Fatalf("the second frame read is a %T (%s), want a PriorityUpdateFrame; a frame "+
			"type missing from the reader's tables is discarded rather than refused",
			got[1], got[1].Type())
	}
	if pu.PrioritizedStreamID != 1 || pu.Field != "u=1, i" {
		t.Errorf("read %+v, want {PrioritizedStreamID:1 Field:%q}", pu, "u=1, i")
	}
}

// TestUnimplementedFrameTypesInTheHoleAreDiscarded is the other side of that
// dispatch. The types between CONTINUATION and PRIORITY_UPDATE index inside both
// tables and are implemented by neither, so they must be discarded like any
// unknown type — and the payload consumed with them, or the connection loses frame
// synchronisation and every later frame is read from the middle of this one.
func TestUnimplementedFrameTypesInTheHoleAreDiscarded(t *testing.T) {
	for typ := TypeContinuation + 1; typ < TypePriorityUpdate; typ++ {
		if typ.known() {
			t.Fatalf("FrameType(0x%x).known() = true; this test assumes it is unimplemented",
				uint8(typ))
		}
		junk := Header{Length: 6, Type: typ, StreamID: 1}
		wire := append(rawFrame(junk, 1, 2, 3, 4, 5, 6), serializeFrame(PingFrame{})...)

		rd := readerOver(wire, ReaderConfig{})
		f, err := rd.ReadFrame()
		wantNoErr(t, err)
		if f.Type() != TypePing {
			t.Errorf("after a 0x%x frame the reader returned a %s, want the PING that "+
				"followed it", uint8(typ), f.Type())
		}
	}
}
