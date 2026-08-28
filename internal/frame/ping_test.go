package frame

import (
	"bytes"
	"testing"

	"zerodeps/zdh/internal/h2"
)

func TestParsePingValid(t *testing.T) {
	tests := []struct {
		name    string
		flags   Flags
		payload []byte
		wantAck bool
	}{
		{
			name:    "request",
			flags:   0,
			payload: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			wantAck: false,
		},
		{
			name:    "reply",
			flags:   FlagAck,
			payload: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			wantAck: true,
		},
		{
			name:    "all-zero payload is legal opaque data",
			payload: []byte{0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			name:    "all-ones payload is legal opaque data",
			payload: []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		},
		{
			// Only bit 0x1 is defined on PING. Every other flag is undefined and
			// must be ignored rather than rejected (§4.1), so an ACK reply is
			// still recognised when a peer sets noise alongside it.
			name:    "undefined flags are ignored, ACK still recognised",
			flags:   0xff,
			payload: []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe},
			wantAck: true,
		},
		{
			name:    "undefined flags without ACK do not invent one",
			flags:   0xfe,
			payload: []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe},
			wantAck: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := Header{Length: pingLen, Type: TypePing, Flags: tt.flags, StreamID: 0}
			f, err := parsePing(h, tt.payload)
			wantNoErr(t, err)
			got, ok := f.(PingFrame)
			if !ok {
				t.Fatalf("parsePing returned %T, want PingFrame", f)
			}
			if got.Ack != tt.wantAck {
				t.Errorf("Ack = %v, want %v", got.Ack, tt.wantAck)
			}
			if !bytes.Equal(got.Data[:], tt.payload) {
				t.Errorf("Data = % x, want % x", got.Data, tt.payload)
			}
		})
	}
}

// TestParsePingBadLength is matrix row 22. Eight octets exactly: no more, no
// fewer. h2spec sends both a short and a long PING.
func TestParsePingBadLength(t *testing.T) {
	for _, length := range []uint32{0, 1, 6, 7, 9, 16, MaxLength} {
		h := Header{Length: length, Type: TypePing, StreamID: 0}
		_, err := parsePing(h, make([]byte, pingLen))
		wantConnErr(t, err, h2.FrameSizeError)
	}
}

// TestParsePingNonZeroStream is matrix row 23.
func TestParsePingNonZeroStream(t *testing.T) {
	for _, stream := range []uint32{1, 2, 3, 0x7fffffff} {
		h := Header{Length: pingLen, Type: TypePing, StreamID: stream}
		_, err := parsePing(h, make([]byte, pingLen))
		wantConnErr(t, err, h2.ProtocolError)
	}
}

// TestParsePingStreamBeatsBadLength pins the validation order: both rules are
// connection-fatal, but the stream identifier is the more specific diagnosis and
// is what a peer's log should show.
func TestParsePingStreamBeatsBadLength(t *testing.T) {
	h := Header{Length: 7, Type: TypePing, StreamID: 1}
	_, err := parsePing(h, make([]byte, pingLen))
	wantConnErr(t, err, h2.ProtocolError)
}

// TestParsePingUsesOnlyTheFirstEightOctets guards the reader's buffer contract:
// the scratch slice handed to a parser may be longer than the frame, and reading
// past the length would splice the next frame's bytes into this one's payload.
func TestParsePingUsesOnlyTheFirstEightOctets(t *testing.T) {
	payload := []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0xff, 0xff, 0xff, 0xff, // belongs to whatever comes next
	}
	h := Header{Length: pingLen, Type: TypePing, StreamID: 0}
	f, err := parsePing(h, payload)
	wantNoErr(t, err)
	want := [pingLen]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if got := f.(PingFrame).Data; got != want {
		t.Errorf("Data = % x, want % x", got, want)
	}
}

// TestParsePingCopiesItsPayload is the ownership test for the reader boundary.
// payload aliases a scratch buffer that the next frame overwrites; a parser that
// retained the slice instead of copying would see its data mutate underneath it,
// and with a stream goroutine reading it that is a data race the race detector
// would only sometimes catch.
func TestParsePingCopiesItsPayload(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	h := Header{Length: pingLen, Type: TypePing, StreamID: 0}
	f, err := parsePing(h, payload)
	wantNoErr(t, err)

	// Simulate the reader reusing the buffer for the next frame.
	for i := range payload {
		payload[i] = 0xff
	}

	want := [pingLen]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if got := f.(PingFrame).Data; got != want {
		t.Errorf("Data = % x after the source buffer was reused, want % x; "+
			"the payload was aliased rather than copied", got, want)
	}
}

func TestPingFrameShape(t *testing.T) {
	req := PingFrame{Data: [pingLen]byte{1, 2, 3, 4, 5, 6, 7, 8}}
	if req.Type() != TypePing {
		t.Errorf("Type = %s, want PING", req.Type())
	}
	if req.Flags() != 0 {
		t.Errorf("Flags = 0x%02x, want 0x00 for a request", uint8(req.Flags()))
	}
	if req.PayloadLen() != pingLen {
		t.Errorf("PayloadLen = %d, want %d", req.PayloadLen(), pingLen)
	}
	// PING has no StreamID field at all: a PING on a stream cannot be built.
	if req.Stream() != 0 {
		t.Errorf("Stream = %d, want 0", req.Stream())
	}

	ack := PingFrame{Ack: true}
	if ack.Flags() != FlagAck {
		t.Errorf("Flags = 0x%02x for an ack, want 0x%02x", uint8(ack.Flags()), uint8(FlagAck))
	}
	if ack.Stream() != 0 {
		t.Errorf("Stream = %d, want 0", ack.Stream())
	}
}

func TestPingRoundTrip(t *testing.T) {
	frames := []PingFrame{
		{},
		{Ack: true},
		{Data: [pingLen]byte{1, 2, 3, 4, 5, 6, 7, 8}},
		{Ack: true, Data: [pingLen]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
		{Data: [pingLen]byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe}},
	}
	for _, want := range frames {
		wire := serializeFrame(want)
		if len(wire) != HeaderLen+pingLen {
			t.Fatalf("serialised %d octets, want %d", len(wire), HeaderLen+pingLen)
		}
		h := ParseHeader(wire)
		f, err := parsePing(h, wire[HeaderLen:])
		wantNoErr(t, err)
		if got := f.(PingFrame); got != want {
			t.Errorf("round trip\n got %+v\nwant %+v", got, want)
		}
	}
}

// TestPingReplyEchoesData records the shape of the answer required by §6.7: a
// PING without ACK must be answered by a PING with ACK carrying the same eight
// octets. Sending it belongs to the connection loop — a parser that answered
// frames would be writing to the socket from the reader goroutine, and exactly
// one goroutine owns the write half.
func TestPingReplyEchoesData(t *testing.T) {
	req := PingFrame{Data: [pingLen]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}}
	reply := PingFrame{Ack: true, Data: req.Data}

	if !reply.Ack {
		t.Error("reply is not an ack")
	}
	if reply.Data != req.Data {
		t.Errorf("reply data = % x, want % x", reply.Data, req.Data)
	}
	wire := serializeFrame(reply)
	want := []byte{
		0x00, 0x00, 0x08, // length 8
		0x06,                   // PING
		0x01,                   // ACK
		0x00, 0x00, 0x00, 0x00, // stream 0
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	}
	if !bytes.Equal(wire, want) {
		t.Errorf("reply wire form\n got % x\nwant % x", wire, want)
	}
}
