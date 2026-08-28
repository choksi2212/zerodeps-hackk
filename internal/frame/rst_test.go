package frame

import (
	"testing"

	"zerodeps/zdh/internal/h2"
)

func TestParseRSTStreamValid(t *testing.T) {
	// Every assigned error code, plus values outside the assigned set. §7
	// requires an unknown code to be treated as INTERNAL_ERROR by the layer
	// acting on the reset — not rejected by the parser, which is why the parser
	// preserves whatever arrived.
	tests := []struct {
		name    string
		payload []byte
		want    h2.ErrCode
	}{
		{"NO_ERROR", []byte{0x00, 0x00, 0x00, 0x00}, h2.NoError},
		{"PROTOCOL_ERROR", []byte{0x00, 0x00, 0x00, 0x01}, h2.ProtocolError},
		{"INTERNAL_ERROR", []byte{0x00, 0x00, 0x00, 0x02}, h2.InternalError},
		{"FLOW_CONTROL_ERROR", []byte{0x00, 0x00, 0x00, 0x03}, h2.FlowControlError},
		{"SETTINGS_TIMEOUT", []byte{0x00, 0x00, 0x00, 0x04}, h2.SettingsTimeout},
		{"STREAM_CLOSED", []byte{0x00, 0x00, 0x00, 0x05}, h2.StreamClosed},
		{"FRAME_SIZE_ERROR", []byte{0x00, 0x00, 0x00, 0x06}, h2.FrameSizeError},
		{"REFUSED_STREAM", []byte{0x00, 0x00, 0x00, 0x07}, h2.RefusedStream},
		{"CANCEL", []byte{0x00, 0x00, 0x00, 0x08}, h2.Cancel},
		{"COMPRESSION_ERROR", []byte{0x00, 0x00, 0x00, 0x09}, h2.CompressionError},
		{"CONNECT_ERROR", []byte{0x00, 0x00, 0x00, 0x0a}, h2.ConnectError},
		{"ENHANCE_YOUR_CALM", []byte{0x00, 0x00, 0x00, 0x0b}, h2.EnhanceYourCalm},
		{"INADEQUATE_SECURITY", []byte{0x00, 0x00, 0x00, 0x0c}, h2.InadequateSecurity},
		{"HTTP_1_1_REQUIRED", []byte{0x00, 0x00, 0x00, 0x0d}, h2.HTTP11Required},
		{"first unassigned code is preserved", []byte{0x00, 0x00, 0x00, 0x0e}, h2.ErrCode(0x0e)},
		{"code is big-endian", []byte{0xde, 0xad, 0xbe, 0xef}, h2.ErrCode(0xdeadbeef)},
		{"maximum code", []byte{0xff, 0xff, 0xff, 0xff}, h2.ErrCode(0xffffffff)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := Header{Length: rstStreamLen, Type: TypeRSTStream, StreamID: 1}
			f, err := parseRSTStream(h, tt.payload)
			wantNoErr(t, err)
			got, ok := f.(RSTStreamFrame)
			if !ok {
				t.Fatalf("parseRSTStream returned %T, want RSTStreamFrame", f)
			}
			if got.ErrCode != tt.want {
				t.Errorf("ErrCode = 0x%x (%s), want 0x%x (%s)",
					uint32(got.ErrCode), got.ErrCode, uint32(tt.want), tt.want)
			}
			if got.StreamID != 1 {
				t.Errorf("StreamID = %d, want 1", got.StreamID)
			}
		})
	}
}

// TestParseRSTStreamStreamZero is matrix row 12.
func TestParseRSTStreamStreamZero(t *testing.T) {
	h := Header{Length: rstStreamLen, Type: TypeRSTStream, StreamID: 0}
	_, err := parseRSTStream(h, []byte{0x00, 0x00, 0x00, 0x08})
	wantConnErr(t, err, h2.ProtocolError)
}

// TestParseRSTStreamBadLength is matrix row 11. Unlike PRIORITY, a wrong
// RST_STREAM length is fatal to the connection.
func TestParseRSTStreamBadLength(t *testing.T) {
	for _, length := range []uint32{0, 1, 3, 5, 8, MaxLength} {
		h := Header{Length: length, Type: TypeRSTStream, StreamID: 1}
		_, err := parseRSTStream(h, make([]byte, rstStreamLen))
		wantConnErr(t, err, h2.FrameSizeError)
	}
}

// TestParseRSTStreamStreamZeroBeatsBadLength pins the validation order: both
// rules are connection-level here, but the stream-identifier rule is the more
// specific diagnosis and is what h2spec expects to see reported.
func TestParseRSTStreamStreamZeroBeatsBadLength(t *testing.T) {
	h := Header{Length: 3, Type: TypeRSTStream, StreamID: 0}
	_, err := parseRSTStream(h, make([]byte, rstStreamLen))
	wantConnErr(t, err, h2.ProtocolError)
}

func TestRSTStreamFrameShape(t *testing.T) {
	f := RSTStreamFrame{StreamID: 9, ErrCode: h2.Cancel}
	if f.Type() != TypeRSTStream {
		t.Errorf("Type = %s, want RST_STREAM", f.Type())
	}
	if f.Flags() != 0 {
		t.Errorf("Flags = 0x%02x, want 0x00; RST_STREAM defines no flags", uint8(f.Flags()))
	}
	if f.Stream() != 9 {
		t.Errorf("Stream = %d, want 9", f.Stream())
	}
	if f.PayloadLen() != rstStreamLen {
		t.Errorf("PayloadLen = %d, want %d", f.PayloadLen(), rstStreamLen)
	}
}

func TestRSTStreamRoundTrip(t *testing.T) {
	frames := []RSTStreamFrame{
		{StreamID: 1, ErrCode: h2.NoError},
		{StreamID: 3, ErrCode: h2.Cancel},
		{StreamID: 0x7fffffff, ErrCode: h2.HTTP11Required},
		{StreamID: 5, ErrCode: h2.ErrCode(0xffffffff)},
	}
	for _, want := range frames {
		wire := serializeFrame(want)
		if len(wire) != HeaderLen+rstStreamLen {
			t.Fatalf("serialised %d octets, want %d", len(wire), HeaderLen+rstStreamLen)
		}
		h := ParseHeader(wire)
		f, err := parseRSTStream(h, wire[HeaderLen:])
		wantNoErr(t, err)
		if got := f.(RSTStreamFrame); got != want {
			t.Errorf("round trip\n got %+v\nwant %+v", got, want)
		}
	}
}
