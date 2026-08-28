package h2

import (
	"errors"
	"fmt"
	"testing"
)

// The wire values are load-bearing: a wrong constant sends the peer the wrong
// GOAWAY code and h2spec reports it as a failure with a confusing message. So
// the numbers are asserted against RFC 9113 §7 literally, not derived from iota.
func TestErrCodeWireValues(t *testing.T) {
	want := map[ErrCode]struct {
		code uint32
		name string
	}{
		NoError:            {0x0, "NO_ERROR"},
		ProtocolError:      {0x1, "PROTOCOL_ERROR"},
		InternalError:      {0x2, "INTERNAL_ERROR"},
		FlowControlError:   {0x3, "FLOW_CONTROL_ERROR"},
		SettingsTimeout:    {0x4, "SETTINGS_TIMEOUT"},
		StreamClosed:       {0x5, "STREAM_CLOSED"},
		FrameSizeError:     {0x6, "FRAME_SIZE_ERROR"},
		RefusedStream:      {0x7, "REFUSED_STREAM"},
		Cancel:             {0x8, "CANCEL"},
		CompressionError:   {0x9, "COMPRESSION_ERROR"},
		ConnectError:       {0xa, "CONNECT_ERROR"},
		EnhanceYourCalm:    {0xb, "ENHANCE_YOUR_CALM"},
		InadequateSecurity: {0xc, "INADEQUATE_SECURITY"},
		HTTP11Required:     {0xd, "HTTP_1_1_REQUIRED"},
	}
	if len(want) != len(errCodeNames) {
		t.Fatalf("test covers %d codes but errCodeNames has %d", len(want), len(errCodeNames))
	}
	for code, exp := range want {
		if uint32(code) != exp.code {
			t.Errorf("%s: wire value = 0x%x, want 0x%x", exp.name, uint32(code), exp.code)
		}
		if got := code.String(); got != exp.name {
			t.Errorf("ErrCode(0x%x).String() = %q, want %q", uint32(code), got, exp.name)
		}
	}
}

// RFC 9113 §7: "Unknown or unsupported error codes MUST NOT trigger any special
// behavior. These MAY be treated by an implementation as being equivalent to
// INTERNAL_ERROR." So an unassigned code must still format, never panic, and
// never index past the name table.
func TestErrCodeUnknownDoesNotPanic(t *testing.T) {
	for _, c := range []ErrCode{0xe, 0xff, 0xffff, 1 << 31, ^ErrCode(0)} {
		got := c.String()
		if want := fmt.Sprintf("UNKNOWN_ERROR(0x%x)", uint32(c)); got != want {
			t.Errorf("ErrCode(0x%x).String() = %q, want %q", uint32(c), got, want)
		}
	}
}

func TestConnErrorImplementsError(t *testing.T) {
	var err error = ConnErrorf(ProtocolError, "preface was %q", "GET / HTTP/1.1")
	const want = `http2: connection error: PROTOCOL_ERROR: preface was "GET / HTTP/1.1"`
	if err.Error() != want {
		t.Errorf("Error() = %q, want %q", err.Error(), want)
	}

	// The conn loop recovers the code with errors.As, so a ConnError returned
	// as a plain error must still be recoverable by value.
	var ce ConnError
	if !errors.As(err, &ce) {
		t.Fatal("errors.As did not recover a ConnError")
	}
	if ce.Code != ProtocolError {
		t.Errorf("recovered code = %s, want PROTOCOL_ERROR", ce.Code)
	}

	// A ConnError must never be mistaken for a StreamError: the two demand
	// opposite responses (close the connection vs reset one stream).
	var se StreamError
	if errors.As(err, &se) {
		t.Error("a ConnError was recovered as a StreamError")
	}
}

func TestStreamErrorImplementsError(t *testing.T) {
	var err error = StreamErrorf(3, StreamClosed, "DATA on closed stream")
	const want = "http2: stream error: stream 3: STREAM_CLOSED: DATA on closed stream"
	if err.Error() != want {
		t.Errorf("Error() = %q, want %q", err.Error(), want)
	}

	var se StreamError
	if !errors.As(err, &se) {
		t.Fatal("errors.As did not recover a StreamError")
	}
	if se.StreamID != 3 || se.Code != StreamClosed {
		t.Errorf("recovered = stream %d %s, want stream 3 STREAM_CLOSED", se.StreamID, se.Code)
	}

	var ce ConnError
	if errors.As(err, &ce) {
		t.Error("a StreamError was recovered as a ConnError")
	}
}

// Field's zero value must be usable, and Sensitive must default to false so
// that nothing is accidentally excluded from the dynamic table.
func TestFieldZeroValue(t *testing.T) {
	var f Field
	if f.Name != "" || f.Value != "" || f.Sensitive {
		t.Errorf("zero Field = %+v, want all-empty and not sensitive", f)
	}
}

// codecStub proves the interface is implementable exactly as written, so the
// seam is checked by the compiler in this package rather than discovered to be
// wrong when the real codec lands.
type codecStub struct{}

func (codecStub) Encode([]Field) []byte          { return nil }
func (codecStub) Decode([]byte) ([]Field, error) { return nil, nil }
func (codecStub) SetMaxDynamicTableSize(int)     {}

var _ HeaderCodec = codecStub{}
