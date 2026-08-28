package frame

import (
	"errors"
	"strings"
	"testing"

	"zerodeps/zdh/internal/h2"
)

// serializeFrame builds the full wire form of f: the 9-octet header, then the
// payload. The length comes from the frame's own payload via HeaderOf, so a
// frame cannot be serialised with a length that contradicts its contents.
func serializeFrame(f Frame) []byte {
	return f.appendPayload(HeaderOf(f).AppendTo(nil))
}

// wantConnErr asserts that err is a connection error with the given code: the
// caller must send GOAWAY and close the connection.
//
// The negative half matters as much as the positive one. Confusing a connection
// error for a stream error means keeping a connection the protocol requires us
// to close, and h2spec tests that distinction on nearly every malformed frame.
func wantConnErr(t *testing.T, err error, want h2.ErrCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("no error; want connection error %s", want)
	}
	var se h2.StreamError
	if errors.As(err, &se) {
		t.Fatalf("got a stream error on stream %d (%s), want a connection error %s: %v",
			se.StreamID, se.Code, want, err)
	}
	var ce h2.ConnError
	if !errors.As(err, &ce) {
		t.Fatalf("got %T (%v), want a connection error %s", err, err, want)
	}
	if ce.Code != want {
		t.Errorf("connection error code = %s, want %s: %v", ce.Code, want, err)
	}
	wantRFCCitation(t, ce.Reason)
}

// wantStreamErr asserts that err is a stream error on the given stream with the
// given code: the caller sends RST_STREAM and keeps serving the connection.
func wantStreamErr(t *testing.T, err error, wantID uint32, want h2.ErrCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("no error; want stream error %s on stream %d", want, wantID)
	}
	var ce h2.ConnError
	if errors.As(err, &ce) {
		t.Fatalf("got a connection error (%s), want a stream error %s on stream %d: %v",
			ce.Code, want, wantID, err)
	}
	var se h2.StreamError
	if !errors.As(err, &se) {
		t.Fatalf("got %T (%v), want a stream error %s on stream %d", err, err, want, wantID)
	}
	if se.Code != want {
		t.Errorf("stream error code = %s, want %s: %v", se.Code, want, err)
	}
	if se.StreamID != wantID {
		t.Errorf("stream error is on stream %d, want %d: %v", se.StreamID, wantID, err)
	}
	wantRFCCitation(t, se.Reason)
}

// wantRFCCitation enforces the package convention that every protocol error
// names the section that mandates it. A conformance failure should be traceable
// to the rule in one step, and a convention nothing checks decays.
func wantRFCCitation(t *testing.T, reason string) {
	t.Helper()
	if !strings.Contains(reason, "RFC") || !strings.Contains(reason, "§") {
		t.Errorf("error reason %q cites no RFC section", reason)
	}
}

func wantNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
