package frame

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"zerodeps/zdh/internal/h2"
)

// frameBytes concatenates the wire forms of frames, which is what arrives on a
// connection: one unbroken byte stream with no record boundaries in it.
func frameBytes(frames ...Frame) []byte {
	var b []byte
	for _, f := range frames {
		b = append(b, serializeFrame(f)...)
	}
	return b
}

// rawFrame builds a frame from an explicit header and explicit payload octets,
// so a test can send what this package would never serialise — a header whose
// declared length is not backed by the payload that follows, or a frame type
// that does not exist.
func rawFrame(h Header, payload ...byte) []byte {
	return append(h.AppendTo(nil), payload...)
}

func readerOver(b []byte, cfg ReaderConfig) *Reader {
	return NewReader(bytes.NewReader(b), cfg)
}

// countingReader records how many octets were actually taken from the stream, so
// a test can assert that the reader did not read a payload it had already decided
// to reject.
type countingReader struct {
	b []byte
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	if c.n >= len(c.b) {
		return 0, io.EOF
	}
	n := copy(p, c.b[c.n:])
	c.n += n
	return n, nil
}

// dribbleReader delivers one octet per Read. A TCP stream is entitled to do
// exactly this, and an implementation that assumed one Read per frame — or even
// one Read per header — would work against every test in this package that uses a
// bytes.Reader and fail against a real network.
type dribbleReader struct {
	b []byte
	n int
}

func (d *dribbleReader) Read(p []byte) (int, error) {
	if d.n >= len(d.b) {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = d.b[d.n]
	d.n++
	return 1, nil
}

func mustReadFrame(t *testing.T, rd *Reader) Frame {
	t.Helper()
	f, err := rd.ReadFrame()
	wantNoErr(t, err)
	return f
}

// mustReadFrames reads n frames, all of which must succeed.
func mustReadFrames(t *testing.T, rd *Reader, n int) []Frame {
	t.Helper()
	got := make([]Frame, 0, n)
	for i := 0; i < n; i++ {
		f, err := rd.ReadFrame()
		if err != nil {
			t.Fatalf("frame %d of %d: unexpected error: %v", i+1, n, err)
		}
		got = append(got, f)
	}
	return got
}

// --- the connection preface -------------------------------------------------

func TestReadPrefaceValid(t *testing.T) {
	stream := append([]byte(ClientPreface), frameBytes(PingFrame{})...)
	rd := readerOver(stream, ReaderConfig{})
	if err := rd.ReadPreface(); err != nil {
		t.Fatalf("ReadPreface: %v", err)
	}
	// Reading the frame that follows is the only way to prove the preface
	// consumed exactly 24 octets: one too few or too many and the next frame
	// header is garbage.
	if f := mustReadFrame(t, rd); f.Type() != TypePing {
		t.Errorf("frame after the preface is %s, want PING; the preface did not consume "+
			"exactly %d octets", f.Type(), len(ClientPreface))
	}
}

// TestReadPrefaceLength pins the preface to the 24 octets §3.4 specifies. It is
// a magic number in the truest sense: it is only correct by matching the spec.
func TestReadPrefaceLength(t *testing.T) {
	if len(ClientPreface) != 24 {
		t.Errorf("ClientPreface is %d octets, want 24 (RFC 9113 §3.4)", len(ClientPreface))
	}
	if ClientPreface != "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
		t.Errorf("ClientPreface = %q", ClientPreface)
	}
}

// TestReadPrefaceTruncated covers a peer that connects and then goes away. That
// is not a protocol violation to send GOAWAY about — there is nobody to send it
// to — so the I/O error must come back unwrapped rather than dressed up as one.
func TestReadPrefaceTruncated(t *testing.T) {
	t.Run("nothing at all", func(t *testing.T) {
		err := readerOver(nil, ReaderConfig{}).ReadPreface()
		if !errors.Is(err, io.EOF) {
			t.Fatalf("err = %v, want io.EOF", err)
		}
		var ce h2.ConnError
		if errors.As(err, &ce) {
			t.Errorf("a closed connection was reported as the protocol error %s", ce.Code)
		}
	})
	t.Run("half a preface", func(t *testing.T) {
		err := readerOver([]byte(ClientPreface[:12]), ReaderConfig{}).ReadPreface()
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("err = %v, want io.ErrUnexpectedEOF", err)
		}
	})
	t.Run("one octet short", func(t *testing.T) {
		err := readerOver([]byte(ClientPreface[:23]), ReaderConfig{}).ReadPreface()
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("err = %v, want io.ErrUnexpectedEOF", err)
		}
	})
}

// TestReadPrefaceHTTP1 is the case that happens in the field: a browser or a
// curl invocation that reached an h2c port over HTTP/1.1. It is a protocol
// error, but a diagnosable one, and the diagnosis has to be in the message
// because nobody reading the log has the packet capture.
func TestReadPrefaceHTTP1(t *testing.T) {
	for _, method := range http1Methods {
		t.Run(method, func(t *testing.T) {
			req := method + " / HTTP/1.1\r\nHost: example.com\r\n\r\n"
			err := readerOver([]byte(req), ReaderConfig{}).ReadPreface()
			wantConnErr(t, err, h2.ProtocolError)
			var ce h2.ConnError
			if !errors.As(err, &ce) {
				t.Fatalf("err = %T", err)
			}
			if !strings.Contains(ce.Reason, method) {
				t.Errorf("reason %q does not name the method %s", ce.Reason, method)
			}
			if !strings.Contains(ce.Reason, "HTTP/2 only") {
				t.Errorf("reason %q does not say the port speaks HTTP/2 only", ce.Reason)
			}
		})
	}
}

// TestReadPrefaceGarbage covers everything that is not the preface and not
// recognisably HTTP/1.1: a TLS ClientHello sent to the cleartext port, a random
// scanner, a method-like prefix that is not a method.
func TestReadPrefaceGarbage(t *testing.T) {
	cases := []struct {
		name  string
		bytes []byte
	}{
		{"a TLS ClientHello on the cleartext port", append(
			[]byte{0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03},
			bytes.Repeat([]byte{0x5a}, 20)...)},
		{"zeroes", make([]byte, 32)},
		{"the preface with one octet changed", []byte("PRI * HTTP/2.1\r\n\r\nSM\r\n\r\n")},
		{"the preface lowercased", []byte("pri * http/2.0\r\n\r\nsm\r\n\r\n")},
		{"a method-like word that is not a method", []byte("GETTING started with HTTP/1.1\r\n\r\n")},
		{"a bare newline flood", bytes.Repeat([]byte{'\n'}, 30)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := readerOver(tc.bytes, ReaderConfig{}).ReadPreface()
			wantConnErr(t, err, h2.ProtocolError)
		})
	}
}

// TestReadPrefaceQuotesPeerBytes is a log-injection test. The bytes in a failed
// preface are entirely peer-controlled, so if they reached the log raw a peer
// could forge log lines and colour them with terminal escapes. %q is what stops
// that, and this asserts it is still there.
func TestReadPrefaceQuotesPeerBytes(t *testing.T) {
	// Every control octet is inside the first 24, because that is all the reader
	// consumes and all it can therefore report.
	hostile := []byte("\x1b[31mFAKE\r\nERR\x00\x07 padding")
	if len(hostile) != len(ClientPreface) {
		t.Fatalf("test input is %d octets, want %d", len(hostile), len(ClientPreface))
	}
	err := readerOver(hostile, ReaderConfig{}).ReadPreface()
	wantConnErr(t, err, h2.ProtocolError)

	var ce h2.ConnError
	if !errors.As(err, &ce) {
		t.Fatalf("err = %T", err)
	}
	if i := strings.IndexAny(ce.Reason, "\r\n\x1b\x00\x07"); i >= 0 {
		t.Fatalf("reason contains a raw control octet at %d: %q", i, ce.Reason)
	}
	// And the octets are still reported, escaped, rather than dropped: a
	// diagnosis with the evidence removed is not a diagnosis.
	for _, want := range []string{`\x1b`, `\r\n`, `\x00`} {
		if !strings.Contains(ce.Reason, want) {
			t.Errorf("reason %q does not contain the escaped form %s", ce.Reason, want)
		}
	}
}

// --- the parser table -------------------------------------------------------

// TestParsersTableIsTotal is the mechanical check the table exists to make
// possible: every assigned frame type has a parser, and the table has no
// unassigned tail. A switch statement could only be checked by reading it.
func TestParsersTableIsTotal(t *testing.T) {
	if got, want := len(parsers), int(maxDefinedType)+1; got != want {
		t.Fatalf("parsers has %d entries, want %d (one per assigned type)", got, want)
	}
	for typ := FrameType(0); typ <= maxDefinedType; typ++ {
		if parsers[typ] == nil {
			t.Errorf("no parser for %s (0x%02x)", typ, uint8(typ))
		}
	}
}

// --- framing ----------------------------------------------------------------

// TestReadFrameEveryType reads one valid frame of each assigned type from a
// single stream, in an order that satisfies the header-block continuity rule, and
// asserts that all ten were seen. The coverage assertion is what makes it a
// completeness test rather than ten spot checks.
func TestReadFrameEveryType(t *testing.T) {
	frames := []Frame{
		SettingsFrame{Settings: []Setting{{ID: SettingMaxConcurrentStreams, Value: 100}}},
		PingFrame{Data: [pingLen]byte{1, 2, 3, 4, 5, 6, 7, 8}},
		PriorityFrame{StreamID: 1, StreamDependency: 3, Weight: 15},
		RSTStreamFrame{StreamID: 1, ErrCode: h2.Cancel},
		WindowUpdateFrame{Increment: DefaultInitialWindowSize},
		DataFrame{StreamID: 1, Data: []byte("hi")},
		HeadersFrame{StreamID: 1, Fragment: []byte{0x82}},
		ContinuationFrame{StreamID: 1, EndHeaders: true, Fragment: []byte{0x86}},
		PushPromiseFrame{StreamID: 1, PromisedID: 2, EndHeaders: true, Fragment: []byte{0x84}},
		GoAwayFrame{LastStreamID: 1, ErrCode: h2.NoError, Debug: []byte("bye")},
	}
	rd := readerOver(frameBytes(frames...), ReaderConfig{})
	got := mustReadFrames(t, rd, len(frames))

	seen := map[FrameType]bool{}
	for i, f := range got {
		if f.Type() != frames[i].Type() {
			t.Errorf("frame %d is %s, want %s", i, f.Type(), frames[i].Type())
		}
		seen[f.Type()] = true
	}
	for typ := FrameType(0); typ <= maxDefinedType; typ++ {
		if !seen[typ] {
			t.Errorf("%s was never read; this test no longer covers every frame type", typ)
		}
	}
	if _, err := rd.ReadFrame(); !errors.Is(err, io.EOF) {
		t.Errorf("after the last frame: err = %v, want io.EOF", err)
	}
}

// TestReadFrameSurvivesAOneOctetAtATimeStream is the network-reality test. TCP
// does not deliver frames; it delivers octets whenever it likes.
func TestReadFrameSurvivesAOneOctetAtATimeStream(t *testing.T) {
	frames := []Frame{
		SettingsFrame{Settings: []Setting{{ID: SettingMaxFrameSize, Value: DefaultMaxFrameSize}}},
		HeadersFrame{StreamID: 1, Fragment: bytes.Repeat([]byte{0x82}, 300)},
		ContinuationFrame{StreamID: 1, EndHeaders: true, Fragment: []byte{0x86}},
		DataFrame{StreamID: 1, EndStream: true, Data: bytes.Repeat([]byte{0xaa}, 500)},
	}
	stream := append([]byte(ClientPreface), frameBytes(frames...)...)
	rd := NewReader(&dribbleReader{b: stream}, ReaderConfig{})
	if err := rd.ReadPreface(); err != nil {
		t.Fatalf("ReadPreface: %v", err)
	}
	got := mustReadFrames(t, rd, len(frames))
	if n := len(got[1].(HeadersFrame).Fragment); n != 300 {
		t.Errorf("HEADERS fragment is %d octets, want 300", n)
	}
	if n := len(got[3].(DataFrame).Data); n != 500 {
		t.Errorf("DATA body is %d octets, want 500", n)
	}
}

// TestReadFrameCleanCloseIsEOF separates the two ways a connection can end. Only
// one of them warrants a GOAWAY, and telling them apart is the caller's job — so
// the error has to survive errors.Is unmolested.
func TestReadFrameCleanCloseIsEOF(t *testing.T) {
	rd := readerOver(frameBytes(PingFrame{}), ReaderConfig{})
	mustReadFrame(t, rd)

	err := errors.New("placeholder")
	for i := 0; i < 3; i++ {
		// Repeated because a reader that returned EOF once and then something
		// else would break a caller's shutdown loop.
		_, err = rd.ReadFrame()
		if !errors.Is(err, io.EOF) {
			t.Fatalf("read %d after the last frame: err = %v, want io.EOF", i, err)
		}
	}
	var ce h2.ConnError
	if errors.As(err, &ce) {
		t.Errorf("a clean close was reported as the protocol error %s", ce.Code)
	}
}

// TestReadFrameTruncated covers a connection cut mid-frame, which is an I/O
// failure rather than a protocol error however deliberate it was.
//
// The row at exactly HeaderLen is the interesting one: the peer sent a complete
// header promising a payload and then closed. io.ReadFull reports that as a plain
// EOF, and passing it on would tell the caller the connection ended cleanly at a
// frame boundary — which is the one thing it did not do.
func TestReadFrameTruncated(t *testing.T) {
	full := serializeFrame(DataFrame{StreamID: 1, Data: []byte("hello there")})
	for _, n := range []int{1, 4, HeaderLen - 1, HeaderLen, HeaderLen + 1, len(full) - 1} {
		rd := readerOver(full[:n], ReaderConfig{})
		_, err := rd.ReadFrame()
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("%d of %d octets: err = %v, want io.ErrUnexpectedEOF", n, len(full), err)
		}
		if errors.Is(err, io.EOF) {
			t.Errorf("%d of %d octets: a truncated frame reported as a clean close", n, len(full))
		}
	}
}

// TestReadFrameZeroLengthFrameAtEOF is the boundary the check above must not
// overreach into: a frame with no payload is complete as soon as its header is
// read, so the close that follows it really is clean.
func TestReadFrameZeroLengthFrameAtEOF(t *testing.T) {
	rd := readerOver(frameBytes(DataFrame{StreamID: 1, EndStream: true}), ReaderConfig{})
	if f := mustReadFrame(t, rd); f.PayloadLen() != 0 {
		t.Fatalf("PayloadLen = %d, want 0", f.PayloadLen())
	}
	if _, err := rd.ReadFrame(); !errors.Is(err, io.EOF) {
		t.Errorf("err = %v, want io.EOF", err)
	}
}

// --- frame size -------------------------------------------------------------

func TestReadFrameAtTheSizeLimit(t *testing.T) {
	body := bytes.Repeat([]byte{0xaa}, DefaultMaxFrameSize)
	rd := readerOver(frameBytes(DataFrame{StreamID: 1, Data: body}), ReaderConfig{})
	f := mustReadFrame(t, rd)
	if got := f.(DataFrame).Data; !bytes.Equal(got, body) {
		t.Errorf("body is %d octets, want %d", len(got), len(body))
	}
}

// TestReadFrameOversizeIsNotRead is the anti-amplification property. The frame is
// rejected from its header alone, so a peer cannot make us read up to 16 MB of a
// payload we have already decided is illegal — and the assertion is on the octets
// taken from the stream, because that is the resource being defended.
func TestReadFrameOversizeIsNotRead(t *testing.T) {
	h := Header{Length: DefaultMaxFrameSize + 1, Type: TypeData, StreamID: 1}
	// The header is followed by nothing at all: if the reader tried to read the
	// payload it would report an I/O error instead of the protocol error, and this
	// test would fail rather than merely be weaker.
	src := &countingReader{b: rawFrame(h)}
	rd := NewReader(src, ReaderConfig{})

	_, err := rd.ReadFrame()
	wantConnErr(t, err, h2.FrameSizeError)
	if src.n != HeaderLen {
		t.Errorf("read %d octets, want %d: the payload of an oversize frame must not be read",
			src.n, HeaderLen)
	}
}

// TestReadFrameSizeLimitIsConfigured checks the bound is the configured one
// rather than the default, at the boundary in both directions.
func TestReadFrameSizeLimitIsConfigured(t *testing.T) {
	const max = 64
	cfg := ReaderConfig{MaxFrameSize: max}

	ok := DataFrame{StreamID: 1, Data: bytes.Repeat([]byte{0xaa}, max)}
	if f := mustReadFrame(t, readerOver(frameBytes(ok), cfg)); f.PayloadLen() != max {
		t.Errorf("PayloadLen = %d, want %d", f.PayloadLen(), max)
	}

	tooBig := DataFrame{StreamID: 1, Data: bytes.Repeat([]byte{0xaa}, max+1)}
	_, err := readerOver(frameBytes(tooBig), cfg).ReadFrame()
	wantConnErr(t, err, h2.FrameSizeError)
}

// TestReadFrameOversizeAppliesToEveryType records the deliberate choice to
// escalate every oversize frame to the connection. §4.2 would permit answering
// some of them with RST_STREAM; doing so would mean draining the payload to stay
// synchronised, which is the amplification the check exists to refuse. The
// unknown type and the CONTINUATION are the interesting rows: the size check runs
// before the discard path and before the continuity check, so neither can be used
// to smuggle an oversize frame past it.
func TestReadFrameOversizeAppliesToEveryType(t *testing.T) {
	types := []FrameType{
		TypeData, TypeHeaders, TypePriority, TypeRSTStream, TypeSettings,
		TypePushPromise, TypePing, TypeGoAway, TypeWindowUpdate, TypeContinuation,
		0x0a, 0xff,
	}
	for _, typ := range types {
		h := Header{Length: DefaultMaxFrameSize + 1, Type: typ, StreamID: 1}
		src := &countingReader{b: rawFrame(h)}
		_, err := NewReader(src, ReaderConfig{}).ReadFrame()
		wantConnErr(t, err, h2.FrameSizeError)
		if src.n != HeaderLen {
			t.Errorf("%s: read %d octets, want %d", typ, src.n, HeaderLen)
		}
	}
}

// --- unknown frame types ----------------------------------------------------

// TestReadFrameDiscardsUnknownTypes covers §4.1. The payload still has to be
// consumed, and the proof of that is that the following frame parses: one octet
// left behind and the next header would be read from the middle of this payload.
func TestReadFrameDiscardsUnknownTypes(t *testing.T) {
	var stream []byte
	stream = append(stream, rawFrame(
		Header{Length: 4, Type: 0x0a, StreamID: 1}, 0xde, 0xad, 0xbe, 0xef)...)
	stream = append(stream, rawFrame(
		Header{Length: 0, Type: 0xff, Flags: 0xff, StreamID: 0})...)
	stream = append(stream, rawFrame(
		Header{Length: 3, Type: 0x2a, StreamID: 7}, 'x', 'y', 'z')...)
	stream = append(stream, frameBytes(PingFrame{Data: [pingLen]byte{9}})...)

	rd := readerOver(stream, ReaderConfig{})
	f := mustReadFrame(t, rd)
	if f.Type() != TypePing {
		t.Fatalf("ReadFrame returned %s; unknown types must never reach the caller", f.Type())
	}
	if got := f.(PingFrame).Data; got[0] != 9 {
		t.Errorf("PING data = % x; the discarded payloads were not consumed exactly", got)
	}
	if _, err := rd.ReadFrame(); !errors.Is(err, io.EOF) {
		t.Errorf("err = %v, want io.EOF", err)
	}
}

// TestReadFrameUnknownTypeDuringHeaderBlock is why the continuity check runs
// before the discard. An unknown frame between HEADERS and END_HEADERS is exactly
// as fatal as a known one — silently discarding it would let a peer interleave
// anything it liked inside a header block, which is the thing §6.10 exists to
// forbid.
func TestReadFrameUnknownTypeDuringHeaderBlock(t *testing.T) {
	var stream []byte
	stream = append(stream, frameBytes(HeadersFrame{StreamID: 1, Fragment: []byte{0x82}})...)
	stream = append(stream, rawFrame(Header{Length: 1, Type: 0x0a, StreamID: 1}, 0x00)...)

	rd := readerOver(stream, ReaderConfig{})
	mustReadFrame(t, rd)
	_, err := rd.ReadFrame()
	wantConnErr(t, err, h2.ProtocolError)
}

// --- header block continuity (RFC 9113 §6.10) -------------------------------

func TestReadFrameHeaderBlockContinued(t *testing.T) {
	frames := []Frame{
		HeadersFrame{StreamID: 1, Fragment: []byte{0x82}},
		ContinuationFrame{StreamID: 1, Fragment: []byte{0x86}},
		ContinuationFrame{StreamID: 1},
		ContinuationFrame{StreamID: 1, EndHeaders: true, Fragment: []byte{0x84}},
		DataFrame{StreamID: 1, EndStream: true, Data: []byte("body")},
	}
	rd := readerOver(frameBytes(frames...), ReaderConfig{})

	mustReadFrame(t, rd)
	if got := rd.BlockOpen(); got != 1 {
		t.Errorf("BlockOpen = %d after HEADERS without END_HEADERS, want 1", got)
	}
	mustReadFrames(t, rd, 2)
	if got := rd.BlockOpen(); got != 1 {
		t.Errorf("BlockOpen = %d mid-block, want 1", got)
	}
	mustReadFrame(t, rd)
	if got := rd.BlockOpen(); got != 0 {
		t.Errorf("BlockOpen = %d after END_HEADERS, want 0", got)
	}
	// And a frame that is not a CONTINUATION is accepted again once the block has
	// closed, which is the other half of the rule.
	if f := mustReadFrame(t, rd); f.Type() != TypeData {
		t.Errorf("frame after the block is %s, want DATA", f.Type())
	}
}

// TestReadFrameContinuityViolations is h2spec http2/6.10 stated as a table.
// Every row is a connection error of type PROTOCOL_ERROR; the reader is the only
// layer that can see any of them, because each frame in isolation is valid.
func TestReadFrameContinuityViolations(t *testing.T) {
	cases := []struct {
		name   string
		frames []Frame
	}{
		{
			name: "CONTINUATION with no header block open",
			frames: []Frame{
				ContinuationFrame{StreamID: 1, EndHeaders: true, Fragment: []byte{0x82}},
			},
		},
		{
			// h2spec sends this one on stream 0. checkContinuity rejects it for
			// having no block open before parseContinuation ever sees the stream
			// identifier, so the code is the same either way.
			name:   "CONTINUATION on stream 0 with no block open",
			frames: []Frame{ContinuationFrame{StreamID: 0, EndHeaders: true}},
		},
		{
			name: "CONTINUATION after a HEADERS that carried END_HEADERS",
			frames: []Frame{
				HeadersFrame{StreamID: 1, EndHeaders: true, Fragment: []byte{0x82}},
				ContinuationFrame{StreamID: 1, EndHeaders: true, Fragment: []byte{0x86}},
			},
		},
		{
			name: "CONTINUATION after a CONTINUATION that carried END_HEADERS",
			frames: []Frame{
				HeadersFrame{StreamID: 1, Fragment: []byte{0x82}},
				ContinuationFrame{StreamID: 1, EndHeaders: true, Fragment: []byte{0x86}},
				ContinuationFrame{StreamID: 1, EndHeaders: true, Fragment: []byte{0x84}},
			},
		},
		{
			name: "CONTINUATION preceded by DATA",
			frames: []Frame{
				DataFrame{StreamID: 1, Data: []byte("x")},
				ContinuationFrame{StreamID: 1, EndHeaders: true, Fragment: []byte{0x82}},
			},
		},
		{
			name: "CONTINUATION preceded by a complete HEADERS on another stream",
			frames: []Frame{
				HeadersFrame{StreamID: 3, EndHeaders: true, Fragment: []byte{0x82}},
				ContinuationFrame{StreamID: 1, EndHeaders: true, Fragment: []byte{0x86}},
			},
		},
		{
			name: "DATA inside an open block",
			frames: []Frame{
				HeadersFrame{StreamID: 1, Fragment: []byte{0x82}},
				DataFrame{StreamID: 1, Data: []byte("x")},
			},
		},
		{
			// A connection-level frame is no more acceptable inside a block than a
			// stream one: the HPACK decoder needs the block whole and in order, and
			// nothing may come between the pieces.
			name: "SETTINGS inside an open block",
			frames: []Frame{
				HeadersFrame{StreamID: 1, Fragment: []byte{0x82}},
				SettingsFrame{},
			},
		},
		{
			name: "PING inside an open block",
			frames: []Frame{
				HeadersFrame{StreamID: 1, Fragment: []byte{0x82}},
				PingFrame{},
			},
		},
		{
			name: "RST_STREAM inside an open block",
			frames: []Frame{
				HeadersFrame{StreamID: 1, Fragment: []byte{0x82}},
				RSTStreamFrame{StreamID: 1, ErrCode: h2.Cancel},
			},
		},
		{
			name: "a second HEADERS inside an open block",
			frames: []Frame{
				HeadersFrame{StreamID: 1, Fragment: []byte{0x82}},
				HeadersFrame{StreamID: 1, EndHeaders: true, Fragment: []byte{0x86}},
			},
		},
		{
			name: "CONTINUATION on a different stream than the open block",
			frames: []Frame{
				HeadersFrame{StreamID: 1, Fragment: []byte{0x82}},
				ContinuationFrame{StreamID: 3, EndHeaders: true, Fragment: []byte{0x86}},
			},
		},
		{
			name: "CONTINUATION on stream 0 while a block is open on stream 1",
			frames: []Frame{
				HeadersFrame{StreamID: 1, Fragment: []byte{0x82}},
				ContinuationFrame{StreamID: 0, EndHeaders: true},
			},
		},
		{
			name: "PUSH_PROMISE opens a block too",
			frames: []Frame{
				PushPromiseFrame{StreamID: 1, PromisedID: 2, Fragment: []byte{0x82}},
				DataFrame{StreamID: 1, Data: []byte("x")},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rd := readerOver(frameBytes(tc.frames...), ReaderConfig{})
			// Every frame but the last is valid, which is the point: no per-frame
			// check could have caught any of these.
			mustReadFrames(t, rd, len(tc.frames)-1)
			_, err := rd.ReadFrame()
			wantConnErr(t, err, h2.ProtocolError)
		})
	}
}

// TestReadFrameContinuityErrorNamesBothStreams checks the wrong-stream message
// carries the information needed to debug it, since a peer that gets this wrong is
// usually confused about which stream it is on.
func TestReadFrameContinuityErrorNamesBothStreams(t *testing.T) {
	frames := []Frame{
		HeadersFrame{StreamID: 1, Fragment: []byte{0x82}},
		ContinuationFrame{StreamID: 3, EndHeaders: true},
	}
	rd := readerOver(frameBytes(frames...), ReaderConfig{})
	mustReadFrame(t, rd)
	_, err := rd.ReadFrame()
	wantConnErr(t, err, h2.ProtocolError)

	var ce h2.ConnError
	if !errors.As(err, &ce) {
		t.Fatalf("err = %T", err)
	}
	for _, want := range []string{"stream 3", "stream 1"} {
		if !strings.Contains(ce.Reason, want) {
			t.Errorf("reason %q does not mention %s", ce.Reason, want)
		}
	}
}

// TestReadFramePushPromiseBlockContinues is the accepting half of the
// PUSH_PROMISE case: the continuation belongs to the stream the promise arrived
// on, not the stream it promised.
func TestReadFramePushPromiseBlockContinues(t *testing.T) {
	frames := []Frame{
		PushPromiseFrame{StreamID: 1, PromisedID: 2, Fragment: []byte{0x82}},
		ContinuationFrame{StreamID: 1, EndHeaders: true, Fragment: []byte{0x86}},
	}
	rd := readerOver(frameBytes(frames...), ReaderConfig{})
	mustReadFrame(t, rd)
	if got := rd.BlockOpen(); got != 1 {
		t.Errorf("BlockOpen = %d after PUSH_PROMISE without END_HEADERS, want 1", got)
	}
	mustReadFrame(t, rd)
	if got := rd.BlockOpen(); got != 0 {
		t.Errorf("BlockOpen = %d after END_HEADERS, want 0", got)
	}
}

// TestBlockOpenAfterATruncatedBlock records what BlockOpen is for: a connection
// that ended mid-block ended in the middle of something, which is worth saying in
// a log rather than leaving as a silent truncation.
func TestBlockOpenAfterATruncatedBlock(t *testing.T) {
	rd := readerOver(frameBytes(HeadersFrame{StreamID: 5, Fragment: []byte{0x82}}), ReaderConfig{})
	mustReadFrame(t, rd)
	if _, err := rd.ReadFrame(); !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v, want io.EOF", err)
	}
	if got := rd.BlockOpen(); got != 5 {
		t.Errorf("BlockOpen = %d, want 5 after a connection that ended mid-block", got)
	}
}

// --- header block limits (CVE-2023-45288) -----------------------------------

// continuationBlock builds a header block spread over the given fragment sizes:
// the first is the HEADERS frame, the rest are CONTINUATION frames, and only the
// last carries END_HEADERS.
func continuationBlock(stream uint32, sizes ...int) []Frame {
	frames := make([]Frame, 0, len(sizes))
	for i, n := range sizes {
		frag := bytes.Repeat([]byte{0x82}, n)
		end := i == len(sizes)-1
		if i == 0 {
			frames = append(frames, HeadersFrame{StreamID: stream, EndHeaders: end, Fragment: frag})
			continue
		}
		frames = append(frames, ContinuationFrame{StreamID: stream, EndHeaders: end, Fragment: frag})
	}
	return frames
}

func TestReadFrameBlockSizeLimit(t *testing.T) {
	cfg := ReaderConfig{MaxFrameSize: 64, MaxHeaderBlockSize: 128}

	t.Run("exactly at the limit is accepted", func(t *testing.T) {
		frames := continuationBlock(1, 64, 64)
		rd := readerOver(frameBytes(frames...), cfg)
		mustReadFrames(t, rd, len(frames))
		if got := rd.BlockOpen(); got != 0 {
			t.Errorf("BlockOpen = %d, want 0", got)
		}
	})

	t.Run("one octet above the limit is refused", func(t *testing.T) {
		frames := continuationBlock(1, 64, 64, 1)
		rd := readerOver(frameBytes(frames...), cfg)
		mustReadFrames(t, rd, len(frames)-1)
		_, err := rd.ReadFrame()
		wantConnErr(t, err, h2.EnhanceYourCalm)
	})
}

// TestReadFrameBlockLimitCountsTheFrameThatEndsTheBlock is a regression test.
// Clearing the accumulated state on END_HEADERS before applying the bound would
// exempt the closing frame from it entirely: a peer could sit one octet under the
// limit for the whole block and then hand over another frame's worth on the way
// out, and the caller — which was promised a bound — would be handed more than it.
func TestReadFrameBlockLimitCountsTheFrameThatEndsTheBlock(t *testing.T) {
	cfg := ReaderConfig{MaxFrameSize: 64, MaxHeaderBlockSize: 128}
	frames := []Frame{
		HeadersFrame{StreamID: 1, Fragment: bytes.Repeat([]byte{0x82}, 64)},
		ContinuationFrame{StreamID: 1, Fragment: bytes.Repeat([]byte{0x82}, 64)},
		// At the limit exactly, and this one carries END_HEADERS.
		ContinuationFrame{StreamID: 1, EndHeaders: true, Fragment: []byte{0x86}},
	}
	rd := readerOver(frameBytes(frames...), cfg)
	mustReadFrames(t, rd, 2)
	_, err := rd.ReadFrame()
	wantConnErr(t, err, h2.EnhanceYourCalm)
}

// TestReadFrameContinuationCountLimit is the bound the octet limit cannot see: a
// zero-length CONTINUATION is legal, adds nothing to the accumulated block, costs
// nine octets to send, and can be repeated forever. This is the exact shape of
// CVE-2023-45288.
func TestReadFrameContinuationCountLimit(t *testing.T) {
	const max = 4
	cfg := ReaderConfig{MaxContinuationFrames: max}

	build := func(n int) []Frame {
		frames := []Frame{HeadersFrame{StreamID: 1, Fragment: []byte{0x82}}}
		for i := 0; i < n; i++ {
			frames = append(frames, ContinuationFrame{StreamID: 1})
		}
		return frames
	}

	t.Run("at the limit", func(t *testing.T) {
		frames := build(max)
		rd := readerOver(frameBytes(frames...), cfg)
		mustReadFrames(t, rd, len(frames))
	})

	t.Run("one frame above the limit", func(t *testing.T) {
		frames := build(max + 1)
		rd := readerOver(frameBytes(frames...), cfg)
		mustReadFrames(t, rd, len(frames)-1)
		_, err := rd.ReadFrame()
		wantConnErr(t, err, h2.EnhanceYourCalm)
		// The accumulated block never grew past the single octet the HEADERS
		// frame carried, so the octet bound could not have caught this and the
		// frame count is doing real work.
		if rd.blockSize != 1 {
			t.Errorf("blockSize = %d, want 1: the flood carried no octets at all", rd.blockSize)
		}
	})
}

// TestReadFrameBlockLimitsResetBetweenBlocks checks a connection is not charged
// for a block it has already finished. Getting this wrong would cap the number of
// requests a connection could carry, which is a bug that only shows up under
// sustained load.
func TestReadFrameBlockLimitsResetBetweenBlocks(t *testing.T) {
	cfg := ReaderConfig{MaxFrameSize: 64, MaxHeaderBlockSize: 128, MaxContinuationFrames: 2}
	var frames []Frame
	for stream := uint32(1); stream <= 9; stream += 2 {
		frames = append(frames, continuationBlock(stream, 64, 32, 32)...)
	}
	rd := readerOver(frameBytes(frames...), cfg)
	mustReadFrames(t, rd, len(frames))
	if got := rd.BlockOpen(); got != 0 {
		t.Errorf("BlockOpen = %d, want 0", got)
	}
	if rd.blockSize != 0 || rd.continuations != 0 {
		t.Errorf("blockSize = %d, continuations = %d after the last block closed, want 0 and 0",
			rd.blockSize, rd.continuations)
	}
}

// TestReadFrameBlockLimitErrorIsDiagnostic checks the message says which bound
// was crossed and by how much. An operator who has to raise a limit needs to know
// which one, and a peer accused of excessive load deserves the number.
func TestReadFrameBlockLimitErrorIsDiagnostic(t *testing.T) {
	cfg := ReaderConfig{MaxFrameSize: 64, MaxHeaderBlockSize: 128}
	frames := continuationBlock(7, 64, 64, 8)
	rd := readerOver(frameBytes(frames...), cfg)
	mustReadFrames(t, rd, len(frames)-1)
	_, err := rd.ReadFrame()
	wantConnErr(t, err, h2.EnhanceYourCalm)

	var ce h2.ConnError
	if !errors.As(err, &ce) {
		t.Fatalf("err = %T", err)
	}
	for _, want := range []string{"stream 7", "136", "128", "CVE-2023-45288"} {
		if !strings.Contains(ce.Reason, want) {
			t.Errorf("reason %q does not mention %s", ce.Reason, want)
		}
	}
}

// TestReadFrameBlockSizeCannotWrap is the arithmetic guarantee behind the octet
// bound. With the limit set to the largest a uint32 can hold, a same-width
// accumulator would wrap to zero on the frame that crossed it and sail on under
// the limit forever — so the flood is refused rather than silently forgiven, and
// the total at the point of refusal is a number a uint32 could not have held.
func TestReadFrameBlockSizeCannotWrap(t *testing.T) {
	// The frame count is put out of the way so that the bound under test is the
	// only one that can fire.
	cfg := ReaderConfig{
		MaxFrameSize:          1 << 14,
		MaxHeaderBlockSize:    1<<32 - 1,
		MaxContinuationFrames: 1 << 30,
	}
	rd := readerOver(nil, cfg)

	// Drive the accumulator past what a uint32 could hold, one legal frame's worth
	// at a time, through the same path a real block takes.
	rd.blockStream = 1
	const frame = 1 << 14
	var total, err = uint64(0), error(nil)
	for err == nil {
		if total > 1<<32+4*frame {
			t.Fatalf("accumulated %d octets against a %d limit without complaint; "+
				"the counter wrapped", total, cfg.MaxHeaderBlockSize)
		}
		total += frame
		err = rd.extendBlock(frame, false)
	}
	wantConnErr(t, err, h2.EnhanceYourCalm)

	if rd.blockSize != total {
		t.Errorf("blockSize = %d after accumulating %d octets", rd.blockSize, total)
	}
	if total <= 1<<32-1 {
		t.Errorf("refused at %d octets, below the %d limit", total, cfg.MaxHeaderBlockSize)
	}
}

// --- configuration ----------------------------------------------------------

func TestNewReaderDefaults(t *testing.T) {
	rd := NewReader(bytes.NewReader(nil), ReaderConfig{})
	if rd.maxFrameSize != DefaultMaxFrameSize {
		t.Errorf("maxFrameSize = %d, want %d", rd.maxFrameSize, DefaultMaxFrameSize)
	}
	if rd.maxHeaderBlockSize != DefaultMaxHeaderBlockSize {
		t.Errorf("maxHeaderBlockSize = %d, want %d",
			rd.maxHeaderBlockSize, DefaultMaxHeaderBlockSize)
	}
	if rd.maxContinuations != DefaultMaxContinuationFrames {
		t.Errorf("maxContinuations = %d, want %d",
			rd.maxContinuations, DefaultMaxContinuationFrames)
	}
	if len(rd.buf) != DefaultMaxFrameSize {
		t.Errorf("scratch buffer is %d octets, want %d", len(rd.buf), DefaultMaxFrameSize)
	}
	if rd.BlockOpen() != 0 {
		t.Errorf("BlockOpen = %d on a fresh reader, want 0", rd.BlockOpen())
	}
}

// TestNewReaderDefaultsAreConsistent checks the shipped defaults do not need the
// adjustment below: a block limit under the frame size would mean the two numbers
// in the configuration disagreed about what a legal request is.
func TestNewReaderDefaultsAreConsistent(t *testing.T) {
	if DefaultMaxHeaderBlockSize < DefaultMaxFrameSize {
		t.Errorf("DefaultMaxHeaderBlockSize (%d) is below DefaultMaxFrameSize (%d)",
			DefaultMaxHeaderBlockSize, DefaultMaxFrameSize)
	}
}

// TestNewReaderRaisesABlockLimitBelowTheFrameSize checks the invariant that
// makes the block bound safe to apply to a single self-contained HEADERS frame: a
// block limit under the frame size would refuse a header block the peer was
// entitled to send in one frame of the size we advertised.
func TestNewReaderRaisesABlockLimitBelowTheFrameSize(t *testing.T) {
	cfg := ReaderConfig{MaxFrameSize: 1000, MaxHeaderBlockSize: 10}
	rd := readerOver(frameBytes(HeadersFrame{
		StreamID:   1,
		EndHeaders: true,
		Fragment:   bytes.Repeat([]byte{0x82}, 1000),
	}), cfg)
	if rd.maxHeaderBlockSize != 1000 {
		t.Errorf("maxHeaderBlockSize = %d, want it raised to the frame size 1000",
			rd.maxHeaderBlockSize)
	}
	if f := mustReadFrame(t, rd); len(f.(HeadersFrame).Fragment) != 1000 {
		t.Error("a single-frame header block within the advertised frame size was refused")
	}
}

// --- error propagation ------------------------------------------------------

// TestReadFrameConnErrorFromAParser checks a per-frame connection error reaches
// the caller unchanged rather than being reclassified on the way out.
func TestReadFrameConnErrorFromAParser(t *testing.T) {
	src := rawFrame(Header{Length: 3, Type: TypeData, StreamID: 0}, 'a', 'b', 'c')
	_, err := readerOver(src, ReaderConfig{}).ReadFrame()
	wantConnErr(t, err, h2.ProtocolError)
}

// TestReadFrameStreamErrorLeavesTheReaderUsable is the property that makes a
// stream error worth distinguishing at all. A PRIORITY frame that makes a stream
// depend on itself is a stream error: the connection survives, so the reader must
// be positioned exactly after that frame and able to carry on.
func TestReadFrameStreamErrorLeavesTheReaderUsable(t *testing.T) {
	frames := []Frame{
		PriorityFrame{StreamID: 5, StreamDependency: 5, Weight: 15},
		PingFrame{Data: [pingLen]byte{7}},
	}
	rd := readerOver(frameBytes(frames...), ReaderConfig{})

	_, err := rd.ReadFrame()
	wantStreamErr(t, err, 5, h2.ProtocolError)

	f := mustReadFrame(t, rd)
	if f.Type() != TypePing {
		t.Fatalf("frame after a stream error is %s, want PING", f.Type())
	}
	if got := f.(PingFrame).Data; got[0] != 7 {
		t.Errorf("PING data = % x; the rejected frame's payload was not consumed exactly", got)
	}
}

// --- buffer ownership -------------------------------------------------------

// TestReadFrameCopiesRetainedPayloads is the end-to-end proof of the convention
// every parser test asserts locally: one scratch buffer is reused for every frame,
// so a frame handed to a stream goroutine must not be looking at octets the reader
// is about to overwrite. Locally each parser copies; here the reader actually
// reuses the buffer and the earlier frames have to survive it.
func TestReadFrameCopiesRetainedPayloads(t *testing.T) {
	frames := []Frame{
		DataFrame{StreamID: 1, Data: bytes.Repeat([]byte{0xaa}, 200)},
		HeadersFrame{StreamID: 1, EndHeaders: true, Fragment: bytes.Repeat([]byte{0xbb}, 200)},
		GoAwayFrame{LastStreamID: 1, ErrCode: h2.NoError, Debug: bytes.Repeat([]byte{0xcc}, 200)},
		DataFrame{StreamID: 1, Data: bytes.Repeat([]byte{0xdd}, 200)},
	}
	rd := readerOver(frameBytes(frames...), ReaderConfig{})
	got := mustReadFrames(t, rd, len(frames))

	// Read them all first, then check the first ones: by now the buffer has been
	// overwritten three times.
	want := []struct {
		name  string
		bytes []byte
		fill  byte
	}{
		{"DATA body", got[0].(DataFrame).Data, 0xaa},
		{"HEADERS fragment", got[1].(HeadersFrame).Fragment, 0xbb},
		{"GOAWAY debug data", got[2].(GoAwayFrame).Debug, 0xcc},
		{"the last DATA body", got[3].(DataFrame).Data, 0xdd},
	}
	for _, w := range want {
		if len(w.bytes) != 200 {
			t.Errorf("%s is %d octets, want 200", w.name, len(w.bytes))
			continue
		}
		if !bytes.Equal(w.bytes, bytes.Repeat([]byte{w.fill}, 200)) {
			t.Errorf("%s was overwritten by a later frame: % x", w.name, w.bytes[:8])
		}
	}
}

// TestReadFrameReusesOneBuffer is the other half: the copying above is only
// necessary because the buffer really is reused, and if it stopped being reused the
// reason for all that copying would quietly disappear from the code.
func TestReadFrameReusesOneBuffer(t *testing.T) {
	frames := []Frame{
		DataFrame{StreamID: 1, Data: []byte("first")},
		DataFrame{StreamID: 1, Data: []byte("second")},
	}
	rd := readerOver(frameBytes(frames...), ReaderConfig{})
	before := rd.buf
	mustReadFrames(t, rd, len(frames))
	if &before[0] != &rd.buf[0] || len(before) != len(rd.buf) {
		t.Error("the reader allocated a new scratch buffer; the copies in every parser " +
			"exist because it does not")
	}
	if got := string(rd.buf[:6]); got != "second" {
		t.Errorf("buffer holds %q after the second frame, want %q", got, "second")
	}
}
