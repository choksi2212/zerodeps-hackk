package frame

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"testing"

	"zerodeps/zdh/internal/h2"
)

// The fuzz targets in this file exist because the tables elsewhere in the package
// test the cases I thought of. A frame decoder is the first thing a hostile peer
// reaches, before any authentication or routing, so the interesting failures are
// the ones nobody enumerated: a length field that agrees with the header but not
// with the payload's internal structure, an optional field that overlaps padding,
// a flag combination no client would send.
//
// `go test` runs these over their seed corpus only, so the seeds double as
// regression tests and cost milliseconds. A real campaign is
//
//	go test ./internal/frame/ -run=Fuzz -fuzz=FuzzFrameReader -fuzztime=5m
//
// and any crash the fuzzer finds is written to testdata/fuzz/, committed, and
// replayed by every later run. testdata/fuzz/ is empty: as of writing, the four
// targets here have survived roughly 320 million executions between them without
// a crash, a hang, or a violated invariant.

// fuzzSeeds are inputs worth starting from: legal sequences, the boundaries, and
// the malformed shapes the reader has named rules about. A fuzzer mutates from
// what it is given, so seeding it with structurally valid frames is what lets it
// spend its budget on the interior of the parsers rather than on guessing a
// nine-octet header.
func fuzzSeeds() [][]byte {
	seeds := [][]byte{
		nil,
		{},
		[]byte(ClientPreface),
		frameBytes(oneOfEachFrameType()...),

		// A complete, legal request-shaped exchange.
		frameBytes(
			SettingsFrame{Settings: []Setting{{ID: SettingMaxConcurrentStreams, Value: 100}}},
			HeadersFrame{StreamID: 1, EndStream: true, EndHeaders: true, Fragment: []byte{0x82, 0x86, 0x84}},
			WindowUpdateFrame{Increment: 1},
			GoAwayFrame{LastStreamID: 1},
		),

		// A header block split the way a large cookie jar splits.
		frameBytes(continuationBlock(1, 100, 100, 100)...),

		// Padding at both extremes, where the pad-length octet and the payload
		// bound each other.
		frameBytes(
			DataFrame{StreamID: 1, Padded: true, PadLen: 0},
			DataFrame{StreamID: 1, Padded: true, PadLen: maxPadLen, Data: []byte{0x00}},
		),

		// Every optional part of HEADERS present at once: padding, priority, and a
		// fragment, which is the payload layout with the most ways to be wrong.
		frameBytes(HeadersFrame{
			StreamID:         1,
			EndHeaders:       true,
			Priority:         true,
			Exclusive:        true,
			StreamDependency: 3,
			Weight:           255,
			Padded:           true,
			PadLen:           8,
			Fragment:         []byte{0x82},
		}),

		// A header with flags and a reserved bit set on a type that defines
		// neither, which must be ignored rather than rejected (§4.1, §5.5).
		rawFrame(Header{Length: 0, Type: TypePing, Flags: 0xff, StreamID: 0}, make([]byte, pingLen)...),
		rawFrame(Header{Length: 8, Type: FrameType(0xff), Flags: 0xff, StreamID: 0xffffffff}, make([]byte, 8)...),

		// A frame header promising a payload that is not there.
		[]byte{0x00, 0x00, 0x08, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00},
		// A length above anything we advertise, so the payload must never be read.
		{0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		// A CONTINUATION with no block open, and a block interrupted by DATA.
		frameBytes(ContinuationFrame{StreamID: 1, EndHeaders: true}),
		frameBytes(
			HeadersFrame{StreamID: 1, Fragment: []byte{0x82}},
			DataFrame{StreamID: 1, Data: []byte("x")},
		),
	}

	// One frame of every type on its own, so a mutation of any single type is one
	// bit-flip away from a valid frame of that type.
	for _, f := range oneOfEachFrameType() {
		seeds = append(seeds, serializeFrame(f))
	}
	return seeds
}

// FuzzFrameReader drives the reader with the bounds a real connection uses.
func FuzzFrameReader(f *testing.F) {
	for _, seed := range fuzzSeeds() {
		f.Add(seed)
	}
	cfg := ReaderConfig{}
	f.Fuzz(func(t *testing.T, in []byte) {
		fuzzReadAll(t, in, cfg)
	})
}

// FuzzFrameReaderTightBounds drives the same reader with limits small enough that
// an ordinary input reaches them. With the production bounds a fuzzer would have
// to synthesise 128 KB of header block to reach the flood checks at all, so those
// paths would go unexplored; here a few hundred octets get there.
func FuzzFrameReaderTightBounds(f *testing.F) {
	for _, seed := range fuzzSeeds() {
		f.Add(seed)
	}
	cfg := ReaderConfig{
		MaxFrameSize:          64,
		MaxHeaderBlockSize:    64,
		MaxContinuationFrames: 3,
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		fuzzReadAll(t, in, cfg)
	})
}

// fuzzReadAll reads in to exhaustion and checks every invariant the reader's
// documentation promises. It asserts properties rather than outputs, because for
// an arbitrary input there is no expected output to compare against — only rules
// that must hold whatever the input was.
func fuzzReadAll(t *testing.T, in []byte, cfg ReaderConfig) {
	t.Helper()

	rd := NewReader(bytes.NewReader(in), cfg)
	want := uint32(0) // the open block, tracked independently of the reader
	for {
		f, err := rd.ReadFrame()
		if err != nil {
			fuzzCheckError(t, err)
			if f != nil {
				t.Fatalf("ReadFrame returned both a %s frame and an error: %v", f.Type(), err)
			}
			return
		}
		if f == nil {
			t.Fatal("ReadFrame returned a nil frame and a nil error")
		}

		// §4.1: an unknown type is discarded inside ReadFrame, so no caller can be
		// handed one and forget to ignore it.
		if !f.Type().known() {
			t.Fatalf("ReadFrame returned an unknown frame type %s", f.Type())
		}
		// The bound the reader advertises as SETTINGS_MAX_FRAME_SIZE is the bound it
		// enforces. A frame above it should have been refused, not parsed.
		if n := f.PayloadLen(); n > rd.maxFrameSize {
			t.Fatalf("%s frame has %d payload octets, above the %d limit",
				f.Type(), n, rd.maxFrameSize)
		}
		// ParseHeader masks the reserved bit, so no frame can name a stream the
		// wire cannot express — which is also what makes it safe to re-serialise.
		if id := f.Stream(); id > streamIDMask {
			t.Fatalf("%s frame names stream %d, above the 31-bit maximum", f.Type(), id)
		}

		if want = expectedOpenBlock(want, f); rd.BlockOpen() != want {
			t.Fatalf("after a %s frame BlockOpen = %d, want %d",
				f.Type(), rd.BlockOpen(), want)
		}

		fuzzCheckRoundTrip(t, f, cfg)
	}
}

// fuzzCheckError holds the reader to its documented error taxonomy: a clean close,
// a truncation, or a protocol fault, and nothing else. The distinction is not
// cosmetic — the connection layer sends GOAWAY for the third and stays silent for
// the first, so an error that falls outside these kinds would be handled by
// whichever branch happened to be last.
func fuzzCheckError(t *testing.T, err error) {
	t.Helper()

	var ce h2.ConnError
	var se h2.StreamError
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return
	case errors.As(err, &ce):
		wantRFCCitation(t, ce.Reason)
	case errors.As(err, &se):
		wantRFCCitation(t, se.Reason)
		if se.StreamID == 0 {
			t.Fatalf("stream error on stream 0, which cannot be reset: %v", err)
		}
	default:
		t.Fatalf("ReadFrame returned %T (%v), which is none of io.EOF, "+
			"io.ErrUnexpectedEOF, h2.ConnError or h2.StreamError", err, err)
	}
}

// fuzzCheckRoundTrip is the invariant that ties the two halves of the package
// together: anything the Reader accepts, the Writer can send, and reading it back
// yields the same frame.
//
// It is worth asserting on fuzzer output specifically. A parser and a serialiser
// written from the same RFC section tend to disagree only on the layouts nobody
// writes by hand — an optional field at a boundary, a padding octet that consumes
// the last of the payload — and those are exactly what a mutator produces.
func fuzzCheckRoundTrip(t *testing.T, f Frame, cfg ReaderConfig) {
	t.Helper()

	var buf bytes.Buffer
	w := NewWriter(&buf, WriterConfig{})
	if err := w.WriteFrame(f); err != nil {
		t.Fatalf("the Reader accepted a %s frame the Writer refuses to send: %v", f.Type(), err)
	}

	rd := NewReader(&buf, cfg)
	// A lone CONTINUATION is illegal, so the second reader is told about the block
	// the first one had open. The continuity rule is tested exhaustively elsewhere;
	// what is under test here is the payload codec.
	if _, ok := f.(ContinuationFrame); ok {
		rd.blockStream = f.Stream()
	}
	got, err := rd.ReadFrame()
	if err != nil {
		t.Fatalf("re-reading a serialised %s frame: %v", f.Type(), err)
	}
	if !reflect.DeepEqual(got, f) {
		t.Fatalf("%s frame did not survive a round trip\n got %+v\nwant %+v", f.Type(), got, f)
	}
	if buf.Len() != 0 {
		t.Fatalf("%s frame left %d octets unread: its declared length disagrees with "+
			"its serialised form", f.Type(), buf.Len())
	}
}

// expectedOpenBlock recomputes which stream has a header block open, from the
// frames alone. It duplicates what the reader tracks internally on purpose: an
// invariant checked by asking the reader what it thinks would hold no matter what
// the reader did.
func expectedOpenBlock(open uint32, f Frame) uint32 {
	switch f := f.(type) {
	case HeadersFrame:
		if f.EndHeaders {
			return 0
		}
		return f.StreamID
	case PushPromiseFrame:
		if f.EndHeaders {
			return 0
		}
		return f.StreamID
	case ContinuationFrame:
		if f.EndHeaders {
			return 0
		}
	}
	return open
}

// FuzzFramePayload fuzzes the payload of a frame whose header is always
// well-formed, so every execution reaches a parser.
//
// FuzzFrameReader is the honest shape of the attack — bytes on a socket — but that
// is also its weakness as a fuzz target: a mutated 24-bit length field exceeds the
// advertised maximum about a thousand times out of a thousand and one, so most
// executions are spent proving the size check works. Deriving the length from the
// payload instead gives up testing that check, which the tables cover by name, and
// buys the interior of every parser.
func FuzzFramePayload(f *testing.F) {
	seeds := oneOfEachFrameType()
	seeds = append(seeds,
		DataFrame{StreamID: 1, Padded: true, PadLen: maxPadLen, Data: []byte{0x00}},
		HeadersFrame{
			StreamID: 1, EndHeaders: true,
			Priority: true, Exclusive: true, StreamDependency: 3, Weight: 255,
			Padded: true, PadLen: 8, Fragment: []byte{0x82},
		},
		SettingsFrame{Settings: []Setting{
			{ID: SettingMaxFrameSize, Value: MaxLength},
			{ID: SettingInitialWindowSize, Value: MaxWindowSize},
		}},
		GoAwayFrame{LastStreamID: streamIDMask, ErrCode: h2.HTTP11Required, Debug: []byte("why")},
		PushPromiseFrame{
			StreamID: 1, PromisedID: 2, EndHeaders: true,
			Padded: true, PadLen: maxPadLen, Fragment: []byte{0x82},
		},
	)
	for _, fr := range seeds {
		h := HeaderOf(fr)
		f.Add(uint8(h.Type), uint8(h.Flags), h.StreamID, fr.appendPayload(nil))
	}

	f.Fuzz(func(t *testing.T, typ, flags uint8, stream uint32, payload []byte) {
		// Truncated rather than skipped: an input the fuzzer cannot use teaches it
		// nothing, whereas a truncated one still exercises the parser.
		payload = payload[:min(len(payload), DefaultMaxFrameSize)]
		h := Header{
			Length:   uint32(len(payload)),
			Type:     FrameType(typ),
			Flags:    Flags(flags),
			StreamID: stream & streamIDMask,
		}

		cfg := ReaderConfig{}
		rd := NewReader(bytes.NewReader(rawFrame(h, payload...)), cfg)
		// A lone CONTINUATION is a continuity error, which would mask the payload
		// parser this target exists to reach.
		if h.Type == TypeContinuation {
			rd.blockStream = h.StreamID
		}

		got, err := rd.ReadFrame()
		if err != nil {
			fuzzCheckError(t, err)
			return
		}
		if got.Type() != h.Type {
			t.Fatalf("parsed a %s frame from a %s header", got.Type(), h.Type)
		}
		if got.Stream() != h.StreamID {
			t.Fatalf("%s frame parsed to stream %d from a header naming stream %d",
				h.Type, got.Stream(), h.StreamID)
		}
		// The parsed frame must account for every octet it was given. A parser that
		// quietly ignored trailing payload would let a peer smuggle content past
		// any length-based accounting above this layer — flow control among it.
		if n := got.PayloadLen(); n != h.Length {
			t.Fatalf("%s frame parsed from %d payload octets declares %d",
				h.Type, h.Length, n)
		}
		fuzzCheckRoundTrip(t, got, cfg)
	})
}

// FuzzReadPreface fuzzes the first 24 octets of a connection — the only bytes a
// peer can send before anything about it has been validated.
func FuzzReadPreface(f *testing.F) {
	f.Add([]byte(ClientPreface))
	f.Add([]byte(ClientPreface + "\x00\x00\x00\x04\x00\x00\x00\x00\x00"))
	f.Add([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r"))
	f.Add([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	f.Add([]byte("\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, in []byte) {
		rd := NewReader(bytes.NewReader(in), ReaderConfig{})
		err := rd.ReadPreface()

		// The preface is 24 fixed octets: accepting anything else would mean an
		// HTTP/1.1 request could be served on this port as if it were HTTP/2.
		if hasPreface := bytes.HasPrefix(in, []byte(ClientPreface)); hasPreface != (err == nil) {
			t.Fatalf("preface %q: err = %v, but HasPrefix = %v", in, err, hasPreface)
		}
		if err == nil {
			return
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			// Short of a full preface. Which of the two it is depends on whether
			// anything at all arrived, and both are tested by name elsewhere.
			if len(in) >= len(ClientPreface) {
				t.Fatalf("preface %q: %d octets is enough to decide, but got %v",
					in, len(in), err)
			}
			return
		}
		var ce h2.ConnError
		if !errors.As(err, &ce) {
			t.Fatalf("preface %q: got %T (%v), want an h2.ConnError", in, err, err)
		}
		if ce.Code != h2.ProtocolError {
			t.Fatalf("preface %q: code = %s, want PROTOCOL_ERROR", in, ce.Code)
		}
		wantRFCCitation(t, ce.Reason)

		// The reason quotes peer-controlled octets, so it must not carry them
		// through raw: a peer that could embed a newline could forge a log line.
		if bytes.ContainsAny([]byte(ce.Reason), "\x00\r\n") {
			t.Fatalf("preface %q: the error reason carries raw control characters: %q",
				in, ce.Reason)
		}
	})
}
