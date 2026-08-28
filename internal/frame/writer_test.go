package frame

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"testing"

	"zerodeps/zdh/internal/h2"
)

// recordingWriter captures every Write call separately, so a test can assert not
// only what was written but how many syscalls it would have taken.
type recordingWriter struct {
	writes [][]byte
	err    error
	short  bool
}

func (r *recordingWriter) Write(p []byte) (int, error) {
	r.writes = append(r.writes, append([]byte(nil), p...))
	if r.err != nil {
		return 0, r.err
	}
	if r.short && len(p) > 0 {
		// A contract violation: fewer octets than asked for, and no error to say
		// so. io.Writer forbids it; a buggy wrapper could still do it.
		return len(p) - 1, nil
	}
	return len(p), nil
}

func (r *recordingWriter) all() []byte {
	var b []byte
	for _, w := range r.writes {
		b = append(b, w...)
	}
	return b
}

// --- queueing and flushing --------------------------------------------------

// TestWriterQueueDoesNotWrite is the property the two-method split exists for: a
// burst of frames costs no syscalls until it is flushed.
func TestWriterQueueDoesNotWrite(t *testing.T) {
	rec := &recordingWriter{}
	w := NewWriter(rec, WriterConfig{})

	frames := []Frame{
		HeadersFrame{StreamID: 1, EndHeaders: true, Fragment: []byte{0x82}},
		DataFrame{StreamID: 1, Data: []byte("hello")},
		DataFrame{StreamID: 1, EndStream: true},
	}
	want := 0
	for _, f := range frames {
		if err := w.Queue(f); err != nil {
			t.Fatalf("Queue(%s): %v", f.Type(), err)
		}
		want += HeaderLen + int(f.PayloadLen())
		if got := w.Buffered(); got != want {
			t.Errorf("Buffered = %d after queueing %s, want %d", got, f.Type(), want)
		}
	}
	if len(rec.writes) != 0 {
		t.Errorf("Queue performed %d writes, want 0", len(rec.writes))
	}

	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if len(rec.writes) != 1 {
		t.Errorf("Flush performed %d writes, want 1: a burst must cost one syscall",
			len(rec.writes))
	}
	if got, want := rec.all(), frameBytes(frames...); !bytes.Equal(got, want) {
		t.Errorf("wrote\n got % x\nwant % x", got, want)
	}
	if got := w.Buffered(); got != 0 {
		t.Errorf("Buffered = %d after Flush, want 0", got)
	}
}

// TestWriterFlushEmptyIsANoOp keeps an idle writer loop from generating empty
// writes, which on a TLS connection would each become a record.
func TestWriterFlushEmptyIsANoOp(t *testing.T) {
	rec := &recordingWriter{}
	w := NewWriter(rec, WriterConfig{})
	for i := 0; i < 3; i++ {
		if err := w.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
	}
	if len(rec.writes) != 0 {
		t.Errorf("performed %d writes with nothing queued, want 0", len(rec.writes))
	}
}

// TestWriterWriteFrameFlushesEachFrame covers the other half of the split: a
// frame that must reach the peer now gets its own write.
func TestWriterWriteFrameFlushesEachFrame(t *testing.T) {
	rec := &recordingWriter{}
	w := NewWriter(rec, WriterConfig{})

	frames := []Frame{
		SettingsFrame{Ack: true},
		PingFrame{Ack: true, Data: [pingLen]byte{1}},
	}
	for _, f := range frames {
		if err := w.WriteFrame(f); err != nil {
			t.Fatalf("WriteFrame(%s): %v", f.Type(), err)
		}
	}
	if len(rec.writes) != len(frames) {
		t.Errorf("performed %d writes for %d frames, want one each",
			len(rec.writes), len(frames))
	}
	if got, want := rec.all(), frameBytes(frames...); !bytes.Equal(got, want) {
		t.Errorf("wrote\n got % x\nwant % x", got, want)
	}
	if got := w.Buffered(); got != 0 {
		t.Errorf("Buffered = %d, want 0", got)
	}
}

func TestWriterByteExact(t *testing.T) {
	rec := &recordingWriter{}
	w := NewWriter(rec, WriterConfig{})
	if err := w.WriteFrame(SettingsFrame{Ack: true}); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	want := []byte{
		0x00, 0x00, 0x00, // length 0
		0x04,                   // SETTINGS
		0x01,                   // ACK
		0x00, 0x00, 0x00, 0x00, // stream 0
	}
	if got := rec.all(); !bytes.Equal(got, want) {
		t.Errorf("wrote\n got % x\nwant % x", got, want)
	}
}

// --- the peer's frame size --------------------------------------------------

// TestWriterInitialMaxFrameSize pins the figure we are entitled to assume before
// the peer's SETTINGS arrive (§6.5.2).
func TestWriterInitialMaxFrameSize(t *testing.T) {
	w := NewWriter(&recordingWriter{}, WriterConfig{})
	if got := w.MaxFrameSize(); got != DefaultMaxFrameSize {
		t.Errorf("MaxFrameSize = %d on a fresh writer, want %d (RFC 9113 §6.5.2)",
			got, DefaultMaxFrameSize)
	}
}

// TestWriterRefusesAnOversizeFrame checks the refusal and, more importantly, that
// it leaves nothing behind. A rejected frame that had already appended its header
// would corrupt the next flush.
func TestWriterRefusesAnOversizeFrame(t *testing.T) {
	rec := &recordingWriter{}
	w := NewWriter(rec, WriterConfig{})

	keep := DataFrame{StreamID: 1, Data: []byte("keep me")}
	if err := w.Queue(keep); err != nil {
		t.Fatalf("Queue: %v", err)
	}
	before := w.Buffered()

	tooBig := DataFrame{StreamID: 1, Data: bytes.Repeat([]byte{0xaa}, DefaultMaxFrameSize+1)}
	err := w.Queue(tooBig)
	wantConnErr(t, err, h2.InternalError)
	if got := w.Buffered(); got != before {
		t.Errorf("Buffered = %d after a refused frame, want %d: a rejected frame must "+
			"leave nothing in the queue", got, before)
	}

	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if got, want := rec.all(), serializeFrame(keep); !bytes.Equal(got, want) {
		t.Errorf("wrote\n got % x\nwant % x", got, want)
	}
}

// TestWriterHonoursThePeersMaxFrameSize checks the bound moves when the peer says
// it may, at the boundary in both directions.
func TestWriterHonoursThePeersMaxFrameSize(t *testing.T) {
	const raised = 1 << 15
	w := NewWriter(&recordingWriter{}, WriterConfig{})

	big := DataFrame{StreamID: 1, Data: bytes.Repeat([]byte{0xaa}, raised)}
	wantConnErr(t, w.Queue(big), h2.InternalError)

	w.SetMaxFrameSize(raised)
	if got := w.MaxFrameSize(); got != raised {
		t.Fatalf("MaxFrameSize = %d, want %d", got, raised)
	}
	if err := w.Queue(big); err != nil {
		t.Errorf("Queue after the peer raised its limit: %v", err)
	}
	tooBig := DataFrame{StreamID: 1, Data: bytes.Repeat([]byte{0xaa}, raised+1)}
	wantConnErr(t, w.Queue(tooBig), h2.InternalError)
}

// TestWriterMaxFrameSizeIsClamped covers the values §6.5.2 makes impossible. They
// can only arrive from a bug on our side, and the clamp is what keeps such a bug
// from wedging the connection: honouring a limit of 1 would make every frame
// unsendable, and honouring one above 2^24-1 would overflow the header's 24-bit
// length field silently.
func TestWriterMaxFrameSizeIsClamped(t *testing.T) {
	cases := []struct {
		set  uint32
		want uint32
	}{
		{0, DefaultMaxFrameSize},
		{1, DefaultMaxFrameSize},
		{DefaultMaxFrameSize - 1, DefaultMaxFrameSize},
		{DefaultMaxFrameSize, DefaultMaxFrameSize},
		{DefaultMaxFrameSize + 1, DefaultMaxFrameSize + 1},
		{MaxLength, MaxLength},
		{MaxLength + 1, MaxLength},
		{0xffffffff, MaxLength},
	}
	for _, tc := range cases {
		w := NewWriter(&recordingWriter{}, WriterConfig{})
		w.SetMaxFrameSize(tc.set)
		if got := w.MaxFrameSize(); got != tc.want {
			t.Errorf("SetMaxFrameSize(%d): MaxFrameSize = %d, want %d", tc.set, got, tc.want)
		}
		// The clamp is also what makes the header's 24-bit length field safe: no
		// frame this writer accepts can declare a length it cannot express.
		if got := w.MaxFrameSize(); got > MaxLength {
			t.Errorf("SetMaxFrameSize(%d) left the bound at %d, above the 24-bit maximum %d",
				tc.set, got, uint32(MaxLength))
		}
	}
}

// TestWriterConfigMaxFrameSizeIsClampedToo checks the constructor goes through
// the same gate rather than assigning the field directly.
func TestWriterConfigMaxFrameSizeIsClampedToo(t *testing.T) {
	w := NewWriter(&recordingWriter{}, WriterConfig{MaxFrameSize: 7})
	if got := w.MaxFrameSize(); got != DefaultMaxFrameSize {
		t.Errorf("MaxFrameSize = %d, want %d", got, DefaultMaxFrameSize)
	}
	w = NewWriter(&recordingWriter{}, WriterConfig{MaxFrameSize: 0xffffffff})
	if got := w.MaxFrameSize(); got != MaxLength {
		t.Errorf("MaxFrameSize = %d, want %d", got, uint32(MaxLength))
	}
}

// TestWriterRefusesAnOversizeStreamID is the check header.go's documentation
// promises exists. AppendTo truncates a 32-bit identifier to the 31 bits the wire
// has, which would send a frame that is valid, deliverable, and about a different
// stream than the caller meant — the kind of bug that shows up as a corrupted
// response on an unrelated request.
func TestWriterRefusesAnOversizeStreamID(t *testing.T) {
	w := NewWriter(&recordingWriter{}, WriterConfig{})

	if err := w.Queue(DataFrame{StreamID: streamIDMask, Data: []byte("ok")}); err != nil {
		t.Errorf("Queue on the maximum legal stream: %v", err)
	}
	before := w.Buffered()

	err := w.Queue(DataFrame{StreamID: streamIDMask + 1, Data: []byte("no")})
	wantConnErr(t, err, h2.InternalError)
	if got := w.Buffered(); got != before {
		t.Errorf("Buffered = %d after a refused frame, want %d", got, before)
	}
}

// --- write failures ---------------------------------------------------------

// TestWriterLatchesTheFirstError checks a dead connection stays dead. Once a
// write has failed there is no offset a retry could resume from, so every later
// call must report the same failure rather than attempt another write.
func TestWriterLatchesTheFirstError(t *testing.T) {
	sentinel := errors.New("connection reset by peer")
	rec := &recordingWriter{err: sentinel}
	w := NewWriter(rec, WriterConfig{})

	if err := w.Queue(PingFrame{}); err != nil {
		t.Fatalf("Queue: %v", err)
	}
	if err := w.Flush(); !errors.Is(err, sentinel) {
		t.Fatalf("Flush: err = %v, want %v", err, sentinel)
	}
	if !errors.Is(w.Err(), sentinel) {
		t.Errorf("Err = %v, want %v", w.Err(), sentinel)
	}

	// Every route back in reports the same error, and none of them writes again.
	if err := w.Queue(PingFrame{}); !errors.Is(err, sentinel) {
		t.Errorf("Queue after a failure: err = %v, want %v", err, sentinel)
	}
	if err := w.Flush(); !errors.Is(err, sentinel) {
		t.Errorf("Flush after a failure: err = %v, want %v", err, sentinel)
	}
	if err := w.WriteFrame(PingFrame{}); !errors.Is(err, sentinel) {
		t.Errorf("WriteFrame after a failure: err = %v, want %v", err, sentinel)
	}
	if len(rec.writes) != 1 {
		t.Errorf("performed %d writes, want 1: nothing may be written after a failure",
			len(rec.writes))
	}
	if got := w.Buffered(); got != 0 {
		t.Errorf("Buffered = %d after a failed flush, want 0: the queue is not "+
			"retryable and must not be kept", got)
	}
}

// TestWriterShortWriteIsAnError covers a writer that breaks the io.Writer
// contract by reporting a partial write with no error. Ignoring it would truncate
// a frame mid-payload and leave the peer reading the rest of the connection as
// though it were a frame header.
func TestWriterShortWriteIsAnError(t *testing.T) {
	rec := &recordingWriter{short: true}
	w := NewWriter(rec, WriterConfig{})

	err := w.WriteFrame(PingFrame{Data: [pingLen]byte{1, 2, 3, 4, 5, 6, 7, 8}})
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("err = %v, want io.ErrShortWrite", err)
	}
	if !errors.Is(w.Err(), io.ErrShortWrite) {
		t.Errorf("Err = %v, want io.ErrShortWrite", w.Err())
	}
	if err := w.WriteFrame(PingFrame{}); !errors.Is(err, io.ErrShortWrite) {
		t.Errorf("the short write was not latched: err = %v", err)
	}
}

// --- buffer behaviour -------------------------------------------------------

// TestWriterReusesItsBuffer checks a steady stream of frames does not allocate a
// new buffer per flush. It is the reason Flush truncates rather than reassigns.
func TestWriterReusesItsBuffer(t *testing.T) {
	rec := &recordingWriter{}
	w := NewWriter(rec, WriterConfig{})
	f := DataFrame{StreamID: 1, Data: bytes.Repeat([]byte{0xaa}, 100)}

	if err := w.WriteFrame(f); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	capacity := cap(w.buf)
	for i := 0; i < 100; i++ {
		if err := w.WriteFrame(f); err != nil {
			t.Fatalf("WriteFrame %d: %v", i, err)
		}
	}
	if cap(w.buf) != capacity {
		t.Errorf("buffer capacity grew from %d to %d over 100 identical frames",
			capacity, cap(w.buf))
	}
	if len(rec.writes) != 101 {
		t.Errorf("performed %d writes, want 101", len(rec.writes))
	}
}

// TestWriterBufferGrowsForABurst checks the initial size is a starting point and
// not a bound: a burst larger than the buffer must still be queued whole, since
// splitting it across flushes is the caller's decision to make, not the buffer's.
func TestWriterBufferGrowsForABurst(t *testing.T) {
	rec := &recordingWriter{}
	w := NewWriter(rec, WriterConfig{BufferSize: 64})

	var frames []Frame
	for i := 0; i < 20; i++ {
		frames = append(frames, DataFrame{StreamID: 1, Data: bytes.Repeat([]byte{0xaa}, 500)})
	}
	for _, f := range frames {
		if err := w.Queue(f); err != nil {
			t.Fatalf("Queue: %v", err)
		}
	}
	if got, want := w.Buffered(), 20*(HeaderLen+500); got != want {
		t.Errorf("Buffered = %d, want %d", got, want)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if len(rec.writes) != 1 {
		t.Errorf("performed %d writes, want 1", len(rec.writes))
	}
	if got, want := rec.all(), frameBytes(frames...); !bytes.Equal(got, want) {
		t.Errorf("wrote %d octets, want %d", len(got), len(want))
	}
}

// --- round trip through the reader ------------------------------------------

// TestWriterRoundTripsEveryFrameTypeThroughTheReader is the integration test for
// the whole framing layer: every assigned type serialised by the Writer, read
// back by the Reader, and equal to what went in. The two halves were written
// against the RFC independently, so agreeing is evidence rather than tautology.
func TestWriterRoundTripsEveryFrameTypeThroughTheReader(t *testing.T) {
	frames := oneOfEachFrameType()

	rec := &recordingWriter{}
	w := NewWriter(rec, WriterConfig{})
	for _, f := range frames {
		if err := w.Queue(f); err != nil {
			t.Fatalf("Queue(%s): %v", f.Type(), err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	rd := readerOver(rec.all(), ReaderConfig{})
	got := mustReadFrames(t, rd, len(frames))
	for i, want := range frames {
		if !reflect.DeepEqual(got[i], want) {
			t.Errorf("frame %d (%s) round trip\n got %+v\nwant %+v",
				i, want.Type(), got[i], want)
		}
	}
	if _, err := rd.ReadFrame(); !errors.Is(err, io.EOF) {
		t.Errorf("after the last frame: err = %v, want io.EOF", err)
	}
}

// TestWriterRoundTripsAwkwardFrames covers the shapes most likely to be wrong in
// exactly one direction: empty payloads, maximum-width fields, and every
// combination of the padding envelope.
func TestWriterRoundTripsAwkwardFrames(t *testing.T) {
	frames := []Frame{
		DataFrame{StreamID: 1},
		DataFrame{StreamID: 1, EndStream: true, Padded: true, PadLen: 0},
		DataFrame{StreamID: 1, Padded: true, PadLen: maxPadLen, Data: []byte{0x00}},
		DataFrame{StreamID: streamIDMask, Data: bytes.Repeat([]byte{0xff}, DefaultMaxFrameSize-1)},
		HeadersFrame{StreamID: 1, EndHeaders: true},
		HeadersFrame{
			StreamID:         3,
			EndStream:        true,
			EndHeaders:       true,
			Priority:         true,
			Exclusive:        true,
			StreamDependency: streamIDMask,
			Weight:           255,
			Padded:           true,
			PadLen:           maxPadLen,
			Fragment:         []byte{0x82},
		},
		SettingsFrame{},
		SettingsFrame{Ack: true},
		SettingsFrame{Settings: []Setting{
			{ID: SettingHeaderTableSize, Value: 0},
			{ID: SettingEnablePush, Value: 0},
			{ID: SettingMaxConcurrentStreams, Value: 0xffffffff},
			{ID: SettingInitialWindowSize, Value: MaxWindowSize},
			{ID: SettingMaxFrameSize, Value: MaxLength},
			{ID: SettingMaxHeaderListSize, Value: 0xffffffff},
		}},
		PingFrame{},
		PingFrame{Ack: true, Data: [pingLen]byte{0xff, 0, 0xff, 0, 0xff, 0, 0xff, 0}},
		GoAwayFrame{},
		GoAwayFrame{LastStreamID: streamIDMask, ErrCode: h2.HTTP11Required},
		GoAwayFrame{Debug: []byte("line1\r\nERROR: forged\x1b[31m")},
		RSTStreamFrame{StreamID: 1},
		RSTStreamFrame{StreamID: streamIDMask, ErrCode: h2.ErrCode(0xffffffff)},
		WindowUpdateFrame{Increment: 1},
		WindowUpdateFrame{StreamID: streamIDMask, Increment: MaxWindowSize},
		PriorityFrame{StreamID: 1, StreamDependency: 3},
		PriorityFrame{StreamID: 1, Exclusive: true, StreamDependency: streamIDMask, Weight: 255},
		PushPromiseFrame{StreamID: 1, PromisedID: 2, EndHeaders: true},
		PushPromiseFrame{
			StreamID:   1,
			PromisedID: streamIDMask,
			EndHeaders: true,
			Padded:     true,
			PadLen:     maxPadLen,
			Fragment:   []byte{0x82},
		},
	}
	for _, want := range frames {
		rec := &recordingWriter{}
		w := NewWriter(rec, WriterConfig{})
		if err := w.WriteFrame(want); err != nil {
			t.Fatalf("WriteFrame(%s): %v", want.Type(), err)
		}
		// Read each in its own reader: several of these are illegal in sequence
		// (two GOAWAYs, a bare PUSH_PROMISE after one) and continuity is not what
		// is under test here.
		rd := readerOver(rec.all(), ReaderConfig{})
		got := mustReadFrame(t, rd)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s round trip\n got %+v\nwant %+v", want.Type(), got, want)
		}
	}
}

// TestWriterAndReaderOverAPipe runs the two halves against each other across a
// real io.Pipe, on separate goroutines, which is how they will actually be used —
// and under -race it is the check that neither one reaches into the other's
// buffers. The pipe delivers whatever the writer wrote in whatever pieces the
// reader asks for, so it also exercises reads that do not align with frames.
func TestWriterAndReaderOverAPipe(t *testing.T) {
	pr, pw := io.Pipe()

	frames := []Frame{
		SettingsFrame{Settings: []Setting{{ID: SettingMaxFrameSize, Value: DefaultMaxFrameSize}}},
		SettingsFrame{Ack: true},
		HeadersFrame{StreamID: 1, Fragment: bytes.Repeat([]byte{0x82}, 4000)},
		ContinuationFrame{StreamID: 1, Fragment: bytes.Repeat([]byte{0x86}, 4000)},
		ContinuationFrame{StreamID: 1, EndHeaders: true, Fragment: []byte{0x84}},
		DataFrame{StreamID: 1, Data: bytes.Repeat([]byte{0xaa}, DefaultMaxFrameSize)},
		DataFrame{StreamID: 1, EndStream: true},
		PingFrame{Data: [pingLen]byte{9, 8, 7, 6, 5, 4, 3, 2}},
		GoAwayFrame{LastStreamID: 1, ErrCode: h2.NoError, Debug: []byte("done")},
	}

	errc := make(chan error, 1)
	go func() {
		defer close(errc)
		w := NewWriter(pw, WriterConfig{})
		for _, f := range frames {
			if err := w.Queue(f); err != nil {
				errc <- err
				_ = pw.CloseWithError(err)
				return
			}
			// Flush at an awkward point so the reader sees frames split across
			// writes rather than one tidy buffer per frame.
			if w.Buffered() > 5000 {
				if err := w.Flush(); err != nil {
					errc <- err
					_ = pw.CloseWithError(err)
					return
				}
			}
		}
		if err := w.Flush(); err != nil {
			errc <- err
		}
		_ = pw.Close()
	}()

	rd := NewReader(pr, ReaderConfig{})
	got := mustReadFrames(t, rd, len(frames))
	if _, err := rd.ReadFrame(); !errors.Is(err, io.EOF) {
		t.Errorf("after the last frame: err = %v, want io.EOF", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("writer goroutine: %v", err)
	}

	for i, want := range frames {
		if !reflect.DeepEqual(got[i], want) {
			t.Errorf("frame %d (%s) did not survive the pipe\n got %+v\nwant %+v",
				i, want.Type(), got[i], want)
		}
	}
	if rd.BlockOpen() != 0 {
		t.Errorf("BlockOpen = %d at the end, want 0", rd.BlockOpen())
	}
}

// TestWriterRefusesAFrameThatMisdeclaresItsLength exercises the last-resort check
// in Queue through a frame type that exists only in this test: a frame whose
// PayloadLen disagrees with what it serialises. No real frame type can do this —
// each has a test sweeping its optional parts — but the failure it would cause is
// the one a peer cannot recover from, since the declared length is how it finds
// the next frame header.
func TestWriterRefusesAFrameThatMisdeclaresItsLength(t *testing.T) {
	rec := &recordingWriter{}
	w := NewWriter(rec, WriterConfig{})

	if err := w.Queue(DataFrame{StreamID: 1, Data: []byte("keep")}); err != nil {
		t.Fatalf("Queue: %v", err)
	}
	before := w.Buffered()

	for _, bad := range []Frame{
		lyingFrame{declared: 10, actual: 4},
		lyingFrame{declared: 4, actual: 10},
		lyingFrame{declared: 0, actual: 1},
		lyingFrame{declared: 1, actual: 0},
	} {
		err := w.Queue(bad)
		wantConnErr(t, err, h2.InternalError)
		if got := w.Buffered(); got != before {
			t.Fatalf("Buffered = %d after refusing a frame, want %d: the half-written "+
				"frame was left in the queue", got, before)
		}
	}

	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	want := serializeFrame(DataFrame{StreamID: 1, Data: []byte("keep")})
	if got := rec.all(); !bytes.Equal(got, want) {
		t.Errorf("wrote\n got % x\nwant % x", got, want)
	}
}

// lyingFrame declares one payload length and writes another. It is the shape of
// the bug the check in Queue exists to stop, and there is no other way to reach
// that branch: every real frame type is proven consistent by its own tests.
type lyingFrame struct {
	declared uint32
	actual   int
}

func (f lyingFrame) Type() FrameType    { return TypeData }
func (f lyingFrame) Flags() Flags       { return 0 }
func (f lyingFrame) Stream() uint32     { return 1 }
func (f lyingFrame) PayloadLen() uint32 { return f.declared }

func (f lyingFrame) appendPayload(dst []byte) []byte {
	return append(dst, make([]byte, f.actual)...)
}
