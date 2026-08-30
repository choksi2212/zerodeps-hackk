package server

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"zerodeps/zdh/internal/frame"
	"zerodeps/zdh/internal/h2"
)

// gateWait bounds every wait in this file. A test that hangs tells you nothing
// until the package times out ten minutes later and dumps every goroutine in the
// binary; a test that fails in two seconds names the step that did not happen.
const gateWait = 2 * time.Second

// errNoDeadline is what a stalled target reports if it is asked to write without
// a deadline having been set. See testTarget.Write.
var errNoDeadline = errors.New("testTarget: Write with no deadline set")

// testTarget is the write half of a connection under the test's control.
//
// This is what the writeTarget interface is for. Every failure the writer has to
// survive is a property of the socket, not of the frames: a peer that stops
// reading, a write that times out, a write that reports fewer octets than it was
// given. Through a real socket none of those can be provoked on demand — you can
// only arrange them and hope. Here each one is a field.
type testTarget struct {
	mu        sync.Mutex
	writes    [][]byte
	deadlines []time.Time

	// The fields below are set before the writer goroutine starts and never
	// written again, so they are read without the lock. The race detector runs
	// over this package's tests and would say so if that were untrue.

	// setErr is returned by SetWriteDeadline.
	setErr error

	// writeErr is returned by Write, for an ungated target.
	writeErr error

	// short makes Write claim it wrote one octet fewer than it was given, with no
	// error to say so. io.Writer forbids that; a wrapper can still do it, and the
	// frame layer turns it into io.ErrShortWrite rather than a silently truncated
	// frame stream.
	short bool

	// stalled makes Write block until the deadline set for it expires and then
	// fail the way a real socket does. It is the peer that has stopped reading.
	stalled bool

	// entered and release, when non-nil, make every Write a handshake: the writer
	// goroutine announces its arrival on entered and waits on release for the
	// result to return. That is what makes coalescing testable — while the writer
	// is parked here the test can fill the queue and know it is full, rather than
	// racing the writer for it.
	entered chan struct{}
	release chan error
}

// newGatedTarget returns a target whose every Write parks until the test lets it
// through.
func newGatedTarget() *testTarget {
	return &testTarget{entered: make(chan struct{}), release: make(chan error)}
}

func (tt *testTarget) SetWriteDeadline(t time.Time) error {
	tt.mu.Lock()
	tt.deadlines = append(tt.deadlines, t)
	tt.mu.Unlock()
	return tt.setErr
}

func (tt *testTarget) Write(p []byte) (int, error) {
	// Recorded before the handshake, so a test that has taken the arrival signal
	// can read the octets straight away instead of having to wait for the write
	// to finish.
	tt.mu.Lock()
	tt.writes = append(tt.writes, append([]byte(nil), p...))
	tt.mu.Unlock()

	if tt.entered != nil {
		tt.entered <- struct{}{}
	}
	err := tt.writeErr
	if tt.release != nil {
		err = <-tt.release
	}

	if tt.stalled {
		d, ok := tt.lastDeadline()
		if !ok {
			// flush is meant to set a deadline before every write, and
			// TestFrameWriterSetsTheWriteDeadline checks that directly. Stalling
			// for ever here would hang the suite, so this fails the write instead
			// and lets the assertion on the returned error say what happened.
			return 0, errNoDeadline
		}
		time.Sleep(time.Until(d))
		err = os.ErrDeadlineExceeded
	}

	if err != nil {
		return 0, err
	}
	if tt.short && len(p) > 0 {
		return len(p) - 1, nil
	}
	return len(p), nil
}

// awaitWrite waits for the writer to reach a Write and returns the function that
// lets it complete with err.
func (tt *testTarget) awaitWrite(t *testing.T) func(error) {
	t.Helper()
	select {
	case <-tt.entered:
	case <-time.After(gateWait):
		t.Fatalf("the writer did not reach a Write within %v; %d writes so far",
			gateWait, tt.writeCount())
	}
	return func(err error) {
		t.Helper()
		select {
		case tt.release <- err:
		case <-time.After(gateWait):
			t.Fatalf("the writer did not collect its result within %v", gateWait)
		}
	}
}

// waitStopped waits for the writer to stop and returns the error that stopped it,
// failing rather than hanging.
//
// It exists because of what the obvious spelling does when a guard is broken.
// w.Wait blocks for ever on a writer that does not stop, and a writer parked on a
// gated target's handshake that nobody is waiting for never stops — so a test
// written as "Wait, then assert" turns a broken guard into a ten-minute package
// timeout and a dump of every goroutine in the binary. That is technically a
// failure and practically useless. Here an unexpected write is named, released so
// the writer can carry on, and the test still reaches its own assertions.
func waitStopped(t *testing.T, w *frameWriter, tt *testTarget) error {
	t.Helper()

	stopped := make(chan error, 1)
	go func() { stopped <- w.Wait() }()

	for {
		select {
		case err := <-stopped:
			return err
		case <-tt.entered:
			// nil for an ungated target, and a receive on a nil channel blocks
			// for ever, which is exactly right: there is no handshake to drain.
			t.Errorf("the writer began write %d when it should have stopped",
				tt.writeCount())
			tt.release <- nil
		case <-time.After(gateWait):
			t.Fatalf("the writer did not stop within %v, after %d writes",
				gateWait, tt.writeCount())
			return nil
		}
	}
}

func (tt *testTarget) writeCount() int {
	tt.mu.Lock()
	defer tt.mu.Unlock()
	return len(tt.writes)
}

// writeSizes is the length of each Write in order. Coalescing is a claim about
// how many calls a burst costs, so the sizes are the assertion.
func (tt *testTarget) writeSizes() []int {
	tt.mu.Lock()
	defer tt.mu.Unlock()
	sizes := make([]int, len(tt.writes))
	for i, w := range tt.writes {
		sizes[i] = len(w)
	}
	return sizes
}

func (tt *testTarget) allWrites() []byte {
	tt.mu.Lock()
	defer tt.mu.Unlock()
	var b []byte
	for _, w := range tt.writes {
		b = append(b, w...)
	}
	return b
}

func (tt *testTarget) allDeadlines() []time.Time {
	tt.mu.Lock()
	defer tt.mu.Unlock()
	return append([]time.Time(nil), tt.deadlines...)
}

func (tt *testTarget) lastDeadline() (time.Time, bool) {
	tt.mu.Lock()
	defer tt.mu.Unlock()
	if len(tt.deadlines) == 0 {
		return time.Time{}, false
	}
	return tt.deadlines[len(tt.deadlines)-1], true
}

// framesWritten decodes everything the target received back into frames.
//
// Reading the octets back rather than comparing them against a hand-built
// expectation is the stronger assertion, and not only because it is shorter: it
// proves the stream is synchronised. A frame whose declared length disagreed with
// its payload would leave the reader at the wrong offset and the decode would
// fail, where a byte comparison would report a diff and leave you to work out
// which of the two it was. TestFrameWriterWritesFrameOctets anchors the octets
// themselves so that a reader and writer agreeing on the wrong format cannot pass.
func framesWritten(t *testing.T, tt *testTarget, cfg frame.ReaderConfig) []frame.Frame {
	t.Helper()
	r := frame.NewReader(bytes.NewReader(tt.allWrites()), cfg)
	var got []frame.Frame
	for {
		f, err := r.ReadFrame()
		if errors.Is(err, io.EOF) {
			return got
		}
		if err != nil {
			t.Fatalf("decoding what the writer wrote: %v (after %d frames)", err, len(got))
		}
		got = append(got, f)
	}
}

// ping is a PING frame carrying n, for tests that need distinguishable frames.
func ping(n uint64) frame.PingFrame {
	var data [8]byte
	binary.BigEndian.PutUint64(data[:], n)
	return frame.PingFrame{Data: data}
}

// --- what reaches the peer ---------------------------------------------------

// TestFrameWriterWritesFrameOctets anchors the decode-and-compare every other
// test in this file relies on.
//
// Those tests read the octets back with frame.NewReader, which would agree with a
// broken encoder as readily as a correct one. This pins one frame against the nine
// header octets of RFC 9113 §4.1, written out by hand.
func TestFrameWriterWritesFrameOctets(t *testing.T) {
	tt := &testTarget{}
	w := startFrameWriter(tt, time.Second)

	if err := w.Enqueue(frame.PingFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	w.Shutdown()
	if err := waitStopped(t, w, tt); err != nil {
		t.Fatalf("Wait: %v", err)
	}

	want := []byte{
		0x00, 0x00, 0x08, // 24-bit length: 8 octets of payload
		0x06,                   // type: PING
		0x00,                   // flags: none, so not an acknowledgement
		0x00, 0x00, 0x00, 0x00, // 32-bit stream identifier: the connection
		1, 2, 3, 4, 5, 6, 7, 8, // opaque data
	}
	if got := tt.allWrites(); !bytes.Equal(got, want) {
		t.Errorf("wrote\n got % x\nwant % x", got, want)
	}
}

// TestFrameWriterWritesInQueueOrder is the writer's core promise. Frames leave in
// the order they were handed over, whatever the batching underneath did.
func TestFrameWriterWritesInQueueOrder(t *testing.T) {
	tt := &testTarget{}
	w := startFrameWriter(tt, time.Second)

	want := []frame.Frame{
		ping(1),
		frame.WindowUpdateFrame{StreamID: 0, Increment: 1000},
		ping(2),
		frame.WindowUpdateFrame{StreamID: 3, Increment: 2000},
		frame.PingFrame{Ack: true, Data: [8]byte{0xff}},
		ping(3),
	}
	for i, f := range want {
		if err := w.Enqueue(f); err != nil {
			t.Fatalf("Enqueue frame %d (%s): %v", i, f.Type(), err)
		}
	}
	w.Shutdown()
	if err := waitStopped(t, w, tt); err != nil {
		t.Fatalf("Wait: %v", err)
	}

	got := framesWritten(t, tt, frame.ReaderConfig{})
	if !reflect.DeepEqual(got, want) {
		t.Errorf("read back\n got %#v\nwant %#v", got, want)
	}
}

// --- coalescing --------------------------------------------------------------

// TestFrameWriterCoalescesABurstIntoOneWrite is the reason Queue and Flush are
// separate at all. Over TLS every Write is at least one record with its own header
// and authentication tag, so a response's HEADERS and DATA going out separately
// costs the peer a second record to process for nothing.
//
// The gate is what makes this deterministic: the writer is parked inside the
// priming write while the burst is queued, so it cannot have taken any of the
// burst frames early and split them across writes.
func TestFrameWriterCoalescesABurstIntoOneWrite(t *testing.T) {
	tt := newGatedTarget()
	w := startFrameWriter(tt, time.Second)

	if err := w.Enqueue(ping(0)); err != nil {
		t.Fatalf("Enqueue priming frame: %v", err)
	}
	letPriming := tt.awaitWrite(t)

	const burst = 5
	for i := 1; i <= burst; i++ {
		if err := w.Enqueue(ping(uint64(i))); err != nil {
			t.Fatalf("Enqueue burst frame %d: %v", i, err)
		}
	}
	letPriming(nil)

	letBurst := tt.awaitWrite(t)
	letBurst(nil)

	w.Shutdown()
	if err := waitStopped(t, w, tt); err != nil {
		t.Fatalf("Wait: %v", err)
	}

	pingSize := frame.HeaderLen + 8
	want := []int{pingSize, burst * pingSize}
	if got := tt.writeSizes(); !reflect.DeepEqual(got, want) {
		t.Errorf("write sizes = %v, want %v: %d queued frames must cost one write, not %d",
			got, want, burst, burst)
	}
	if got := len(framesWritten(t, tt, frame.ReaderConfig{})); got != burst+1 {
		t.Errorf("read back %d frames, want %d", got, burst+1)
	}
}

// TestFrameWriterFlushesAtTheHighWater is the other half of coalescing: it stops.
// Buffering past one maximum-size frame cannot save a TLS record, because a record
// cannot carry more than 16 KiB and the record layer would split it anyway — it
// would only delay the frames already buffered and grow the buffer for the life of
// the connection.
func TestFrameWriterFlushesAtTheHighWater(t *testing.T) {
	tt := newGatedTarget()
	w := startFrameWriter(tt, time.Second)

	if err := w.Enqueue(ping(0)); err != nil {
		t.Fatalf("Enqueue priming frame: %v", err)
	}
	letPriming := tt.awaitWrite(t)

	// Three frames of half the maximum size. Two of them are 32786 octets on the
	// wire, which crosses the high water, so the third cannot join them.
	const half = frame.DefaultMaxFrameSize / 2
	const dataSize = frame.HeaderLen + half
	for i := 0; i < 3; i++ {
		f := frame.DataFrame{StreamID: 1, Data: bytes.Repeat([]byte{byte(i)}, half)}
		if err := w.Enqueue(f); err != nil {
			t.Fatalf("Enqueue DATA frame %d: %v", i, err)
		}
	}
	letPriming(nil)

	first := tt.awaitWrite(t)
	first(nil)
	second := tt.awaitWrite(t)
	second(nil)

	w.Shutdown()
	if err := waitStopped(t, w, tt); err != nil {
		t.Fatalf("Wait: %v", err)
	}

	want := []int{frame.HeaderLen + 8, 2 * dataSize, dataSize}
	if got := tt.writeSizes(); !reflect.DeepEqual(got, want) {
		t.Errorf("write sizes = %v, want %v: the burst must stop at the %d-octet high water",
			got, want, coalesceHighWater)
	}
}

// TestCoalesceHighWaterCannotExceedATLSRecord pins the constant to the argument
// its comment makes. Raising it above a record buys nothing and costs buffer.
func TestCoalesceHighWaterCannotExceedATLSRecord(t *testing.T) {
	const tlsRecordMax = 1 << 14
	if coalesceHighWater > tlsRecordMax {
		t.Errorf("coalesceHighWater = %d, above the %d octets a TLS record can carry: "+
			"buffering past a record cannot save one", coalesceHighWater, tlsRecordMax)
	}
	if coalesceHighWater < frame.DefaultMaxFrameSize {
		t.Errorf("coalesceHighWater = %d, below the %d-octet maximum frame size: a single "+
			"legal frame would flush on its own and never coalesce with anything",
			coalesceHighWater, frame.DefaultMaxFrameSize)
	}
}

// --- field blocks ------------------------------------------------------------

// block is a field block spread over one HEADERS frame and len(rest) CONTINUATION
// frames, with END_HEADERS on the last of them.
func block(id uint32, first int, rest ...int) []frame.Frame {
	frames := []frame.Frame{frame.HeadersFrame{
		StreamID:   id,
		EndHeaders: len(rest) == 0,
		Fragment:   bytes.Repeat([]byte{0xaa}, first),
	}}
	for i, n := range rest {
		frames = append(frames, frame.ContinuationFrame{
			StreamID:   id,
			EndHeaders: i == len(rest)-1,
			Fragment:   bytes.Repeat([]byte{byte(i)}, n),
		})
	}
	return frames
}

// TestFrameWriterKeepsAFieldBlockContiguous is §4.3 of RFC 9113 observed on the
// wire, and the defect that replacing the channel was for.
//
// A response's header section is enqueued by internal/response from a stream
// goroutine. A PING acknowledgement is enqueued by the connection's reader
// goroutine, which is not holding internal/response's mutex and has no reason to.
// Nothing in the two goroutines' timing keeps the second out of the middle of the
// first, and a channel wrote them in the order they arrived — which §6.10 of
// RFC 9113 entitles the peer to treat as a connection error of type PROTOCOL_ERROR.
//
// The decode is half the assertion on its own: frame.Reader enforces the same rule,
// so an interleaved stream does not merely read back in the wrong order, it fails
// to read back at all.
func TestFrameWriterKeepsAFieldBlockContiguous(t *testing.T) {
	tt := newGatedTarget()
	w := startFrameWriter(tt, time.Second)

	if err := w.Enqueue(ping(0)); err != nil {
		t.Fatalf("Enqueue priming frame: %v", err)
	}
	letPriming := tt.awaitWrite(t)

	// Exactly what the reader goroutine does when a peer pings twice during a
	// header section, which is the arrival order a channel would have written out.
	fields := block(1, 8, 8, 8)
	interleaved := []frame.Frame{fields[0], ping(1), fields[1], ping(2), fields[2]}
	for i, f := range interleaved {
		if err := w.Enqueue(f); err != nil {
			t.Fatalf("Enqueue frame %d (%s): %v", i, f.Type(), err)
		}
	}
	letPriming(nil)

	letBurst := tt.awaitWrite(t)
	letBurst(nil)

	w.Shutdown()
	if err := waitStopped(t, w, tt); err != nil {
		t.Fatalf("Wait: %v", err)
	}

	// The two acknowledgements overtake the block rather than being held behind
	// it: they are nine and seventeen octets whose purpose is to keep the peer
	// moving, and holding them behind a header section would be the same mistake
	// in the other direction.
	want := []frame.Frame{ping(0), ping(1), ping(2), fields[0], fields[1], fields[2]}
	got := framesWritten(t, tt, frame.ReaderConfig{})
	if !reflect.DeepEqual(got, want) {
		t.Errorf("wrote\n got %#v\nwant %#v", got, want)
	}
}

// TestFrameWriterCloseCannotTruncateAFieldBlock is the hazard the burst's own
// stopping rule exists for, and it is reachable only through the high water.
//
// A block whose frames do not all fit under coalesceHighWater would, by the plain
// reading of the coalescing rule, be flushed part-way through — putting a HEADERS
// frame on the wire whose CONTINUATION frames are still queued. That is legal for
// as long as the rest follows, and a Close arriving in the meantime is what makes
// it permanent: the peer is left holding an unterminated field block and, by §6.10
// of RFC 9113, a connection error. So the burst continues past the high water while
// the scheduler is part-way through a block.
//
// The Close lands while the writer is inside the write, which is the only moment
// that can distinguish the two behaviours.
func TestFrameWriterCloseCannotTruncateAFieldBlock(t *testing.T) {
	tt := newGatedTarget()
	w := startFrameWriter(tt, time.Second)

	if err := w.Enqueue(ping(0)); err != nil {
		t.Fatalf("Enqueue priming frame: %v", err)
	}
	letPriming := tt.awaitWrite(t)

	// The first frame alone crosses the high water, so every frame after it is
	// buffered only because the block is unfinished.
	fields := block(1, coalesceHighWater-4, 500, 500)
	for i, f := range fields {
		if err := w.Enqueue(f); err != nil {
			t.Fatalf("Enqueue block frame %d: %v", i, err)
		}
	}
	letPriming(nil)

	letBlock := tt.awaitWrite(t)
	w.Close()
	letBlock(nil)

	if err := waitStopped(t, w, tt); err != nil {
		t.Fatalf("Wait: %v", err)
	}

	if got := tt.writeCount(); got != 2 {
		t.Errorf("%d writes, want 2: the whole block belongs to the write the Close "+
			"could not interrupt", got)
	}
	want := append([]frame.Frame{ping(0)}, fields...)
	got := framesWritten(t, tt, frame.ReaderConfig{})
	if !reflect.DeepEqual(got, want) {
		t.Errorf("wrote %d frames, want %d: a Close must not leave a field block "+
			"unterminated on the wire\n got %#v\nwant %#v", len(got), len(want), got, want)
	}
}

// TestFrameWriterDropsAnIncompleteFieldBlockOnShutdown is the same rule from the
// other side. A block whose CONTINUATION frames were never enqueued cannot be
// completed by anyone, so a shutdown drops it rather than sending a HEADERS frame
// that promises a continuation nobody will send.
//
// This is why await checks the graceful flag only with the queue empty and not with
// the scheduler empty: an unfinished block is not in the queue.
func TestFrameWriterDropsAnIncompleteFieldBlockOnShutdown(t *testing.T) {
	tt := &testTarget{}
	w := startFrameWriter(tt, time.Second)

	opening := frame.HeadersFrame{StreamID: 1, Fragment: []byte("half a header section")}
	if err := w.Enqueue(opening); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	w.Shutdown()
	if err := waitStopped(t, w, tt); err != nil {
		t.Fatalf("Wait: %v", err)
	}

	if got := tt.writeCount(); got != 0 {
		t.Errorf("%d writes, want 0: a HEADERS frame without its continuation must not "+
			"be sent", got)
	}
}

// TestFrameWriterAdmitsAContinuationForAFullQueue is the one exception to the depth
// bound, and it is a deadlock rather than a nicety.
//
// The bound is backpressure against a peer that has stopped reading. A CONTINUATION
// frame for a block already begun is the opposite case: refusing it leaves a block
// that can never be completed, which can never be written, so the queue never
// drains and the connection stalls with the depth bound holding it shut. The frames
// are bounded by the one block, which internal/response has already encoded in full
// before it enqueues the first of them, so admitting them costs no memory that has
// not already been spent.
func TestFrameWriterAdmitsAContinuationForAFullQueue(t *testing.T) {
	tt := newGatedTarget()
	w := startFrameWriter(tt, time.Second)

	if err := w.Enqueue(ping(0)); err != nil {
		t.Fatalf("Enqueue priming frame: %v", err)
	}
	letPriming := tt.awaitWrite(t)

	fields := block(1, 8, 8)
	if err := w.Enqueue(fields[0]); err != nil {
		t.Fatalf("Enqueue the HEADERS that opens the block: %v", err)
	}
	// An unfinished block does not count towards the depth, because it is not a
	// frame that can be written; the queue is filled with frames that are.
	for i := 1; i <= defaultQueueDepth; i++ {
		if err := w.Enqueue(ping(uint64(i))); err != nil {
			t.Fatalf("Enqueue frame %d, filling the queue: %v", i, err)
		}
	}

	admitted := make(chan error, 1)
	go func() { admitted <- w.Enqueue(fields[1]) }()
	select {
	case err := <-admitted:
		if err != nil {
			t.Errorf("the CONTINUATION completing an open block was refused: %v", err)
		}
	case <-time.After(gateWait):
		t.Fatalf("the CONTINUATION completing an open block blocked on a full queue for %v; "+
			"the block can never complete and the queue can never drain", gateWait)
	}

	w.Close()
	letPriming(nil)
	if err := waitStopped(t, w, tt); err != nil {
		t.Errorf("Wait: %v", err)
	}
}

// --- stopping ----------------------------------------------------------------

// TestFrameWriterShutdownWritesWhatIsQueued is how a GOAWAY reaches the peer.
//
// A shutdown that dropped the queue would close the connection with the
// explanation still in it, which is the difference between a failure someone can
// diagnose from a packet capture and a bare reset.
//
// This used to run twenty times, and the reason it no longer needs to is the
// change worth recording. With a channel, the loop selected over the queue and a
// closed graceful channel, both branches wrote the GOAWAY, and Go chose between
// them uniformly — so a single attempt proved only that one of the two paths sent
// it, and an early version of this test passed with the graceful branch's flush
// deleted. There is now one path: await drains the queue before it looks at the
// graceful flag, so a GOAWAY queued before Shutdown is written every time and once
// is enough to say so.
func TestFrameWriterShutdownWritesWhatIsQueued(t *testing.T) {
	goaway := frame.GoAwayFrame{
		LastStreamID: 7,
		ErrCode:      h2.EnhanceYourCalm,
		Debug:        []byte("too many resets"),
	}

	tt := newGatedTarget()
	w := startFrameWriter(tt, time.Second)

	// The priming frame parks the writer inside a Write, so the GOAWAY is queued
	// and Shutdown is called while the loop is somewhere it can observe neither.
	// That is the case a shutdown which dropped the queue would fail.
	if err := w.Enqueue(ping(0)); err != nil {
		t.Fatalf("Enqueue priming frame: %v", err)
	}
	letPriming := tt.awaitWrite(t)

	if err := w.Enqueue(goaway); err != nil {
		t.Fatalf("Enqueue GOAWAY: %v", err)
	}
	w.Shutdown()
	letPriming(nil)

	// The assertion that catches a shutdown which drops the queue: with no second
	// write the writer never arrives here and this reports it by name within
	// gateWait, rather than the test hanging on Wait.
	letGoAway := tt.awaitWrite(t)
	letGoAway(nil)

	if err := waitStopped(t, w, tt); err != nil {
		t.Fatalf("Wait: %v", err)
	}

	got := framesWritten(t, tt, frame.ReaderConfig{})
	if len(got) != 2 {
		t.Fatalf("read back %d frames, want the priming PING and the GOAWAY", len(got))
	}
	if !reflect.DeepEqual(got[1], goaway) {
		t.Fatalf("GOAWAY read back as %#v, want %#v", got[1], goaway)
	}
}

// TestFrameWriterShutdownRefusesAWaitingEnqueue is the other half of Shutdown, and
// a case the channel could not decide.
//
// A stream goroutine blocked on a full queue when the connection starts shutting
// down has to be told something, and with a channel it was told whichever of two
// ready select cases Go picked: sometimes the frame went onto a queue that was
// about to stop being drained, sometimes it was refused. Enqueue now re-examines
// the stop flags before every push, so a Shutdown always wins the race against a
// waiting caller — and the frame that would have been silently dropped is instead
// reported to the layer that built it.
func TestFrameWriterShutdownRefusesAWaitingEnqueue(t *testing.T) {
	tt := newGatedTarget()
	w := startFrameWriter(tt, time.Second)

	if err := w.Enqueue(ping(0)); err != nil {
		t.Fatalf("Enqueue priming frame: %v", err)
	}
	letPriming := tt.awaitWrite(t)

	for i := 1; i <= defaultQueueDepth; i++ {
		if err := w.Enqueue(ping(uint64(i))); err != nil {
			t.Fatalf("Enqueue frame %d, filling the queue: %v", i, err)
		}
	}

	blocked := make(chan error, 1)
	go func() { blocked <- w.Enqueue(ping(1 << 20)) }()

	// Given time to reach the wait rather than assumed to have reached it. If it
	// has not, the Shutdown below is observed by the pre-check instead of by the
	// wait, which is a weaker version of the same assertion rather than a wrong
	// one — so this cannot make the test flaky in the direction of passing.
	select {
	case err := <-blocked:
		t.Fatalf("Enqueue on a full queue returned %v before the writer stopped", err)
	case <-time.After(50 * time.Millisecond):
	}

	w.Shutdown()
	select {
	case err := <-blocked:
		if !errors.Is(err, errWriterStopped) {
			t.Errorf("a waiting Enqueue released by Shutdown returned %v, want errWriterStopped", err)
		}
	case <-time.After(gateWait):
		t.Fatalf("a waiting Enqueue was not released by Shutdown within %v", gateWait)
	}

	w.Close()
	letPriming(nil)
	if err := waitStopped(t, w, tt); err != nil {
		t.Errorf("Wait: %v", err)
	}
}

// TestFrameWriterCloseDropsTheQueue is Close's contract: nothing further is
// written. It is for a connection that is already lost, where there is no peer
// left to explain anything to.
//
// With a channel this needed twenty attempts, because a ready queue and a closed
// abrupt channel were two ready select cases and Go picked uniformly: the loop
// carried a separate non-blocking pre-check to stop it writing one more burst
// about half the time, and a single attempt could not tell whether that pre-check
// was there. await checks the abrupt flag before it looks at the queue, so the
// precedence is now the order of two statements and one attempt observes it.
func TestFrameWriterCloseDropsTheQueue(t *testing.T) {
	tt := newGatedTarget()
	w := startFrameWriter(tt, time.Second)

	if err := w.Enqueue(ping(0)); err != nil {
		t.Fatalf("Enqueue priming frame: %v", err)
	}
	letPriming := tt.awaitWrite(t)

	if err := w.Enqueue(ping(1)); err != nil {
		t.Fatalf("Enqueue queued frame: %v", err)
	}
	w.Close()
	letPriming(nil)

	if err := waitStopped(t, w, tt); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if got := tt.writeCount(); got != 1 {
		t.Fatalf("%d writes after Close, want 1: the queued frame must not be written", got)
	}
	got := framesWritten(t, tt, frame.ReaderConfig{})
	if len(got) != 1 || !reflect.DeepEqual(got[0], ping(0)) {
		t.Fatalf("read back %#v, want only the frame already being written", got)
	}
}

// TestFrameWriterCloseBeatsShutdown settles the precedence between the two stop
// signals. Close is the stronger: a connection that has been lost cannot be
// drained onto, and a graceful flush that ran anyway would write to a dead socket
// and wait out the write timeout doing it.
//
// It cannot interrupt a burst already being written — a write that has reached the
// socket is out of our hands — so both signals are raised while the writer is
// parked, which is the case that is actually decidable.
func TestFrameWriterCloseBeatsShutdown(t *testing.T) {
	tt := newGatedTarget()
	w := startFrameWriter(tt, time.Second)

	if err := w.Enqueue(ping(0)); err != nil {
		t.Fatalf("Enqueue priming frame: %v", err)
	}
	letPriming := tt.awaitWrite(t)

	if err := w.Enqueue(ping(1)); err != nil {
		t.Fatalf("Enqueue queued frame: %v", err)
	}
	w.Shutdown()
	w.Close()
	letPriming(nil)

	if err := waitStopped(t, w, tt); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if got := tt.writeCount(); got != 1 {
		t.Fatalf("%d writes after Shutdown then Close, want 1: Close wins", got)
	}
}

// TestFrameWriterRefusesEnqueueAfterStopping covers the check Enqueue makes before
// every push. A frame accepted onto a queue that will never be drained is lost
// silently: the layer above is told the frame was handed over.
//
// The case with room free is the one that used to be able to go wrong, when the
// send and the stop signal were two ready select cases and the choice between them
// was Go's. It is now the order of two statements, so this asserts it once per stop
// signal rather than two hundred times each.
func TestFrameWriterRefusesEnqueueAfterStopping(t *testing.T) {
	stops := []struct {
		name string
		stop func(*frameWriter)
	}{
		{"Shutdown", (*frameWriter).Shutdown},
		{"Close", (*frameWriter).Close},
	}
	for _, tc := range stops {
		t.Run(tc.name, func(t *testing.T) {
			tt := &testTarget{}
			w := startFrameWriter(tt, time.Second)
			tc.stop(w)

			err := w.Enqueue(ping(1))
			if !errors.Is(err, errWriterStopped) {
				t.Fatalf("Enqueue after %s = %v, want errWriterStopped with room free",
					tc.name, err)
			}
			if err := waitStopped(t, w, tt); err != nil {
				t.Fatalf("Wait: %v", err)
			}
			if got := tt.writeCount(); got != 0 {
				t.Fatalf("%d writes, want 0: the refused frame must not reach the peer", got)
			}
		})
	}
}

// TestFrameWriterStopSignalsAreIdempotent is a property the connection layer needs
// and no longer has to be engineered: the stop signals are flags under a mutex, and
// setting a flag that is already set does nothing. They were closed channels, and
// closing a closed channel panics, so each carried a sync.Once — which is what this
// test was originally for.
//
// Keeping it is not sentiment. The connection layer has several reasons to stop a
// writer that can arrive together, a read error and a shutdown among them, and a
// future change that reintroduced something with a once-only step would break here
// rather than in production.
func TestFrameWriterStopSignalsAreIdempotent(t *testing.T) {
	tt := &testTarget{}
	w := startFrameWriter(tt, time.Second)

	w.Shutdown()
	w.Shutdown()
	w.Close()
	w.Close()
	w.Shutdown()

	if err := waitStopped(t, w, tt); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	// Deliberately the bare Wait: the writer has already been observed stopped, so
	// this cannot hang, and what it checks is that Wait is answerable more than
	// once — the connection layer has several places that may want to know.
	if err := w.Wait(); err != nil {
		t.Fatalf("second Wait: %v", err)
	}
}

// TestFrameWriterStopSignalsAreConcurrencySafe is the same property under the race
// detector, since the connection layer stops the writer from whichever goroutine
// noticed the problem first.
func TestFrameWriterStopSignalsAreConcurrencySafe(t *testing.T) {
	tt := &testTarget{}
	w := startFrameWriter(tt, time.Second)

	const callers = 8
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				w.Shutdown()
			} else {
				w.Close()
			}
			// The bare Wait, not waitStopped: this is the call under test — eight
			// goroutines waiting on one writer — and waitStopped reports through
			// t.Fatalf, which may only be called from the goroutine running the
			// test. The bound is on wg.Wait below instead.
			if err := w.Wait(); err != nil {
				t.Errorf("caller %d: Wait: %v", i, err)
			}
		}(i)
	}

	returned := make(chan struct{})
	go func() {
		wg.Wait()
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(gateWait):
		t.Fatalf("%d callers did not all return from Wait within %v", callers, gateWait)
	}
}

// --- write failures ----------------------------------------------------------

// TestFrameWriterLatchesAWriteError checks both halves of a failed write: the loop
// stops, and every later Enqueue is told why rather than being left to block on a
// queue nothing is draining.
func TestFrameWriterLatchesAWriteError(t *testing.T) {
	wantErr := errors.New("connection reset by peer")
	tt := &testTarget{writeErr: wantErr}
	w := startFrameWriter(tt, time.Second)

	if err := w.Enqueue(ping(1)); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if err := waitStopped(t, w, tt); !errors.Is(err, wantErr) {
		t.Fatalf("Wait = %v, want %v", err, wantErr)
	}
	if err := w.Enqueue(ping(2)); !errors.Is(err, wantErr) {
		t.Errorf("Enqueue after a failed write = %v, want the write error: the reason the "+
			"writer stopped is more use than the fact that it stopped", err)
	}
	// The bare Wait is safe and deliberate here for the same reason as in the
	// idempotence test: the writer is already known to have stopped.
	if err := w.Wait(); !errors.Is(err, wantErr) {
		t.Errorf("second Wait = %v, want the same error as the first", err)
	}
}

// TestFrameWriterReportsAShortWrite covers an io.Writer that breaks its contract:
// fewer octets than it was given, and no error. Left alone that truncates a frame
// mid-payload and every frame after it is read at the wrong offset, so it has to
// stop the connection rather than be ignored.
func TestFrameWriterReportsAShortWrite(t *testing.T) {
	tt := &testTarget{short: true}
	w := startFrameWriter(tt, time.Second)

	if err := w.Enqueue(ping(1)); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if err := waitStopped(t, w, tt); !errors.Is(err, io.ErrShortWrite) {
		t.Errorf("Wait = %v, want io.ErrShortWrite", err)
	}
}

// TestFrameWriterStopsOnADeadlineError covers the failure nobody writes a test for
// because it "cannot happen": SetWriteDeadline failing. It does happen — on a
// connection the operating system has already closed — and continuing would write
// with no deadline at all, which is the one state the six timeouts exist to
// prevent.
func TestFrameWriterStopsOnADeadlineError(t *testing.T) {
	wantErr := errors.New("use of closed network connection")
	tt := &testTarget{setErr: wantErr}
	w := startFrameWriter(tt, time.Second)

	if err := w.Enqueue(ping(1)); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if err := waitStopped(t, w, tt); !errors.Is(err, wantErr) {
		t.Fatalf("Wait = %v, want %v", err, wantErr)
	}
	if got := tt.writeCount(); got != 0 {
		t.Errorf("%d writes after SetWriteDeadline failed, want 0: an undeadlined write can "+
			"block for ever", got)
	}
}

// TestFrameWriterSetsTheWriteDeadline pins the deadline to the timeout it was
// configured with. The bracket is exact rather than approximate: the deadline is
// set between the two clock readings, so it must land between them plus the
// timeout, and no tolerance has to be invented.
func TestFrameWriterSetsTheWriteDeadline(t *testing.T) {
	const timeout = 3 * time.Second
	tt := newGatedTarget()
	w := startFrameWriter(tt, timeout)

	before := time.Now()
	if err := w.Enqueue(ping(1)); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	let := tt.awaitWrite(t)
	after := time.Now()
	let(nil)

	w.Shutdown()
	if err := waitStopped(t, w, tt); err != nil {
		t.Fatalf("Wait: %v", err)
	}

	got := tt.allDeadlines()
	if len(got) != 1 {
		t.Fatalf("SetWriteDeadline called %d times for one write, want 1", len(got))
	}
	lo, hi := before.Add(timeout), after.Add(timeout)
	if got[0].Before(lo) || got[0].After(hi) {
		t.Errorf("write deadline %v is outside [%v, %v]: it must be the %v timeout from the "+
			"moment of the write", got[0], lo, hi, timeout)
	}
}

// TestFrameWriterSetsNoDeadlineWithNothingToWrite is the syscall a shutdown on an
// idle connection does not make, and most connections close idle.
//
// It used to be a guard inside flush, which returned early with nothing buffered
// because the graceful path flushed unconditionally. await removed the reason: the
// loop takes a frame or it stops, so with nothing queued it never reaches a flush
// at all and there is no empty case left to guard. The assertion is unchanged
// because the observable behaviour is — the deadline count is still the only way to
// see it, since frame.Writer.Flush never had octets at risk here.
func TestFrameWriterSetsNoDeadlineWithNothingToWrite(t *testing.T) {
	tt := &testTarget{}
	w := startFrameWriter(tt, time.Second)

	w.Shutdown()
	if err := waitStopped(t, w, tt); err != nil {
		t.Fatalf("Wait: %v", err)
	}

	if got := tt.allDeadlines(); len(got) != 0 {
		t.Errorf("SetWriteDeadline called %d times with nothing queued, want 0", len(got))
	}
	if got := tt.writeCount(); got != 0 {
		t.Errorf("%d writes with nothing queued, want 0", got)
	}
}

// TestFrameWriterReleasesAnEnqueueBlockedOnAStalledPeer is the no-deadlock claim
// in Enqueue's documentation, and the one property in this file that a real server
// depends on to stay alive.
//
// A peer that stops reading fills the socket buffer, then the writer's queue, and
// then blocks whichever goroutine is trying to enqueue — a stream handler, or the
// connection's reader goroutine. Nothing here has a timeout of its own. The wait
// is bounded by the write deadline: it fails the blocked write, which stops the
// loop, which closes done, which releases every blocked Enqueue at once.
func TestFrameWriterReleasesAnEnqueueBlockedOnAStalledPeer(t *testing.T) {
	baseline := goroutineBaseline()

	const timeout = 150 * time.Millisecond
	tt := &testTarget{stalled: true}
	w := startFrameWriter(tt, timeout)

	// Frames big enough that a burst takes only a few of them, so the queue fills
	// rather than being drained into the buffer as fast as it is filled.
	payload := make([]byte, 1024)

	const attempts = 1000
	start := time.Now()
	var err error
	accepted := 0
	for ; accepted < attempts; accepted++ {
		err = w.Enqueue(frame.DataFrame{StreamID: 1, Data: payload})
		if err != nil {
			break
		}
	}
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("%d frames accepted by a writer whose peer stopped reading; the queue is "+
			"not bounded", attempts)
	}
	if accepted < defaultQueueDepth {
		t.Errorf("Enqueue refused after %d frames, want at least the queue depth of %d",
			accepted, defaultQueueDepth)
	}
	if elapsed < timeout/2 {
		t.Errorf("Enqueue returned after %v without waiting for the %v write deadline: "+
			"backpressure means blocking, not refusing", elapsed, timeout)
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("Enqueue = %v, want the deadline error that stopped the writer", err)
	}
	if err := waitStopped(t, w, tt); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("Wait = %v, want os.ErrDeadlineExceeded", err)
	}
	assertNoGoroutineLeak(t, baseline)
}

// TestFrameWriterDropsTheBurstItCannotFinish covers a frame this writer refuses to
// send: oversize, so frame.Writer.Queue rejects it mid-burst.
//
// The frames buffered ahead of it are dropped with it, and that is the intended
// behaviour rather than an oversight. A refusal here means the layer above built
// something unsendable, so what is buffered is the front half of a response whose
// back half does not exist; a peer given HEADERS and then a GOAWAY has been told
// less accurately what happened than one given only the GOAWAY.
func TestFrameWriterDropsTheBurstItCannotFinish(t *testing.T) {
	tt := newGatedTarget()
	w := startFrameWriter(tt, time.Second)

	if err := w.Enqueue(ping(0)); err != nil {
		t.Fatalf("Enqueue priming frame: %v", err)
	}
	letPriming := tt.awaitWrite(t)

	if err := w.Enqueue(ping(1)); err != nil {
		t.Fatalf("Enqueue the frame that will be dropped: %v", err)
	}
	oversize := frame.DataFrame{
		StreamID: 1,
		Data:     make([]byte, frame.DefaultMaxFrameSize+1),
	}
	if err := w.Enqueue(oversize); err != nil {
		t.Fatalf("Enqueue oversize frame: %v", err)
	}
	letPriming(nil)

	err := waitStopped(t, w, tt)
	var ce h2.ConnError
	if !errors.As(err, &ce) {
		t.Fatalf("Wait = %v, want an h2.ConnError", err)
	}
	if ce.Code != h2.InternalError {
		t.Errorf("Wait error code = %s, want INTERNAL_ERROR: an unsendable frame is our bug, "+
			"not the peer's", ce.Code)
	}
	if got := tt.writeCount(); got != 1 {
		t.Errorf("%d writes, want 1: only the frame already being written reaches the peer",
			got)
	}
}

// TestFrameWriterRefusesAnOversizeStreamID is the other refusal, and the one worth
// having: the stream identifier field is 31 bits and the serialiser truncates
// rather than reporting, so an identifier above the maximum would produce a frame
// that is valid, deliverable, and about the wrong stream.
func TestFrameWriterRefusesAnOversizeStreamID(t *testing.T) {
	tt := &testTarget{}
	w := startFrameWriter(tt, time.Second)

	if err := w.Enqueue(frame.DataFrame{StreamID: 1 << 31, Data: []byte("x")}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	err := waitStopped(t, w, tt)
	var ce h2.ConnError
	if !errors.As(err, &ce) || ce.Code != h2.InternalError {
		t.Fatalf("Wait = %v, want an h2.ConnError with INTERNAL_ERROR", err)
	}
	if got := tt.writeCount(); got != 0 {
		t.Errorf("%d writes, want 0: a frame about the wrong stream must not be sent", got)
	}
}

// TestFrameWriterSetMaxFrameSizeRaisesTheLimit checks that the peer's
// SETTINGS_MAX_FRAME_SIZE reaches the writer. Without it the server would refuse
// to send frames a peer explicitly asked for, and the symptom would be a stalled
// response rather than an error.
func TestFrameWriterSetMaxFrameSizeRaisesTheLimit(t *testing.T) {
	const raised = 1 << 15
	tt := &testTarget{}
	w := startFrameWriter(tt, time.Second)
	w.SetMaxFrameSize(raised)

	big := frame.DataFrame{StreamID: 1, Data: bytes.Repeat([]byte{0xab}, frame.DefaultMaxFrameSize+1)}
	if err := w.Enqueue(big); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	w.Shutdown()
	if err := waitStopped(t, w, tt); err != nil {
		t.Fatalf("Wait: %v: a %d-octet frame was refused after SETTINGS_MAX_FRAME_SIZE was "+
			"raised to %d", err, big.PayloadLen(), raised)
	}

	got := framesWritten(t, tt, frame.ReaderConfig{MaxFrameSize: raised})
	if len(got) != 1 {
		t.Fatalf("read back %d frames, want 1", len(got))
	}
	if !reflect.DeepEqual(got[0], big) {
		t.Errorf("frame read back changed: got %d octets, want %d",
			got[0].PayloadLen(), big.PayloadLen())
	}
}

// TestFrameWriterReportsTheCapAResponseMustSplitAt covers the value rather than its
// effect. The effect is the test above; this is the reading that internal/stream's
// side of ConnWriter does before it splits a header list, and it has to be right in
// three ways: the protocol's default before the peer has said anything (§6.5.2), the
// peer's value once it has, and never below the default even if the peer asks for
// less — §6.5.2 sets 16384 as the smallest value the setting may carry, so a smaller
// one is a peer bug, and a writer that honoured it would fragment every response
// against a limit the protocol forbids.
func TestFrameWriterReportsTheCapAResponseMustSplitAt(t *testing.T) {
	tt := &testTarget{}
	w := startFrameWriter(tt, time.Second)
	defer func() {
		w.Shutdown()
		if err := waitStopped(t, w, tt); err != nil {
			t.Errorf("Wait: %v", err)
		}
	}()

	if got := w.MaxFrameSize(); got != frame.DefaultMaxFrameSize {
		t.Errorf("a new writer reports a cap of %d, want the protocol default %d",
			got, uint32(frame.DefaultMaxFrameSize))
	}

	const raised = 1 << 15
	w.SetMaxFrameSize(raised)
	if got := w.MaxFrameSize(); got != raised {
		t.Errorf("after the peer raised the cap to %d the writer reports %d", uint32(raised), got)
	}

	w.SetMaxFrameSize(frame.DefaultMaxFrameSize - 1)
	if got := w.MaxFrameSize(); got != frame.DefaultMaxFrameSize {
		t.Errorf("after a peer asked for %d the writer reports %d, want the floor %d",
			frame.DefaultMaxFrameSize-1, got, uint32(frame.DefaultMaxFrameSize))
	}
}

// --- concurrency and lifetime ------------------------------------------------

// TestFrameWriterSurvivesConcurrentEnqueue is the invariant the whole type exists
// for. Enqueue is called from every stream goroutine on the connection at once,
// and if any of that reached the socket directly the frames would interleave
// octet-wise — which is unrecoverable, because there is no framing marker for the
// peer to resynchronise to.
//
// Every frame carries its sender and sequence number, so the assertion is that all
// of them arrived, exactly once, and decodable. Corruption shows up as a decode
// failure; loss shows up as a missing entry.
func TestFrameWriterSurvivesConcurrentEnqueue(t *testing.T) {
	const senders, each = 8, 64
	tt := &testTarget{}
	w := startFrameWriter(tt, 10*time.Second)

	var wg sync.WaitGroup
	for g := 0; g < senders; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				if err := w.Enqueue(ping(uint64(g)<<32 | uint64(i))); err != nil {
					t.Errorf("sender %d frame %d: Enqueue: %v", g, i, err)
					return
				}
			}
		}(g)
	}
	// Every sender is finished before the shutdown, deliberately: Enqueue after a
	// Shutdown is refused by design, and a test that raced the two would be
	// asserting that frames it never handed over went missing.
	wg.Wait()

	w.Shutdown()
	if err := waitStopped(t, w, tt); err != nil {
		t.Fatalf("Wait: %v", err)
	}

	got := framesWritten(t, tt, frame.ReaderConfig{})
	if len(got) != senders*each {
		t.Fatalf("read back %d frames, want %d", len(got), senders*each)
	}
	seen := make(map[[8]byte]int, len(got))
	for i, f := range got {
		p, ok := f.(frame.PingFrame)
		if !ok {
			t.Fatalf("frame %d is a %s, want PING", i, f.Type())
		}
		seen[p.Data]++
	}
	for g := 0; g < senders; g++ {
		for i := 0; i < each; i++ {
			want := ping(uint64(g)<<32 | uint64(i)).Data
			if n := seen[want]; n != 1 {
				t.Errorf("frame from sender %d sequence %d arrived %d times, want once", g, i, n)
			}
		}
	}
}

// TestFrameWriterReleasesEveryWaiterWhenTheLoopDies is the liveness property the
// whole condition variable rests on: a stream goroutine blocked on a full queue
// when the socket dies has to be released by something, and the only something is
// what stop does.
//
// The rounds are for the omission — a missing broadcast leaves eight goroutines
// blocked for ever and is reported by name within gateWait rather than as a package
// timeout ten minutes later, with every goroutine in the binary attached.
//
// What the rounds are honestly not for is the ordering inside stop: the flag a
// waiter wakes to read is set while the mutex is still held, and setting it after
// releasing the mutex instead was measured to pass all two hundred rounds, because
// the two statements are adjacent and the window is a few instructions wide. That
// version is caught by the race detector instead — the flag becomes an unsynchronised
// write against a read under the mutex — and the race detector runs over this
// package in the gate. Worth writing down, because a test that looked like it
// covered the ordering and did not would be worse than one that says so.
func TestFrameWriterReleasesEveryWaiterWhenTheLoopDies(t *testing.T) {
	baseline := goroutineBaseline()
	errBoom := errors.New("connection reset by peer")

	const rounds, waiters = 200, 8
	for round := 0; round < rounds; round++ {
		tt := newGatedTarget()
		w := startFrameWriter(tt, time.Second)

		// Parked inside the priming write, so the queue can be filled to the depth
		// and the waiters below are genuinely waiting rather than racing a drain.
		if err := w.Enqueue(ping(0)); err != nil {
			t.Fatalf("round %d: Enqueue priming frame: %v", round, err)
		}
		letPriming := tt.awaitWrite(t)
		for i := 1; i <= defaultQueueDepth; i++ {
			if err := w.Enqueue(ping(uint64(i))); err != nil {
				t.Fatalf("round %d: Enqueue frame %d, filling the queue: %v", round, i, err)
			}
		}

		released := make(chan error, waiters)
		for i := 0; i < waiters; i++ {
			go func(i int) { released <- w.Enqueue(ping(uint64(1<<20 + i))) }(i)
		}

		// The write fails, which is the one way the loop ends with neither stop
		// flag set — so the waiters can only be released by what stop does.
		letPriming(errBoom)

		for i := 0; i < waiters; i++ {
			select {
			case err := <-released:
				if !errors.Is(err, errBoom) {
					t.Fatalf("round %d: a released Enqueue returned %v, want the write error",
						round, err)
				}
			case <-time.After(gateWait):
				t.Fatalf("round %d: %d of %d waiters were still blocked %v after the writer "+
					"died", round, waiters-i, waiters, gateWait)
			}
		}
		if err := w.Wait(); !errors.Is(err, errBoom) {
			t.Fatalf("round %d: Wait = %v, want the write error", round, err)
		}
	}

	assertNoGoroutineLeak(t, baseline)
}

// TestFrameWriterDoesNotLeakItsGoroutine is the §12.4 check applied to the writer.
// One goroutine that outlives its connection turns connect-and-disconnect into a
// denial of service, so both stop paths are exercised.
func TestFrameWriterDoesNotLeakItsGoroutine(t *testing.T) {
	baseline := goroutineBaseline()

	const connections = 50
	for i := 0; i < connections; i++ {
		tt := &testTarget{}
		w := startFrameWriter(tt, time.Second)
		if err := w.Enqueue(ping(uint64(i))); err != nil {
			t.Fatalf("connection %d: Enqueue: %v", i, err)
		}
		if i%2 == 0 {
			w.Shutdown()
		} else {
			w.Close()
		}
		if err := waitStopped(t, w, tt); err != nil {
			t.Fatalf("connection %d: Wait: %v", i, err)
		}
	}

	assertNoGoroutineLeak(t, baseline)
}

// TestFrameWriterQueueHasTheDocumentedDepth is a tripwire on the constant and on
// the memory argument its comment makes. The depth is per connection, so it is
// multiplied by every connection the server will hold open.
//
// It is asserted through Enqueue rather than by reading a field, which is the only
// honest way to state it now that the frames wait in a scheduler rather than a
// channel: what the constant means is how many frames a caller may hand over
// before it has to wait, and the capacity of whatever holds them is a detail of
// how that is arranged. The writer is parked inside its priming write throughout,
// so the queue cannot be drained underneath the count.
func TestFrameWriterQueueHasTheDocumentedDepth(t *testing.T) {
	tt := newGatedTarget()
	w := startFrameWriter(tt, time.Second)

	if err := w.Enqueue(ping(0)); err != nil {
		t.Fatalf("Enqueue priming frame: %v", err)
	}
	letPriming := tt.awaitWrite(t)

	// One more frame than the depth. The last is expected to block, so the whole
	// run is a goroutine that reports through channels — both buffered deeply
	// enough that it can never be left blocked on a send once the test is over.
	accepted := make(chan struct{}, defaultQueueDepth+1)
	refused := make(chan error, 1)
	go func() {
		for i := 1; i <= defaultQueueDepth+1; i++ {
			if err := w.Enqueue(ping(uint64(i))); err != nil {
				refused <- err
				return
			}
			accepted <- struct{}{}
		}
	}()

	for got := 0; got < defaultQueueDepth; got++ {
		select {
		case <-accepted:
		case err := <-refused:
			t.Fatalf("frame %d of %d was refused: %v", got+1, defaultQueueDepth, err)
		case <-time.After(gateWait):
			t.Fatalf("only %d frames accepted within %v, want the depth of %d",
				got, gateWait, defaultQueueDepth)
		}
	}

	// The depth is a bound, and the bound blocks rather than refuses. Refusing
	// would lose a frame the layer above has been told was handed over; not
	// bounding at all would let a peer that has stopped reading grow the queue.
	select {
	case <-accepted:
		t.Errorf("frame %d was accepted with %d already queued: the depth is not a bound",
			defaultQueueDepth+1, defaultQueueDepth)
	case err := <-refused:
		t.Errorf("Enqueue on a full queue returned %v, want it to wait for room", err)
	case <-time.After(100 * time.Millisecond):
	}

	// Close rather than Shutdown: the writer is about to come back from the
	// priming write with a full queue, and draining it would need a handshake per
	// burst for frames this test has no interest in.
	w.Close()
	letPriming(nil)
	if err := waitStopped(t, w, tt); err != nil {
		t.Errorf("Wait: %v", err)
	}

	const megabyte = 1 << 20
	worst := defaultQueueDepth * (frame.HeaderLen + frame.DefaultMaxFrameSize)
	if worst > megabyte {
		t.Errorf("a full queue of maximum-size frames is %d octets per connection, above the "+
			"%d the depth's rationale assumes", worst, megabyte)
	}
}
