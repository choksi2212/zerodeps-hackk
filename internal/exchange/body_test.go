package exchange

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"zerodeps/zdh/internal/h2"
)

// The tests in this file drive Body directly, without a stream table above it. What
// they are about is the handover between two goroutines — one that must never block and
// one that must — and driving it from frames would decide the interleavings for us.
// Everything about how a Body is filled from real DATA frames is in exchange_test.go.

// read is the whole of a body, or the error that stopped it.
//
// Bounded by a deadline, and not as a formality. The failure mode of nearly every guard
// in body.go is a Read that does not come back: an END_STREAM that was not recorded, a
// signal that never reached the waiter, an offset that never advanced. Without the
// deadline each of those is a test that hangs until the package timeout and then prints
// every goroutine in the binary, which detects the bug and tells nobody.
func read(t *testing.T, b *Body) (string, error) {
	t.Helper()

	type result struct {
		s   string
		err error
	}
	done := make(chan result, 1)
	go func() {
		got, err := io.ReadAll(b)
		done <- result{string(got), err}
	}()

	select {
	case r := <-done:
		return r.s, r.err
	case <-time.After(10 * time.Second):
		t.Fatal("reading the body did not finish within 10s")
		return "", nil
	}
}

// newTestBody is a body on stream 1 whose consumed-content reports are kept but not
// looked at, for the tests here that are about the handover rather than about flow
// control. The ones that are about flow control build their own and read it back.
func newTestBody() *Body {
	return newBody(1, &creditLog{})
}

// creditLog is a bodyCredit that remembers what a body reported.
//
// Locked, because the whole point of the reports is that they are made from the handler's
// goroutine while the reader's is still filling the body, so a test reading them back is
// a second goroutine by construction.
type creditLog struct {
	mu  sync.Mutex
	got []consumed
}

// consumed is one call to ReportConsumed.
type consumed struct {
	id   uint32
	n    int
	more bool
}

func (c *creditLog) ReportConsumed(id uint32, n int, more bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.got = append(c.got, consumed{id: id, n: n, more: more})
}

// reports is a copy of what has been reported so far.
func (c *creditLog) reports() []consumed {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]consumed(nil), c.got...)
}

// total is how many octets have been reported.
func (c *creditLog) total() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	var n int
	for _, r := range c.got {
		n += r.n
	}
	return n
}

// TestAnEndedBodyWithNothingInItIsEOF is the common case: a GET, whose Body exists
// only so that a handler needs no special case for it.
func TestAnEndedBodyWithNothingInItIsEOF(t *testing.T) {
	b := newTestBody()
	b.end(nil)

	if got, err := read(t, b); got != "" || err != nil {
		t.Errorf("reading a body that ended empty gave (%q, %v), want (\"\", nil)", got, err)
	}
}

// TestABodyReadsBackWhatArrived pins the ordering: chunks come out in the order the
// DATA frames went in, concatenated, with no boundary visible in the result.
func TestABodyReadsBackWhatArrived(t *testing.T) {
	b := newTestBody()
	b.add([]byte("one "))
	b.add([]byte("two "))
	b.add([]byte("three"))
	b.end(nil)

	if got, err := read(t, b); got != "one two three" || err != nil {
		t.Errorf("reading gave (%q, %v), want (%q, nil)", got, err, "one two three")
	}
}

// TestOneReadNeverCrossesAChunk is io.Reader's contract being kept in the direction
// that is easy to get wrong. A caller with a large buffer gets one frame's worth,
// because the alternative is to block waiting for a frame that would fill it and a peer
// is entitled never to send one.
func TestOneReadNeverCrossesAChunk(t *testing.T) {
	b := newTestBody()
	b.add([]byte("abc"))
	b.add([]byte("de"))
	b.end(nil)

	p := make([]byte, 64)
	n, err := b.Read(p)
	if n != 3 || err != nil || string(p[:n]) != "abc" {
		t.Fatalf("the first read gave (%d, %v, %q), want (3, nil, \"abc\")", n, err, p[:n])
	}
	n, err = b.Read(p)
	if n != 2 || err != nil || string(p[:n]) != "de" {
		t.Fatalf("the second read gave (%d, %v, %q), want (2, nil, \"de\")", n, err, p[:n])
	}
	if n, err := b.Read(p); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("the third read gave (%d, %v), want (0, EOF)", n, err)
	}
}

// TestAPartiallyReadChunkResumesWhereItStopped covers the offset. A handler reading a
// byte at a time is a handler this must not lose track of.
func TestAPartiallyReadChunkResumesWhereItStopped(t *testing.T) {
	b := newTestBody()
	b.add([]byte("hello"))
	b.end(nil)

	var got []byte
	p := make([]byte, 1)
	for {
		n, err := b.Read(p)
		got = append(got, p[:n]...)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				t.Fatalf("reading one byte at a time ended with %v, want EOF", err)
			}
			break
		}
	}
	if string(got) != "hello" {
		t.Errorf("one byte at a time read back %q, want %q", got, "hello")
	}
}

// TestAReadChunkIsDroppedRatherThanKept is about memory rather than behaviour, and it
// is worth a test because nothing a handler can observe would ever notice: a body that
// held every chunk it had already handed over would keep a whole request body alive
// until the response finished, per stream, and look correct doing it.
func TestAReadChunkIsDroppedRatherThanKept(t *testing.T) {
	b := newTestBody()
	b.add([]byte("abc"))
	b.add([]byte("def"))
	b.end(nil)

	p := make([]byte, 3)
	if _, err := b.Read(p); err != nil {
		t.Fatalf("read: %v", err)
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.chunks) != 1 {
		t.Errorf("the body holds %d chunks after one of its two was read, want 1", len(b.chunks))
	}
	if b.off != 0 {
		t.Errorf("the offset into the front chunk is %d after that chunk was finished, want 0", b.off)
	}
}

// TestAZeroLengthReadDoesNotBlock is the deadlock io.Copy would otherwise find. It
// probes with an empty buffer, and a Read that waited for content before noticing there
// was nowhere to put it would park the handler for the life of the connection.
func TestAZeroLengthReadDoesNotBlock(t *testing.T) {
	b := newTestBody()

	done := make(chan struct{})
	go func() {
		defer close(done)
		if n, err := b.Read(nil); n != 0 || err != nil {
			t.Errorf("a zero-length read gave (%d, %v), want (0, nil)", n, err)
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a zero-length read on an empty body did not return")
	}
}

// TestReadBlocksUntilContentArrives is the whole point of the type, so it is asserted
// rather than assumed: the handler is parked, the reader goroutine hands over a payload,
// and the handler wakes with it.
//
// The negative half — that the read had not already returned — is a window rather than
// a fact, because "still blocked" is not observable. A false failure here is a machine
// that could not schedule a goroutine in a tenth of a second, which is not a failure
// mode worth designing around, and the positive half is what the test is for.
func TestReadBlocksUntilContentArrives(t *testing.T) {
	b := newTestBody()
	got := make(chan string, 1)

	go func() {
		p := make([]byte, 16)
		n, err := b.Read(p)
		if err != nil {
			t.Errorf("read: %v", err)
		}
		got <- string(p[:n])
	}()

	select {
	case s := <-got:
		t.Fatalf("a read on an empty body returned %q before anything arrived", s)
	case <-time.After(100 * time.Millisecond):
	}

	b.add([]byte("late"))
	select {
	case s := <-got:
		if s != "late" {
			t.Errorf("the woken read returned %q, want %q", s, "late")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a read parked on an empty body was not woken by the payload that arrived")
	}
}

// TestEndWakesAParkedRead is the other way a parked read finishes: the peer sent
// END_STREAM and there is nothing more to wait for.
func TestEndWakesAParkedRead(t *testing.T) {
	b := newTestBody()
	done := make(chan error, 1)
	go func() {
		_, err := b.Read(make([]byte, 16))
		done <- err
	}()

	time.Sleep(10 * time.Millisecond)
	b.end(nil)

	select {
	case err := <-done:
		if !errors.Is(err, io.EOF) {
			t.Errorf("the woken read returned %v, want EOF", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a read parked on an empty body was not woken by END_STREAM")
	}
}

// TestFailWakesAParkedRead is the third way, and the one a peer causes: RST_STREAM, or
// the connection ending underneath the request.
func TestFailWakesAParkedRead(t *testing.T) {
	b := newTestBody()
	gone := errors.New("the stream is gone")

	done := make(chan error, 1)
	go func() {
		_, err := b.Read(make([]byte, 16))
		done <- err
	}()

	time.Sleep(10 * time.Millisecond)
	b.fail(gone)

	select {
	case err := <-done:
		if !errors.Is(err, gone) {
			t.Errorf("the woken read returned %v, want %v", err, gone)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a read parked on an empty body was not woken by the stream failing")
	}
}

// TestEndWakesEveryParkedRead is the difference between Signal and Broadcast in end.
//
// A handler that fanned its body out to several goroutines and then reached the peer's
// END_STREAM would, with a Signal, see one of them return io.EOF and the rest park for
// the life of the connection. It needs its own test rather than riding on
// TestManyGoroutinesReadingOneBody, which cannot reliably reproduce the case: there the
// filler outruns the readers, so by the time end is called the body still holds content
// and nobody is waiting to be woken.
func TestEndWakesEveryParkedRead(t *testing.T) {
	b := newTestBody()

	const readers = 8
	woken := make(chan error, readers)
	for i := 0; i < readers; i++ {
		go func() {
			_, err := b.Read(make([]byte, 16))
			woken <- err
		}()
	}

	// Long enough for eight goroutines to reach Wait. If one has not, it parks after the
	// Broadcast and the receive below is what notices.
	time.Sleep(50 * time.Millisecond)
	b.end(nil)

	for i := 0; i < readers; i++ {
		select {
		case err := <-woken:
			if !errors.Is(err, io.EOF) {
				t.Errorf("a woken read returned %v, want EOF", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d of %d parked reads were woken by END_STREAM", i, readers)
		}
	}
}

// TestFailWakesEveryParkedRead is the same difference in fail, and the reason a stream
// the peer reset does not leave a fanned-out handler parked on it.
func TestFailWakesEveryParkedRead(t *testing.T) {
	b := newTestBody()
	gone := errors.New("the stream is gone")

	const readers = 8
	woken := make(chan error, readers)
	for i := 0; i < readers; i++ {
		go func() {
			_, err := b.Read(make([]byte, 16))
			woken <- err
		}()
	}

	// Long enough for eight goroutines to reach Wait. If one has not, it parks after the
	// Broadcast and the receive below is what notices.
	time.Sleep(50 * time.Millisecond)
	b.fail(gone)

	for i := 0; i < readers; i++ {
		select {
		case err := <-woken:
			if !errors.Is(err, gone) {
				t.Errorf("a woken read returned %v, want %v", err, gone)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d of %d parked reads were woken by the body failing", i, readers)
		}
	}
}

// TestAFailedBodyReportsItsErrorAheadOfWhatArrived is the decision Read documents, and
// it is a decision rather than an accident. A stream the peer reset is a request this
// server must not act on, and a handler handed the front of a body whose end will never
// come is invited to parse what it has, answer, and be wrong.
func TestAFailedBodyReportsItsErrorAheadOfWhatArrived(t *testing.T) {
	b := newTestBody()
	b.add([]byte("half an upload"))
	gone := errors.New("the stream is gone")
	b.fail(gone)

	if got, err := read(t, b); got != "" || !errors.Is(err, gone) {
		t.Errorf("reading a failed body gave (%q, %v), want (\"\", %v)", got, err, gone)
	}
}

// TestTheFirstFailureIsTheOneReported: a stream can be lost twice in a moment — the
// peer resets it and then the connection ends under it — and the first reason is the one
// that explains the second.
func TestTheFirstFailureIsTheOneReported(t *testing.T) {
	b := newTestBody()
	first := errors.New("the peer reset the stream")
	b.fail(first)
	b.fail(errors.New("the connection ended"))

	if _, err := read(t, b); !errors.Is(err, first) {
		t.Errorf("the body reports %v, want the first reason %v", err, first)
	}
}

// TestContentThatArrivedBeforeEndStreamIsStillRead is the ordinary complete upload, and
// the assertion is that END_STREAM does not discard what it ends.
func TestContentThatArrivedBeforeEndStreamIsStillRead(t *testing.T) {
	b := newTestBody()
	b.add([]byte("complete"))
	b.end([]h2.Field{{Name: "checksum", Value: "1"}})

	got, err := read(t, b)
	if got != "complete" || err != nil {
		t.Fatalf("reading gave (%q, %v), want (%q, nil)", got, err, "complete")
	}
	if fs := b.Trailers(); len(fs) != 1 || fs[0].Name != "checksum" {
		t.Errorf("the trailer section reads back as %v, want one checksum field", fs)
	}
}

// TestTrailersAreNilUntilTheBodyEnds is §8.1's ordering as a handler sees it: the
// trailer section is after the content, so one that could be read before the content was
// finished would be one that had not arrived.
func TestTrailersAreNilUntilTheBodyEnds(t *testing.T) {
	b := newTestBody()
	b.add([]byte("x"))

	if fs := b.Trailers(); fs != nil {
		t.Errorf("the trailer section reads back as %v before the body ended, want nil", fs)
	}
}

// TestManyGoroutinesReadingOneBody is the race detector's test, and it is here because
// the promise this type makes is about goroutines rather than about bytes. One filler
// standing in for the connection's reader, four readers standing in for a handler that
// fanned its body out, and the assertions are that every octet comes out exactly once
// and that -race says nothing.
//
// What it does not cover is the signalling, which is worth saying because it looks like
// it should. The filler outruns the readers, so by the time end is called there is still
// content buffered and no reader is parked to be woken — narrowing end's Broadcast to a
// Signal leaves this test passing. TestEndWakesEveryParkedRead is the one that fails.
// The deadline on the wait below is still worth having: every other way a reader can be
// left parked shows up here first, and without it the symptom is a test that never
// finishes rather than one that says how many readers never came back.
func TestManyGoroutinesReadingOneBody(t *testing.T) {
	b := newTestBody()

	const chunks = 200
	go func() {
		for i := 0; i < chunks; i++ {
			b.add([]byte("ab"))
		}
		b.end(nil)
	}()

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		n    int
		left = 4
	)
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := make([]byte, 3)
			for {
				got, err := b.Read(p)
				mu.Lock()
				n += got
				if err != nil {
					left--
				}
				mu.Unlock()
				if err != nil {
					if !errors.Is(err, io.EOF) {
						t.Errorf("read: %v", err)
					}
					return
				}
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		mu.Lock()
		parked := left
		mu.Unlock()
		t.Fatalf("%d of 4 readers were still parked 10s after the body ended", parked)
	}

	mu.Lock()
	defer mu.Unlock()
	if want := chunks * 2; n != want {
		t.Errorf("four readers took %d octets between them, want the %d that were added", n, want)
	}
}

// TestAddNeverBlocks is the promise the connection's reader goroutine depends on. It is
// also the one goroutine on a connection that must never be made to wait: it answers the
// peer's PING frames and notices its GOAWAY, for every stream at once, so a handler that
// stopped reading its body must not be able to stall it.
func TestAddNeverBlocks(t *testing.T) {
	b := newTestBody()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 10_000; i++ {
			b.add([]byte("nobody is reading this"))
		}
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("ten thousand payloads could not be handed to a body nobody was reading")
	}
}

// recv is the value ch carries, or a named failure if it does not carry one soon.
//
// Every handover between a test and a handler goes through this rather than a bare
// receive, for the reason read gives: a guard that goes missing in this package usually
// shows up as a goroutine that never reaches its next line, and a bare receive turns that
// into a test that hangs instead of a test that says what did not happen.
func recv[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(10 * time.Second):
		t.Fatalf("%s did not happen within 10s", what)
		var zero T
		return zero
	}
}

// safeBuf is a bytes.Buffer a log.Logger can write to from a handler's goroutine while
// a test reads it from its own.
type safeBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *safeBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *safeBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func (s *safeBuf) contains(sub string) bool { return strings.Contains(s.String(), sub) }

// --- reporting consumed content ---------------------------------------------

// TestReadingABodyReportsEveryOctetItConsumed.
//
// The report is what returns the peer's flow-control window, so an octet read and not
// reported is an octet of window this connection never gets back — a stall that arrives
// after a body's worth of traffic rather than at the read that caused it.
func TestReadingABodyReportsEveryOctetItConsumed(t *testing.T) {
	c := &creditLog{}
	b := newBody(7, c)

	b.add([]byte("hello "))
	b.add([]byte("world"))
	b.end(nil)

	if got, err := read(t, b); got != "hello world" || err != nil {
		t.Fatalf("reading the body gave (%q, %v), want (\"hello world\", nil)", got, err)
	}
	if got, want := c.total(), len("hello world"); got != want {
		t.Errorf("the body reported %d octets consumed, want %d", got, want)
	}
	for _, r := range c.reports() {
		if r.id != 7 {
			t.Errorf("a report named stream %d, want 7", r.id)
		}
	}
}

// TestOnlyTheLastReadOfABodyReportsThatThereIsNoMore.
//
// The flag decides whether the stream gets a WINDOW_UPDATE of its own alongside the
// connection's, so getting it wrong in one direction sends a frame naming a stream that
// is finished with and in the other stalls a peer that is not.
func TestOnlyTheLastReadOfABodyReportsThatThereIsNoMore(t *testing.T) {
	c := &creditLog{}
	b := newBody(1, c)

	b.add([]byte("aa"))
	b.add([]byte("bb"))
	b.end(nil)

	if got, err := read(t, b); got != "aabb" || err != nil {
		t.Fatalf("reading the body gave (%q, %v), want (\"aabb\", nil)", got, err)
	}

	got := c.reports()
	if len(got) != 2 {
		t.Fatalf("two payloads produced %d reports, want 2: %v", len(got), got)
	}
	if !got[0].more {
		t.Error("the first of two payloads reported that no more content was coming")
	}
	if got[1].more {
		t.Error("the last payload of an ended body reported that more content was coming")
	}
}

// TestReadingAnUnendedBodyReportsThatMoreIsComing, even having emptied the buffer.
//
// This is the case the whole mechanism exists for: a peer that has spent its window is
// waiting to be told there is room, and the handler has read everything that arrived. If
// the last read before the buffer empties said there was no more content, the stream's
// window would never be replenished and the upload would stop there.
func TestReadingAnUnendedBodyReportsThatMoreIsComing(t *testing.T) {
	c := &creditLog{}
	b := newBody(1, c)
	b.add([]byte("aa"))

	if n, err := b.Read(make([]byte, 8)); n != 2 || err != nil {
		t.Fatalf("reading the one payload that arrived gave (%d, %v), want (2, nil)", n, err)
	}

	got := c.reports()
	if len(got) != 1 {
		t.Fatalf("one read produced %d reports, want 1: %v", len(got), got)
	}
	if !got[0].more {
		t.Error("emptying the buffer of a body the peer has not ended reported that no more content was coming")
	}
}

// TestAShortReadReportsOnlyWhatItTook.
//
// A Read smaller than the payload in front of it leaves the rest for the next call, and
// the credit has to follow the octets rather than the frame: reporting the payload would
// return window for content the handler has not looked at, which is the one direction
// flow control must not err in.
func TestAShortReadReportsOnlyWhatItTook(t *testing.T) {
	c := &creditLog{}
	b := newBody(1, c)
	b.add([]byte("abcdef"))

	if n, err := b.Read(make([]byte, 2)); n != 2 || err != nil {
		t.Fatalf("a 2-octet read of a 6-octet payload gave (%d, %v), want (2, nil)", n, err)
	}

	got := c.reports()
	if len(got) != 1 || got[0].n != 2 {
		t.Fatalf("a 2-octet read reported %v, want one report of 2 octets", got)
	}
}

// TestReadsThatConsumeNothingReportNothing.
//
// §6.9.1 makes a WINDOW_UPDATE with an increment of 0 a PROTOCOL_ERROR, so a read that
// took no octets must not become one. All three ways of taking none are here: io.Copy's
// habit of probing with an empty buffer, a read at the end of a body, and a read of a
// body the peer reset.
func TestReadsThatConsumeNothingReportNothing(t *testing.T) {
	c := &creditLog{}
	b := newBody(1, c)

	if n, err := b.Read(nil); n != 0 || err != nil {
		t.Fatalf("a zero-length read gave (%d, %v), want (0, nil)", n, err)
	}

	b.end(nil)
	if n, err := b.Read(make([]byte, 8)); n != 0 || err != io.EOF {
		t.Fatalf("a read at the end of a body gave (%d, %v), want (0, io.EOF)", n, err)
	}

	failed := newBody(1, c)
	failed.fail(errors.New("the peer reset the stream"))
	if n, _ := failed.Read(make([]byte, 8)); n != 0 {
		t.Fatalf("a read of a failed body took %d octets, want 0", n)
	}

	if got := c.reports(); len(got) != 0 {
		t.Errorf("reads that consumed nothing produced %d reports, want none: %v", len(got), got)
	}
}

// TestContentIsReportedWithTheLockReleased is the deadlock this file's design is arranged
// around, and the reason Read is split in two.
//
// Reporting puts a WINDOW_UPDATE on the connection's write queue, which a peer that has
// stopped reading its socket can block. b.mu is the lock the connection's reader
// goroutine takes to hand over the next payload, and that goroutine is also the one
// answering PING on every other stream of the connection. So a report made under this
// lock would let one stalled peer stop the connection it is stalling on — and the shape
// of that bug is a test that hangs, which is why the assertion is a deadline.
func TestContentIsReportedWithTheLockReleased(t *testing.T) {
	c := &blockingCredit{entered: make(chan struct{}), release: make(chan struct{})}
	b := newBody(1, c)
	b.add([]byte("aa"))

	go b.Read(make([]byte, 8))

	select {
	case <-c.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the read never reported the content it consumed")
	}
	defer close(c.release)

	// The reader goroutine's two calls, both of which must complete while the report is
	// still in progress.
	done := make(chan struct{})
	go func() {
		b.add([]byte("bb"))
		b.end(nil)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the connection's reader goroutine is blocked behind a report of consumed content")
	}
}

// blockingCredit is a bodyCredit that stops inside ReportConsumed until it is released,
// which is what a frame writer behind a peer that has stopped reading looks like.
type blockingCredit struct {
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (c *blockingCredit) ReportConsumed(uint32, int, bool) {
	c.once.Do(func() { close(c.entered) })
	<-c.release
}

// TestNewBodyRefusesToBeBuiltWithNowhereToReportTo.
//
// At construction, because the alternative is a nil dereference on the first read of the
// first upload large enough to need credit returned — a panic in a handler's goroutine,
// on whichever deployment happens to receive one.
func TestNewBodyRefusesToBeBuiltWithNowhereToReportTo(t *testing.T) {
	const want = "exchange: newBody requires somewhere to report consumed content"
	defer func() {
		if got := recover(); got != want {
			t.Errorf("newBody with a nil credit panicked with %v, want %q", got, want)
		}
	}()
	newBody(1, nil)
}
