package server

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"zerodeps/zdh/internal/frame"
	"zerodeps/zdh/internal/h2"
	"zerodeps/zdh/internal/limits"
	"zerodeps/zdh/internal/priority"
)

// --- helpers ---
//
// Every frame a test pushes carries a label in its payload, and the tests assert on
// the sequence of labels that comes out. Comparing labels rather than frames is what
// makes a failure readable: "1a 3a 1b" against "1a 1b 3a" says which participant lost
// a turn, where a diff of two frame structs says that something moved.

// dataOn is a DATA frame on a stream, labelled.
func dataOn(id uint32, label string) frame.DataFrame {
	return frame.DataFrame{StreamID: id, Data: []byte(label)}
}

// headersOn is a HEADERS frame that either completes its field block or does not.
func headersOn(id uint32, endHeaders bool, label string) frame.HeadersFrame {
	return frame.HeadersFrame{StreamID: id, EndHeaders: endHeaders, Fragment: []byte(label)}
}

// contOn is a CONTINUATION frame.
func contOn(id uint32, endHeaders bool, label string) frame.ContinuationFrame {
	return frame.ContinuationFrame{StreamID: id, EndHeaders: endHeaders, Fragment: []byte(label)}
}

// labelOf recovers what a test put in a frame. Every frame type that carries a
// payload this package puts a label in is here; anything else names its type, which
// is enough for the frames a test pushes one of.
func labelOf(f frame.Frame) string {
	switch v := f.(type) {
	case frame.DataFrame:
		return string(v.Data)
	case frame.HeadersFrame:
		return string(v.Fragment)
	case frame.ContinuationFrame:
		return string(v.Fragment)
	case frame.PushPromiseFrame:
		return string(v.Fragment)
	case frame.PingFrame:
		return fmt.Sprintf("ping%d", binary.BigEndian.Uint64(v.Data[:]))
	case frame.WindowUpdateFrame:
		return fmt.Sprintf("wu%d", v.StreamID)
	case frame.RSTStreamFrame:
		return fmt.Sprintf("rst%d", v.StreamID)
	case frame.SettingsFrame:
		return "settings"
	case frame.GoAwayFrame:
		return "goaway"
	default:
		return f.Type().String()
	}
}

// popAll drains the scheduler and returns the labels in the order they came out.
//
// It bounds itself, because the failure mode of a round robin that forgets to rotate
// is an infinite loop and a test that hangs says much less than a test that fails.
func popAll(t *testing.T, s *scheduler) string {
	t.Helper()

	var out []string
	for range 1 << 20 {
		f, ok := s.Pop()
		if !ok {
			return strings.Join(out, " ")
		}
		out = append(out, labelOf(f))
	}
	t.Fatalf("Pop kept returning frames after %d of them; the scheduler is not draining", 1<<20)
	return ""
}

// popN takes exactly n frames, failing if the scheduler runs out first.
func popN(t *testing.T, s *scheduler, n int) string {
	t.Helper()

	var out []string
	for i := range n {
		f, ok := s.Pop()
		if !ok {
			t.Fatalf("Pop = false after %d of %d frames; got %q", i, n, strings.Join(out, " "))
		}
		out = append(out, labelOf(f))
	}
	return strings.Join(out, " ")
}

// pushAll is the setup line most of these tests need.
func pushAll(s *scheduler, frames ...frame.Frame) {
	for _, f := range frames {
		s.Push(f)
	}
}

// urgency is a Params with only the urgency parameter set.
func urgency(u int) priority.Params {
	return priority.Params{}.WithUrgency(u)
}

// incremental is a Params with the urgency set and the incremental parameter true.
func incremental(u int) priority.Params {
	return priority.Params{}.WithUrgency(u).WithIncremental(true)
}

// assertDrained is the invariant every test ends on: nothing held, nothing
// remembered about a stream that has none, and no band still claiming a participant.
// A scheduler that reports the right order and leaks a ring entry has a slow failure
// rather than no failure.
func assertDrained(t *testing.T, s *scheduler) {
	t.Helper()

	if got := s.Len(); got != 0 {
		t.Errorf("Len() = %d after draining, want 0", got)
	}
	if got := len(s.lane); got != 0 {
		t.Errorf("%d items left in the lane after draining", got)
	}
	if got := len(s.pinned); got != 0 {
		t.Errorf("%d frames left pinned after draining", got)
	}
	if got := len(s.streams); got != 0 {
		t.Errorf("%d stream queues left after draining: %v", got, s.streams)
	}
	for u := range numBands {
		if got := len(s.bands[u].ring); got != 0 {
			t.Errorf("band %d still has %d participants after draining: %v",
				u, got, s.bands[u].ring)
		}
		if got := len(s.bands[u].nonInc); got != 0 {
			t.Errorf("band %d still has %d non-incremental streams after draining: %v",
				u, got, s.bands[u].nonInc)
		}
	}
}

// --- the empty and the trivial ---

func TestSchedulerEmpty(t *testing.T) {
	s := newScheduler()

	if f, ok := s.Pop(); ok {
		t.Errorf("Pop() = %v, true on a new scheduler; want false", f)
	}
	if got := s.Len(); got != 0 {
		t.Errorf("Len() = %d on a new scheduler, want 0", got)
	}
	assertDrained(t, s)
}

// TestSchedulerNonDataKeepsItsOrder is the half of the structure that does not
// reorder anything. Every one of these frames means something about the connection
// rather than about bandwidth, and two of them out of order — a SETTINGS
// acknowledgement after the GOAWAY that ends the connection — would be a worse
// connection, not a faster one.
func TestSchedulerNonDataKeepsItsOrder(t *testing.T) {
	s := newScheduler()
	pushAll(s,
		frame.SettingsFrame{Ack: true},
		ping(1),
		frame.WindowUpdateFrame{StreamID: 0, Increment: 100},
		frame.WindowUpdateFrame{StreamID: 3, Increment: 100},
		frame.RSTStreamFrame{StreamID: 5, ErrCode: h2.Cancel},
		ping(2),
		frame.GoAwayFrame{LastStreamID: 5, ErrCode: h2.NoError},
	)

	want := "settings ping1 wu0 wu3 rst5 ping2 goaway"
	if got := popAll(t, s); got != want {
		t.Errorf("order = %q, want %q", got, want)
	}
	assertDrained(t, s)
}

// TestSchedulerNonDataGoesBeforeData pins the lane split. The DATA frames were
// pushed first and go out last.
func TestSchedulerNonDataGoesBeforeData(t *testing.T) {
	s := newScheduler()
	pushAll(s,
		dataOn(1, "1a"),
		dataOn(1, "1b"),
		ping(7),
		frame.WindowUpdateFrame{StreamID: 0, Increment: 1},
	)

	want := "ping7 wu0 1a 1b"
	if got := popAll(t, s); got != want {
		t.Errorf("order = %q, want %q", got, want)
	}
	assertDrained(t, s)
}

func TestSchedulerLenCountsWhatCanBeWritten(t *testing.T) {
	s := newScheduler()

	for i, f := range []frame.Frame{ping(1), dataOn(1, "a"), dataOn(3, "b"), ping(2)} {
		s.Push(f)
		if got := s.Len(); got != i+1 {
			t.Fatalf("Len() = %d after %d pushes, want %d", got, i+1, i+1)
		}
	}
	for want := 3; want >= 0; want-- {
		if _, ok := s.Pop(); !ok {
			t.Fatalf("Pop() = false with %d frames still expected", want+1)
		}
		if got := s.Len(); got != want {
			t.Fatalf("Len() = %d, want %d", got, want)
		}
	}
	assertDrained(t, s)
}

// --- field blocks ---

// TestSchedulerHoldsAnIncompleteFieldBlock is the mechanism §4.3's contiguity rule is
// enforced by: until the block is complete there is nothing to write, and Pop says so
// rather than writing the front of it.
func TestSchedulerHoldsAnIncompleteFieldBlock(t *testing.T) {
	s := newScheduler()
	s.Push(headersOn(1, false, "h1"))

	if f, ok := s.Pop(); ok {
		t.Errorf("Pop() = %v, true with only an incomplete field block held; want false",
			labelOf(f))
	}
	if got := s.Len(); got != 0 {
		t.Errorf("Len() = %d with only an incomplete block held, want 0", got)
	}
	if got := s.blocked; got != 1 {
		t.Errorf("blocked = %d, want 1", got)
	}

	s.Push(contOn(1, false, "c1"))
	if _, ok := s.Pop(); ok {
		t.Error("Pop() = true with the block still incomplete")
	}
	if got := s.blocked; got != 2 {
		t.Errorf("blocked = %d after a second fragment, want 2", got)
	}

	s.Push(contOn(1, true, "c2"))
	if got := s.blocked; got != 0 {
		t.Errorf("blocked = %d once the block completed, want 0", got)
	}
	if got := s.Len(); got != 3 {
		t.Errorf("Len() = %d once the block completed, want 3", got)
	}

	want := "h1 c1 c2"
	if got := popAll(t, s); got != want {
		t.Errorf("order = %q, want %q", got, want)
	}
	assertDrained(t, s)
}

// TestSchedulerFieldBlockIsContiguous is the defect this structure exists to make
// impossible. The two PING frames were pushed between the fragments of one field
// block — which is what the reader goroutine does when a peer pings mid-response —
// and §4.3 makes writing them there a connection error. They come out in front of the
// whole block instead.
func TestSchedulerFieldBlockIsContiguous(t *testing.T) {
	s := newScheduler()
	pushAll(s,
		headersOn(1, false, "h"),
		ping(1),
		contOn(1, false, "c1"),
		ping(2),
		contOn(1, true, "c2"),
		ping(3),
	)

	want := "ping1 ping2 h c1 c2 ping3"
	if got := popAll(t, s); got != want {
		t.Errorf("order = %q, want %q\nthe field block must be contiguous and the frames "+
			"pushed inside it must be written outside it", got, want)
	}
	assertDrained(t, s)
}

// TestSchedulerPinnedBlockOutlastsLaterPushes closes the other half of contiguity: a
// block that has started coming out cannot be interrupted by something pushed while
// it is coming out. The reader goroutine can push at any moment, including between
// two of the writer's Pops.
func TestSchedulerPinnedBlockOutlastsLaterPushes(t *testing.T) {
	s := newScheduler()
	pushAll(s,
		headersOn(1, false, "h"),
		contOn(1, false, "c1"),
		contOn(1, true, "c2"),
	)

	if got := popN(t, s, 1); got != "h" {
		t.Fatalf("first Pop = %q, want %q", got, "h")
	}
	// Mid-block. Everything pushed here has to wait, whatever it is.
	pushAll(s, ping(1), dataOn(1, "1a"), frame.SettingsFrame{Ack: true})

	want := "c1 c2 ping1 settings 1a"
	if got := popAll(t, s); got != want {
		t.Errorf("order = %q, want %q", got, want)
	}
	assertDrained(t, s)
}

// TestSchedulerCompleteFieldBlockIsNotHeld is the common case, and the one that must
// not pay for the mechanism: a header section that fits in one frame is one item and
// is writable the moment it arrives.
func TestSchedulerCompleteFieldBlockIsNotHeld(t *testing.T) {
	s := newScheduler()
	s.Push(headersOn(1, true, "h"))

	if got := s.blocked; got != 0 {
		t.Errorf("blocked = %d for a block complete in its first frame, want 0", got)
	}
	if got := s.Len(); got != 1 {
		t.Errorf("Len() = %d, want 1", got)
	}
	if got := popAll(t, s); got != "h" {
		t.Errorf("order = %q, want %q", got, "h")
	}
	assertDrained(t, s)
}

// TestSchedulerIncompleteBlockIsNeverWritten is the shutdown case. The connection
// stops with a block half enqueued, and the half is dropped rather than sent: a peer
// that receives a HEADERS frame without END_HEADERS and then nothing has been handed
// a connection error by a server that was closing politely.
func TestSchedulerIncompleteBlockIsNeverWritten(t *testing.T) {
	s := newScheduler()
	pushAll(s,
		headersOn(1, true, "h1"),
		dataOn(1, "1a"),
		headersOn(3, false, "h3"), // the block that never completes
		contOn(3, false, "c3"),
		ping(1),
	)

	want := "h1 ping1 1a"
	if got := popAll(t, s); got != want {
		t.Errorf("order = %q, want %q", got, want)
	}
	if got := s.blocked; got != 2 {
		t.Errorf("blocked = %d, want 2: the incomplete block is still held", got)
	}
	if got := s.Len(); got != 0 {
		t.Errorf("Len() = %d, want 0: an incomplete block is not writable", got)
	}
	if _, ok := s.runs[3]; !ok {
		t.Error("the incomplete block for stream 3 was not retained")
	}
}

// TestSchedulerContinuesBlock pins the admission question. The writer's depth bound
// must not be applied to a frame that completes a block, and must be applied to
// everything else.
func TestSchedulerContinuesBlock(t *testing.T) {
	s := newScheduler()

	// Nothing open: a CONTINUATION is as ordinary as anything else.
	for _, f := range []frame.Frame{
		contOn(1, true, "c"),
		headersOn(1, false, "h"),
		dataOn(1, "d"),
		ping(1),
	} {
		if s.ContinuesBlock(f) {
			t.Errorf("ContinuesBlock(%s) = true with no block open", labelOf(f))
		}
	}

	s.Push(headersOn(1, false, "h"))

	if !s.ContinuesBlock(contOn(1, false, "c")) {
		t.Error("ContinuesBlock(CONTINUATION on stream 1) = false with stream 1's block open")
	}
	if !s.ContinuesBlock(contOn(1, true, "c")) {
		t.Error("ContinuesBlock(final CONTINUATION on stream 1) = false")
	}
	// The block is stream 1's. Nothing else gets past the bound on its account —
	// §6.10 makes a frame on a different stream the error, not an exception to it.
	for _, f := range []frame.Frame{
		contOn(3, true, "c"),
		dataOn(1, "d"),
		headersOn(1, true, "h"),
		ping(1),
	} {
		if s.ContinuesBlock(f) {
			t.Errorf("ContinuesBlock(%s) = true; only a CONTINUATION on the open stream "+
				"may bypass the depth bound", labelOf(f))
		}
	}

	s.Push(contOn(1, true, "c"))
	if s.ContinuesBlock(contOn(1, false, "c")) {
		t.Error("ContinuesBlock = true after the block closed")
	}
}

// TestSchedulerOrphanContinuationIsWritten is the deliberate non-recovery. A
// CONTINUATION with nothing to continue is a bug above this file, and §6.10 makes the
// peer report it precisely; inventing a repair here would hide the bug and produce a
// header block this server cannot account for.
func TestSchedulerOrphanContinuationIsWritten(t *testing.T) {
	s := newScheduler()
	pushAll(s, ping(1), contOn(1, true, "orphan"), ping(2))

	want := "ping1 orphan ping2"
	if got := popAll(t, s); got != want {
		t.Errorf("order = %q, want %q", got, want)
	}
	assertDrained(t, s)
}

// TestSchedulerPushPromiseOpensABlock covers the other frame §4.3 names as the start
// of a field block. This server does not push, so the case is unreachable today —
// which is the reason to pin it rather than to leave it to a future reader.
func TestSchedulerPushPromiseOpensABlock(t *testing.T) {
	s := newScheduler()
	pushAll(s,
		frame.PushPromiseFrame{StreamID: 1, PromisedID: 2, Fragment: []byte("pp")},
		ping(1),
		contOn(1, true, "c"),
	)

	want := "ping1 pp c"
	if got := popAll(t, s); got != want {
		t.Errorf("order = %q, want %q", got, want)
	}
	assertDrained(t, s)
}

// TestSchedulerTwoOpenBlocksDoNotInterleave is unreachable through internal/response,
// which holds one mutex across a whole burst, and is pinned because the structure
// must not corrupt if that ever stops being true. Each block comes out whole, in the
// order the blocks completed rather than the order they opened.
func TestSchedulerTwoOpenBlocksDoNotInterleave(t *testing.T) {
	s := newScheduler()
	pushAll(s,
		headersOn(1, false, "h1"),
		headersOn(3, false, "h3"),
		contOn(3, true, "c3"),
		contOn(1, true, "c1"),
	)

	want := "h3 c3 h1 c1"
	if got := popAll(t, s); got != want {
		t.Errorf("order = %q, want %q", got, want)
	}
	assertDrained(t, s)
}

// --- urgency ---

// TestSchedulerServesTheLowestUrgencyFirst is §10 of RFC 9218's first recommendation,
// and the reason the bands are an array indexed by urgency rather than a sorted list.
func TestSchedulerServesTheLowestUrgencyFirst(t *testing.T) {
	s := newScheduler()
	s.SetPriority(1, urgency(7))
	s.SetPriority(3, urgency(3))
	s.SetPriority(5, urgency(0))

	// Pushed worst-first, so a structure that ignored urgency would pass nothing.
	pushAll(s,
		dataOn(1, "u7a"), dataOn(1, "u7b"),
		dataOn(3, "u3a"), dataOn(3, "u3b"),
		dataOn(5, "u0a"), dataOn(5, "u0b"),
	)

	want := "u0a u0b u3a u3b u7a u7b"
	if got := popAll(t, s); got != want {
		t.Errorf("order = %q, want %q", got, want)
	}
	assertDrained(t, s)
}

// TestSchedulerDefaultUrgencyIsThree pins that a stream nobody signalled about lands
// where §4.1 of RFC 9218 puts it, between urgency 2 and urgency 4. It matters because
// the great majority of streams on a real connection are exactly that stream: a
// browser sends PRIORITY_UPDATE for some requests and no priority signal at all for
// the rest.
func TestSchedulerDefaultUrgencyIsThree(t *testing.T) {
	s := newScheduler()
	s.SetPriority(1, urgency(4))
	s.SetPriority(5, urgency(2))
	// Stream 3 is never mentioned.

	pushAll(s, dataOn(1, "u4"), dataOn(3, "default"), dataOn(5, "u2"))

	want := "u2 default u4"
	if got := popAll(t, s); got != want {
		t.Errorf("order = %q, want %q", got, want)
	}
	assertDrained(t, s)
}

// TestSchedulerNonIncrementalGoesInAscendingStreamID is §10 of RFC 9218's rule for
// the non-incremental case. Stream 5 was pushed first and is served last, because the
// order that matters is the order the client made the requests in and the stream
// identifier is the record of it.
func TestSchedulerNonIncrementalGoesInAscendingStreamID(t *testing.T) {
	s := newScheduler()
	pushAll(s,
		dataOn(5, "5a"), dataOn(5, "5b"),
		dataOn(1, "1a"), dataOn(1, "1b"),
		dataOn(3, "3a"), dataOn(3, "3b"),
	)

	want := "1a 1b 3a 3b 5a 5b"
	if got := popAll(t, s); got != want {
		t.Errorf("order = %q, want %q", got, want)
	}
	assertDrained(t, s)
}

// TestSchedulerNonIncrementalPicksUpANewLowerStream is the same rule under a client
// that keeps asking. A request that arrives while an earlier one is still being
// served gets a lower identifier than nothing and a higher one than the stream in
// progress, so it waits; a stream that goes quiet and comes back does not lose its
// place, because the place is its identifier.
func TestSchedulerNonIncrementalPicksUpANewLowerStream(t *testing.T) {
	s := newScheduler()
	pushAll(s, dataOn(3, "3a"), dataOn(3, "3b"), dataOn(5, "5a"))

	if got := popN(t, s, 1); got != "3a" {
		t.Fatalf("first = %q, want %q", got, "3a")
	}
	// Stream 1 arrives late and is still the lowest.
	s.Push(dataOn(1, "1a"))

	want := "1a 3b 5a"
	if got := popAll(t, s); got != want {
		t.Errorf("order = %q, want %q", got, want)
	}
	assertDrained(t, s)
}

// TestSchedulerIncrementalSharesBandwidth is §10 of RFC 9218's rule for the other
// case. Three incremental streams at one urgency get one turn each in rotation, which
// is the closest a frame-granular scheduler comes to sharing.
func TestSchedulerIncrementalSharesBandwidth(t *testing.T) {
	s := newScheduler()
	for _, id := range []uint32{1, 3, 5} {
		s.SetPriority(id, incremental(3))
	}
	for _, id := range []uint32{1, 3, 5} {
		for _, n := range []string{"a", "b", "c"} {
			s.Push(dataOn(id, fmt.Sprintf("%d%s", id, n)))
		}
	}

	want := "1a 3a 5a 1b 3b 5b 1c 3c 5c"
	if got := popAll(t, s); got != want {
		t.Errorf("order = %q, want %q", got, want)
	}
	assertDrained(t, s)
}

// TestSchedulerIncrementalRotationSurvivesAStreamEnding checks the bookkeeping the
// round robin is most likely to get wrong: a participant leaving mid-rotation must
// not cost the next participant its turn, which is what an index cursor into a
// shrinking slice does.
func TestSchedulerIncrementalRotationSurvivesAStreamEnding(t *testing.T) {
	s := newScheduler()
	for _, id := range []uint32{1, 3, 5} {
		s.SetPriority(id, incremental(3))
	}
	pushAll(s,
		dataOn(1, "1a"), dataOn(1, "1b"),
		dataOn(3, "3a"), // stream 3 has one frame and leaves after it
		dataOn(5, "5a"), dataOn(5, "5b"),
	)

	want := "1a 3a 5a 1b 5b"
	if got := popAll(t, s); got != want {
		t.Errorf("order = %q, want %q", got, want)
	}
	assertDrained(t, s)
}

// TestSchedulerNonIncrementalGroupIsOneParticipant is the local policy decision, and
// the test exists to make it a decision rather than an accident. Three non-incremental
// streams and one incremental stream at the same urgency make two participants, not
// four: the incremental stream gets half the turns.
func TestSchedulerNonIncrementalGroupIsOneParticipant(t *testing.T) {
	s := newScheduler()
	s.SetPriority(7, incremental(3))

	for _, id := range []uint32{1, 3, 5} {
		s.Push(dataOn(id, fmt.Sprintf("%da", id)))
		s.Push(dataOn(id, fmt.Sprintf("%db", id)))
	}
	for _, n := range []string{"a", "b", "c"} {
		s.Push(dataOn(7, "7"+n))
	}

	want := "1a 7a 1b 7b 3a 7c 3b 5a 5b"
	if got := popAll(t, s); got != want {
		t.Errorf("order = %q, want %q", got, want)
	}
	assertDrained(t, s)
}

// TestSchedulerAvoidsTheStarvationRFC9218Names runs the two shapes §10 of RFC 9218
// gives as examples of what strict ordering gets wrong, and asserts that neither
// response has to wait for the other to finish.
func TestSchedulerAvoidsTheStarvationRFC9218Names(t *testing.T) {
	// §10 of RFC 9218: "At the same urgency level, a non-incremental request for a
	// large resource followed by an incremental request for a small resource."
	t.Run("large non-incremental, then small incremental", func(t *testing.T) {
		s := newScheduler()
		for i := range 20 {
			s.Push(dataOn(1, fmt.Sprintf("large%d", i)))
		}
		s.SetPriority(3, incremental(3))
		s.Push(dataOn(3, "small0"))
		s.Push(dataOn(3, "small1"))

		got := popN(t, s, 4)
		if want := "large0 small0 large1 small1"; got != want {
			t.Errorf("first four = %q, want %q\nthe small incremental response must not "+
				"wait for the large non-incremental one", got, want)
		}
	})

	// §10 of RFC 9218: "At the same urgency level, an incremental request of
	// indeterminate length followed by a non-incremental large resource."
	t.Run("endless incremental, then large non-incremental", func(t *testing.T) {
		s := newScheduler()
		s.SetPriority(1, incremental(3))
		for i := range 20 {
			s.Push(dataOn(1, fmt.Sprintf("endless%d", i)))
		}
		for i := range 20 {
			s.Push(dataOn(3, fmt.Sprintf("large%d", i)))
		}

		got := popN(t, s, 4)
		if want := "endless0 large0 endless1 large1"; got != want {
			t.Errorf("first four = %q, want %q\nthe non-incremental response must make "+
				"progress against a stream of indeterminate length", got, want)
		}
	})
}

// TestSchedulerLowerBandPreempts is the part of urgency that a batch reordering would
// miss. A high-urgency response that arrives while a lower-urgency one is being
// written goes next, not after.
func TestSchedulerLowerBandPreempts(t *testing.T) {
	s := newScheduler()
	for i := range 5 {
		s.Push(dataOn(1, fmt.Sprintf("slow%d", i)))
	}
	if got := popN(t, s, 2); got != "slow0 slow1" {
		t.Fatalf("first two = %q, want %q", got, "slow0 slow1")
	}

	s.SetPriority(3, urgency(0))
	s.Push(dataOn(3, "urgent"))

	want := "urgent slow2 slow3 slow4"
	if got := popAll(t, s); got != want {
		t.Errorf("order = %q, want %q", got, want)
	}
	assertDrained(t, s)
}

// TestSchedulerBandsKeepSeparateRotations pins that the round robin is per urgency. A
// band that is drained, left empty, and refilled resumes from wherever its own
// rotation was, and is not affected by the other bands that ran in between.
func TestSchedulerBandsKeepSeparateRotations(t *testing.T) {
	s := newScheduler()
	for _, id := range []uint32{1, 3} {
		s.SetPriority(id, incremental(5))
	}
	for _, id := range []uint32{5, 7} {
		s.SetPriority(id, incremental(1))
	}

	pushAll(s,
		dataOn(1, "lo1"), dataOn(3, "lo3"),
		dataOn(5, "hi5"), dataOn(7, "hi7"),
	)

	// Band 1 first, in its own rotation; then band 5, in its own.
	want := "hi5 hi7 lo1 lo3"
	if got := popAll(t, s); got != want {
		t.Errorf("order = %q, want %q", got, want)
	}
	assertDrained(t, s)
}

// --- reprioritization ---

// TestSchedulerSetPriorityMovesQueuedData is the difference between a priority signal
// that applies and one that applies to the next response. §7 of RFC 9218 lets a
// client reprioritize a stream at any point, and a stream that has been reading a
// large file has its next frames here.
func TestSchedulerSetPriorityMovesQueuedData(t *testing.T) {
	s := newScheduler()
	s.SetPriority(3, urgency(1))
	pushAll(s,
		dataOn(1, "1a"), dataOn(1, "1b"),
		dataOn(3, "3a"), dataOn(3, "3b"),
	)

	// Stream 1 is at the default urgency 3 and would go second.
	s.SetPriority(1, urgency(0))

	want := "1a 1b 3a 3b"
	if got := popAll(t, s); got != want {
		t.Errorf("order = %q, want %q", got, want)
	}
	assertDrained(t, s)
}

// TestSchedulerSetPriorityChangesTheParticipantKind is the bookkeeping half: a stream
// that becomes incremental has to leave the non-incremental group and take a turn of
// its own, and the group has to lose its turn when it loses its last member.
func TestSchedulerSetPriorityChangesTheParticipantKind(t *testing.T) {
	s := newScheduler()
	pushAll(s, dataOn(1, "1a"), dataOn(1, "1b"), dataOn(3, "3a"), dataOn(3, "3b"))

	// Both non-incremental: one participant, so stream 1 drains first.
	if got := popN(t, s, 1); got != "1a" {
		t.Fatalf("first = %q, want %q", got, "1a")
	}

	s.SetPriority(1, incremental(3))
	s.SetPriority(3, incremental(3))
	if got := len(s.bands[3].nonInc); got != 0 {
		t.Errorf("band 3 still has %d non-incremental streams, want 0", got)
	}
	if got := len(s.bands[3].ring); got != 2 {
		t.Errorf("band 3 ring = %v, want two participants", s.bands[3].ring)
	}

	want := "1b 3a 3b"
	if got := popAll(t, s); got != want {
		t.Errorf("order = %q, want %q", got, want)
	}
	assertDrained(t, s)
}

// TestSchedulerSetPriorityToTheSameValueChangesNothing matters because a client may
// send the same PRIORITY_UPDATE repeatedly, and a reprioritization sends the stream to
// the back of its ring. A signal that says nothing new must not cost a turn, or a
// client could be punished for repeating itself.
func TestSchedulerSetPriorityToTheSameValueChangesNothing(t *testing.T) {
	s := newScheduler()
	for _, id := range []uint32{1, 3} {
		s.SetPriority(id, incremental(3))
	}
	pushAll(s, dataOn(1, "1a"), dataOn(1, "1b"), dataOn(3, "3a"), dataOn(3, "3b"))

	for range 100 {
		s.SetPriority(1, incremental(3))
		s.SetPriority(3, incremental(3))
	}

	want := "1a 3a 1b 3b"
	if got := popAll(t, s); got != want {
		t.Errorf("order = %q, want %q", got, want)
	}
	assertDrained(t, s)
}

// TestSchedulerSetPriorityForStreamZeroIsIgnored guards the sentinel. A
// PRIORITY_UPDATE naming stream 0 is refused long before here, and if one ever
// reached this far it must not be recorded — the identifier means the whole
// non-incremental group in the rings.
func TestSchedulerSetPriorityForStreamZeroIsIgnored(t *testing.T) {
	s := newScheduler()
	s.SetPriority(0, urgency(0))

	if got := len(s.prio); got != 0 {
		t.Errorf("prio = %v after SetPriority(0, ...), want it untouched", s.prio)
	}
}

// TestSchedulerForgetBoundsThePriorityTable is the only bound on that map. A
// connection may serve a million requests, each with its own priority signal, and
// none of them is remembered once the stream is finished.
func TestSchedulerForgetBoundsThePriorityTable(t *testing.T) {
	s := newScheduler()

	const rounds = 10000
	for i := range uint32(rounds) {
		id := 1 + 2*i
		s.SetPriority(id, incremental(int(i%8)))
		s.Push(dataOn(id, "x"))
		if _, ok := s.Pop(); !ok {
			t.Fatalf("Pop() = false on round %d", i)
		}
		s.Forget(id)
	}

	if got := len(s.prio); got != 0 {
		t.Errorf("prio holds %d entries after %d streams came and went, want 0", got, rounds)
	}
	assertDrained(t, s)
}

// TestSchedulerForgetLeavesQueuedDataScheduled pins the ordering hazard in Forget: the
// stream's classification is recorded on its queue, not looked up on each Pop, so
// forgetting the signal while frames are still waiting cannot move them out from under
// the ring they are in.
func TestSchedulerForgetLeavesQueuedDataScheduled(t *testing.T) {
	s := newScheduler()
	s.SetPriority(1, incremental(7))
	s.SetPriority(3, incremental(7))
	pushAll(s, dataOn(1, "1a"), dataOn(1, "1b"), dataOn(3, "3a"), dataOn(3, "3b"))

	s.Forget(1)
	s.Forget(3)

	// Still urgency 7, still incremental, still sharing: the queues remember.
	want := "1a 3a 1b 3b"
	if got := popAll(t, s); got != want {
		t.Errorf("order = %q, want %q", got, want)
	}
	assertDrained(t, s)
}

// --- a stream's own order ---

// TestSchedulerTrailersFollowTheirOwnData is the case that decides whether the lane
// split is safe. A trailer section is a field block, so it is in the FIFO lane, and
// the lane is written first — but §8.1 puts a trailer section after the content, so
// the stream's queued DATA has to go out in front of it.
func TestSchedulerTrailersFollowTheirOwnData(t *testing.T) {
	s := newScheduler()
	pushAll(s,
		headersOn(1, true, "head"),
		dataOn(1, "1a"), dataOn(1, "1b"),
		headersOn(1, true, "trailers"),
	)

	want := "head 1a 1b trailers"
	if got := popAll(t, s); got != want {
		t.Errorf("order = %q, want %q", got, want)
	}
	assertDrained(t, s)
}

// TestSchedulerMultiFrameTrailerBlockFollowsItsData is the same case with the trailer
// section spread over CONTINUATION frames, so that both rules apply at once: the DATA
// goes first, and then the block goes out whole.
func TestSchedulerMultiFrameTrailerBlockFollowsItsData(t *testing.T) {
	s := newScheduler()
	pushAll(s,
		dataOn(1, "1a"), dataOn(1, "1b"),
		headersOn(1, false, "t0"),
		contOn(1, true, "t1"),
		ping(1),
	)

	want := "1a 1b t0 t1 ping1"
	if got := popAll(t, s); got != want {
		t.Errorf("order = %q, want %q", got, want)
	}
	assertDrained(t, s)
}

// TestSchedulerResetFollowsItsOwnData is the other frame whose order against a
// stream's content matters. §5.1 closes a stream on RST_STREAM, so DATA written after
// one is DATA on a closed stream — a frame the peer is entitled to answer with a
// connection error.
func TestSchedulerResetFollowsItsOwnData(t *testing.T) {
	s := newScheduler()
	pushAll(s,
		dataOn(1, "1a"), dataOn(1, "1b"),
		frame.RSTStreamFrame{StreamID: 1, ErrCode: h2.InternalError},
	)

	want := "1a 1b rst1"
	if got := popAll(t, s); got != want {
		t.Errorf("order = %q, want %q", got, want)
	}
	assertDrained(t, s)
}

// TestSchedulerOutOfTurnDataIsOnlyTheBlockedStreams pins the cost of the rule above,
// because it does have one: the DATA that goes out early is that one stream's, and no
// other stream's turn is spent on it. Stream 3 is at urgency 0 and stream 1 at
// urgency 7, so a rule that flushed more than it had to would be visible here.
func TestSchedulerOutOfTurnDataIsOnlyTheBlockedStreams(t *testing.T) {
	s := newScheduler()
	s.SetPriority(1, urgency(7))
	s.SetPriority(5, urgency(7))
	s.SetPriority(3, urgency(0))

	pushAll(s,
		dataOn(1, "1a"), dataOn(1, "1b"),
		dataOn(5, "5a"),
		dataOn(3, "3a"),
		headersOn(1, true, "trailers1"),
	)

	// Stream 1's two frames are forced out ahead of the urgency 0 stream because its
	// trailer section is at the head of the lane. Stream 5 shares stream 1's urgency
	// and its band, and is not dragged along.
	want := "1a 1b trailers1 3a 5a"
	if got := popAll(t, s); got != want {
		t.Errorf("order = %q, want %q", got, want)
	}
	assertDrained(t, s)
}

// TestSchedulerOutOfTurnKeepsTheRingIntact is the bookkeeping under the same rule: a
// stream drained out of turn has to leave its band exactly as it would have if it had
// been drained in turn, or the band keeps claiming a participant that has nothing.
func TestSchedulerOutOfTurnKeepsTheRingIntact(t *testing.T) {
	s := newScheduler()
	s.SetPriority(1, incremental(3))
	s.SetPriority(3, incremental(3))

	pushAll(s,
		dataOn(1, "1a"),
		dataOn(3, "3a"), dataOn(3, "3b"),
		frame.RSTStreamFrame{StreamID: 1, ErrCode: h2.Cancel},
	)

	if got := popN(t, s, 2); got != "1a rst1" {
		t.Fatalf("first two = %q, want %q", got, "1a rst1")
	}
	if got := len(s.bands[3].ring); got != 1 {
		t.Errorf("band 3 ring = %v after stream 1 drained out of turn, want just stream 3",
			s.bands[3].ring)
	}

	want := "3a 3b"
	if got := popAll(t, s); got != want {
		t.Errorf("order = %q, want %q", got, want)
	}
	assertDrained(t, s)
}

// TestSchedulerLaneFrameForAStreamWithLaterData is the mirror of the trailer case, and
// the one that must not force anything: HEADERS pushed before a stream's DATA is
// already in front of it, so the lane is written as the lane and no DATA jumps.
func TestSchedulerLaneFrameForAStreamWithLaterData(t *testing.T) {
	s := newScheduler()
	s.SetPriority(1, urgency(7))
	s.SetPriority(3, urgency(0))

	pushAll(s,
		headersOn(1, true, "head1"),
		dataOn(1, "1a"),
		headersOn(3, true, "head3"),
		dataOn(3, "3a"),
	)

	want := "head1 head3 3a 1a"
	if got := popAll(t, s); got != want {
		t.Errorf("order = %q, want %q", got, want)
	}
	assertDrained(t, s)
}

// --- the shapes that should not happen ---

// TestSchedulerDataOnStreamZeroIsNotBanded routes an impossible frame. §6.1 requires
// that "DATA frames MUST be associated with a stream", frame.Writer refuses this one,
// and the point of the test is that the bands are not corrupted on the way to that
// refusal — nonIncrementalTurn means the group, and a stream 0 participant would make
// it mean two things.
func TestSchedulerDataOnStreamZeroIsNotBanded(t *testing.T) {
	s := newScheduler()
	pushAll(s, dataOn(0, "bad"), dataOn(1, "1a"))

	for u := range numBands {
		for _, id := range s.bands[u].ring {
			if id == nonIncrementalTurn && u != 3 {
				t.Errorf("band %d claims the non-incremental group; only stream 1's band "+
					"should", u)
			}
		}
	}
	if got := len(s.bands[3].nonInc); got != 1 || s.bands[3].nonInc[0] != 1 {
		t.Errorf("band 3 non-incremental = %v, want just stream 1", s.bands[3].nonInc)
	}

	want := "bad 1a"
	if got := popAll(t, s); got != want {
		t.Errorf("order = %q, want %q", got, want)
	}
	assertDrained(t, s)
}

// TestSchedulerHighestStreamIdentifier walks the top of the client-initiated stream
// space, where a uint32 held as an int or compared in a signed type goes wrong. §5.1.1
// makes 2^31-1 the largest a client can open.
func TestSchedulerHighestStreamIdentifier(t *testing.T) {
	s := newScheduler()
	const top = uint32(1<<31 - 1)

	pushAll(s, dataOn(top, "top"), dataOn(top-2, "next"), dataOn(1, "first"))

	want := "first next top"
	if got := popAll(t, s); got != want {
		t.Errorf("order = %q, want %q", got, want)
	}
	assertDrained(t, s)
}

// --- scale ---

// TestSchedulerUnderTheWorstClient is the adversarial shape: every stream this server
// will admit, all of them at once, in every combination of urgency and incrementality,
// with the priorities changing under the queue as it drains. Nothing may be lost,
// duplicated, or delivered out of order within its own stream, and the structure must
// end empty.
func TestSchedulerUnderTheWorstClient(t *testing.T) {
	const streams = limits.MaxConcurrentStreams
	const perStream = 8

	s := newScheduler()
	for i := range uint32(streams) {
		id := 1 + 2*i
		if i%3 == 0 {
			s.SetPriority(id, incremental(int(i%8)))
		} else {
			s.SetPriority(id, urgency(int(i%8)))
		}
	}
	for n := range perStream {
		for i := range uint32(streams) {
			id := 1 + 2*i
			s.Push(dataOn(id, fmt.Sprintf("%d:%d", id, n)))
		}
	}
	if got, want := s.Len(), streams*perStream; got != want {
		t.Fatalf("Len() = %d, want %d", got, want)
	}

	// Drain, reprioritizing constantly. A client is allowed to do this, and the
	// bookkeeping between the bands and the queues is what it stresses.
	seen := make(map[uint32]int, streams)
	for popped := 0; ; popped++ {
		if popped%7 == 0 {
			id := uint32(1 + 2*(popped%streams))
			if popped%14 == 0 {
				s.SetPriority(id, incremental(popped%8))
			} else {
				s.SetPriority(id, urgency(popped%8))
			}
		}
		f, ok := s.Pop()
		if !ok {
			break
		}
		var id uint32
		var n int
		if _, err := fmt.Sscanf(labelOf(f), "%d:%d", &id, &n); err != nil {
			t.Fatalf("unreadable label %q: %v", labelOf(f), err)
		}
		if n != seen[id] {
			t.Fatalf("stream %d delivered frame %d after %d; a stream's own frames must "+
				"stay in order", id, n, seen[id]-1)
		}
		seen[id] = n + 1
	}

	if got := len(seen); got != streams {
		t.Errorf("%d streams were served, want %d", got, streams)
	}
	for id, n := range seen {
		if n != perStream {
			t.Errorf("stream %d delivered %d frames, want %d", id, n, perStream)
		}
	}
	assertDrained(t, s)
}

// TestSchedulerRespectsUrgencyUnderTheWorstClient is the property the previous test
// does not check: that at no point is a frame served from a band while a lower band
// has one waiting. Nothing is reprioritized here, because the property is only well
// defined when the bands hold still.
func TestSchedulerRespectsUrgencyUnderTheWorstClient(t *testing.T) {
	const streams = limits.MaxConcurrentStreams
	const perStream = 8

	s := newScheduler()
	band := make(map[uint32]int, streams)
	for i := range uint32(streams) {
		id := 1 + 2*i
		u := int(i % 8)
		band[id] = u
		if i%2 == 0 {
			s.SetPriority(id, incremental(u))
		} else {
			s.SetPriority(id, urgency(u))
		}
	}
	for range perStream {
		for i := range uint32(streams) {
			id := 1 + 2*i
			s.Push(dataOn(id, fmt.Sprintf("%d", id)))
		}
	}

	worst := 0
	for {
		f, ok := s.Pop()
		if !ok {
			break
		}
		u := band[f.Stream()]
		if u < worst {
			t.Fatalf("stream %d at urgency %d was served after urgency %d had begun; "+
				"a lower band must be emptied first", f.Stream(), u, worst)
		}
		worst = u
	}
	if worst != 7 {
		t.Errorf("the last frame served was at urgency %d, want 7", worst)
	}
	assertDrained(t, s)
}

// TestSchedulerDoesNotGrowOverAConnectionsLife is the leak test. A long connection
// pushes and pops millions of frames through the same structure, and every slice and
// map in it has to return to its floor — the rings especially, because a round robin
// that reslices off the front walks forward through its array forever.
func TestSchedulerDoesNotGrowOverAConnectionsLife(t *testing.T) {
	s := newScheduler()

	const rounds = 20000
	for i := range uint32(rounds) {
		id := 1 + 2*(i%64)
		s.SetPriority(id, incremental(int(i%8)))
		s.Push(headersOn(id, true, "h"))
		s.Push(dataOn(id, "d"))
		s.Push(frame.RSTStreamFrame{StreamID: id, ErrCode: h2.NoError})
		s.Push(ping(uint64(i)))
		// The PING is last because it was pushed last, and the DATA precedes the
		// RST_STREAM because the reset closes the stream it belongs to.
		want := fmt.Sprintf("h d rst%d ping%d", id, i)
		if got := popAll(t, s); got != want {
			t.Fatalf("round %d order = %q, want %q", i, got, want)
		}
		s.Forget(id)
	}

	if got := cap(s.lane); got > 16 {
		t.Errorf("cap(lane) = %d after %d rounds; the lane is growing", got, rounds)
	}
	for u := range numBands {
		if got := cap(s.bands[u].ring); got > 16 {
			t.Errorf("cap(bands[%d].ring) = %d after %d rounds; the ring is growing",
				u, got, rounds)
		}
		if got := cap(s.bands[u].nonInc); got > 16 {
			t.Errorf("cap(bands[%d].nonInc) = %d after %d rounds", u, got, rounds)
		}
	}
	if got := len(s.prio); got != 0 {
		t.Errorf("prio holds %d entries, want 0", got)
	}
	if got := len(s.runs); got != 0 {
		t.Errorf("runs holds %d entries, want 0", got)
	}
	assertDrained(t, s)
}

// TestSchedulerNothingIsLostUnderAnArbitrarySequence drives the structure with a
// deterministic pseudo-random mix of every operation and checks the two properties
// that hold whatever the order: every frame comes out exactly once, and a stream's
// frames come out in the order they went in.
//
// The generator is four lines of arithmetic rather than a call to math/rand, so that a
// failure reproduces from the seed printed in this file and from nothing else.
func TestSchedulerNothingIsLostUnderAnArbitrarySequence(t *testing.T) {
	const seed = 0x5eed5eed5eed5eed

	state := uint64(seed)
	next := func(n int) int {
		// A 64-bit xorshift. Every constant is from Marsaglia's paper.
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		return int(state % uint64(n))
	}

	s := newScheduler()
	pushed := make(map[uint32]int)
	popped := make(map[uint32]int)
	live := make(map[uint32]bool)

	for range 200000 {
		switch next(10) {
		case 0, 1, 2, 3, 4, 5:
			id := uint32(1 + 2*next(32))
			s.Push(dataOn(id, fmt.Sprintf("%d:%d", id, pushed[id])))
			pushed[id]++
			live[id] = true
		case 6:
			id := uint32(1 + 2*next(32))
			if next(2) == 0 {
				s.SetPriority(id, incremental(next(8)))
			} else {
				s.SetPriority(id, urgency(next(8)))
			}
		case 7:
			s.Forget(uint32(1 + 2*next(32)))
		case 8:
			s.Push(ping(uint64(next(1000))))
		case 9:
			for range 1 + next(4) {
				f, ok := s.Pop()
				if !ok {
					break
				}
				if f.Type() != frame.TypeData {
					continue
				}
				var id uint32
				var n int
				if _, err := fmt.Sscanf(labelOf(f), "%d:%d", &id, &n); err != nil {
					t.Fatalf("unreadable label %q: %v", labelOf(f), err)
				}
				if n != popped[id] {
					t.Fatalf("stream %d delivered frame %d after %d", id, n, popped[id]-1)
				}
				popped[id] = n + 1
			}
		}
	}

	// Drain what is left, then account for every frame that was ever pushed.
	for {
		f, ok := s.Pop()
		if !ok {
			break
		}
		if f.Type() != frame.TypeData {
			continue
		}
		var id uint32
		var n int
		if _, err := fmt.Sscanf(labelOf(f), "%d:%d", &id, &n); err != nil {
			t.Fatalf("unreadable label %q: %v", labelOf(f), err)
		}
		if n != popped[id] {
			t.Fatalf("stream %d delivered frame %d after %d", id, n, popped[id]-1)
		}
		popped[id] = n + 1
	}

	for id := range live {
		if pushed[id] != popped[id] {
			t.Errorf("stream %d: %d frames pushed, %d popped", id, pushed[id], popped[id])
		}
	}
	assertDrained(t, s)
}

// --- the pieces ---

func TestLowest(t *testing.T) {
	for _, tt := range []struct {
		ids  []uint32
		want uint32
	}{
		{[]uint32{7}, 7},
		{[]uint32{1, 3, 5}, 1},
		{[]uint32{5, 3, 1}, 1},
		{[]uint32{3, 1, 5}, 1},
		{[]uint32{1<<31 - 1, 1<<31 - 3}, 1<<31 - 3},
		{[]uint32{1<<31 - 1, 1}, 1},
	} {
		if got := lowest(tt.ids); got != tt.want {
			t.Errorf("lowest(%v) = %d, want %d", tt.ids, got, tt.want)
		}
	}
}

func TestRotate(t *testing.T) {
	for _, tt := range []struct {
		in, want []uint32
	}{
		{nil, nil},
		{[]uint32{}, []uint32{}},
		{[]uint32{1}, []uint32{1}},
		{[]uint32{1, 3}, []uint32{3, 1}},
		{[]uint32{1, 3, 5}, []uint32{3, 5, 1}},
		{[]uint32{0, 3, 5, 7}, []uint32{3, 5, 7, 0}},
	} {
		got := append([]uint32(nil), tt.in...)
		rotate(got)
		if len(got) != len(tt.want) {
			t.Fatalf("rotate(%v) changed the length to %d", tt.in, len(got))
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("rotate(%v) = %v, want %v", tt.in, got, tt.want)
				break
			}
		}
	}

	// A full rotation returns the ring to where it started, which is what makes it a
	// rotation rather than a shuffle.
	ring := []uint32{1, 3, 5, 7, 9}
	for range len(ring) {
		rotate(ring)
	}
	for i, want := range []uint32{1, 3, 5, 7, 9} {
		if ring[i] != want {
			t.Errorf("after a full rotation ring = %v, want the original order", ring)
			break
		}
	}
}

func TestRemoveID(t *testing.T) {
	for _, tt := range []struct {
		in   []uint32
		id   uint32
		want []uint32
	}{
		{[]uint32{1, 3, 5}, 1, []uint32{3, 5}},
		{[]uint32{1, 3, 5}, 3, []uint32{1, 5}},
		{[]uint32{1, 3, 5}, 5, []uint32{1, 3}},
		{[]uint32{1}, 1, []uint32{}},
		{[]uint32{1, 3, 5}, 7, []uint32{1, 3, 5}}, // absent is a no-op
		{nil, 1, nil},
		{[]uint32{0, 1}, 0, []uint32{1}}, // the non-incremental sentinel
	} {
		got := removeID(append([]uint32(nil), tt.in...), tt.id)
		if len(got) != len(tt.want) {
			t.Errorf("removeID(%v, %d) = %v, want %v", tt.in, tt.id, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("removeID(%v, %d) = %v, want %v", tt.in, tt.id, got, tt.want)
				break
			}
		}
	}
}

// TestRemoveItemReleasesTheVacatedEntry is a retention test, not an ordering one. An
// item holds a slice of frames and each frame holds its payload, so an entry left
// behind past the length keeps a whole field block alive for as long as the
// connection's lane exists.
func TestRemoveItemReleasesTheVacatedEntry(t *testing.T) {
	items := []item{
		{frames: []frame.Frame{ping(1)}, seq: 1},
		{frames: []frame.Frame{ping(2)}, seq: 2},
		{frames: []frame.Frame{ping(3)}, seq: 3},
	}
	full := items[:3:3]

	items = removeItem(items, 0)
	if len(items) != 2 {
		t.Fatalf("len = %d after removing one of three, want 2", len(items))
	}
	if labelOf(items[0].frames[0]) != "ping2" || labelOf(items[1].frames[0]) != "ping3" {
		t.Errorf("order = %q %q, want ping2 ping3",
			labelOf(items[0].frames[0]), labelOf(items[1].frames[0]))
	}
	if full[2].frames != nil {
		t.Errorf("the vacated entry still holds %d frames", len(full[2].frames))
	}
	if full[2].seq != 0 {
		t.Errorf("the vacated entry still holds seq %d", full[2].seq)
	}
}

// TestOpensAndEndsBlock covers the two predicates the field block machinery turns on,
// including the frame types that carry the END_HEADERS flag and the ones that do not.
func TestOpensAndEndsBlock(t *testing.T) {
	for _, tt := range []struct {
		f          frame.Frame
		opens, end bool
	}{
		{headersOn(1, false, ""), true, false},
		{headersOn(1, true, ""), false, true},
		{contOn(1, false, ""), false, false},
		{contOn(1, true, ""), false, true},
		{frame.PushPromiseFrame{StreamID: 1, PromisedID: 2}, true, false},
		{frame.PushPromiseFrame{StreamID: 1, PromisedID: 2, EndHeaders: true}, false, true},
		{dataOn(1, ""), false, false},
		{ping(1), false, false},
		{frame.SettingsFrame{Ack: true}, false, false},
		{frame.RSTStreamFrame{StreamID: 1}, false, false},
		{frame.WindowUpdateFrame{StreamID: 1, Increment: 1}, false, false},
		{frame.GoAwayFrame{}, false, false},
	} {
		if got := opensBlock(tt.f); got != tt.opens {
			t.Errorf("opensBlock(%s, flags %#x) = %v, want %v",
				tt.f.Type(), uint8(tt.f.Flags()), got, tt.opens)
		}
		if got := endsBlock(tt.f); got != tt.end {
			t.Errorf("endsBlock(%s, flags %#x) = %v, want %v",
				tt.f.Type(), uint8(tt.f.Flags()), got, tt.end)
		}
	}
}
