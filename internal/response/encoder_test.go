package response

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"zerodeps/zdh/internal/frame"
	"zerodeps/zdh/internal/h2"
)

// --- the shape of one response ---

func TestABodylessResponseIsOneHeadersFrameThatEndsTheStream(t *testing.T) {
	enc, c, tr := newEncoder()

	if err := enc.WriteHeaders(1, okFields(), true); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}

	fs := tr.taken()
	if len(fs) != 1 {
		t.Fatalf("%d frames enqueued, want 1", len(fs))
	}
	block := checkBlock(t, fs, 1, true, maxFrame)
	if want := c.encodes[0]; len(want) != 1 || want[0] != status("200") {
		t.Errorf("the codec was given %v, want just a :status", want)
	}
	if got, want := string(block), ":status=200\n"; got != want {
		t.Errorf("the frames carry %q, want the encoded block %q", got, want)
	}
}

func TestAResponseWithABodyLeavesEndStreamClear(t *testing.T) {
	enc, _, tr := newEncoder()

	if err := enc.WriteHeaders(3, okFields(), false); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}
	checkBlock(t, tr.taken(), 3, false, maxFrame)
}

func TestAnEmptyBlockStillProducesOneHeadersFrame(t *testing.T) {
	// A codec is entitled to produce nothing: every field of a short response can
	// already be in the static table as an indexed pair, and a dynamic table size
	// update is the only thing that must be emitted and need not be. What must not
	// happen is that "the block is empty" becomes "there is no response".
	enc, c, tr := newEncoder()
	c.block = func(int, []h2.Field) []byte { return nil }

	if err := enc.WriteHeaders(1, okFields(), true); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}

	fs := tr.taken()
	if len(fs) != 1 {
		t.Fatalf("%d frames enqueued for an empty block, want 1", len(fs))
	}
	if block := checkBlock(t, fs, 1, true, maxFrame); len(block) != 0 {
		t.Errorf("the frame carries %d octets, want none", len(block))
	}
}

// --- the split, and the cap it is measured against ---

// filler is a block of n octets, every one of them tag, so that a fragment can be
// recognised after the block has been cut up and reassembled from several frames.
func filler(n int, tag byte) []byte { return bytes.Repeat([]byte{tag}, n) }

func TestABlockIsSplitAtThePeersFrameSizeCap(t *testing.T) {
	// The boundaries either side of the cap, and two blocks that need three and four
	// frames. The last of them is what catches a split that is right for one
	// continuation and wrong for the next.
	for _, tc := range []struct {
		size, frames int
	}{
		{1, 1},
		{maxFrame - 1, 1},
		{maxFrame, 1},
		{maxFrame + 1, 2},
		{2 * maxFrame, 2},
		{2*maxFrame + 1, 3},
		{3*maxFrame + 7, 4},
	} {
		t.Run(fmt.Sprintf("%d octets", tc.size), func(t *testing.T) {
			enc, c, tr := newEncoder()
			want := filler(tc.size, 'x')
			c.block = func(int, []h2.Field) []byte { return want }

			if err := enc.WriteHeaders(1, okFields(), true); err != nil {
				t.Fatalf("WriteHeaders: %v", err)
			}

			fs := tr.taken()
			if len(fs) != tc.frames {
				t.Fatalf("%d frames for a %d octet block, want %d", len(fs), tc.size, tc.frames)
			}
			if got := checkBlock(t, fs, 1, true, maxFrame); !bytes.Equal(got, want) {
				t.Errorf("the frames reassemble to %d octets, want the %d that were encoded",
					len(got), len(want))
			}
		})
	}
}

func TestTheSplitUsesThePeersRaisedCapRatherThanTheProtocolDefault(t *testing.T) {
	const raised = 1 << 15

	enc, c, tr := newEncoder()
	tr.max.Store(raised)
	want := filler(maxFrame+1, 'x')
	c.block = func(int, []h2.Field) []byte { return want }

	if err := enc.WriteHeaders(1, okFields(), true); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}

	fs := tr.taken()
	if len(fs) != 1 {
		t.Fatalf("%d frames for a %d octet block under a cap of %d, want 1",
			len(fs), len(want), raised)
	}
	if got := checkBlock(t, fs, 1, true, raised); !bytes.Equal(got, want) {
		t.Errorf("the frame carries %d octets, want %d", len(got), len(want))
	}
}

func TestACapBelowTheProtocolFloorIsFlooredRatherThanObeyed(t *testing.T) {
	// A transport reporting zero has broken its own contract, and the useful answer is
	// a connection that keeps working. The unacceptable answer is the one the
	// arithmetic gives without a floor: a split into fragments of nothing, which never
	// reaches the end of the block.
	//
	// The fake transport's frame budget is what turns that non-termination into a
	// failure rather than a hang — see frameBudget. The deadline below is the backstop
	// for a runaway that does not enqueue, which the budget cannot see.
	for _, cap := range []uint32{0, 1, maxFrame - 1} {
		t.Run(fmt.Sprintf("cap %d", cap), func(t *testing.T) {
			enc, c, tr := newEncoder()
			tr.max.Store(cap)
			want := filler(maxFrame+1, 'x')
			c.block = func(int, []h2.Field) []byte { return want }

			done := make(chan error, 1)
			go func() { done <- enc.WriteHeaders(1, okFields(), true) }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("WriteHeaders under a cap of %d: %v", cap, err)
				}
			case <-time.After(gateWait):
				t.Fatalf("WriteHeaders did not return within %v: a cap of %d split the block "+
					"into fragments that never consumed it", gateWait, cap)
			}

			fs := tr.taken()
			if len(fs) != 2 {
				t.Fatalf("%d frames under a cap of %d, want the 2 the %d floor gives",
					len(fs), cap, maxFrame)
			}
			if got := checkBlock(t, fs, 1, true, maxFrame); !bytes.Equal(got, want) {
				t.Errorf("the frames reassemble to %d octets, want %d", len(got), len(want))
			}
		})
	}
}

func TestTheFrameSizeCapIsReadOnceForTheWholeBurst(t *testing.T) {
	// §6.5.3 makes a new SETTINGS value bind from the point its acknowledgement is
	// sent, and that acknowledgement is enqueued by the reader goroutine — which is a
	// different goroutine from the one splitting this block. So the cap can change
	// between two frames of one burst, and both values are legal for the whole of it.
	//
	// What must not happen is a split computed against two different numbers: the
	// block is cut into fragments whose sizes were each right when they were measured
	// and which no single cap accounts for. Reading once is what makes the burst
	// consistent with itself, and one read is the observable form of that.
	enc, c, tr := newEncoder()
	c.block = func(int, []h2.Field) []byte { return filler(3*maxFrame+7, 'x') }

	if err := enc.WriteHeaders(1, okFields(), true); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}

	if len(tr.taken()) != 4 {
		t.Fatalf("%d frames, want the 4 a %d octet block needs", len(tr.taken()), 3*maxFrame+7)
	}
	if got := tr.maxReads.Load(); got != 1 {
		t.Errorf("the transport's frame size cap was read %d times for one burst of 4 frames, want once", got)
	}
}

func TestEveryFragmentIsACopyRatherThanAViewOfTheCodecsBuffer(t *testing.T) {
	// h2.HeaderCodec does not promise that Encode returns a fresh allocation, and an
	// encoder that reused one scratch buffer across calls would satisfy every word of
	// it. The frames are read by the connection's writer goroutine after this call has
	// returned, so a fragment that aliased that buffer would be one response's header
	// block appearing inside another's.
	const size = 2*maxFrame + 5

	enc, c, tr := newEncoder()
	scratch := make([]byte, 0, size)
	c.block = func(n int, _ []h2.Field) []byte {
		scratch = append(scratch[:0], filler(size, byte('a'+n))...)
		return scratch
	}

	if err := enc.WriteHeaders(1, okFields(), true); err != nil {
		t.Fatalf("WriteHeaders on stream 1: %v", err)
	}
	first := tr.taken()
	if err := enc.WriteHeaders(3, okFields(), true); err != nil {
		t.Fatalf("WriteHeaders on stream 3: %v", err)
	}

	got := checkBlock(t, first, 1, true, maxFrame)
	if want := filler(size, 'a'); !bytes.Equal(got, want) {
		t.Errorf("stream 1's block became %q...; the second response overwrote the buffer "+
			"its frames were pointing into", got[:min(len(got), 8)])
	}
}

// --- one lock over the encode and the enqueue ---

func TestNoSecondBlockIsEncodedWhileTheFirstIsStillBeingEnqueued(t *testing.T) {
	// The invariant HPACK depends on, and the one this package exists to hold: a
	// header block must be encoded and enqueued as one indivisible step. Encoding
	// under a lock and enqueuing outside it keeps our own dynamic table consistent
	// and still desynchronises the peer's, because §4.3 of RFC 7541 is a rule about
	// the order blocks are *processed* in and the peer processes them in the order
	// they arrive.
	//
	// Deterministic in the direction that matters. While the first goroutine is parked
	// in Enqueue, the gate has exactly one possible sender left, so an arrival on it
	// is a second goroutine that got past the lock — and the absence of one is the
	// guard holding. The wait below is therefore a proof of absence: it has to be
	// waited out on the passing path, and a break that releases the lock early fires
	// it in microseconds.
	enc, c, tr := newEncoder()
	tr.gate()

	done := make(chan error, 2)
	go func() { done <- enc.WriteHeaders(1, okFields(), true) }()
	<-tr.entered

	go func() { done <- enc.WriteHeaders(3, okFields(), true) }()
	select {
	case <-tr.entered:
		t.Fatalf("a second header block reached the transport while the first was still " +
			"being enqueued: the encode and the enqueue are not under one lock")
	case <-time.After(gateWait):
	}

	// One encode, because the second goroutine is still waiting for the lock. Read
	// while that goroutine is blocked and the first is parked in the gate, so nothing
	// is writing this field.
	if len(c.encodes) != 1 {
		t.Errorf("%d blocks encoded while the first was being enqueued, want 1", len(c.encodes))
	}

	tr.release <- nil
	<-tr.entered
	tr.release <- nil
	for range 2 {
		if err := <-done; err != nil {
			t.Fatalf("WriteHeaders: %v", err)
		}
	}
}

func TestBlocksReachTheWireInTheOrderTheyWereEncoded(t *testing.T) {
	// The same invariant under contention, which is where the arithmetic of the split
	// and the ordering of the bursts have to hold at once. Every block spans three
	// frames and is filled with its own encode ordinal, so the recorded frame stream
	// says both which order the bursts went out in and whether any of them was cut in
	// half by another.
	const (
		responses = 48
		size      = 2*maxFrame + 1
	)

	enc, c, tr := newEncoder()
	c.block = func(n int, _ []h2.Field) []byte { return filler(size, byte(n)) }

	var wg sync.WaitGroup
	errs := make(chan error, responses)
	for i := range responses {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Odd identifiers: a response goes out on a stream the client opened, and
			// §5.1.1 makes those odd.
			if err := enc.WriteHeaders(uint32(2*i+1), okFields(), true); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("WriteHeaders: %v", err)
	}

	bs := blocks(t, tr.taken())
	if len(bs) != responses {
		t.Fatalf("%d blocks on the wire, want %d", len(bs), responses)
	}
	if len(c.encodes) != responses {
		t.Fatalf("%d blocks encoded, want %d", len(c.encodes), responses)
	}
	for i, b := range bs {
		want := filler(size, byte(i))
		got := checkBlock(t, b, b[0].Stream(), true, maxFrame)
		if !bytes.Equal(got, want) {
			t.Fatalf("block %d on the wire is tagged %d, want %d: the blocks did not reach "+
				"the transport in the order they were encoded", i, got[0], i)
		}
	}
}

// --- the peer's two header-related settings ---

func TestSetMaxDynamicTableSizeReachesTheCodec(t *testing.T) {
	enc, c, _ := newEncoder()

	for _, n := range []int{4096, 0, 65536} {
		enc.SetMaxDynamicTableSize(n)
	}
	if want := []int{4096, 0, 65536}; len(c.tableSizes) != 3 ||
		c.tableSizes[0] != want[0] || c.tableSizes[1] != want[1] || c.tableSizes[2] != want[2] {
		t.Errorf("the codec was told %v, want %v", c.tableSizes, want)
	}
}

func TestNoAdvertisedHeaderListLimitAllowsAnySize(t *testing.T) {
	enc, _, tr := newEncoder()

	fields := okFields()
	for i := range 500 {
		fields = append(fields, h2.Field{Name: fmt.Sprintf("x-pad-%03d", i), Value: strings.Repeat("v", 200)})
	}
	if err := enc.WriteHeaders(1, fields, true); err != nil {
		t.Fatalf("WriteHeaders with no advertised limit: %v", err)
	}
	if len(tr.taken()) == 0 {
		t.Error("nothing was enqueued")
	}
}

func TestTheHeaderListSizeIsCountedTheWaySettingsDefinesIt(t *testing.T) {
	// §6.5.2: "the uncompressed size of field lines, including the length of the name
	// and value in units of octets plus an overhead of 32 octets for each field line".
	// So the two fields below cost their octets plus 64, and the pair of subtests is
	// the boundary either side of that number — which is the only way to tell the
	// accounting from one that forgot the overhead, or charged it once, or measured
	// the encoded block instead.
	fields := []h2.Field{status("200"), {Name: "content-length", Value: "3"}}
	size := int64(0)
	for _, f := range fields {
		// The 32 is written out rather than taken from fieldOverhead. A test that
		// computed its expectation from the constant under test would agree with any
		// value of it, including zero, which is the one mistake worth catching here.
		size += int64(len(f.Name)) + int64(len(f.Value)) + 32
	}

	for _, tc := range []struct {
		name  string
		limit int64
		sent  bool
	}{
		{"the list exactly at the limit", size, true},
		{"the list one octet over", size - 1, false},
		{"the list one octet under", size + 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			enc, c, tr := newEncoder()
			enc.SetMaxHeaderListSize(uint32(tc.limit))

			err := enc.WriteHeaders(1, fields, true)
			switch {
			case tc.sent && err != nil:
				t.Fatalf("WriteHeaders with a limit of %d for a list of %d: %v", tc.limit, size, err)
			case !tc.sent && !errors.Is(err, ErrHeaderListTooLarge):
				t.Fatalf("WriteHeaders with a limit of %d for a list of %d: %v, want %v",
					tc.limit, size, err, ErrHeaderListTooLarge)
			}
			if got := len(tr.taken()) > 0; got != tc.sent {
				t.Errorf("frames enqueued: %v, want %v", got, tc.sent)
			}
			// The refusal has to happen before the codec is asked, or the dynamic
			// table has already moved on and every later response on the connection
			// is encoded against a state the peer does not share. A refusal that
			// corrupts the connection it was protecting is worse than no refusal.
			if got := len(c.encodes) > 0; got != tc.sent {
				t.Errorf("the codec was called: %v, want %v", got, tc.sent)
			}
		})
	}
}

func TestAnAdvertisedHeaderListLimitOfZeroIsNotTheSameAsNoLimit(t *testing.T) {
	// Zero is a legal value for the setting, and a peer that sends it has said
	// something absurd but has said it. A sentinel that used zero for "unadvertised"
	// would make this pair indistinguishable — and would take the wrong half of the
	// pair on every connection, because no peer sends zero and every peer omits it.
	enc, _, tr := newEncoder()
	enc.SetMaxHeaderListSize(0)

	if err := enc.WriteHeaders(1, okFields(), true); !errors.Is(err, ErrHeaderListTooLarge) {
		t.Fatalf("WriteHeaders under a limit of 0: %v, want %v", err, ErrHeaderListTooLarge)
	}
	if fs := tr.taken(); len(fs) != 0 {
		t.Errorf("%d frames enqueued under a limit of 0, want none", len(fs))
	}
}

func TestTheHeaderListLimitIsNotMeasuredOnTheEncodedBlock(t *testing.T) {
	// A codec that compresses this list to nothing — every field already in its
	// dynamic table — does not make the list smaller for the peer, which has to hold
	// the decoded fields. Measuring the block instead of the list would let a response
	// through by virtue of how well it happened to compress.
	enc, c, _ := newEncoder()
	c.block = func(int, []h2.Field) []byte { return nil }
	enc.SetMaxHeaderListSize(8)

	if err := enc.WriteHeaders(1, okFields(), true); !errors.Is(err, ErrHeaderListTooLarge) {
		t.Fatalf("WriteHeaders: %v, want %v", err, ErrHeaderListTooLarge)
	}
}

// --- refusals, and what they leave behind ---

func TestAMalformedFieldListIsRefusedWithoutBeingEncoded(t *testing.T) {
	// The point of every one of these is that it is caught here rather than on the
	// wire. A response is this server's own construction, so an invalid field line is
	// a bug on this side — and the codec must not see it, because encoding it would
	// move the dynamic table on for a block that is never sent.
	for _, tc := range []struct {
		name   string
		fields []h2.Field
	}{
		{"no :status", []h2.Field{{Name: "content-length", Value: "0"}}},
		{"a request pseudo-header field", []h2.Field{status("200"), {Name: ":path", Value: "/"}}},
		{"a repeated :status", []h2.Field{status("200"), status("204")}},
		{":status after a regular field", []h2.Field{{Name: "server", Value: "zdh"}, status("200")}},
		{"an uppercase field name", []h2.Field{status("200"), {Name: "Server", Value: "zdh"}}},
		{"a CR in a value", []h2.Field{status("200"), {Name: "location", Value: "/a\r\nx: y"}}},
		{"a connection-specific field", []h2.Field{status("200"), {Name: "transfer-encoding", Value: "chunked"}}},
		{"a two-digit :status", []h2.Field{status("20")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			enc, c, tr := newEncoder()

			err := enc.WriteHeaders(1, tc.fields, true)
			if !errors.Is(err, ErrMalformedResponse) {
				t.Fatalf("WriteHeaders: %v, want %v", err, ErrMalformedResponse)
			}
			if len(c.encodes) != 0 {
				t.Errorf("the codec was asked to encode %d blocks, want none", len(c.encodes))
			}
			if fs := tr.taken(); len(fs) != 0 {
				t.Errorf("%d frames enqueued, want none", len(fs))
			}
		})
	}
}

func TestARefusedHeadersFrameIsReported(t *testing.T) {
	want := errors.New("the write half has stopped")

	enc, _, tr := newEncoder()
	tr.refuse = func(int, frame.Frame) error { return want }

	if err := enc.WriteHeaders(1, okFields(), true); !errors.Is(err, want) {
		t.Errorf("WriteHeaders: %v, want %v", err, want)
	}
}

func TestARefusedContinuationIsReportedWithTheHeadersAlreadyQueued(t *testing.T) {
	// The stream is left with a header block that has no END_HEADERS, and there is
	// nothing this package can do about that: §6.10 forbids sending anything else
	// until the block is finished, and the reason a frame was refused is that the
	// write half has stopped. What must not happen is that the failure is swallowed
	// and the caller goes on to write a body onto a stream whose header block never
	// ended.
	want := errors.New("the write half has stopped")

	enc, c, tr := newEncoder()
	c.block = func(int, []h2.Field) []byte { return filler(2*maxFrame+1, 'x') }
	tr.refuse = func(n int, _ frame.Frame) error {
		if n == 2 {
			return want
		}
		return nil
	}

	if err := enc.WriteHeaders(1, okFields(), true); !errors.Is(err, want) {
		t.Fatalf("WriteHeaders: %v, want %v", err, want)
	}

	fs := tr.taken()
	if len(fs) != 2 {
		t.Fatalf("%d frames queued before the refusal, want 2", len(fs))
	}
	// Neither of the two that got through claims the block is finished. A block cut
	// short is bad; a block cut short whose last frame says otherwise is worse, because
	// the peer would then act on a header section it has only part of.
	for i, f := range fs {
		if f.Flags()&frame.FlagEndHeaders != 0 {
			t.Errorf("frame %d (%s) sets END_HEADERS on a block that was cut short", i, f.Type())
		}
	}
}

// --- trailers ---

func TestATrailerSectionAlwaysEndsTheStream(t *testing.T) {
	// §8.1 gives no way to send a trailer section and carry on: it is the last thing
	// on a stream by definition. So END_STREAM is not a parameter, which is what makes
	// a stream left open after its trailers unwritable rather than merely unwritten.
	enc, _, tr := newEncoder()

	if err := enc.WriteTrailers(1, []h2.Field{{Name: "grpc-status", Value: "0"}}); err != nil {
		t.Fatalf("WriteTrailers: %v", err)
	}
	checkBlock(t, tr.taken(), 1, true, maxFrame)
}

func TestATrailerSectionRefusesEveryPseudoHeaderField(t *testing.T) {
	// §8.3: "Pseudo-header fields MUST NOT appear in a trailer section." Including
	// ":status", which is the one a header section requires — so the two sections
	// cannot be checked by one set of rules, and this is the case that proves the
	// distinction is live rather than decorative.
	for _, name := range []string{":status", ":path", ":method", ":whatever"} {
		t.Run(name, func(t *testing.T) {
			enc, c, tr := newEncoder()

			err := enc.WriteTrailers(1, []h2.Field{{Name: name, Value: "200"}})
			if !errors.Is(err, ErrMalformedResponse) {
				t.Fatalf("WriteTrailers with %q: %v, want %v", name, err, ErrMalformedResponse)
			}
			if len(c.encodes) != 0 || len(tr.taken()) != 0 {
				t.Errorf("%d blocks encoded and %d frames enqueued, want none of either",
					len(c.encodes), len(tr.taken()))
			}
		})
	}
}

func TestATrailerSectionNeedsNoStatus(t *testing.T) {
	enc, _, tr := newEncoder()

	if err := enc.WriteTrailers(1, []h2.Field{{Name: "x-checksum", Value: "deadbeef"}}); err != nil {
		t.Fatalf("WriteTrailers: %v", err)
	}
	if len(tr.taken()) != 1 {
		t.Errorf("%d frames enqueued, want 1", len(tr.taken()))
	}
}

func TestATrailerSectionIsHeldToTheFieldRules(t *testing.T) {
	// The half of §8.2 both sections share. A trailer is the easier of the two places
	// to forget it, because nothing about a trailer looks like a header — and a CRLF
	// smuggled through one is exactly as good to an attacker.
	enc, _, tr := newEncoder()

	err := enc.WriteTrailers(1, []h2.Field{{Name: "x-note", Value: "a\r\nx-injected: 1"}})
	if !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("WriteTrailers: %v, want %v", err, ErrMalformedResponse)
	}
	if len(tr.taken()) != 0 {
		t.Errorf("%d frames enqueued, want none", len(tr.taken()))
	}
}

// --- construction and the identifiers it refuses ---

func TestNewEncoderRefusesToBeBuiltWithoutItsTwoHalves(t *testing.T) {
	// Both are dereferenced on the first response of the connection rather than at
	// construction, so without these the symptom is a nil method call from a stream
	// goroutine with a peer's traffic in the stack trace.
	for _, tc := range []struct {
		name  string
		build func()
	}{
		{"no codec", func() { NewEncoder(nil, newTransport()) }},
		{"no transport", func() { NewEncoder(&fakeCodec{}, nil) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Errorf("NewEncoder with %s returned instead of panicking", tc.name)
				}
			}()
			tc.build()
		})
	}
}

func TestAHeaderBlockOnTheConnectionPanics(t *testing.T) {
	// §6.2 and §6.10 make HEADERS and CONTINUATION stream frames, so a zero here
	// could not be sent even if it were built. The identifier comes from this server's
	// own stream table rather than from the peer, which is what makes it a programming
	// error rather than a protocol one.
	for _, tc := range []struct {
		name  string
		write func(*Encoder)
	}{
		{"WriteHeaders", func(e *Encoder) { _ = e.WriteHeaders(0, okFields(), true) }},
		{"WriteTrailers", func(e *Encoder) { _ = e.WriteTrailers(0, nil) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			enc, _, _ := newEncoder()
			defer func() {
				if recover() == nil {
					t.Errorf("%s on stream 0 returned instead of panicking", tc.name)
				}
			}()
			tc.write(enc)
		})
	}
}
