package priority

import (
	"testing"

	"zerodeps/zdh/internal/limits"
)

// TestPendingZeroValueIsUsable matters because a Pending is a field of a per-connection
// struct and nothing constructs one. Every method has to work on the nil map, including the
// ones that only read it — a connection that receives a request before it receives a
// PRIORITY_UPDATE reaches Take and Prune with the map still absent.
func TestPendingZeroValueIsUsable(t *testing.T) {
	var p Pending

	if got := p.Len(); got != 0 {
		t.Errorf("Len() = %d on a zero Pending, want 0", got)
	}
	if p.Held(1) {
		t.Error("Held(1) = true on a zero Pending")
	}
	if params, ok := p.Take(1); ok || params != (Params{}) {
		t.Errorf("Take(1) = %+v, %v on a zero Pending, want the zero Params and false",
			params, ok)
	}
	if got := p.Prune(0xffffffff); got != 0 {
		t.Errorf("Prune() = %d on a zero Pending, want 0", got)
	}
	// Still zero: none of the reads may have created the map, because the whole point of
	// creating it late is that a connection which never sees the frame allocates nothing.
	if p.of != nil {
		t.Error("reading a zero Pending created its map")
	}

	// And it becomes usable without ceremony.
	p.Put(1, Params{}.WithUrgency(0))
	if got := p.Len(); got != 1 {
		t.Errorf("Len() = %d after the first Put, want 1", got)
	}
}

func TestPendingPutTake(t *testing.T) {
	var p Pending
	want := Params{}.WithUrgency(1).WithIncremental(true)
	p.Put(7, want)

	if !p.Held(7) {
		t.Error("Held(7) = false after Put(7)")
	}
	got, ok := p.Take(7)
	if !ok {
		t.Fatal("Take(7) = false after Put(7)")
	}
	if got != want {
		t.Errorf("Take(7) = %+v, want %+v", got, want)
	}
}

// TestPendingTakeForgets is the half of Take that bounds the map: applying a buffered
// priority has to drop the entry, or a client that opens every stream it prioritized leaves
// one behind for each and the §7.1 of RFC 9218 check starts refusing frames for streams that
// are no longer idle.
func TestPendingTakeForgets(t *testing.T) {
	var p Pending
	p.Put(3, Params{}.WithUrgency(2))

	if _, ok := p.Take(3); !ok {
		t.Fatal("first Take(3) = false")
	}
	if p.Held(3) {
		t.Error("Held(3) = true after Take(3)")
	}
	if params, ok := p.Take(3); ok {
		t.Errorf("second Take(3) = %+v, true; want false", params)
	}
	if got := p.Len(); got != 0 {
		t.Errorf("Len() = %d after taking the only entry, want 0", got)
	}
}

// TestPendingPutReplaces is §7 of RFC 9218's bound per stream: the most recent frame is the
// one kept, and a thousand frames for one stream are one entry.
func TestPendingPutReplaces(t *testing.T) {
	var p Pending
	for u := range MaxUrgency + 1 {
		p.Put(5, Params{}.WithUrgency(u))
		if got := p.Len(); got != 1 {
			t.Fatalf("Len() = %d after %d Puts for one stream, want 1", got, u+1)
		}
	}
	got, ok := p.Take(5)
	if !ok {
		t.Fatal("Take(5) = false")
	}
	if want := (Params{}.WithUrgency(MaxUrgency)); got != want {
		t.Errorf("Take(5) = %+v, want the most recent %+v", got, want)
	}
}

// TestPendingPutReplacesWithSomethingSmaller is the case the "most recently received" rule
// makes awkward to get wrong: a client that first prioritizes a stream and then sends a
// frame with an empty field value has withdrawn the signal, and the entry must hold the
// withdrawal rather than the earlier value. §7 of RFC 9218 makes an omitted parameter a
// signal to use its default, so the zero Params is a real signal and not an absence of one.
func TestPendingPutReplacesWithSomethingSmaller(t *testing.T) {
	var p Pending
	p.Put(9, Params{}.WithUrgency(0).WithIncremental(true))
	p.Put(9, Params{})

	got, ok := p.Take(9)
	if !ok {
		t.Fatal("Take(9) = false")
	}
	if got != (Params{}) {
		t.Errorf("Take(9) = %+v, want the zero Params that the second frame signalled", got)
	}
}

// TestPendingHeldIsNotTake pins that the §7.1 of RFC 9218 check does not consume what it
// asks about. A caller counts prioritized idle streams before deciding whether to buffer;
// if asking dropped the entry, a second frame for a stream already pending would look new
// and the count would be wrong in the direction that admits more entries.
func TestPendingHeldIsNotTake(t *testing.T) {
	var p Pending
	p.Put(11, Params{}.WithUrgency(4))

	for range 3 {
		if !p.Held(11) {
			t.Fatal("Held(11) = false while the entry is buffered")
		}
	}
	if got := p.Len(); got != 1 {
		t.Errorf("Len() = %d after three Helds, want 1", got)
	}
	if p.Held(12) {
		t.Error("Held(12) = true for a stream never put")
	}
	if got := p.Len(); got != 1 {
		t.Errorf("Len() = %d after asking about an absent stream, want 1", got)
	}
}

func TestPendingLen(t *testing.T) {
	var p Pending
	for i := range uint32(10) {
		p.Put(1+2*i, Params{}.WithUrgency(int(i%8)))
		if got, want := p.Len(), int(i)+1; got != want {
			t.Fatalf("Len() = %d after %d distinct streams, want %d", got, i+1, want)
		}
	}
	// Replacing does not add.
	p.Put(1, Params{})
	if got := p.Len(); got != 10 {
		t.Errorf("Len() = %d after replacing an entry, want 10", got)
	}
	// Taking subtracts, and taking something absent does not.
	if _, ok := p.Take(1); !ok {
		t.Fatal("Take(1) = false")
	}
	if _, ok := p.Take(2); ok {
		t.Error("Take(2) = true for an even identifier that was never put")
	}
	if got := p.Len(); got != 9 {
		t.Errorf("Len() = %d, want 9", got)
	}
}

// TestPruneBoundary is the exact edge, and it is the one that decides whether a stream's own
// buffered priority survives long enough to be applied. below is the identifier of a stream
// that has just left the idle state; §5.1.1 of RFC 9113 closes the ones under it and says
// nothing about that one, and Take is what consumes it.
func TestPruneBoundary(t *testing.T) {
	var p Pending
	for _, id := range []uint32{1, 3, 5, 7, 9} {
		p.Put(id, Params{}.WithUrgency(0))
	}

	if got := p.Prune(5); got != 2 {
		t.Errorf("Prune(5) = %d, want 2 (streams 1 and 3)", got)
	}
	for _, id := range []uint32{1, 3} {
		if p.Held(id) {
			t.Errorf("stream %d survived Prune(5)", id)
		}
	}
	for _, id := range []uint32{5, 7, 9} {
		if !p.Held(id) {
			t.Errorf("stream %d did not survive Prune(5); the boundary is exclusive because "+
				"the stream that just opened is the one about to be taken", id)
		}
	}
	if got := p.Len(); got != 3 {
		t.Errorf("Len() = %d after Prune(5), want 3", got)
	}
}

func TestPruneEdges(t *testing.T) {
	fill := func() *Pending {
		p := new(Pending)
		for _, id := range []uint32{1, 3, 5} {
			p.Put(id, Params{}.WithUrgency(1))
		}
		return p
	}

	// Stream 1 is the lowest a client can open, so Prune(1) can never have anything to do.
	// It is worth pinning: the caller prunes on every stream that opens, and the first one
	// must not be a special case at the call site.
	p := fill()
	if got := p.Prune(1); got != 0 {
		t.Errorf("Prune(1) = %d, want 0", got)
	}
	if got := p.Len(); got != 3 {
		t.Errorf("Len() = %d after Prune(1), want 3", got)
	}

	// Zero is not a legal prioritized stream identifier, so this is a caller bug and the
	// safe behaviour is to do nothing rather than to clear the map.
	p = fill()
	if got := p.Prune(0); got != 0 {
		t.Errorf("Prune(0) = %d, want 0", got)
	}
	if got := p.Len(); got != 3 {
		t.Errorf("Len() = %d after Prune(0), want 3", got)
	}

	// The largest identifier a client can open closes everything below it, which is the
	// end of the connection's usable stream space and the one moment the whole map goes.
	p = fill()
	if got := p.Prune(1<<31 - 1); got != 3 {
		t.Errorf("Prune(2^31-1) = %d, want 3", got)
	}
	if got := p.Len(); got != 0 {
		t.Errorf("Len() = %d after pruning everything, want 0", got)
	}

	// And repeating it is not an error.
	if got := p.Prune(1<<31 - 1); got != 0 {
		t.Errorf("Prune on an emptied Pending = %d, want 0", got)
	}
}

// TestPruneThenTakeAndTakeThenPrune runs the two orders the caller might use when a stream
// opens, because the boundary is only safe if it does not depend on which comes first.
func TestPruneThenTakeAndTakeThenPrune(t *testing.T) {
	want := Params{}.WithUrgency(6)

	// Prune first, then apply the opening stream's own priority.
	p := new(Pending)
	p.Put(1, Params{}.WithUrgency(0))
	p.Put(3, want)
	if got := p.Prune(3); got != 1 {
		t.Errorf("Prune(3) = %d, want 1", got)
	}
	got, ok := p.Take(3)
	if !ok || got != want {
		t.Errorf("Take(3) after Prune(3) = %+v, %v; want %+v, true", got, ok, want)
	}

	// Apply first, then prune. The entry is already gone, so the count is one lower and
	// stream 1 goes either way.
	p = new(Pending)
	p.Put(1, Params{}.WithUrgency(0))
	p.Put(3, want)
	got, ok = p.Take(3)
	if !ok || got != want {
		t.Errorf("Take(3) = %+v, %v; want %+v, true", got, ok, want)
	}
	if n := p.Prune(3); n != 1 {
		t.Errorf("Prune(3) after Take(3) = %d, want 1", n)
	}
	if p.Len() != 0 {
		t.Errorf("Len() = %d, want 0", p.Len())
	}
}

// TestPendingUnderTheWorstClient is the adversarial shape: a peer that buffers as many
// streams as this server would ever admit, replaces every one of them repeatedly, and then
// skips to a high identifier instead of opening any. The map has to end empty, because the
// §5.1.1 of RFC 9113 close is the thing standing between that client and memory that is
// never reclaimed.
//
// The count comes from limits rather than a literal so that raising the advertised
// concurrency raises what this test buffers. §7.1 of RFC 9218 makes that setting the bound,
// so a test that hard-coded a smaller number would stop testing the bound the moment the
// server advertised a larger one.
func TestPendingUnderTheWorstClient(t *testing.T) {
	const streams = limits.MaxConcurrentStreams

	var p Pending
	for i := range uint32(streams) {
		p.Put(1+2*i, Params{}.WithUrgency(int(i%8)))
	}
	if got := p.Len(); got != streams {
		t.Fatalf("Len() = %d, want %d", got, streams)
	}

	// Ten thousand more frames, none of them a new stream.
	const rounds = 10000 / streams
	for round := range uint32(rounds) {
		for i := range uint32(streams) {
			p.Put(1+2*i, Params{}.WithUrgency(int((round+i)%8)))
		}
	}
	if got := p.Len(); got != streams {
		t.Fatalf("Len() = %d after %d replacements, want %d", got, rounds*streams, streams)
	}

	// Now the client skips the lot. Every buffered stream is below the one it opened, so
	// every one of them is closed and every entry is dead.
	const skipTo = 1 + 2*streams
	if got := p.Prune(skipTo); got != streams {
		t.Errorf("Prune(%d) = %d, want %d", skipTo, got, streams)
	}
	if got := p.Len(); got != 0 {
		t.Errorf("Len() = %d after the skip, want 0", got)
	}
	if _, ok := p.Take(1); ok {
		t.Error("stream 1 is still buffered after the client skipped past it")
	}
}

// TestPendingHoldsEveryLegalIdentifier walks the ends of the client-initiated stream space.
// The identifiers are 31 bits and odd, and the top of that range is where a uint32 stored
// as an int, or a comparison done in a signed type, would go wrong.
func TestPendingHoldsEveryLegalIdentifier(t *testing.T) {
	ids := []uint32{
		1,
		3,
		1 << 15,
		1<<31 - 3,
		1<<31 - 1, // the largest §5.1.1 of RFC 9113 allows
	}

	var p Pending
	for i, id := range ids {
		p.Put(id, Params{}.WithUrgency(i%8))
	}
	for i, id := range ids {
		got, ok := p.Take(id)
		if !ok {
			t.Errorf("Take(%d) = false", id)
			continue
		}
		if want := (Params{}.WithUrgency(i % 8)); got != want {
			t.Errorf("Take(%d) = %+v, want %+v", id, got, want)
		}
	}
	if got := p.Len(); got != 0 {
		t.Errorf("Len() = %d, want 0", got)
	}
}
