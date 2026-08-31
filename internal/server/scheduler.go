package server

import (
	"zerodeps/zdh/internal/frame"
	"zerodeps/zdh/internal/priority"
)

// The scheduler decides which of the frames waiting for one connection goes next.
//
// It replaces a channel, and the thing a channel could not express is the whole
// reason it exists: a queue that hands frames out in the order they arrived spends
// the connection's bandwidth in the order this server happened to produce it, which
// is the order the disk and the runtime chose. §10 of RFC 9218 asks for a different
// order — the client's — and this is where that request is answered.
//
// It holds no lock and starts no goroutine. Every method is called by the writer
// under the writer's mutex, so the structure is single-threaded by construction and
// the tests can drive it directly, one Push and one Pop at a time, without any
// timing at all.
//
// # Only DATA is reordered
//
// There are two lanes. Everything that is not a DATA frame goes into one FIFO lane
// and is written before any DATA frame; DATA frames go into a lane per stream and
// are chosen between by urgency.
//
// The split is not a simplification, it is the correctness argument. §10 of RFC
// 9218 is written about bandwidth: "This section describes considerations regarding
// how servers can schedule the order in which the competing responses will be sent
// when such competition exists." A SETTINGS acknowledgement, a PING acknowledgement
// and a WINDOW_UPDATE are not competing for bandwidth — they are nine to seventeen
// octets that unblock the peer — and reordering them buys nothing while costing a
// great deal. A WINDOW_UPDATE held behind a megabyte of high-urgency response stalls
// the peer's request body on a stream the peer itself marked unimportant, and
// urgency in RFC 9218 is a statement about responses, not about the credit this
// server owes for requests. A PING acknowledgement held the same way looks to the
// peer like a connection that has died.
//
// The second half of the argument is HEADERS. A response's header section could be
// scheduled — it is the thing the client is waiting for — but it cannot be reordered
// against the CONTINUATION frames that continue it, and the next section is about
// what that costs.
//
// # A field block is one item
//
// §4.3 requires that "Field blocks MUST be transmitted as a contiguous sequence of
// frames, with no interleaved frames of any other type or from any other stream",
// and §6.10 makes the failure loud: "If the END_HEADERS flag is not set, this frame
// MUST be followed by another CONTINUATION frame. A receiver MUST treat the receipt
// of any other type of frame or a frame on a different stream as a connection error
// (Section 5.4.1) of type PROTOCOL_ERROR."
//
// Upstream of here, internal/response encodes a header section and enqueues its
// HEADERS and every CONTINUATION under one mutex, which keeps them adjacent among
// the frames that package sends. It does not keep them adjacent on the connection:
// the reader goroutine enqueues SETTINGS and PING acknowledgements straight to the
// writer, and internal/stream enqueues WINDOW_UPDATE, and any of those may land
// between a HEADERS and its CONTINUATION. Nothing has ever reproduced that here,
// because a response header section this server builds fits in one frame — but "the
// bug needs a 16 KiB header section" is a bound on this server's current handlers,
// not on the protocol, and it is not a bound worth relying on.
//
// So a field block is not put in the lane until it is complete. An incomplete one is
// held aside in runs, keyed by stream, and moves into the lane as a single item when
// the frame with END_HEADERS arrives. §4.3 describes the intended effect exactly:
// "This allows a field block to be logically equivalent to a single frame."
//
// Three consequences, all of them improvements:
//
//   - The interleaving above is now impossible rather than unlikely, whoever
//     enqueues what, because there is no moment at which half a block is in the
//     lane.
//   - Frames continuing an open block are admitted past the writer's depth bound —
//     see ContinuesBlock. They have to be: the writer cannot write the block until
//     it is complete, so a bound that refused the rest of it would be a deadlock.
//     The memory is free, because internal/response has already encoded the whole
//     block into one buffer before it enqueues the first frame of it.
//   - A block whose remaining frames never arrive is never written at all. That is
//     the shutdown case, and it is the reverse of what the FIFO did: the peer used
//     to receive a HEADERS frame promising a continuation that the closing
//     connection would never send, which is a connection error under §6.10, from a
//     server that was trying to shut down politely.
//
// A CONTINUATION frame that arrives with no open block for its stream is put in the
// lane like anything else. It is a bug in the layer above — §6.10 also requires that
// "A CONTINUATION frame MUST be preceded by a HEADERS, PUSH_PROMISE or CONTINUATION
// frame without the END_HEADERS flag set." — and writing it produces the connection
// error that names the bug, which is better than this file inventing a recovery for
// a state that should not exist.
//
// # The order among DATA frames
//
// Eight lanes, one per urgency, and the lowest-numbered non-empty one is served.
// §10 of RFC 9218: "It is RECOMMENDED that, when possible, servers respect the
// urgency parameter (Section 4.1), sending higher-urgency responses before
// lower-urgency responses."
//
// Within one urgency the two kinds of response are treated differently, because the
// specification treats them differently. §10 of RFC 9218: "Non-incremental responses
// of the same urgency SHOULD be served by prioritizing bandwidth allocation in
// ascending order of the stream ID, which corresponds to the order in which clients
// make requests." And §10 of RFC 9218: "Incremental responses of the same urgency
// SHOULD be served by sharing bandwidth among them."
//
// Both are satisfied by a round robin over participants, where a participant is
// either one incremental stream or the entire non-incremental group:
//
//   - Each incremental stream with DATA waiting is its own participant, so they
//     share the band's turns between them.
//   - Every non-incremental stream with DATA waiting shares a single participant,
//     and when its turn comes the frame is taken from the lowest stream identifier
//     among them. Only the lowest is ever eligible, so bandwidth goes in ascending
//     order of stream identifier without any need to sort or to pin.
//
// How the two kinds relate at one urgency is left open, and §10 of RFC 9218 names
// the difficulty instead: "Strictly abiding by the scheduling guidance based on
// urgency and request generation order might lead to suboptimal results at the
// client, as early non-incremental responses might prevent the serving of
// incremental responses issued later."
//
// Giving the non-incremental group one participant rather than one each is this
// server's answer to it. A large non-incremental response cannot starve an
// incremental one at the same urgency, because they alternate; and an incremental
// response cannot starve the non-incremental queue either, because that queue holds
// a turn of its own however many incremental streams appear. §10 of RFC 9218 asks
// for exactly this much and no more: "It is RECOMMENDED that servers avoid such
// starvation where possible. The method for doing so is an implementation decision."
//
// # Starvation across urgencies
//
// Nothing here stops a stream at urgency 0 from taking the whole connection while a
// stream at urgency 7 waits, and that is deliberate: it is what the client asked
// for, and §10 of RFC 9218's recommendation about respecting urgency is unqualified.
//
// It is bounded anyway, and not by this file. A stream produces DATA only while it
// has flow-control credit, and credit comes from the peer: §6.9 makes the receiver
// the one who grants it. A client that starves its own urgency 7 stream is a client
// that is choosing to send WINDOW_UPDATE for the urgency 0 stream instead, which is
// the same decision it expressed in the priority signal. The failure this file could
// cause on its own — a low-urgency stream never written even though the peer is
// asking for it — cannot happen, because when the higher band runs out of credit its
// lane empties and the next band is served on the very next Pop.
//
// # What this is not
//
// The unit of the round robin is one frame, not one octet. Two participants
// alternating with frames of different sizes therefore do not get equal bandwidth,
// and the honest fix is deficit round robin: give each participant a quantum of
// octets, let it send while its deficit covers the next frame, and carry the
// remainder. It is not here, and the reason is that it would make no difference. The
// writer holds a bounded number of frames, a response's DATA frames are all the same
// size except the last one, and a stream that is producing short frames is a stream
// that has little to send rather than one being served unfairly — so the deficit
// would accumulate unspent. A quantum would add state to every participant to change
// the outcome in no case this server can reach.
//
// The reorder window is that same bound. This structure can only order what it
// holds, the writer holds tens of frames rather than thousands, and the real
// serialisation point upstream is internal/response's mutex. So the scheduling here
// is a reordering of what is in flight, not a global plan for the connection — which
// is all §10 of RFC 9218 claims for any of it: "Endpoints cannot depend on
// particular treatment based on priority signals."

// numBands is one lane per urgency value, which §4.1 of RFC 9218 fixes at eight.
const numBands = priority.MaxUrgency + 1

// nonIncrementalTurn is the ring entry that stands for a band's whole
// non-incremental group rather than for one stream.
//
// Zero is free for the purpose because it can never be a real participant: §6.1
// requires that "DATA frames MUST be associated with a stream", a participant is a
// stream with DATA waiting, and Push routes a DATA frame on stream 0 away from the
// bands entirely.
const nonIncrementalTurn uint32 = 0

// queued is one DATA frame and the position it was pushed at.
//
// The position is not for ordering within the stream — a slice already does that —
// but for ordering against that stream's own later non-DATA frames. See Pop.
type queued struct {
	f   frame.Frame
	seq uint64
}

// item is one indivisible unit of the FIFO lane: a single frame, or a whole field
// block.
type item struct {
	frames []frame.Frame
	stream uint32

	// seq is the position of the first frame, which is the position the whole item
	// occupies in the connection's order.
	seq uint64
}

// streamQueue is the DATA waiting on one stream, and where in the bands it is.
//
// band and inc are recorded rather than looked up on each Pop because they must not
// change under the ring: a stream is in exactly one band's ring as exactly one kind
// of participant, and if a PRIORITY_UPDATE arrived between the entry and the removal
// then a fresh lookup would remove it from a ring it was never in. SetPriority moves
// it explicitly instead.
type streamQueue struct {
	data []queued
	band int
	inc  bool
}

// band is one urgency's round-robin state.
type band struct {
	// ring is the participant order. An entry is an incremental stream's identifier,
	// or nonIncrementalTurn standing for every non-incremental stream at once.
	ring []uint32

	// nonInc is the non-incremental streams with DATA waiting, unordered. The
	// lowest identifier in it is the one served, and a linear scan finds it: the
	// slice is bounded by the writer's queue depth, which is tens, and a heap would
	// cost more to maintain on every push and pop than the scan costs to run.
	nonInc []uint32
}

// scheduler holds the frames waiting to be written on one connection.
//
// Not safe for concurrent use, deliberately. See the commentary above.
type scheduler struct {
	// seq numbers pushes, so that a stream's DATA can be ordered against its own
	// later non-DATA frames. It is a uint64 and so cannot wrap: a connection would
	// have to send eighteen quintillion frames.
	seq uint64

	// lane is the FIFO of items that are not DATA, in push order.
	lane []item

	// pinned is the unwritten remainder of the item Pop is part-way through. While
	// it is non-empty nothing else may be written, which is what makes a field
	// block contiguous on the wire.
	pinned []frame.Frame

	// runs holds the field blocks that are still incomplete, by stream. An entry
	// here is not in lane and is not writable.
	runs map[uint32]*item

	// streams holds the DATA of every stream with any waiting. An entry is deleted
	// as soon as its last frame is taken, so this map is bounded by n.
	streams map[uint32]*streamQueue

	bands [numBands]band

	// prio is what the peer has said about each stream. A stream with no entry gets
	// the zero Params, which §4 of RFC 9218 makes the defaults. Bounded by Forget.
	prio map[uint32]priority.Params

	// n counts the frames that could be written now; blocked counts the ones held in
	// incomplete field blocks. Len reports the first, and the split is the point:
	// the writer's depth bound is backpressure against a peer that is not reading,
	// and a frame that this server is still producing is not evidence of that.
	n       int
	blocked int
}

func newScheduler() *scheduler {
	return &scheduler{
		runs:    make(map[uint32]*item),
		streams: make(map[uint32]*streamQueue),
		prio:    make(map[uint32]priority.Params),
	}
}

// Len is the number of frames waiting that could be written now. It excludes the
// frames of an incomplete field block, which could not.
func (s *scheduler) Len() int { return s.n }

// ContinuesBlock reports whether f continues a field block this scheduler is already
// holding, and so must be accepted regardless of any depth bound.
//
// The writer's bound exists to stop a peer that has stopped reading from being sent
// unbounded memory. A CONTINUATION frame for a block already begun is the opposite
// case: refusing it leaves a block that can never complete, which can never be
// written, which stops the queue draining at all. The frames are bounded by the one
// field block, and that block is already encoded in full upstream, so admitting them
// costs no memory that has not already been spent.
func (s *scheduler) ContinuesBlock(f frame.Frame) bool {
	return f.Type() == frame.TypeContinuation && s.runs[f.Stream()] != nil
}

// MidBlock reports whether the frames handed out so far end part-way through a field
// block, so that the next Pop is the rest of it.
//
// The writer needs this because it stops buffering at a high-water mark, and stopping
// there mid-block would put a HEADERS frame on the wire with its CONTINUATION frames
// still here — which §6.10 of RFC 9113 makes a connection error for the peer that
// reads it, and which no later burst can repair if the connection stops first.
// Continuing past the mark is safe in a way that waiting for a fragment would not be:
// every frame of a pinned block is already in this structure, so the next Pop returns
// one immediately rather than blocking.
func (s *scheduler) MidBlock() bool { return len(s.pinned) > 0 }

// SetPriority records the peer's priority signal for a stream, moving any DATA the
// stream already has waiting into its new band.
//
// Moving it is the difference between a signal that applies and one that applies to
// the next response. §7 of RFC 9218 lets a client reprioritize a stream at any point
// in its life, and a stream that has been reading a large file for a second has its
// next frames in this structure, not in the future.
//
// The moved stream joins the back of its new band's ring rather than keeping a
// place. There is no place to keep — the ring it left is a different band's — and
// the back is the answer that cannot let a client gain turns by reprioritizing.
func (s *scheduler) SetPriority(id uint32, p priority.Params) {
	if id == nonIncrementalTurn {
		// §7.1 of RFC 9218 gives the frame a Prioritized Stream ID, and a
		// PRIORITY_UPDATE naming stream 0 is refused long before here. Ignoring it
		// keeps the sentinel meaning one thing.
		return
	}
	s.prio[id] = p

	q := s.streams[id]
	if q == nil {
		return
	}
	if q.band == p.Urgency() && q.inc == p.Incremental() {
		return
	}
	s.leave(id, q)
	s.enter(id, q)
}

// Forget drops what was remembered about a stream's priority.
//
// The caller calls this when a stream is finished, and it is the only bound on the
// priority table: without it a connection that serves a million requests remembers a
// million signals. Any DATA still waiting on the stream keeps the classification it
// entered its band with, which is the one this server has already been scheduling it
// under — see streamQueue.
func (s *scheduler) Forget(id uint32) {
	delete(s.prio, id)
}

// Push adds f to whichever lane it belongs in.
//
// It never blocks and never refuses. The depth bound is the writer's, applied before
// this is reached, because only the writer can block a caller and only the caller
// can be told to wait.
func (s *scheduler) Push(f frame.Frame) {
	s.seq++
	id := f.Stream()

	if f.Type() == frame.TypeData && id != nonIncrementalTurn {
		q := s.streams[id]
		if q == nil {
			q = &streamQueue{}
			s.streams[id] = q
		}
		q.data = append(q.data, queued{f: f, seq: s.seq})
		s.n++
		if len(q.data) == 1 {
			s.enter(id, q)
		}
		return
	}

	// A frame continuing a block already begun joins it, and completes it if it
	// carries END_HEADERS.
	if open := s.runs[id]; open != nil {
		open.frames = append(open.frames, f)
		s.blocked++
		if endsBlock(f) {
			delete(s.runs, id)
			s.blocked -= len(open.frames)
			s.n += len(open.frames)
			s.lane = append(s.lane, *open)
		}
		return
	}

	// A block that is not complete in its first frame is held aside until it is.
	if opensBlock(f) {
		s.runs[id] = &item{frames: []frame.Frame{f}, stream: id, seq: s.seq}
		s.blocked++
		return
	}

	s.lane = append(s.lane, item{frames: []frame.Frame{f}, stream: id, seq: s.seq})
	s.n++
}

// Pop removes and returns the frame to write next, or reports that there is nothing
// that can be written. An incomplete field block is nothing that can be written.
func (s *scheduler) Pop() (frame.Frame, bool) {
	// Part-way through an item: there is no decision to make, which is the whole
	// mechanism by which a field block stays contiguous.
	if len(s.pinned) > 0 {
		return s.unpin(), true
	}

	if len(s.lane) > 0 {
		head := s.lane[0]

		// The head of the FIFO lane can be a stream's trailer section, and that
		// stream's DATA was pushed before it. §8.1 puts a trailer section after the
		// content, so writing the head first would put the end of a response ahead
		// of its middle. The DATA goes out of turn to prevent it.
		//
		// This is bounded and cannot repeat: the frames it forces out are the ones
		// already waiting on a stream that has finished producing content, and the
		// alternative — leaving the head blocked — would hold every other stream's
		// SETTINGS and PING acknowledgements behind it.
		if q := s.streams[head.stream]; q != nil && q.data[0].seq < head.seq {
			return s.outOfTurn(head.stream, q), true
		}

		s.lane = removeItem(s.lane, 0)
		s.pinned = head.frames
		return s.unpin(), true
	}

	for u := range numBands {
		if len(s.bands[u].ring) > 0 {
			return s.serve(u), true
		}
	}
	return nil, false
}

// unpin takes the next frame of the item being written.
func (s *scheduler) unpin() frame.Frame {
	f := s.pinned[0]
	s.pinned = s.pinned[1:]
	s.n--
	return f
}

// serve takes one DATA frame from band u, whose ring is known to be non-empty, and
// advances the round robin.
func (s *scheduler) serve(u int) frame.Frame {
	b := &s.bands[u]

	turn := b.ring[0]
	id := turn
	if turn == nonIncrementalTurn {
		id = lowest(b.nonInc)
	}

	q := s.streams[id]
	f := s.take(id, q)
	if len(q.data) > 0 {
		// The participant keeps its place in the order by going to the back of it.
		rotate(b.ring)
		return f
	}

	s.leave(id, q)
	if turn == nonIncrementalTurn && len(b.nonInc) > 0 {
		// The group outlived the stream that was served, so its turn is still in the
		// ring and has now been used. When it did not outlive it, leave took the
		// turn out and the next participant is already at the front.
		rotate(b.ring)
	}
	return f
}

// outOfTurn takes a stream's head DATA frame without consulting the round robin,
// which is what Pop's trailer case needs. The stream keeps its place if it has more.
func (s *scheduler) outOfTurn(id uint32, q *streamQueue) frame.Frame {
	f := s.take(id, q)
	if len(q.data) == 0 {
		s.leave(id, q)
	}
	return f
}

// take removes the head DATA frame of a stream known to have one.
func (s *scheduler) take(id uint32, q *streamQueue) frame.Frame {
	f := q.data[0].f
	q.data = q.data[1:]
	s.n--
	if len(q.data) == 0 {
		// The queue is dropped rather than kept empty, so that the map is bounded by
		// the frames held and not by the streams the connection has ever carried.
		delete(s.streams, id)
	}
	return f
}

// enter puts a stream with DATA waiting into the band its priority names.
func (s *scheduler) enter(id uint32, q *streamQueue) {
	p := s.prio[id]
	q.band = p.Urgency()
	q.inc = p.Incremental()

	b := &s.bands[q.band]
	if q.inc {
		b.ring = append(b.ring, id)
		return
	}
	b.nonInc = append(b.nonInc, id)
	if len(b.nonInc) == 1 {
		b.ring = append(b.ring, nonIncrementalTurn)
	}
}

// leave takes a stream out of the band it entered.
func (s *scheduler) leave(id uint32, q *streamQueue) {
	b := &s.bands[q.band]
	if q.inc {
		b.ring = removeID(b.ring, id)
		return
	}
	b.nonInc = removeID(b.nonInc, id)
	if len(b.nonInc) == 0 {
		b.ring = removeID(b.ring, nonIncrementalTurn)
	}
}

// opensBlock reports whether f begins a field block that later frames must complete.
func opensBlock(f frame.Frame) bool {
	switch f.Type() {
	case frame.TypeHeaders, frame.TypePushPromise:
		return !endsBlock(f)
	default:
		return false
	}
}

// endsBlock reports whether f carries END_HEADERS.
func endsBlock(f frame.Frame) bool {
	return f.Flags()&frame.FlagEndHeaders != 0
}

// lowest is the smallest identifier in a non-empty set of them.
func lowest(ids []uint32) uint32 {
	best := ids[0]
	for _, id := range ids[1:] {
		best = min(best, id)
	}
	return best
}

// rotate moves the front entry to the back, leaving the rest in order.
//
// In place, because the alternative — reslicing off the front and appending to the
// back — walks the ring forward through its array and reallocates for as long as the
// connection lives.
func rotate(r []uint32) {
	if len(r) < 2 {
		return
	}
	first := r[0]
	copy(r, r[1:])
	r[len(r)-1] = first
}

// removeID drops the first entry equal to id.
//
// A missing entry is a no-op rather than a panic, and the reason is that this is the
// only place a bookkeeping mistake between the bands and the queues could show up:
// every caller reaches it holding a stream that is supposed to be ringed, so a
// silent nothing here is a scheduler that keeps serving the connection while a test
// on the counters catches the mistake, rather than one that kills the process.
func removeID(ids []uint32, id uint32) []uint32 {
	for i, have := range ids {
		if have == id {
			return append(ids[:i], ids[i+1:]...)
		}
	}
	return ids
}

// removeItem drops one item, keeping the rest in order and the slice anchored at the
// front of its array.
func removeItem(items []item, i int) []item {
	// The vacated tail entry is cleared because an item holds a slice of frames,
	// each of which holds a payload: leaving the reference behind would keep the
	// last field block of a connection alive for as long as the connection is.
	items = append(items[:i], items[i+1:]...)
	clear(items[len(items) : len(items)+1])
	return items
}
