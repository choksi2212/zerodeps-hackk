"""Deliberately break internal/server/scheduler.go, one guard at a time, and report
which tests notice.

Each entry below removes exactly one guard and names the tests that must fail as a
result. See breakage.py for the harness and for what the five outcomes mean.

This is the file with the fewest rules from RFC 9113 in it and the most ways to be
subtly wrong. A frame writer that drops a frame fails h2spec; a scheduler that loses a
turn writes every frame, in an order nobody can see from the outside. So the counters
and the ring bookkeeping are broken here as thoroughly as the ordering is: nine of the
breaks below touch nothing but s.n and s.blocked, and the symptom of several of those is
a Len that has gone negative by the time the connection drains -- which is a queue the
writer's depth bound would admit anything at all into.

Two breaks found holes rather than guards, and they are the reason to run a campaign
against a file that already had forty-six tests.

  * SetPriority's same-value early return. Removing it charges a client a turn for
    repeating a PRIORITY_UPDATE it has already sent, and that was undetectable while
    TestSchedulerSetPriorityToTheSameValueChangesNothing re-signalled both of its two
    streams in turn: re-signalling every participant of a ring in order is a full
    rotation of that ring and leaves it exactly where it started. The test now repeats
    the signal for one stream as well, which is what a client sending the same frame
    twice actually does.

  * The delete that takes a completed field block out of runs. Every field block in
    TestSchedulerDoesNotGrowOverAConnectionsLife was complete in its first frame, so
    the map that round was meant to bound was never populated in it at all. That test's
    header section is now spread over two frames, and the symptom turns out to be worse
    than the leak it was written for: the RST_STREAM pushed after the block joins the
    item that was left in runs, which has already been copied into the lane, so the
    reset is never written.

Three guards have no break, and all three absences are deliberate.

  * lowest's unsigned comparison. Holding an identifier in an int32, or comparing two
    of them signed, is the classic way to get this wrong -- and it cannot be wrong
    here, because §5.1.1 makes 2^31-1 the largest identifier a client can open, so no
    two identifiers this scheduler can hold differ in sign. The break would be a no-op
    on every reachable input, which is a break that comes back a pass on a suite with
    nothing to find. TestLowest walks the top of the space anyway.

  * The absence of a mutex. Every method here is called by the writer under the
    writer's, which is the whole reason this structure can be driven one Push and one
    Pop at a time by a test with no timing in it. There is no lock to remove; the
    pairing is covered by the race detector over internal/server, which the gate runs.

  * The sequence a completed field block is stamped with -- the position of its first
    frame rather than its last. Stamping it last would only reorder a block against a
    stream's own DATA pushed *between* two of the block's frames, and internal/response
    holds one mutex across a whole burst, so nothing upstream can produce that shape.
    A break for it would be a break on an unreachable input.

Run from the repository root. Restores the file on the way out, including on error.
"""

import breakage

SRC = "internal/server/scheduler.go"
PKG = "./internal/server/"

# (name, old, new, tests that must fail)
BREAKS = [
    # --- the two constants ----------------------------------------------------
    (
        "numBands is one short, so the urgency §4.1 of RFC 9218 allows has no lane",
        """const numBands = priority.MaxUrgency + 1""",
        """const numBands = priority.MaxUrgency""",
        [
            "TestSchedulerServesTheLowestUrgencyFirst",
            "TestSchedulerRespectsUrgencyUnderTheWorstClient",
        ],
    ),
    (
        "the non-incremental sentinel is a real stream identifier, so stream 1 is not banded",
        """const nonIncrementalTurn uint32 = 0""",
        """const nonIncrementalTurn uint32 = 1""",
        [
            "TestSchedulerNonDataGoesBeforeData",
            "TestSchedulerDataOnStreamZeroIsNotBanded",
        ],
    ),

    # --- Len, and the counters that make it mean something --------------------
    (
        "Len counts the frames of an incomplete block, so the writer's bound refuses them",
        """func (s *scheduler) Len() int { return s.n }""",
        """func (s *scheduler) Len() int { return s.n + s.blocked }""",
        [
            "TestSchedulerHoldsAnIncompleteFieldBlock",
            "TestSchedulerIncompleteBlockIsNeverWritten",
        ],
    ),
    (
        "Push does not count a queued DATA frame",
        """		q.data = append(q.data, queued{f: f, seq: s.seq})
		s.n++""",
        """		q.data = append(q.data, queued{f: f, seq: s.seq})""",
        [
            "TestSchedulerLenCountsWhatCanBeWritten",
            "TestSchedulerNonDataGoesBeforeData",
        ],
    ),
    (
        "Push does not count a frame it puts in the lane",
        """	s.lane = append(s.lane, item{frames: []frame.Frame{f}, stream: id, seq: s.seq})
	s.n++""",
        """	s.lane = append(s.lane, item{frames: []frame.Frame{f}, stream: id, seq: s.seq})""",
        [
            "TestSchedulerLenCountsWhatCanBeWritten",
            "TestSchedulerNonDataKeepsItsOrder",
        ],
    ),
    (
        "a completed block reaches the lane uncounted, so Len says the connection is idle",
        """			s.blocked -= len(open.frames)
			s.n += len(open.frames)""",
        """			s.blocked -= len(open.frames)""",
        [
            "TestSchedulerHoldsAnIncompleteFieldBlock",
            "TestSchedulerFieldBlockIsContiguous",
        ],
    ),
    (
        "a completed block stays counted as blocked as well as writable",
        """			s.blocked -= len(open.frames)
""",
        "",
        ["TestSchedulerHoldsAnIncompleteFieldBlock"],
    ),
    (
        "a fragment joining an open block is not counted as blocked",
        """	if open := s.runs[id]; open != nil {
		open.frames = append(open.frames, f)
		s.blocked++""",
        """	if open := s.runs[id]; open != nil {
		open.frames = append(open.frames, f)""",
        [
            "TestSchedulerHoldsAnIncompleteFieldBlock",
            "TestSchedulerIncompleteBlockIsNeverWritten",
        ],
    ),
    (
        "the first frame of a held block is not counted as blocked",
        """	if opensBlock(f) {
		s.runs[id] = &item{frames: []frame.Frame{f}, stream: id, seq: s.seq}
		s.blocked++
		return
	}""",
        """	if opensBlock(f) {
		s.runs[id] = &item{frames: []frame.Frame{f}, stream: id, seq: s.seq}
		return
	}""",
        [
            "TestSchedulerHoldsAnIncompleteFieldBlock",
            "TestSchedulerIncompleteBlockIsNeverWritten",
        ],
    ),
    (
        "unpin does not discount the frame it hands out, so the queue never appears to drain",
        """	f := s.pinned[0]
	s.pinned = s.pinned[1:]
	s.n--""",
        """	f := s.pinned[0]
	s.pinned = s.pinned[1:]""",
        [
            "TestSchedulerLenCountsWhatCanBeWritten",
            "TestSchedulerNonDataKeepsItsOrder",
        ],
    ),
    (
        "take does not discount the DATA frame it hands out",
        """	f := q.data[0].f
	q.data = q.data[1:]
	s.n--""",
        """	f := q.data[0].f
	q.data = q.data[1:]""",
        [
            "TestSchedulerLenCountsWhatCanBeWritten",
            "TestSchedulerNonDataGoesBeforeData",
        ],
    ),

    # --- ContinuesBlock and MidBlock: what the writer asks --------------------
    (
        "ContinuesBlock: any frame on a stream with an open block bypasses the depth bound",
        """	return f.Type() == frame.TypeContinuation && s.runs[f.Stream()] != nil""",
        """	return s.runs[f.Stream()] != nil""",
        ["TestSchedulerContinuesBlock"],
    ),
    (
        "ContinuesBlock: any CONTINUATION bypasses it, whether a block is open or not",
        """	return f.Type() == frame.TypeContinuation && s.runs[f.Stream()] != nil""",
        """	return f.Type() == frame.TypeContinuation""",
        ["TestSchedulerContinuesBlock"],
    ),
    (
        "MidBlock: never, so the writer's high water can stop inside a field block",
        """func (s *scheduler) MidBlock() bool { return len(s.pinned) > 0 }""",
        """func (s *scheduler) MidBlock() bool { return false }""",
        ["TestFrameWriterCloseCannotTruncateAFieldBlock"],
    ),
    (
        "MidBlock: always, so the burst never stops and the buffer is unbounded",
        """func (s *scheduler) MidBlock() bool { return len(s.pinned) > 0 }""",
        """func (s *scheduler) MidBlock() bool { return true }""",
        ["TestFrameWriterFlushesAtTheHighWater"],
    ),

    # --- SetPriority and Forget ----------------------------------------------
    (
        "SetPriority records a signal for stream 0, so the sentinel means two things",
        """	if id == nonIncrementalTurn {
		// §7.1 of RFC 9218 gives the frame a Prioritized Stream ID, and a
		// PRIORITY_UPDATE naming stream 0 is refused long before here. Ignoring it
		// keeps the sentinel meaning one thing.
		return
	}
""",
        "",
        ["TestSchedulerSetPriorityForStreamZeroIsIgnored"],
    ),
    (
        "SetPriority remembers nothing for a stream that has no DATA waiting yet",
        """	s.prio[id] = p

	q := s.streams[id]
	if q == nil {
		return
	}""",
        """	q := s.streams[id]
	if q == nil {
		return
	}
	s.prio[id] = p""",
        [
            "TestSchedulerServesTheLowestUrgencyFirst",
            "TestSchedulerDefaultUrgencyIsThree",
            "TestSchedulerIncrementalSharesBandwidth",
        ],
    ),
    (
        "SetPriority records the signal on the way out, so the move reads the old one",
        """	s.prio[id] = p

	q := s.streams[id]""",
        """	defer func() { s.prio[id] = p }()

	q := s.streams[id]""",
        [
            "TestSchedulerSetPriorityMovesQueuedData",
            "TestSchedulerSetPriorityChangesTheParticipantKind",
        ],
    ),
    (
        "SetPriority moves the stream even when the signal says nothing new",
        """	if q.band == p.Urgency() && q.inc == p.Incremental() {
		return
	}
""",
        "",
        ["TestSchedulerSetPriorityToTheSameValueChangesNothing"],
    ),
    (
        "SetPriority does not move the DATA already waiting, so the signal applies to the next response",
        """	s.leave(id, q)
	s.enter(id, q)""",
        """	_ = q.band""",
        [
            "TestSchedulerSetPriorityMovesQueuedData",
            "TestSchedulerSetPriorityChangesTheParticipantKind",
        ],
    ),
    (
        "Forget remembers, so a connection's priority table grows with every request",
        """	delete(s.prio, id)""",
        """	_ = id""",
        [
            "TestSchedulerForgetBoundsThePriorityTable",
            "TestSchedulerDoesNotGrowOverAConnectionsLife",
        ],
    ),
    (
        "Forget reclassifies the DATA still waiting, moving it out from under its ring",
        """	delete(s.prio, id)""",
        """	delete(s.prio, id)
	if q := s.streams[id]; q != nil {
		s.leave(id, q)
		s.enter(id, q)
	}""",
        ["TestSchedulerForgetLeavesQueuedDataScheduled"],
    ),

    # --- Push: which lane, and the sequence ----------------------------------
    (
        "Push does not advance the sequence, so nothing can be ordered against a stream's own DATA",
        """func (s *scheduler) Push(f frame.Frame) {
	s.seq++""",
        """func (s *scheduler) Push(f frame.Frame) {""",
        [
            "TestSchedulerTrailersFollowTheirOwnData",
            "TestSchedulerResetFollowsItsOwnData",
            "TestSchedulerDoesNotGrowOverAConnectionsLife",
        ],
    ),
    (
        "Push bands a DATA frame on stream 0, which is the sentinel's identifier",
        """	if f.Type() == frame.TypeData && id != nonIncrementalTurn {""",
        """	if f.Type() == frame.TypeData {""",
        ["TestSchedulerDataOnStreamZeroIsNotBanded"],
    ),
    (
        "Push enters the stream into its band on every DATA frame, not on its first",
        """		if len(q.data) == 1 {
			s.enter(id, q)
		}""",
        """		if len(q.data) >= 1 {
			s.enter(id, q)
		}""",
        [
            "TestSchedulerIncrementalSharesBandwidth",
            "TestSchedulerNonDataGoesBeforeData",
        ],
    ),

    # --- Push: a field block is one item -------------------------------------
    (
        "Push does not join a fragment to the block it continues, so §4.3's contiguity is gone",
        """	// A frame continuing a block already begun joins it, and completes it if it
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

""",
        "",
        [
            "TestSchedulerHoldsAnIncompleteFieldBlock",
            "TestSchedulerFieldBlockIsContiguous",
            "TestSchedulerIncompleteBlockIsNeverWritten",
            "TestSchedulerMultiFrameTrailerBlockFollowsItsData",
        ],
    ),
    (
        "a completed block is left in runs, so the next block on that stream joins it",
        """		if endsBlock(f) {
			delete(s.runs, id)""",
        """		if endsBlock(f) {""",
        [
            "TestSchedulerContinuesBlock",
            "TestSchedulerDoesNotGrowOverAConnectionsLife",
        ],
    ),
    (
        "opensBlock: a block complete in its first frame is held anyway, and never completes",
        """	case frame.TypeHeaders, frame.TypePushPromise:
		return !endsBlock(f)""",
        """	case frame.TypeHeaders, frame.TypePushPromise:
		return true""",
        [
            "TestOpensAndEndsBlock",
            "TestSchedulerCompleteFieldBlockIsNotHeld",
            "TestSchedulerTrailersFollowTheirOwnData",
        ],
    ),
    (
        "opensBlock: PUSH_PROMISE does not begin a field block, though §4.3 says it does",
        """	case frame.TypeHeaders, frame.TypePushPromise:""",
        """	case frame.TypeHeaders:""",
        ["TestOpensAndEndsBlock", "TestSchedulerPushPromiseOpensABlock"],
    ),
    (
        "endsBlock reads END_STREAM rather than END_HEADERS",
        """	return f.Flags()&frame.FlagEndHeaders != 0""",
        """	return f.Flags()&frame.FlagEndStream != 0""",
        [
            "TestOpensAndEndsBlock",
            "TestSchedulerCompleteFieldBlockIsNotHeld",
            "TestSchedulerHoldsAnIncompleteFieldBlock",
        ],
    ),

    # --- Pop: the pinned item, the lane, the trailer, and the bands ----------
    (
        "Pop ignores the item it is part-way through, so half a field block is discarded",
        """	if len(s.pinned) > 0 {
		return s.unpin(), true
	}

""",
        "",
        [
            "TestSchedulerHoldsAnIncompleteFieldBlock",
            "TestSchedulerFieldBlockIsContiguous",
            "TestSchedulerPinnedBlockOutlastsLaterPushes",
        ],
    ),
    (
        "Pop serves the lane last, so a WINDOW_UPDATE waits behind a megabyte of DATA",
        """	if len(s.lane) > 0 {
		head := s.lane[0]""",
        """	if len(s.streams) == 0 && len(s.lane) > 0 {
		head := s.lane[0]""",
        [
            "TestSchedulerNonDataGoesBeforeData",
            "TestSchedulerLaneFrameForAStreamWithLaterData",
            "TestSchedulerPinnedBlockOutlastsLaterPushes",
        ],
    ),
    (
        "Pop pins an item without taking it out of the lane, so the lane never drains",
        """		s.lane = removeItem(s.lane, 0)
		s.pinned = head.frames""",
        """		s.pinned = head.frames""",
        [
            "TestSchedulerNonDataKeepsItsOrder",
            "TestSchedulerLenCountsWhatCanBeWritten",
        ],
    ),
    (
        "Pop writes the lane's head before the DATA that was pushed ahead of it",
        """		if q := s.streams[head.stream]; q != nil && q.data[0].seq < head.seq {
			return s.outOfTurn(head.stream, q), true
		}

""",
        "",
        [
            "TestSchedulerTrailersFollowTheirOwnData",
            "TestSchedulerMultiFrameTrailerBlockFollowsItsData",
            "TestSchedulerResetFollowsItsOwnData",
            "TestSchedulerDoesNotGrowOverAConnectionsLife",
        ],
    ),
    (
        "Pop compares the sequence the wrong way, so a stream's DATA jumps its own HEADERS",
        """q != nil && q.data[0].seq < head.seq""",
        """q != nil && q.data[0].seq > head.seq""",
        [
            "TestSchedulerLaneFrameForAStreamWithLaterData",
            "TestSchedulerTrailersFollowTheirOwnData",
        ],
    ),
    (
        "Pop searches the bands from the highest urgency down",
        """	for u := range numBands {
		if len(s.bands[u].ring) > 0 {
			return s.serve(u), true
		}
	}""",
        """	for u := numBands - 1; u >= 0; u-- {
		if len(s.bands[u].ring) > 0 {
			return s.serve(u), true
		}
	}""",
        [
            "TestSchedulerServesTheLowestUrgencyFirst",
            "TestSchedulerDefaultUrgencyIsThree",
            "TestSchedulerLowerBandPreempts",
            "TestSchedulerBandsKeepSeparateRotations",
            "TestSchedulerRespectsUrgencyUnderTheWorstClient",
        ],
    ),

    # --- serve: the round robin ----------------------------------------------
    (
        "serve takes the sentinel for a stream identifier instead of resolving the group",
        """	turn := b.ring[0]
	id := turn
	if turn == nonIncrementalTurn {
		id = lowest(b.nonInc)
	}""",
        """	turn := b.ring[0]
	id := turn""",
        [
            "TestSchedulerNonIncrementalGoesInAscendingStreamID",
            "TestSchedulerDefaultUrgencyIsThree",
        ],
    ),
    (
        "serve does not rotate, so the first participant keeps the band until it is done",
        """	if len(q.data) > 0 {
		// The participant keeps its place in the order by going to the back of it.
		rotate(b.ring)
		return f
	}""",
        """	if len(q.data) > 0 {
		return f
	}""",
        [
            "TestSchedulerIncrementalSharesBandwidth",
            "TestSchedulerNonIncrementalGroupIsOneParticipant",
            "TestSchedulerAvoidsTheStarvationRFC9218Names",
        ],
    ),
    (
        "serve rotates when the participant leaves too, so the next one loses its turn",
        """	s.leave(id, q)
	if turn == nonIncrementalTurn && len(b.nonInc) > 0 {
		// The group outlived the stream that was served, so its turn is still in the
		// ring and has now been used. When it did not outlive it, leave took the
		// turn out and the next participant is already at the front.
		rotate(b.ring)
	}
	return f""",
        """	s.leave(id, q)
	rotate(b.ring)
	return f""",
        ["TestSchedulerIncrementalRotationSurvivesAStreamEnding"],
    ),
    (
        "serve never rotates on a leave, so a surviving group keeps a turn it has used",
        """	s.leave(id, q)
	if turn == nonIncrementalTurn && len(b.nonInc) > 0 {
		// The group outlived the stream that was served, so its turn is still in the
		// ring and has now been used. When it did not outlive it, leave took the
		// turn out and the next participant is already at the front.
		rotate(b.ring)
	}
	return f""",
        """	s.leave(id, q)
	return f""",
        ["TestSchedulerNonIncrementalGroupIsOneParticipant"],
    ),

    # --- outOfTurn and take --------------------------------------------------
    (
        "outOfTurn leaves the band claiming a participant with nothing waiting",
        """	f := s.take(id, q)
	if len(q.data) == 0 {
		s.leave(id, q)
	}
	return f""",
        """	f := s.take(id, q)
	return f""",
        [
            "TestSchedulerOutOfTurnKeepsTheRingIntact",
            "TestSchedulerTrailersFollowTheirOwnData",
        ],
    ),
    (
        "take keeps the empty queue, so the map is bounded by the connection's streams",
        """	if len(q.data) == 0 {
		// The queue is dropped rather than kept empty, so that the map is bounded by
		// the frames held and not by the streams the connection has ever carried.
		delete(s.streams, id)
	}
""",
        "",
        [
            "TestSchedulerNonDataGoesBeforeData",
            "TestSchedulerTrailersFollowTheirOwnData",
        ],
    ),

    # --- enter and leave: the band bookkeeping -------------------------------
    (
        "enter ignores the incremental parameter, so §10 of RFC 9218's sharing never happens",
        """	q.band = p.Urgency()
	q.inc = p.Incremental()""",
        """	q.band = p.Urgency()
	q.inc = false""",
        [
            "TestSchedulerIncrementalSharesBandwidth",
            "TestSchedulerIncrementalRotationSurvivesAStreamEnding",
        ],
    ),
    (
        "enter ignores the urgency, so every stream shares one band",
        """	q.band = p.Urgency()
	q.inc = p.Incremental()""",
        """	q.band = 0
	q.inc = p.Incremental()""",
        [
            "TestSchedulerServesTheLowestUrgencyFirst",
            "TestSchedulerDefaultUrgencyIsThree",
            "TestSchedulerBandsKeepSeparateRotations",
        ],
    ),
    (
        "enter gives the non-incremental group a turn per stream instead of one turn",
        """	b.nonInc = append(b.nonInc, id)
	if len(b.nonInc) == 1 {
		b.ring = append(b.ring, nonIncrementalTurn)
	}""",
        """	b.nonInc = append(b.nonInc, id)
	b.ring = append(b.ring, nonIncrementalTurn)""",
        [
            "TestSchedulerNonIncrementalGroupIsOneParticipant",
            "TestSchedulerNonIncrementalGoesInAscendingStreamID",
        ],
    ),
    (
        "leave takes the group's turn away while the group still has members",
        """	b.nonInc = removeID(b.nonInc, id)
	if len(b.nonInc) == 0 {
		b.ring = removeID(b.ring, nonIncrementalTurn)
	}""",
        """	b.nonInc = removeID(b.nonInc, id)
	b.ring = removeID(b.ring, nonIncrementalTurn)""",
        [
            "TestSchedulerNonIncrementalGoesInAscendingStreamID",
            "TestSchedulerNonIncrementalGroupIsOneParticipant",
        ],
    ),
    (
        "leave looks the classification up instead of using the one the stream entered with",
        """func (s *scheduler) leave(id uint32, q *streamQueue) {
	b := &s.bands[q.band]
	if q.inc {""",
        """func (s *scheduler) leave(id uint32, q *streamQueue) {
	p := s.prio[id]
	b := &s.bands[p.Urgency()]
	if p.Incremental() {""",
        [
            "TestSchedulerSetPriorityChangesTheParticipantKind",
            "TestSchedulerSetPriorityMovesQueuedData",
            "TestSchedulerForgetLeavesQueuedDataScheduled",
        ],
    ),

    # --- the pieces ----------------------------------------------------------
    (
        "lowest returns the last identifier rather than the least",
        """	best := ids[0]
	for _, id := range ids[1:] {
		best = min(best, id)
	}""",
        """	best := ids[0]
	for _, id := range ids[1:] {
		best = id
	}""",
        ["TestLowest", "TestSchedulerNonIncrementalGoesInAscendingStreamID"],
    ),
    (
        "rotate turns the ring backwards",
        """	first := r[0]
	copy(r, r[1:])
	r[len(r)-1] = first""",
        """	last := r[len(r)-1]
	copy(r[1:], r)
	r[0] = last""",
        ["TestRotate"],
    ),
    (
        "rotate does not guard the ring too short to turn",
        """	if len(r) < 2 {
		return
	}
""",
        "",
        ["TestRotate"],
    ),
    (
        "removeID empties the slice when the entry is not in it",
        """	return ids
}""",
        """	return nil
}""",
        ["TestRemoveID"],
    ),
    (
        "removeItem leaves the vacated entry holding a field block for the connection's life",
        """	items = append(items[:i], items[i+1:]...)
	clear(items[len(items) : len(items)+1])
	return items""",
        """	items = append(items[:i], items[i+1:]...)
	return items""",
        ["TestRemoveItemReleasesTheVacatedEntry"],
    ),
    (
        "removeItem clears one entry too far, taking a live item with it",
        """	clear(items[len(items) : len(items)+1])""",
        """	clear(items[len(items)-1 : len(items)])""",
        ["TestRemoveItemReleasesTheVacatedEntry", "TestSchedulerNonDataKeepsItsOrder"],
    ),
]

breakage.main(SRC, PKG, BREAKS)
