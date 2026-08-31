"""Deliberately break internal/server/writer.go, one guard at a time, and report
which tests notice.

Each entry below removes exactly one guard and names the tests that must fail as a
result. See breakage.py for the harness and for what the five outcomes mean.

This campaign was rewritten once, and the preflight is what forced it. Replacing the
writer's buffered channel with a scheduler behind a mutex left ten of fourteen anchors
matching nothing: the campaign refused itself with exit 2 and tested none of the file.
That is the outcome to want from a stale campaign, and it is worth writing down
because the alternative -- anchors that still matched but removed the wrong lines --
would have reported a suite full of holes.

Two of the fourteen guards did not survive the rewrite, and both are named rather
than left as breaks that no longer break anything.

  * The sync.Once pair behind Shutdown and Close. Both signals are now bools under
    the mutex, and setting a bool twice is not a thing that can go wrong. The
    idempotence tests are kept -- writer_test.go says why -- but there is nothing
    left here to remove.

  * flush's empty-buffer guard. flush is now reached only from writeBurst, which has
    already queued a frame, so there is no empty case. The test that covered it now
    covers something better: a graceful stop with nothing queued performs no syscall
    at all, and the break for it is the old behaviour restored -- a flush on the way
    out of the loop.

Two of the breaks found holes rather than guards, and they are the reason to run a
campaign against a file that already had thirty-five tests. Each of the two
broadcasts that carry this writer's liveness -- Enqueue waking the loop, and the loop
waking a caller that is waiting for room -- could be deleted with the whole suite
still green, because Shutdown and Close broadcast as well and every test that stops
the writer was handed the wakeup for free. Neither is a rule from RFC 9113 and neither
shows up as a wrong octet: the symptom is a response that is never written, or a
stream goroutine that never returns. writer_test.go's "the two wakeups" section exists
because these two breaks came back as passes.

Three guards have no break for reasons of the harness rather than the suite.

  * stop's broadcast while the mutex is still held. Moving it after the unlock is a
    lost-wakeup window a few instructions wide: the failure is a blocked Enqueue that
    is never woken, which this harness sees as a hang and counts as a hole. The race
    detector is what covers it, and it runs over this package in the gate.

  * The mutex in Prioritize and Forget. Removing it is an unsynchronised write
    against the writer goroutine's reads, which is a data race and not a failure --
    `go test` without -race would report every named test as passing.

  * await's rule that stopGraceful is checked only with the *queue* empty rather than
    the scheduler empty. What distinguishes the two is Pop declining to release a
    frame from an unfinished field block, which is a guard in scheduler.go and belongs
    to that file's campaign.

Two of the breaks below are the reason this file is worth running rather than reading.
The ordering of the three checks in await used to be three comments about which select
case Go might pick, and the two breaks that swap them are the ones that were
unwritable before: a Close that drops the queue about half the time, and a Shutdown
that writes what is queued about half the time, both green under any number of runs.
They are now one exchange of adjacent if statements each.

Run from the repository root. Restores the file on the way out, including on error.
"""

import breakage

SRC = "internal/server/writer.go"
PKG = "./internal/server/"

# (name, old, new, tests that must fail)
BREAKS = [
    # --- await: the three checks, and their order ----------------------------
    (
        "await: stopAbrupt is checked after the queue, so a Close writes one more burst",
        """		if w.stopAbrupt {
			return nil, false
		}
		if f, ok := w.sched.Pop(); ok {
			w.cond.Broadcast()
			return f, true
		}""",
        """		if f, ok := w.sched.Pop(); ok {
			w.cond.Broadcast()
			return f, true
		}
		if w.stopAbrupt {
			return nil, false
		}""",
        ["TestFrameWriterCloseDropsTheQueue", "TestFrameWriterCloseBeatsShutdown"],
    ),
    (
        "await: stopGraceful is checked before the queue, so a GOAWAY never reaches the peer",
        """		if f, ok := w.sched.Pop(); ok {
			w.cond.Broadcast()
			return f, true
		}
		if w.stopGraceful {
			return nil, false
		}""",
        """		if w.stopGraceful {
			return nil, false
		}
		if f, ok := w.sched.Pop(); ok {
			w.cond.Broadcast()
			return f, true
		}""",
        ["TestFrameWriterShutdownWritesWhatIsQueued"],
    ),
    (
        "await: a released frame wakes nobody, so a caller waiting for room waits for ever",
        """		if f, ok := w.sched.Pop(); ok {
			w.cond.Broadcast()
			return f, true
		}""",
        """		if f, ok := w.sched.Pop(); ok {
			return f, true
		}""",
        ["TestFrameWriterAdmitsAWaitingEnqueueWhenTheWriterMakesRoom"],
    ),

    # --- Enqueue: the pre-check, and the bound -------------------------------
    (
        "Enqueue: no pre-check, so a stopped writer accepts a frame it will never write",
        """		if err := w.stopped(); err != nil {
			return err
		}
		if w.admits(f) {""",
        """		if w.admits(f) {""",
        [
            "TestFrameWriterRefusesEnqueueAfterStopping",
            "TestFrameWriterShutdownRefusesAWaitingEnqueue",
        ],
    ),
    (
        "Enqueue: drops the frame instead of blocking, so backpressure is gone",
        """			w.sched.Push(f)
			w.cond.Broadcast()
			return nil
		}
		w.cond.Wait()""",
        """			w.sched.Push(f)
			w.cond.Broadcast()
			return nil
		}
		return nil""",
        [
            "TestFrameWriterQueueHasTheDocumentedDepth",
            "TestFrameWriterShutdownRefusesAWaitingEnqueue",
            "TestFrameWriterReleasesAnEnqueueBlockedOnAStalledPeer",
        ],
    ),
    (
        "Enqueue: the push wakes nobody, so the writer sleeps through the frame it was given",
        """			w.sched.Push(f)
			w.cond.Broadcast()""",
        """			w.sched.Push(f)""",
        ["TestFrameWriterWakesForAFrameEnqueuedWhileItWaits"],
    ),
    (
        "admits: a continuation is refused for a full queue, so an unfinished block deadlocks",
        """	return w.sched.ContinuesBlock(f) || w.sched.Len() < defaultQueueDepth""",
        """	return w.sched.Len() < defaultQueueDepth""",
        ["TestFrameWriterAdmitsAContinuationForAFullQueue"],
    ),
    (
        "admits: no depth bound, so a peer that has stopped reading grows the queue",
        """	return w.sched.ContinuesBlock(f) || w.sched.Len() < defaultQueueDepth""",
        """	return true""",
        ["TestFrameWriterQueueHasTheDocumentedDepth"],
    ),

    # --- stopped: which of two true things to report -------------------------
    (
        "stopped: a writer stopped by a failed write reports nothing, so the frame is lost silently",
        """	if w.gone {
		return w.stoppedErr()
	}
""",
        "",
        [
            "TestFrameWriterLatchesAWriteError",
            "TestFrameWriterReleasesEveryWaiterWhenTheLoopDies",
        ],
    ),
    (
        "stopped: the stop flags are read first, so a failed write reports only that it stopped",
        """	if w.gone {
		return w.stoppedErr()
	}
	if w.stopGraceful || w.stopAbrupt {
		return errWriterStopped
	}""",
        """	if w.stopGraceful || w.stopAbrupt {
		return errWriterStopped
	}
	if w.gone {
		return w.stoppedErr()
	}""",
        ["TestFrameWriterReportsTheWriteErrorAfterAShutdown"],
    ),

    # --- the burst: coalescing, the high water, and the field block ----------
    (
        "writeBurst: no high water, so the buffer grows without bound",
        """		next, ok := w.takeIf(w.fw.Buffered() < coalesceHighWater)""",
        """		next, ok := w.takeIf(true)""",
        ["TestFrameWriterFlushesAtTheHighWater"],
    ),
    (
        "writeBurst: no coalescing, one write per frame",
        """		next, ok := w.takeIf(w.fw.Buffered() < coalesceHighWater)""",
        """		next, ok := w.takeIf(false)""",
        ["TestFrameWriterCoalescesABurstIntoOneWrite"],
    ),
    (
        "takeIf: the burst stops at the high water mid-block, so a Close truncates a field block",
        """	if !room && !w.sched.MidBlock() {""",
        """	if !room {""",
        ["TestFrameWriterCloseCannotTruncateAFieldBlock"],
    ),
    (
        "writeBurst: flushes the frames buffered ahead of one it cannot send",
        """		if err := w.fw.Queue(next); err != nil {
			return err
		}""",
        """		if err := w.fw.Queue(next); err != nil {
			if ferr := w.flush(); ferr != nil {
				return ferr
			}
			return err
		}""",
        ["TestFrameWriterDropsTheBurstItCannotFinish"],
    ),

    # --- the loop's ending ---------------------------------------------------
    (
        "run: the write error is not latched, so Wait reports success",
        """		if err := w.writeBurst(f); err != nil {
			w.err = err
			return
		}""",
        """		if err := w.writeBurst(f); err != nil {
			return
		}""",
        [
            "TestFrameWriterLatchesAWriteError",
            "TestFrameWriterReportsAShortWrite",
            "TestFrameWriterStopsOnADeadlineError",
            "TestFrameWriterDropsTheBurstItCannotFinish",
            "TestFrameWriterRefusesAnOversizeStreamID",
            "TestFrameWriterReleasesAnEnqueueBlockedOnAStalledPeer",
        ],
    ),
    (
        "run: a stop flushes the empty buffer, so a shutdown with nothing queued still writes",
        """		f, ok := w.await()
		if !ok {
			return
		}""",
        """		f, ok := w.await()
		if !ok {
			if ferr := w.flush(); ferr != nil {
				w.err = ferr
			}
			return
		}""",
        ["TestFrameWriterSetsNoDeadlineWithNothingToWrite"],
    ),

    # --- flush: the deadline -------------------------------------------------
    (
        "flush: SetWriteDeadline failure ignored, so the write runs undeadlined",
        """	if err := w.target.SetWriteDeadline(time.Now().Add(w.timeout)); err != nil {
		return err
	}""",
        """	if err := w.target.SetWriteDeadline(time.Now().Add(w.timeout)); err != nil {
		_ = err
	}""",
        ["TestFrameWriterStopsOnADeadlineError"],
    ),
    (
        "flush: deadline is now rather than now plus the timeout",
        """SetWriteDeadline(time.Now().Add(w.timeout))""",
        """SetWriteDeadline(time.Now())""",
        ["TestFrameWriterSetsTheWriteDeadline"],
    ),

    # --- the peer's frame size ----------------------------------------------
    (
        "SetMaxFrameSize: a no-op, so the peer's SETTINGS never reach the writer",
        """	w.fw.SetMaxFrameSize(size)""",
        """	_ = size""",
        ["TestFrameWriterSetMaxFrameSizeRaisesTheLimit"],
    ),
    (
        "MaxFrameSize: the protocol default rather than the peer's, so responses split too small",
        """	return w.fw.MaxFrameSize()""",
        """	return frame.DefaultMaxFrameSize""",
        [
            "TestFrameWriterReportsTheCapAResponseMustSplitAt",
            "TestTheWritePathAHandlerIsGivenReportsThePeersFrameSizeCap",
        ],
    ),

    # --- the two priority methods -------------------------------------------
    (
        "Prioritize: the peer's signal never reaches the scheduler",
        """	w.sched.SetPriority(id, p)""",
        """	_ = p""",
        [
            "TestFrameWriterPrioritizeReordersTheQueue",
            "TestFrameWriterForgetDropsThePriorityItWasGiven",
        ],
    ),
    (
        "Forget: the scheduler keeps a closed stream's priority for the life of the connection",
        """	w.sched.Forget(id)""",
        """	_ = id""",
        ["TestFrameWriterForgetDropsThePriorityItWasGiven"],
    ),
]

breakage.main(SRC, PKG, BREAKS)
