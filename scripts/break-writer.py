"""Deliberately break internal/server/writer.go, one guard at a time, and report
which tests notice.

Each entry below removes exactly one guard and names the tests that must fail as a
result. See breakage.py for the harness and for what the five outcomes mean.

Run from the repository root. Restores the file on the way out, including on error.
"""

import breakage

SRC = "internal/server/writer.go"
PKG = "./internal/server/"

# (name, old, new, tests that must fail)
BREAKS = [
    (
        "run: no abrupt pre-check, so a closed abrupt races a ready queue",
        """		select {
		case <-w.abrupt:
			return
		default:
		}

		select {
		case f := <-w.queue:""",
        """		select {
		case f := <-w.queue:""",
        ["TestFrameWriterCloseDropsTheQueue", "TestFrameWriterCloseBeatsShutdown"],
    ),
    (
        "Enqueue: no pre-check, so a stopped writer accepts a frame it will never write",
        """	select {
	case <-w.graceful:
		return errWriterStopped
	case <-w.abrupt:
		return errWriterStopped
	case <-w.done:
		return w.stoppedErr()
	default:
	}

	select {
	case w.queue <- f:""",
        """	select {
	case w.queue <- f:""",
        ["TestFrameWriterRefusesEnqueueAfterStopping"],
    ),
    (
        "flush: deadline set even with nothing buffered",
        """	if w.fw.Buffered() == 0 {""",
        """	if false {""",
        ["TestFrameWriterSetsNoDeadlineWithNothingToWrite"],
    ),
    (
        "writeBurst: no high water, so the buffer grows without bound",
        """	for w.fw.Buffered() < coalesceHighWater {
		select {
		case next := <-w.queue:
			if err := w.fw.Queue(next); err != nil {
				return err
			}
		default:
			return w.flush()
		}
	}
	return w.flush()""",
        """	for {
		select {
		case next := <-w.queue:
			if err := w.fw.Queue(next); err != nil {
				return err
			}
		default:
			return w.flush()
		}
	}""",
        ["TestFrameWriterFlushesAtTheHighWater"],
    ),
    (
        "writeBurst: no coalescing, one write per frame",
        """	for w.fw.Buffered() < coalesceHighWater {""",
        """	for false {""",
        ["TestFrameWriterCoalescesABurstIntoOneWrite"],
    ),
    (
        "run: graceful drops the queue, so a GOAWAY never reaches the peer",
        """			if err := w.flushQueued(); err != nil {
				w.err = err
			}
			return""",
        """			return""",
        ["TestFrameWriterShutdownWritesWhatIsQueued"],
    ),
    (
        "run: the write error is not latched, so Wait reports success",
        """			if err := w.writeBurst(f); err != nil {
				w.err = err
				return
			}""",
        """			if err := w.writeBurst(f); err != nil {
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
    (
        "Enqueue: drops the frame instead of blocking, so backpressure is gone",
        """	select {
	case w.queue <- f:
		return nil
	case <-w.graceful:""",
        """	select {
	case w.queue <- f:
		return nil
	default:
		return nil
	case <-w.graceful:""",
        ["TestFrameWriterReleasesAnEnqueueBlockedOnAStalledPeer"],
    ),
    (
        "writeBurst: flushes the frames buffered ahead of one it cannot send",
        """		case next := <-w.queue:
			if err := w.fw.Queue(next); err != nil {
				return err
			}""",
        """		case next := <-w.queue:
			if err := w.fw.Queue(next); err != nil {
				if ferr := w.flush(); ferr != nil {
					return ferr
				}
				return err
			}""",
        ["TestFrameWriterDropsTheBurstItCannotFinish"],
    ),
    (
        "SetMaxFrameSize: a no-op, so the peer's SETTINGS never reach the writer",
        """	w.fw.SetMaxFrameSize(size)""",
        """	_ = size""",
        ["TestFrameWriterSetMaxFrameSizeRaisesTheLimit"],
    ),
    (
        "Shutdown and Close: no sync.Once, so a second call closes a closed channel",
        """func (w *frameWriter) Shutdown() {
	w.gracefulOnce.Do(func() { close(w.graceful) })
}""",
        """func (w *frameWriter) Shutdown() {
	close(w.graceful)
}""",
        ["TestFrameWriterStopSignalsAreIdempotent", "TestFrameWriterStopSignalsAreConcurrencySafe"],
    ),
]

breakage.main(SRC, PKG, BREAKS)
