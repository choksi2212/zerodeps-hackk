"""Deliberately break internal/server/writer.go, one guard at a time, and report
which tests notice.

The convention this project runs on: a guard that has never been observed failing
is a guard nobody has tested. Each entry below removes exactly one guard and names
the tests that must fail as a result. A break that fires nothing is a hole — either
in the test or in the reasoning that put the guard there.

A guard is only signed off when its test *fails by name*. Two weaker outcomes are
reported separately rather than being rounded up to a pass, because both mislead:
a test that hangs until the timeout has detected the break and told nobody, and a
test whose binary panics has detected it legibly but has not reported it through
the suite. See outcome() for the full taxonomy.

Run from the repository root. Restores the file on the way out, including on error.
"""

import pathlib
import re
import subprocess
import sys

SRC = pathlib.Path("internal/server/writer.go")

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


def write(text):
    """Write text back byte for byte: no newline translation, so the file that
    goes back at the end is the file that was there at the start."""
    with open(SRC, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def say(line):
    """Print immediately. The campaign takes minutes and is usually run in the
    background, where a buffered stdout shows nothing until it is over."""
    print(line, flush=True)


def outcome(test):
    """Run one test in its own process and say what happened to it.

    One process per test, rather than one per break, and that is the whole point
    of this function. The first version of this script ran every expected test in
    a single `go test` invocation, and a break that panicked killed the binary
    before the later tests in the pattern had run — so a test that never executed
    was reported as having passed, which read as a hole in the suite when it was
    an artifact of the harness. A test is only judged on a run of its own.

    Returns (status, detail):

      fire   the test failed and named itself. This is what a tested guard does.
      crash  the process died without a --- FAIL line, almost always a panic.
             The guard's absence was detected, and the panic message usually
             points straight at the line — for a guard whose absence *is* a
             panic, such as a missing sync.Once, there is nothing better to
             expect. Reported separately so it is never mistaken for a fire.
      hang   the test ran out of time. A real detection with useless
             diagnostics: ten minutes of nothing, then every goroutine in the
             binary dumped. Counted as a hole, because a check nobody can read
             is a check nobody will keep.
      build  the break does not compile. A bug in this script, not in the suite.
      pass   the test passed with the guard removed. A hole.
    """
    proc = subprocess.run(
        ["go", "test", "-count=1", "-timeout", "60s", "-run", "^%s$" % test,
         "./internal/server/"],
        capture_output=True,
        text=True,
    )
    combined = proc.stdout + proc.stderr
    lines = [line.rstrip() for line in combined.splitlines()]

    for i, line in enumerate(lines):
        if line.strip().startswith("--- FAIL:") and line.strip().split()[2].split("/")[0] == test:
            return "fire", fail_detail(lines[i + 1:])

    if proc.returncode == 0:
        return "pass", ""
    if "[build failed]" in combined or "\n# " in "\n" + combined:
        return "build", first_matching(lines, lambda l: l.startswith("./") or ": " in l)
    if "test timed out" in combined:
        return "hang", "no result within the 60s timeout"
    if "panic:" in combined or "fatal error:" in combined:
        return "crash", first_matching(
            lines, lambda l: l.startswith("panic:") or l.startswith("fatal error:"))
    return "crash", "the binary failed without naming a test"


def clip(text, width=96):
    text = text.strip()
    return text if len(text) <= width else text[:width - 3] + "..."


def fail_detail(lines):
    """The assertion's own message, which says more about which guard went missing
    than the test's name does.

    Matched on the `file_test.go:12: message` form rather than on anything with a
    line number in it, because a panicking test prints its stack trace under the
    same banner and those frames would otherwise be quoted in place of the
    message. When there is no message — a panic, where the banner is all the
    framework got out — the panic line is the next best thing.
    """
    for line in lines:
        m = re.search(r"_test\.go:\d+: (.*)", line)
        if m:
            return clip(m.group(1))
    for line in lines:
        if line.strip().startswith(("panic:", "fatal error:")):
            return clip(line)
    return ""


def first_matching(lines, pred):
    for line in lines:
        if pred(line.strip()) or pred(line):
            return clip(line)
    return ""


def main():
    with open(SRC, "r", encoding="utf-8", newline="") as fh:
        original = fh.read()
    holes = []
    try:
        for name, old, new, expect in BREAKS:
            if original.count(old) != 1:
                say("SKIP  %s\n      (the anchor matched %d times, not once)"
                    % (name, original.count(old)))
                holes.append(name + " [anchor did not match]")
                continue
            write(original.replace(old, new, 1))

            results = [(test,) + outcome(test) for test in expect]
            crashed = [t for t, s, _ in results if s == "crash"]
            unnoticed = [t for t, s, _ in results if s not in ("fire", "crash")]

            if unnoticed:
                say("HOLE  " + name)
                holes.append(name)
            elif crashed:
                say("OK*   " + name + "  (detected, but as a crash rather than a failure)")
            else:
                say("OK    " + name)
            for test, status, detail in results:
                # ASCII on purpose: the console this is run from is not UTF-8, and
                # an em-dash here comes out as mojibake in every report line.
                say("      %-5s %s%s" % (status, test, "  -- " + detail if detail else ""))
    finally:
        write(original)

    say("")
    if holes:
        say("%d of %d breaks went unnoticed:" % (len(holes), len(BREAKS)))
        for h in holes:
            say("  - " + h)
        return 1
    say("all %d breaks were caught" % len(BREAKS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
