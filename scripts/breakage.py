"""The harness the break campaigns run on.

The convention this project runs on: a guard that has never been observed failing
is a guard nobody has tested. A campaign is a list of edits that each remove
exactly one guard from one file, together with the tests that must fail as a
result. A break that fires nothing is a hole — either in the test or in the
reasoning that put the guard there.

A guard is only signed off when its test *fails by name*. Two weaker outcomes are
reported separately rather than being rounded up to a pass, because both mislead:
a test that hangs until the timeout has detected the break and told nobody, and a
test whose binary panics has detected it legibly but has not reported it through
the suite. See outcome() for the full taxonomy.

Every campaign is checked before any of it is run — see preflight — because a
malformed break is silent in the worst way: it reports the tests it named as passing,
which reads as a hole in the suite rather than a typo in the campaign.

This module holds no campaign of its own. It exists because the second campaign
would otherwise have been a copy of the first, and two copies of a harness drift:
the taxonomy the reports are read against has to be one taxonomy.
"""

import pathlib
import re
import subprocess
import sys


def write(path, text):
    """Write text back byte for byte: no newline translation, so the file that goes
    back at the end is the file that was there at the start.

    This matters on Windows, where the default text mode would turn every LF in the
    file into CRLF and leave the whole file rewritten after a campaign that is
    supposed to be a no-op."""
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def read(path):
    with open(path, "r", encoding="utf-8", newline="") as fh:
        return fh.read()


def say(line):
    """Print immediately. A campaign takes minutes and is usually run in the
    background, where a buffered stdout shows nothing until it is over."""
    print(line, flush=True)


def outcome(test, package):
    """Run one test in its own process and say what happened to it.

    One process per test, rather than one per break, and that is the whole point of
    this function. The first version ran every expected test in a single `go test`
    invocation, and a break that panicked killed the binary before the later tests
    in the pattern had run — so a test that never executed was reported as having
    passed, which read as a hole in the suite when it was an artifact of the
    harness. A test is only judged on a run of its own.

    Returns (status, detail):

      fire   the test failed and named itself. This is what a tested guard does.
      crash  the process died without a --- FAIL line, almost always a panic.
             The guard's absence was detected, and the panic message usually
             points straight at the line — for a guard whose absence *is* a
             panic, such as a missing sync.Once, there is nothing better to
             expect. Reported separately so it is never mistaken for a fire.
      hang   the test ran out of time. A real detection with useless
             diagnostics: a minute of nothing, then every goroutine in the
             binary dumped. Counted as a hole, because a check nobody can read
             is a check nobody will keep.
      build  the break does not compile. A bug in the campaign, not in the suite.
      pass   the test passed with the guard removed. A hole.
    """
    proc = subprocess.run(
        ["go", "test", "-count=1", "-timeout", "60s", "-run", "^%s$" % test, package],
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
    same banner and those frames would otherwise be quoted in place of the message.
    When there is no message — a panic, where the banner is all the framework got
    out — the panic line is the next best thing.
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


def preflight(original, breaks):
    """Check every break before any of them is run, and report what cannot work.

    Up front rather than as each break comes round, which is where this check used to
    live. A campaign is thirty to forty breaks and each one is several `go test`
    processes, so a bad anchor on the last break was twenty minutes of waiting to be
    told about a typo. Everything checked here is a property of the campaign and of
    the file it edits, both of which are known before the first test runs.

    An anchor that matches twice removes a different guard than the one named. One
    that matches none tests nothing while every expected test reports a pass, which
    reads as a suite full of holes. A break whose replacement equals its anchor is a
    no-op with the same symptom. A break with no expected tests can never fail. Two
    breaks sharing a name make the hole list ambiguous, which matters because that
    list is what gets acted on.
    """
    problems = []
    seen = set()
    for name, old, new, expect in breaks:
        n = original.count(old)
        if n != 1:
            problems.append("%s: the anchor matched %d times, not once" % (name, n))
        if old == new:
            problems.append("%s: the replacement is identical to the anchor" % name)
        if not expect:
            problems.append("%s: no tests are named as having to fail" % name)
        if name in seen:
            problems.append("%s: two breaks share this name" % name)
        seen.add(name)
    return problems


def campaign(source, package, breaks):
    """Run every break in turn and report. Returns a process exit status.

    source is the file to edit, package the Go package whose tests are run, and
    breaks a list of (name, old, new, tests) tuples. The file is restored on the
    way out, including on error: a campaign that left the tree modified would be
    indistinguishable from a campaign that found a bug.

    Exit status 0 if every break was caught, 1 if any went unnoticed, and 2 if the
    campaign itself is malformed. The last is separate on purpose: a campaign that
    cannot run has found nothing, and reporting it as holes would say the suite is
    weak when what is wrong is the file describing it.
    """
    src = pathlib.Path(source)
    original = read(src)

    problems = preflight(original, breaks)
    if problems:
        say("%d of %d breaks cannot be run as written, and nothing was tested:"
            % (len(problems), len(breaks)))
        for p in problems:
            say("  - " + p)
        return 2

    holes = []
    try:
        for name, old, new, expect in breaks:
            write(src, original.replace(old, new, 1))

            results = [(test,) + outcome(test, package) for test in expect]
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
        write(src, original)

    say("")
    if holes:
        say("%d of %d breaks went unnoticed:" % (len(holes), len(breaks)))
        for h in holes:
            say("  - " + h)
        return 1
    say("all %d breaks were caught" % len(breaks))
    return 0


def main(source, package, breaks):
    """The entry point a campaign script ends with."""
    sys.exit(campaign(source, package, breaks))
