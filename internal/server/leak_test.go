package server

import (
	"runtime"
	"testing"
	"time"
)

// Goroutine-leak detection, without a library.
//
// A leak here is not a slow memory creep, it is a denial of service: this server
// starts goroutines per connection, so one goroutine that outlives its connection
// means a peer can accumulate them by connecting and disconnecting. That makes it
// a security property, and a security property with no test is a hope.
//
// The technique is a baseline count, the work, and then a bounded wait for the
// count to come back. The wait is what makes it usable: a goroutine that is
// returning is not necessarily returned, because the scheduler need not have run
// it yet, so a single count taken straight after the work would fail
// intermittently on a busy machine and teach everyone to ignore it. Polling turns
// "did it return" into "did it return within a deadline", which is the question
// worth asking of a server.
const (
	// leakWait is how long a goroutine has to finish returning. Two seconds is
	// far beyond any scheduling delay and short enough that a real leak is
	// reported rather than waited on.
	leakWait = 2 * time.Second

	// leakPoll is the interval between counts.
	leakPoll = 10 * time.Millisecond
)

// goroutineBaseline is the goroutine count to compare against later. It is called
// before the work starts.
//
// It runs the garbage collector first, not for the memory but for the timing: it
// gives goroutines left over from an earlier test in the same binary a chance to
// finish, so that their late exit cannot be subtracted from this test's count and
// used to hide a real leak.
func goroutineBaseline() int {
	runtime.GC()
	return runtime.NumGoroutine()
}

// goroutineSurplus polls for up to wait and returns how many goroutines are still
// running above baseline, or 0 if the count came back.
//
// It is separate from the assertion so that the polling itself can be tested. A
// leak check that cannot fail is worse than no leak check, because it is read as
// evidence.
//
// The comparison is <=, not ==, deliberately. A count below the baseline means
// something that started before this test has since finished — noise from another
// test, not a leak — and failing on it would make the check flaky in exactly the
// way that gets checks deleted.
func goroutineSurplus(baseline int, wait time.Duration) int {
	deadline := time.Now().Add(wait)
	for {
		runtime.Gosched()
		got := runtime.NumGoroutine()
		if got <= baseline {
			return 0
		}
		if time.Now().After(deadline) {
			return got - baseline
		}
		time.Sleep(leakPoll)
	}
}

// assertNoGoroutineLeak fails t if the goroutine count has not returned to
// baseline within leakWait.
func assertNoGoroutineLeak(t *testing.T, baseline int) {
	t.Helper()

	n := goroutineSurplus(baseline, leakWait)
	if n == 0 {
		return
	}
	// The stack dump is the whole value of the failure. A count says something
	// leaked; the dump says what it was blocked on, which is almost always the
	// answer.
	buf := make([]byte, 1<<16)
	buf = buf[:runtime.Stack(buf, true)]
	t.Fatalf("%d goroutines leaked: still running %v after the work finished, "+
		"baseline was %d\n\n%s", n, leakWait, baseline, buf)
}

// TestGoroutineSurplusNoticesALeak tests the test, with a goroutine deliberately
// left blocked until the check has had its full deadline to see it.
//
// The wait is short rather than leakWait because what is under test is the
// polling, not the length of the deadline: a check that returned 0 on the first
// poll would pass every leak in the package.
func TestGoroutineSurplusNoticesALeak(t *testing.T) {
	baseline := goroutineBaseline()

	release := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		<-release
	}()

	if n := goroutineSurplus(baseline, 100*time.Millisecond); n < 1 {
		t.Errorf("goroutineSurplus = %d with a goroutine deliberately left running, want at least 1", n)
	}

	close(release)
	<-stopped
	assertNoGoroutineLeak(t, baseline)
}

// TestGoroutineSurplusReturnsPromptlyWithNoLeak pins the other half: the check
// must not spend its deadline when nothing leaked. Without it, every test that
// calls the assertion would silently cost leakWait and the suite would slow to
// the point of being skipped.
func TestGoroutineSurplusReturnsPromptlyWithNoLeak(t *testing.T) {
	baseline := goroutineBaseline()

	start := time.Now()
	if n := goroutineSurplus(baseline, leakWait); n != 0 {
		t.Fatalf("goroutineSurplus = %d with nothing started, want 0", n)
	}
	if elapsed := time.Since(start); elapsed >= leakWait {
		t.Errorf("goroutineSurplus took %v with nothing to wait for, want well under %v",
			elapsed, leakWait)
	}
}
