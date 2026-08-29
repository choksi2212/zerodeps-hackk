package attack

import "testing"

// TestRapidReset drives CVE-2023-44487 (HTTP/2 Rapid Reset): open a stream
// with HEADERS, then immediately RST_STREAM it, thousands of times. Each
// cycle makes the server do real work — HPACK decode, stream setup — but
// the stream closes instantly, so a naive MAX_CONCURRENT_STREAMS counter
// never trips.
//
// The test asserts the server eventually sends GOAWAY with
// ENHANCE_YOUR_CALM and closes, once the reset rate exceeds its budget
// (internal/limits' reset bucket).
//
// This is blocked on internal/server exposing an in-process test hook and
// having its stream layer wired up (both "not started" as of this writing
// per README.md's status table — that file is Manas's column, this
// comment is just reading it). See implementation-mihir.md §8.1 and the
// H+50 coordination point in the build plan: he exposes a way to start the
// server in-process for a test, this test drives it. Skipped, not deleted,
// so it stays visible as exactly the next thing to fill in.
func TestRapidReset(t *testing.T) {
	t.Skip("blocked on internal/server's stream layer and an in-process test hook (see comment)")
}

// TestContinuationFlood drives CVE-2023-45288 (CONTINUATION Flood): send
// HEADERS without END_HEADERS, then an unbounded stream of CONTINUATION
// frames that never end the block. A naive server buffers forever.
//
// The test asserts the server tears the connection down once its per-block
// count/byte cap is exceeded, rather than accepting unbounded frames.
//
// Blocked for the same reason as TestRapidReset — see that comment.
func TestContinuationFlood(t *testing.T) {
	t.Skip("blocked on internal/server's stream layer and an in-process test hook (see comment)")
}
