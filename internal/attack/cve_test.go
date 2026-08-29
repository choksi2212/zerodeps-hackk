package attack

import (
	"strings"
	"testing"
	"time"

	"zerodeps/zdh/internal/frame"
	"zerodeps/zdh/internal/h2"
)

// TestRapidReset drives CVE-2023-44487 (HTTP/2 Rapid Reset): open a stream
// with HEADERS, then immediately RST_STREAM it, over and over. Each cycle
// makes the server do real work — HPACK decode, stream setup — but the
// stream closes instantly, so SETTINGS_MAX_CONCURRENT_STREAMS never trips:
// it bounds streams in flight, not streams opened per second.
//
// The defense lives in internal/stream's reset-rate token bucket
// (internal/limits.NewResetBucket, burst 100 per internal/limits.ResetBurst).
// This test sends well past the burst and asserts the server ends the
// connection with GOAWAY(ENHANCE_YOUR_CALM), per RFC 9113 §7.
//
// Writing and reading happen concurrently, on purpose: the server closes the
// socket the moment the bucket empties, and by then this client has already
// queued far more than it takes to trip it. A test that finishes writing
// before it starts reading would see its own write fail with a reset
// connection instead of ever seeing the GOAWAY that caused it.
func TestRapidReset(t *testing.T) {
	addr, logs := startTestServer(t)

	c, err := Dial(addr, 5*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}

	if _, err := c.ReadFrame(); err != nil { // the server's own SETTINGS
		t.Fatalf("reading server SETTINGS: %v", err)
	}

	go func() {
		// internal/limits.ResetBurst is 100. Just past it, not far past it:
		// this loopback connection can queue frames far faster than the
		// server can process and react to them, so sending thousands more
		// than needed leaves a large unread backlog on the server's socket
		// at the moment it closes — which on Windows turns the close into a
		// TCP RST that can arrive before (and discard) the GOAWAY this test
		// is trying to read. Staying close to the threshold keeps that
		// backlog small enough for the GOAWAY to win the race reliably.
		const attempts = 130
		var streamID uint32 = 1
		for i := 0; i < attempts; i++ {
			if err := c.OpenStream(streamID, requestBlock, true); err != nil {
				return
			}
			if err := c.Reset(streamID, h2.Cancel); err != nil {
				return
			}
			streamID += 2 // client-initiated streams are odd (RFC 9113 section 5.1.1)
		}
	}()

	goAway, err := readUntilGoAway(c)
	assertEnhanceYourCalm(t, goAway, err, logs, "CVE-2023-44487")
}

// TestContinuationFlood drives CVE-2023-45288 (CONTINUATION Flood): send
// HEADERS without END_HEADERS, then an unbounded stream of CONTINUATION
// frames that never end the block. A naive server buffers every fragment
// forever, spending unbounded memory (and, if any fragment is
// Huffman-coded, unbounded CPU) on a request it will never be able to act
// on, because the block never completes.
//
// The defense lives in internal/frame.Reader's block limits
// (MaxHeaderBlockSize, MaxContinuationFrames — internal/frame/reader.go,
// checkBlockLimits), explicitly citing this CVE. This test sends more than
// DefaultMaxContinuationFrames (32) empty CONTINUATION frames and asserts
// the server ends the connection with GOAWAY(ENHANCE_YOUR_CALM).
func TestContinuationFlood(t *testing.T) {
	addr, logs := startTestServer(t)

	c, err := Dial(addr, 5*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}

	if _, err := c.ReadFrame(); err != nil { // the server's own SETTINGS
		t.Fatalf("reading server SETTINGS: %v", err)
	}

	if err := c.OpenStreamWithoutEndHeaders(1, requestBlock); err != nil {
		t.Fatalf("OpenStreamWithoutEndHeaders: %v", err)
	}

	go func() {
		// frame.DefaultMaxContinuationFrames is 32. Just past it, not far
		// past it, for the same reason TestRapidReset stays close to its own
		// threshold: less unread backlog on the server's socket when it
		// closes means a more reliable race between the GOAWAY and a TCP
		// RST. Each CONTINUATION is empty on purpose — the flood is in frame
		// count, not bytes, which is exactly the gap MaxHeaderBlockSize
		// alone does not cover.
		const floodFrames = 60
		for i := 0; i < floodFrames; i++ {
			if err := c.Continue(1, nil); err != nil {
				return
			}
		}
	}()

	goAway, err := readUntilGoAway(c)
	assertEnhanceYourCalm(t, goAway, err, logs, "CVE-2023-45288")
}

// readUntilGoAway reads frames until a GOAWAY arrives or the read fails
// (including the connection closing), ignoring anything else the server
// sends in the meantime (SETTINGS, WINDOW_UPDATE, and the like are not the
// point of either test above). The deadline set on c by the caller is what
// bounds this if the server neither sends GOAWAY nor closes.
func readUntilGoAway(c *Client) (frame.GoAwayFrame, error) {
	for {
		f, err := c.ReadFrame()
		if err != nil {
			return frame.GoAwayFrame{}, err
		}
		if ga, ok := f.(frame.GoAwayFrame); ok {
			return ga, nil
		}
	}
}

// assertEnhanceYourCalm checks that the server ended the connection with
// GOAWAY(ENHANCE_YOUR_CALM). If the GOAWAY itself could not be read, it
// falls back to the server's own log (see serverLog's doc comment for why
// that race is inherent to this kind of test, not a bug in it).
//
// The fallback polls rather than checking once: internal/server closes the
// socket as part of conn.Serve returning, and only logs the reason in its
// caller, serveConn, once Serve has already returned — so the client's read
// can fail slightly before the log line exists, not just slightly after.
// The window is a goroutine reschedule, not a network round trip, so a
// short poll is enough without making a passing test slow.
func assertEnhanceYourCalm(t *testing.T, goAway frame.GoAwayFrame, readErr error, logs *serverLog, cveMarker string) {
	t.Helper()

	if readErr == nil {
		if goAway.ErrCode != h2.EnhanceYourCalm {
			t.Fatalf("GOAWAY error code = %s, want ENHANCE_YOUR_CALM", goAway.ErrCode)
		}
		return
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		logged := logs.String()
		if strings.Contains(logged, "ENHANCE_YOUR_CALM") && strings.Contains(logged, cveMarker) {
			t.Logf("GOAWAY was not readable off the wire (%v — see serverLog's doc comment), "+
				"but the server's own log confirms the defense fired:\n%s", readErr, logged)
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("could not read a GOAWAY (%v), and the server log never confirmed ENHANCE_YOUR_CALM / %s either:\n%s",
				readErr, cveMarker, logged)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
