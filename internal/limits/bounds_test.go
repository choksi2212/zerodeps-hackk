package limits

import (
	"testing"

	"zerodeps/zdh/internal/frame"
)

// hpackDefaultTableSize is the dynamic table size a connection starts with, from §4.2
// of RFC 7541 — and therefore the size in force when a peer sends no
// SETTINGS_HEADER_TABLE_SIZE at all, which is what browsers do.
//
// Not in bounds.go, because it is not this server's policy: it is a number the
// protocol fixes, and the assertions below are what relate our policy to it.
const hpackDefaultTableSize = 4096

// TestFrameBoundsMatchTheFrameLayer is what makes the frame layer's comments true.
//
// internal/frame documents these bounds as living here and carries its own copies
// as the defaults for a zero-valued ReaderConfig, so that the package stands alone
// in a test without importing a policy package. Two copies of a security number
// that can drift apart is worse than either place owning it outright: the server
// would run with one value and the tests would prove the other.
//
// This is the only place the two packages meet, and it meets them in a test rather
// than at runtime so that internal/limits stays a leaf.
func TestFrameBoundsMatchTheFrameLayer(t *testing.T) {
	cases := []struct {
		name   string
		policy int
		frame  int
	}{
		{"MaxFrameSize", MaxFrameSize, frame.DefaultMaxFrameSize},
		{"MaxHeaderBlockSize", MaxHeaderBlockSize, frame.DefaultMaxHeaderBlockSize},
		{"MaxContinuationFrames", MaxContinuationFrames, frame.DefaultMaxContinuationFrames},
	}
	for _, tc := range cases {
		if tc.policy != tc.frame {
			t.Errorf("limits.%s is %d but frame's default is %d; the two must agree, "+
				"or the server enforces one bound and the frame tests prove another",
				tc.name, tc.policy, tc.frame)
		}
	}
}

// TestMaxFrameSizeIsLegal checks the bound against the protocol rather than
// against our own preference. §6.5.2 fixes the permitted range for
// SETTINGS_MAX_FRAME_SIZE, and a value outside it is a value a peer is entitled to
// reject — advertising it would make the connection fail at SETTINGS.
func TestMaxFrameSizeIsLegal(t *testing.T) {
	const (
		floor   = 1 << 14   // the initial value, and the minimum §6.5.2 allows
		ceiling = 1<<24 - 1 // the maximum §6.5.2 allows
	)
	if MaxFrameSize < floor || MaxFrameSize > ceiling {
		t.Errorf("MaxFrameSize = %d, want between %d and %d (RFC 9113 §6.5.2)",
			MaxFrameSize, floor, ceiling)
	}
}

// TestHeaderBlockBoundIsReachable checks the bound is not accidentally stricter
// than the frame size, which would refuse a single HEADERS frame the peer is
// entitled to send: we advertise MaxFrameSize, so a peer may fill one.
func TestHeaderBlockBoundIsReachable(t *testing.T) {
	if MaxHeaderBlockSize < MaxFrameSize {
		t.Errorf("MaxHeaderBlockSize = %d is below MaxFrameSize = %d; a peer sending "+
			"one legal maximum-size HEADERS frame would be refused for flooding",
			MaxHeaderBlockSize, MaxFrameSize)
	}
}

// TestBothContinuationBoundsAreNecessary proves neither CVE-2023-45288 bound is
// redundant, by showing each is reachable without the other firing first.
//
// This is the claim the comments in bounds.go make, and it is the kind of claim
// that quietly stops being true when someone tunes a number. If the count bound
// were raised past the point where the size bound always fires first, the
// small-frame flood — which is the attack as reported — would go unbounded while
// the code still looked like it had two defences.
func TestBothContinuationBoundsAreNecessary(t *testing.T) {
	// Large frames: the accumulated size is reached before the frame count is, so
	// the size bound is the one that fires and the count bound alone would not.
	if MaxContinuationFrames*MaxFrameSize < MaxHeaderBlockSize {
		t.Errorf("%d CONTINUATION frames of %d octets total %d, which is below "+
			"MaxHeaderBlockSize = %d: the size bound can never fire, so it is dead",
			MaxContinuationFrames, MaxFrameSize,
			MaxContinuationFrames*MaxFrameSize, MaxHeaderBlockSize)
	}

	// Small frames: MaxContinuationFrames frames of one octet each accumulate
	// almost nothing, so the size bound cannot fire and only the count bound
	// stops the flood.
	if MaxContinuationFrames >= MaxHeaderBlockSize {
		t.Errorf("MaxContinuationFrames = %d is not below MaxHeaderBlockSize = %d: "+
			"a flood of one-octet CONTINUATION frames would hit the size bound "+
			"first, making the count bound dead", MaxContinuationFrames, MaxHeaderBlockSize)
	}
}

// TestResetBurstCoversAFullStreamTable is the relation between the two limits that
// matters, and it is not obvious.
//
// A user navigating away cancels every request in flight, so a browser with the
// full advertised stream table open sends MaxConcurrentStreams resets in a single
// burst. If the reset burst were smaller than the stream limit, the server would
// close the connection of every user who clicked a link while a page was loading —
// a rate limit that fires on the traffic it exists to permit.
func TestResetBurstCoversAFullStreamTable(t *testing.T) {
	if ResetBurst < MaxConcurrentStreams {
		t.Errorf("ResetBurst = %d is below MaxConcurrentStreams = %d; cancelling a "+
			"full stream table at once is ordinary browser behaviour and must not "+
			"trip the limit", ResetBurst, MaxConcurrentStreams)
	}
}

// TestBoundsArePlausible bounds every number from both sides. A limit set absurdly
// high is not a limit, and one set absurdly low breaks clients; both failures are
// invisible until someone is affected by them.
func TestBoundsArePlausible(t *testing.T) {
	cases := []struct {
		name    string
		got     int
		floor   int
		ceiling int
		tooLow  string
		tooHigh string
	}{
		{
			name: "MaxHeaderBlockSize", got: MaxHeaderBlockSize,
			floor: 1 << 13, ceiling: 1 << 22,
			tooLow:  "ordinary requests carry a kilobyte or two of headers, and cookies push that up",
			tooHigh: "the whole point of the bound is that a peer cannot make us buffer without limit",
		},
		{
			name: "MaxContinuationFrames", got: MaxContinuationFrames,
			floor: 1, ceiling: 1024,
			tooLow:  "a header block legitimately spans a continuation when it exceeds the frame size",
			tooHigh: "each frame costs a parse, which is what the flood exploits",
		},
		{
			name: "MaxConcurrentStreams", got: MaxConcurrentStreams,
			floor: 8, ceiling: 1000,
			tooLow:  "browsers open dozens of streams for one page and stall below that",
			tooHigh: "each stream is a goroutine and a set of buffers one peer can hold",
		},
		{
			name: "MaxEncoderTableSize", got: MaxEncoderTableSize,
			floor: hpackDefaultTableSize, ceiling: 1 << 24,
			tooLow:  "below HPACK's own default the bound would clamp a table nobody asked to enlarge",
			tooHigh: "the table is memory a peer allocates with one SETTINGS entry",
		},
		{
			name: "MaxConns", got: MaxConns,
			floor: 16, ceiling: 8192,
			tooLow:  "a browser opens one connection per origin and a load balancer opens several",
			tooHigh: "the process runs out of file descriptors before it runs out of memory",
		},
		{
			name: "ResetBurst", got: ResetBurst,
			floor: MaxConcurrentStreams, ceiling: 10_000,
			tooLow:  "cancelling a full page of requests is ordinary",
			tooHigh: "the burst is what an attacker gets for free on every connection",
		},
		{
			name: "ResetRefillPerSecond", got: ResetRefillPerSecond,
			floor: 1, ceiling: 1000,
			tooLow:  "a person clicking through a site generates a few cancellations a second",
			tooHigh: "the sustained rate is the whole bound on CVE-2023-44487",
		},
	}
	for _, tc := range cases {
		if tc.got < tc.floor {
			t.Errorf("%s = %d, below the floor of %d: %s", tc.name, tc.got, tc.floor, tc.tooLow)
		}
		if tc.got > tc.ceiling {
			t.Errorf("%s = %d, above the ceiling of %d: %s", tc.name, tc.got, tc.ceiling, tc.tooHigh)
		}
	}
}

// TestMaxConnsLeavesDescriptorHeadroom is the reasoning in MaxConns' comment,
// written down as an assertion.
//
// The bound is chosen against file descriptors, not memory, and the failure it
// avoids is specific: a process that accepts as many connections as it has
// descriptors spends the last of them on a peer and then cannot open anything else —
// no accept, no log rotation, no certificate reload. The symptom is a server that
// answers requests it already has and refuses everything new, under load, with
// nothing in the log to say why.
//
// The commonest soft limit is 1024, and half of it is the headroom. Raising MaxConns
// past that is defensible, but only together with raising the process limit — which
// is a deployment decision this repository cannot make, so it fails here instead.
func TestMaxConnsLeavesDescriptorHeadroom(t *testing.T) {
	// The soft RLIMIT_NOFILE a process on Linux typically starts with.
	const commonDescriptorLimit = 1024

	if MaxConns > commonDescriptorLimit/2 {
		t.Errorf("MaxConns = %d is more than half of the usual %d descriptor limit; "+
			"at that many connections the process has no descriptors left for the "+
			"listener, the certificate or the log", MaxConns, commonDescriptorLimit)
	}
}

// TestMaxConcurrentStreamsFitsItsSettingsField checks the value can be sent.
// SETTINGS_MAX_CONCURRENT_STREAMS is a 32-bit field (§6.5.1), so a value above
// that range would be truncated on the wire into something we do not enforce.
func TestMaxConcurrentStreamsFitsItsSettingsField(t *testing.T) {
	if MaxConcurrentStreams < 0 || uint64(MaxConcurrentStreams) > 1<<32-1 {
		t.Errorf("MaxConcurrentStreams = %d does not fit the 32-bit SETTINGS field "+
			"(RFC 9113 §6.5.1)", MaxConcurrentStreams)
	}
}

// TestEncoderTableBoundSurvivesNarrowingToInt is the last sentence of
// MaxEncoderTableSize's comment, written down as an assertion.
//
// SETTINGS_HEADER_TABLE_SIZE arrives as a uint32 and the codec's
// SetMaxDynamicTableSize takes an int, so the conversion happens somewhere, and
// bounding the value before converting it is what makes it safe. That only holds
// while the bound itself fits an int on the narrowest platform Go compiles for — an
// int is 32 bits on 386 and on arm — and a bound above that would reach the codec as
// a negative table size on a platform nobody ran these tests on.
func TestEncoderTableBoundSurvivesNarrowingToInt(t *testing.T) {
	// The largest value a 32-bit int holds.
	const narrowestInt = 1<<31 - 1

	if MaxEncoderTableSize > narrowestInt {
		t.Errorf("MaxEncoderTableSize = %d does not fit a 32-bit int; bounding a peer's "+
			"SETTINGS_HEADER_TABLE_SIZE against it would still hand the codec a negative "+
			"size on a 32-bit platform", MaxEncoderTableSize)
	}
}
