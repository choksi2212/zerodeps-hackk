package limits

import (
	"math"
	"testing"
	"time"
)

// epoch is an arbitrary fixed instant. Bucket takes the time as a parameter, so
// every test below is deterministic and none of them sleeps.
var epoch = time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC)

// TestBucketAllowsExactlyItsBurst is the boundary in both directions: the last
// permitted event and the first refused one, with no time passing between them.
func TestBucketAllowsExactlyItsBurst(t *testing.T) {
	const burst = 10
	b := NewBucket(burst, 1, epoch)
	for i := range burst {
		if !b.Allow(epoch) {
			t.Fatalf("event %d of %d refused; the bucket starts full", i+1, burst)
		}
	}
	if b.Allow(epoch) {
		t.Errorf("event %d permitted with no time elapsed; the burst is %d",
			burst+1, burst)
	}
}

// TestBucketStartsFull checks the choice made in NewBucket. An empty bucket is the
// more obvious implementation and the wrong one: for the reset limiter it would
// refuse the first request cancellation on every connection a browser opens.
func TestBucketStartsFull(t *testing.T) {
	b := NewBucket(5, 1, epoch)
	if got := b.Tokens(epoch); got != 5 {
		t.Errorf("Tokens at construction = %d, want 5", got)
	}
}

// TestBucketRefillsAtItsRate walks the boundary either side of one interval. The
// interval-minus-one-nanosecond case is the one an implementation using rounding
// gets wrong.
func TestBucketRefillsAtItsRate(t *testing.T) {
	// 20 a second: one token every 50ms.
	const interval = 50 * time.Millisecond
	b := NewBucket(1, 20, epoch)

	if !b.Allow(epoch) {
		t.Fatal("the single token was refused at construction")
	}
	cases := []struct {
		after time.Duration
		want  bool
		why   string
	}{
		{0, false, "no time has passed"},
		{interval - time.Nanosecond, false, "one nanosecond short of a full interval"},
		{interval, true, "exactly one interval"},
	}
	for _, tc := range cases {
		fresh := NewBucket(1, 20, epoch)
		if !fresh.Allow(epoch) {
			t.Fatal("the single token was refused at construction")
		}
		if got := fresh.Allow(epoch.Add(tc.after)); got != tc.want {
			t.Errorf("Allow at +%v = %v, want %v (%s)", tc.after, got, tc.want, tc.why)
		}
	}
}

// TestBucketCarriesTheRemainder is the drift test, and the most important one here.
//
// A bucket that set last to now on every refill would throw away the fraction of
// an interval that had not yet earned a token. The rate would then depend on how
// often the caller asked, which is the one thing a rate limit must not do.
//
// The numbers are chosen so the difference is a whole token and the step is not a
// divisor of the interval, which is what makes the bug visible. Asking every 30ms
// against a 50ms interval, the last ask lands at 990ms, by which time nineteen
// whole intervals have completed — so nineteen events are permitted. An
// implementation that discarded the remainder would restart the clock at each ask
// that earned something, effectively earning one token per 60ms, and would permit
// sixteen.
//
// The burst is 100 and the bucket is drained first, so the refill takes the branch
// that carries the remainder. With a burst of one, every refill fills the bucket
// and the carrying branch never runs at all — which is how the first version of
// this test managed to pass with the remainder discarded.
func TestBucketCarriesTheRemainder(t *testing.T) {
	const (
		burst = 100
		rate  = 20 // one token every 50ms
		step  = 30 * time.Millisecond
		asks  = 33 // the last at 990ms
		want  = 19 // floor(990ms / 50ms)
	)
	b := NewBucket(burst, rate, epoch)
	for i := range burst {
		if !b.Allow(epoch) {
			t.Fatalf("event %d of the initial burst was refused", i+1)
		}
	}

	allowed := 0
	for i := 1; i <= asks; i++ {
		if b.Allow(epoch.Add(time.Duration(i) * step)) {
			allowed++
		}
	}
	if allowed != want {
		t.Errorf("a caller asking every %v was allowed %d events over %v, want %d; "+
			"asking more often must not change the rate",
			step, allowed, time.Duration(asks)*step, want)
	}
}

// TestBucketRateIsIndependentOfPollingFrequency generalises the property across
// sampling rates. The steps that are not divisors of the 50ms interval are the ones
// that matter: against a divisor, a bucket that discards the remainder discards
// nothing, so those cases pass either way.
//
// The burst is well above the tokens earned in the window, so the cap cannot mask
// a difference — with a burst of one, every implementation agrees, correct or not.
func TestBucketRateIsIndependentOfPollingFrequency(t *testing.T) {
	const (
		window = time.Second
		burst  = 100
		rate   = 20 // one token every 50ms
	)
	steps := []time.Duration{
		time.Microsecond,
		3 * time.Millisecond,
		7 * time.Millisecond,
		13 * time.Millisecond,
		25 * time.Millisecond, // a divisor
		30 * time.Millisecond,
		70 * time.Millisecond, // longer than the interval
	}
	drained := func() *Bucket {
		b := NewBucket(burst, rate, epoch)
		for i := range burst {
			if !b.Allow(epoch) {
				t.Fatalf("event %d of the initial burst was refused", i+1)
			}
		}
		return b
	}

	// A bucket asked only once at the end of the window is the reference: it has
	// no opportunity to lose a remainder.
	want := drained().Tokens(epoch.Add(window))
	if want != rate {
		t.Fatalf("reference bucket earned %d tokens in %v at %d/s, want %d",
			want, window, rate, rate)
	}

	for _, step := range steps {
		b := drained()
		// Sampling without consuming: only the refill bookkeeping is under test.
		for at := time.Duration(0); at < window; at += step {
			b.Tokens(epoch.Add(at))
		}
		if got := b.Tokens(epoch.Add(window)); got != want {
			t.Errorf("sampled every %v: %d tokens after %v, want %d as when sampled once",
				step, got, window, want)
		}
	}
}

// TestBucketDoesNotBankAFractionWhileFull is the other side of the remainder rule,
// and the two pull in opposite directions: time that has not earned a token must be
// carried forward, unless the bucket was already full, in which case there was
// nothing to earn and carrying it forward would grant the next token early.
//
// The overshoot is under one token, so it takes a deliberate setup to see. A bucket
// filled part-way through an interval, then drained, must wait a full interval from
// the moment it was drained — not from the interval boundary before it.
func TestBucketDoesNotBankAFractionWhileFull(t *testing.T) {
	const interval = 50 * time.Millisecond // 20 a second
	b := NewBucket(1, 20, epoch)
	if !b.Allow(epoch) {
		t.Fatal("the initial token was refused")
	}

	// Idle for one and a half intervals. The bucket fills at the first interval
	// and the remaining half earns nothing, because there was no room for it.
	filled := epoch.Add(interval + interval/2)
	if !b.Allow(filled) {
		t.Fatalf("refused at +%v, by which time a token had been earned", interval+interval/2)
	}

	cases := []struct {
		after time.Duration
		want  bool
	}{
		{interval - time.Nanosecond, false},
		{interval, true},
	}
	for _, tc := range cases {
		fresh := NewBucket(1, 20, epoch)
		fresh.Allow(epoch)
		fresh.Allow(filled)
		if got := fresh.Allow(filled.Add(tc.after)); got != tc.want {
			t.Errorf("Allow %v after the bucket was drained = %v, want %v; the wait "+
				"runs from the moment it was drained, not from the interval "+
				"boundary before it", tc.after, got, tc.want)
		}
	}
}

// TestBucketCapsAtItsBurst checks that an idle connection banks nothing beyond the
// burst. Without the cap, a connection held open for an hour would arrive with
// seventy-two thousand reset tokens, which is the attack with a delay in front.
func TestBucketCapsAtItsBurst(t *testing.T) {
	idle := []time.Duration{
		time.Second,
		time.Minute,
		time.Hour,
		24 * time.Hour,
		365 * 24 * time.Hour,
	}
	for _, d := range idle {
		b := NewBucket(10, 20, epoch)
		for range 10 {
			b.Allow(epoch)
		}
		if got := b.Tokens(epoch.Add(d)); got != 10 {
			t.Errorf("after %v idle: %d tokens, want the burst of 10", d, got)
		}
		// And spending the refilled burst must still stop at the burst.
		allowed := 0
		for range 100 {
			if b.Allow(epoch.Add(d)) {
				allowed++
			}
		}
		if allowed != 10 {
			t.Errorf("after %v idle: %d events allowed at once, want 10", d, allowed)
		}
	}
}

// TestBucketIgnoresTimeGoingBackwards covers a caller that passes a
// non-monotonic time, which time.Now does not produce but a test, a serialised
// timestamp or a mistaken subtraction all can.
//
// The requirement is one-sided: going back must not earn tokens, and must not
// destroy tokens already earned. A limiter that can be rewound is a limiter an
// attacker resets at will.
func TestBucketIgnoresTimeGoingBackwards(t *testing.T) {
	b := NewBucket(3, 20, epoch)
	for range 3 {
		b.Allow(epoch)
	}
	// Forward far enough to refill fully, then back well before construction.
	if got := b.Tokens(epoch.Add(time.Second)); got != 3 {
		t.Fatalf("Tokens after a second = %d, want the burst of 3", got)
	}
	for _, back := range []time.Duration{-time.Nanosecond, -time.Hour, -365 * 24 * time.Hour} {
		if got := b.Tokens(epoch.Add(time.Second).Add(back)); got != 3 {
			t.Errorf("Tokens at %v in the past = %d, want the 3 already earned", back, got)
		}
	}
	// And going back does not grant anything either: spend the burst at a past
	// instant and the bucket is empty, not replenished.
	past := epoch.Add(-time.Hour)
	for i := range 3 {
		if !b.Allow(past) {
			t.Fatalf("event %d refused; the 3 earned tokens should still be there", i+1)
		}
	}
	if b.Allow(past) {
		t.Error("a fourth event was permitted at an instant in the past")
	}
}

// TestBucketClampsItsConfiguration covers the values a mistake produces. A burst
// or rate of zero would make the bucket refuse everything, which presents as a
// server that rejects all traffic for no visible reason.
func TestBucketClampsItsConfiguration(t *testing.T) {
	cases := []struct {
		name  string
		burst int
		rate  int
	}{
		{"zero burst", 0, 20},
		{"negative burst", -1, 20},
		{"most negative burst", math.MinInt, 20},
		{"zero rate", 10, 0},
		{"negative rate", 10, -1},
		{"both zero", 0, 0},
		{"both most negative", math.MinInt, math.MinInt},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := NewBucket(tc.burst, tc.rate, epoch)
			if b.Burst() < 1 {
				t.Fatalf("Burst = %d, want at least 1", b.Burst())
			}
			if !b.Allow(epoch) {
				t.Error("the first event was refused; a bucket that permits nothing " +
					"is never the intended configuration")
			}
			// And it must still refill, rather than permit that one event forever.
			for range b.Burst() {
				b.Allow(epoch)
			}
			if !b.Allow(epoch.Add(2 * time.Second)) {
				t.Error("no token after two seconds; the clamped rate does not refill")
			}
		})
	}
}

// TestBucketSurvivesARateTooFastForItsUnit is the divide-by-zero case. A rate
// above a billion a second truncates to a zero-length interval, and dividing the
// elapsed time by it panics — which would be a remote crash if the rate ever came
// from anything but a constant in this package.
//
// Every rate here yields the finest interval a time.Duration can express, one
// nanosecond, so five nanoseconds must earn exactly the burst of five.
func TestBucketSurvivesARateTooFastForItsUnit(t *testing.T) {
	rates := []int{
		1_000_000_000, // exactly one token per nanosecond
		1_000_000_001, // the first rate that truncates the interval to zero
		2_000_000_000,
		math.MaxInt32,
		math.MaxInt, // and an absurd one, in case the clamp is a range check
	}
	for _, rate := range rates {
		b := NewBucket(5, rate, epoch)
		for range 5 {
			b.Allow(epoch)
		}
		// The panic, if there is one, happens here.
		if got := b.Tokens(epoch.Add(5 * time.Nanosecond)); got != 5 {
			t.Errorf("rate %d: %d tokens after 5ns, want the burst of 5", rate, got)
		}
	}
}

// TestBucketHandlesFarFutureTimes checks the arithmetic at the edge of what a
// time.Duration can express. A Duration tops out at about 292 years, so Sub
// saturates on the later cases rather than wrapping, and the refill multiplies a
// token count by an interval — a connection whose timestamps are centuries apart
// must not come out with a negative token count.
func TestBucketHandlesFarFutureTimes(t *testing.T) {
	far := []time.Time{
		epoch.Add(100 * 365 * 24 * time.Hour), // a century, still inside the range
		epoch.AddDate(1000, 0, 0),             // a millennium, well outside it
		time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
		time.Unix(1<<62, 0),
	}
	for _, at := range far {
		b := NewBucket(10, 20, epoch)
		for range 10 {
			b.Allow(epoch)
		}
		if got := b.Tokens(at); got != 10 {
			t.Errorf("at %v: %d tokens, want the burst of 10 and no overflow", at, got)
		}
		if !b.Allow(at) {
			t.Errorf("at %v: an event was refused with a full bucket", at)
		}
	}
}

// TestBucketRateWithAnUnevenDivisor checks a rate that does not divide a second.
// Three a second is 333.333…ms and the interval truncates to 333ms, which makes
// the refill marginally fast — the direction an error has to go, since this
// limiter closes connections when it fires.
func TestBucketRateWithAnUnevenDivisor(t *testing.T) {
	const (
		rate    = 3
		burst   = 100 // above the tokens earned below, so the cap never engages
		seconds = 10
	)
	b := NewBucket(burst, rate, epoch)
	for range burst {
		b.Allow(epoch)
	}
	allowed := 0
	for i := 1; i <= seconds*1000; i++ {
		if b.Allow(epoch.Add(time.Duration(i) * time.Millisecond)) {
			allowed++
		}
	}
	if want := rate * seconds; allowed != want {
		t.Errorf("%d events over %ds at a rate of %d/s, want %d; the truncated "+
			"interval must not cost the peer a whole token", allowed, seconds, rate, want)
	}
}

// TestResetBucketRefusesTheRapidResetAttack is CVE-2023-44487 as the attacker
// sends it: open a stream, reset it, repeat with no delay. Every frame is legal
// and no other limit engages, because a stream reset immediately never counts
// against SETTINGS_MAX_CONCURRENT_STREAMS.
func TestResetBucketRefusesTheRapidResetAttack(t *testing.T) {
	b := NewResetBucket(epoch)
	allowed := 0
	// Ten thousand resets in the same instant, which is roughly what the attack
	// achieves per connection per second.
	for range 10_000 {
		if b.Allow(epoch) {
			allowed++
		}
	}
	if allowed != ResetBurst {
		t.Errorf("%d of 10000 instantaneous resets permitted, want exactly the "+
			"burst of %d", allowed, ResetBurst)
	}

	// Sustained at ten times the permitted rate, the attacker gets the rate and
	// not the request rate they asked for.
	b = NewResetBucket(epoch)
	for range ResetBurst {
		b.Allow(epoch)
	}
	const (
		attackRate = 10 * ResetRefillPerSecond
		seconds    = 10
	)
	allowed = 0
	for i := range attackRate * seconds {
		at := epoch.Add(time.Duration(i) * (time.Second / attackRate))
		if b.Allow(at) {
			allowed++
		}
	}
	if want := ResetRefillPerSecond * seconds; allowed > want+1 {
		t.Errorf("%d resets permitted over %d seconds at %d/s, want no more than "+
			"%d — the sustained rate is what bounds the attack",
			allowed, seconds, attackRate, want)
	}
}

// TestResetBucketPermitsABrowser is the other side, and the reason the burst is a
// hundred rather than something tighter. A user navigating away cancels every
// request in flight at once; a limiter that treated that as an attack would close
// the connection of every user who clicked a link early.
func TestResetBucketPermitsABrowser(t *testing.T) {
	b := NewResetBucket(epoch)

	// A page with a full stream table, all cancelled at once.
	for i := range MaxConcurrentStreams {
		if !b.Allow(epoch) {
			t.Fatalf("cancellation %d of %d refused; a browser may legitimately "+
				"cancel every open stream in one burst",
				i+1, MaxConcurrentStreams)
		}
	}

	// Then five minutes of ordinary browsing: a couple of cancellations a second,
	// which is more than a person generates.
	at := epoch
	for range 5 * 60 * 2 {
		at = at.Add(500 * time.Millisecond)
		if !b.Allow(at) {
			t.Fatalf("a cancellation was refused %v into ordinary browsing at 2/s",
				at.Sub(epoch))
		}
	}
}

// TestBucketTokensDoesNotConsume separates the observer from the consumer. Tokens
// is used in a diagnostic, and a diagnostic that changed the thing it reports
// would make the limit depend on whether anyone was looking.
func TestBucketTokensDoesNotConsume(t *testing.T) {
	b := NewBucket(4, 20, epoch)
	for range 10 {
		if got := b.Tokens(epoch); got != 4 {
			t.Fatalf("Tokens = %d after being read repeatedly, want 4", got)
		}
	}
	for i := range 4 {
		if !b.Allow(epoch) {
			t.Fatalf("event %d refused after Tokens was read 10 times", i+1)
		}
	}
}
