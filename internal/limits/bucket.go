package limits

import "time"

// Bucket is a token bucket: it permits a burst of events and then a fixed rate.
//
// It is the shape a rate limit has to have here. A plain counter cannot tell a
// browser cancelling a page's worth of requests from an attacker, because both
// send a hundred resets in a moment; a plain rate cannot either, because the
// browser's hundred arrive faster than any sustainable rate. Only "a burst, and
// then a rate" describes both.
//
// The current time is a parameter rather than read from the clock inside. That is
// not for dependency-injection tidiness: a rate limiter whose tests have to sleep
// is a rate limiter that is tested at one rate, slowly, and flakily under load.
// With the time passed in, a test can step a bucket through an hour of hostile
// traffic in microseconds and assert exactly where it refuses.
//
// A Bucket is not safe for concurrent use. It is owned by the connection whose
// events it counts, and touched only from that connection's reader goroutine.
type Bucket struct {
	// burst is the capacity, in tokens.
	burst int64

	// interval is the time to earn one token. Storing the interval rather than a
	// rate keeps the refill in integer arithmetic: with a rate, the tokens earned
	// in an interval would be fractional and the remainder would have to be
	// carried in a float.
	interval time.Duration

	// tokens is the number available now, as of last.
	tokens int64

	// last is the time the bucket was last refilled. It is advanced by whole
	// intervals rather than to the current time, so the fraction of an interval
	// that has not yet earned a token is carried forward instead of discarded.
	// Rounding it away would cost a caller that asks frequently a slice of its
	// allowance on every call, and would make the effective rate depend on how
	// often the caller asks — which is the one thing a rate limit must not do.
	last time.Time
}

// NewBucket returns a bucket that permits burst events immediately and then
// refillPerSecond events a second, full at time now.
//
// It starts full rather than empty. An empty bucket would refuse a peer's first
// action, which for a reset limiter would mean rejecting the first request
// cancellation on every connection.
//
// burst and refillPerSecond must be positive; a bucket that permits nothing is a
// configuration mistake that would present as a server rejecting all traffic, so
// both are raised to 1 rather than accepted. There is no way to construct a
// bucket that permits everything, for the same reason the timeouts cannot be
// switched off.
func NewBucket(burst, refillPerSecond int, now time.Time) *Bucket {
	if burst < 1 {
		burst = 1
	}
	if refillPerSecond < 1 {
		refillPerSecond = 1
	}
	// Integer division truncates, so a rate that does not divide a second evenly
	// yields a slightly shorter interval and therefore a slightly faster refill:
	// the error is in the peer's favour, which is the correct direction for a limit
	// that closes connections when it fires.
	interval := time.Second / time.Duration(refillPerSecond)
	if interval < 1 {
		// A rate above a billion a second truncates to a zero-length interval,
		// which would divide by zero on the first refill. One nanosecond is the
		// finest interval a time.Duration can express, so it is the fastest rate
		// this can mean. No caller wants a rate this high; the clamp is here
		// because "no caller wants it" is not the same as "it cannot happen".
		interval = 1
	}
	return &Bucket{
		burst:    int64(burst),
		interval: interval,
		tokens:   int64(burst),
		last:     now,
	}
}

// NewResetBucket returns the bucket that bounds RST_STREAM on one connection
// (CVE-2023-44487), full at time now.
func NewResetBucket(now time.Time) *Bucket {
	return NewBucket(ResetBurst, ResetRefillPerSecond, now)
}

// Allow reports whether one event is permitted at time now, and consumes a token
// if it is.
//
// now is expected to come from time.Now, whose values carry a monotonic reading —
// so a system clock that jumps, forward or back, does not affect the rate. A now
// earlier than the last call is still handled: it earns nothing rather than
// removing tokens already earned, because a limiter that can be rewound is a
// limiter an attacker can reset.
func (b *Bucket) Allow(now time.Time) bool {
	b.refill(now)
	if b.tokens <= 0 {
		return false
	}
	b.tokens--
	return true
}

// Tokens returns the tokens available at time now, refilling first. It exists for
// tests and for the diagnostic in a GOAWAY debug field; nothing in the protocol
// path needs it.
func (b *Bucket) Tokens(now time.Time) int64 {
	b.refill(now)
	return b.tokens
}

// Burst returns the bucket's capacity.
func (b *Bucket) Burst() int64 { return b.burst }

// refill credits the tokens earned since the last refill.
func (b *Bucket) refill(now time.Time) {
	earned := int64(now.Sub(b.last) / b.interval)
	if earned <= 0 {
		// Either not yet a whole token, or now is before the last refill. The two
		// cases want the same thing and it is not a coincidence: in both, nothing
		// has been earned and last must not move, so that the elapsed time counts
		// towards the next token instead of being discarded.
		//
		// The backwards case is the one worth stating. time.Now carries a
		// monotonic reading, so a system clock that jumps cannot produce it — but
		// a timestamp that has been serialised, or a subtraction done in the wrong
		// order, can. Truncation toward zero means a small step backwards yields
		// zero rather than a negative, so this one check has to cover both.
		return
	}
	if earned >= b.burst-b.tokens {
		// Full, and last moves to now rather than by whole intervals: a full
		// bucket has no unspent fraction to carry. Advancing it by intervals
		// instead would leave last behind now by up to an interval, and the next
		// token would arrive that much early — a small overshoot, but one that
		// compounds once per burst.
		//
		// This branch is also what keeps the addition below from overflowing.
		// earned is bounded only by how long the connection has been idle, and at
		// an interval of a nanosecond it can reach the largest int64 there is;
		// tokens are only ever added when earned is smaller than the space left,
		// so the sum cannot exceed the burst.
		b.tokens = b.burst
		b.last = now
		return
	}
	b.tokens += earned
	b.last = b.last.Add(time.Duration(earned) * b.interval)
}
