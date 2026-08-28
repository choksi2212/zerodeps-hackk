// Package limits holds every bound this server places on a peer: the timeouts,
// the frame-layer caps, and the rate limits that answer the two HTTP/2 denial-of-
// service CVEs.
//
// They are collected in one package rather than scattered across the layers that
// apply them, for two reasons. A number that bounds a peer is a security decision
// and deserves to be read alongside the others, not found by grepping. And the
// question "what stops a client from doing X forever?" should have one place to
// look — including for the cases where the answer turns out to be "nothing yet".
//
// This package imports nothing but the standard library's time, so it can be
// imported by any layer without introducing a cycle. The layers apply the bounds;
// this package only states them.
package limits

import "time"

// Timeouts bounds how long a connection may spend in each state where a peer
// controls the pace.
//
// A server without these is a denial-of-service target that costs nothing to
// attack: a client that opens a connection and sends nothing occupies a goroutine,
// a TLS session and a file descriptor indefinitely, and one that reads its
// responses one octet a minute occupies the same for as long as it likes. None of
// it requires bandwidth, credentials or a bug.
//
// Every field has a positive default and none can be switched off. A zero or
// negative value takes the default rather than meaning "no limit": in Go a
// deadline in the past means "already expired", so a mistyped configuration would
// either break every connection instantly or, if zero meant infinite, quietly
// remove the defence. Neither is a failure mode worth supporting to gain a
// configuration option nobody should use.
type Timeouts struct {
	// TLSHandshake bounds crypto/tls's handshake. A peer that completes the TCP
	// connection and then dribbles handshake records holds a connection open
	// without ever becoming an HTTP/2 client, so this bound is reached before any
	// other one starts.
	TLSHandshake time.Duration

	// Preface bounds the wait for the 24-octet client connection preface
	// (RFC 9113 §3.4). Connect and say nothing is the cheapest attack there is:
	// one TCP handshake per held connection.
	Preface time.Duration

	// Idle bounds a connection with no open streams and no traffic. It is what
	// stops a client from opening connections purely to hold them, and it is the
	// only one of these that a well-behaved client will legitimately reach —
	// which is why it is the longest.
	Idle time.Duration

	// Write bounds a single socket write. A client that stops reading makes the
	// kernel's send buffer fill and our write block; without this the writer
	// goroutine parks forever holding everything queued behind it.
	Write time.Duration

	// SettingsAck bounds the wait for a peer's acknowledgement of our SETTINGS.
	// §6.5.3 makes this specifically a SETTINGS_TIMEOUT connection error rather
	// than a generic timeout, so the connection layer must be able to tell the
	// two apart.
	SettingsAck time.Duration

	// ShutdownGrace bounds how long a graceful shutdown waits for streams to
	// finish after GOAWAY before the connection is closed regardless. Without a
	// bound, one slow stream makes shutdown unbounded, which turns "stop the
	// server" into "wait indefinitely".
	ShutdownGrace time.Duration
}

// The default timeouts. Each is a compromise between a legitimate client on a bad
// network and an attacker holding resources for free; where there is doubt they
// are on the generous side, because the cost of being wrong in that direction is
// bounded and the cost in the other direction is a broken client.
const (
	DefaultTLSHandshake  = 10 * time.Second
	DefaultPreface       = 10 * time.Second
	DefaultIdle          = 60 * time.Second
	DefaultWrite         = 10 * time.Second
	DefaultSettingsAck   = 10 * time.Second
	DefaultShutdownGrace = 5 * time.Second
)

// DefaultTimeouts returns the timeouts a server uses unless it is told otherwise.
func DefaultTimeouts() Timeouts {
	return Timeouts{
		TLSHandshake:  DefaultTLSHandshake,
		Preface:       DefaultPreface,
		Idle:          DefaultIdle,
		Write:         DefaultWrite,
		SettingsAck:   DefaultSettingsAck,
		ShutdownGrace: DefaultShutdownGrace,
	}
}

// WithDefaults returns t with every unset field filled from DefaultTimeouts, so a
// caller can override one timeout without restating the rest — which is what tests
// do, and a test that had to restate all six would silently stop testing the
// defaults the moment one of them changed.
func (t Timeouts) WithDefaults() Timeouts {
	return t.withDefaultsFrom(DefaultTimeouts())
}

// withDefaultsFrom is WithDefaults with the source of the defaults as a parameter.
//
// The seam exists for one reason, and it is worth stating because the method is
// otherwise pointless indirection: four of the six defaults are ten seconds, so a
// copy-paste slip that filled SettingsAck from d.Write would produce exactly the
// right number and no test comparing against the defaults could see it. Given
// distinct values to fill from, a test can prove that each field is filled from
// its own default rather than from one that happens to match.
func (t Timeouts) withDefaultsFrom(d Timeouts) Timeouts {
	if t.TLSHandshake <= 0 {
		t.TLSHandshake = d.TLSHandshake
	}
	if t.Preface <= 0 {
		t.Preface = d.Preface
	}
	if t.Idle <= 0 {
		t.Idle = d.Idle
	}
	if t.Write <= 0 {
		t.Write = d.Write
	}
	if t.SettingsAck <= 0 {
		t.SettingsAck = d.SettingsAck
	}
	if t.ShutdownGrace <= 0 {
		t.ShutdownGrace = d.ShutdownGrace
	}
	return t
}
