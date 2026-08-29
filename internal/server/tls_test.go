package server

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"zerodeps/zdh/internal/certgen"
	"zerodeps/zdh/internal/frame"
	"zerodeps/zdh/internal/limits"
)

// handshakeConn has to be satisfied by the type this server actually gets.
//
// This is the assertion that keeps the whole file honest, and it is a compile-time
// one because the runtime symptom is silence. handshake decides whether a connection
// is TLS by asserting nc to this interface; add a method *tls.Conn does not have and
// the assertion fails for every connection, every handshake is skipped as though the
// socket were cleartext, and the server answers an unencrypted SETTINGS frame to a
// client waiting for a ServerHello. No test that builds its own fake would notice.
var _ handshakeConn = (*tls.Conn)(nil)

// --- a certificate the whole file shares --------------------------------------

// The certificate is generated once. Key generation is one scalar multiplication and
// cheap, but forty tests each doing their own is forty for no gain — and one
// certificate also means the pool below trusts exactly what every server here serves.
var (
	tlsCertOnce sync.Once
	tlsCertPEM  certgen.PEM
	tlsCertErr  error
)

func testCertPEM(t *testing.T) certgen.PEM {
	t.Helper()
	tlsCertOnce.Do(func() {
		tlsCertPEM, tlsCertErr = certgen.Self(certgen.Config{Hosts: []string{"localhost", "127.0.0.1"}})
	})
	if tlsCertErr != nil {
		t.Fatalf("generating the test certificate: %v", tlsCertErr)
	}
	return tlsCertPEM
}

func testCert(t *testing.T) tls.Certificate {
	t.Helper()
	cert, err := testCertPEM(t).Certificate()
	if err != nil {
		t.Fatalf("parsing the test certificate: %v", err)
	}
	return cert
}

func testCertPool(t *testing.T) *x509.CertPool {
	t.Helper()
	pool, err := testCertPEM(t).Pool()
	if err != nil {
		t.Fatalf("building the test certificate pool: %v", err)
	}
	return pool
}

// --- a TLS connection under the test's control --------------------------------

// fakeTLSConn satisfies handshakeConn without any cryptography.
//
// Two of the failures it can produce are unreachable through a real handshake
// against a configuration checkTLSConfig has approved — a client cannot complete a
// handshake having negotiated a protocol the server never offered, and a loopback
// socket does not refuse a deadline. Both still need a path that has been run, and
// the second is the one that matters: SetDeadline fails on a descriptor that has gone
// away, and the code under it must report that rather than proceed into a handshake
// with no timeout at all.
//
// It embeds a nil net.Conn to be a net.Conn, which is what handshake takes. Nothing
// here calls through to it, and a change that made handshake read or write before
// negotiating would fail as a nil dereference — loudly, which is the right outcome
// for a server that wrote to a socket before it was encrypted.
type fakeTLSConn struct {
	net.Conn

	handshakeErr error
	proto        string

	// setDeadlineErr fails the failNthSet'th SetDeadline call, counting from one, so
	// that a test can fail the arming and the clearing separately. They are different
	// bugs: the first leaves a handshake with no timeout, the second leaves a working
	// connection with the handshake's.
	setDeadlineErr error
	failNthSet     int

	mu        sync.Mutex
	deadlines []time.Time
	shook     int
}

func (c *fakeTLSConn) Handshake() error {
	c.mu.Lock()
	c.shook++
	c.mu.Unlock()
	return c.handshakeErr
}

func (c *fakeTLSConn) ConnectionState() tls.ConnectionState {
	return tls.ConnectionState{NegotiatedProtocol: c.proto}
}

func (c *fakeTLSConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadlines = append(c.deadlines, t)
	n := len(c.deadlines)
	c.mu.Unlock()
	if c.setDeadlineErr != nil && n == c.failNthSet {
		return c.setDeadlineErr
	}
	return nil
}

func (c *fakeTLSConn) deadlinesSet() []time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Time(nil), c.deadlines...)
}

func (c *fakeTLSConn) handshakes() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.shook
}

// testHandshaker is a server with nothing but the fields handshake reads, which is
// how these tests avoid standing up an accept loop to negotiate one connection.
func testHandshaker(to limits.Timeouts) *Server {
	return New(func() streamHandler { return handlerFunc(func(frame.Frame) error { return nil }) },
		Config{Timeouts: to})
}

// --- checkTLSConfig -----------------------------------------------------------

func TestTLSConfigIsAcceptedByTheCheckItHasToPass(t *testing.T) {
	// The one case in this group that has to pass. Every other describes a
	// configuration a caller built; this one describes the configuration this package
	// hands out, and a TLSConfig that its own ServeTLS refuses is a package nobody can
	// use.
	if err := checkTLSConfig(TLSConfig(testCert(t))); err != nil {
		t.Fatalf("checkTLSConfig refused the config TLSConfig returned: %v", err)
	}
}

func TestCheckTLSConfigRefusesWhatCannotServeH2(t *testing.T) {
	cert := testCert(t)
	base := func() *tls.Config { return TLSConfig(cert) }

	for _, tc := range []struct {
		name string
		cfg  *tls.Config
		want string
	}{
		{
			name: "no config at all",
			cfg:  nil,
			want: "requires a TLS configuration",
		},
		{
			name: "no certificate and no way to get one",
			cfg: &tls.Config{
				NextProtos:   []string{ALPNProtocol},
				MinVersion:   tls.VersionTLS12,
				CipherSuites: h2CipherSuites(),
			},
			want: "neither Certificates nor GetCertificate",
		},
		{
			name: "no ALPN list",
			cfg: func() *tls.Config {
				c := base()
				c.NextProtos = nil
				return c
			}(),
			want: "does not advertise",
		},
		{
			name: "an ALPN list without h2",
			cfg: func() *tls.Config {
				c := base()
				c.NextProtos = []string{"http/1.1"}
				return c
			}(),
			want: "does not advertise",
		},
		{
			name: "a protocol this server cannot speak alongside h2",
			cfg: func() *tls.Config {
				c := base()
				c.NextProtos = []string{ALPNProtocol, "http/1.1"}
				return c
			}(),
			want: `advertises ["http/1.1"]`,
		},
		{
			name: "an unset version floor",
			cfg: func() *tls.Config {
				c := base()
				c.MinVersion = 0
				return c
			}(),
			want: "MinVersion is unset",
		},
		{
			name: "a TLS 1.0 floor",
			cfg: func() *tls.Config {
				c := base()
				c.MinVersion = tls.VersionTLS10
				return c
			}(),
			want: "MinVersion is TLS 1.0",
		},
		{
			name: "a TLS 1.1 floor",
			cfg: func() *tls.Config {
				c := base()
				c.MinVersion = tls.VersionTLS11
				return c
			}(),
			want: "MinVersion is TLS 1.1",
		},
		{
			// The case Go's own defaults produce, and the reason this check exists.
			name: "TLS 1.2 with Go's default cipher suites",
			cfg: func() *tls.Config {
				c := base()
				c.CipherSuites = nil
				return c
			}(),
			want: "no CipherSuites",
		},
		{
			// Ephemeral, not RC4, not 3DES, not RSA key exchange — so Go offers it by
			// default — and still forbidden, because CBC is not an AEAD.
			name: "TLS 1.2 with a CBC suite Go would offer by default",
			cfg: func() *tls.Config {
				c := base()
				c.CipherSuites = append(h2CipherSuites(), tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)
				return c
			}(),
			want: "0xc013",
		},
		{
			name: "TLS 1.2 with RSA key exchange",
			cfg: func() *tls.Config {
				c := base()
				c.CipherSuites = []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256}
				return c
			}(),
			want: "0x009c",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkTLSConfig(tc.cfg)
			if err == nil {
				t.Fatal("checkTLSConfig accepted a configuration that cannot serve HTTP/2 correctly")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the error is %q, which does not mention %q — and an operator who cannot tell "+
					"which field is wrong has to read this package to find out", err, tc.want)
			}
		})
	}
}

func TestCheckTLSConfigAcceptsWhatCanServeH2(t *testing.T) {
	cert := testCert(t)

	for _, tc := range []struct {
		name string
		cfg  *tls.Config
	}{
		{
			name: "a certificate fetched per connection",
			cfg: &tls.Config{
				GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil },
				NextProtos:     []string{ALPNProtocol},
				MinVersion:     tls.VersionTLS12,
				CipherSuites:   h2CipherSuites(),
			},
		},
		{
			// No cipher suites needed, and this is why the check stops rather than
			// insisting: crypto/tls ignores the field above TLS 1.2, and every suite it
			// will negotiate there is an AEAD. Refusing this would make the check a
			// hardening opinion rather than the protocol rule it claims to be.
			name: "TLS 1.3 only, with no cipher suites named",
			cfg: &tls.Config{
				Certificates: []tls.Certificate{cert},
				NextProtos:   []string{ALPNProtocol},
				MinVersion:   tls.VersionTLS13,
			},
		},
		{
			name: "a subset of the allowed suites",
			cfg: &tls.Config{
				Certificates: []tls.Certificate{cert},
				NextProtos:   []string{ALPNProtocol},
				MinVersion:   tls.VersionTLS12,
				CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkTLSConfig(tc.cfg); err != nil {
				t.Errorf("checkTLSConfig refused a configuration that serves HTTP/2 correctly: %v", err)
			}
		})
	}
}

// --- the cipher suite list ----------------------------------------------------

func TestH2CipherSuitesAreAllAEADWithEphemeralKeyExchange(t *testing.T) {
	// Asserted against crypto/tls's own catalogue rather than against a second copy of
	// the list, so that this fails if a suite is added that does not meet §9.2's two
	// requirements — rather than only if the list changes.
	named := make(map[uint16]*tls.CipherSuite)
	for _, cs := range tls.CipherSuites() {
		named[cs.ID] = cs
	}
	for _, cs := range tls.InsecureCipherSuites() {
		named[cs.ID] = cs
	}

	suites := h2CipherSuites()
	if len(suites) == 0 {
		t.Fatal("h2CipherSuites is empty, which leaves a TLS 1.2 handshake nothing to agree on")
	}
	for _, id := range suites {
		cs, ok := named[id]
		if !ok {
			t.Errorf("crypto/tls does not implement %#04x, so offering it does nothing", id)
			continue
		}
		if !strings.Contains(cs.Name, "ECDHE") {
			t.Errorf("%s has no ephemeral key exchange, which RFC 9113 §9.2.1 requires", cs.Name)
		}
		if !strings.Contains(cs.Name, "GCM") && !strings.Contains(cs.Name, "CHACHA20_POLY1305") {
			t.Errorf("%s is not an AEAD, and RFC 9113 §9.2.2 forbids it over TLS 1.2", cs.Name)
		}
		for _, insecure := range tls.InsecureCipherSuites() {
			if insecure.ID == id {
				t.Errorf("crypto/tls lists %s among its insecure suites", cs.Name)
			}
		}
	}
}

func TestH2CipherSuitesOffersEveryAEADSuiteGoHasForTLS12(t *testing.T) {
	// The other half of the assertion above, and the one that catches a suite dropped
	// by accident. A list that is merely correct can also be needlessly short, and a
	// server that offers three AEADs where six were available fails handshakes with
	// clients that had one of the other three — a compatibility bug that looks like a
	// network problem.
	offered := h2CipherSuites()
	for _, cs := range tls.CipherSuites() {
		aead := strings.Contains(cs.Name, "GCM") || strings.Contains(cs.Name, "CHACHA20_POLY1305")
		if !aead || !strings.Contains(cs.Name, "ECDHE") {
			continue
		}
		// A TLS 1.3 suite is listed with 1.3 as its only supported version and is not
		// configurable, so it is not this list's business.
		var forTLS12 bool
		for _, v := range cs.SupportedVersions {
			if v == tls.VersionTLS12 {
				forTLS12 = true
			}
		}
		if !forTLS12 {
			continue
		}
		if !containsUint16(offered, cs.ID) {
			t.Errorf("crypto/tls implements %s for TLS 1.2 and RFC 9113 permits it, but this server "+
				"does not offer it", cs.Name)
		}
	}
}

func TestH2CipherSuitesCannotBeMutatedByACaller(t *testing.T) {
	// A function and not a package variable, and this is the difference. TLSConfig
	// hands the slice to a caller who owns the config it lands in; a shared backing
	// array would let that caller — or a caller holding an earlier config — change what
	// every later handshake offers.
	first := h2CipherSuites()
	if len(first) == 0 {
		t.Fatal("h2CipherSuites is empty")
	}
	want := first[0]
	first[0] = tls.TLS_RSA_WITH_AES_128_CBC_SHA

	if got := h2CipherSuites()[0]; got != want {
		t.Errorf("after a caller overwrote the first suite, h2CipherSuites returns %#04x, want %#04x",
			got, want)
	}
}

func TestTLSConfigStatesTheVersionFloorRatherThanInheritingIt(t *testing.T) {
	cfg := TLSConfig(testCert(t))

	// Zero would mean TLS 1.2 today and TLS 1.0 under GODEBUG=tls10server=1, and §9.2
	// requires 1.2. A floor an environment variable can lower is not one this server
	// can claim to hold.
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion is %s, want TLS 1.2 stated explicitly", versionName(cfg.MinVersion))
	}
	if got := cfg.NextProtos; len(got) != 1 || got[0] != ALPNProtocol {
		t.Errorf("NextProtos is %q, want exactly [%q]", got, ALPNProtocol)
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("the config holds %d certificates, want the one it was given", len(cfg.Certificates))
	}
	// Left to crypto/tls on purpose: naming curves here would exclude the post-quantum
	// exchange Go enables by default, for the appearance of diligence.
	if cfg.CurvePreferences != nil {
		t.Errorf("CurvePreferences is %v, and pinning it excludes whatever Go adds next",
			cfg.CurvePreferences)
	}
}

func TestALPNProtocolIsWhatRFC9113Registers(t *testing.T) {
	if ALPNProtocol != "h2" {
		t.Errorf("ALPNProtocol is %q, and RFC 9113 §3.2 registers exactly one identifier: %q",
			ALPNProtocol, "h2")
	}
}

func TestVersionNameNamesEveryVersionItCanBeGiven(t *testing.T) {
	for _, tc := range []struct {
		in   uint16
		want string
	}{
		{0, "unset"},
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
		{0x0999, "0x0999"},
	} {
		if got := versionName(tc.in); got != tc.want {
			t.Errorf("versionName(%#04x) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestContainsUint16FindsAndMisses(t *testing.T) {
	haystack := []uint16{0x0001, 0x0002, 0xc02f}
	for _, want := range haystack {
		if !containsUint16(haystack, want) {
			t.Errorf("containsUint16 did not find %#04x, which is in the list", want)
		}
	}
	for _, absent := range []uint16{0, 0x0003, 0xc030, 0xffff} {
		if containsUint16(haystack, absent) {
			t.Errorf("containsUint16 found %#04x, which is not in the list", absent)
		}
	}
	if containsUint16(nil, 0) {
		t.Error("containsUint16 found a value in an empty list")
	}
}

// --- handshake ----------------------------------------------------------------

func TestHandshakePassesThroughACleartextConnection(t *testing.T) {
	// h2c by prior knowledge (§3.4). A net.Pipe end is a net.Conn with no Handshake
	// method, which is exactly the case the type assertion is there to recognise, and
	// this asserts the assertion's *negative* branch — the one a plaintext port
	// depends on.
	sock, peer := net.Pipe()
	defer closeBoth(t, sock, peer)

	if err := testHandshaker(testTimeouts()).handshake(sock); err != nil {
		t.Errorf("handshake on a cleartext connection returned %v; there is nothing to negotiate on "+
			"one, and refusing it would close every h2c connection this server accepts", err)
	}
}

func TestHandshakeArmsAndClearsTheDeadlineAroundTheHandshake(t *testing.T) {
	to := testTimeouts()
	to.TLSHandshake = 3 * time.Second
	tc := &fakeTLSConn{proto: ALPNProtocol}

	before := time.Now()
	if err := testHandshaker(to).handshake(tc); err != nil {
		t.Fatalf("handshake with h2 negotiated returned %v", err)
	}
	after := time.Now()

	if got := tc.handshakes(); got != 1 {
		t.Errorf("Handshake was called %d times, want exactly 1", got)
	}

	set := tc.deadlinesSet()
	if len(set) != 2 {
		t.Fatalf("SetDeadline was called %d times with the deadlines %v, want 2: one to arm the "+
			"handshake timeout and one to clear it", len(set), set)
	}
	// Arming: within the window the call itself occupied, which is the only bound a
	// test can hold it to without reimplementing the clock.
	if lo, hi := before.Add(to.TLSHandshake), after.Add(to.TLSHandshake); set[0].Before(lo) || set[0].After(hi) {
		t.Errorf("the handshake deadline is %v, want Timeouts.TLSHandshake (%v) from now, so between "+
			"%v and %v", set[0], to.TLSHandshake, lo, hi)
	}
	// Clearing, and the zero time specifically. Anything else is a deadline that
	// expires later on a connection that is working, and the symptom is a client
	// disconnected mid-request exactly Timeouts.TLSHandshake after it connected.
	if !set[1].IsZero() {
		t.Errorf("the deadline after the handshake is %v, want the zero time: from here the read "+
			"deadline belongs to the connection and the write deadline to the writer", set[1])
	}
}

func TestHandshakeRefusesWhatCannotSpeakHTTP2(t *testing.T) {
	failed := errors.New("the client offered no cipher suite in common")

	for _, tc := range []struct {
		name string
		conn *fakeTLSConn
		want []string
		// wrapped is the error the returned one must unwrap to, where there is one. A
		// message that merely mentions the failure is not the same as an error a caller
		// can match on.
		wrapped error
		// shook says whether the handshake itself should have been attempted.
		shook int
	}{
		{
			name:    "a handshake that failed",
			conn:    &fakeTLSConn{handshakeErr: failed},
			want:    []string{"TLS handshake"},
			wrapped: failed,
			shook:   1,
		},
		{
			name: "a handshake that negotiated no protocol at all",
			conn: &fakeTLSConn{proto: ""},
			// The reachable case: a client that sends no ALPN extension completes the
			// handshake, and Go reports "". §3.2 makes ALPN the only way to arrive at h2
			// over TLS, so there is nothing to fall back to.
			want:  []string{"without negotiating ALPN", "§3.2"},
			shook: 1,
		},
		{
			name:  "a handshake that negotiated another protocol",
			conn:  &fakeTLSConn{proto: "http/1.1"},
			want:  []string{`"http/1.1"`, "only HTTP/2"},
			shook: 1,
		},
		{
			name: "a socket that will not take the handshake deadline",
			conn: &fakeTLSConn{
				proto:          ALPNProtocol,
				setDeadlineErr: errors.New("use of closed network connection"),
				failNthSet:     1,
			},
			// Refused before the handshake, not after. A handshake with no timeout is a
			// socket a silent peer holds until the process runs out of descriptors.
			want:  []string{"setting the TLS handshake deadline"},
			shook: 0,
		},
		{
			name: "a socket that will not give the handshake deadline back",
			conn: &fakeTLSConn{
				proto:          ALPNProtocol,
				setDeadlineErr: errors.New("use of closed network connection"),
				failNthSet:     2,
			},
			want:  []string{"clearing the TLS handshake deadline"},
			shook: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := testHandshaker(testTimeouts()).handshake(tc.conn)
			if err == nil {
				t.Fatal("handshake accepted a connection that cannot carry HTTP/2")
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the error is %q, which does not mention %q", err, want)
				}
			}
			if tc.wrapped != nil && !errors.Is(err, tc.wrapped) {
				t.Errorf("the error is %q, which does not wrap the underlying %v — and a caller that "+
					"wanted to tell a timeout from a bad certificate cannot", err, tc.wrapped)
			}
			if got := tc.conn.handshakes(); got != tc.shook {
				t.Errorf("Handshake was called %d times, want %d", got, tc.shook)
			}
		})
	}
}

func TestHandshakeDoesNotClearTheDeadlineOfAFailedHandshake(t *testing.T) {
	// The clearing is for a connection that is about to be served. A failed handshake
	// is about to be closed, and closing it under an armed deadline is what stops a
	// peer that is not reading from holding the close as well.
	tc := &fakeTLSConn{handshakeErr: errors.New("bad record MAC")}
	if err := testHandshaker(testTimeouts()).handshake(tc); err == nil {
		t.Fatal("handshake accepted a failed handshake")
	}

	set := tc.deadlinesSet()
	if len(set) != 1 {
		t.Fatalf("SetDeadline was called %d times with %v, want 1: the arming, and no clearing on a "+
			"connection that is being closed", len(set), set)
	}
	if set[0].IsZero() {
		t.Error("the one deadline set was the zero time, so the handshake ran without a timeout")
	}
}

// --- discard ------------------------------------------------------------------

func TestDiscardClosesTheSocketWithoutWritingToIt(t *testing.T) {
	baseline := goroutineBaseline()

	tt := &testTarget{}
	ts := newTestSocket(tt)
	c := newConn(ts, rejectingHandler(t), testTimeouts())

	if err := c.discard(); err != nil {
		t.Errorf("discard returned %v, want nil for a socket and writer that both stopped cleanly", err)
	}

	// The whole point of the method. A GOAWAY needs a peer that reads HTTP/2 frames,
	// and this peer either has no TLS session or is not speaking this protocol: an
	// unencrypted frame written to a client waiting for a ServerHello is not a
	// courtesy, it is a protocol violation on top of a failed handshake.
	if got := tt.writeCount(); got != 0 {
		t.Errorf("discard wrote %d times to a connection that never negotiated HTTP/2, want 0: %q",
			got, tt.allWrites())
	}
	if got := ts.closeCount(); got != 1 {
		t.Errorf("discard closed the socket %d times, want exactly 1 — Serve, which normally closes "+
			"it, was never called", got)
	}
	assertNoGoroutineLeak(t, baseline)
}

func TestDiscardReportsBothHalvesOfTheTeardown(t *testing.T) {
	baseline := goroutineBaseline()

	closeErr := errors.New("setsockopt: socket is not connected")
	writeErr := errors.New("connection reset by peer")

	tt := newGatedTarget()
	ts := &closeFailsSocket{testSocket: newTestSocket(tt), err: closeErr}
	c := newConn(ts, rejectingHandler(t), testTimeouts())

	// The writer has to have failed before discard runs, and it has to have failed
	// deterministically. Parking it inside a Write and then releasing it with an error
	// is the only way to know it is dead rather than about to be: a target that simply
	// returns an error leaves the test racing the writer goroutine for which error
	// Wait reports.
	if err := c.w.Enqueue(ping(1)); err != nil {
		t.Fatalf("enqueueing a frame for the writer to fail on: %v", err)
	}
	tt.awaitWrite(t)(writeErr)

	err := c.discard()
	if err == nil {
		t.Fatal("discard returned nil although both the writer and the socket failed")
	}
	if !errors.Is(err, writeErr) {
		t.Errorf("discard returned %v, which does not report the writer's failure (%v)", err, writeErr)
	}
	if !errors.Is(err, closeErr) {
		t.Errorf("discard returned %v, which does not report the socket's failure (%v)", err, closeErr)
	}
	assertNoGoroutineLeak(t, baseline)
}

// closeFailsSocket is a socket whose Close reports an error, which a real one does:
// Close is a syscall, and on a socket that has already been reset it fails.
type closeFailsSocket struct {
	*testSocket
	err error
}

func (s *closeFailsSocket) Close() error {
	if err := s.testSocket.Close(); err != nil {
		return errors.Join(err, s.err)
	}
	return s.err
}

// closeBoth closes two connections, reporting either failure rather than discarding
// it: a test helper that swallows an error is a test helper that hides one.
func closeBoth(t *testing.T, a, b net.Conn) {
	t.Helper()
	if err := errors.Join(a.Close(), b.Close()); err != nil {
		t.Errorf("closing the test connections: %v", err)
	}
}

// --- ServeTLS -----------------------------------------------------------------

func TestServeTLSRefusesABadConfigWithoutAcceptingAnything(t *testing.T) {
	// Refused before the listener is wrapped, and the listener closed anyway. The
	// alternative — return the error and leave l open — is a caller that has to
	// remember which of the two failure modes leaks a listening socket.
	s, _ := testServer(t, Config{Timeouts: serverTimeouts()}, nil)
	l := newTestListener(nil, nil)
	closeServerAfter(t, s)

	// Called on a goroutine with a bounded wait, rather than inline, because the thing
	// that goes wrong here does not return at all: a ServeTLS that stops checking wraps
	// l, starts accepting, and serves for ever. Inline, that is a test which hangs until
	// the go test timeout and then dumps every goroutine in the binary — a detection
	// nobody reads. See scripts/break-tls.py, where this break has to fail by name.
	cfg := &tls.Config{Certificates: []tls.Certificate{testCert(t)}}
	done := make(chan error, 1)
	go func() { done <- s.ServeTLS(l, cfg) }()

	err := awaitServe(t, done)
	if err == nil {
		t.Fatal("ServeTLS accepted a config with no ALPN list, so no client could ever negotiate h2")
	}
	if errors.Is(err, ErrServerClosed) {
		t.Errorf("ServeTLS reported %v for a refused configuration, and a caller that logs "+
			"ErrServerClosed as a clean stop would never see the problem", err)
	}
	if !strings.Contains(err.Error(), "does not advertise") {
		t.Errorf("ServeTLS returned %q, which does not name the field that is wrong", err)
	}

	if got := l.acceptCount(); got != 0 {
		t.Errorf("ServeTLS called Accept %d times on a configuration it had already refused, want 0",
			got)
	}
	if got := l.closeCount(); got != 1 {
		t.Errorf("ServeTLS closed the listener %d times after refusing the configuration, want exactly "+
			"1: it closes l on every path out, and a caller closing it again is what onceListener is "+
			"not there for", got)
	}
}

func TestServeTLSLogsAListenerItCannotClose(t *testing.T) {
	// The refusal is still returned, because it is the caller's answer. The close
	// failure is logged, because it is not — and because a discarded error here is a
	// descriptor nobody knows about.
	s, rec := testServer(t, Config{Timeouts: serverTimeouts()}, nil)
	closeErr := errors.New("bad file descriptor")
	l := newTestListener().unclosable(closeErr)
	closeServerAfter(t, s)

	done := make(chan error, 1)
	go func() { done <- s.ServeTLS(l, nil) }()

	err := awaitServe(t, done)
	if err == nil || !strings.Contains(err.Error(), "requires a TLS configuration") {
		t.Fatalf("ServeTLS returned %v for a nil config, want the refusal", err)
	}
	assertLogged(t, rec, closeErr.Error())
}

// closeServerAfter stops s when the test ends.
//
// Nothing to close in a healthy run of either test above: ServeTLS refuses before it
// registers a listener, so Close finds an empty set. It is here for the unhealthy run
// — a ServeTLS that wrongly starts serving would otherwise carry its accept loop, its
// connection goroutines and its wrapped listener into whatever test runs next.
func closeServerAfter(t *testing.T, s *Server) {
	t.Helper()
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("closing a server ServeTLS should never have started: %v", err)
		}
	})
}

func TestServeTLSDropsAClientThatNeverSendsAClientHello(t *testing.T) {
	// The reason the handshake has a deadline of its own. A peer that connects and
	// says nothing costs a descriptor, a goroutine and a connection slot, and
	// MaxConns makes the slot the scarcest of the three: without this timeout a few
	// hundred silent sockets close the server to everyone else, at no cost to the
	// attacker.
	baseline := goroutineBaseline()

	to := serverTimeouts()
	to.TLSHandshake = 150 * time.Millisecond
	s, rec := testServer(t, Config{Timeouts: to}, nil)
	l := newTestListener(nil)
	done := make(chan error, 1)
	cfg := TLSConfig(testCert(t))
	go func() { done <- s.ServeTLS(l, cfg) }()

	awaitPeers(t, l, 1)
	p := l.peer(t, 0)

	// The peer's end goes when the server closes its own, which is the observable
	// consequence of the timeout: the connection is gone, and nothing was sent on it.
	awaitPeerGone(t, p)
	if got := p.octets(); len(got) != 0 {
		t.Errorf("the server sent %d octets to a peer that never sent a ClientHello, want 0: %q",
			len(got), got)
	}
	// "TLS handshake: " with the colon, and the colon is doing real work. Without it the
	// string is also a substring of "the client completed a TLS handshake without
	// negotiating ALPN", so an assertion for "TLS handshake" is satisfied by the ALPN
	// refusal as well as by the handshake failure this test is about. The break campaign
	// found that: discarding Handshake's error left this test passing, because the
	// connection then failed one line further down and logged prose that happened to
	// contain the phrase. The colon is only in handshake's own wrap of the error.
	awaitLog(t, rec, "TLS handshake: ", gateWait)
	awaitSlotsHeld(t, s, 1)

	if err := s.Shutdown(); err != nil {
		t.Errorf("Shutdown: %v", err)
	}
	assertServerClosed(t, awaitServe(t, done))
	assertLoggedLines(t, rec, 1) // See TestServeTLSRefusesAClientThatNegotiatesNoProtocol.
	if got := l.closeCount(); got != 1 {
		t.Errorf("the underlying listener was closed %d times, want exactly 1: ServeTLS wraps l in a "+
			"TLS listener, and closing the wrapper has to reach through to l", got)
	}
	assertNoGoroutineLeak(t, baseline)
}

// --- a real TLS connection over a real socket ---------------------------------

// tlsHarness is a server serving HTTP/2 over TLS on loopback.
//
// Everything in this group needs a real socket. crypto/tls will run over net.Pipe,
// but a pipe is unbuffered: the handshake's own records deadlock the moment either
// side writes more than the other is reading, and a client that has to be driven by
// a goroutine per record is not a client this server will ever meet.
type tlsHarness struct {
	s    *Server
	rec  *logRecorder
	addr string
	l    net.Listener
	done chan error
}

func newTLSHarness(t *testing.T, to limits.Timeouts) *tlsHarness {
	t.Helper()

	// The certificate is fetched here rather than inside the goroutine below, because
	// testCert calls t.Fatalf and that only stops the goroutine it runs on.
	cfg := TLSConfig(testCert(t))

	s, rec := testServer(t, Config{Timeouts: to}, nil)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening on loopback: %v", err)
	}
	h := &tlsHarness{s: s, rec: rec, addr: l.Addr().String(), l: l, done: make(chan error, 1)}
	go func() { h.done <- s.ServeTLS(l, cfg) }()
	return h
}

// dial returns a client that has not yet handshaken, so that each test decides what
// the handshake is supposed to do.
func (h *tlsHarness) dial(t *testing.T, cfg *tls.Config) *tls.Conn {
	t.Helper()
	nc, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatalf("dialling %v: %v", h.addr, err)
	}
	tc := tls.Client(nc, cfg)
	t.Cleanup(func() {
		// Not asserted on. The server closes these connections deliberately in most of
		// these tests, and a close of an already-reset socket fails for that reason.
		if err := tc.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Logf("closing the client connection: %v", err)
		}
	})
	if err := tc.SetDeadline(time.Now().Add(gateWait)); err != nil {
		t.Fatalf("setting the client's deadline: %v", err)
	}
	return tc
}

func (h *tlsHarness) stop(t *testing.T) {
	t.Helper()
	if err := h.s.Shutdown(); err != nil {
		t.Errorf("Shutdown: %v", err)
	}
	assertServerClosed(t, awaitServe(t, h.done))

	// ServeTLS closes l on the way out, through the TLS listener wrapping it. A second
	// close reporting "already closed" is the proof; one reporting nil would mean the
	// descriptor was still open.
	if err := h.l.Close(); err == nil {
		t.Error("closing the listener after ServeTLS returned succeeded, so ServeTLS left it open")
	}
}

// clientTLSConfig trusts the test certificate and offers the named protocols. No
// argument means no ALPN extension at all, which is a case the server has to handle.
func clientTLSConfig(t *testing.T, protos ...string) *tls.Config {
	t.Helper()
	return &tls.Config{
		RootCAs:    testCertPool(t),
		ServerName: "localhost",
		NextProtos: protos,
		MinVersion: tls.VersionTLS12,
	}
}

func awaitSlotsHeld(t *testing.T, s *Server, want int) {
	t.Helper()
	// One is the settled figure for a running server, not zero: the accept loop takes
	// its slot *before* calling Accept, so the connection it is waiting for already
	// holds one. Anything above that is a connection whose goroutine has not given its
	// slot back, and a refused handshake that keeps its slot is a server a client can
	// close with a handful of sockets.
	poll(t, gateWait, func() bool { return len(s.slots) <= want }, func() string {
		return fmt.Sprintf("%d connection slots are held, want at most %d — %d for the accept that is "+
			"waiting and none for connections that have ended", len(s.slots), want, want)
	})
}

func TestServeTLSServesHTTP2ToAClientThatNegotiatesIt(t *testing.T) {
	// The whole layer, end to end, on the transport it ships against: a real
	// handshake, a real ALPN negotiation, and the HTTP/2 connection preface over the
	// encrypted stream. Nothing else in this file proves that the frames the
	// connection layer writes come out the other side of crypto/tls intact.
	baseline := goroutineBaseline()

	to := serverTimeouts()
	to.TLSHandshake = gateWait
	h := newTLSHarness(t, to)

	// The literal "h2", deliberately, and not ALPNProtocol. A client on the wire offers
	// the identifier RFC 9113 §3.2 registers; spelling this end with the server's own
	// constant would make the two agree on whatever that constant said, and the break
	// campaign found exactly that — changing it to "h2c" left this test passing while
	// every real client in the world stopped being able to connect. The constant is
	// pinned to the wire name by TestALPNProtocolIsWhatRFC9113Registers; this test is
	// what proves the wire name is the one the server actually selects.
	tc := h.dial(t, clientTLSConfig(t, "h2"))
	if err := tc.Handshake(); err != nil {
		t.Fatalf("the client's TLS handshake failed: %v", err)
	}
	if got := tc.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Fatalf("the client negotiated %q, want %q", got, "h2")
	}

	if _, err := tc.Write(clientHello(t)); err != nil {
		t.Fatalf("sending the client connection preface: %v", err)
	}

	// Our SETTINGS first (§3.4), then the acknowledgement of theirs.
	r := frame.NewReader(tc, frame.ReaderConfig{})
	first, err := r.ReadFrame()
	if err != nil {
		t.Fatalf("reading the server connection preface over TLS: %v", err)
	}
	if _, ok := first.(frame.SettingsFrame); !ok {
		t.Fatalf("the first frame over TLS was %s, want SETTINGS (RFC 9113 §3.4)", first.Type())
	}
	second, err := r.ReadFrame()
	if err != nil {
		t.Fatalf("reading the acknowledgement of the client's SETTINGS: %v", err)
	}
	if sf, ok := second.(frame.SettingsFrame); !ok || !sf.Ack {
		t.Errorf("the second frame over TLS was %#v, want a SETTINGS acknowledgement", second)
	}

	if got := h.rec.text(); got != "" {
		t.Errorf("a clean HTTP/2-over-TLS connection logged something:\n%s", got)
	}
	h.stop(t)
	assertNoGoroutineLeak(t, baseline)
}

func TestServeTLSNegotiatesH2OnTLS12(t *testing.T) {
	// TLS 1.2 is the floor §9.2 sets and the version the cipher suite list exists
	// for, and it is the one a default Go client never reaches: it prefers 1.3 and
	// gets it. So the client is pinned, and the suite it lands on is asserted — a
	// blacklisted suite negotiated here is an INADEQUATE_SECURITY a conformance
	// suite would find and a packet capture would have to prove.
	baseline := goroutineBaseline()

	to := serverTimeouts()
	to.TLSHandshake = gateWait
	h := newTLSHarness(t, to)

	// The literal, for the reason given in the test above.
	cfg := clientTLSConfig(t, "h2")
	cfg.MaxVersion = tls.VersionTLS12
	tc := h.dial(t, cfg)
	if err := tc.Handshake(); err != nil {
		t.Fatalf("the client's TLS 1.2 handshake failed: %v", err)
	}

	st := tc.ConnectionState()
	if st.Version != tls.VersionTLS12 {
		t.Fatalf("the connection is %s, want TLS 1.2 — the client was pinned to it", versionName(st.Version))
	}
	if st.NegotiatedProtocol != "h2" {
		t.Errorf("the client negotiated %q over TLS 1.2, want %q", st.NegotiatedProtocol, "h2")
	}
	if !containsUint16(h2CipherSuites(), st.CipherSuite) {
		t.Errorf("the handshake settled on %s, which is not in the AEAD-only list this server offers; "+
			"RFC 9113 §9.2.2 forbids it and a peer may answer INADEQUATE_SECURITY",
			tls.CipherSuiteName(st.CipherSuite))
	}

	// The connection still has to work, not merely exist.
	if _, err := tc.Write(clientHello(t)); err != nil {
		t.Fatalf("sending the client connection preface over TLS 1.2: %v", err)
	}
	got, err := frame.NewReader(tc, frame.ReaderConfig{}).ReadFrame()
	if err != nil {
		t.Fatalf("reading the server connection preface over TLS 1.2: %v", err)
	}
	if _, ok := got.(frame.SettingsFrame); !ok {
		t.Errorf("the first frame over TLS 1.2 was %s, want SETTINGS", got.Type())
	}

	h.stop(t)
	assertNoGoroutineLeak(t, baseline)
}

func TestServeTLSRefusesAClientThatNegotiatesNoProtocol(t *testing.T) {
	// The case a real client produces: no ALPN extension at all. Go's server completes
	// the handshake and reports NegotiatedProtocol == "", so this is the one refusal
	// that happens *after* a successful handshake — and the only way to reach it is
	// from a real client, which is why it is here and not among the fakes.
	baseline := goroutineBaseline()

	to := serverTimeouts()
	to.TLSHandshake = gateWait
	h := newTLSHarness(t, to)

	tc := h.dial(t, clientTLSConfig(t))
	if err := tc.Handshake(); err != nil {
		t.Fatalf("the client's handshake failed; a client that offers no ALPN is meant to get a TLS "+
			"session and then be turned away at the HTTP/2 layer: %v", err)
	}
	if got := tc.ConnectionState().NegotiatedProtocol; got != "" {
		t.Fatalf("the client negotiated %q having offered nothing, so this test is not testing the "+
			"case it describes", got)
	}

	assertNoApplicationData(t, tc)
	awaitLog(t, h.rec, "without negotiating ALPN", gateWait)
	awaitSlotsHeld(t, h.s, 1)
	h.stop(t)

	// One line, and one only. A refusal that is logged and then not acted on — runConn
	// dropping the connection and falling through into Serve anyway — sends no frame,
	// because the socket has already been closed underneath it, so every assertion above
	// still holds. What it does instead is fail on that closed socket and log a second
	// time. The count is the only thing in this test that notices, which is why it is
	// here and why it is after the stop: before it, the number of lines is a race with
	// the connection's own goroutine.
	assertLoggedLines(t, h.rec, 1)
	assertNoGoroutineLeak(t, baseline)
}

func TestServeTLSRefusesAnHTTP11ClientThatCryptoTLSLetIn(t *testing.T) {
	// The most important test in this file, because the obvious expectation is wrong.
	//
	// A client offering only "http/1.1" to a server offering only "h2" has no protocol
	// in common, and the natural assumption is that crypto/tls sends the
	// no_application_protocol alert and this server never sees the connection. It does
	// not: negotiateALPN has an explicit special case for exactly this pair — an
	// http/1.1-only client against an h2-only server is treated as though it had not
	// offered ALPN at all (Go issue 46310) — so the handshake *succeeds* and arrives
	// here with no negotiated protocol.
	//
	// This is a browser that has fallen back, or curl without --http2. Without the
	// server's own ALPN check the reply to "GET / HTTP/1.1" would be a SETTINGS frame.
	baseline := goroutineBaseline()

	to := serverTimeouts()
	to.TLSHandshake = gateWait
	h := newTLSHarness(t, to)

	tc := h.dial(t, clientTLSConfig(t, "http/1.1"))
	if err := tc.Handshake(); err != nil {
		t.Fatalf("the http/1.1 client's handshake failed with %v; if crypto/tls has stopped applying "+
			"its http/1.1 fallback then this server's ALPN check is no longer what keeps HTTP/1.1 "+
			"clients off an h2 port, and the reasoning in handshake needs revisiting", err)
	}
	if got := tc.ConnectionState().NegotiatedProtocol; got != "" {
		t.Fatalf("the client negotiated %q having offered only http/1.1, so this test is not testing "+
			"the case it describes", got)
	}

	assertNoApplicationData(t, tc)
	awaitLog(t, h.rec, "without negotiating ALPN", gateWait)
	awaitSlotsHeld(t, h.s, 1)
	h.stop(t)
	assertLoggedLines(t, h.rec, 1) // See the test above.
	assertNoGoroutineLeak(t, baseline)
}

func TestServeTLSRefusesAClientThatOffersAProtocolNobodyShares(t *testing.T) {
	// The other half of the pair above, and the case where crypto/tls does refuse: a
	// client offering something that is neither "h2" nor "http/1.1" gets the
	// no_application_protocol alert, so the failure arrives as a handshake error rather
	// than as an empty protocol. It is the only way to reach handshake's Handshake()
	// error path with a real client, which is what makes it worth a socket.
	baseline := goroutineBaseline()

	to := serverTimeouts()
	to.TLSHandshake = gateWait
	h := newTLSHarness(t, to)

	tc := h.dial(t, clientTLSConfig(t, "spdy/3"))
	err := tc.Handshake()
	if err == nil {
		t.Fatalf("the handshake succeeded having negotiated %q; this server advertises only %q and "+
			"crypto/tls has no fallback for spdy/3", tc.ConnectionState().NegotiatedProtocol, ALPNProtocol)
	}
	if !strings.Contains(err.Error(), "no application protocol") {
		t.Errorf("the client's handshake failed with %v, want the no_application_protocol alert", err)
	}

	// The colon, for the reason given at the same assertion in
	// TestServeTLSDropsAClientThatNeverSendsAClientHello: it is what distinguishes a
	// handshake that failed from one that succeeded and negotiated nothing.
	awaitLog(t, h.rec, "TLS handshake: ", gateWait)
	awaitSlotsHeld(t, h.s, 1)
	h.stop(t)
	assertNoGoroutineLeak(t, baseline)
}

// assertNoApplicationData checks that the server sent no HTTP/2 octets before closing.
//
// Read and not a byte count on the socket, because the socket carries TLS records the
// server is right to send: a close_notify alert is how a TLS peer says goodbye
// properly. What must not appear is a single octet of application data — a SETTINGS
// frame on a connection with no negotiated protocol is a frame the peer cannot parse
// and did not ask for.
func assertNoApplicationData(t *testing.T, tc *tls.Conn) {
	t.Helper()
	if err := tc.SetReadDeadline(time.Now().Add(gateWait)); err != nil {
		t.Fatalf("setting the client's read deadline: %v", err)
	}
	buf := make([]byte, 64)
	n, err := tc.Read(buf)
	if n != 0 {
		t.Errorf("the server sent %d octets of application data on a connection it refused: %q",
			n, buf[:n])
	}
	if err == nil {
		t.Error("the client's read succeeded, so the server left a refused connection open")
		return
	}
	// io.EOF is the close_notify; a reset is what a peer sees when the socket goes
	// without one, which is legitimate here and is what Windows reports. A deadline
	// error is neither: it means the connection is still open.
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Errorf("the client's read timed out after %v, so the server neither served the connection "+
			"nor closed it", gateWait)
	}
}
