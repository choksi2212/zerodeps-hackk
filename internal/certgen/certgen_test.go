package certgen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// handshakeWait bounds every handshake in this file. A TLS handshake over loopback
// takes well under a millisecond; anything approaching this means one side is blocked
// on the other, and the test should fail rather than hang.
const handshakeWait = 5 * time.Second

// testHosts is what cmd/zdh will ask for, and therefore the combination that has to
// work: a name, an IPv4 address and an IPv6 address, all reaching the same server.
var testHosts = []string{"localhost", "127.0.0.1", "::1"}

// fixedNow is a whole second in UTC, because a whole second is all a certificate can
// store. X.509 encodes validity as UTCTime or GeneralizedTime, neither of which has a
// fractional part, so a test comparing against an arbitrary time.Time would fail on
// the nanoseconds the encoding silently dropped.
var fixedNow = time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)

func testConfig() Config {
	return Config{Hosts: testHosts, Now: fixedNow}
}

// liveConfig is testConfig on the real clock, and every handshake below uses it.
//
// A pinned clock is right for asserting on fields and wrong here. crypto/tls checks
// validity against time.Now unless it is told otherwise, and telling it otherwise
// would hide the failure worth catching: a certificate back-dated in the wrong
// direction is valid in a test that agreed to pretend, and refused by everything real.
// So the handshake tests generate a certificate now and require it to work now.
func liveConfig(hosts ...string) Config {
	if len(hosts) == 0 {
		hosts = testHosts
	}
	return Config{Hosts: hosts}
}

// mustSelf generates a pair, failing the test rather than returning an error, for the
// many tests whose subject is something other than whether generation works.
func mustSelf(t *testing.T, cfg Config) PEM {
	t.Helper()
	p, err := Self(cfg)
	if err != nil {
		t.Fatalf("Self(%+v): %v", cfg, err)
	}
	return p
}

func mustLeaf(t *testing.T, p PEM) *x509.Certificate {
	t.Helper()
	leaf, err := p.Leaf()
	if err != nil {
		t.Fatalf("parsing the generated certificate: %v", err)
	}
	return leaf
}

func mustPool(t *testing.T, p PEM) *x509.CertPool {
	t.Helper()
	pool, err := p.Pool()
	if err != nil {
		t.Fatalf("building a pool from the generated certificate: %v", err)
	}
	return pool
}

// --- the handshake, which is the only thing that proves any of this works ---

// handshakeResult is what a real client and a real server made of the certificate.
//
// Both errors are kept. The client's says why it refused; the server's is what
// distinguishes "refused the certificate" from "never got far enough to see it".
type handshakeResult struct {
	state     tls.ConnectionState
	clientErr error
	serverErr error
}

// handshake runs a TLS handshake between two crypto/tls endpoints over a loopback
// socket, with the client verifying the server against pool.
//
// This is the test that matters. A certificate is not a struct with fields worth
// checking for their own sake — it is a thing a peer either accepts or does not, and
// every field this package sets is there because some peer checks it.
func handshake(t *testing.T, p PEM, pool *x509.CertPool, serverName string, clientALPN []string) handshakeResult {
	t.Helper()

	cert, err := p.Certificate()
	if err != nil {
		t.Fatalf("building a tls.Certificate: %v", err)
	}

	// A loopback socket rather than net.Pipe, because net.Pipe is unbuffered. A client
	// that stops reading part-way through the server's flight — which is exactly what
	// a client refusing a certificate does — leaves the server blocked in a write, and
	// the client's own alert blocked behind it. That deadlock is broken only by the
	// deadline, which turns every test expecting a refusal into a five-second wait. A
	// kernel socket buffer holds a whole handshake flight, so neither side blocks.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening on loopback: %v", err)
	}
	defer closeAll(t, ln)

	type accepted struct {
		conn net.Conn
		err  error
	}
	acceptc := make(chan accepted, 1)
	go func() {
		conn, err := ln.Accept()
		acceptc <- accepted{conn, err}
	}()

	clientSide, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dialling %v: %v", ln.Addr(), err)
	}
	defer closeAll(t, clientSide)

	a := <-acceptc
	if a.err != nil {
		t.Fatalf("accepting the loopback connection: %v", a.err)
	}
	serverSide := a.conn
	defer closeAll(t, serverSide)

	// Deadlines on both ends, so that a handshake which cannot complete ends as a
	// failure and not as a test that never returns.
	deadline := time.Now().Add(handshakeWait)
	if err := serverSide.SetDeadline(deadline); err != nil {
		t.Fatalf("setting a deadline on the server end: %v", err)
	}
	if err := clientSide.SetDeadline(deadline); err != nil {
		t.Fatalf("setting a deadline on the client end: %v", err)
	}

	serverErr := make(chan error, 1)
	go func() {
		server := tls.Server(serverSide, &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2"},
			MinVersion:   tls.VersionTLS12,
		})
		serverErr <- server.Handshake()
	}()

	client := tls.Client(clientSide, &tls.Config{
		RootCAs:    pool,
		ServerName: serverName,
		NextProtos: clientALPN,
		MinVersion: tls.VersionTLS12,
	})
	res := handshakeResult{clientErr: client.Handshake()}
	res.state = client.ConnectionState()

	select {
	case res.serverErr = <-serverErr:
	case <-time.After(handshakeWait):
		t.Fatalf("the server side of the handshake did not finish within %v", handshakeWait)
	}
	return res
}

func closeAll(t *testing.T, closers ...io.Closer) {
	t.Helper()
	for _, c := range closers {
		if err := c.Close(); err != nil {
			t.Errorf("closing %T: %v", c, err)
		}
	}
}

func TestSelfNegotiatesH2WithARealTLSClient(t *testing.T) {
	p := mustSelf(t, liveConfig())
	res := handshake(t, p, mustPool(t, p), "localhost", []string{"h2"})

	if res.clientErr != nil {
		t.Fatalf("the client refused the generated certificate: %v", res.clientErr)
	}
	if res.serverErr != nil {
		t.Fatalf("the server could not complete the handshake: %v", res.serverErr)
	}

	// The whole point of the package. Without ALPN agreeing on h2 there is no HTTP/2
	// connection to have, whatever the rest of this server does.
	if res.state.NegotiatedProtocol != "h2" {
		t.Errorf("ALPN negotiated %q, want %q", res.state.NegotiatedProtocol, "h2")
	}
	if res.state.Version < tls.VersionTLS12 {
		t.Errorf("the handshake settled on version %#04x, below TLS 1.2", res.state.Version)
	}
	if !res.state.HandshakeComplete {
		t.Error("the handshake reported no error and did not complete")
	}
}

func TestSelfIsAcceptedForEveryHostItNames(t *testing.T) {
	p := mustSelf(t, liveConfig())
	pool := mustPool(t, p)

	for _, host := range testHosts {
		t.Run(host, func(t *testing.T) {
			if res := handshake(t, p, pool, host, []string{"h2"}); res.clientErr != nil {
				// A certificate that works for the name and not for the address is
				// the usual version of this bug, and it stays invisible until
				// somebody types the address into a browser.
				t.Fatalf("the client refused the certificate for %q, which it names: %v",
					host, res.clientErr)
			}
		})
	}
}

func TestSelfIsRefusedForAHostItDoesNotName(t *testing.T) {
	p := mustSelf(t, liveConfig("localhost"))

	// The negative half of the test above, and the reason neither of them uses
	// InsecureSkipVerify: that setting turns the name check off along with the trust
	// check, so a certificate issued for the wrong host would pass both.
	res := handshake(t, p, mustPool(t, p), "not-localhost.test", []string{"h2"})
	if res.clientErr == nil {
		t.Fatal("a client verifying the name accepted a certificate issued for a different one")
	}
	var hostErr x509.HostnameError
	if !errors.As(res.clientErr, &hostErr) {
		t.Fatalf("the client failed with %v, want an x509.HostnameError; if the name check is not what "+
			"refused this, the test above proves less than it appears to", res.clientErr)
	}
}

func TestSelfIsRefusedByAClientThatDoesNotTrustIt(t *testing.T) {
	served := mustSelf(t, liveConfig())
	other := mustSelf(t, liveConfig())

	// Same hosts, different key, so trust is the only thing that distinguishes them.
	// This is what a browser sees before anyone has imported anything.
	res := handshake(t, served, mustPool(t, other), "localhost", []string{"h2"})
	if res.clientErr == nil {
		t.Fatal("a client accepted a self-signed certificate that was not in its pool")
	}
	var authErr x509.UnknownAuthorityError
	if !errors.As(res.clientErr, &authErr) {
		t.Fatalf("the client failed with %v, want an x509.UnknownAuthorityError", res.clientErr)
	}
}

func TestSelfAcceptsAWildcardName(t *testing.T) {
	p := mustSelf(t, liveConfig("*.example.test"))
	pool := mustPool(t, p)

	if res := handshake(t, p, pool, "zdh.example.test", []string{"h2"}); res.clientErr != nil {
		t.Errorf("the client refused a wildcard certificate for a name it covers: %v", res.clientErr)
	}
	// A wildcard covers one label and not zero of them, so it must not match the
	// bare parent. Asserted because the alternative to knowing this is guessing.
	if res := handshake(t, p, pool, "example.test", []string{"h2"}); res.clientErr == nil {
		t.Error("a wildcard matched the bare parent name, which RFC 6125 §6.4.3 does not allow")
	}
}

// --- the fields a peer checks that the handshake above does not ---

func TestSelfSplitsNamesFromAddresses(t *testing.T) {
	leaf := mustLeaf(t, mustSelf(t, Config{
		Hosts: []string{"localhost", "127.0.0.1", "example.test", "::1"},
		Now:   fixedNow,
	}))

	wantDNS := []string{"localhost", "example.test"}
	if len(leaf.DNSNames) != len(wantDNS) {
		t.Fatalf("DNS names are %q, want %q", leaf.DNSNames, wantDNS)
	}
	for i, want := range wantDNS {
		if leaf.DNSNames[i] != want {
			t.Errorf("DNS name %d is %q, want %q", i, leaf.DNSNames[i], want)
		}
	}

	wantIPs := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	if len(leaf.IPAddresses) != len(wantIPs) {
		t.Fatalf("IP addresses are %v, want %v", leaf.IPAddresses, wantIPs)
	}
	for i, want := range wantIPs {
		// Equal rather than a byte comparison: x509 stores an IPv4 SAN in four
		// octets and net.ParseIP hands back sixteen, and the two are the same
		// address.
		if !leaf.IPAddresses[i].Equal(want) {
			t.Errorf("IP address %d is %v, want %v", i, leaf.IPAddresses[i], want)
		}
	}
}

func TestSelfSetsTheUsagesAPeerChecks(t *testing.T) {
	leaf := mustLeaf(t, mustSelf(t, testConfig()))

	// Every assertion here is one the handshake tests cannot make. crypto/x509
	// short-circuits verification when the leaf is itself in the root pool — verify.go
	// reads `if opts.Roots.contains(c) { candidateChains = [][]*Certificate{{c}} }` —
	// so on that path the CA bit, the key usage and the self-signature are never
	// looked at. A browser importing the same file into a trust store walks the slow
	// path and checks all three. The handshake proving the certificate works is
	// therefore not evidence that it is well formed.
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("KeyUsage omits DigitalSignature, which is what an ECDSA key does in a handshake")
	}
	if leaf.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("KeyUsage omits CertSign, so a verifier walking the chain will not accept this " +
			"certificate as its own issuer")
	}
	if !leaf.BasicConstraintsValid {
		t.Error("BasicConstraintsValid is false, so the extension is left out of the certificate " +
			"altogether and the CA bit says nothing")
	}
	if !leaf.IsCA {
		t.Error("IsCA is false on a certificate that signed itself")
	}

	// An absent EKU list means "any use", so leaving it out passes a Go client and is
	// refused by browsers, which want serverAuth stated.
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("ExtKeyUsage is %v, want exactly [ServerAuth]", leaf.ExtKeyUsage)
	}
}

func TestSelfUsesECDSAOnP256(t *testing.T) {
	leaf := mustLeaf(t, mustSelf(t, testConfig()))

	if leaf.PublicKeyAlgorithm != x509.ECDSA {
		t.Fatalf("the public key algorithm is %v, want ECDSA", leaf.PublicKeyAlgorithm)
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("the public key is a %T, want *ecdsa.PublicKey", leaf.PublicKey)
	}
	// Not a preference. crypto/tls will not use a certificate on a curve it does not
	// support, and P-224 is one it does not, so a smaller curve is a server that
	// starts and then cannot complete a handshake.
	if pub.Curve != elliptic.P256() {
		t.Errorf("the key is on curve %s, want P-256", pub.Curve.Params().Name)
	}
	if leaf.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Errorf("the signature algorithm is %v, want ECDSA-SHA256", leaf.SignatureAlgorithm)
	}
}

func TestSelfSignsItselfVerifiably(t *testing.T) {
	leaf := mustLeaf(t, mustSelf(t, testConfig()))

	// The slow path a trust store walks, made explicit. A signature that does not
	// check out fails on import into a browser, and the handshake tests above still
	// pass.
	if err := leaf.CheckSignatureFrom(leaf); err != nil {
		t.Errorf("the certificate does not verify against itself: %v", err)
	}
	if leaf.Issuer.String() != leaf.Subject.String() {
		t.Errorf("issuer %q and subject %q differ on a self-signed certificate", leaf.Issuer, leaf.Subject)
	}
}

func TestSelfEncodesThePrivateKeyAsPKCS8(t *testing.T) {
	p := mustSelf(t, testConfig())
	block := onlyBlock(t, "the key", p.Key)

	if block.Type != "PRIVATE KEY" {
		t.Errorf("the key block is a %q, want %q; an %q block is SEC 1, which does not name the "+
			"algorithm it holds", block.Type, "PRIVATE KEY", "EC PRIVATE KEY")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("the key does not parse as PKCS#8: %v", err)
	}
	priv, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("the key is a %T, want *ecdsa.PrivateKey", key)
	}

	// The pair has to be a pair. tls.X509KeyPair checks this too; checking it here
	// says which of the two is wrong when it is not.
	pub, ok := mustLeaf(t, p).PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("the certificate does not carry an ECDSA public key")
	}
	if !priv.PublicKey.Equal(pub) {
		t.Error("the private key does not match the public key in the certificate")
	}
}

func TestSelfCertificateBlockStandsAlone(t *testing.T) {
	block := onlyBlock(t, "the certificate", mustSelf(t, testConfig()).Cert)
	if block.Type != "CERTIFICATE" {
		t.Errorf("the certificate block is a %q, want %q", block.Type, "CERTIFICATE")
	}
}

// onlyBlock decodes the single PEM block in b, and insists that it is the only one.
//
// A trailing block would mean a chain, and neither of these files has one. Tools
// disagree about whether to take the first block or the last, so a stray one is a file
// that works in one place and not in another.
func onlyBlock(t *testing.T, what string, b []byte) *pem.Block {
	t.Helper()
	block, rest := pem.Decode(b)
	if block == nil {
		t.Fatalf("%s holds no PEM block: %q", what, b)
	}
	if len(rest) != 0 {
		t.Errorf("%d octets follow the one block in %s: %q", len(rest), what, rest)
	}
	return block
}

// --- validity, which is the part most likely to be off by an hour ---

func TestSelfBackDatesValidityAgainstClockSkew(t *testing.T) {
	const lifetime = 30 * 24 * time.Hour
	leaf := mustLeaf(t, mustSelf(t, Config{Hosts: testHosts, Lifetime: lifetime, Now: fixedNow}))

	// A certificate valid from exactly now fails on a machine whose clock is a minute
	// behind, and it fails with a message about the certificate rather than about the
	// clock.
	wantBefore := fixedNow.Add(-clockSkew)
	if !leaf.NotBefore.Equal(wantBefore) {
		t.Errorf("NotBefore is %s, want %s (%v before the clock)",
			leaf.NotBefore.Format(time.RFC3339), wantBefore.Format(time.RFC3339), clockSkew)
	}

	// The skew is added back at the far end, so a caller asking for thirty days gets
	// thirty days from now rather than thirty days minus an hour.
	wantAfter := fixedNow.Add(lifetime)
	if !leaf.NotAfter.Equal(wantAfter) {
		t.Errorf("NotAfter is %s, want %s; the back-dating must not be taken out of the lifetime",
			leaf.NotAfter.Format(time.RFC3339), wantAfter.Format(time.RFC3339))
	}
}

func TestSelfFallsBackToTheDefaultLifetime(t *testing.T) {
	for _, tc := range []struct {
		name     string
		lifetime time.Duration
	}{
		{"unset", 0},
		{"negative", -time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			leaf := mustLeaf(t, mustSelf(t, Config{Hosts: testHosts, Lifetime: tc.lifetime, Now: fixedNow}))

			want := fixedNow.Add(DefaultLifetime)
			if !leaf.NotAfter.Equal(want) {
				t.Errorf("NotAfter is %s, want %s; a %v lifetime has to take the default, because the "+
					"alternative is a certificate that expired before it was written",
					leaf.NotAfter.Format(time.RFC3339), want.Format(time.RFC3339), tc.lifetime)
			}
			if !leaf.NotAfter.After(leaf.NotBefore) {
				t.Errorf("NotAfter %s is not after NotBefore %s",
					leaf.NotAfter.Format(time.RFC3339), leaf.NotBefore.Format(time.RFC3339))
			}
		})
	}
}

func TestDefaultLifetimeIsInsideTheBrowserCeiling(t *testing.T) {
	// Browsers refuse a certificate whose validity exceeds 398 days outright, so a
	// generous default is a certificate nothing accepts.
	const ceiling = 398 * 24 * time.Hour
	if DefaultLifetime+clockSkew >= ceiling {
		t.Errorf("a generated certificate is valid for %v, at or above the %v browsers accept",
			DefaultLifetime+clockSkew, ceiling)
	}
	if DefaultLifetime < 24*time.Hour {
		t.Errorf("a generated certificate is valid for %v, which cannot outlast the demonstration it "+
			"exists for", DefaultLifetime)
	}
}

func TestSelfUsesTheWallClockWhenNoneIsGiven(t *testing.T) {
	before := time.Now()
	leaf := mustLeaf(t, mustSelf(t, Config{Hosts: testHosts}))
	after := time.Now()

	// A second of slack at each end, because the certificate stores whole seconds.
	earliest := before.Add(-clockSkew - time.Second)
	latest := after.Add(-clockSkew + time.Second)
	if leaf.NotBefore.Before(earliest) || leaf.NotBefore.After(latest) {
		t.Errorf("NotBefore is %s, outside [%s, %s]; an unset Config.Now has to mean now and not the "+
			"zero time", leaf.NotBefore.Format(time.RFC3339),
			earliest.Format(time.RFC3339), latest.Format(time.RFC3339))
	}
}

// --- serial numbers ---

func TestSelfDrawsADistinctSerialEachTime(t *testing.T) {
	const runs = 16
	seen := make(map[string]bool, runs)
	for i := range runs {
		leaf := mustLeaf(t, mustSelf(t, testConfig()))

		// RFC 5280 §4.1.2.2: a positive integer of at most twenty octets.
		if leaf.SerialNumber.Sign() <= 0 {
			t.Fatalf("run %d drew the serial %v, which is not positive", i, leaf.SerialNumber)
		}
		if n := len(leaf.SerialNumber.Bytes()); n > 20 {
			t.Fatalf("run %d drew a %d-octet serial, above the 20 RFC 5280 §4.1.2.2 allows", i, n)
		}

		s := leaf.SerialNumber.String()
		if seen[s] {
			// Two certificates sharing a serial, in one trust store, is a conflict a
			// browser resolves by refusing one of them.
			t.Fatalf("run %d drew the serial %s a second time", i, s)
		}
		seen[s] = true
	}
}

func TestSerialNumberStaysPositiveWhenTheDrawIsZero(t *testing.T) {
	// rand.Int returns a value in [0, max), so zero is a legal draw and a zero serial
	// violates RFC 5280 §4.1.2.2. Reaching that draw by chance takes on the order of
	// 2^128 attempts; reaching it deliberately takes a source that returns zeros.
	swapRand(t, zeroReader{})

	n, err := serialNumber()
	if err != nil {
		t.Fatalf("serialNumber with a zero source: %v", err)
	}
	if n.Sign() <= 0 {
		t.Errorf("serialNumber returned %v when the draw was zero, want a positive integer", n)
	}
}

// --- what happens when the machine has no entropy ---

// TestSerialNumberReportsAFailedDraw goes at serialNumber directly, because Self cannot
// reach this. Self generates the key after building the template, so a reader that fails
// for everything fails the key generation too — and both failures wrap the same
// underlying error, which makes a test through Self pass whether the serial's error is
// propagated or dropped on the floor.
func TestSerialNumberReportsAFailedDraw(t *testing.T) {
	want := errors.New("the entropy pool is empty")
	swapRand(t, errReader{err: want})

	n, err := serialNumber()
	if err == nil {
		t.Fatalf("serialNumber returned %v with no source of randomness", n)
	}
	if !errors.Is(err, want) {
		t.Errorf("serialNumber failed with %v, which does not wrap the underlying error", err)
	}
	if n != nil {
		t.Errorf("serialNumber returned the serial %v alongside an error", n)
	}
}

func TestSelfFailsWhenThereIsNoEntropy(t *testing.T) {
	want := errors.New("the entropy pool is empty")
	swapRand(t, errReader{err: want})

	p, err := Self(testConfig())
	if err == nil {
		t.Fatal("Self produced a certificate with no source of randomness")
	}
	if !errors.Is(err, want) {
		t.Errorf("Self failed with %v, which does not wrap the underlying error", err)
	}
	assertNoPEM(t, p)
}

func TestSelfFailsWhenTheEntropySourceDiesPartWay(t *testing.T) {
	// Enough octets for the serial number and not enough for a P-256 key: the serial
	// draw takes seventeen and a key needs at least thirty-two. Which stage fails is
	// not the point. The point is that a certificate is never returned alongside an
	// error, because a caller that logs the error and carries on would then be
	// serving a key drawn from a source that failed.
	swapRand(t, &shortReader{left: 24})

	p, err := Self(testConfig())
	if err == nil {
		t.Fatal("Self produced a certificate from a source of randomness that ran out")
	}
	assertNoPEM(t, p)
}

func assertNoPEM(t *testing.T, p PEM) {
	t.Helper()
	if p.Cert != nil || p.Key != nil {
		t.Errorf("Self returned an error together with %d octets of certificate and %d of key",
			len(p.Cert), len(p.Key))
	}
}

// swapRand replaces the process-wide source of randomness for one test and puts it
// back afterwards.
//
// A package-level variable is a poor seam, and it is the seam crypto/rand offers.
// Nothing in this file runs in parallel, which is what makes it safe.
func swapRand(t *testing.T, r io.Reader) {
	t.Helper()
	saved := rand.Reader
	rand.Reader = r
	t.Cleanup(func() { rand.Reader = saved })
}

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

type zeroReader struct{}

func (zeroReader) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = 0
	}
	return len(b), nil
}

// shortReader serves left octets and then refuses.
type shortReader struct{ left int }

func (r *shortReader) Read(b []byte) (int, error) {
	if r.left <= 0 {
		return 0, io.ErrUnexpectedEOF
	}
	n := min(len(b), r.left)
	for i := range b[:n] {
		// Not zeros: a key generator rejects an out-of-range scalar and draws again,
		// so a zero source can make it loop rather than fail. The leading 0x40 also
		// keeps rand.Int's rejection sampling to a single attempt, which is what
		// makes the count above predictable.
		b[i] = byte(0x40 + i)
	}
	r.left -= n
	return n, nil
}

// --- hosts that cannot be certified ---

func TestSelfRejectsAnEmptyHostList(t *testing.T) {
	p, err := Self(Config{Now: fixedNow})
	if err == nil {
		t.Fatal("Self issued a certificate valid for no name at all")
	}
	if !strings.Contains(err.Error(), "Hosts") {
		t.Errorf("the error is %q and does not name the field at fault", err)
	}
	assertNoPEM(t, p)
}

func TestSelfRejectsAHostThatIsNeitherNameNorAddress(t *testing.T) {
	for _, tc := range []struct {
		name string
		host string
	}{
		// The mistake worth catching: a listen address pasted into the wrong field.
		// It parses as no IP, it is not a DNS name, and it would otherwise become a
		// SAN nothing ever asks for.
		{"an address with a port", "localhost:8443"},
		{"a URL", "https://localhost"},
		{"a scoped IPv6 address", "fe80::1%eth0"},
		{"a comma-separated list", "localhost,127.0.0.1"},
		{"a name with a space", "local host"},
		{"a name with a tab", "localhost\there"},
		{"a path", "/var/run/zdh"},
		{"an email address", "zdh@example.test"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Self(Config{Hosts: []string{tc.host}, Now: fixedNow})
			if err == nil {
				t.Fatalf("Self accepted %q as a host", tc.host)
			}
			// Quoted, because the error quotes it: a host holding a tab appears in the
			// message as an escape and not as the octet.
			if !strings.Contains(err.Error(), fmt.Sprintf("%q", tc.host)) {
				t.Errorf("the error is %q and does not quote the host at fault", err)
			}
			assertNoPEM(t, p)
		})
	}
}

func TestSelfRejectsAnEmptyHostAmongValidOnes(t *testing.T) {
	// The shape a configuration file produces: strings.Split over a trailing comma.
	p, err := Self(Config{Hosts: []string{"localhost", "", "127.0.0.1"}, Now: fixedNow})
	if err == nil {
		t.Fatal("Self accepted an empty name in the middle of a valid list")
	}
	// The message, and not merely the failure, because crypto/x509 may come to refuse
	// an empty SAN of its own accord. If it does, the error arrives from two layers
	// down talking about ASN.1, and whoever wrote the trailing comma learns nothing.
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("the error is %q, which does not say that a name was empty", err)
	}
	assertNoPEM(t, p)
}

func TestSelfRejectsAnOversizedName(t *testing.T) {
	p, err := Self(Config{Hosts: []string{strings.Repeat("a", 254)}, Now: fixedNow})
	if err == nil {
		t.Fatal("Self accepted a 254-octet DNS name, above the 253 RFC 1035 §2.3.4 allows")
	}
	if !strings.Contains(err.Error(), "254") {
		t.Errorf("the error is %q and does not say how long the name was", err)
	}
	assertNoPEM(t, p)
}

func TestSelfKeepsTheFirstHostAsTheCommonName(t *testing.T) {
	leaf := mustLeaf(t, mustSelf(t, Config{Hosts: []string{"zdh.example.test", "127.0.0.1"}, Now: fixedNow}))

	// Cosmetic — nothing has verified a common name since RFC 6125 — and it is the
	// title a certificate viewer shows, which is the first thing anyone deciding
	// whether to trust this will read.
	if leaf.Subject.CommonName != "zdh.example.test" {
		t.Errorf("the common name is %q, want the first host", leaf.Subject.CommonName)
	}
}

// --- parsing what came back ---

func TestLeafRejectsWhatIsNotACertificate(t *testing.T) {
	good := mustSelf(t, testConfig())

	for _, tc := range []struct {
		name string
		cert []byte
		want string
	}{
		{"nothing at all", nil, "no PEM block"},
		{"a comment and no block", []byte("# this is not a certificate\n"), "no PEM block"},
		{"the private key in the certificate's place", good.Key, "PRIVATE KEY"},
		{"a certificate block holding rubbish", []byte(
			"-----BEGIN CERTIFICATE-----\nZGVmaW5pdGVseSBub3QgYSBjZXJ0aWZpY2F0ZQ==\n" +
				"-----END CERTIFICATE-----\n"), "parsing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			leaf, err := PEM{Cert: tc.cert, Key: good.Key}.Leaf()
			if err == nil {
				t.Fatalf("Leaf parsed %s as a certificate", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the error is %q, which does not mention %q, so it does not say what was wrong",
					err, tc.want)
			}
			if leaf != nil {
				t.Error("Leaf returned a certificate alongside an error")
			}
		})
	}
}

func TestCertificateRejectsAMismatchedPair(t *testing.T) {
	a := mustSelf(t, testConfig())
	b := mustSelf(t, testConfig())

	// Two certificates for the same hosts, so nothing but the key distinguishes them.
	// Serving a certificate whose key belongs to another fails in the middle of a
	// handshake, which is a much harder error to read than this one.
	if _, err := (PEM{Cert: a.Cert, Key: b.Key}).Certificate(); err == nil {
		t.Fatal("Certificate accepted a certificate and a key from different pairs")
	}
}

func TestPoolRejectsWhatItCannotParse(t *testing.T) {
	if _, err := (PEM{Cert: []byte("not a certificate")}).Pool(); err == nil {
		t.Fatal("Pool built a pool out of something that is not a certificate")
	}
}

// --- writing to disk ---

func paths(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, "zdh.crt"), filepath.Join(dir, "zdh.key")
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return b
}

func assertAbsent(t *testing.T, path, why string) {
	t.Helper()
	_, err := os.Stat(path)
	switch {
	case err == nil:
		t.Errorf("%s exists: %s", path, why)
	case !errors.Is(err, os.ErrNotExist):
		t.Fatalf("looking for %s: %v", path, err)
	}
}

func TestWriteSavesAPairThatLoadsBack(t *testing.T) {
	certPath, keyPath := paths(t)
	p := mustSelf(t, testConfig())

	if err := Write(certPath, keyPath, p); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// The round trip through the filesystem is the claim: what a browser is handed
	// has to be what was generated, and PEM is the encoding that makes those the same
	// thing.
	if got := readFile(t, certPath); string(got) != string(p.Cert) {
		t.Error("the certificate on disk is not the certificate that was generated")
	}
	if got := readFile(t, keyPath); string(got) != string(p.Key) {
		t.Error("the key on disk is not the key that was generated")
	}
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		t.Errorf("crypto/tls cannot load the pair that was just written: %v", err)
	}
}

func TestWriteCreatesTheDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "etc", "zdh", "tls")
	certPath := filepath.Join(dir, "zdh.crt")
	keyPath := filepath.Join(dir, "zdh.key")

	if err := Write(certPath, keyPath, mustSelf(t, testConfig())); err != nil {
		t.Fatalf("Write into a directory that does not exist yet: %v", err)
	}
	if _, err := os.Stat(certPath); err != nil {
		t.Errorf("the certificate was reported written and is not there: %v", err)
	}
}

func TestWriteRefusesToReplaceAnExistingFile(t *testing.T) {
	for _, tc := range []struct {
		name     string
		occupied func(certPath, keyPath string) string
	}{
		{"the certificate", func(certPath, _ string) string { return certPath }},
		{"the key", func(_, keyPath string) string { return keyPath }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			certPath, keyPath := paths(t)
			occupied := tc.occupied(certPath, keyPath)

			const existing = "something that was already here\n"
			if err := os.WriteFile(occupied, []byte(existing), 0o600); err != nil {
				t.Fatalf("planting a file at %s: %v", occupied, err)
			}

			err := Write(certPath, keyPath, mustSelf(t, testConfig()))
			if err == nil {
				t.Fatalf("Write replaced %s", occupied)
			}
			if !strings.Contains(err.Error(), occupied) {
				t.Errorf("the error is %q and does not name the file in the way", err)
			}
			// The assertion that matters. One of these two files is a private key,
			// and this package cannot tell its own leftovers from a key somebody
			// still needs.
			if got := readFile(t, occupied); string(got) != existing {
				t.Errorf("%s now holds %q, want the %q that was there", occupied, got, existing)
			}
		})
	}
}

func TestWriteLeavesNoKeyWhenTheCertificateCannotBeWritten(t *testing.T) {
	certPath, keyPath := paths(t)

	// A directory where the certificate belongs: a path that exists, that O_EXCL
	// refuses, and that no amount of retrying will make writable.
	if err := os.Mkdir(certPath, 0o700); err != nil {
		t.Fatalf("planting a directory at %s: %v", certPath, err)
	}

	if err := Write(certPath, keyPath, mustSelf(t, testConfig())); err == nil {
		t.Fatal("Write reported success with a directory where the certificate belongs")
	}
	// The certificate is written first precisely so that a failure here leaves a
	// public document behind rather than a private key that nothing will come back
	// for.
	assertAbsent(t, keyPath, "a private key was written for a certificate that failed")
}

func TestWriteKeepsThePrivateKeyToItsOwner(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Windows synthesises a file mode from the ACL a file inherits, so the number
		// asked for here is not the number that governs. The 0o700 on the directory
		// is in the same position.
		t.Skip("file modes are advisory on Windows; the ACL is what governs")
	}

	certPath, keyPath := paths(t)
	if err := Write(certPath, keyPath, mustSelf(t, testConfig())); err != nil {
		t.Fatalf("Write: %v", err)
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("looking at the key: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("the private key is mode %04o, want 0600; every account on the machine can read a "+
			"key that is not", perm)
	}
}

func TestWriteRaceLeavesOneWinner(t *testing.T) {
	certPath, keyPath := paths(t)

	// A restart racing itself, or two copies of the server started at once. Between
	// checking whether a file exists and writing it is exactly where one process
	// overwrites a key another has already served, so the write is O_EXCL and this is
	// the test that says so.
	const writers = 8
	var wg sync.WaitGroup
	errs := make([]error, writers)
	start := make(chan struct{})
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, err := Self(testConfig())
			if err != nil {
				errs[i] = err
				return
			}
			<-start
			errs[i] = Write(certPath, keyPath, p)
		}()
	}
	close(start)
	wg.Wait()

	won := 0
	for i, err := range errs {
		if err == nil {
			won++
			continue
		}
		if !strings.Contains(err.Error(), certPath) && !strings.Contains(err.Error(), keyPath) {
			t.Errorf("writer %d failed with %v, which names neither file", i, err)
		}
	}
	if won != 1 {
		t.Fatalf("%d of %d concurrent writers reported success, want exactly 1", won, writers)
	}

	// And what is left is a usable pair, not one writer's certificate beside
	// another's key.
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		t.Errorf("the pair left behind by the race does not load: %v", err)
	}
}

// --- LoadOrCreate ---

func mustSerial(t *testing.T, cert tls.Certificate) *big.Int {
	t.Helper()
	if len(cert.Certificate) == 0 {
		t.Fatal("a returned tls.Certificate carries no certificate at all")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parsing a returned certificate: %v", err)
	}
	return leaf.SerialNumber
}

func TestLoadOrCreateGeneratesWhenNothingIsThere(t *testing.T) {
	certPath, keyPath := paths(t)

	cert, origin, err := LoadOrCreate(certPath, keyPath, testConfig())
	if err != nil {
		t.Fatalf("LoadOrCreate on an empty directory: %v", err)
	}
	if !strings.Contains(origin, "generated") {
		t.Errorf("the origin is %q and does not say the certificate is new; whoever reads the log then "+
			"has no way to know a browser's trust decision has just been invalidated", origin)
	}
	if !strings.Contains(origin, certPath) {
		t.Errorf("the origin is %q and does not say where the certificate went", origin)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("LoadOrCreate returned an empty certificate and no error")
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Errorf("the key was not saved: %v", err)
	}
}

func TestLoadOrCreateReusesWhatItWrote(t *testing.T) {
	certPath, keyPath := paths(t)

	first, _, err := LoadOrCreate(certPath, keyPath, testConfig())
	if err != nil {
		t.Fatalf("the first LoadOrCreate: %v", err)
	}
	second, origin, err := LoadOrCreate(certPath, keyPath, testConfig())
	if err != nil {
		t.Fatalf("the second LoadOrCreate: %v", err)
	}

	if !strings.Contains(origin, "loaded") {
		t.Errorf("the second call reported %q, want it to say the certificate was loaded", origin)
	}
	// Why it matters: whoever imported the first certificate into a browser did so
	// once. A second run that quietly issues a new one throws that away and puts the
	// warning page back.
	if got, want := mustSerial(t, second), mustSerial(t, first); got.Cmp(want) != 0 {
		t.Errorf("the second call returned serial %s, want the %s the first wrote", got, want)
	}
}

func TestLoadOrCreateSetsTheParsedLeaf(t *testing.T) {
	// x509keypairleaf is what makes this worth asserting. crypto/tls parses the leaf on
	// the way in regardless — it has to, to check that the certificate matches the key
	// — but it only keeps the result while this setting is on, and it is off for any
	// module that declares go 1.22 or older. Leaving the test on the default would be a
	// test of crypto/tls's behaviour rather than of this package's, and it would pass
	// with the assignment in load deleted.
	t.Setenv("GODEBUG", "x509keypairleaf=0")

	certPath, keyPath := paths(t)
	if _, _, err := LoadOrCreate(certPath, keyPath, testConfig()); err != nil {
		t.Fatalf("generating: %v", err)
	}

	cert, _, err := LoadOrCreate(certPath, keyPath, testConfig())
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	// It was parsed here already to check the dates, so leaving it unset throws that
	// work away and has crypto/tls do it again on the first handshake.
	if cert.Leaf == nil {
		t.Error("the loaded certificate has no parsed leaf, so crypto/tls will parse it a second time")
	}
}

func TestLoadOrCreateRefusesHalfAPair(t *testing.T) {
	for _, tc := range []struct {
		name  string
		which func(certPath, keyPath string) (present, missing string)
	}{
		{"the certificate without its key", func(c, k string) (string, string) { return c, k }},
		{"the key without its certificate", func(c, k string) (string, string) { return k, c }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			certPath, keyPath := paths(t)
			present, missing := tc.which(certPath, keyPath)

			const planted = "half of a pair\n"
			if err := os.WriteFile(present, []byte(planted), 0o600); err != nil {
				t.Fatalf("planting %s: %v", present, err)
			}

			_, _, err := LoadOrCreate(certPath, keyPath, testConfig())
			if err == nil {
				t.Fatalf("LoadOrCreate resolved a directory holding only %s", present)
			}
			for _, want := range []string{present, missing} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the error is %q and does not name %s", err, want)
				}
			}
			// The half that is there may be a key somebody needs, so neither file may
			// be touched: not the one present, and not the one missing, because
			// filling that in would complete a pair whose halves do not match.
			if got := readFile(t, present); string(got) != planted {
				t.Errorf("%s now holds %q, want the %q that was there", present, got, planted)
			}
			assertAbsent(t, missing, "the missing half of a pair was filled in")
		})
	}
}

func TestLoadOrCreateRejectsAnExpiredCertificate(t *testing.T) {
	certPath, keyPath := paths(t)

	// Written a year ago with a thirty-day life: what a long-lived install looks like
	// on the day it stops working.
	issued := fixedNow.Add(-365 * 24 * time.Hour)
	p := mustSelf(t, Config{Hosts: testHosts, Lifetime: 30 * 24 * time.Hour, Now: issued})
	if err := Write(certPath, keyPath, p); err != nil {
		t.Fatalf("Write: %v", err)
	}

	_, _, err := LoadOrCreate(certPath, keyPath, testConfig())
	if err == nil {
		t.Fatal("LoadOrCreate returned an expired certificate; a tls.Config serves one perfectly " +
			"happily and every client refuses it, so the failure would land in a browser instead of here")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("the error is %q and does not say the certificate expired", err)
	}
	// And it says what to do about it, which is the difference between a sentence and
	// a support question.
	if !strings.Contains(err.Error(), keyPath) {
		t.Errorf("the error is %q and does not name the key that has to go with it", err)
	}
}

func TestLoadOrCreateRejectsACertificateFromTheFuture(t *testing.T) {
	certPath, keyPath := paths(t)

	p := mustSelf(t, Config{Hosts: testHosts, Now: fixedNow.Add(365 * 24 * time.Hour)})
	if err := Write(certPath, keyPath, p); err != nil {
		t.Fatalf("Write: %v", err)
	}

	_, _, err := LoadOrCreate(certPath, keyPath, testConfig())
	if err == nil {
		t.Fatal("LoadOrCreate returned a certificate that is not valid yet")
	}
	if !strings.Contains(err.Error(), "not valid until") {
		t.Errorf("the error is %q and does not say the certificate is not valid yet", err)
	}
}

func TestLoadOrCreateAcceptsAPairAtTheEdgesOfItsValidity(t *testing.T) {
	// The two instants either check rejects if it uses the wrong comparison. The
	// certificate is valid at both of them, inclusive.
	certPath, keyPath := paths(t)
	if err := Write(certPath, keyPath, mustSelf(t, testConfig())); err != nil {
		t.Fatalf("Write: %v", err)
	}

	for _, tc := range []struct {
		name string
		now  time.Time
	}{
		{"the first instant it is valid", fixedNow.Add(-clockSkew)},
		{"the last instant it is valid", fixedNow.Add(DefaultLifetime)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := LoadOrCreate(certPath, keyPath, Config{Hosts: testHosts, Now: tc.now})
			if err != nil {
				t.Errorf("LoadOrCreate refused a certificate that is valid at %s: %v",
					tc.now.Format(time.RFC3339), err)
			}
		})
	}
}

func TestLoadOrCreateReportsAPairItCannotRead(t *testing.T) {
	certPath, keyPath := paths(t)

	// Both paths exist, so this is the load path, and one of them is a directory,
	// which no read will ever succeed on.
	if err := os.Mkdir(certPath, 0o700); err != nil {
		t.Fatalf("planting a directory at %s: %v", certPath, err)
	}
	if err := os.WriteFile(keyPath, mustSelf(t, testConfig()).Key, 0o600); err != nil {
		t.Fatalf("planting %s: %v", keyPath, err)
	}

	_, _, err := LoadOrCreate(certPath, keyPath, testConfig())
	if err == nil {
		t.Fatal("LoadOrCreate loaded a certificate out of a directory")
	}
	if !strings.Contains(err.Error(), certPath) {
		t.Errorf("the error is %q and does not name the path it could not read", err)
	}
}

func TestLoadOrCreateReportsAPathItCannotEvenCheck(t *testing.T) {
	dir := t.TempDir()

	// A NUL in a path is refused by the system call itself on every platform this
	// builds for, which makes it the one portable way to get a stat failure that is
	// not "the file is not there". Treating the two alike sends the caller down the
	// generate path, where it fails again on the same path and reports the second
	// failure in place of the first.
	bad := filepath.Join(dir, "zdh\x00.crt")
	good := filepath.Join(dir, "zdh.key")

	_, _, err := LoadOrCreate(bad, good, testConfig())
	if err == nil {
		t.Fatal("LoadOrCreate reported success for a path it cannot have looked at")
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Errorf("the error is %q, which reads as the file being absent rather than unreadable", err)
	}
	// That it failed is not the guard — without the guard it fails too, one step later,
	// on the write to the same impossible path. The guard is that the *first* failure is
	// the one reported, so the message has to be about looking rather than about
	// creating.
	if !strings.Contains(err.Error(), "looking for") {
		t.Errorf("the error is %q, which reports a later failure in place of the stat that failed first", err)
	}
	assertAbsent(t, good, "a key was written for a certificate whose path could not be checked")
}

func TestLoadOrCreateRefusesAnUncertifiableHost(t *testing.T) {
	certPath, keyPath := paths(t)

	// A configuration error has to be reported before anything reaches the disk.
	_, _, err := LoadOrCreate(certPath, keyPath, Config{Hosts: []string{"localhost:8443"}, Now: fixedNow})
	if err == nil {
		t.Fatal("LoadOrCreate accepted a host that cannot be certified")
	}
	assertAbsent(t, certPath, "a certificate was written for a host that was rejected")
	assertAbsent(t, keyPath, "a key was written for a certificate that was never issued")
}

func TestLoadOrCreateProducesSomethingAClientAccepts(t *testing.T) {
	certPath, keyPath := paths(t)
	if _, _, err := LoadOrCreate(certPath, keyPath, Config{Hosts: testHosts}); err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	// End to end, through the filesystem, on the real clock: the pair on disk has to
	// negotiate h2 with a client that verifies it. Every other test in this file
	// checks one field of that.
	p := PEM{Cert: readFile(t, certPath), Key: readFile(t, keyPath)}
	res := handshake(t, p, mustPool(t, p), "127.0.0.1", []string{"h2"})
	if res.clientErr != nil {
		t.Fatalf("a client refused the pair LoadOrCreate wrote: %v", res.clientErr)
	}
	if res.serverErr != nil {
		t.Fatalf("the server could not serve the pair LoadOrCreate wrote: %v", res.serverErr)
	}
	if res.state.NegotiatedProtocol != "h2" {
		t.Errorf("ALPN negotiated %q over the pair on disk, want %q", res.state.NegotiatedProtocol, "h2")
	}
}

func TestLoadOrCreateRaceLeavesOneCertificate(t *testing.T) {
	certPath, keyPath := paths(t)

	// Two servers starting at once against a shared directory. One writes the pair,
	// and the others must either load that one or fail saying why. What none of them
	// may do is serve a key the winner's certificate does not match.
	const starters = 8
	var wg sync.WaitGroup
	certs := make([]tls.Certificate, starters)
	errs := make([]error, starters)
	start := make(chan struct{})
	for i := range starters {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			certs[i], _, errs[i] = LoadOrCreate(certPath, keyPath, Config{Hosts: testHosts})
		}()
	}
	close(start)
	wg.Wait()

	var serial *big.Int
	succeeded := 0
	for i, err := range errs {
		if err != nil {
			// Losing the race is a legitimate outcome: the loser saw half a pair, or
			// a file that appeared between its two checks. What it must not do is
			// return a certificate anyway.
			if len(certs[i].Certificate) != 0 {
				t.Errorf("starter %d failed with %v and returned a certificate as well", i, err)
			}
			continue
		}
		succeeded++
		got := mustSerial(t, certs[i])
		if serial == nil {
			serial = got
			continue
		}
		if serial.Cmp(got) != 0 {
			t.Errorf("starter %d is serving serial %s while another serves %s; two servers on one "+
				"directory are presenting different identities", i, got, serial)
		}
	}
	if succeeded == 0 {
		t.Fatalf("all %d starters failed: %v", starters, errors.Join(errs...))
	}

	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		t.Errorf("the pair left behind by the race does not load: %v", err)
	}
}
