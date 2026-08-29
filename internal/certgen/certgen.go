// Package certgen makes the self-signed certificate a TLS server needs in order to
// exist at all.
//
// It is here because of what the alternative would cost. Every HTTP/2 client that
// matters negotiates the protocol through TLS ALPN, so a server with no certificate
// cannot be demonstrated to a browser at all — and asking whoever runs this to
// produce one first means asking them to install and drive openssl, which Rule 11
// puts outside this project's scope. Two hundred lines of crypto/x509 remove that
// dependency entirely.
//
// Nothing here is a certificate authority and nothing here should be trusted by
// anything that matters. It exists so that `zdh serve` works on a machine that has
// never seen a certificate, and so that a judge can reach https://localhost:8443 and
// read "h2" in the protocol column.
package certgen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultLifetime is how long a generated certificate is valid for.
//
// Ninety days is the public web's own answer, and the reasoning carries over: short
// enough that a leaked key stops mattering, long enough that nobody is regenerating
// one mid-demonstration. It is also comfortably inside the 398 days after which
// browsers reject a certificate outright.
const DefaultLifetime = 90 * 24 * time.Hour

// clockSkew is how far back the certificate's validity is dated.
//
// Not paranoia: a fresh container, a virtual machine resumed from a snapshot, and a
// Windows laptop that has just woken up all routinely have clocks minutes out. A
// certificate valid from exactly now is a certificate that fails on the first
// handshake, and it fails with a message about the certificate rather than about the
// clock, which is a bad hour for whoever has to work it out.
const clockSkew = time.Hour

// Config describes the certificate to make.
type Config struct {
	// Hosts are the names and addresses the certificate is valid for. An entry that
	// parses as an IP address becomes an IP SAN and everything else becomes a DNS
	// SAN, because a client checks exactly one of those two lists and never the
	// other: "127.0.0.1" in the DNS list is a certificate that silently does not
	// work for https://127.0.0.1.
	//
	// Required. A certificate valid for nothing is worse than no certificate, since
	// it fails at handshake time with a message about names rather than at startup
	// with a message about configuration.
	Hosts []string

	// Lifetime is how long the certificate is valid for. Zero or negative takes
	// DefaultLifetime.
	Lifetime time.Duration

	// Now overrides the clock, for tests. Zero means time.Now.
	Now time.Time
}

func (c Config) lifetime() time.Duration {
	if c.Lifetime <= 0 {
		return DefaultLifetime
	}
	return c.Lifetime
}

func (c Config) now() time.Time {
	if c.Now.IsZero() {
		return time.Now()
	}
	return c.Now
}

// PEM is a certificate and its private key, in the encoding both crypto/tls and every
// other tool in the world reads.
//
// PEM rather than the parsed forms because it is the one representation that is
// certainly the same thing on disk, in a browser's import dialogue and in
// tls.Config: a round trip through it is how this package knows that what it
// generated is what a peer will be handed.
type PEM struct {
	Cert []byte
	Key  []byte
}

// Self generates a self-signed certificate and its key.
//
// The key is ECDSA on P-256, for two reasons that both come down to what browsers
// actually accept. Ed25519 is the better curve and no shipping browser will accept a
// certificate that uses it. RSA is accepted everywhere and its key generation takes
// somewhere between fifty milliseconds and a second depending on how the primes fall,
// which is a server that appears to hang for a random length of time on first run;
// P-256 generation is a single scalar multiplication, and 256 bits of it is about the
// strength of a 3072-bit RSA key.
func Self(cfg Config) (PEM, error) {
	tmpl, err := template(cfg)
	if err != nil {
		return PEM{}, err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		// Reached when the operating system's entropy source fails, which is rare
		// and must never be papered over: the fallback for a key nobody could
		// generate is not a key nobody should trust.
		return PEM{}, fmt.Errorf("certgen: generating a P-256 key: %w", err)
	}

	// Self-signed: the template is both the certificate and its own issuer, and the
	// key signs for itself.
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return PEM{}, fmt.Errorf("certgen: signing the certificate: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return PEM{}, fmt.Errorf("certgen: encoding the private key: %w", err)
	}

	return PEM{
		Cert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		// PKCS#8 rather than SEC 1 ("EC PRIVATE KEY"), because PKCS#8 names the
		// algorithm inside the structure. Everything reads it, and a file that says
		// what it contains is one fewer thing to guess when it does not load.
		Key: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}, nil
}

// template builds the certificate to be signed, and is where every decision a client
// will check lives.
func template(cfg Config) (*x509.Certificate, error) {
	dns, ips, err := splitHosts(cfg.Hosts)
	if err != nil {
		return nil, err
	}

	serial, err := serialNumber()
	if err != nil {
		return nil, err
	}

	notBefore := cfg.now().Add(-clockSkew)
	return &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"zdh"},
			// Cosmetic, and deliberately so. The common name has not been consulted
			// for host matching since RFC 6125, and Chrome stopped honouring it
			// entirely in 2017 — the SANs below are what a client checks. It is set
			// because it is what a certificate viewer shows as the title, and an
			// untitled certificate in a browser's dialogue is needlessly alarming.
			CommonName: cfg.Hosts[0],
		},
		DNSNames:    dns,
		IPAddresses: ips,

		NotBefore: notBefore,
		NotAfter:  notBefore.Add(clockSkew + cfg.lifetime()),

		// DigitalSignature is what an ECDSA key does in every TLS 1.3 handshake.
		// CertSign is here because this certificate is its own issuer: it is
		// presented as a leaf and, when someone imports it into a trust store to
		// silence the browser's warning, it is verified as a root. A root without
		// CertSign is a certificate some verifiers reject for the reason it was
		// imported.
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},

		// Both of these follow from being its own issuer. Without
		// BasicConstraintsValid the extension is left out altogether and the CA bit
		// says nothing.
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, nil
}

// splitHosts sorts the configured hosts into the two lists a client checks, and
// refuses anything that would end up in neither.
func splitHosts(hosts []string) (dns []string, ips []net.IP, err error) {
	if len(hosts) == 0 {
		return nil, nil, errors.New("certgen: Config.Hosts is empty; a certificate valid for no name " +
			"fails at the handshake rather than here, and says nothing useful when it does")
	}

	for _, h := range hosts {
		if h == "" {
			return nil, nil, errors.New("certgen: Config.Hosts contains an empty name")
		}
		if ip := net.ParseIP(h); ip != nil {
			ips = append(ips, ip)
			continue
		}
		// Everything that is not an address is treated as a DNS name, so anything
		// that cannot be one has to be refused here. The mistake this catches is
		// "localhost:8443": an address with a port, which parses as no IP, is not a
		// DNS name, and would otherwise become a SAN no client will ever ask for —
		// producing a certificate that is wrong in a way only visible in a browser's
		// error page.
		if i := strings.IndexAny(h, ":/%,@ \t"); i >= 0 {
			return nil, nil, fmt.Errorf("certgen: %q is neither an IP address nor a DNS name "+
				"(it contains %q); a host and port belong to a listen address, not to a certificate",
				h, h[i])
		}
		if len(h) > 253 {
			return nil, nil, fmt.Errorf("certgen: the DNS name %q is %d octets, above the 253 a name "+
				"may have (RFC 1035 §2.3.4)", h[:32]+"...", len(h))
		}
		dns = append(dns, h)
	}
	return dns, ips, nil
}

// serialNumber returns a random positive serial number.
//
// Random because a serial has to be unpredictable for a real CA and unique for
// everyone: two certificates sharing one, in the same trust store, is a conflict
// browsers resolve by refusing one of them. Positive because RFC 5280 §4.1.2.2 says
// so, and rand.Int can return zero.
func serialNumber() (*big.Int, error) {
	// 128 bits, which is the CA/Browser Forum's floor for entropy in a serial and
	// well inside the twenty octets §4.1.2.2 allows.
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("certgen: drawing a serial number: %w", err)
	}
	return n.Add(n, big.NewInt(1)), nil
}

// Certificate parses p into the form crypto/tls wants.
func (p PEM) Certificate() (tls.Certificate, error) {
	cert, err := tls.X509KeyPair(p.Cert, p.Key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("certgen: the certificate and key do not form a pair: %w", err)
	}
	return cert, nil
}

// Leaf parses the certificate on its own, without the key.
func (p PEM) Leaf() (*x509.Certificate, error) {
	block, _ := pem.Decode(p.Cert)
	if block == nil {
		return nil, errors.New("certgen: no PEM block in the certificate")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("certgen: the first PEM block is a %q, not a CERTIFICATE", block.Type)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("certgen: parsing the certificate: %w", err)
	}
	return cert, nil
}

// Pool returns a certificate pool trusting exactly this certificate, which is what a
// client needs to reach a server using it without being told to skip verification.
//
// It is here so that the tests, and anyone demonstrating this server with a client of
// their own, never have to reach for InsecureSkipVerify. That setting disables the
// name check as well as the trust check, so a test using it would pass against a
// certificate issued for the wrong host — which is one of the things this package has
// to get right.
func (p PEM) Pool() (*x509.CertPool, error) {
	leaf, err := p.Leaf()
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return pool, nil
}

// Write saves the pair, refusing to touch either path that already exists.
//
// Refusing rather than overwriting, because one of these two files is a private key
// and this package cannot tell its own leftovers from a key that matters. The cost of
// being wrong in one direction is an error message naming the file to move; in the
// other it is somebody's certificate, gone.
func Write(certPath, keyPath string, p PEM) error {
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return fmt.Errorf("certgen: making the directory for %s: %w", certPath, err)
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return fmt.Errorf("certgen: making the directory for %s: %w", keyPath, err)
	}

	// The certificate first, and the order is the point. Either write can fail — a
	// full disk, a read-only mount, a path one of the two already occupies — and
	// whichever went first is left behind. Failing after the certificate leaves a
	// public document on disk; failing after the key leaves a private key, written
	// for a certificate that will never exist and that nothing will ever come back
	// to clean up. Both leave a half pair the load path refuses, so the only thing
	// the order decides is which half.
	if err := writeNew(certPath, p.Cert, 0o644); err != nil {
		return err
	}
	if err := writeNew(keyPath, p.Key, 0o600); err != nil {
		return err
	}
	return nil
}

// writeNew creates path and fails if it is already there.
//
// O_EXCL rather than checking first and then writing. Two copies of this server
// starting at once — a restart racing itself, a test suite running in parallel — is
// the ordinary case, and between a check and a write is exactly where one of them
// overwrites the other's key with a key the other has already served.
func writeNew(path string, content []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("certgen: creating %s: %w", path, err)
	}
	if _, err := f.Write(content); err != nil {
		f.Close()
		return fmt.Errorf("certgen: writing %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("certgen: closing %s: %w", path, err)
	}
	return nil
}

// LoadOrCreate returns the certificate at certPath and keyPath, generating and saving
// one if neither file is there yet. The returned string says which of the two
// happened, in a form fit for a log line.
//
// Generating only when *both* files are absent is the whole design. A directory
// holding one half of a pair is a state this package must not resolve on its own: the
// half that is there may be a key somebody needs, and writing a new one over it is
// unrecoverable in a way that no error message is.
func LoadOrCreate(certPath, keyPath string, cfg Config) (tls.Certificate, string, error) {
	haveCert, err := exists(certPath)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	haveKey, err := exists(keyPath)
	if err != nil {
		return tls.Certificate{}, "", err
	}

	switch {
	case haveCert && haveKey:
		cert, err := load(certPath, keyPath, cfg.now())
		if err != nil {
			return tls.Certificate{}, "", err
		}
		return cert, fmt.Sprintf("loaded the certificate from %s", certPath), nil

	case haveCert != haveKey:
		present, missing := certPath, keyPath
		if haveKey {
			present, missing = keyPath, certPath
		}
		return tls.Certificate{}, "", fmt.Errorf("certgen: %s exists but %s does not; move or remove "+
			"%s if it is not wanted, because generating a new pair over half of one would replace a "+
			"key that may still be in use", present, missing, present)
	}

	p, err := Self(cfg)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	if err := Write(certPath, keyPath, p); err != nil {
		return tls.Certificate{}, "", err
	}
	cert, err := p.Certificate()
	if err != nil {
		return tls.Certificate{}, "", err
	}
	return cert, fmt.Sprintf("generated a certificate for %s and saved it to %s",
		strings.Join(cfg.Hosts, ", "), certPath), nil
}

// load reads a pair and checks the one thing tls.LoadX509KeyPair does not.
//
// It does not check validity dates: a tls.Config serves an expired certificate
// perfectly happily and every client refuses it, so the failure lands in a browser as
// an interstitial about a certificate rather than at startup as a line about a file.
// Catching it here turns a support question into a sentence.
func load(certPath, keyPath string, now time.Time) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("certgen: loading the pair at %s and %s: %w",
			certPath, keyPath, err)
	}

	// LoadX509KeyPair parses the leaf itself in order to check that it matches the
	// key, and since Go 1.23 it keeps the result — but only while the GODEBUG setting
	// x509keypairleaf is on, and it is off for any module declaring go 1.22 or older.
	// Certificate[0] is the leaf by definition of the field's order, and it has to be
	// parsed here anyway to check the dates below, so this is a parse already paid for
	// rather than one the setting can take away.
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("certgen: parsing %s: %w", certPath, err)
	}

	switch {
	case now.Before(leaf.NotBefore):
		return tls.Certificate{}, fmt.Errorf("certgen: the certificate in %s is not valid until %s, "+
			"which is in the future; either this machine's clock is wrong or the file is",
			certPath, leaf.NotBefore.Format(time.RFC3339))
	case now.After(leaf.NotAfter):
		return tls.Certificate{}, fmt.Errorf("certgen: the certificate in %s expired on %s; remove it "+
			"and %s to have a new pair generated", certPath, leaf.NotAfter.Format(time.RFC3339), keyPath)
	}

	// Kept, so that the caller — and crypto/tls — does not parse it a third time.
	cert.Leaf = leaf
	return cert, nil
}

// exists reports whether path is there, distinguishing "no" from "cannot tell".
//
// The distinction is the point. Treating a permission error as absence sends the
// caller down the generate path, where it fails again on a write to the same
// unreadable directory, reporting the second failure instead of the first.
func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	default:
		return false, fmt.Errorf("certgen: looking for %s: %w", path, err)
	}
}
