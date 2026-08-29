package server

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"
)

// ALPNProtocol is the ALPN identifier for HTTP/2 over TLS (RFC 9113 §3.2).
//
// It is the entirety of the protocol negotiation. Over TLS there is no upgrade
// exchange and no version header: the client offers "h2" in its ClientHello, the
// server selects it, and both ends begin with the connection preface. A connection
// on which it was not selected is not an HTTP/2 connection, whatever is sent over it
// afterwards — which is why the handshake below refuses one rather than reading from
// it and reporting a malformed preface.
const ALPNProtocol = "h2"

// h2CipherSuites are the TLS 1.2 cipher suites this server offers.
//
// The list is not a hardening preference; it is a protocol requirement that Go's
// defaults do not meet. RFC 9113 §9.2.2 forbids an HTTP/2 deployment over TLS 1.2
// from using any suite in Appendix A, which is every suite that is not an AEAD, and
// a peer that sees one MAY answer with INADEQUATE_SECURITY. Go's default TLS 1.2 set
// drops RC4, 3DES and RSA key exchange, and still contains four suites that would
// violate that rule — 0xC009, 0xC00A, 0xC013 and 0xC014, AES in CBC mode with ECDHE
// — because they are ephemeral and are neither 3DES nor RSA key exchange. So a Go
// server that leaves Config.CipherSuites unset and admits TLS 1.2 is offering
// blacklisted suites, and it is offering them silently.
//
// What is left is every AEAD suite Go implements for TLS 1.2, all six of them with
// ECDHE, which also satisfies §9.2.1's requirement of an ephemeral key exchange.
//
// This says nothing about TLS 1.3: Go ignores Config.CipherSuites there, and all
// three of its TLS 1.3 suites are AEADs, so there is nothing to exclude.
func h2CipherSuites() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}
}

// TLSConfig returns the TLS policy this server serves HTTP/2 under, holding cert.
//
// Three of §9.2.1's requirements need no field here and are worth saying so, because
// a reader looking for them will not find them: crypto/tls implements no TLS-level
// compression at all, its server refuses renegotiation outright rather than by
// configuration, and it offers no finite-field DHE, so the 2048-bit floor on that
// exchange cannot be undershot. The 224-bit floor on ECDHE is met by every curve it
// will negotiate.
//
// CurvePreferences is deliberately left unset. Naming curves here would pin the key
// exchange to whatever was current when this was written and quietly exclude
// X25519MLKEM768, which Go 1.24 added to the defaults and enables by default — a
// post-quantum exchange this server would then not offer, for no reason but a line
// of configuration that looked like diligence.
func TLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{ALPNProtocol},

		// Stated rather than left to the default, which is TLS 1.2 for a server
		// unless GODEBUG contains tls10server=1, in which case it is TLS 1.0. §9.2
		// requires 1.2, and a floor that an environment variable can lower is not a
		// floor this server can claim.
		MinVersion:   tls.VersionTLS12,
		CipherSuites: h2CipherSuites(),
	}
}

// ServeTLS accepts connections on l, negotiates TLS on each, and serves HTTP/2 to
// the ones that asked for it. It behaves as Serve does otherwise, and closes l on
// the way out — including when cfg is refused, so that a caller has one rule to
// remember rather than two.
//
// cfg is checked before anything is accepted. Every one of those checks catches a
// configuration whose symptom would otherwise be per-connection: a missing
// certificate fails every handshake, an ALPN list without "h2" fails every
// negotiation, and a TLS 1.2 floor with the wrong cipher suites fails nothing at all
// and is a conformance violation a packet capture has to find. Once per startup is
// where an operator can act on them.
func (s *Server) ServeTLS(l net.Listener, cfg *tls.Config) error {
	if err := checkTLSConfig(cfg); err != nil {
		if cerr := l.Close(); cerr != nil {
			s.logf("closing a listener whose TLS configuration was refused: %v", cerr)
		}
		return err
	}
	return s.Serve(tls.NewListener(l, cfg))
}

// checkTLSConfig reports what is wrong with cfg for serving HTTP/2, if anything.
func checkTLSConfig(cfg *tls.Config) error {
	if cfg == nil {
		return errors.New("server: ServeTLS requires a TLS configuration; TLSConfig returns one")
	}

	if len(cfg.Certificates) == 0 && cfg.GetCertificate == nil {
		return errors.New("server: the TLS configuration has neither Certificates nor GetCertificate, " +
			"so every handshake will fail; see internal/certgen for generating a self-signed pair")
	}

	// The ALPN list has to contain "h2" and nothing else. Containing it is what lets a
	// client negotiate at all. Containing nothing else is because this server speaks
	// one protocol: advertising a second one means a client may select it, and what it
	// then gets is a connection this server closes on the first frame it cannot read.
	var offersH2 bool
	var others []string
	for _, p := range cfg.NextProtos {
		if p == ALPNProtocol {
			offersH2 = true
			continue
		}
		others = append(others, p)
	}
	if !offersH2 {
		return fmt.Errorf("server: the TLS configuration does not advertise %q in NextProtos, so no "+
			"client can negotiate HTTP/2 with it (RFC 9113 §3.2)", ALPNProtocol)
	}
	if len(others) > 0 {
		return fmt.Errorf("server: the TLS configuration advertises %q alongside %q, and this server "+
			"speaks only HTTP/2; a client selecting one of the others gets a connection that is closed "+
			"on its first request", others, ALPNProtocol)
	}

	// §9.2 requires TLS 1.2 or better, and an unset MinVersion does not state it: the
	// server-side default is TLS 1.2 only while GODEBUG does not say tls10server=1.
	if cfg.MinVersion < tls.VersionTLS12 {
		return fmt.Errorf("server: the TLS configuration's MinVersion is %s, and RFC 9113 §9.2 requires "+
			"TLS 1.2 or higher; set it explicitly, because zero leaves the floor to a GODEBUG setting",
			versionName(cfg.MinVersion))
	}

	// Cipher suites only matter while TLS 1.2 is reachable. Above it the field is
	// ignored by crypto/tls and every suite it will negotiate is an AEAD.
	if cfg.MinVersion >= tls.VersionTLS13 {
		return nil
	}
	if cfg.CipherSuites == nil {
		return errors.New("server: the TLS configuration admits TLS 1.2 with no CipherSuites, which " +
			"takes Go's defaults — and those include four CBC suites that RFC 9113 §9.2.2 forbids " +
			"an HTTP/2 deployment from using; TLSConfig sets the AEAD-only list this needs")
	}
	allowed := h2CipherSuites()
	for _, id := range cfg.CipherSuites {
		if !containsUint16(allowed, id) {
			return fmt.Errorf("server: the TLS configuration offers cipher suite %#04x, which is not an "+
				"AEAD with an ephemeral key exchange and is therefore forbidden to an HTTP/2 deployment "+
				"over TLS 1.2 (RFC 9113 §9.2.2, Appendix A)", id)
		}
	}
	return nil
}

func containsUint16(haystack []uint16, needle uint16) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

// versionName names a TLS version for an error message, including the zero value,
// which is the one a caller is most likely to have arrived here with.
func versionName(v uint16) string {
	switch v {
	case 0:
		return "unset"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("%#04x", v)
	}
}

// handshakeConn is the part of *tls.Conn this server drives.
//
// An interface rather than the concrete type so that the tests can provoke a
// handshake that fails, one that hangs, and one that succeeds while negotiating the
// wrong protocol — the last of which a real client cannot be made to do against a
// configuration checkTLSConfig has approved.
type handshakeConn interface {
	Handshake() error
	ConnectionState() tls.ConnectionState
	SetDeadline(t time.Time) error
}

// handshake completes TLS on nc, if nc is a TLS connection at all, and refuses one
// that did not negotiate HTTP/2.
//
// It runs on the connection's own goroutine rather than in the accept loop, and that
// is the whole reason this is not left to tls.NewListener's lazy handshake. A
// handshake performed inside Accept would let one client that opens a socket and
// sends nothing hold up every other client's accept. A handshake left until the
// first Read happens inside conn.Serve, under the preface deadline, with no
// opportunity to check ALPN and no separate timeout — so a peer that never sends a
// ClientHello would be charged the preface's patience instead of the handshake's, and
// a peer that negotiated no protocol at all would be answered with SETTINGS.
//
// The connection's slot is already taken by the time this runs, which is deliberate:
// a handshake in progress is a connection consuming this process's resources, and
// MaxConns is the only thing that bounds a flood of them.
func (s *Server) handshake(nc net.Conn) error {
	tc, ok := nc.(handshakeConn)
	if !ok {
		// Cleartext, and there is nothing to negotiate. §3.4's prior-knowledge h2c: the
		// preface is the only announcement there is, and conn.Serve is about to require
		// it.
		return nil
	}

	if err := tc.SetDeadline(time.Now().Add(s.timeouts.TLSHandshake)); err != nil {
		return fmt.Errorf("server: setting the TLS handshake deadline: %w", err)
	}
	if err := tc.Handshake(); err != nil {
		return fmt.Errorf("server: TLS handshake: %w", err)
	}
	// Cleared rather than left to expire — and worth being exact about what that is
	// worth, because it is less than it looks.
	//
	// Nothing in this server currently reads or writes under this deadline. Every read
	// arms its own first (conn.setReadDeadline: preface, then idle), every write arms
	// its own (frameWriter.flush), and crypto/tls arms a five-second one of its own
	// around the close_notify alert in Conn.Close. SetDeadline sets both halves and each
	// half is replaced before it is used, so a handshake deadline left in force has
	// nothing left to expire against. The break campaign records this rather than hiding
	// it: dropping this call fires the tests that assert it directly and not one
	// end-to-end test.
	//
	// It stays because the invariant is "no deadline outlives the operation that set
	// it", and the alternative is a connection whose correctness rests on all three of
	// those arming theirs — none of which is this function's to guarantee, and any of
	// which is one refactor from not being true. The cost is a syscall per connection.
	if err := tc.SetDeadline(time.Time{}); err != nil {
		return fmt.Errorf("server: clearing the TLS handshake deadline: %w", err)
	}

	switch p := tc.ConnectionState().NegotiatedProtocol; p {
	case ALPNProtocol:
		return nil

	case "":
		// Not the exotic case it looks like. Two ordinary clients arrive here, and the
		// second is the reason this branch is load-bearing rather than defensive.
		//
		// The first sends no ALPN extension at all, and crypto/tls reports no protocol.
		// The second offers "http/1.1" and nothing else — a browser that has fallen back,
		// or curl without --http2 — and crypto/tls *accepts* it: negotiateALPN has an
		// explicit special case that treats an http/1.1-only client against an h2-only
		// server as though it had not offered ALPN, rather than sending the
		// no_application_protocol alert (Go issue 46310, because servers configured with
		// only "h2" had been accepting those clients before the check existed).
		//
		// So a Go server cannot rely on the TLS layer to keep HTTP/1.1 clients off an
		// h2-only port. Without this branch, the answer to "GET / HTTP/1.1" would be a
		// SETTINGS frame.
		return fmt.Errorf("server: the client completed a TLS handshake without negotiating ALPN; %q "+
			"over TLS is negotiated by ALPN and by nothing else (RFC 9113 §3.2), so this connection "+
			"has no protocol and is being closed rather than guessed at", ALPNProtocol)

	default:
		// Unreachable through a real client against a configuration checkTLSConfig has
		// approved: crypto/tls only ever selects a string from the server's own list, and
		// that list is required to be exactly ["h2"]. It is here because the requirement
		// is a check in another function, and a switch whose default is a silent success
		// would turn a change there into this server speaking a protocol it does not
		// implement.
		return fmt.Errorf("server: the client negotiated %q rather than %q, and this server speaks "+
			"only HTTP/2", p, ALPNProtocol)
	}
}
