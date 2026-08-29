"""Break campaign for internal/server/tls.go.

Each entry below removes exactly one guard from the TLS and ALPN layer and names the
tests that must fail as a result. Run from the repository root:

    python scripts/break-tls.py

Three of these say something a green suite does not.

The first is the cipher-suite list. Putting a CBC suite into h2CipherSuites leaves
TestTLSConfigIsAcceptedByTheCheckItHasToPass passing, because checkTLSConfig validates
a configuration against h2CipherSuites itself: the check and the list agree by
construction, and they would agree just as happily on a list RFC 9113 Appendix A
forbids. What makes the list mean anything is the pair of catalogue tests that assert
it against crypto/tls's own suite metadata — one for correctness, that every suite is
an AEAD with an ephemeral key exchange, and one for completeness, that no AEAD suite Go
implements for TLS 1.2 has been left out. A short list is not a conformance bug; it is
a compatibility bug that reaches an operator as "the client could not connect".

The second is clearing the handshake deadline. Dropping that call fires the two tests
that assert it directly and *not one end-to-end test*, and that is not a hole in the
suite — it is the honest measure of the guard. Nothing in this server reads or writes
under that deadline: conn.setReadDeadline arms its own before the preface and before
every idle read, frameWriter.flush arms its own before every write, and crypto/tls arms
a five-second one of its own around the close_notify alert in Conn.Close. SetDeadline
sets both halves and each half is replaced before it is used. The call stays because
"no deadline outlives the operation that set it" should not depend on all three of
those, but the campaign records what it is worth rather than implying more.

The third is the pre-check in ServeTLS, and it changed a test rather than the code.
Both refusal tests used to call ServeTLS inline. Removing the check does not make an
inline call fail — it makes it *never return*, because ServeTLS goes on to wrap the
listener and serve, so the break reported as a hang: sixty seconds of nothing followed
by every goroutine in the binary. Both tests now call ServeTLS on a goroutine and wait
with awaitServe, so the break fails by name in two seconds.

Two more were holes on the first run, and both were in the tests. They are recorded
because they are the same mistake in two disguises — an assertion that is satisfied by
something other than the thing it was written to check.

  * Changing ALPNProtocol to "h2c" fired the constant's own test and left
    TestServeTLSServesHTTP2ToAClientThatNegotiatesIt passing, because that test dialled
    with clientTLSConfig(t, ALPNProtocol). Both ends read the same constant, so they
    agreed on "h2c" and negotiated it happily, while every real client in the world
    would have stopped connecting. It is the cipher-suite weakness above in another
    place: a test written against the implementation's own idea of the wire cannot
    notice the implementation changing its mind. Both end-to-end tests now dial with the
    literal "h2".

  * Discarding Handshake's error left TestServeTLSRefusesAClientThatOffersAProtocolNobodyShares
    passing. It asserted the log mentioned "TLS handshake" — which is also a substring
    of "the client completed a TLS handshake without negotiating ALPN", the line the
    connection logs one branch further down once a failed handshake is carried on from.
    The assertion matched prose it was not written for. It now asserts "TLS handshake: "
    with the colon, which appears only in handshake's own wrap of a handshake error.

Two guards here have no break, and both are named rather than quietly skipped:

  * var _ handshakeConn = (*tls.Conn)(nil) in the test file. It is the most important
    line in it — handshake decides whether a connection is TLS by asserting to that
    interface, so an interface *tls.Conn does not satisfy means every handshake is
    silently skipped and the server answers an unencrypted SETTINGS frame to a client
    waiting for a ServerHello. There is no break for it because it is a compile-time
    assertion: any edit that violates it reports "build", which this harness treats as
    a bug in the campaign rather than a tested guard. The runtime half of the same
    guard is broken below, as "a TLS connection is treated as cleartext".

  * crypto/tls's own ALPN behaviour. The http/1.1 fallback that
    TestServeTLSRefusesAnHTTP11ClientThatCryptoTLSLetIn depends on lives in
    negotiateALPN, in the standard library, and is not this file's to break. That test
    fails loudly with the reason if the fallback ever goes away.

One break is detected as a panic rather than as a named failure, and the harness
reports it separately rather than rounding it up: removing checkTLSConfig's nil check
announces itself as a nil dereference, and for a guard whose absence *is* a nil
dereference there is nothing better to expect.
"""

import breakage

SRC = "internal/server/tls.go"
PKG = "./internal/server/"

BREAKS = [
    # ------------------------------------------------------------ the ALPN identifier
    (
        "the ALPN identifier is h2c, which no TLS client offers",
        """const ALPNProtocol = "h2\"""",
        """const ALPNProtocol = "h2c\"""",
        [
            "TestALPNProtocolIsWhatRFC9113Registers",
            "TestServeTLSServesHTTP2ToAClientThatNegotiatesIt",
            "TestServeTLSNegotiatesH2OnTLS12",
        ],
    ),

    # --------------------------------------------------------------- the cipher suites
    (
        "a CBC suite RFC 9113 Appendix A forbids is offered (the check still passes)",
        """		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,""",
        """		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,""",
        [
            "TestH2CipherSuitesAreAllAEADWithEphemeralKeyExchange",
            "TestH2CipherSuitesOffersEveryAEADSuiteGoHasForTLS12",
        ],
    ),
    (
        "an AEAD suite Go implements is left out, so a client that has only it fails",
        """		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
""",
        """""",
        ["TestH2CipherSuitesOffersEveryAEADSuiteGoHasForTLS12"],
    ),
    (
        "the suite list is shared, so one caller's edit reaches every later config",
        """func h2CipherSuites() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}
}""",
        """var sharedH2CipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
}

func h2CipherSuites() []uint16 { return sharedH2CipherSuites }""",
        ["TestH2CipherSuitesCannotBeMutatedByACaller"],
    ),

    # -------------------------------------------------------------------- TLSConfig
    (
        "the version floor is inherited, so a GODEBUG setting can lower it to TLS 1.0",
        """		MinVersion:   tls.VersionTLS12,
""",
        """""",
        [
            "TestTLSConfigStatesTheVersionFloorRatherThanInheritingIt",
            "TestTLSConfigIsAcceptedByTheCheckItHasToPass",
        ],
    ),
    (
        "TLSConfig advertises no protocol, so no client can negotiate h2 at all",
        """		NextProtos:   []string{ALPNProtocol},
""",
        """""",
        [
            "TestTLSConfigStatesTheVersionFloorRatherThanInheritingIt",
            "TestServeTLSServesHTTP2ToAClientThatNegotiatesIt",
        ],
    ),
    (
        "the suites are left to Go's defaults, four of which RFC 9113 forbids",
        """		CipherSuites: h2CipherSuites(),
""",
        """""",
        [
            "TestTLSConfigIsAcceptedByTheCheckItHasToPass",
            "TestServeTLSServesHTTP2ToAClientThatNegotiatesIt",
        ],
    ),
    (
        "CurvePreferences is pinned, excluding the post-quantum exchange Go added",
        """		CipherSuites: h2CipherSuites(),""",
        """		CipherSuites:     h2CipherSuites(),
		CurvePreferences: []tls.CurveID{tls.CurveP256},""",
        ["TestTLSConfigStatesTheVersionFloorRatherThanInheritingIt"],
    ),

    # --------------------------------------------------------------------- ServeTLS
    (
        "the configuration is never checked, so every symptom is per-connection",
        """	if err := checkTLSConfig(cfg); err != nil {
		if cerr := l.Close(); cerr != nil {
			s.logf("closing a listener whose TLS configuration was refused: %v", cerr)
		}
		return err
	}
""",
        """""",
        [
            "TestServeTLSRefusesABadConfigWithoutAcceptingAnything",
            "TestServeTLSLogsAListenerItCannotClose",
        ],
    ),
    (
        "a refused configuration leaves the listening socket open",
        """		if cerr := l.Close(); cerr != nil {
			s.logf("closing a listener whose TLS configuration was refused: %v", cerr)
		}
		return err""",
        """		return err""",
        [
            "TestServeTLSRefusesABadConfigWithoutAcceptingAnything",
            "TestServeTLSLogsAListenerItCannotClose",
        ],
    ),
    (
        "a listener that cannot be closed is closed silently",
        """		if cerr := l.Close(); cerr != nil {
			s.logf("closing a listener whose TLS configuration was refused: %v", cerr)
		}""",
        """		l.Close()""",
        ["TestServeTLSLogsAListenerItCannotClose"],
    ),

    # ---------------------------------------------------------------- checkTLSConfig
    (
        "a nil configuration is dereferenced instead of named",
        """	if cfg == nil {
		return errors.New("server: ServeTLS requires a TLS configuration; TLSConfig returns one")
	}

""",
        """""",
        [
            "TestCheckTLSConfigRefusesWhatCannotServeH2",
            "TestServeTLSLogsAListenerItCannotClose",
        ],
    ),
    (
        "a configuration with no certificate is accepted, failing every handshake",
        """	if len(cfg.Certificates) == 0 && cfg.GetCertificate == nil {
		return errors.New("server: the TLS configuration has neither Certificates nor GetCertificate, " +
			"so every handshake will fail; see internal/certgen for generating a self-signed pair")
	}

""",
        """""",
        ["TestCheckTLSConfigRefusesWhatCannotServeH2"],
    ),
    (
        "GetCertificate alone is refused, rejecting a configuration that works",
        """	if len(cfg.Certificates) == 0 && cfg.GetCertificate == nil {""",
        """	if len(cfg.Certificates) == 0 {""",
        ["TestCheckTLSConfigAcceptsWhatCanServeH2"],
    ),
    (
        "an ALPN list without h2 is accepted",
        """	if !offersH2 {""",
        """	if false && !offersH2 {""",
        ["TestCheckTLSConfigRefusesWhatCannotServeH2"],
    ),
    (
        "one protocol alongside h2 is tolerated",
        """	if len(others) > 0 {""",
        """	if len(others) > 1 {""",
        ["TestCheckTLSConfigRefusesWhatCannotServeH2"],
    ),
    (
        "an unset floor is read as the TLS 1.2 default a GODEBUG can take away",
        """	if cfg.MinVersion < tls.VersionTLS12 {""",
        """	if cfg.MinVersion != 0 && cfg.MinVersion < tls.VersionTLS12 {""",
        ["TestCheckTLSConfigRefusesWhatCannotServeH2"],
    ),
    (
        "TLS 1.0 and 1.1 are admitted, against RFC 9113 section 9.2",
        """	if cfg.MinVersion < tls.VersionTLS12 {""",
        """	if cfg.MinVersion < tls.VersionTLS10 {""",
        ["TestCheckTLSConfigRefusesWhatCannotServeH2"],
    ),
    (
        "the suites stop being checked one version early, so TLS 1.2 goes unchecked",
        """	if cfg.MinVersion >= tls.VersionTLS13 {""",
        """	if cfg.MinVersion >= tls.VersionTLS12 {""",
        ["TestCheckTLSConfigRefusesWhatCannotServeH2"],
    ),
    (
        "TLS 1.2 with no suites named is accepted, which is Go's forbidden default",
        """	if cfg.CipherSuites == nil {
		return errors.New("server: the TLS configuration admits TLS 1.2 with no CipherSuites, which " +
			"takes Go's defaults — and those include four CBC suites that RFC 9113 §9.2.2 forbids " +
			"an HTTP/2 deployment from using; TLSConfig sets the AEAD-only list this needs")
	}
""",
        """""",
        ["TestCheckTLSConfigRefusesWhatCannotServeH2"],
    ),
    (
        "a forbidden suite passes the allowlist",
        """		if !containsUint16(allowed, id) {""",
        """		if false && !containsUint16(allowed, id) {""",
        ["TestCheckTLSConfigRefusesWhatCannotServeH2"],
    ),
    (
        "containsUint16 answers the opposite question",
        """		if v == needle {""",
        """		if v != needle {""",
        [
            "TestContainsUint16FindsAndMisses",
            "TestCheckTLSConfigRefusesWhatCannotServeH2",
        ],
    ),
    (
        "versionName has no word for the zero value, which is the commonest mistake",
        """	case 0:
		return "unset"
""",
        """""",
        [
            "TestVersionNameNamesEveryVersionItCanBeGiven",
            "TestCheckTLSConfigRefusesWhatCannotServeH2",
        ],
    ),

    # -------------------------------------------------------------------- handshake
    (
        "a TLS connection is treated as cleartext, so nothing is negotiated or checked",
        """	tc, ok := nc.(handshakeConn)
	if !ok {""",
        """	tc, ok := nc.(handshakeConn)
	if ok || true {""",
        [
            "TestHandshakeArmsAndClearsTheDeadlineAroundTheHandshake",
            "TestHandshakeRefusesWhatCannotSpeakHTTP2",
            "TestServeTLSRefusesAClientThatNegotiatesNoProtocol",
        ],
    ),
    (
        "the handshake has no deadline, so a silent peer holds its slot for ever",
        """	if err := tc.SetDeadline(time.Now().Add(s.timeouts.TLSHandshake)); err != nil {
		return fmt.Errorf("server: setting the TLS handshake deadline: %w", err)
	}
""",
        """""",
        [
            "TestHandshakeArmsAndClearsTheDeadlineAroundTheHandshake",
            "TestServeTLSDropsAClientThatNeverSendsAClientHello",
        ],
    ),
    (
        "a socket that will not take the deadline is handshaked without one",
        """	if err := tc.SetDeadline(time.Now().Add(s.timeouts.TLSHandshake)); err != nil {
		return fmt.Errorf("server: setting the TLS handshake deadline: %w", err)
	}""",
        """	tc.SetDeadline(time.Now().Add(s.timeouts.TLSHandshake))""",
        ["TestHandshakeRefusesWhatCannotSpeakHTTP2"],
    ),
    (
        "a failed handshake is carried on from as though it had succeeded",
        """	if err := tc.Handshake(); err != nil {
		return fmt.Errorf("server: TLS handshake: %w", err)
	}""",
        """	tc.Handshake()""",
        [
            "TestHandshakeRefusesWhatCannotSpeakHTTP2",
            "TestHandshakeDoesNotClearTheDeadlineOfAFailedHandshake",
            "TestServeTLSRefusesAClientThatOffersAProtocolNobodyShares",
        ],
    ),
    (
        "the handshake deadline is left in force (no end-to-end test notices)",
        """	if err := tc.SetDeadline(time.Time{}); err != nil {
		return fmt.Errorf("server: clearing the TLS handshake deadline: %w", err)
	}
""",
        """""",
        [
            "TestHandshakeArmsAndClearsTheDeadlineAroundTheHandshake",
            "TestHandshakeRefusesWhatCannotSpeakHTTP2",
        ],
    ),
    (
        "a socket that will not give the deadline back is served anyway",
        """	if err := tc.SetDeadline(time.Time{}); err != nil {
		return fmt.Errorf("server: clearing the TLS handshake deadline: %w", err)
	}""",
        """	tc.SetDeadline(time.Time{})""",
        ["TestHandshakeRefusesWhatCannotSpeakHTTP2"],
    ),
    (
        "a connection that negotiated no protocol is served HTTP/2 regardless",
        """		return fmt.Errorf("server: the client completed a TLS handshake without negotiating ALPN; %q "+
			"over TLS is negotiated by ALPN and by nothing else (RFC 9113 §3.2), so this connection "+
			"has no protocol and is being closed rather than guessed at", ALPNProtocol)""",
        """		return nil""",
        [
            "TestHandshakeRefusesWhatCannotSpeakHTTP2",
            "TestServeTLSRefusesAClientThatNegotiatesNoProtocol",
            "TestServeTLSRefusesAnHTTP11ClientThatCryptoTLSLetIn",
        ],
    ),
    (
        "a protocol this server does not implement is served as though it were h2",
        """		return fmt.Errorf("server: the client negotiated %q rather than %q, and this server speaks "+
			"only HTTP/2", p, ALPNProtocol)""",
        """		return nil""",
        ["TestHandshakeRefusesWhatCannotSpeakHTTP2"],
    ),
]

breakage.main(SRC, PKG, BREAKS)
