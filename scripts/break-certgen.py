"""Break campaign for internal/certgen/certgen.go.

Each entry below removes exactly one guard from the certificate generator and names
the tests that must fail as a result. Run from the repository root:

    python scripts/break-certgen.py

Four of these are the reason the campaign is run rather than reasoned about. Removing
ExtKeyUsage, IsCA, KeyUsageCertSign or BasicConstraintsValid leaves *every handshake
test in the package passing*, because crypto/x509 short-circuits verification when the
leaf is itself in the client's root pool:

    if opts.Roots.contains(c) {
            candidateChains = [][]*Certificate{{c}}
    } else {
            candidateChains, err = c.buildChains(...)
    }
                                  -- $GOROOT/src/crypto/x509/verify.go, ~line 597

A chain of one is never handed to CheckSignatureFrom, so the CA bits and the
self-signature are not consulted on that path at all. checkChainForKeyUsage still runs,
which is why ExtKeyUsage set to ClientAuth *is* caught by a handshake while ExtKeyUsage
removed entirely is not: an absent extended-usage list means "any use". Those four
guards are held by field assertions in TestSelfSetsTheUsagesAPeerChecks and by
TestSelfSignsItselfVerifiably, and by nothing else. A trust store that verifies the
imported certificate as a root — which is the reason it was imported — does consult
them, so they are not decoration.

Two guards have no break here, and both are named rather than quietly skipped:

  * The private key's 0o600 mode. TestWriteKeepsThePrivateKeyToItsOwner skips on
    Windows, where file modes are advisory and the ACL governs, so a break for it would
    report a hole on the machine this project is built on rather than a missing test.
    It fires on a POSIX filesystem; run the campaign there and add
    ("the key is world readable", '0o600', '0o644', [...]) to see it.

  * writeNew's f.Close error. On a local filesystem a close that fails after a
    successful write of two kilobytes needs a fault injector to reach, and this project
    has no business growing one for it.

Two breaks in the first run of this campaign went unnoticed, and both were holes in the
tests rather than in the code. They are worth recording because neither was visible by
reading:

  * Dropping serialNumber's error changed nothing observable through Self, because Self
    builds the template before generating the key, and a dead entropy source fails both
    — wrapping the same underlying error either way. TestSerialNumberReportsAFailedDraw
    now calls serialNumber directly.

  * Dropping `cert.Leaf = leaf` in load changed nothing either, because crypto/tls sets
    Leaf itself in X509KeyPair since Go 1.23. It does so only while the GODEBUG setting
    x509keypairleaf is on, which is off for any module declaring go 1.22 or older, so
    TestLoadOrCreateSetsTheParsedLeaf turns it off and asserts against this package
    rather than against the standard library. The comment in load claimed
    LoadX509KeyPair leaves Leaf unset; that claim was simply wrong, and the campaign is
    what found it.
"""

import breakage

SRC = "internal/certgen/certgen.go"
PKG = "./internal/certgen/"

BREAKS = [
    # ---------------------------------------------------------------- Config defaults
    (
        "a zero lifetime is taken literally instead of defaulted",
        """	if c.Lifetime <= 0 {""",
        """	if c.Lifetime < 0 {""",
        ["TestSelfFallsBackToTheDefaultLifetime"],
    ),
    (
        "the zero clock is used as a date in year one",
        """	if c.Now.IsZero() {
		return time.Now()
	}
	return c.Now""",
        """	return c.Now""",
        ["TestSelfUsesTheWallClockWhenNoneIsGiven"],
    ),

    # ------------------------------------------------------------------------- the key
    (
        "the key is generated on P-224",
        """	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)""",
        """	key, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)""",
        ["TestSelfUsesECDSAOnP256"],
    ),
    (
        "a key that could not be generated is reported as success",
        """		return PEM{}, fmt.Errorf("certgen: generating a P-256 key: %w", err)""",
        """		return PEM{}, nil""",
        ["TestSelfFailsWhenTheEntropySourceDiesPartWay"],
    ),
    (
        "an uncertifiable host is carried into CreateCertificate as a nil template",
        """	tmpl, err := template(cfg)
	if err != nil {
		return PEM{}, err
	}""",
        """	tmpl, _ := template(cfg)""",
        ["TestSelfRejectsAnEmptyHostList"],
    ),
    (
        "the key is marshalled as SEC 1 under a PKCS#8 block type",
        """	keyDER, err := x509.MarshalPKCS8PrivateKey(key)""",
        """	keyDER, err := x509.MarshalECPrivateKey(key)""",
        ["TestSelfEncodesThePrivateKeyAsPKCS8"],
    ),
    (
        "the key block is labelled EC PRIVATE KEY",
        """		Key: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),""",
        """		Key: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),""",
        ["TestSelfEncodesThePrivateKeyAsPKCS8"],
    ),

    # -------------------------------------------------------------------- the template
    (
        "validity starts exactly now, with no allowance for a wrong clock",
        """	notBefore := cfg.now().Add(-clockSkew)""",
        """	notBefore := cfg.now()""",
        ["TestSelfBackDatesValidityAgainstClockSkew"],
    ),
    (
        "the back-dated hour is taken out of the lifetime instead of added to it",
        """		NotAfter:  notBefore.Add(clockSkew + cfg.lifetime()),""",
        """		NotAfter:  notBefore.Add(cfg.lifetime()),""",
        [
            "TestSelfBackDatesValidityAgainstClockSkew",
            "TestSelfFallsBackToTheDefaultLifetime",
        ],
    ),
    (
        "the certificate cannot sign, so it cannot be trusted as the root it is",
        """		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,""",
        """		KeyUsage:    x509.KeyUsageDigitalSignature,""",
        ["TestSelfSetsTheUsagesAPeerChecks", "TestSelfSignsItselfVerifiably"],
    ),
    (
        "no extended key usage at all (every handshake still passes)",
        """		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},""",
        """		ExtKeyUsage: nil,""",
        ["TestSelfSetsTheUsagesAPeerChecks"],
    ),
    (
        "the extended key usage says client rather than server",
        """		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},""",
        """		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},""",
        [
            "TestSelfSetsTheUsagesAPeerChecks",
            "TestSelfNegotiatesH2WithARealTLSClient",
        ],
    ),
    (
        "basic constraints are left out, so the CA bit says nothing",
        """		BasicConstraintsValid: true,""",
        """		BasicConstraintsValid: false,""",
        ["TestSelfSetsTheUsagesAPeerChecks"],
    ),
    (
        "the certificate is not a CA, so importing it as a root does not help",
        """		IsCA:                  true,""",
        """		IsCA:                  false,""",
        ["TestSelfSetsTheUsagesAPeerChecks", "TestSelfSignsItselfVerifiably"],
    ),
    (
        "the subject has no common name for a viewer to title",
        """			CommonName: cfg.Hosts[0],""",
        """			CommonName: "",""",
        ["TestSelfKeepsTheFirstHostAsTheCommonName"],
    ),

    # ----------------------------------------------------------------------- the hosts
    (
        "an empty host list indexes past the end of it",
        """	if len(hosts) == 0 {
		return nil, nil, errors.New("certgen: Config.Hosts is empty; a certificate valid for no name " +
			"fails at the handshake rather than here, and says nothing useful when it does")
	}

""",
        """""",
        ["TestSelfRejectsAnEmptyHostList"],
    ),
    (
        "addresses are put in the DNS list, where no client looks for them",
        """		if ip := net.ParseIP(h); ip != nil {
			ips = append(ips, ip)
			continue
		}""",
        """		if net.ParseIP(h) != nil {
			dns = append(dns, h)
			continue
		}""",
        [
            "TestSelfSplitsNamesFromAddresses",
            "TestSelfIsAcceptedForEveryHostItNames",
            "TestLoadOrCreateProducesSomethingAClientAccepts",
        ],
    ),
    (
        "a host and port becomes a DNS name nothing will ask for",
        """		if i := strings.IndexAny(h, ":/%,@ \\t"); i >= 0 {
			return nil, nil, fmt.Errorf("certgen: %q is neither an IP address nor a DNS name "+
				"(it contains %q); a host and port belong to a listen address, not to a certificate",
				h, h[i])
		}""",
        """""",
        ["TestSelfRejectsAHostThatIsNeitherNameNorAddress"],
    ),
    (
        "an empty name among valid ones becomes an empty SAN",
        """		if h == "" {
			return nil, nil, errors.New("certgen: Config.Hosts contains an empty name")
		}
""",
        """""",
        ["TestSelfRejectsAnEmptyHostAmongValidOnes"],
    ),
    (
        "a name longer than DNS allows is certified anyway",
        """		if len(h) > 253 {
			return nil, nil, fmt.Errorf("certgen: the DNS name %q is %d octets, above the 253 a name "+
				"may have (RFC 1035 §2.3.4)", h[:32]+"...", len(h))
		}
""",
        """""",
        ["TestSelfRejectsAnOversizedName"],
    ),

    # --------------------------------------------------------------- serial numbers
    (
        "a serial of zero is issued as zero",
        """	return n.Add(n, big.NewInt(1)), nil""",
        """	return n, nil""",
        ["TestSerialNumberStaysPositiveWhenTheDrawIsZero"],
    ),
    (
        "the serial is drawn wider than the twenty octets RFC 5280 allows",
        """	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))""",
        """	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 200))""",
        ["TestSelfDrawsADistinctSerialEachTime"],
    ),
    (
        "a serial nobody could draw is reported as success",
        """		return nil, fmt.Errorf("certgen: drawing a serial number: %w", err)""",
        """		return nil, nil""",
        ["TestSerialNumberReportsAFailedDraw"],
    ),

    # -------------------------------------------------------------------- parsing
    (
        "a mismatched pair is reported as a usable certificate",
        """		return tls.Certificate{}, fmt.Errorf("certgen: the certificate and key do not form a pair: %w", err)""",
        """		return tls.Certificate{}, nil""",
        ["TestCertificateRejectsAMismatchedPair"],
    ),
    (
        "PEM that decodes to nothing is dereferenced",
        """	if block == nil {
		return nil, errors.New("certgen: no PEM block in the certificate")
	}
""",
        """""",
        ["TestLeafRejectsWhatIsNotACertificate"],
    ),
    (
        "any PEM block is parsed as though it were a certificate",
        """	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("certgen: the first PEM block is a %q, not a CERTIFICATE", block.Type)
	}
""",
        """""",
        ["TestLeafRejectsWhatIsNotACertificate"],
    ),
    (
        "the pool is returned empty, trusting nothing",
        """	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return pool, nil""",
        """	pool := x509.NewCertPool()
	_ = leaf
	return pool, nil""",
        [
            "TestSelfNegotiatesH2WithARealTLSClient",
            "TestSelfIsAcceptedForEveryHostItNames",
        ],
    ),

    # ------------------------------------------------------------------- the disk
    (
        "the directory is expected to exist rather than made",
        """	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return fmt.Errorf("certgen: making the directory for %s: %w", certPath, err)
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return fmt.Errorf("certgen: making the directory for %s: %w", keyPath, err)
	}""",
        """	if filepath.Dir(certPath) == "" || filepath.Dir(keyPath) == "" {
		return errors.New("certgen: a bare filename has no directory to make")
	}""",
        ["TestWriteCreatesTheDirectory"],
    ),
    (
        "the key is written first, so a failed write leaves a private key behind",
        """	if err := writeNew(certPath, p.Cert, 0o644); err != nil {
		return err
	}
	if err := writeNew(keyPath, p.Key, 0o600); err != nil {
		return err
	}""",
        """	if err := writeNew(keyPath, p.Key, 0o600); err != nil {
		return err
	}
	if err := writeNew(certPath, p.Cert, 0o644); err != nil {
		return err
	}""",
        ["TestWriteLeavesNoKeyWhenTheCertificateCannotBeWritten"],
    ),
    (
        "an existing key is truncated instead of refused",
        """	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)""",
        """	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)""",
        ["TestWriteRefusesToReplaceAnExistingFile", "TestWriteRaceLeavesOneWinner"],
    ),
    (
        "a path that cannot even be examined is treated as absent",
        """		return false, fmt.Errorf("certgen: looking for %s: %w", path, err)""",
        """		return false, nil""",
        ["TestLoadOrCreateReportsAPathItCannotEvenCheck"],
    ),

    # ------------------------------------------------------------- LoadOrCreate
    (
        "half a pair falls through to generation over the surviving half",
        """
	case haveCert != haveKey:
		present, missing := certPath, keyPath
		if haveKey {
			present, missing = keyPath, certPath
		}
		return tls.Certificate{}, "", fmt.Errorf("certgen: %s exists but %s does not; move or remove "+
			"%s if it is not wanted, because generating a new pair over half of one would replace a "+
			"key that may still be in use", present, missing, present)
	}""",
        """
	}""",
        ["TestLoadOrCreateRefusesHalfAPair"],
    ),
    (
        "a pair that cannot be read is reported as a loaded certificate",
        """		return tls.Certificate{}, fmt.Errorf("certgen: loading the pair at %s and %s: %w",
			certPath, keyPath, err)""",
        """		return tls.Certificate{}, nil""",
        ["TestLoadOrCreateReportsAPairItCannotRead"],
    ),
    (
        "an expired certificate on disk is served to every client that refuses it",
        """	case now.After(leaf.NotAfter):
		return tls.Certificate{}, fmt.Errorf("certgen: the certificate in %s expired on %s; remove it "+
			"and %s to have a new pair generated", certPath, leaf.NotAfter.Format(time.RFC3339), keyPath)
""",
        """""",
        ["TestLoadOrCreateRejectsAnExpiredCertificate"],
    ),
    (
        "a certificate dated in the future is served as though the clock agreed",
        """	case now.Before(leaf.NotBefore):
		return tls.Certificate{}, fmt.Errorf("certgen: the certificate in %s is not valid until %s, "+
			"which is in the future; either this machine's clock is wrong or the file is",
			certPath, leaf.NotBefore.Format(time.RFC3339))
""",
        """""",
        ["TestLoadOrCreateRejectsACertificateFromTheFuture"],
    ),
    (
        "validity is exclusive at both ends, refusing a pair on its first and last day",
        """	case now.Before(leaf.NotBefore):""",
        """	case !now.After(leaf.NotBefore):""",
        ["TestLoadOrCreateAcceptsAPairAtTheEdgesOfItsValidity"],
    ),
    (
        "the parsed leaf is dropped, so crypto/tls parses the DER a third time",
        """	cert.Leaf = leaf
""",
        """""",
        ["TestLoadOrCreateSetsTheParsedLeaf"],
    ),
    (
        "the log line does not say a certificate was generated",
        """	return cert, fmt.Sprintf("generated a certificate for %s and saved it to %s",
		strings.Join(cfg.Hosts, ", "), certPath), nil""",
        """	return cert, "the certificate is ready", nil""",
        ["TestLoadOrCreateGeneratesWhenNothingIsThere"],
    ),
    (
        "the log line does not say a certificate was loaded",
        """		return cert, fmt.Sprintf("loaded the certificate from %s", certPath), nil""",
        """		return cert, "the certificate is ready", nil""",
        ["TestLoadOrCreateReusesWhatItWrote"],
    ),
]

breakage.main(SRC, PKG, BREAKS)
