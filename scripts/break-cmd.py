"""Deliberately break cmd/zdh, one guard at a time, and report which tests notice.

Each entry below removes exactly one guard and names the tests that must fail as a
result. See breakage.py for the harness and for what the five outcomes mean.

This is the only campaign that targets a command rather than a package, and the
breaks it can make are of two kinds. The first is ordinary: a bound checked, a
list deduplicated, a socket closed. The second is what makes this file worth
having — the wiring itself. Every package under internal/ declares the interfaces
it needs instead of importing what satisfies them, so no unit test anywhere can
observe two of them connected wrongly. newConn is where that connecting happens,
and the breaks below take it apart in the three ways it can plausibly be got
wrong: one codec where there must be two, a cycle left unclosed, and a teardown
that reaches half of what it must reach.

Run from the repository root. Restores the files on the way out, including on error.
"""

import breakage

SRC = ["cmd/zdh/main.go", "cmd/zdh/serve.go"]
PKG = "./cmd/zdh/"

# (name, old, new, tests that must fail)
BREAKS = [
    # --- the wiring ------------------------------------------------------------
    (
        "newConn: one HPACK codec for both directions, so the two dynamic tables become one",
        """		enc := response.NewEncoder(hpack.New(), w)
		sender := flow.NewSender()

		reqs := exchange.New(exchange.Config{
			Handler: h,
			Encoder: enc,
			Credit:  sender,
			Log:     errLog,
		})

		// MaxConcurrent is left at its default on purpose. §5.1.2 lets a peer
		// open exactly as many streams as it was promised, so the number the
		// table enforces has to be the number the connection advertised — and
		// both default to limits.MaxConcurrentStreams, so naming it here would
		// add a third place for the same value to be wrong in.
		tab := stream.New(stream.Config{
			Codec:    hpack.New(),""",
        """		shared := hpack.New()
		enc := response.NewEncoder(shared, w)
		sender := flow.NewSender()

		reqs := exchange.New(exchange.Config{
			Handler: h,
			Encoder: enc,
			Credit:  sender,
			Log:     errLog,
		})

		tab := stream.New(stream.Config{
			Codec:    shared,""",
        # Only the sequential test. TestServeConcurrentStreams opens every stream
        # before reading anything, so the server decodes all of them before a
        # handler has encoded a response and the two tables never diverge.
        ["TestServeOneConnectionManyRequests"],
    ),
    (
        "newConn: the cycle left open, so a finished response never reports its stream",
        """		reqs.Attach(tab)
""",
        """""",
        ["TestServeOneConnectionManyRequests", "TestServeConcurrentStreams"],
    ),
    (
        "streamHandler.Close: the request layer left running, so a parked upload is never told",
        """	h.Table.Close(err)
	h.reqs.Close(err)""",
        """	h.Table.Close(err)""",
        ["TestPeerHangingUpMidUploadWakesTheHandler"],
    ),
    (
        "newConn: no handler for the response writer, so nothing answers a request",
        """		reqs := exchange.New(exchange.Config{
			Handler: h,""",
        """		reqs := exchange.New(exchange.Config{
			Handler: nil,""",
        ["TestServeOneConnectionManyRequests"],
    ),

    # --- shutdown --------------------------------------------------------------
    (
        "serve: shutdown only on an interrupt, so a failed accept loop leaves the rest running",
        """	shutErr := srv.Shutdown()""",
        """	var shutErr error""",
        # Not TestServeShutdownSendsGoAway: that test calls Shutdown itself, so it
        # would pass with this line gone. Only a test that runs serve can see it.
        ["TestServeAnswersOnThePortItPrints"],
    ),

    # --- the listeners ---------------------------------------------------------
    (
        "bind: a failure leaves every socket it already opened held",
        """		for _, b := range bs {
			b.l.Close()
		}
		return nil, err""",
        """		return nil, err""",
        ["TestBindClosesWhatItOpenedOnFailure"],
    ),
    (
        "bind: the TLS listener carries no configuration, so an https URL serves cleartext",
        """		bs = append(bs, binding{
			l:      l,
			tlsCfg: tlsCfg,""",
        """		bs = append(bs, binding{
			l:      l,
			tlsCfg: nil,""",
        ["TestBindOpensBothListeners"],
    ),
    (
        "bind: the cleartext listener carries a TLS configuration, so h2c expects a handshake",
        """		bs = append(bs, binding{
			l:    l,
			url:  "http://" + browserHost(l.Addr()) + "/",""",
        """		bs = append(bs, binding{
			l:      l,
			tlsCfg: tlsCfg,
			url:    "http://" + browserHost(l.Addr()) + "/",""",
        ["TestBindOpensBothListeners"],
    ),
    (
        "browserHost: a wildcard printed as itself, so the startup line is not a URL",
        """	if wildcard(host) {
		host = "localhost"
	}""",
        """""",
        # Not TestBindOpensBothListeners: it binds 127.0.0.1, which is not a
        # wildcard, so browserHost never reaches this branch there.
        ["TestBrowserHost"],
    ),
    (
        "browserHost: the port dropped, so the URL points at 443",
        """	host, port, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	if wildcard(host) {
		host = "localhost"
	}
	return net.JoinHostPort(host, port)""",
        """	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	if wildcard(host) {
		host = "localhost"
	}
	return host""",
        ["TestBrowserHost", "TestBindOpensBothListeners"],
    ),

    # --- the certificate's names ----------------------------------------------
    (
        "certHosts: only the name, so https://127.0.0.1 fails on a certificate that has it",
        """	hosts := []string{"localhost", "127.0.0.1", "::1"}""",
        """	hosts := []string{"localhost"}""",
        ["TestCertHosts"],
    ),
    (
        "certHosts: no deduplication, so -host localhost repeats a SAN",
        """	out := make([]string, 0, len(hosts))
	seen := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		if !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	return out""",
        """	return hosts""",
        ["TestCertHosts"],
    ),
    (
        "certHosts: a wildcard added as a name, so the certificate carries \"0.0.0.0\"",
        """	if host, _, err := net.SplitHostPort(addr); err == nil && !wildcard(host) {""",
        """	if host, _, err := net.SplitHostPort(addr); err == nil {""",
        ["TestCertHosts"],
    ),
    (
        "certHosts: an unsplittable address contributed whole, so the SAN is \"not-an-address\"",
        """	if host, _, err := net.SplitHostPort(addr); err == nil && !wildcard(host) {
		hosts = append(hosts, host)
	}""",
        """	if host, _, err := net.SplitHostPort(addr); err == nil && !wildcard(host) {
		hosts = append(hosts, host)
	} else {
		hosts = append(hosts, addr)
	}""",
        ["TestCertHosts"],
    ),
    (
        "certHosts: -host untrimmed, so a list written with spaces produces SANs with spaces",
        """		if h = strings.TrimSpace(h); h != "" {""",
        """		if h != "" {""",
        ["TestCertHosts"],
    ),
    (
        "certHosts: an empty -host entry kept, so a trailing comma produces an empty SAN",
        """		if h = strings.TrimSpace(h); h != "" {
			hosts = append(hosts, h)
		}""",
        """		hosts = append(hosts, strings.TrimSpace(h))""",
        ["TestCertHosts"],
    ),
    (
        "wildcard: the empty host not recognised, so :8443 puts \"\" in the certificate",
        """	return host == "" || host == "0.0.0.0" ||""",
        """	return host == "0.0.0.0" ||""",
        ["TestCertHosts", "TestBrowserHost"],
    ),

    # --- the command line ------------------------------------------------------
    (
        "parse: a stray argument ignored, so `zdh serve` serves the wrong directory silently",
        """	if fs.NArg() > 0 {""",
        """	if false {""",
        ["TestParseRejectsPositionalArgument"],
    ),
    (
        "parse: the stray argument not named, so the complaint cannot be acted on",
        """		fmt.Fprintf(errOut, "zdh: unexpected argument %q\\n", fs.Arg(0))""",
        """		fmt.Fprintln(errOut, "zdh: unexpected argument")""",
        ["TestParseRejectsPositionalArgument"],
    ),
    (
        "parse: no usage after the complaint, so the reader is not told what is accepted",
        """		fs.Usage()
		return nil, errUsage""",
        """		return nil, errUsage""",
        ["TestParseRejectsPositionalArgument"],
    ),
    (
        "run: the flag package's diagnostics sent to stdout, so a redirected startup log collects the complaints",
        # At the call site rather than inside parse, where the only way to reach
        # stdout is os.Stdout — and a break that writes to the real process stdout
        # is one no test with a buffer can see.
        """	o, err := parse(args, errOut)""",
        """	o, err := parse(args, out)""",
        ["TestParseWritesNothingToStdout"],
    ),
    (
        "run: no listeners is not a usage error, so the exit status says nothing went wrong",
        """		fmt.Fprintln(errOut, `zdh: -addr and -h2c are both empty, so there is nothing to listen on`)
		return errUsage""",
        """		return nil""",
        ["TestRunRejectsNoListeners"],
    ),
    (
        "run: the complaint does not name the flags, so nobody knows which to set",
        """		fmt.Fprintln(errOut, `zdh: -addr and -h2c are both empty, so there is nothing to listen on`)""",
        """		fmt.Fprintln(errOut, "zdh: nothing to listen on")""",
        ["TestRunRejectsNoListeners"],
    ),
    (
        "run: -version printed to stderr, so `zdh -version > build.txt` collects nothing",
        # Not the short-circuit itself, tempting as that is: with it gone, -version
        # falls through and binds :8443, and the campaign would record a hang rather
        # than the failure. A break has to fail fast to be worth making.
        """		fmt.Fprint(out, buildReport())""",
        """		fmt.Fprint(errOut, buildReport())""",
        ["TestRunVersion"],
    ),
    (
        "parse: -dir defaults to the wrong directory",
        """	fs.StringVar(&o.dir, "dir", ".", "directory to serve")""",
        """	fs.StringVar(&o.dir, "dir", "public", "directory to serve")""",
        ["TestParseDefaults"],
    ),
    (
        "parse: -addr defaults to a port nothing expects",
        """	fs.StringVar(&o.tlsAddr, "addr", ":8443",""",
        """	fs.StringVar(&o.tlsAddr, "addr", ":443",""",
        ["TestParseDefaults"],
    ),
    (
        "parse: -max-conns defaults to the stream bound rather than the connection one",
        """	fs.IntVar(&o.maxConns, "max-conns", limits.MaxConns,""",
        """	fs.IntVar(&o.maxConns, "max-conns", limits.MaxConcurrentStreams,""",
        ["TestParseDefaults"],
    ),
    (
        "parse: -max-conns not read, so the bound cannot be lowered",
        """	fs.IntVar(&o.maxConns, "max-conns", limits.MaxConns, "connections served at once")""",
        """	o.maxConns = limits.MaxConns""",
        ["TestParseFlags"],
    ),
    (
        "buildReport: the dependency count taken from the module graph's length rather than the binary's",
        """	s += fmt.Sprintf("dependencies: %d\\n", len(bi.Deps))""",
        """	s += fmt.Sprintf("dependencies: %d\\n", len(bi.Settings))""",
        ["TestBuildReportZeroDependencies"],
    ),
]

breakage.main(SRC, PKG, BREAKS)
