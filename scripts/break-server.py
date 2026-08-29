"""Deliberately break internal/server/server.go, one guard at a time, and report
which tests notice.

Each entry below removes exactly one guard and names the tests that must fail as a
result. See breakage.py for the harness and for what the five outcomes mean.

Three of these are the reason the file is worth running rather than reading. Taking
the connection slot after the accept instead of before it leaves a server that still
honours its bound and still spends a descriptor and a handshake telling one peer per
excess connection that it has no room. Dropping `delay = 0` after a successful accept
leaves a server that recovers from a rough patch on paper and carries a one-second
pause before every connection for the rest of the week. And forgetting to stop the
writer goroutine after a contained panic leaks two goroutines per panic, which a green
suite reports as a server that survived.

Two guards in server.go have no break here, and both are honest gaps rather than
oversights:

  acquire's check of stopping() before its select. With both cases of that select
  ready, Go chooses at random, so the guard changes a coin toss into a certainty.
  A campaign entry for it would be a test of the scheduler.

  removeListener's close of the listener. It covers an interleaving — Serve's
  deferred removal winning the mutex before Shutdown's snapshot takes it, leaving
  the listener in nobody's set — which is reachable but not schedulable from a
  test. The close is also what keeps every other path out of Serve safe as more
  are added.

One break is worth reading for what it measured rather than for what it caught.
Deleting runConn's whole handshake step leaves a well-behaved client served
correctly: TestServeTLSServesHTTP2ToAClientThatNegotiatesIt passes. That is not a
hole in the suite, it is the truth about the guard. ServeTLS hands runConn a
*tls.Conn from tls.NewListener, and crypto/tls handshakes lazily on the first Read
— which arrives a moment later inside conn.Serve — negotiating h2 from the server's
own NextProtos with no help from this package. A good client cannot tell the
difference, and the happy-path test was named on that break in the belief that it
could. It was wrong, and the break now names only the two tests that do fail.

What the explicit handshake is worth is therefore entirely in the connections that
are not well-behaved, and those are exactly what the other two tests hold: a client
that negotiates no protocol is refused rather than answered with SETTINGS, and a
client that never sends a ClientHello is timed out on Timeouts.TLSHandshake instead
of sitting on the preface clock. Both fire. Written down because the same reasoning
would otherwise recur as "the eager handshake buys nothing, so move it back into
Serve" — it buys nothing on the path that works and everything on the two that
don't.

Run from the repository root. Restores the file on the way out, including on error.
"""

import breakage

SRC = "internal/server/server.go"
PKG = "./internal/server/"

# (name, old, new, tests that must fail)
BREAKS = [
    # --- construction --------------------------------------------------------
    (
        "New: a nil handler factory is accepted and panics later, on the first connection",
        """	if newHandler == nil {
		panic("server: New requires a handler factory")
	}
""",
        "",
        ["TestServerNewRequiresAHandlerFactory"],
    ),
    (
        "New: an unset MaxConns is taken literally, so the server serves nothing at all",
        """	max := cfg.MaxConns
	if max <= 0 {
		max = limits.MaxConns
	}
""",
        """	max := cfg.MaxConns
""",
        ["TestServerFillsUnsetConfig"],
    ),
    (
        "New: unset timeouts keep their zero values, so every deadline is already past",
        """		timeouts:   cfg.Timeouts.WithDefaults(),""",
        """		timeouts:   cfg.Timeouts,""",
        ["TestServerFillsUnsetConfig"],
    ),
    (
        "New: the connection bound is four times what the caller asked for",
        """		slots:      make(chan struct{}, max),""",
        """		slots:      make(chan struct{}, max*4),""",
        [
            "TestServerBoundsConcurrentConnections",
            "TestServerBoundIsSharedAcrossListeners",
        ],
    ),

    # --- the accept loop -----------------------------------------------------
    (
        "Serve: a listener registered after the shutdown is left open for ever",
        """		if err := ol.Close(); err != nil {
			s.logf("closing a listener the server was too late to accept on: %v", err)
		}
		return ErrServerClosed""",
        """		return ErrServerClosed""",
        ["TestServerServeAfterShutdownDoesNotAccept"],
    ),
    (
        "Serve: a listener that stopped stays in the set the shutdown walks",
        """	defer s.removeListener(ol)
""",
        "",
        ["TestServerForgetsAListenerThatStopped"],
    ),
    (
        "Serve: the connection slot is taken after the accept, not before it",
        """		if !s.acquire() {
			return ErrServerClosed
		}

		nc, err := ol.Accept()""",
        """		nc, err := ol.Accept()
		if err == nil && !s.acquire() {
			return ErrServerClosed
		}""",
        [
            "TestServerBoundsConcurrentConnections",
            "TestServerBoundIsSharedAcrossListeners",
        ],
    ),
    (
        "Serve: a requested stop is reported as the listener having broken",
        """			case s.stopping():
				return ErrServerClosed
			case errors.Is(err, net.ErrClosed):""",
        """			case errors.Is(err, net.ErrClosed):""",
        [
            "TestServerShutdownSendsGoAwayToEveryConnection",
            "TestServerShutdownClosesEachListenerOnce",
        ],
    ),
    (
        "Serve: a listener closed behind the server's back is retried for ever",
        """			case errors.Is(err, net.ErrClosed):
				// Closed by someone other than Shutdown. Nothing will ever be
				// accepted on it again, so the retry below would be a spin, and the
				// caller is owed the reason rather than a clean ending.
				return fmt.Errorf("server: accept on a closed listener: %w", err)
			}
""",
        """			}
""",
        [
            "TestServerStopsAcceptingOnAClosedListener",
            "TestServerForgetsAListenerThatStopped",
        ],
    ),
    (
        "Serve: a failing accept is retried without pausing, spinning a core",
        """			if !s.pause(delay) {
				return ErrServerClosed
			}
			continue""",
        """			continue""",
        ["TestServerBacksOffOnAnAcceptFailure"],
    ),
    (
        "Serve: the pause after a failed accept is not reset by a successful one",
        """		delay = 0
		s.serveConn(nc)""",
        """		s.serveConn(nc)""",
        ["TestServerAcceptDelayResetsAfterASuccess"],
    ),
    (
        "pause: an accept backoff cannot be interrupted, so a shutdown waits it out",
        """	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-s.quit:
		return false
	}""",
        """	time.Sleep(d)
	return true""",
        ["TestServerAcceptBackoffIsInterruptedByShutdown"],
    ),
    (
        "nextAcceptDelay: the pause doubles without a ceiling",
        """	case d >= maxAcceptDelay/2:
		return maxAcceptDelay
""",
        "",
        ["TestNextAcceptDelay"],
    ),
    (
        "nextAcceptDelay: a negative delay doubles into a longer negative one",
        """	case d <= 0:""",
        """	case d == 0:""",
        ["TestNextAcceptDelay"],
    ),

    # --- one connection ------------------------------------------------------
    (
        "serveConn: a connection accepted after the shutdown is served as if nothing happened",
        """	tracked := s.track(c)
	if !tracked {
		// The server stopped between the accept and here, so this connection is in
		// nobody's set and the shutdown has already been past. It is still served —
		// saying goodbye costs one frame — but it is told to stop immediately, and
		// nothing waits for it.
		c.Shutdown()
	}
""",
        """	tracked := s.track(c)
""",
        ["TestServerShutdownReachesAConnectionAcceptedInTheRace"],
    ),
    (
        "serveConn: a finished connection never gives its slot back",
        """		defer s.release()
""",
        "",
        ["TestServerBoundsConcurrentConnections"],
    ),
    (
        "track: connections are registered but not counted, so nothing waits for them",
        """	s.connWG.Add(1)
	return true""",
        """	return true""",
        ["TestServerShutdownSendsGoAwayToEveryConnection"],
    ),
    (
        "stop: the closed flag is never set, so a connection can be accepted afterwards",
        """	s.closed = true
	listeners := make""",
        """	listeners := make""",
        ["TestServerShutdownReachesAConnectionAcceptedInTheRace"],
    ),
    (
        "stop: the quit channel is closed directly, so the second shutdown closes it again",
        """	s.quitOnce.Do(func() { close(s.quit) })""",
        """	close(s.quit)""",
        ["TestServerShutdownIsIdempotent"],
    ),

    # --- containment ---------------------------------------------------------
    (
        "runConn: a panic reached through a peer's frame takes the whole process down",
        """	defer func() {
		r := recover()
		if r == nil {
			return
		}
		// The stack is the whole value of this line. A contained panic with no stack
		// is a bug that gets logged for months and never found.
		s.logf("connection from %v panicked, closing it: %v\\n%s", nc.RemoteAddr(), r, debug.Stack())

		// Serve's own deferred close ran as the panic went past it, so the socket is
		// gone; its wait for the writer did not, so that goroutine is still there.
		c.w.Close()
		if err := c.w.Wait(); err != nil {
			s.logf("connection from %v: stopping the writer after the panic: %v", nc.RemoteAddr(), err)
		}
	}()""",
        """	defer func() {
		if len(debug.Stack()) == 0 {
			s.logf("connection from %v: no stack", nc.RemoteAddr())
		}
	}()""",
        ["TestServerRecoversFromAPanickingHandler"],
    ),
    (
        "runConn: a contained panic is logged without its stack",
        """		s.logf("connection from %v panicked, closing it: %v\\n%s", nc.RemoteAddr(), r, debug.Stack())""",
        """		s.logf("connection from %v panicked, closing it: %v (%d octets of stack discarded)",
			nc.RemoteAddr(), r, len(debug.Stack()))""",
        ["TestServerRecoversFromAPanickingHandler"],
    ),
    (
        "runConn: the writer goroutine is left running after a panic",
        """		c.w.Close()
		if err := c.w.Wait(); err != nil {
			s.logf("connection from %v: stopping the writer after the panic: %v", nc.RemoteAddr(), err)
		}
""",
        "",
        ["TestServerRecoversFromAPanickingHandler"],
    ),
    (
        "runConn: a connection that failed is logged without the peer or the reason",
        """	if err := c.Serve(); err != nil {
		s.logf("connection from %v: %v", nc.RemoteAddr(), err)
	}""",
        """	if err := c.Serve(); err != nil {
		s.logf("a connection ended")
	}""",
        ["TestServerLogsWhyAConnectionEnded"],
    ),

    # --- the TLS handshake step ----------------------------------------------
    #
    # The handshake itself is broken in scripts/break-tls.py, against the file it
    # lives in. What is broken here is runConn's use of it: whether it happens at
    # all, whether a refusal is reported, and whether a connection that was refused
    # is actually taken down rather than served.
    (
        "runConn: TLS is never negotiated, so every h2 client is answered in cleartext",
        """	if err := s.handshake(nc); err != nil {
		s.logf("connection from %v: %v", nc.RemoteAddr(), err)
		if derr := c.discard(); derr != nil {
			s.logf("connection from %v: closing it after the failed handshake: %v", nc.RemoteAddr(), derr)
		}
		return
	}

""",
        "",
        [
            # Deliberately not TestServeTLSServesHTTP2ToAClientThatNegotiatesIt. It
            # passes with this whole block removed, and that is the finding rather than
            # a hole: see the note in the docstring.
            "TestServeTLSRefusesAClientThatNegotiatesNoProtocol",
            "TestServeTLSDropsAClientThatNeverSendsAClientHello",
        ],
    ),
    (
        "runConn: a refused handshake is silent, so a misconfigured client is undiagnosable",
        """		s.logf("connection from %v: %v", nc.RemoteAddr(), err)
		if derr := c.discard(); derr != nil {""",
        """		if derr := c.discard(); derr != nil {""",
        [
            "TestServeTLSRefusesAClientThatNegotiatesNoProtocol",
            "TestServeTLSDropsAClientThatNeverSendsAClientHello",
            "TestServeTLSRefusesAClientThatOffersAProtocolNobodyShares",
        ],
    ),
    (
        "runConn: a refused connection is returned from without closing its socket",
        """		if derr := c.discard(); derr != nil {
			s.logf("connection from %v: closing it after the failed handshake: %v", nc.RemoteAddr(), derr)
		}
		return""",
        """		return""",
        [
            "TestServeTLSDropsAClientThatNeverSendsAClientHello",
            "TestServeTLSRefusesAClientThatNegotiatesNoProtocol",
        ],
    ),
    (
        "runConn: a refused connection falls through and is served HTTP/2 anyway",
        """		if derr := c.discard(); derr != nil {
			s.logf("connection from %v: closing it after the failed handshake: %v", nc.RemoteAddr(), derr)
		}
		return
	}""",
        """		if derr := c.discard(); derr != nil {
			s.logf("connection from %v: closing it after the failed handshake: %v", nc.RemoteAddr(), derr)
		}
	}""",
        [
            "TestServeTLSRefusesAClientThatNegotiatesNoProtocol",
            "TestServeTLSDropsAClientThatNeverSendsAClientHello",
        ],
    ),
    (
        "logf: a server with no log dereferences it anyway",
        """	if s.log == nil {
		return
	}
""",
        "",
        [
            "TestServerWithNoLogDiscardsEveryLine",
            "TestServerFillsUnsetConfig",
        ],
    ),

    # --- shutdown ------------------------------------------------------------
    (
        "Shutdown: nobody is asked to stop, so no peer is told the server is leaving",
        """	s.shutdownConns()

	if s.awaitConns""",
        """	if s.awaitConns""",
        [
            "TestServerShutdownSendsGoAwayToEveryConnection",
            "TestServerServesARealSocket",
        ],
    ),
    (
        "Shutdown: the grace period is not waited out, so every request is cut short",
        """	if s.awaitConns(s.timeouts.ShutdownGrace) {
		return errors.Join(errs...)
	}

""",
        "",
        [
            "TestServerShutdownSendsGoAwayToEveryConnection",
            "TestServerServesARealSocket",
        ],
    ),
    (
        "awaitConns: an expired grace period is reported as every connection having finished",
        """	case <-timer.C:
		// The goroutine above outlives this call, still blocked on connWG. It ends
		// when the last connection does, which the caller is about to force.
		return false
	}""",
        """	case <-timer.C:
		return true
	}""",
        [
            "TestServerShutdownForcesAStalledConnectionPastTheGrace",
            "TestServerShutdownReportsAConnectionThatWillNotStop",
        ],
    ),
    (
        "Shutdown: a connection that outlived even a closed socket is not reported",
        """	if !s.awaitConns(s.timeouts.ShutdownGrace) {
		errs = append(errs, fmt.Errorf("%w: %d connections did not stop even after being closed",
			ErrShutdownGraceExpired, forced))
		return errors.Join(errs...)
	}

""",
        "",
        ["TestServerShutdownReportsAConnectionThatWillNotStop"],
    ),
    (
        "Shutdown: connections cut mid-flight are closed silently and reported as a clean stop",
        """	if forced > 0 {
		errs = append(errs, fmt.Errorf("%w: %d connections were closed mid-flight",
			ErrShutdownGraceExpired, forced))
	}
""",
        "",
        ["TestServerShutdownForcesAStalledConnectionPastTheGrace"],
    ),
    (
        "closeConns: the count of forced connections is thrown away",
        """	return len(conns)""",
        """	return 0""",
        ["TestServerShutdownForcesAStalledConnectionPastTheGrace"],
    ),
    (
        "closeListeners: a listener that would not close is closed silently",
        """		if err := l.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing listener %v: %w", l.Addr(), err))
		}""",
        """		l.Close()""",
        ["TestServerShutdownReportsAListenerThatWillNotClose"],
    ),
    (
        "Close: the impatient path says goodbye after all, and waits to",
        """	errs := s.closeListeners(s.stop())
	s.closeConns()""",
        """	errs := s.closeListeners(s.stop())
	s.shutdownConns()""",
        ["TestServerCloseStopsWithoutAGoAway"],
    ),
    (
        "Close: a connection that would not stop is not reported",
        """		errs = append(errs, ErrShutdownGraceExpired)
""",
        "",
        ["TestServerCloseReportsAConnectionThatWillNotStop"],
    ),
    (
        "onceListener: the descriptor is closed once per caller instead of once",
        """	l.once.Do(func() { l.err = l.Listener.Close() })
	return l.err""",
        """	return l.Listener.Close()""",
        ["TestServerShutdownClosesEachListenerOnce"],
    ),
]

breakage.main(SRC, PKG, BREAKS)
