"""Deliberately break internal/server/conn.go, one guard at a time, and report
which tests notice.

Each entry below removes exactly one guard and names the tests that must fail as a
result. See breakage.py for the harness and for what the five outcomes mean.

Two of these breaks are the reason the file is worth running rather than reading.
Recomputing the SETTINGS-acknowledgement deadline on each read passes the
silent-peer test and still lets a peer hold the connection open for ever, and
dropping the writer's queue on a clean close loses a mandatory acknowledgement
only when the timing goes one way. Neither is visible in a green suite.

Run from the repository root. Restores the file on the way out, including on error.
"""

import breakage

SRC = "internal/server/conn.go"
PKG = "./internal/server/"

# (name, old, new, tests that must fail)
BREAKS = [
    # --- construction --------------------------------------------------------
    (
        "newConn: a nil handler is accepted and fails later, on a peer's first frame",
        """	if h == nil {
		panic("server: newConn requires a stream handler")
	}
""",
        "",
        ["TestNewConnRequiresAStreamHandler"],
    ),
    (
        "newConn: unset timeouts keep their zero values, so every deadline is now",
        """	t = t.WithDefaults()
	return &conn{""",
        """	return &conn{""",
        ["TestNewConnFillsUnsetTimeouts"],
    ),
    (
        "readerConfig: the header-block bound is left at the reader's fallback",
        """		MaxHeaderBlockSize:    limits.MaxHeaderBlockSize,
""",
        "",
        ["TestReaderConfigSetsEveryField"],
    ),
    (
        "initialSettings: ENABLE_PUSH is not advertised",
        """		{ID: frame.SettingEnablePush, Value: 0},
""",
        "",
        ["TestInitialSettingsAdvertiseTheServersLimits"],
    ),
    (
        "initialSettings: MAX_CONCURRENT_STREAMS advertises a limit nothing enforces",
        """		{ID: frame.SettingMaxConcurrentStreams, Value: limits.MaxConcurrentStreams},""",
        """		{ID: frame.SettingMaxConcurrentStreams, Value: limits.MaxConcurrentStreams + 1},""",
        ["TestInitialSettingsAdvertiseTheServersLimits"],
    ),
    (
        "applySetting: two of the peer's parameters are no longer named at all",
        """	case frame.SettingHeaderTableSize, frame.SettingMaxHeaderListSize:
""",
        "",
        ["TestApplySettingNamesEverySettingID"],
    ),

    # --- the preface ---------------------------------------------------------
    (
        "run: the server's SETTINGS goes out after the preface is read, not before",
        """	if err := c.w.Enqueue(initialSettings()); err != nil {
		return err
	}

	if err := c.setReadDeadline(deadlinePreface); err != nil {
		return err
	}
	if err := c.r.ReadPreface(); err != nil {
		return c.readError(err)
	}""",
        """	if err := c.setReadDeadline(deadlinePreface); err != nil {
		return err
	}
	if err := c.r.ReadPreface(); err != nil {
		return c.readError(err)
	}
	if err := c.w.Enqueue(initialSettings()); err != nil {
		return err
	}""",
        ["TestServeSendsItsSettingsBeforeReadingThePreface"],
    ),
    (
        "run: the 6.5.3 clock starts before the preface, so a silent peer gets the wrong code",
        """	if err := c.setReadDeadline(deadlinePreface); err != nil {""",
        """	c.settingsAckDue = time.Now().Add(c.timeouts.SettingsAck)
	if err := c.setReadDeadline(deadlinePreface); err != nil {""",
        ["TestServeDoesNotStartTheSettingsClockBeforeThePreface"],
    ),
    (
        "run: a stream error is treated as fatal, taking every other request with it",
        """			if !errors.As(err, &se) {""",
        """			if true {""",
        ["TestServeResetsOneStreamAndKeepsTheConnection"],
    ),

    # --- endings -------------------------------------------------------------
    (
        "Serve: a clean close drops the writer's queue, losing the SETTINGS acknowledgement",
        """		c.w.Shutdown()
		gone = true""",
        """		c.w.Close()
		gone = true""",
        ["TestServeFlushesWhatIsQueuedWhenThePeerCloses"],
    ),
    (
        "Serve: a failed flush to a departed peer is reported as this server's fault",
        """		// up, which is the one event on a public port that carries no information.
		return nil""",
        """		// up, which is the one event on a public port that carries no information.
		return werr""",
        ["TestServeDoesNotReportAFailedFlushToADepartedPeer"],
    ),
    (
        "Serve: the socket is not closed, so every ending leaks a file descriptor",
        """	defer c.sock.Close()
""",
        "",
        ["TestServeAlwaysClosesTheSocket"],
    ),
    (
        "Serve: a connection error ends the connection without telling the peer why",
        """		sendErr = c.farewell(ce.Code, ce.Reason)""",
        """		c.w.Close()""",
        ["TestServeRejectsAnHTTP1Request", "TestServeStopsOnAConnectionErrorFromTheHandler"],
    ),
    (
        "Serve: a broken socket is sent a GOAWAY, whose failure competes with the real error",
        """	default:
		// A transport failure: the socket is broken, so there is no GOAWAY to
		// send and no point starting one.
		c.w.Close()
	}""",
        """	default:
		sendErr = c.farewell(h2.InternalError, "read failed")
	}""",
        ["TestServeSaysNothingAfterATransportFailure"],
    ),
    (
        "Serve: the peer's own debug octets are reflected back at it",
        """		sendErr = c.farewell(h2.NoError, "")""",
        """		sendErr = c.farewell(h2.NoError, err.Error())""",
        ["TestServeDoesNotEchoThePeersDebugData"],
    ),
    (
        "Serve: the idle GOAWAY says nothing, leaving the client to guess whether to retry",
        """		sendErr = c.farewell(h2.NoError, "idle timeout")""",
        """		sendErr = c.farewell(h2.NoError, "")""",
        ["TestServeGoesAwayOnTheIdleTimeout"],
    ),
    (
        "Serve: closing an idle connection is reported as a failure",
        """	case errors.Is(err, errIdle):
		sendErr = c.farewell(h2.NoError, "idle timeout")
		err = nil""",
        """	case errors.Is(err, errIdle):
		sendErr = c.farewell(h2.NoError, "idle timeout")""",
        ["TestServeGoesAwayOnTheIdleTimeout"],
    ),
    (
        "farewell: the GOAWAY is queued and never flushed, so Wait never returns",
        """	c.w.Shutdown()
	return err""",
        """	return err""",
        ["TestServeGoesAwayOnTheIdleTimeout"],
    ),

    # --- deadlines -----------------------------------------------------------
    (
        "setReadDeadline: the socket is never told, so a silent peer is never timed out",
        """	c.deadlineKind = kind
	return c.sock.SetReadDeadline(deadline)""",
        """	c.deadlineKind = kind
	_ = deadline
	return nil""",
        ["TestServeSetsAReadDeadlineBeforeEveryRead"],
    ),
    (
        "setReadDeadline: which deadline is running is not recorded, so the code is guessed",
        """	c.deadlineKind = kind""",
        """	_ = kind""",
        ["TestServeReportsASettingsTimeout"],
    ),
    (
        "setReadDeadline: the acknowledgement deadline never brings a read's deadline forward",
        """	if !c.settingsAckDue.IsZero() {
		if due := c.deadlineFor(deadlineSettingsAck); due.Before(deadline) {
			kind, deadline = deadlineSettingsAck, due
		}
	}
""",
        "",
        ["TestServeReportsASettingsTimeout", "TestServeStopsTheSettingsClockOnAnAcknowledgement"],
    ),
    (
        "deadlineFor: the 6.5.3 deadline is recomputed per read, so a chatty peer postpones it",
        """	case deadlineSettingsAck:
		return c.settingsAckDue""",
        """	case deadlineSettingsAck:
		return time.Now().Add(c.timeouts.SettingsAck)""",
        ["TestServeReportsASettingsTimeoutToAChattyPeer"],
    ),
    (
        "readError: a frame cut in half is reported as a peer that closed politely",
        """	case errors.Is(err, io.EOF):""",
        """	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):""",
        ["TestServeReportsATruncatedPreface", "TestServeReportsATruncatedFrame"],
    ),

    # --- SETTINGS ------------------------------------------------------------
    (
        "handleSettings: an acknowledgement is answered, so the two sides trade them for ever",
        """	if f.Ack {
		// This is what stops the §6.5.3 clock.""",
        """	if false {
		// This is what stops the §6.5.3 clock.""",
        ["TestServeDoesNotAcknowledgeAnAcknowledgement"],
    ),
    (
        "handleSettings: the acknowledgement does not stop the 6.5.3 clock",
        """		c.settingsAckDue = time.Time{}
""",
        "",
        ["TestServeStopsTheSettingsClockOnAnAcknowledgement"],
    ),
    (
        "handleSettings: acknowledged before applied, licensing a frame we might still refuse",
        """	for _, s := range f.Settings {
		c.applySetting(s)
	}
	return c.w.Enqueue(frame.SettingsFrame{Ack: true})""",
        """	if err := c.w.Enqueue(frame.SettingsFrame{Ack: true}); err != nil {
		return err
	}
	for _, s := range f.Settings {
		c.applySetting(s)
	}
	return nil""",
        ["TestServeAppliesSettingsBeforeAcknowledging"],
    ),
    (
        "handleSettings: nothing is acknowledged, so a peer waiting for one stalls",
        """	return c.w.Enqueue(frame.SettingsFrame{Ack: true})""",
        """	return nil""",
        [
            "TestServeAcceptsAnEmptySettingsAsTheFirstFrame",
            "TestServeAcknowledgesTheSettingsItDoesNotActOnYet",
        ],
    ),
    (
        "applySetting: MAX_FRAME_SIZE never reaches the writer",
        """		c.w.SetMaxFrameSize(s.Value)""",
        """		_ = s.Value""",
        ["TestServeAppliesAndAcknowledgesThePeersSettings"],
    ),

    # --- dispatch ------------------------------------------------------------
    (
        "dispatch: the first frame need not be SETTINGS, so an HTTP/1 request is served",
        """	if !c.gotSettings {
		if f.Type() != frame.TypeSettings {
			return h2.ConnErrorf(h2.ProtocolError,
				"first frame on the connection is %s, but RFC 9113 §3.4 requires SETTINGS",
				f.Type())
		}
		c.gotSettings = true
	}
""",
        "",
        ["TestServeRequiresSettingsAsTheFirstFrame"],
    ),
    (
        "dispatch: the peer's GOAWAY is ignored and the connection keeps reading",
        """		return fmt.Errorf("%w: %s: %q", errPeerGoAway, f.ErrCode, f.Debug)""",
        """		return nil""",
        ["TestServeAnswersAPeerGoAway", "TestRunReportsWhatThePeersGoAwaySaid"],
    ),
    (
        "dispatch: a client's PUSH_PROMISE is routed to the stream layer instead of refused",
        """		return h2.ConnErrorf(h2.ProtocolError,
			"PUSH_PROMISE received on stream %d: a client cannot push (RFC 9113 §8.4)",
			f.Stream())""",
        """		return c.handleStreamFrame(f)""",
        ["TestServeRefusesAPushPromiseFromAClient", "TestServeReportsTheLastStreamItTouched"],
    ),
    (
        "dispatch: a stream-0 WINDOW_UPDATE is handed to the stream layer, which has no stream 0",
        """		if f.StreamID == 0 {""",
        """		if false {""",
        ["TestServeKeepsAStreamZeroWindowUpdateFromTheHandler"],
    ),

    # --- PING ----------------------------------------------------------------
    (
        "handlePing: an acknowledgement is answered with another one",
        """	if f.Ack {
		// A reply to a PING we sent""",
        """	if false {
		// A reply to a PING we sent""",
        ["TestServeDoesNotAnswerAPingAcknowledgement"],
    ),
    (
        "handlePing: the reply carries no ACK flag, so the peer reads it as a fresh PING",
        """	return c.w.Enqueue(frame.PingFrame{Ack: true, Data: f.Data})""",
        """	return c.w.Enqueue(frame.PingFrame{Data: f.Data})""",
        ["TestServeAnswersAPing", "TestServeAnswersAPingFloodInOrder"],
    ),
    (
        "handlePing: the reply carries eight zero octets rather than the peer's own",
        """	return c.w.Enqueue(frame.PingFrame{Ack: true, Data: f.Data})""",
        """	return c.w.Enqueue(frame.PingFrame{Ack: true})""",
        ["TestServeAnswersAPing", "TestServeAnswersAPingFloodInOrder"],
    ),

    # --- the stream boundary -------------------------------------------------
    (
        "handleStreamFrame: the highest dispatched stream is not tracked, so GOAWAY names 0",
        """	if id := f.Stream(); id > c.lastStreamID {
		c.lastStreamID = id
	}
""",
        "",
        ["TestServeReportsTheLastStreamItTouched"],
    ),
    (
        "handleStreamFrame: stream frames are swallowed and never reach the stream layer",
        """	return c.handler.HandleFrame(f)""",
        """	return nil""",
        ["TestServeHandsStreamFramesToTheHandler", "TestServeResetsOneStreamAndKeepsTheConnection"],
    ),
]

breakage.main(SRC, PKG, BREAKS)
