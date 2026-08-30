"""Deliberately break internal/server/conn.go, one guard at a time, and report
which tests notice.

Each entry below removes exactly one guard and names the tests that must fail as a
result. See breakage.py for the harness and for what the five outcomes mean.

Two of these breaks are the reason the file is worth running rather than reading.
Recomputing the SETTINGS-acknowledgement deadline on each read passes the
silent-peer test and still lets a peer hold the connection open for ever, and
dropping the writer's queue on a clean close loses a mandatory acknowledgement
only when the timing goes one way. Neither is visible in a green suite.

A third joined them with graceful shutdown: setReadDeadline's check of the quit
flag covers a window a few instructions wide, between the read loop checking that
flag and the loop arming the deadline for its next read. Removing it leaves a
server that answers a shutdown when the connection next hears from its peer, which
on an idle connection is a minute later and on an abandoned one is never.

A fourth and fifth are about a value rather than a route. HEADER_TABLE_SIZE and
MAX_HEADER_LIST_SIZE each take 0 as a meaningful setting -- a peer that keeps no
dynamic table for decoding, and a peer that will read no header list at all -- so a
route that forwarded only non-zero values would carry every value a test is likely to
pick and drop the one number that is hard to tell apart from the parameter never having
been sent. Both breaks are that skip, and TestServeForwardsAHeaderSettingOfZero is the
test that notices; nothing else in the suite does, because every other setting in it is
non-zero on purpose.

A sixth is not about a frame at all. Serve tells the stream layer why the connection
ended, and the reason that hook exists is a goroutine writing a response body: it is
parked on a condition variable inside flow control, so closing the socket does not reach
it and neither does stopping the writer. The break that deletes the call leaks a
request, a response and a stack per parked writer for the life of the process, on the
ordinary event of a peer hanging up mid-download, and a suite that only looks at the
wire cannot see it. Two more are about *when*: called sequentially after the read loop
instead of deferred, it is skipped entirely when the read loop panics -- which is the
one ending a server survives, because runConn recovers it -- and it runs before the
writer has stopped, so a writer this call wakes may put a frame on the wire behind the
GOAWAY that has already gone out.

Two more came with extensible priorities, and both are a comparison rather than a
route. The §7.1 cap on buffered priority signals is checked with >= rather than >,
because the frame being admitted is not yet in the buffer it is counted against: the
> version admits one signal past the SETTINGS_MAX_CONCURRENT_STREAMS this connection
advertised, which is a limit exceeded by exactly one and visible in nothing else. And
handleStreamFrame defers the buffer's application past the stream layer's handling
rather than calling it inline; called inline it asks whether a stream is live before
the frame that would open it has been handled, so every buffered signal is dropped
and the SHOULD in §7 of RFC 9218 is honoured in appearance only.

Two guards in discard have no break, and both are named rather than quietly skipped.

  * c.w.Close(). Removing it does not fail a test, it deadlocks one: the writer sits
    on its queue for ever and the c.w.Wait() on the next line never returns. A
    deadlock is not a detection — this harness would report it as a hang, which it
    counts as a hole, and rightly, because nothing in the suite would have said what
    was wrong.

  * The waiting itself, as distinct from the error it collects. Dropping the error
    is broken below and caught. Dropping the wait while keeping the Close is not
    observable here: the writer's queue is always empty on this path, because discard
    runs before Serve and therefore before anything has been enqueued, so the
    goroutine returns as soon as it is signalled whether or not anyone waits. The
    goroutine-leak assertion polls, so it would come back green either way.

Related, and for the same reason: c.w.Close() and c.w.Shutdown() are
indistinguishable on this path. Shutdown flushes what is queued, Close does not, and
with an empty queue those are the same thing. The distinction matters in Serve, where
it is broken and caught.

The campaign went stale twice, and the preflight is what said so rather than a run
full of holes. applySetting grew an error return when the connection started routing
INITIAL_WINDOW_SIZE to the stream layer, which left this file's acknowledge-before-
apply break anchored on a loop body that no longer existed: it matched 0 times, the
harness refused the whole campaign with exit 2, and nothing was tested. That is the
outcome the preflight is for. The alternative -- a break that removes nothing, so
every test it names comes back green -- reports as a hole in the suite, and the three
routing behaviours added in the same commit as the error return genuinely had no
breaks at all. They have them now.

The second time was the same two shapes again: routing PRIORITY_UPDATE into the
scheduler put a line between handleSettings' apply loop and its acknowledgement, and
another inside handleStreamFrame's high-water branch. Both anchors matched 0 times.
The acknowledge-before-apply break is now anchored on the loop alone and enqueues the
acknowledgement ahead of it, which needs no line that a later change is likely to sit
next to.

Run from the repository root. Restores the file on the way out, including on error.
"""

import breakage

SRC = "internal/server/conn.go"
PKG = "./internal/server/"

# (name, old, new, tests that must fail)
BREAKS = [
    # --- construction --------------------------------------------------------
    (
        "newConn: a nil factory is accepted and fails later, on a peer's first frame",
        """	if newHandler == nil {
		panic("server: newConn requires a stream handler factory")
	}
""",
        "",
        ["TestNewConnRequiresAStreamHandlerFactory"],
    ),
    (
        "newConn: a factory that returns no handler is accepted, and the nil arrives on dispatch",
        """	if h == nil {""",
        """	if false {""",
        ["TestNewConnRejectsAFactoryThatReturnsNoHandler"],
    ),
    (
        "newConn: the writer is left running when the handler is refused, so a recovered panic leaks it",
        """		w.Close()
		_ = w.Wait()
		panic("server: the stream handler factory returned no handler")""",
        """		panic("server: the stream handler factory returned no handler")""",
        ["TestNewConnRejectsAFactoryThatReturnsNoHandler"],
    ),
    (
        "newConn: the handler gets a writer of its own, so two goroutines own one socket",
        """	h := newHandler(w)""",
        """	h := newHandler(startFrameWriter(sock, t.Write))""",
        ["TestServeLeaksNoGoroutines"],
    ),
    (
        "newConn: unset timeouts keep their zero values, so every deadline is now",
        """	t = t.WithDefaults()
""",
        "",
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
        "applySetting: HEADER_TABLE_SIZE is no longer named at all",
        """	case frame.SettingHeaderTableSize:
""",
        "",
        ["TestApplySettingNamesEverySettingID"],
    ),
    (
        "applySetting: MAX_HEADER_LIST_SIZE is no longer named at all",
        """	case frame.SettingMaxHeaderListSize:
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
        "Serve: the stream layer is never told the connection ended, so a writer parked for credit waits for the life of the process",
        """	ended := errReadLoopPanicked
	defer func() { c.handler.Close(ended) }()

	err := c.run()
	ended = err
""",
        """	err := c.run()
""",
        [
            "TestServeAlwaysTellsTheStreamLayerWhyTheConnectionEnded",
            "TestServeWakesTheStreamLayerWhenTheReadLoopPanics",
            "TestServeClosesTheStreamLayerAfterTheWriterHasStopped",
        ],
    ),
    (
        "Serve: the stream layer is told the read loop panicked whatever actually ended the connection",
        """	err := c.run()
	ended = err
""",
        """	err := c.run()
""",
        [
            "TestServeAlwaysTellsTheStreamLayerWhyTheConnectionEnded",
            "TestServeStopsOnAConnectionErrorFromTheHandler",
        ],
    ),
    (
        "Serve: the stream layer is closed as soon as the read loop stops, so a woken writer can queue a frame behind the GOAWAY",
        """	ended := errReadLoopPanicked
	defer func() { c.handler.Close(ended) }()

	err := c.run()
	ended = err
""",
        """	err := c.run()
	c.handler.Close(err)
""",
        [
            "TestServeClosesTheStreamLayerAfterTheWriterHasStopped",
            "TestServeWakesTheStreamLayerWhenTheReadLoopPanics",
        ],
    ),
    (
        "Serve: a read loop that panicked wakes its writers with no reason at all",
        """	ended := errReadLoopPanicked""",
        """	var ended error""",
        ["TestServeWakesTheStreamLayerWhenTheReadLoopPanics"],
    ),

    # --- discard -------------------------------------------------------------
    #
    # The teardown for a connection that never became one: a TLS handshake that
    # failed, or one that succeeded and negotiated something this server does not
    # speak. Serve never ran, so nothing else is going to close the socket, and
    # there is no HTTP/2 session to send a GOAWAY over.
    (
        "discard: the socket is left open, so every refused handshake leaks a descriptor",
        """	return errors.Join(c.w.Wait(), c.sock.Close())""",
        """	return c.w.Wait()""",
        [
            "TestDiscardClosesTheSocketWithoutWritingToIt",
            "TestDiscardReportsBothHalvesOfTheTeardown",
            "TestServeTLSDropsAClientThatNeverSendsAClientHello",
        ],
    ),
    (
        "discard: the writer is never waited for, so its failure is discarded with it",
        """	return errors.Join(c.w.Wait(), c.sock.Close())""",
        """	c.w.Wait()
	return c.sock.Close()""",
        ["TestDiscardReportsBothHalvesOfTheTeardown"],
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
        """	return c.sock.SetReadDeadline(deadline)""",
        """	_ = deadline
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
		if err := c.applySetting(s); err != nil {
			return err
		}
	}""",
        """	if err := c.w.Enqueue(frame.SettingsFrame{Ack: true}); err != nil {
		return err
	}
	for _, s := range f.Settings {
		if err := c.applySetting(s); err != nil {
			return err
		}
	}""",
        [
            "TestServeAppliesSettingsBeforeAcknowledging",
            "TestServeStopsOnASettingItCannotApply",
        ],
    ),
    (
        "handleSettings: nothing is acknowledged, so a peer waiting for one stalls",
        """	return c.w.Enqueue(frame.SettingsFrame{Ack: true})""",
        """	return nil""",
        [
            "TestServeAcceptsAnEmptySettingsAsTheFirstFrame",
            "TestServeAcknowledgesTheSettingsItHasNothingToDoAbout",
        ],
    ),
    (
        "applySetting: MAX_FRAME_SIZE never reaches the writer",
        """		c.w.SetMaxFrameSize(s.Value)""",
        """		_ = s.Value""",
        ["TestServeAppliesAndAcknowledgesThePeersSettings"],
    ),
    (
        "handleSettings: a parameter that cannot be applied is skipped and the rest acknowledged",
        """		if err := c.applySetting(s); err != nil {
			return err
		}""",
        """		_ = c.applySetting(s)""",
        ["TestServeStopsOnASettingItCannotApply"],
    ),
    (
        "applySetting: INITIAL_WINDOW_SIZE never reaches the streams that hold the windows",
        """		return c.handler.SetInitialWindowSize(s.Value)""",
        """		_ = s.Value""",
        [
            "TestServeAppliesInitialWindowSizeToTheStreamLayer",
            "TestServeStopsOnASettingItCannotApply",
        ],
    ),
    (
        "applySetting: HEADER_TABLE_SIZE never reaches the encoder, which compresses "
        "against a table the peer is not keeping",
        """		c.handler.SetHeaderTableSize(s.Value)""",
        """		_ = s.Value""",
        [
            "TestServeAppliesTheHeaderSettingsToTheEncodingSide",
            "TestServeForwardsAHeaderSettingOfZero",
        ],
    ),
    (
        "applySetting: MAX_HEADER_LIST_SIZE never reaches the layer that builds the list",
        """		c.handler.SetMaxHeaderListSize(s.Value)""",
        """		_ = s.Value""",
        [
            "TestServeAppliesTheHeaderSettingsToTheEncodingSide",
            "TestServeForwardsAHeaderSettingOfZero",
        ],
    ),
    (
        "applySetting: a HEADER_TABLE_SIZE of 0 is read as no value at all, so the peer's "
        "emptied table is never honoured",
        """		c.handler.SetHeaderTableSize(s.Value)""",
        """		if s.Value != 0 {
			c.handler.SetHeaderTableSize(s.Value)
		}""",
        ["TestServeForwardsAHeaderSettingOfZero"],
    ),
    (
        "applySetting: a MAX_HEADER_LIST_SIZE of 0 is read as no value at all, which is "
        "the one state it must be distinguishable from",
        """		c.handler.SetMaxHeaderListSize(s.Value)""",
        """		if s.Value != 0 {
			c.handler.SetMaxHeaderListSize(s.Value)
		}""",
        ["TestServeForwardsAHeaderSettingOfZero"],
    ),
    (
        "applySetting: the two header parameters are crossed, so each is applied as the other",
        """		c.handler.SetHeaderTableSize(s.Value)""",
        """		c.handler.SetMaxHeaderListSize(s.Value)""",
        ["TestServeAppliesTheHeaderSettingsToTheEncodingSide"],
    ),
    (
        "handleConnectionWindowUpdate: a stream-0 credit is swallowed at the connection level",
        """	return c.handler.ConnWindowUpdate(f.Increment)""",
        """	_ = f.Increment
	return nil""",
        [
            "TestServeKeepsAStreamZeroWindowUpdateFromTheHandler",
            "TestServeReportsARefusedConnectionWindowUpdate",
        ],
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
		defer c.leftIdle(id)
	}""",
        """	if id := f.Stream(); id > c.lastStreamID {
		defer c.leftIdle(id)
	}""",
        ["TestServeReportsTheLastStreamItTouched"],
    ),
    (
        "handleStreamFrame: stream frames are swallowed and never reach the stream layer",
        """	return c.handler.HandleFrame(f)""",
        """	return nil""",
        ["TestServeHandsStreamFramesToTheHandler", "TestServeResetsOneStreamAndKeepsTheConnection"],
    ),

    # --- extensible priorities -----------------------------------------------
    (
        "dispatch: a PRIORITY_UPDATE is handed to the stream layer, which has no stream 0",
        """	case frame.PriorityUpdateFrame:
		return c.handlePriorityUpdate(f)""",
        """	case frame.PriorityUpdateFrame:
		_ = f""",
        ["TestServeKeepsAPriorityUpdateFromTheHandler"],
    ),
    (
        "handlePriorityUpdate: an even prioritized identifier is accepted, not refused as a push stream",
        """	if f.PrioritizedStreamID%2 == 0 {""",
        """	if false {""",
        ["TestServeRefusesAPriorityUpdateForAPushStream"],
    ),
    (
        "handlePriorityUpdate: a live stream is not prioritized, so the signal is discarded",
        """	case c.handler.Live(id):
		c.w.Prioritize(id, p)""",
        """	case false:
		c.w.Prioritize(id, p)""",
        ["TestServePrioritizesALiveStreamStraightAway"],
    ),
    (
        "handlePriorityUpdate: a closed stream is buffered rather than discarded, and the entry is never removed",
        """	case id > c.lastStreamID:""",
        """	case true:""",
        ["TestServeDiscardsAPriorityUpdateForAClosedStream"],
    ),
    (
        "handlePriorityUpdate: no §7.1 cap, so a client buffers priorities without bound",
        """		if !c.pending.Held(id) && c.pending.Len()+c.handler.Len() >= limits.MaxConcurrentStreams {""",
        """		if false {""",
        ["TestServeRefusesPrioritizedIdleStreamsPastTheLimit"],
    ),
    (
        "handlePriorityUpdate: the §7.1 cap does not count the frame being admitted, so the limit is exceeded by one",
        """c.pending.Len()+c.handler.Len() >= limits.MaxConcurrentStreams {""",
        """c.pending.Len()+c.handler.Len() > limits.MaxConcurrentStreams {""",
        ["TestServeRefusesPrioritizedIdleStreamsPastTheLimit"],
    ),
    (
        "handlePriorityUpdate: a replacement counts against the cap, so a client cannot change its mind",
        """		if !c.pending.Held(id) && c.pending.Len()""",
        """		if c.pending.Len()""",
        ["TestServeReprioritizingABufferedStreamDoesNotUseUpMoreRoom"],
    ),
    (
        "handleStreamFrame: the buffer is applied before the stream layer has ruled on the frame",
        """		defer c.leftIdle(id)
	}
	return c.handler.HandleFrame(f)""",
        """		c.leftIdle(id)
	}
	return c.handler.HandleFrame(f)""",
        [
            "TestServeBuffersAPriorityUpdateUntilTheStreamOpens",
            "TestServeLetsAPriorityUpdateOverrideTheRequestsOwnPriorityField",
        ],
    ),
    (
        "leftIdle: a refused stream's buffered priority is applied, and nothing will ever forget it",
        """	if p, ok := c.pending.Take(id); ok && c.handler.Live(id) {""",
        """	if p, ok := c.pending.Take(id); ok {""",
        ["TestServeDoesNotPrioritizeARefusedStream"],
    ),
    (
        "leftIdle: the identifiers §5.1.1 just closed are not pruned, so the buffer fills for good",
        """	c.pending.Prune(id)
""",
        "",
        ["TestServeOpeningAStreamRestoresRoomToPrioritize"],
    ),

    # --- graceful shutdown ---------------------------------------------------
    (
        "Serve: a shutdown is reported as a failure and the peer is never told why",
        """		sendErr = c.farewell(h2.NoError, "server shutting down")
		err = nil""",
        "",
        [
            "TestConnShutdownInterruptsAParkedRead",
            "TestConnShutdownBeforeTheFirstReadEndsAtOnce",
            "TestConnShutdownDoesNotServeAnotherFrame",
            "TestConnShutdownIsIdempotent",
        ],
    ),
    (
        "Serve: the shutdown GOAWAY blames the peer for a connection this server ended",
        """		sendErr = c.farewell(h2.NoError, "server shutting down")""",
        """		sendErr = c.farewell(h2.InternalError, "server shutting down")""",
        ["TestConnShutdownInterruptsAParkedRead", "TestConnShutdownDoesNotServeAnotherFrame"],
    ),
    (
        "Shutdown: the parked read is never interrupted, so a shutdown waits out the idle timeout",
        """	if err := c.sock.SetReadDeadline(time.Now()); err != nil {
		// Nothing to do and nothing to report: a socket rejects a deadline once it
		// is closed, which is the state this call is asking for. The read it would
		// have interrupted has already finished.
		return
	}
""",
        "",
        ["TestConnShutdownInterruptsAParkedRead", "TestConnShutdownIsIdempotent"],
    ),
    (
        "setReadDeadline: the loop pushes the deadline back out over Shutdown's interrupt",
        """	if c.stopping() {
		// Shutdown has already brought the deadline forward and this call would push
		// it back out. Deciding inside the lock is what makes the two orderings
		// equivalent: either Shutdown's deadline lands after ours and wins, or it
		// landed before and this branch repeats it.
		deadline = time.Now()
	}
""",
        "",
        ["TestConnShutdownBeforeTheFirstReadEndsAtOnce"],
    ),
    (
        "readError: our own interrupt is reported to the peer as its fault",
        """		if c.stopping() {
			return errShuttingDown
		}
		switch c.deadlineKind {""",
        """		switch c.deadlineKind {""",
        [
            "TestConnShutdownInterruptsAParkedRead",
            "TestConnShutdownBeforeTheFirstReadEndsAtOnce",
        ],
    ),
    (
        "run: a shutdown still serves whatever the peer had already buffered",
        """		if c.stopping() {
			return errShuttingDown
		}
		if err := c.setReadDeadline(deadlineIdle); err != nil {""",
        """		if err := c.setReadDeadline(deadlineIdle); err != nil {""",
        ["TestConnShutdownDoesNotServeAnotherFrame"],
    ),
]

breakage.main(SRC, PKG, BREAKS)
