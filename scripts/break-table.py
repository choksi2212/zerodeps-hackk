"""Deliberately break internal/stream/table.go, one guard at a time, and report
which tests notice.

Each entry below removes exactly one guard and names the tests that must fail as a
result. See breakage.py for the harness and for what the five outcomes mean.

This is the largest campaign in the project, because table.go is the file where the
protocol's rules stop being arithmetic and start being decisions. Most of what it
holds is not a computation that can be wrong by a digit but an *ordering*: which of
two applicable errors is returned, whether a debit happens before or after a
rejection, whether a state is settled before or after the request is delivered.
An ordering has no natural symptom. Both orders compile, both pass a suite that
only checks the happy path, and the wrong one shows up as a transfer that stalls
half an hour later or a peer that gets told the wrong thing about its own bug.

Four of the breaks below are the ones worth reading for what they are testing
rather than what they remove.

  Returning the deferred verdict before the decode in completeBlock leaves a server
  that is correct for every request a client sends until one of them is refused --
  and from that moment the HPACK dynamic table is one insertion behind the peer's,
  so every later request on the connection decodes into header fields nobody sent.
  §5.1 requires the compression state to be updated for a stream that is closed or
  refused, and this is the break that shows why: the refusal is the cheap half, and
  the decode is the half the connection's future depends on.

  Moving the connection-window debit in data below the stream lookup leaves flow
  control that is exactly right for every frame it accepts and silently wrong for
  every frame it refuses. §6.9.1 requires the debit either way. Nothing looks
  broken; the two ends simply stop agreeing about the connection's credit, by the
  size of whatever was dropped, permanently.

  Recording highestRemote only for a stream that was admitted leaves a window after
  every refusal in which the peer may open a *lower* identifier -- which §5.1.1
  exists to make impossible, because a lower identifier is one this server has
  already declared closed.

  Delivering a request before its state is settled hands the handler a stream that
  says "open" for a request the peer has already finished. A handler that decides
  whether to wait for a body from that answer waits for a body that will never
  come, and the stream sits there until the idle timeout.

Every guard in the file has a break here, both scopes of every error that has a
choice of scope, and every message has one that strips its section reference.
All 114 are caught, and two of them are worth knowing about for how they are caught
rather than that they are: removing the CONTINUATION-with-no-block guard and dropping
the streams map from the constructor both produce a nil dereference rather than a
failed assertion. Both still report as an ordinary failure of the named test, because
the panic happens on the goroutine running that test and go test attributes it there
-- so neither needs the harness's crash outcome, which is for a break that takes the
package down somewhere no test's name is attached to.

The campaign found four missing tests rather than four weak guards, which is the
other outcome these files exist to produce. All four are now in table_test.go, and
each of them started as a break that fired nothing:

  TestARefusedStreamStillSpendsItsIdentifier -- nothing observed that a refused
  stream's identifier is spent, though openStream's comment claims it in as many
  words.

  TestTrailersOnAHalfClosedStreamAreClosedRatherThanMalformed -- beginTrailers
  chooses between §5.1 and §8.1 for a frame that breaks both, and nothing pinned
  the choice.

  TestTrailersSplitAcrossContinuationsAreDecodedAsOne -- the trailer path has its
  own call into the assembler and every existing trailer test sent END_HEADERS on
  the first frame, so completing the block early was invisible.

  TestDataAfterEndStreamIsStillCountedAgainstTheConnectionWindow -- the closed-stream
  case of §6.9.1's accounting rule was covered and the half-closed case was not,
  which left the whole state check free to move above the debit.

TestContinuationOnTheWrongStreamEndsTheConnection was also weak rather than absent:
it only ever sent a CONTINUATION on a *higher* identifier than the open block's, so
turning `!=` into `>` fired nothing. It now runs both directions.

The campaign's own first run was refused by preflight, on the rstStream idle-stream
anchor: `if t.StateOf(f.StreamID) == StateIdle {` appears twice in the file, once at
one tab in rstStream and once at two inside windowUpdate, and the one-tab form is a
substring of the two-tab one. The anchor now carries the comment line beneath it. The
check counts substrings rather than lines because a substring is what the replacement
will act on, and being refused by it is the cheaper outcome: the alternative is a
break that silently guts windowUpdate and reports rstStream's test as a hole.

One result is a measurement rather than a catch, and it is written down because the
reasoning is what a reader would otherwise reconstruct wrongly.

  Setting endStream on a trailer block is not observable at all. completeBlock's
  trailer path calls recvEnd unconditionally -- it may, because beginTrailers has
  already made a trailer section without END_STREAM a stream error -- so the field
  is only ever read for a block that opens a request. The break is kept, commented
  out, below beginTrailers' live entries, and block.endStream's doc comment now says
  which of the two kinds of block reads it.

Run from the repository root. Restores the file on the way out, including on error.
"""

import breakage

SRC = "internal/stream/table.go"
PKG = "./internal/stream/"

# (name, old, new, tests that must fail)
#
# `if false {` and `case false:` appear as replacements throughout. They disable a
# guard without touching the comment that explains it, which keeps these anchors to
# a line each -- an anchor that has to quote six lines of prose is an anchor that
# breaks the next time the prose is edited, and a campaign that fails to apply is a
# campaign that reports the suite as weak.
BREAKS = [
    # --- construction --------------------------------------------------------
    (
        "New accepts a nil codec, so the connection's first request panics in the reader goroutine",
        """	if cfg.Codec == nil {
		panic("stream: New requires a header codec")
	}
""",
        "",
        ["TestNewPanicsWithoutACodec"],
    ),
    (
        "New accepts a nil Requests",
        """	if cfg.Requests == nil {
		panic("stream: New requires a Requests")
	}
""",
        "",
        ["TestNewPanicsWithoutRequests"],
    ),
    (
        "New leaves the concurrency limit at zero, so every stream is refused",
        """	if cfg.MaxConcurrent == 0 {
		cfg.MaxConcurrent = limits.MaxConcurrentStreams
	}
""",
        "",
        ["TestNewDefaultsTheConcurrencyLimitToThePolicyBound"],
    ),
    (
        "New leaves the clock nil, which is a nil call in the constructor itself",
        """	if cfg.Now == nil {
		cfg.Now = time.Now
	}
""",
        "",
        ["TestNewDefaultsTheClockToTimeNow"],
    ),
    (
        "New has no streams map, so the first stream to open panics",
        """		streams:       make(map[uint32]*Stream),
""",
        "",
        ["TestHeadersOpensAStreamAndDeliversItsFields"],
    ),
    (
        "New makes the connection's receive window a stream window, so a connection fault resets stream 1",
        """		connRecv:      flow.NewConnWindow(),""",
        """		connRecv:      flow.NewStreamWindow(1, flow.InitialWindowSize),""",
        [
            "TestNewStartsBothConnectionWindowsAtTheProtocolInitialSize",
            "TestDataPastTheConnectionWindowEndsTheConnection",
        ],
    ),
    (
        "New makes the connection's send window a stream window, so its overflow is one stream's fault",
        """		connSend:      flow.NewConnWindow(),""",
        """		connSend:      flow.NewStreamWindow(1, flow.InitialWindowSize),""",
        ["TestConnWindowUpdateOverflowEndsTheConnection"],
    ),
    (
        "New starts new streams' send windows at zero rather than the protocol's initial size",
        """		peerInitialWindow: flow.InitialWindowSize,""",
        """		peerInitialWindow: 0,""",
        ["TestNewSizesNewStreamWindowsFromTheProtocolInitialSize"],
    ),
    (
        "New sizes the reset bucket from something other than the advisory's policy",
        """		resets: limits.NewResetBucket(cfg.Now()),""",
        """		resets: limits.NewBucket(1<<30, 1<<30, cfg.Now()),""",
        ["TestARstStreamFloodEndsTheConnection"],
    ),

    # --- StateOf: the three-way distinction ----------------------------------
    (
        "StateOf does not consult the map, so a live stream reads as closed",
        """	if s := t.streams[id]; s != nil {
		return s.state
	}
""",
        "",
        ["TestStateOfTracksAStreamThroughEveryTransition"],
    ),
    (
        "StateOf forgets that even identifiers are never anything but idle (RFC 9113 5.1.1)",
        """	if id%2 == 0 {
		return StateIdle
	}
""",
        "",
        ["TestStateOfIsAlwaysIdleForAnEvenIdentifier"],
    ),
    (
        "StateOf calls the highest identifier the peer used idle again once its stream is gone",
        """	if id > t.highestRemote {""",
        """	if id >= t.highestRemote {""",
        [
            "TestStateOfTracksAStreamThroughEveryTransition",
            "TestHeadersOnAStreamThatHasFinishedEndsTheConnection",
        ],
    ),
    (
        "StateOf calls a skipped identifier idle, so RST_STREAM on one ends the connection",
        """	return StateClosed""",
        """	return StateIdle""",
        [
            "TestStateOfIsClosedForAnIdentifierThePeerSkipped",
            "TestRstStreamOnASkippedIdentifierIsIgnored",
        ],
    ),

    # --- SendEnd: the other half of the two-sided close ----------------------
    (
        "SendEnd never closes a stream the peer had already finished",
        """	if s.state == StateHalfClosedRemote {""",
        """	if s.state == StateHalfClosedLocal {""",
        [
            "TestStateOfTracksAStreamThroughEveryTransition",
            "TestAHalfClosedStreamStillCountsAgainstTheLimit",
        ],
    ),
    (
        "SendEnd closes a stream and leaves it in the table, so the concurrency limit ratchets down",
        """		s.state = StateClosed
		t.retire(s)
		return""",
        """		s.state = StateClosed
		return""",
        [
            "TestTheTableOnlyHoldsStreamsThatCountAsConcurrent",
            "TestAHalfClosedStreamStillCountsAgainstTheLimit",
        ],
    ),
    (
        "SendEnd closes a stream the peer has not finished with",
        """	s.state = StateHalfClosedLocal""",
        """	s.state = StateClosed""",
        [
            "TestStateOfTracksTheOtherOrderOfClosing",
            "TestTheTableOnlyHoldsStreamsThatCountAsConcurrent",
        ],
    ),

    # --- HandleFrame: the dispatch -------------------------------------------
    (
        "HandleFrame has no CONTINUATION arm, so every split header block ends the connection",
        """	case frame.ContinuationFrame:
		return t.continuation(v)
""",
        "",
        ["TestABlockSplitAcrossContinuationsIsDecodedAsOne"],
    ),
    (
        "HandleFrame has no PRIORITY arm, so a browser's PRIORITY frame ends the connection",
        """	case frame.PriorityFrame:
		return t.priority(v)
""",
        "",
        ["TestPriorityIsAcceptedAndChangesNothing"],
    ),
    (
        "HandleFrame has no WINDOW_UPDATE arm, so a stream's credit ends the connection",
        """	case frame.WindowUpdateFrame:
		return t.windowUpdate(v)
""",
        "",
        ["TestWindowUpdateCreditsTheStreamsSendWindow"],
    ),
    (
        "HandleFrame accepts DATA and does nothing with it",
        """	case frame.DataFrame:
		return t.data(v)""",
        """	case frame.DataFrame:
		return nil""",
        ["TestDataIsDeliveredWithoutItsPadding"],
    ),
    (
        "HandleFrame accepts a frame type it does not handle, silently",
        """		return h2.ConnErrorf(h2.InternalError,
			"frame type %s on stream %d reached the stream table", f.Type(), f.Stream())""",
        """		return nil""",
        ["TestAConnectionFrameReachingTheTableIsAnInternalError"],
    ),

    # --- the connection-level frames the server forwards ---------------------
    (
        "ConnWindowUpdate credits our own receive window with the peer's grant",
        """	return t.connSend.Increase(increment)""",
        """	return t.connRecv.Increase(increment)""",
        ["TestConnWindowUpdateCreditsTheConnectionSendWindow"],
    ),
    (
        "ConnWindowUpdate swallows an increment past the maximum window",
        """	return t.connSend.Increase(increment)
}""",
        """	t.connSend.Increase(increment)
	return nil
}""",
        ["TestConnWindowUpdateOverflowEndsTheConnection"],
    ),
    (
        "SetInitialWindowSize does not reach the streams that are already open (RFC 9113 6.9.2)",
        """	for _, s := range t.streams {""",
        """	for _, s := range map[uint32]*Stream(nil) {""",
        [
            "TestSetInitialWindowSizeAppliesADeltaToOpenStreams",
            "TestSetInitialWindowSizeAppliesToEveryOpenStream",
            "TestSetInitialWindowSizeOverflowEndsTheConnection",
        ],
    ),
    (
        "SetInitialWindowSize does not remember the value, so streams opened later use the old one",
        """	t.peerInitialWindow = n
""",
        "",
        [
            "TestSetInitialWindowSizeSizesStreamsOpenedAfterwards",
            "TestSetInitialWindowSizeWithNoStreamsOpenIsRemembered",
        ],
    ),
    (
        "SetInitialWindowSize applies the peer's setting to our own grant instead of the peer's",
        """		if err := s.send.SetInitialSize(n); err != nil {""",
        """		if err := s.recv.SetInitialSize(n); err != nil {""",
        [
            "TestSetInitialWindowSizeAppliesADeltaToOpenStreams",
            "TestSetInitialWindowSizeAppliesToEveryOpenStream",
        ],
    ),
    (
        "SetInitialWindowSize applies the setting to the connection window too (RFC 9113 6.9.2)",
        """func (t *Table) SetInitialWindowSize(n uint32) error {
	for _, s := range t.streams {""",
        """func (t *Table) SetInitialWindowSize(n uint32) error {
	if err := t.connSend.SetInitialSize(n); err != nil {
		return err
	}
	for _, s := range t.streams {""",
        ["TestSetInitialWindowSizeLeavesTheConnectionWindowAlone"],
    ),

    # --- headers: which of the two kinds of block this is --------------------
    (
        "headers concatenates a new request's fragments onto the block already open (RFC 9113 6.10)",
        """	if t.assembling != nil {""",
        """	if false {""",
        ["TestHeadersWhileABlockIsOpenEndsTheConnection"],
    ),
    (
        "headers treats a trailer section as a new request, so every trailer ends the connection",
        """	if s := t.streams[f.StreamID]; s != nil {
		return t.beginTrailers(f, s)
	}
""",
        "",
        ["TestTrailersEndTheStreamAndCarryTheirOwnFields"],
    ),
    (
        "headers checks 5.1.1's identifier rule ahead of the trailer lookup, so trailers are impossible",
        """func (t *Table) headers(f frame.HeadersFrame) error {
	if t.assembling != nil {""",
        """func (t *Table) headers(f frame.HeadersFrame) error {
	if f.StreamID <= t.highestRemote {
		return h2.ConnErrorf(h2.ProtocolError,
			"HEADERS on stream %d, which is not above stream %d already used by the peer (RFC 9113 §5.1.1)",
			f.StreamID, t.highestRemote)
	}
	if t.assembling != nil {""",
        [
            "TestHeadersOnAnIdentifierThatIsStillLiveIsNotIdentifierReuse",
            "TestTrailersEndTheStreamAndCarryTheirOwnFields",
        ],
    ),

    # --- openStream: 5.1.1's identifier rules --------------------------------
    (
        "openStream lets a client open an even-numbered stream (RFC 9113 5.1.1)",
        """	if f.StreamID%2 == 0 {""",
        """	if false {""",
        ["TestHeadersOnAnEvenStreamEndsTheConnection"],
    ),
    (
        "openStream accepts an identifier the peer has already used, if it is the highest one",
        """	if f.StreamID <= t.highestRemote {""",
        """	if f.StreamID < t.highestRemote {""",
        [
            "TestHeadersOnAStreamThatHasFinishedEndsTheConnection",
            "TestHeadersOnAnIdentifierThatIsStillLiveIsNotIdentifierReuse",
        ],
    ),
    (
        "openStream does not check that the identifier increases at all (RFC 9113 5.1.1)",
        """	if f.StreamID <= t.highestRemote {
		return h2.ConnErrorf(h2.ProtocolError,""",
        """	if false {
		return h2.ConnErrorf(h2.ProtocolError,""",
        ["TestHeadersOnADecreasingIdentifierEndsTheConnection"],
    ),
    (
        "openStream does not record the identifier, so no lower one is ever implicitly closed",
        """	t.highestRemote = f.StreamID
""",
        "",
        [
            "TestStateOfIsClosedForAnIdentifierThePeerSkipped",
            "TestHeadersOnADecreasingIdentifierEndsTheConnection",
        ],
    ),
    (
        "openStream records the identifier only for a stream it admitted",
        """	t.highestRemote = f.StreamID

	t.assembling = &block{
		id:        f.StreamID,
		endStream: f.EndStream,
		verdict:   t.admit(f),
	}""",
        """	t.assembling = &block{
		id:        f.StreamID,
		endStream: f.EndStream,
		verdict:   t.admit(f),
	}
	if t.assembling.verdict == nil {
		t.highestRemote = f.StreamID
	}""",
        ["TestARefusedStreamStillSpendsItsIdentifier"],
    ),
    (
        "openStream reaches no verdict, so no stream is ever refused",
        """		verdict:   t.admit(f),
""",
        "",
        [
            "TestTheConcurrencyLimitRefusesTheStreamPastTheMaximum",
            "TestASelfDependentStreamIsRefusedAndItsBlockDecoded",
        ],
    ),
    (
        "openStream drops the HEADERS frame's END_STREAM flag",
        """		id:        f.StreamID,
		endStream: f.EndStream,
		verdict:   t.admit(f),""",
        """		id:        f.StreamID,
		verdict:   t.admit(f),""",
        ["TestHeadersWithEndStreamLeavesTheStreamHalfClosed"],
    ),
    (
        "openStream completes the block on the HEADERS frame, whatever END_HEADERS said",
        """		verdict:   t.admit(f),
	}
	return t.extend(f.Fragment, f.EndHeaders)""",
        """		verdict:   t.admit(f),
	}
	return t.extend(f.Fragment, true)""",
        [
            "TestABlockSplitAcrossContinuationsIsDecodedAsOne",
            "TestABlockIsNotDecodedUntilItIsComplete",
        ],
    ),

    # --- admit: the stream-level verdict, and which of two faults wins -------
    (
        "admit accepts a stream that depends on itself (RFC 7540 5.3.1)",
        """	if f.Priority && f.StreamDependency == f.StreamID {""",
        """	if false {""",
        ["TestASelfDependentStreamIsRefusedAndItsBlockDecoded"],
    ),
    # Not a live break, and it is here rather than deleted because it was run and
    # found nothing, which is worth recording:
    #
    #     "admit: the self-dependency check drops the flag it depends on"
    #     `if f.Priority && f.StreamDependency == f.StreamID {`
    #       ->  `if f.StreamDependency == f.StreamID {`
    #
    # No test can name this one, and none should be written to. internal/frame leaves
    # StreamDependency at zero on a HEADERS frame without the PRIORITY flag, and it
    # rejects a dependency on stream 0 before the frame gets here -- so for every
    # frame that can reach admit the two forms agree. The flag is kept because the
    # field it guards is only meaningful when it is set, not because dropping it has
    # a symptom.
    (
        "admit tells a client its self-dependent frame was merely refused, not malformed",
        """		return h2.StreamErrorf(f.StreamID, h2.ProtocolError,
			"stream %d depends on itself (RFC 7540 §5.3.1)", f.StreamID)""",
        """		return h2.StreamErrorf(f.StreamID, h2.RefusedStream,
			"stream %d depends on itself (RFC 7540 §5.3.1)", f.StreamID)""",
        [
            "TestASelfDependentStreamIsRefusedAndItsBlockDecoded",
            "TestASelfDependencyIsReportedAheadOfTheConcurrencyLimit",
        ],
    ),
    (
        "admit admits one stream more than the connection advertised",
        """	if uint32(len(t.streams)) >= t.maxConcurrent {""",
        """	if uint32(len(t.streams)) > t.maxConcurrent {""",
        [
            "TestTheConcurrencyLimitRefusesTheStreamPastTheMaximum",
            "TestNewDefaultsTheConcurrencyLimitToThePolicyBound",
        ],
    ),
    (
        "admit enforces no concurrency limit at all (RFC 9113 5.1.2)",
        """	if uint32(len(t.streams)) >= t.maxConcurrent {
		return h2.StreamErrorf(f.StreamID, h2.RefusedStream,""",
        """	if false {
		return h2.StreamErrorf(f.StreamID, h2.RefusedStream,""",
        ["TestTheConcurrencyLimitRefusesTheStreamPastTheMaximum"],
    ),
    (
        "admit tells a client its request was malformed when this server was simply full (RFC 9113 8.7)",
        """		return h2.StreamErrorf(f.StreamID, h2.RefusedStream,
			"stream %d would exceed the %d concurrent streams advertised (RFC 9113 §5.1.2)",
			f.StreamID, t.maxConcurrent)""",
        """		return h2.StreamErrorf(f.StreamID, h2.ProtocolError,
			"stream %d would exceed the %d concurrent streams advertised (RFC 9113 §5.1.2)",
			f.StreamID, t.maxConcurrent)""",
        [
            "TestTheConcurrencyLimitRefusesTheStreamPastTheMaximum",
            "TestNewDefaultsTheConcurrencyLimitToThePolicyBound",
        ],
    ),
    (
        "admit reports a malformed frame as a busy server, so the client retries it for ever",
        """	if f.Priority && f.StreamDependency == f.StreamID {
		return h2.StreamErrorf(f.StreamID, h2.ProtocolError,
			"stream %d depends on itself (RFC 7540 §5.3.1)", f.StreamID)
	}""",
        """	if uint32(len(t.streams)) >= t.maxConcurrent {
		return h2.StreamErrorf(f.StreamID, h2.RefusedStream,
			"stream %d would exceed the %d concurrent streams advertised (RFC 9113 §5.1.2)",
			f.StreamID, t.maxConcurrent)
	}
	if f.Priority && f.StreamDependency == f.StreamID {
		return h2.StreamErrorf(f.StreamID, h2.ProtocolError,
			"stream %d depends on itself (RFC 7540 §5.3.1)", f.StreamID)
	}""",
        ["TestASelfDependencyIsReportedAheadOfTheConcurrencyLimit"],
    ),

    # --- beginTrailers: the second header block on a stream (8.1) -----------
    (
        "beginTrailers accepts a third header block after the peer's END_STREAM (RFC 9113 5.1)",
        """	case s.peerDone():""",
        """	case false:""",
        ["TestTrailersOnAHalfClosedStreamAreAStreamError"],
    ),
    (
        "beginTrailers accepts a trailer section that does not end the stream (RFC 9113 8.1)",
        """	case !f.EndStream:""",
        """	case false:""",
        ["TestTrailersWithoutEndStreamAreAStreamError"],
    ),
    (
        "beginTrailers reports a frame that was not allowed to arrive as malformed instead",
        """	switch {
	case s.peerDone():""",
        """	switch {
	case !f.EndStream:
		verdict = h2.StreamErrorf(f.StreamID, h2.ProtocolError,
			"trailers on stream %d without END_STREAM (RFC 9113 §8.1)", f.StreamID)

	case s.peerDone():""",
        ["TestTrailersOnAHalfClosedStreamAreClosedRatherThanMalformed"],
    ),
    (
        "beginTrailers loses the stream the trailers belong to, so they open a second one",
        """		s:         s,
""",
        "",
        ["TestTrailersEndTheStreamAndCarryTheirOwnFields"],
    ),
    (
        "beginTrailers completes the trailer block on its first frame",
        """		s:         s,
		endStream: f.EndStream,
		verdict:   verdict,
	}
	return t.extend(f.Fragment, f.EndHeaders)""",
        """		s:         s,
		endStream: f.EndStream,
		verdict:   verdict,
	}
	return t.extend(f.Fragment, true)""",
        ["TestTrailersSplitAcrossContinuationsAreDecodedAsOne"],
    ),
    # Not a live break, for the reason in the docstring:
    #
    #     "beginTrailers records the wrong END_STREAM flag on the block"
    #     `endStream: f.EndStream,`  ->  `endStream: false,`  (in beginTrailers)
    #
    # Unobservable, and not because the suite is thin. completeBlock's trailer path
    # calls recvEnd unconditionally, which it may because beginTrailers has already
    # made a trailer section without END_STREAM a stream error -- so block.endStream
    # is only ever read for a block that opens a request. The assignment stays
    # because a struct field that is true of one kind of block and false-by-omission
    # of the other is a field every reader has to check the constructor for.

    # --- continuation: 6.10's continuity rule --------------------------------
    (
        "continuation accepts a fragment with no block open, and dereferences nil",
        """	if t.assembling == nil {""",
        """	if false {""",
        ["TestContinuationWithNoBlockOpenEndsTheConnection"],
    ),
    (
        "continuation concatenates two streams' fragments into one block that decodes cleanly",
        """	if f.StreamID != t.assembling.id {""",
        """	if false {""",
        ["TestContinuationOnTheWrongStreamEndsTheConnection"],
    ),
    (
        "continuation only refuses a fragment on a higher identifier than the open block's",
        """	if f.StreamID != t.assembling.id {
		// Also the reader's rule""",
        """	if f.StreamID > t.assembling.id {
		// Also the reader's rule""",
        ["TestContinuationOnTheWrongStreamEndsTheConnection"],
    ),

    # --- extend: accumulating the block --------------------------------------
    (
        "extend discards every fragment, so every block decodes as empty",
        """	t.assembling.buf = append(t.assembling.buf, fragment...)
""",
        "",
        [
            "TestABlockSplitAcrossContinuationsIsDecodedAsOne",
            "TestHeadersOpensAStreamAndDeliversItsFields",
        ],
    ),
    (
        "extend keeps only the last fragment instead of appending",
        """	t.assembling.buf = append(t.assembling.buf, fragment...)""",
        """	t.assembling.buf = fragment""",
        ["TestABlockSplitAcrossContinuationsIsDecodedAsOne"],
    ),
    (
        "extend completes the block on every fragment, so a split block is decoded in pieces",
        """	if !endHeaders {""",
        """	if false {""",
        [
            "TestABlockIsNotDecodedUntilItIsComplete",
            "TestABlockSplitAcrossContinuationsIsDecodedAsOne",
        ],
    ),

    # --- completeBlock: the decode, the verdict, and their order -------------
    (
        "completeBlock leaves the block open, so the next HEADERS reports the wrong fault",
        """	t.assembling = nil
""",
        "",
        [
            "TestABlockIsClosedEvenWhenItsStreamIsRefused",
            "TestTheCodecIsDrivenOncePerBlockAndInArrivalOrder",
        ],
    ),
    (
        "completeBlock closes the block only when nothing failed",
        """	if b.verdict != nil {
		return b.verdict
	}""",
        """	if b.verdict != nil {
		t.assembling = b
		return b.verdict
	}""",
        ["TestABlockIsClosedEvenWhenItsStreamIsRefused"],
    ),
    (
        "completeBlock returns the verdict before the decode, desynchronising HPACK (RFC 9113 5.1)",
        """	fields, err := t.codec.Decode(b.buf)
	if err != nil {""",
        """	if b.verdict != nil {
		return b.verdict
	}
	fields, err := t.codec.Decode(b.buf)
	if err != nil {""",
        [
            "TestARefusedStreamsBlockIsStillDecoded",
            "TestACompressionErrorBeatsADeferredStreamError",
            "TestASelfDependentStreamIsRefusedAndItsBlockDecoded",
            "TestTheCodecIsDrivenOncePerBlockAndInArrivalOrder",
        ],
    ),
    (
        "completeBlock never returns the verdict, so a refused stream is served anyway",
        """	if b.verdict != nil {
		return b.verdict
	}

""",
        "",
        [
            "TestTheConcurrencyLimitRefusesTheStreamPastTheMaximum",
            "TestARefusedStreamIsNotReportedUntilItsBlockIsComplete",
        ],
    ),
    (
        "completeBlock keeps a connection running on a dynamic table nobody can agree about",
        """		return h2.ConnErrorf(h2.CompressionError,
			"HPACK decoding failed on stream %d: %v (RFC 9113 §4.3)", b.id, err)""",
        """		return h2.StreamErrorf(b.id, h2.CompressionError,
			"HPACK decoding failed on stream %d: %v (RFC 9113 §4.3)", b.id, err)""",
        [
            "TestABlockThatFailsToDecodeEndsTheConnection",
            "TestACompressionErrorBeatsADeferredStreamError",
        ],
    ),
    (
        "completeBlock sizes our own grant from the peer's setting (RFC 9113 6.9.2)",
        """		recv: flow.NewStreamWindow(b.id, flow.InitialWindowSize),""",
        """		recv: flow.NewStreamWindow(b.id, t.peerInitialWindow),""",
        ["TestSetInitialWindowSizeSizesStreamsOpenedAfterwards"],
    ),
    (
        "completeBlock ignores the peer's SETTINGS_INITIAL_WINDOW_SIZE for a new stream",
        """		send: flow.NewStreamWindow(b.id, t.peerInitialWindow),""",
        """		send: flow.NewStreamWindow(b.id, flow.InitialWindowSize),""",
        [
            "TestSetInitialWindowSizeSizesStreamsOpenedAfterwards",
            "TestSetInitialWindowSizeWithNoStreamsOpenIsRemembered",
        ],
    ),
    (
        "completeBlock delivers the request without putting the stream in the table",
        """	t.streams[b.id] = s
""",
        "",
        ["TestHeadersOpensAStreamAndDeliversItsFields"],
    ),
    (
        "completeBlock ignores END_STREAM on the HEADERS frame, so the request never ends",
        """	if b.endStream {
		s.recvEnd()
	}""",
        """	if false {
		s.recvEnd()
	}""",
        ["TestHeadersWithEndStreamLeavesTheStreamHalfClosed"],
    ),
    (
        "completeBlock delivers the request before the state it produced is settled",
        """	if b.endStream {
		s.recvEnd()
	}
	return t.reqs.Headers(s, fields, b.endStream)""",
        """	err = t.reqs.Headers(s, fields, b.endStream)
	if b.endStream {
		s.recvEnd()
	}
	return err""",
        ["TestHeadersWithEndStreamLeavesTheStreamHalfClosed"],
    ),
    (
        "completeBlock does not end the stream a trailer section arrived on",
        """		b.s.recvEnd()
		t.retire(b.s)""",
        """		t.retire(b.s)""",
        ["TestTrailersEndTheStreamAndCarryTheirOwnFields"],
    ),
    (
        "completeBlock leaves a stream its trailers closed in the table",
        """		b.s.recvEnd()
		t.retire(b.s)
		return t.reqs.Trailers(b.s, fields)""",
        """		b.s.recvEnd()
		return t.reqs.Trailers(b.s, fields)""",
        ["TestTrailersCloseAStreamWeHadAlreadyFinished"],
    ),
    (
        "completeBlock delivers a trailer section as though it were a second request",
        """		return t.reqs.Trailers(b.s, fields)""",
        """		return t.reqs.Headers(b.s, fields, true)""",
        ["TestTrailersEndTheStreamAndCarryTheirOwnFields"],
    ),

    # --- data: flow control first, then the state ---------------------------
    (
        "data counts only the body, not the padding it was sent with (RFC 9113 6.1)",
        """	n := f.PayloadLen()""",
        """	n := uint32(len(f.Data))""",
        ["TestPaddedDataIsFlowControlledByItsWholeLength"],
    ),
    (
        "data never debits the connection window (RFC 9113 6.9.1)",
        """	if err := t.connRecv.Consume(n); err != nil {
		return err
	}
""",
        "",
        [
            "TestDataPastTheConnectionWindowEndsTheConnection",
            "TestPaddedDataIsFlowControlledByItsWholeLength",
        ],
    ),
    (
        "data debits the connection window only for a frame it is going to accept",
        """	n := f.PayloadLen()
	if err := t.connRecv.Consume(n); err != nil {
		return err
	}

	s := t.streams[f.StreamID]
	if s == nil {
		return t.absent("DATA", f.StreamID)
	}""",
        """	n := f.PayloadLen()
	s := t.streams[f.StreamID]
	if s == nil {
		return t.absent("DATA", f.StreamID)
	}""",
        ["TestDataOnAClosedStreamIsStillCountedAgainstTheConnectionWindow"],
    ),
    (
        "data debits the connection window below the state check, so a frame after END_STREAM is free",
        """	n := f.PayloadLen()
	if err := t.connRecv.Consume(n); err != nil {
		return err
	}
""",
        """	n := f.PayloadLen()
	live := t.streams[f.StreamID]
	if live != nil && !live.peerDone() {
		if err := t.connRecv.Consume(n); err != nil {
			return err
		}
	}
""",
        [
            "TestDataAfterEndStreamIsStillCountedAgainstTheConnectionWindow",
            "TestDataOnAClosedStreamIsStillCountedAgainstTheConnectionWindow",
        ],
    ),
    (
        "data never debits the stream window, so one stream may send as much as it likes",
        """	if err := s.recv.Consume(n); err != nil {
		return err
	}
""",
        "",
        [
            "TestPaddedDataIsFlowControlledByItsWholeLength",
            "TestDataRefusedByAStreamWindowIsStillCountedAgainstTheConnectionWindow",
        ],
    ),
    (
        "data debits the stream's send window with the peer's DATA",
        """	if err := s.recv.Consume(n); err != nil {""",
        """	if err := s.send.Consume(n); err != nil {""",
        [
            "TestPaddedDataIsFlowControlledByItsWholeLength",
            "TestDataRefusedByAStreamWindowIsStillCountedAgainstTheConnectionWindow",
        ],
    ),
    (
        "data accepts a body the peer had already finished sending (RFC 9113 5.1)",
        """	if s.peerDone() {""",
        """	if false {""",
        [
            "TestDataOnAHalfClosedStreamIsAStreamError",
            "TestDataAfterEndStreamIsStillCountedAgainstTheConnectionWindow",
        ],
    ),
    (
        "data ignores END_STREAM, so no request body ever ends",
        """	if f.EndStream {
		s.recvEnd()
		t.retire(s)
	}""",
        """	if false {
		s.recvEnd()
		t.retire(s)
	}""",
        [
            "TestStateOfTracksAStreamThroughEveryTransition",
            "TestDataWithEndStreamClosesAStreamWeHadFinished",
        ],
    ),
    (
        "data leaves a stream the last DATA frame closed in the table",
        """	if f.EndStream {
		s.recvEnd()
		t.retire(s)
	}
	return t.reqs.Data(s, f.Data, f.EndStream)""",
        """	if f.EndStream {
		s.recvEnd()
	}
	return t.reqs.Data(s, f.Data, f.EndStream)""",
        [
            "TestDataWithEndStreamClosesAStreamWeHadFinished",
            "TestTheTableOnlyHoldsStreamsThatCountAsConcurrent",
        ],
    ),
    (
        "data delivers the last frame of a body before the state it produced is settled",
        """	if f.EndStream {
		s.recvEnd()
		t.retire(s)
	}
	return t.reqs.Data(s, f.Data, f.EndStream)
}""",
        """	err := t.reqs.Data(s, f.Data, f.EndStream)
	if f.EndStream {
		s.recvEnd()
		t.retire(s)
	}
	return err
}""",
        ["TestDataWithEndStreamClosesAStreamWeHadFinished"],
    ),
    (
        "data tells the handler no frame is ever the last of a body",
        """	return t.reqs.Data(s, f.Data, f.EndStream)""",
        """	return t.reqs.Data(s, f.Data, false)""",
        ["TestDataWithEndStreamClosesAStreamWeHadFinished"],
    ),

    # --- rstStream: 6.4, and CVE-2023-44487 ---------------------------------
    (
        "rstStream accepts a reset for a stream that has never been used (RFC 9113 6.4)",
        """	if t.StateOf(f.StreamID) == StateIdle {
		// §6.4 in as many words""",
        """	if false {
		// §6.4 in as many words""",
        ["TestRstStreamOnAnIdleStreamEndsTheConnection"],
    ),
    (
        "rstStream reports one malformed frame as a flood",
        """	if t.StateOf(f.StreamID) == StateIdle {
		// §6.4 in as many words""",
        """	if !t.resets.Allow(t.now()) {
		return h2.ConnErrorf(h2.EnhanceYourCalm,
			"more than %d stream resets in a burst (CVE-2023-44487)", t.resets.Burst())
	}
	if t.StateOf(f.StreamID) == StateIdle {
		// §6.4 in as many words""",
        ["TestRstStreamOnAnIdleStreamIsReportedAheadOfTheRateLimit"],
    ),
    (
        "rstStream bounds how many resets are in flight and not how many arrive (CVE-2023-44487)",
        """	if !t.resets.Allow(t.now()) {""",
        """	if false {""",
        [
            "TestARstStreamFloodEndsTheConnection",
            "TestARstStreamOfAClosedStreamStillCostsAToken",
        ],
    ),
    (
        "rstStream gives a reset of an already-closed stream away for nothing",
        """	if !t.resets.Allow(t.now()) {
		return h2.ConnErrorf(h2.EnhanceYourCalm,""",
        """	if t.streams[f.StreamID] != nil && !t.resets.Allow(t.now()) {
		return h2.ConnErrorf(h2.EnhanceYourCalm,""",
        ["TestARstStreamOfAClosedStreamStillCostsAToken"],
    ),
    (
        "rstStream punishes a reset that crossed our own on the wire (RFC 9113 6.4)",
        """	s := t.streams[f.StreamID]
	if s == nil {
		// Closed already""",
        """	if t.streams[f.StreamID] == nil {
		return t.absent("RST_STREAM", f.StreamID)
	}
	s := t.streams[f.StreamID]
	if s == nil {
		// Closed already""",
        [
            "TestRstStreamOnAClosedStreamIsIgnored",
            "TestRstStreamOnASkippedIdentifierIsIgnored",
        ],
    ),
    (
        "rstStream leaves the stream it closed in the table",
        """	s.state = StateClosed
	t.retire(s)
	t.reqs.Canceled(s, f.ErrCode)""",
        """	s.state = StateClosed
	t.reqs.Canceled(s, f.ErrCode)""",
        [
            "TestARefusedStreamDoesNotCountAgainstTheLimit",
            "TestTheTableOnlyHoldsStreamsThatCountAsConcurrent",
        ],
    ),
    (
        "rstStream does not tell the handler its response has been abandoned",
        """	t.reqs.Canceled(s, f.ErrCode)
""",
        "",
        ["TestRstStreamClosesTheStreamAndTellsTheHandler"],
    ),

    # --- priority: accepted, and affecting nothing --------------------------
    (
        "priority spends the identifier, so the HEADERS a browser sends next is refused",
        """func (t *Table) priority(frame.PriorityFrame) error { return nil }""",
        """func (t *Table) priority(f frame.PriorityFrame) error {
	if f.StreamID > t.highestRemote {
		t.highestRemote = f.StreamID
	}
	return nil
}""",
        ["TestPriorityOnAnIdleStreamDoesNotUseUpTheIdentifier"],
    ),
    (
        "priority is refused on a stream that is not live, though 5.1 keeps it legal in any state",
        """func (t *Table) priority(frame.PriorityFrame) error { return nil }""",
        """func (t *Table) priority(f frame.PriorityFrame) error { return t.absent("PRIORITY", f.StreamID) }""",
        [
            "TestPriorityIsAcceptedAndChangesNothing",
            "TestPriorityOnAClosedStreamIsAccepted",
        ],
    ),

    # --- windowUpdate --------------------------------------------------------
    (
        "windowUpdate accepts credit for a stream that has never been used (RFC 9113 5.1)",
        """		if t.StateOf(f.StreamID) == StateIdle {""",
        """		if false {""",
        ["TestWindowUpdateOnAnIdleStreamEndsTheConnection"],
    ),
    (
        "windowUpdate refuses the credit 6.9 exempts by name, for a stream that is over",
        """		return nil
	}
	return s.send.Increase(f.Increment)""",
        """		return t.absent("WINDOW_UPDATE", f.StreamID)
	}
	return s.send.Increase(f.Increment)""",
        ["TestWindowUpdateOnAClosedStreamIsIgnored"],
    ),
    (
        "windowUpdate credits the window we grant the peer instead of the one it granted us",
        """	return s.send.Increase(f.Increment)""",
        """	return s.recv.Increase(f.Increment)""",
        ["TestWindowUpdateCreditsTheStreamsSendWindow"],
    ),
    (
        "windowUpdate swallows an increment that takes a stream window past the maximum",
        """	return s.send.Increase(f.Increment)
}""",
        """	s.send.Increase(f.Increment)
	return nil
}""",
        ["TestWindowUpdateOverflowingAStreamWindowIsAStreamError"],
    ),

    # --- absent: the split between a stream that never was and one that is over
    (
        "absent has the two halves of 5.1 the wrong way round",
        """	if t.StateOf(id) == StateIdle {""",
        """	if t.StateOf(id) != StateIdle {""",
        [
            "TestDataOnAnIdleStreamEndsTheConnection",
            "TestDataOnAClosedStreamResetsTheStreamAndKeepsTheConnection",
        ],
    ),
    (
        "absent answers a frame on a stream that never existed with one stream's reset",
        """		return h2.ConnErrorf(h2.ProtocolError,
			"%s on idle stream %d (RFC 9113 §5.1)", kind, id)""",
        """		return h2.StreamErrorf(id, h2.ProtocolError,
			"%s on idle stream %d (RFC 9113 §5.1)", kind, id)""",
        ["TestDataOnAnIdleStreamEndsTheConnection"],
    ),
    (
        "absent ends the connection over a race this server started",
        """	return h2.StreamErrorf(id, h2.StreamClosed,
		"%s on closed stream %d (RFC 9113 §5.1)", kind, id)""",
        """	return h2.ConnErrorf(h2.StreamClosed,
		"%s on closed stream %d (RFC 9113 §5.1)", kind, id)""",
        ["TestDataOnAClosedStreamResetsTheStreamAndKeepsTheConnection"],
    ),

    # --- retire: the map's invariant ----------------------------------------
    (
        "retire drops a stream that is only half closed, which this server still owes a response",
        """	if s.state == StateClosed {""",
        """	if true {""",
        [
            "TestStateOfTracksAStreamThroughEveryTransition",
            "TestTrailersEndTheStreamAndCarryTheirOwnFields",
        ],
    ),
    (
        "retire drops nothing, so the table is a memory footprint the peer controls",
        """		delete(t.streams, s.id)
""",
        "",
        [
            "TestTheTableOnlyHoldsStreamsThatCountAsConcurrent",
            "TestARefusedStreamDoesNotCountAgainstTheLimit",
        ],
    ),

    # --- what the log says ---------------------------------------------------
    #
    # Every one of these leaves a working server and an undiagnosable one. These
    # strings are read next to h2spec output, or in a bug report from someone whose
    # client this server refused, by a reader who has RFC 9113 open and does not have
    # the connection. The section reference is the part that cannot be reconstructed
    # from anything else in the line.
    (
        "the dispatch hole is reported without saying where the frame arrived",
        """		return h2.ConnErrorf(h2.InternalError,
			"frame type %s on stream %d reached the stream table", f.Type(), f.Stream())""",
        """		return h2.ConnErrorf(h2.InternalError, "internal error")""",
        ["TestEveryErrorNamesTheRuleAndTheStream"],
    ),
    (
        "a HEADERS frame interrupting a block is reported without 6.10 or either stream",
        """		return h2.ConnErrorf(h2.ProtocolError,
			"HEADERS on stream %d while stream %d's header block is open (RFC 9113 §6.10)",
			f.StreamID, t.assembling.id)""",
        """		return h2.ConnErrorf(h2.ProtocolError, "unexpected HEADERS")""",
        ["TestEveryErrorNamesTheRuleAndTheStream"],
    ),
    (
        "an even-numbered stream is refused without saying that only a server may open one",
        """		return h2.ConnErrorf(h2.ProtocolError,
			"HEADERS on even-numbered stream %d, which only a server may open (RFC 9113 §5.1.1)",
			f.StreamID)""",
        """		return h2.ConnErrorf(h2.ProtocolError, "bad stream identifier")""",
        ["TestEveryErrorNamesTheRuleAndTheStream"],
    ),
    (
        "a non-increasing identifier is refused without naming 5.1.1 or the highest one seen",
        """		return h2.ConnErrorf(h2.ProtocolError,
			"HEADERS on stream %d, which is not above stream %d already used by the peer (RFC 9113 §5.1.1)",
			f.StreamID, t.highestRemote)""",
        """		return h2.ConnErrorf(h2.ProtocolError, "bad stream identifier")""",
        ["TestEveryErrorNamesTheRuleAndTheStream"],
    ),
    (
        "a self-dependent stream is refused without citing the rule it broke",
        """			"stream %d depends on itself (RFC 7540 §5.3.1)", f.StreamID)""",
        """			"bad priority on stream %d", f.StreamID)""",
        ["TestEveryErrorNamesTheRuleAndTheStream"],
    ),
    (
        "the concurrency refusal does not say how many streams were advertised",
        """			"stream %d would exceed the %d concurrent streams advertised (RFC 9113 §5.1.2)",
			f.StreamID, t.maxConcurrent)""",
        """			"too many streams")""",
        ["TestEveryErrorNamesTheRuleAndTheStream"],
    ),
    (
        "a header block on a finished stream is refused without naming the state it was in",
        """		verdict = h2.StreamErrorf(f.StreamID, h2.StreamClosed,
			"HEADERS on stream %d in state %s (RFC 9113 §5.1)", f.StreamID, s.state)""",
        """		verdict = h2.StreamErrorf(f.StreamID, h2.StreamClosed, "stream closed")""",
        ["TestEveryErrorNamesTheRuleAndTheStream"],
    ),
    (
        "trailers without END_STREAM are refused without citing 8.1",
        """		verdict = h2.StreamErrorf(f.StreamID, h2.ProtocolError,
			"trailers on stream %d without END_STREAM (RFC 9113 §8.1)", f.StreamID)""",
        """		verdict = h2.StreamErrorf(f.StreamID, h2.ProtocolError, "bad trailers")""",
        ["TestEveryErrorNamesTheRuleAndTheStream"],
    ),
    (
        "a stray CONTINUATION is refused without citing 6.10",
        """		return h2.ConnErrorf(h2.ProtocolError,
			"CONTINUATION on stream %d with no header block open (RFC 9113 §6.10)",
			f.StreamID)""",
        """		return h2.ConnErrorf(h2.ProtocolError, "unexpected CONTINUATION")""",
        ["TestEveryErrorNamesTheRuleAndTheStream"],
    ),
    (
        "a CONTINUATION on the wrong stream is refused without naming either stream",
        """		return h2.ConnErrorf(h2.ProtocolError,
			"CONTINUATION on stream %d while stream %d's header block is open (RFC 9113 §6.10)",
			f.StreamID, t.assembling.id)""",
        """		return h2.ConnErrorf(h2.ProtocolError, "unexpected CONTINUATION")""",
        ["TestEveryErrorNamesTheRuleAndTheStream"],
    ),
    (
        "a failed decode is reported without 4.3, the stream, or what the codec said",
        """		return h2.ConnErrorf(h2.CompressionError,
			"HPACK decoding failed on stream %d: %v (RFC 9113 §4.3)", b.id, err)""",
        """		return h2.ConnErrorf(h2.CompressionError, "compression error")""",
        ["TestEveryErrorNamesTheRuleAndTheStream"],
    ),
    (
        "DATA after END_STREAM is refused without naming the state or 5.1",
        """		return h2.StreamErrorf(f.StreamID, h2.StreamClosed,
			"DATA on stream %d in state %s (RFC 9113 §5.1)", f.StreamID, s.state)""",
        """		return h2.StreamErrorf(f.StreamID, h2.StreamClosed, "stream closed")""",
        ["TestEveryErrorNamesTheRuleAndTheStream"],
    ),
    (
        "RST_STREAM on an idle stream is refused without citing 6.4",
        """		return h2.ConnErrorf(h2.ProtocolError,
			"RST_STREAM on idle stream %d (RFC 9113 §6.4)", f.StreamID)""",
        """		return h2.ConnErrorf(h2.ProtocolError, "unexpected RST_STREAM")""",
        ["TestEveryErrorNamesTheRuleAndTheStream"],
    ),
    (
        "the reset flood refusal names neither the advisory nor the burst an operator would raise",
        """		return h2.ConnErrorf(h2.EnhanceYourCalm,
			"more than %d stream resets in a burst (CVE-2023-44487)", t.resets.Burst())""",
        """		return h2.ConnErrorf(h2.EnhanceYourCalm, "too many resets")""",
        ["TestTheResetFloodErrorNamesTheBurstItExceeded"],
    ),
    (
        "WINDOW_UPDATE on an idle stream is refused without citing 5.1",
        """			return h2.ConnErrorf(h2.ProtocolError,
				"WINDOW_UPDATE on idle stream %d (RFC 9113 §5.1)", f.StreamID)""",
        """			return h2.ConnErrorf(h2.ProtocolError, "unexpected WINDOW_UPDATE")""",
        ["TestEveryErrorNamesTheRuleAndTheStream"],
    ),
    (
        "a frame on a stream that never existed is refused without saying which frame or rule",
        """		return h2.ConnErrorf(h2.ProtocolError,
			"%s on idle stream %d (RFC 9113 §5.1)", kind, id)""",
        """		return h2.ConnErrorf(h2.ProtocolError, "unexpected frame")""",
        ["TestEveryErrorNamesTheRuleAndTheStream"],
    ),
    (
        "a frame on a stream that is over is refused without saying which frame or rule",
        """	return h2.StreamErrorf(id, h2.StreamClosed,
		"%s on closed stream %d (RFC 9113 §5.1)", kind, id)""",
        """	return h2.StreamErrorf(id, h2.StreamClosed, "stream closed")""",
        ["TestEveryErrorNamesTheRuleAndTheStream"],
    ),
]

breakage.main(SRC, PKG, BREAKS)
