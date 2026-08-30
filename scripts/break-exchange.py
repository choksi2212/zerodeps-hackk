"""Deliberately break internal/exchange, one guard at a time, and report which tests
notice.

Each entry below removes exactly one guard and names the tests that must fail as a
result. See breakage.py for the harness and for what the five outcomes mean.

Two files, because the package is two halves of one job and the guards in each only
mean anything with the other in place. body.go is the handover between the connection's
reader goroutine and a handler's; exchange.go is what a decoded header block, a DATA
payload and a peer's RST_STREAM turn into on the way to that handler and back.

  Almost every guard in body.go fails the same way when it is removed: a Read that
  never returns. An END_STREAM that was not recorded, a Signal that never reached the
  waiter, an offset that never advanced -- each is a handler parked for the life of the
  connection, which is the leak the type exists to prevent and is also the least legible
  failure a test can have. That is why the tests wrap every read and every handover in a
  deadline: without one, the breaks below would be caught as hangs, and a hang is a
  detection nobody can read. The deadline is what turns them into fires. It is worth
  saying plainly that this was the reason the deadlines were added, and not tidiness.

  The same applies to waitSent in exchange_test.go, and it earns its keep several times
  over: a break that leaves a handler blocked -- Data that never ends the body, Headers
  that never ends a GET's, a nil Body -- is caught by the response that never came rather
  than by a test that stops.

  The content-length rule of 8.1.1 is broken from both directions and at both ends.
  Inverting the comparison, widening it by one, dropping the running total, and removing
  either of the two equality checks are five different bugs that all look like "the
  arithmetic is slightly off", and four of them leave a server that serves files
  perfectly well. The pair that matters most is the two equality checks: they are the
  same three lines in two places, which is exactly the kind of duplication that gets
  deleted by someone tidying up, and only one of them is reachable by a request that ends
  with DATA.

  Three of the entries below take the delete out of a path that ends a request without
  removing anything else. All three leave a server that answers every request correctly
  and grows a map for as long as the connection lasts, which is the shape of bug that
  gets found in production and never in a test suite -- so each one is named against a
  test that counts what is left in arriving rather than against one that checks a
  response.

Two guards are not in this campaign, and both absences are deliberate.

  `b.chunks[0] = nil`, the line that drops a consumed payload's slice header before the
  slice advances past it, has no test and cannot have one. What it changes is whether the
  frame's octets are reachable from the backing array, and once `b.chunks = b.chunks[1:]`
  has run the slot it cleared is not addressable from inside the package, let alone from
  a test. TestAReadChunkIsDroppedRatherThanKept covers the advance and the offset reset
  beside it; the nil is asserted by the comment above it and by nothing else. Claiming a
  test for it here would be worse than admitting there is none.

  add's Signal is not broken into a Broadcast, because that is not a bug: waking every
  waiter for a payload only one of them can take is wasteful and correct. The direction
  that is a bug -- Broadcast narrowed to Signal in end and in fail -- is broken, once
  each, and the two need different tests because one body with several readers is the
  only shape either can go wrong in.

Run from the repository root. Restores both files on the way out, including on error.
"""

import breakage

SRC = ["internal/exchange/body.go", "internal/exchange/exchange.go"]
PKG = "./internal/exchange/"

# (name, old, new, tests that must fail)
BREAKS = [
    # --- body.go: io.Reader's two easy contracts ---------------------------
    (
        "Read waits for content before noticing there is nowhere to put it, so io.Copy's empty probe deadlocks",
        """	if len(p) == 0 {
		return 0, nil
	}

""",
        "",
        ["TestAZeroLengthReadDoesNotBlock"],
    ),
    (
        "take hands over the front of a body whose stream is already gone before reporting why",
        """		if b.err != nil {
			return 0, false, b.err
		}
		if len(b.chunks) > 0 {
			break
		}""",
        """		if len(b.chunks) > 0 {
			break
		}
		if b.err != nil {
			return 0, false, b.err
		}""",
        ["TestAFailedBodyReportsItsErrorAheadOfWhatArrived"],
    ),
    (
        "Read never reports EOF, so a handler that reads its whole body never returns",
        """		if b.ended {""",
        """		if false {""",
        [
            "TestAnEndedBodyWithNothingInItIsEOF",
            "TestABodyReadsBackWhatArrived",
        ],
    ),

    # --- body.go: the offset and the queue ---------------------------------
    (
        "take does not advance into the chunk it read, so the same payload is handed over forever",
        """	n = copy(p, b.chunks[0][b.off:])
	b.off += n""",
        """	n = copy(p, b.chunks[0][b.off:])""",
        [
            "TestOneReadNeverCrossesAChunk",
            "TestAReadChunkIsDroppedRatherThanKept",
        ],
    ),
    (
        "take ignores how far it had got into the front chunk and re-reads it from the start",
        """	n = copy(p, b.chunks[0][b.off:])""",
        """	n = copy(p, b.chunks[0])""",
        ["TestAPartiallyReadChunkResumesWhereItStopped"],
    ),
    (
        "a fully read chunk is never dropped, so every read after the first returns nothing",
        """	if b.off == len(b.chunks[0]) {""",
        """	if false {""",
        [
            "TestOneReadNeverCrossesAChunk",
            "TestAReadChunkIsDroppedRatherThanKept",
        ],
    ),

    # --- body.go: what end and fail record ---------------------------------
    (
        "end does not record the peer's END_STREAM, so the body never finishes",
        """	b.trailers = trailers
	b.ended = true""",
        """	b.trailers = trailers""",
        [
            "TestAnEndedBodyWithNothingInItIsEOF",
            "TestABodyReadsBackWhatArrived",
        ],
    ),
    (
        "end discards the trailer section it was given",
        """	b.mu.Lock()
	b.trailers = trailers
	b.ended = true""",
        """	b.mu.Lock()
	b.ended = true""",
        [
            "TestContentThatArrivedBeforeEndStreamIsStillRead",
            "TestTrailersReachTheHandlerAfterItsBody",
        ],
    ),
    (
        "Trailers answers with nothing whatever the request sent",
        """	return b.trailers""",
        """	return nil""",
        [
            "TestContentThatArrivedBeforeEndStreamIsStillRead",
            "TestTrailersReachTheHandlerAfterItsBody",
        ],
    ),
    (
        "fail lets the second reason a stream was lost overwrite the first",
        """	if b.err == nil {
		b.err = err
	}""",
        """	b.err = err""",
        ["TestTheFirstFailureIsTheOneReported"],
    ),

    # --- body.go: the signalling --------------------------------------------
    (
        "add hands over a payload without waking the handler waiting for one",
        """	b.wake.Signal()""",
        "",
        ["TestReadBlocksUntilContentArrives"],
    ),
    (
        "end wakes one reader of a body several are reading, and leaves the rest parked",
        """	b.ended = true
	b.mu.Unlock()

	b.wake.Broadcast()""",
        """	b.ended = true
	b.mu.Unlock()

	b.wake.Signal()""",
        ["TestEndWakesEveryParkedRead"],
    ),
    (
        "fail wakes one reader of a body several are reading, and leaves the rest parked",
        """	if b.err == nil {
		b.err = err
	}
	b.mu.Unlock()

	b.wake.Broadcast()""",
        """	if b.err == nil {
		b.err = err
	}
	b.mu.Unlock()

	b.wake.Signal()""",
        ["TestFailWakesEveryParkedRead"],
    ),
    (
        "newBody returns a body with no condition variable to wait on",
        """	b := &Body{id: id, credit: credit}
	b.wake = sync.NewCond(&b.mu)
	return b""",
        """	b := &Body{id: id, credit: credit}
	return b""",
        ["TestABodyReadsBackWhatArrived"],
    ),

    # --- exchange.go: what New refuses to be built without ------------------
    (
        "New accepts a nil handler, so every request panics on a goroutine of its own",
        """	if cfg.Handler == nil {
		panic("exchange: New requires a handler")
	}
""",
        "",
        ["TestNewRequiresEverythingItWillDereference"],
    ),
    (
        "New accepts a nil response encoder",
        """	if cfg.Encoder == nil {
		panic("exchange: New requires a response encoder")
	}
""",
        "",
        ["TestNewRequiresEverythingItWillDereference"],
    ),
    (
        "New accepts a nil source of flow-control credit",
        """	if cfg.Credit == nil {
		panic("exchange: New requires a source of flow-control credit")
	}
""",
        "",
        ["TestNewRequiresEverythingItWillDereference"],
    ),
    (
        "New's message for a missing handler names the type rather than the thing",
        """		panic("exchange: New requires a handler")""",
        """		panic("exchange: New requires a Handler")""",
        ["TestNewRequiresEverythingItWillDereference"],
    ),
    (
        "New leaves arriving nil, so the first upload panics writing to it",
        """		arriving: make(map[uint32]*inbound),""",
        """		arriving: nil,""",
        ["TestAnUploadArrivesAsItWasFramed"],
    ),
    (
        "Attach accepts a nil stream table, so no finished response is ever reported",
        """	if s == nil {
		panic("exchange: Attach requires a stream table")
	}
""",
        "",
        ["TestAttachRefusesTheTwoWaysOfGettingItWrong"],
    ),
    (
        "Attach silently replaces the table, sending one connection's finished responses to another's",
        """	if r.streams != nil {
		panic("exchange: the stream table is already attached")
	}
""",
        "",
        ["TestAttachRefusesTheTwoWaysOfGettingItWrong"],
    ),

    # --- exchange.go: Headers -----------------------------------------------
    (
        "Headers ignores what internal/request said about the header section",
        """	req, err := request.Parse(s.ID(), fields, endStream)
	if err != nil {
		return err
	}""",
        """	req, _ := request.Parse(s.ID(), fields, endStream)""",
        ["TestAMalformedHeaderSectionIsRefusedBeforeAnyHandlerRuns"],
    ),
    (
        "Headers runs a handler for a request it has already found malformed",
        """	req, err := request.Parse(s.ID(), fields, endStream)
	if err != nil {
		return err
	}""",
        """	req, err := request.Parse(s.ID(), fields, endStream)
	if err != nil {
		r.start(s.ID(), &Request{Request: req, Body: newBody(s.ID(), r.streams)})
		return err
	}""",
        ["TestAMalformedHeaderSectionIsRefusedBeforeAnyHandlerRuns"],
    ),
    (
        "Headers treats a request that arrived complete as one still arriving",
        """	body := newBody(s.ID(), r.streams)
	if endStream {
		body.end(nil)""",
        """	body := newBody(s.ID(), r.streams)
	if false {
		body.end(nil)""",
        [
            "TestARequestThatArrivedCompleteIsNotHeldOntoAtAll",
            "TestAGetsBodyIsEmptyRatherThanAbsent",
        ],
    ),
    (
        "Headers does not record a request whose content is still coming",
        """	} else {
		r.arriving[s.ID()] = &inbound{body: body, declared: req.ContentLength}
	}""",
        """	}""",
        ["TestAnUploadArrivesAsItWasFramed"],
    ),
    (
        "Headers forgets the content-length the request declared, so 8.1.1 is unenforceable",
        """		r.arriving[s.ID()] = &inbound{body: body, declared: req.ContentLength}""",
        """		r.arriving[s.ID()] = &inbound{body: body, declared: request.NoContentLength}""",
        [
            "TestABodyLongerThanItsContentLengthIsMalformedAtTheFrameThatExceedsIt",
            "TestABodyShorterThanItsContentLengthIsMalformedAtItsEndStream",
            "TestAnEmptyBodyAgainstANonZeroContentLengthIsMalformed",
            "TestTrailersOnAShortBodyAreMalformed",
        ],
    ),
    (
        "Headers hands the handler a request with no body at all",
        """	r.start(s.ID(), &Request{Request: req, Body: body})""",
        """	r.start(s.ID(), &Request{Request: req})""",
        [
            "TestAGetsBodyIsEmptyRatherThanAbsent",
            "TestAnUploadArrivesAsItWasFramed",
        ],
    ),

    # --- exchange.go: Data and 8.1.1's arithmetic ---------------------------
    (
        "Data accepts a payload for a request that is not arriving and panics on it",
        """	in := r.arriving[s.ID()]
	if in == nil {
		return r.notArriving("DATA", s.ID())
	}
""",
        """	in := r.arriving[s.ID()]
""",
        ["TestABodyFrameForARequestThatIsNotArrivingIsAConnectionError"],
    ),
    (
        "Data does not count the content it received, so every declared length looks unmet",
        """	in.received += int64(len(b))
""",
        "",
        [
            "TestABodyThatMatchesItsContentLengthIsAccepted",
            "TestABodyLongerThanItsContentLengthIsMalformedAtTheFrameThatExceedsIt",
        ],
    ),
    (
        "Data has 8.1.1's over-length comparison the wrong way round",
        """	if in.declared != request.NoContentLength && in.received > in.declared {""",
        """	if in.declared != request.NoContentLength && in.received < in.declared {""",
        [
            "TestABodyLongerThanItsContentLengthIsMalformedAtTheFrameThatExceedsIt",
            "TestABodyThatMatchesItsContentLengthIsAccepted",
        ],
    ),
    (
        "Data refuses an upload of exactly the length it declared",
        """	if in.declared != request.NoContentLength && in.received > in.declared {""",
        """	if in.declared != request.NoContentLength && in.received >= in.declared {""",
        ["TestABodyThatMatchesItsContentLengthIsAccepted"],
    ),
    (
        "Data drops the payload instead of handing it to the handler",
        """	in.body.add(b)
""",
        "",
        [
            "TestAnUploadArrivesAsItWasFramed",
            "TestManyStreamsAtOnce",
        ],
    ),
    (
        "Data accepts a body that ended short of the length it declared",
        """		if in.declared != request.NoContentLength && in.received != in.declared {
			return r.malformed(s.ID(), in, "content-length %d and %d octets of content",
				in.declared, in.received)
		}
		in.body.end(nil)""",
        """		in.body.end(nil)""",
        [
            "TestABodyShorterThanItsContentLengthIsMalformedAtItsEndStream",
            "TestAnEmptyBodyAgainstANonZeroContentLengthIsMalformed",
        ],
    ),
    (
        "Data never ends the body, so a handler reading a complete upload waits forever",
        """		in.body.end(nil)
		delete(r.arriving, s.ID())""",
        """		delete(r.arriving, s.ID())""",
        ["TestAnUploadArrivesAsItWasFramed"],
    ),
    (
        "Data leaves a finished request recorded as still arriving",
        """		in.body.end(nil)
		delete(r.arriving, s.ID())""",
        """		in.body.end(nil)""",
        [
            "TestManyStreamsAtOnce",
            "TestABodyFrameForARequestThatIsNotArrivingIsAConnectionError",
        ],
    ),

    # --- exchange.go: Trailers ---------------------------------------------
    (
        "Trailers accepts a trailer section for a request that is not arriving and panics on it",
        """	in := r.arriving[s.ID()]
	if in == nil {
		return r.notArriving("trailers", s.ID())
	}
""",
        """	in := r.arriving[s.ID()]
""",
        ["TestABodyFrameForARequestThatIsNotArrivingIsAConnectionError"],
    ),
    (
        "Trailers does not validate the trailer section, so 8.1's pseudo-header ban is unenforced",
        """	if err := request.ValidateTrailers(s.ID(), fields); err != nil {
		in.body.fail(err)
		delete(r.arriving, s.ID())
		return err
	}
""",
        "",
        ["TestATrailerSectionWithAPseudoHeaderFieldResetsTheStreamAndStopsTheHandler"],
    ),
    (
        "Trailers refuses a trailer section without telling the handler waiting for it",
        """		in.body.fail(err)
		delete(r.arriving, s.ID())
		return err""",
        """		delete(r.arriving, s.ID())
		return err""",
        ["TestATrailerSectionWithAPseudoHeaderFieldResetsTheStreamAndStopsTheHandler"],
    ),
    (
        "Trailers accepts a trailer section on a body short of the length it declared",
        """	if in.declared != request.NoContentLength && in.received != in.declared {
		return r.malformed(s.ID(), in, "content-length %d and %d octets of content",
			in.declared, in.received)
	}

	in.body.end(fields)""",
        """	in.body.end(fields)""",
        ["TestTrailersOnAShortBodyAreMalformed"],
    ),
    (
        "Trailers ends the body without the trailer section it just validated",
        """	in.body.end(fields)
	delete(r.arriving, s.ID())""",
        """	in.body.end(nil)
	delete(r.arriving, s.ID())""",
        ["TestTrailersReachTheHandlerAfterItsBody"],
    ),
    (
        "Trailers leaves a request that ended with trailers recorded as still arriving",
        """	in.body.end(fields)
	delete(r.arriving, s.ID())""",
        """	in.body.end(fields)""",
        ["TestTrailersReachTheHandlerAfterItsBody"],
    ),

    # --- exchange.go: the stream going away underneath a handler ------------
    (
        "Canceled panics on a reset of a stream whose request had no content",
        """	in := r.arriving[s.ID()]
	if in == nil {
		return
	}
""",
        """	in := r.arriving[s.ID()]
""",
        ["TestCanceledForAStreamWithNoBodyIsNothingToDo"],
    ),
    (
        "Canceled leaves a handler parked on the body of a stream the peer abandoned",
        """	in.body.fail(h2.StreamErrorf(s.ID(), code, "the peer reset the stream"))
	delete(r.arriving, s.ID())""",
        """	delete(r.arriving, s.ID())""",
        ["TestAPeerResetWakesAHandlerReadingTheBody"],
    ),
    (
        "Canceled tells the handler the stream ended cleanly rather than why the peer dropped it",
        """	in.body.fail(h2.StreamErrorf(s.ID(), code, "the peer reset the stream"))""",
        """	in.body.fail(h2.StreamErrorf(s.ID(), h2.NoError, "the peer reset the stream"))""",
        ["TestAPeerResetWakesAHandlerReadingTheBody"],
    ),
    (
        "Canceled leaves a reset stream recorded as still arriving",
        """	in.body.fail(h2.StreamErrorf(s.ID(), code, "the peer reset the stream"))
	delete(r.arriving, s.ID())""",
        """	in.body.fail(h2.StreamErrorf(s.ID(), code, "the peer reset the stream"))""",
        ["TestAResetStreamIsNoLongerRecordedAsArriving"],
    ),
    (
        "Close forgets the connection's handlers, leaking one goroutine per upload in flight",
        """	for id, in := range r.arriving {
		in.body.fail(err)
		delete(r.arriving, id)
	}""",
        """	for id := range r.arriving {
		delete(r.arriving, id)
	}""",
        ["TestTheConnectionEndingWakesEveryHandlerReadingABody"],
    ),
    (
        "Close wakes the handlers but leaves their requests recorded as arriving",
        """	for id, in := range r.arriving {
		in.body.fail(err)
		delete(r.arriving, id)
	}""",
        """	for _, in := range r.arriving {
		in.body.fail(err)
	}""",
        ["TestTheConnectionEndingWakesEveryHandlerReadingABody"],
    ),

    # --- exchange.go: the goroutine and the panic it contains ---------------
    (
        "start runs the handler on the connection's reader goroutine",
        """	go func() {""",
        """	func() {""",
        ["TestEachRequestIsAnsweredOnItsOwnGoroutine"],
    ),
    (
        "start does not contain a handler's panic, so one stream's bug ends the process",
        """			if v := recover(); v != nil {""",
        """			if v := any(nil); v != nil {""",
        ["TestAHandlerThatPanicsBeforeWritingGetsA500AndIsLogged"],
    ),
    (
        "the log line for a contained panic carries no stack",
        """				r.logf("stream %d: the handler panicked: %v\\n%s", id, v, debug.Stack())""",
        """				_ = debug.Stack()
				r.logf("stream %d: the handler panicked: %v", id, v)""",
        ["TestAHandlerThatPanicsBeforeWritingGetsA500AndIsLogged"],
    ),
    (
        "the log line for a contained panic does not say which stream it was on",
        """				r.logf("stream %d: the handler panicked: %v\\n%s", id, v, debug.Stack())""",
        """				r.logf("a handler panicked: %v\\n%s", v, debug.Stack())""",
        ["TestAHandlerThatPanicsBeforeWritingGetsA500AndIsLogged"],
    ),
    (
        "start does not finish the response, so every stream is left open and unreported",
        """			r.finish(id, w)
""",
        "",
        ["TestAFinishedResponseIsReportedOnceAndOnlyOnce"],
    ),
    (
        "start builds the handler's writer for a stream the peer did not open",
        """	w := response.NewWriter(r.enc, r.credit, id)""",
        """	w := response.NewWriter(r.enc, r.credit, id+2)""",
        ["TestAGetReachesItsHandlerAndItsAnswerReachesThePeer"],
    ),
    (
        "logf writes to a logger that was never given, taking the process down with the panic it was reporting",
        """	if r.log == nil {
		return
	}
""",
        "",
        ["TestAPanicWithNowhereToLogItIsStillContained"],
    ),

    # --- exchange.go: finish -----------------------------------------------
    (
        "finish leaves a stream whose handler wrote nothing with no response on it at all",
        """	if err := w.Close(); errors.Is(err, response.ErrNoHeader) {""",
        """	if err := w.Close(); errors.Is(err, response.ErrDone) {""",
        [
            "TestAHandlerThatWritesNothingGetsA500",
            "TestAHandlerThatOnlySentAnInterimResponseStillGetsAFinalOne",
            "TestAHandlerThatPanicsBeforeWritingGetsA500AndIsLogged",
        ],
    ),
    (
        "finish never closes the response, so a handler that did not end its own leaves the stream open",
        """	if err := w.Close(); errors.Is(err, response.ErrNoHeader) {""",
        """	if err := error(nil); errors.Is(err, response.ErrNoHeader) {""",
        [
            "TestAHandlerThatPanicsAfterItsHeaderSectionEndsTheStreamWhereItStopped",
            "TestAHandlerThatWritesNothingGetsA500",
        ],
    ),
    (
        "the response of last resort is a 200 rather than a 500",
        """var serverError = []h2.Field{{Name: ":status", Value: "500"}}""",
        """var serverError = []h2.Field{{Name: ":status", Value: "200"}}""",
        ["TestAHandlerThatWritesNothingGetsA500"],
    ),
    (
        "finish never reports the response, so 5.1.2's concurrency slot is leaked once per request",
        """	r.streams.ReportSendEnd(id)""",
        "",
        [
            "TestAFinishedResponseIsReportedOnceAndOnlyOnce",
            "TestTheStreamTableSeesTheResponseEnd",
        ],
    ),
    (
        "finish reports the response twice, freeing a concurrency slot the connection does not have",
        """	r.streams.ReportSendEnd(id)""",
        """	r.streams.ReportSendEnd(id)
	r.streams.ReportSendEnd(id)""",
        ["TestAFinishedResponseIsReportedOnceAndOnlyOnce"],
    ),

    # --- exchange.go: how a fault is reported ------------------------------
    (
        "malformed resets the stream without waking the handler reading its body",
        """	err := h2.StreamErrorf(id, h2.ProtocolError, "malformed request: "+format, args...)
	in.body.fail(err)""",
        """	err := h2.StreamErrorf(id, h2.ProtocolError, "malformed request: "+format, args...)""",
        ["TestABodyLongerThanItsContentLengthIsMalformedAtTheFrameThatExceedsIt"],
    ),
    (
        "malformed blames this server for a request the peer got wrong",
        """	err := h2.StreamErrorf(id, h2.ProtocolError, "malformed request: "+format, args...)""",
        """	err := h2.StreamErrorf(id, h2.InternalError, "malformed request: "+format, args...)""",
        [
            "TestABodyShorterThanItsContentLengthIsMalformedAtItsEndStream",
            "TestAnEmptyBodyAgainstANonZeroContentLengthIsMalformed",
            "TestTrailersOnAShortBodyAreMalformed",
        ],
    ),
    (
        "malformed leaves the request it refused recorded as still arriving",
        """	in.body.fail(err)
	delete(r.arriving, id)
	return err""",
        """	in.body.fail(err)
	return err""",
        ["TestABodyShorterThanItsContentLengthIsMalformedAtItsEndStream"],
    ),
    (
        "the two layers disagreeing about what is open is answered on one stream instead of the connection",
        """	return h2.ConnErrorf(h2.InternalError,
		"%s for stream %d, whose request is not arriving", kind, id)""",
        """	return h2.StreamErrorf(id, h2.InternalError,
		"%s for stream %d, whose request is not arriving", kind, id)""",
        ["TestABodyFrameForARequestThatIsNotArrivingIsAConnectionError"],
    ),
    (
        "a fault on this side of the connection is reported as the peer's protocol error",
        """	return h2.ConnErrorf(h2.InternalError,""",
        """	return h2.ConnErrorf(h2.ProtocolError,""",
        ["TestABodyFrameForARequestThatIsNotArrivingIsAConnectionError"],
    ),
    # --- reporting consumed content (§6.9) ----------------------------------
    #
    # What a Read reports is what returns the peer's flow-control window, so every break
    # here is an upload that stops partway with no error on either end: the peer waiting
    # to be told there is room, the handler waiting for content. None of them can be seen
    # on a body smaller than one window, which is every request a browser makes.
    (
        "a body is built with nowhere to report the content a handler reads",
        """	if credit == nil {
		panic("exchange: newBody requires somewhere to report consumed content")
	}""",
        """	// a body with nowhere to report to is accepted""",
        ["TestNewBodyRefusesToBeBuiltWithNowhereToReportTo"],
    ),
    (
        "Read: a read that took nothing is reported, which is §6.9.1's zero increment",
        """	if n > 0 {
		b.credit.ReportConsumed(b.id, n, more)
	}""",
        """	b.credit.ReportConsumed(b.id, n, more)""",
        ["TestReadsThatConsumeNothingReportNothing"],
    ),
    (
        "Read: the content is reported against the connection rather than the stream",
        """		b.credit.ReportConsumed(b.id, n, more)""",
        """		b.credit.ReportConsumed(0, n, more)""",
        [
            "TestReadingABodyReportsEveryOctetItConsumed",
            "TestContentAHandlerReadsIsReportedToTheTable",
        ],
    ),
    (
        "Read: the payload in front of the handler is reported rather than what it took",
        """	n, more, err := b.take(p)
	if n > 0 {
		b.credit.ReportConsumed(b.id, n, more)
	}""",
        """	n, more, err := b.take(p)
	if n > 0 {
		b.credit.ReportConsumed(b.id, len(p), more)
	}""",
        ["TestAShortReadReportsOnlyWhatItTook"],
    ),
    (
        "the content is reported with the body's lock still held",
        """	return n, !b.ended || len(b.chunks) > 0, nil""",
        """	more = !b.ended || len(b.chunks) > 0
	b.credit.ReportConsumed(b.id, n, more)
	return n, more, nil""",
        [
            "TestContentIsReportedWithTheLockReleased",
            "TestReadingABodyReportsEveryOctetItConsumed",
        ],
    ),
    (
        "take: a body the peer has not ended reports no more content once its buffer empties",
        """	return n, !b.ended || len(b.chunks) > 0, nil""",
        """	return n, !b.ended, nil""",
        ["TestOnlyTheLastReadOfABodyReportsThatThereIsNoMore"],
    ),
    (
        "take: the last read of a finished body reports that more content is coming",
        """	return n, !b.ended || len(b.chunks) > 0, nil""",
        """	return n, true, nil""",
        ["TestOnlyTheLastReadOfABodyReportsThatThereIsNoMore"],
    ),
    (
        "Headers: the body reports its content against the connection rather than its stream",
        """	body := newBody(s.ID(), r.streams)""",
        """	body := newBody(0, r.streams)""",
        ["TestContentAHandlerReadsIsReportedToTheTable"],
    ),
]

breakage.main(SRC, PKG, BREAKS)
