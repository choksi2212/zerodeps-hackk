"""Deliberately break internal/flow/sender.go, one guard at a time, and report
which tests notice.

Each entry below removes exactly one guard and names the tests that must fail as a
result. See breakage.py for the harness and for what the five outcomes mean.

This is the first campaign in the repository against code that is shared between
goroutines, and that changes what a break looks like. Everywhere else a removed
guard makes a test report a wrong value or the wrong error. Here about a third of
them make a test report nothing at all: a writer parked on a condition variable
that nobody broadcasts to does not fail, it waits, and the only thing that ever
notices is `go test`'s own timeout -- which names the package, dumps every
goroutine in it, and says nothing about which broadcast went missing.

That would score as `hang`, which this harness counts as a hole, and rightly: a
break whose only symptom is a hang is a break nobody has diagnosed. So the tests
are written to fail rather than hang. Every wait in sender_test.go is bounded by
parkDeadline and says what it was waiting for, and the wake-up breaks below each
fire a named test in five seconds instead of stalling one for sixty. That bound
exists because of this campaign; it is not defensive decoration.

Five breaks are worth reading for what they are testing rather than what they
remove.

  Clamping Reserve to the stream window alone leaves a server that is correct on
  every single-stream connection and oversends on every concurrent one. It is the
  §6.9.1 mistake: the connection window is shared, so a stream with a full window of
  its own may still send only what the connection has left, and a peer is entitled
  to end the connection over the difference. Nothing about the frame that breaks it
  looks unusual, which is why it takes two streams to catch.

  Turning Broadcast into Signal is the classic condition-variable bug and it is
  invisible on a connection with one stream. The writers parked here are not
  interchangeable: credit that arrived on stream 3 is no use to a writer waiting on
  stream 5, and Signal wakes exactly one of them -- possibly the wrong one, which
  goes back to sleep having spent the only notification there was. All three Signal
  breaks -- on CreditConn, on SetInitialSize and on Close -- are caught by tests that
  park several writers and then let one thing happen. Two of them need nothing more
  than several writers, because what arrives is good for all of them and only one
  comes back. The connection-window one is the awkward case: the credit is usable by
  exactly one of the four parked writers, so the queue order decides whether Signal
  happens to pick it. The test parks that writer last, behind three that cannot use
  what arrives, and starts each only once the previous one is known to be asleep.
  Go's sync.Cond wakes waiters in the order they parked, which is what makes the
  break fire every time rather than three times in four; the test itself does not
  depend on the ordering, only on Broadcast reaching everyone.

  All three also depend on nothing else having woken the writers first. A writer that
  is already on its way back to the lock when Signal runs returns without needing to
  be woken, and the break passes -- which is exactly how the Close one was found to
  be a hole on the first run of this campaign, against a test that had retired
  streams beforehand. So each of those tests arranges that no credit arrives and no
  stream is retired between the last park and the event under test. The waiter count
  cannot help here: it does not drop between a broadcast and the woken writer
  re-acquiring the lock, by design, so no test can tell a parked writer from a waking
  one.

  The same reasoning is why neither of the two tests that drive many writers in a loop
  -- TestTheConnectionWindowIsNeverOverspent and TestTheSenderIsSafeForConcurrentUse
  -- is named by any break that removes a broadcast. Their writers reserve in a loop,
  so a writer woken by an earlier broadcast re-takes the lock and finds the next thing
  it was waiting for -- credit, or its own stream retired -- without needing a fresh
  notification. They catch a broadcast that never happens at all only by luck, and a
  break caught by luck is reported as a hole on the run where the luck runs out; both
  of them were, on the first two runs of this campaign. What they are for is the
  arithmetic under contention, which no single-writer test can reach. The wake-ups are
  the deterministic tests' job.

  Checking `s.err` after the windows rather than before leaves a writer that looks at
  the credit on a connection that has already ended. Whether that is a wrong value or
  a writer that never returns depends on the credit: with enough on both windows it
  returns a successful reservation and the caller sends a frame down a socket nobody
  is reading; with credit on one window and none on the other -- the state the test
  arranges, because it is the one that separates the two checks -- it parks again on a
  connection that will never grant it anything. The second is the worse symptom and
  the easier one to assert, so that is the one the test looks for.

  There is a tempting third arrangement that does not work: park a writer, Close the
  connection, and then credit the stream so that the credit and the reason arrive
  together. It cannot happen. All three crediting methods return early once `s.err` is
  set, so credit offered after Close is dropped rather than applied, and a test built
  that way would be asserting nothing -- which is what the first run of this campaign
  caught.

  Dropping Reserve's re-lookup of the stream after it wakes leaves a writer holding
  a window that belongs to a stream that has been reset. No test that retires the
  stream before the writer parks can catch it -- that path returns early -- so it
  needs the reset to arrive while the writer is asleep.

  Answering a request for nothing with a reservation of nothing is a hang rather
  than a wrong value, because zero octets clamps to zero and parks. So the two
  breaks of that guard replace the panic with the two things a caller might have
  written instead -- return zero, or round the request up -- rather than deleting it,
  and both come back through the assertion instead of through the timeout.

Four results are measurements rather than catches, and are written down because a
reader would otherwise reconstruct the reasoning wrongly.

  Removing the `waiting` counter's increment or decrement is not a break in the
  production sense -- the field exists for the tests, and no production code reads
  it -- but it is broken here anyway, because a miscounted park is a helper that
  returns before the writer is actually asleep, which would turn half the tests
  below into races that pass. Both fire, and what they fire is the helper rather
  than a guard.

  Sorting SetInitialSize's iteration is a determinism guard, not a protocol one. The
  connection ends either way and the octets on the wire are identical; what changes
  is whether the log line naming the stream is the same on two runs. Only
  TestSetInitialSizeNamesTheLowestStreamItOverflows can see it, and it has to
  iterate to see it at all -- one call against five streams picks the lowest by luck
  one time in five.

  Reserve's two Consume results cannot fail while the clamping above them is
  correct, so no break of the checks themselves fires anything and none is listed.
  They are checked because the clamps *can* be broken, and the entries that break
  them are held by exactly these returns: with the connection clamp gone, Consume is
  what refuses the overdraft, and the error it returns is what the test sees instead
  of a silent overspend.

  There is no break for holding the lock across the wait -- replacing
  `s.credit.Wait()` with an unlock and a re-lock. It is a real mistake and the other
  way to get a condition variable wrong: it turns every parked writer into a spin
  that burns a core until credit arrives. It is also not observable through this
  type's surface. The values are identical, the wake-ups still arrive, and the
  counter cannot be caught mid-transition because Reserve decrements and
  re-increments it under one hold of the lock. A break detectable only by watching
  CPU is not one this harness can score, and inventing a test that timed the wait to
  catch it would be the flaky concurrency test the Sender's own comments argue
  against.

  TestOpenRefusesTheConnectionAsAStream and TestOpenRefusesTheSameStreamTwice read
  like a pair, and only the second has a break here. The first asserts that
  NewStreamWindow's refusal of stream 0 is still reachable through Open; the guard
  itself is in window.go and break-flow.py removes it there. There is no line in
  this file to take away for it, which is the reason to assert it in this one.

Run from the repository root. Restores the file on the way out, including on error.
"""

import breakage

SRC = "internal/flow/sender.go"
PKG = "./internal/flow/"

# (name, old, new, tests that must fail)
BREAKS = [
    # --- construction --------------------------------------------------------
    (
        "NewSender starts the connection window empty",
        """		conn:    NewConnWindow(),""",
        """		conn:    NewStreamWindow(1, 0),""",
        ["TestNewSenderStartsAtTheSizesBothEndsMustAssume"],
    ),
    (
        "NewSender starts the initial stream window at zero rather than 65535",
        """		initial: InitialWindowSize,""",
        """		initial: 0,""",
        ["TestNewSenderStartsAtTheSizesBothEndsMustAssume"],
    ),

    # --- Open ----------------------------------------------------------------
    (
        "Open replaces the window of a stream that is already open",
        """	if _, ok := s.stream[id]; ok {
		panic("flow: Sender.Open called twice for the same stream")
	}""",
        """	_ = id""",
        ["TestOpenRefusesTheSameStreamTwice"],
    ),
    (
        "Open sizes every stream at 65535 rather than at what the peer advertised",
        """	s.stream[id] = NewStreamWindow(id, s.initial)""",
        """	s.stream[id] = NewStreamWindow(id, InitialWindowSize)""",
        [
            "TestOpenSizesAStreamAtThePeersInitialWindow",
            "TestSetInitialSizeSizesStreamsOpenedAfterwards",
            "TestReserveIsCappedByTheStreamWindow",
        ],
    ),
    (
        "Open credits the connection window for every stream the peer opens",
        """	s.stream[id] = NewStreamWindow(id, s.initial)""",
        """	s.stream[id] = NewStreamWindow(id, s.initial)
	_ = s.conn.Increase(s.initial)""",
        ["TestOpenDoesNotTouchTheConnectionWindow"],
    ),

    # --- Retire --------------------------------------------------------------
    (
        "Retire leaves the stream in the map, so a reset stream keeps its credit",
        """	delete(s.stream, id)""",
        """	_ = id""",
        [
            "TestRetireClosesTheStream",
            "TestReserveWakesWhenTheStreamIsRetired",
        ],
    ),
    (
        "Retire does not wake the writers parked on the stream it just closed",
        """	delete(s.stream, id)

	// Broadcast even though no credit arrived. A writer parked on this stream is
	// waiting for something that can no longer happen, and the deletion above is
	// the only news it will ever get.
	s.credit.Broadcast()""",
        """	delete(s.stream, id)""",
        ["TestReserveWakesWhenTheStreamIsRetired"],
    ),
    (
        "Retire panics on a stream that is not open, so the second call to it ends the connection",
        """	if _, ok := s.stream[id]; !ok {
		return
	}""",
        """	if _, ok := s.stream[id]; !ok {
		panic("flow: Sender.Retire of a stream that is not open")
	}""",
        ["TestRetireOfAStreamThatIsNotOpenChangesNothing"],
    ),

    # --- CreditConn ----------------------------------------------------------
    (
        "CreditConn discards the increment, so the connection window never grows",
        """	if err := s.conn.Increase(n); err != nil {
		return err
	}""",
        """	_ = n""",
        [
            "TestReserveWaitsForAConnectionWindowUpdate",
            "TestCreditOnTheConnectionWakesEveryWriterAndNotJustOne",
            "TestTheConnectionWindowIsNeverOverspent",
        ],
    ),
    (
        "CreditConn does not report a WINDOW_UPDATE that overflows the connection window",
        """	if err := s.conn.Increase(n); err != nil {
		return err
	}""",
        """	_ = s.conn.Increase(n)""",
        ["TestCreditConnRefusesAnOverflow"],
    ),
    (
        "CreditConn does not wake the writers waiting for the credit it just applied",
        """	if err := s.conn.Increase(n); err != nil {
		return err
	}
	s.credit.Broadcast()
	return nil
}

// CreditStream applies""",
        """	if err := s.conn.Increase(n); err != nil {
		return err
	}
	return nil
}

// CreditStream applies""",
        [
            "TestReserveWaitsForAConnectionWindowUpdate",
            "TestReserveWaitsForWhicheverWindowIsEmpty",
            "TestCreditOnTheConnectionWakesEveryWriterAndNotJustOne",
        ],
    ),
    (
        "CreditConn wakes one writer rather than all of them",
        """	if err := s.conn.Increase(n); err != nil {
		return err
	}
	s.credit.Broadcast()
	return nil
}

// CreditStream applies""",
        """	if err := s.conn.Increase(n); err != nil {
		return err
	}
	s.credit.Signal()
	return nil
}

// CreditStream applies""",
        ["TestCreditOnTheConnectionWakesEveryWriterAndNotJustOne"],
    ),

    # --- CreditStream --------------------------------------------------------
    (
        "CreditStream discards the increment, so a stream window never grows",
        """	if err := w.Increase(n); err != nil {
		return err
	}""",
        """	_, _ = w, n""",
        [
            "TestReserveWaitsForAStreamWindowUpdate",
            "TestReserveFillsADeficitBeforeItPaysForAnything",
        ],
    ),
    (
        "CreditStream does not report a WINDOW_UPDATE that overflows a stream window",
        """	if err := w.Increase(n); err != nil {
		return err
	}""",
        """	_ = w.Increase(n)""",
        ["TestCreditStreamRefusesAnOverflow"],
    ),
    (
        "CreditStream does not wake the writers waiting for the credit it just applied",
        """	if err := w.Increase(n); err != nil {
		return err
	}
	s.credit.Broadcast()""",
        """	if err := w.Increase(n); err != nil {
		return err
	}""",
        [
            "TestReserveWaitsForAStreamWindowUpdate",
            "TestReserveFillsADeficitBeforeItPaysForAnything",
        ],
    ),
    (
        "CreditStream ends the connection over a WINDOW_UPDATE for a stream that has closed",
        """	w, ok := s.stream[id]
	if !ok {
		return nil
	}""",
        """	w, ok := s.stream[id]
	if !ok {
		return errors.New("flow: WINDOW_UPDATE for a stream that is not open")
	}""",
        ["TestCreditStreamIgnoresAStreamThatIsNotOpen"],
    ),

    # --- SetInitialSize ------------------------------------------------------
    (
        "SetInitialSize applies the peer's setting to no stream at all",
        """	for _, id := range slices.Sorted(maps.Keys(s.stream)) {""",
        """	for _, id := range slices.Sorted(maps.Keys(s.stream))[:0] {""",
        [
            "TestSetInitialSizeAppliesToOpenStreamsAsADelta",
            "TestSetInitialSizeWakesEveryParkedWriter",
            "TestSetInitialSizeRefusesAChangeThatOverflowsAStreamWindow",
            "TestSetInitialSizeNamesTheLowestStreamItOverflows",
        ],
    ),
    (
        "SetInitialSize applies the setting to the streams that are open and forgets it for the next one",
        """	s.initial = n""",
        """	_ = n""",
        [
            "TestOpenSizesAStreamAtThePeersInitialWindow",
            "TestSetInitialSizeSizesStreamsOpenedAfterwards",
        ],
    ),
    (
        "SetInitialSize does not report a setting that overflows a stream window",
        """		if err := s.stream[id].SetInitialSize(n); err != nil {
			// The streams before this one keep the new size. That is not a
			// partial update left lying around: the error is a connection error,
			// so the connection is about to end and every one of these windows is
			// about to be discarded. Rolling back would be work to restore a
			// state nothing will read.
			return err
		}""",
        """		_ = s.stream[id].SetInitialSize(n)""",
        [
            "TestSetInitialSizeRefusesAChangeThatOverflowsAStreamWindow",
            "TestSetInitialSizeNamesTheLowestStreamItOverflows",
        ],
    ),
    (
        "SetInitialSize applies §6.9.2's delta to the connection window as well",
        """	s.initial = n""",
        """	if n > s.initial {
		_ = s.conn.Increase(n - s.initial)
	}
	s.initial = n""",
        ["TestSetInitialSizeLeavesTheConnectionWindowAlone"],
    ),
    (
        "SetInitialSize does not wake the writers its delta just granted credit to",
        """	s.initial = n

	// A raise grants credit to every open stream at once, and this is the only
	// notification the writers parked on them will get. §6.9.2's delta is a grant
	// exactly as a WINDOW_UPDATE is; the only difference is the frame that
	// carried it.
	s.credit.Broadcast()""",
        """	s.initial = n""",
        ["TestSetInitialSizeWakesEveryParkedWriter"],
    ),
    (
        "SetInitialSize wakes one of the writers its delta granted credit to",
        """	s.initial = n

	// A raise grants credit to every open stream at once, and this is the only
	// notification the writers parked on them will get. §6.9.2's delta is a grant
	// exactly as a WINDOW_UPDATE is; the only difference is the frame that
	// carried it.
	s.credit.Broadcast()""",
        """	s.initial = n
	s.credit.Signal()""",
        ["TestSetInitialSizeWakesEveryParkedWriter"],
    ),
    (
        "SetInitialSize walks the streams in map order, so the stream it blames varies by run",
        """	for _, id := range slices.Sorted(maps.Keys(s.stream)) {""",
        """	_ = slices.Sorted(maps.Keys(s.stream))
	for id := range s.stream {""",
        ["TestSetInitialSizeNamesTheLowestStreamItOverflows"],
    ),

    # --- Close ---------------------------------------------------------------
    (
        "Close does not wake the writers parked on the connection it just ended",
        """	s.err = err
	s.credit.Broadcast()""",
        """	s.err = err""",
        ["TestReserveWakesEveryWriterWhenTheConnectionEnds"],
    ),
    (
        "Close wakes one of the writers parked on the connection it just ended",
        """	s.err = err
	s.credit.Broadcast()""",
        """	s.err = err
	s.credit.Signal()""",
        ["TestReserveWakesEveryWriterWhenTheConnectionEnds"],
    ),
    (
        "Close records the last reason rather than the first",
        """	if s.err != nil {
		return
	}
	s.err = err""",
        """	s.err = err""",
        ["TestCloseKeepsTheFirstReason"],
    ),
    (
        "Close accepts a nil reason, which a parked writer cannot tell from success",
        """	if err == nil {
		panic("flow: Sender.Close requires a non-nil reason")
	}""",
        """	_ = err""",
        ["TestCloseRefusesANilReason"],
    ),
    (
        "Close wakes the writers without recording why, so each one parks again",
        """	s.err = err
	s.credit.Broadcast()""",
        """	s.credit.Broadcast()""",
        [
            "TestReserveWakesEveryWriterWhenTheConnectionEnds",
            "TestReserveOnAClosedConnectionDoesNotWait",
            "TestCloseKeepsTheFirstReason",
            "TestTheSenderIsSafeForConcurrentUse",
        ],
    ),

    # --- the shutdown checks on the crediting path ---------------------------
    (
        "CreditConn reports a fault on a connection that has already ended",
        """	if s.err != nil {
		// Not an error to report. The connection is already over and the reader
		// goroutine is on its way out; failing here would make it log a second,
		// invented fault on top of the real one. The credit is simply dropped,
		// because there is nobody left to spend it.
		return nil
	}""",
        """	if s.err != nil && false {
		return nil
	}""",
        ["TestCreditAfterCloseIsDroppedRatherThanReported"],
    ),
    (
        "CreditStream reports a fault on a connection that has already ended",
        """	if s.err != nil {
		return nil
	}
	w, ok := s.stream[id]""",
        """	if s.err != nil && false {
		return nil
	}
	w, ok := s.stream[id]""",
        ["TestCreditAfterCloseIsDroppedRatherThanReported"],
    ),
    (
        "SetInitialSize reports a fault on a connection that has already ended",
        """	if s.err != nil {
		return nil
	}

	// Sorted, so that a SETTINGS frame overflowing several streams at once names""",
        """	if s.err != nil && false {
		return nil
	}

	// Sorted, so that a SETTINGS frame overflowing several streams at once names""",
        ["TestCreditAfterCloseIsDroppedRatherThanReported"],
    ),

    # --- Reserve: the request itself -----------------------------------------
    (
        "Reserve answers a request for nothing with permission to send nothing",
        """		panic("flow: Sender.Reserve requires a positive number of octets")""",
        """		return 0, nil""",
        ["TestReserveRefusesARequestForNothing"],
    ),
    (
        "Reserve rounds a request for nothing up to a request for something",
        """	if want <= 0 {
		panic("flow: Sender.Reserve requires a positive number of octets")
	}""",
        """	if want <= 0 {
		want = 1
	}""",
        ["TestReserveRefusesARequestForNothing"],
    ),

    # --- Reserve: the clamps -------------------------------------------------
    (
        "Reserve clamps to the stream window alone, ignoring the connection's",
        """		n := int64(want)
		if a := s.conn.Available(); a < n {
			n = a
		}""",
        """		n := int64(want)""",
        [
            "TestReserveIsCappedByTheConnectionWindow",
            "TestReserveTakesTheSmallerOfTwoCapsWhicheverItIs",
            "TestReserveWaitsForAConnectionWindowUpdate",
            "TestReserveWaitsForWhicheverWindowIsEmpty",
            "TestTheConnectionWindowIsNeverOverspent",
        ],
    ),
    (
        "Reserve clamps to the connection window alone, ignoring the stream's",
        """		if a := w.Available(); a < n {
			n = a
		}""",
        """		_ = w""",
        [
            "TestReserveIsCappedByTheStreamWindow",
            "TestReserveTakesTheSmallerOfTwoCapsWhicheverItIs",
            "TestReserveWaitsForAStreamWindowUpdate",
            "TestReserveFillsADeficitBeforeItPaysForAnything",
        ],
    ),
    (
        "Reserve takes the larger of the two windows rather than the smaller",
        """		if a := s.conn.Available(); a < n {
			n = a
		}
		if a := w.Available(); a < n {
			n = a
		}""",
        """		if a := s.conn.Available(); a > n {
			n = a
		}
		if a := w.Available(); a > n {
			n = a
		}""",
        [
            "TestReserveIsCappedByTheStreamWindow",
            "TestReserveIsCappedByTheConnectionWindow",
            "TestReserveTakesTheSmallerOfTwoCapsWhicheverItIs",
        ],
    ),
    (
        "Reserve ignores what was asked for and takes everything both windows have",
        """		n := int64(want)""",
        """		n := int64(MaxWindowSize)
		_ = want""",
        [
            "TestReserveTakesWhatWasAskedWhenBothWindowsAllowIt",
            "TestReserveDebitsBothWindows",
        ],
    ),

    # --- Reserve: the debit --------------------------------------------------
    (
        "Reserve debits the connection window and not the stream's",
        """			if err := w.Consume(uint32(n)); err != nil {
				return 0, err
			}""",
        """			_ = w""",
        [
            "TestReserveDebitsBothWindows",
            "TestReserveFillsADeficitBeforeItPaysForAnything",
        ],
    ),
    (
        "Reserve debits the stream window and not the connection's",
        """			if err := s.conn.Consume(uint32(n)); err != nil {
				return 0, err
			}
""",
        """""",
        [
            "TestReserveDebitsBothWindows",
            "TestReserveIsCappedByTheConnectionWindow",
            "TestTheConnectionWindowIsNeverOverspent",
        ],
    ),
    (
        "Reserve reports having taken the whole request rather than what it got",
        """			return int(n), nil""",
        """			return want, nil""",
        [
            "TestReserveIsCappedByTheStreamWindow",
            "TestReserveIsCappedByTheConnectionWindow",
            "TestReserveTakesTheSmallerOfTwoCapsWhicheverItIs",
            "TestReserveWaitsForAStreamWindowUpdate",
            "TestTheConnectionWindowIsNeverOverspent",
        ],
    ),

    # --- Reserve: the waiting condition --------------------------------------
    (
        "Reserve hands out an empty window as a reservation of nothing",
        """		if n > 0 {""",
        """		if n >= 0 {""",
        [
            "TestReserveWaitsForAStreamWindowUpdate",
            "TestReserveWaitsForAConnectionWindowUpdate",
            "TestReserveWaitsForWhicheverWindowIsEmpty",
        ],
    ),
    (
        "Reserve treats a negative window as credit, so a deficit is spent twice",
        """		if n > 0 {""",
        """		if n != 0 {""",
        ["TestReserveFillsADeficitBeforeItPaysForAnything"],
    ),
    (
        "Reserve returns instead of waiting, so a response with a full window is dropped",
        """		s.waiting++
		s.credit.Wait()
		s.waiting--""",
        """		return 0, ErrStreamGone""",
        [
            "TestReserveWaitsForAStreamWindowUpdate",
            "TestReserveWaitsForAConnectionWindowUpdate",
            "TestReserveFillsADeficitBeforeItPaysForAnything",
            "TestSetInitialSizeWakesEveryParkedWriter",
        ],
    ),

    # --- Reserve: what is re-checked after waking ----------------------------
    (
        "Reserve checks the connection's fate after the windows rather than before",
        """		if s.err != nil {
			return 0, s.err
		}
		w, ok := s.stream[id]
		if !ok {
			return 0, ErrStreamGone
		}""",
        """		w, ok := s.stream[id]
		if !ok {
			return 0, ErrStreamGone
		}""",
        [
            "TestReserveWakesEveryWriterWhenTheConnectionEnds",
            "TestReserveOnAClosedConnectionDoesNotWait",
            "TestCloseKeepsTheFirstReason",
            "TestReserveReportsTheConnectionEndingEvenWhenThereIsCreditToSpend",
            "TestTheSenderIsSafeForConcurrentUse",
        ],
    ),
    (
        "Reserve prefers the credit that arrived with the end of the connection",
        """		if s.err != nil {
			return 0, s.err
		}
		w, ok := s.stream[id]
		if !ok {
			return 0, ErrStreamGone
		}""",
        """		w, ok := s.stream[id]
		if !ok {
			return 0, ErrStreamGone
		}
		if s.err != nil && w.Available() <= 0 {
			return 0, s.err
		}""",
        [
            "TestReserveReportsTheConnectionEndingEvenWhenThereIsCreditToSpend",
            "TestReserveOnAClosedConnectionDoesNotWait",
            "TestCloseKeepsTheFirstReason",
        ],
    ),
    (
        "Reserve invents a window for a stream that is not open",
        """		w, ok := s.stream[id]
		if !ok {
			return 0, ErrStreamGone
		}""",
        """		w, ok := s.stream[id]
		if !ok {
			w = NewStreamWindow(id, s.initial)
			s.stream[id] = w
		}""",
        [
            "TestReserveReportsAStreamThatIsNotOpen",
            "TestReserveWakesWhenTheStreamIsRetired",
        ],
    ),
    (
        "Reserve looks the stream up once and keeps the window across the wait",
        """	for {
		// Checked before the windows, so that a writer parked on a connection
		// that has since ended returns the reason it ended rather than the credit
		// that happened to arrive alongside it.
		if s.err != nil {
			return 0, s.err
		}
		w, ok := s.stream[id]
		if !ok {
			return 0, ErrStreamGone
		}""",
        """	w, ok := s.stream[id]
	if !ok {
		return 0, ErrStreamGone
	}
	for {
		if s.err != nil {
			return 0, s.err
		}""",
        ["TestReserveWakesWhenTheStreamIsRetired"],
    ),

    # --- the waiter count the tests observe ----------------------------------
    (
        "the waiter count is not incremented, so a test proceeds before the writer parks",
        """		s.waiting++
		s.credit.Wait()""",
        """		s.credit.Wait()""",
        [
            "TestReserveWaitsForAStreamWindowUpdate",
            "TestSetInitialSizeWakesEveryParkedWriter",
        ],
    ),
    (
        "the waiter count is never decremented, so a park is counted for ever",
        """		s.credit.Wait()
		s.waiting--""",
        """		s.credit.Wait()""",
        ["TestReserveWaitsForAStreamWindowUpdate"],
    ),

    # --- the introspection the stream table reads ----------------------------
    (
        "Available reports a stream that is not open as open with no credit",
        """	w, ok := s.stream[id]
	if !ok {
		return 0, false
	}
	return w.Available(), true""",
        """	w, ok := s.stream[id]
	if !ok {
		return 0, true
	}
	return w.Available(), ok""",
        [
            "TestAvailableReportsAStreamThatWasNeverOpened",
            "TestRetireClosesTheStream",
        ],
    ),
    (
        "Available reports the connection's credit rather than the stream's",
        """	return w.Available(), true""",
        """	_ = w
	return s.conn.Available(), true""",
        [
            "TestOpenSizesAStreamAtThePeersInitialWindow",
            "TestSetInitialSizeAppliesToOpenStreamsAsADelta",
            "TestSetInitialSizeSizesStreamsOpenedAfterwards",
            "TestReserveFillsADeficitBeforeItPaysForAnything",
        ],
    ),
    (
        "ConnAvailable reports the peer's initial window size rather than the credit left",
        """	return s.conn.Available()""",
        """	return int64(s.initial)""",
        [
            "TestReserveDebitsBothWindows",
            "TestReserveIsCappedByTheConnectionWindow",
            "TestSetInitialSizeLeavesTheConnectionWindowAlone",
            "TestTheConnectionWindowIsNeverOverspent",
        ],
    ),
    (
        "InitialSize reports 65535 whatever the peer advertised",
        """	return s.initial""",
        """	return InitialWindowSize""",
        ["TestSetInitialSizeSizesStreamsOpenedAfterwards"],
    ),
]

breakage.main(SRC, PKG, BREAKS)
