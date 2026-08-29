"""Deliberately break internal/flow/window.go, one guard at a time, and report
which tests notice.

Each entry below removes exactly one guard and names the tests that must fail as a
result. See breakage.py for the harness and for what the five outcomes mean.

This file is smaller than the other campaigns because the package is: four methods
of pure arithmetic and two constructors. What makes it worth its own campaign is
that almost every guard here is a comparison, and a comparison is the kind of guard
that a green suite is worst at defending. Five of the breaks below are one character
each -- `>` for `>=`, `+` for `-`, `int64` dropped from a conversion -- and every one
of them is a real bug that has shipped in real HTTP/2 implementations.

Three are worth reading for what they are testing rather than what they remove.

  Dropping the int64 conversion in Increase's overflow check leaves arithmetic that
  is correct for every increment a normal peer sends and wrong for the one an
  attacker sends: the sum of two maxima wraps to a negative number, the check reads
  it as a window far below the limit, and the guard licenses exactly the frame it
  exists to refuse.

  Turning SetInitialSize's delta into an assignment leaves flow control that works
  perfectly until a peer changes the setting mid-connection, at which point every
  open stream is handed back the credit it had already spent. Nothing about the
  connection looks wrong; the two ends simply stop agreeing about how much data is
  in flight.

  Removing Consume's zero-length exemption leaves a server that passes every test a
  well-behaved client can produce and deadlocks a stream that has finished its body
  on a window that has gone negative -- a state only a SETTINGS change can create,
  which is why it survives an ordinary test suite.

Every guard in the file has a break here, and the two panics have one each. The
panics are expected to fire rather than crash, because both tests recover: see
assertPanics and assertDoesNotPanic in window_test.go for why the legal side of a
panicking bound needs a recover of its own.

Two results are measurements rather than catches, and both are written down because
the reasoning is what a reader would otherwise reconstruct wrongly.

  Raising InitialWindowSize to 65536 is caught by the agreement test and by nothing
  else. TestNewWindowsStartAtTheInitialSize compares each new window against the
  constant rather than against a literal, so it passes whatever the constant says --
  which is correct for what that test is for, since a constructor's job is to start
  a window at the configured initial size, not to know what the RFC's number is. The
  RFC's number is asserted in exactly one place, as a literal, and that place is the
  agreement test.

  Folding the zero-length exemption into the size comparison as `n > 0 &&` fires
  nothing, and cannot: `&&` short-circuits, so the comparison is never evaluated for
  an empty frame. The two forms are equivalent. window.go carried a comment claiming
  otherwise until this campaign was run against it; the comment is corrected and the
  break is kept, commented out, below Consume's live entries.

The campaign also found one weak test rather than one weak guard, which is the other
outcome these files exist to produce. Turning SetInitialSize's delta into an
outright assignment left TestSetInitialSizeIsADeltaAgainstThePreviousSettingNotThe-
First passing, because it changed the setting twice on a window that had spent
nothing -- and on an untouched window a delta and an assignment land on the same
number. It now consumes 70 octets first, which is what separates them.

Run from the repository root. Restores the file on the way out, including on error.
"""

import breakage

SRC = "internal/flow/window.go"
PKG = "./internal/flow/"

# (name, old, new, tests that must fail)
BREAKS = [
    # --- the protocol constants ----------------------------------------------
    (
        "InitialWindowSize is 64 KiB rather than the 65535 octets RFC 9113 specifies",
        """	InitialWindowSize = 1<<16 - 1""",
        """	InitialWindowSize = 1 << 16""",
        [
            # Deliberately not TestNewWindowsStartAtTheInitialSize. It asserts that
            # the constructors start a window at InitialWindowSize, comparing
            # against the constant rather than against a literal, so it passes
            # whatever the constant is. That split is on purpose -- see the note in
            # the docstring -- and this break is held by the agreement test alone.
            "TestWindowConstantsAgreeWithTheFrameLayer",
        ],
    ),
    (
        "MaxWindowSize is 2^31, one octet above the largest legal window",
        """	MaxWindowSize = 1<<31 - 1""",
        """	MaxWindowSize = 1 << 31""",
        ["TestWindowConstantsAgreeWithTheFrameLayer"],
    ),

    # --- construction --------------------------------------------------------
    (
        "NewConnWindow starts the connection empty, so the first DATA frame is refused",
        """	return &Window{streamID: 0, initial: InitialWindowSize, n: InitialWindowSize}""",
        """	return &Window{streamID: 0, initial: InitialWindowSize}""",
        ["TestNewWindowsStartAtTheInitialSize"],
    ),
    (
        "NewConnWindow claims a stream, so every connection fault resets stream 1 instead",
        """	return &Window{streamID: 0, initial: InitialWindowSize, n: InitialWindowSize}""",
        """	return &Window{streamID: 1, initial: InitialWindowSize, n: InitialWindowSize}""",
        [
            "TestNewWindowsStartAtTheInitialSize",
            "TestConsumeRefusesOneOctetTooMany",
            "TestIncreaseRefusesTheOctetPastTheMaximum",
            "TestSetInitialSizeRefusesTheConnectionWindow",
        ],
    ),
    (
        "NewStreamWindow accepts stream 0, so one stream's fault ends the connection",
        """	if id == 0 {
		panic("flow: NewStreamWindow requires a non-zero stream identifier; use NewConnWindow")
	}
""",
        "",
        ["TestNewStreamWindowRefusesWhatCannotBeAStreamWindow"],
    ),
    (
        "NewStreamWindow accepts an initial size the SETTINGS validator must have refused",
        """	if int64(initial) > MaxWindowSize {
		panic("flow: NewStreamWindow initial size is above the maximum window")
	}
""",
        "",
        ["TestNewStreamWindowRefusesWhatCannotBeAStreamWindow"],
    ),
    (
        "NewStreamWindow refuses the largest legal initial size as though it were too large",
        """	if int64(initial) > MaxWindowSize {""",
        """	if int64(initial) >= MaxWindowSize {""",
        ["TestNewStreamWindowRefusesWhatCannotBeAStreamWindow"],
    ),
    (
        "NewStreamWindow records the size as credit but not as the initial size",
        """	return &Window{streamID: id, initial: int64(initial), n: int64(initial)}""",
        """	return &Window{streamID: id, n: int64(initial)}""",
        [
            "TestSetInitialSizeAppliesTheChangeAsADelta",
            "TestSetInitialSizeTakesTheWindowNegativeAndKeepsItThere",
            "TestConsumeLetsAnEmptyFrameThroughANegativeWindow",
        ],
    ),

    # --- Consume -------------------------------------------------------------
    (
        "Consume: a zero-length DATA frame is refused on a window with no room (RFC 9113 6.9.1)",
        """	if n == 0 {
		return nil
	}

""",
        "",
        # Only the negative-window test. TestTheWindowStaysInRangeAtBothExtremes was
        # named here in the belief that it drives the window negative and would
        # therefore notice, and it does drive it negative -- but by SetInitialSize,
        # never by consuming an empty frame afterwards. It cannot see this guard.
        ["TestConsumeLetsAnEmptyFrameThroughANegativeWindow"],
    ),
    # Not a live break, and it is here rather than deleted because it was run and
    # found nothing, which is worth recording:
    #
    #     "Consume: the exemption is folded into the comparison"
    #     `if n == 0 { return nil }` + `if int64(n) > w.n {`  ->  `if n > 0 && int64(n) > w.n {`
    #
    # No test can name this one. `&&` short-circuits, so that form never evaluates
    # the comparison for an empty frame and admits it on any window, negative
    # included -- it is exactly equivalent to the branch it replaces. The code
    # carried a comment claiming the form "gets this wrong" until this campaign
    # measured it, and the comment is now corrected in window.go. Left commented out
    # rather than live because breakage.preflight refuses a break with no expected
    # tests, and rightly: such a break can never fail.
    (
        "Consume: a frame exactly filling the window is refused",
        """	if int64(n) > w.n {""",
        """	if int64(n) >= w.n {""",
        [
            "TestConsumeSpendsExactlyTheWindowAndNoMore",
            "TestTheWindowStaysInRangeAtBothExtremes",
        ],
    ),
    (
        "Consume: nothing is checked, so a peer may send as much DATA as it likes",
        """	if int64(n) > w.n {
		return w.errorf(h2.FlowControlError,
			"DATA of %d octets on a flow-control window of %d (RFC 9113 §6.9.1)", n, w.n)
	}
""",
        "",
        [
            "TestConsumeRefusesOneOctetTooMany",
            "TestConsumeRefusesAFrameLargerThanAnyWindow",
            "TestConsumeLetsAnEmptyFrameThroughANegativeWindow",
            "TestIncreaseFillsADeficitBeforeItPaysForAnything",
        ],
    ),
    (
        "Consume: the length is compared as a signed 32-bit value, so a huge frame reads as free",
        """	if int64(n) > w.n {""",
        """	if int64(int32(n)) > w.n {""",
        ["TestConsumeRefusesAFrameLargerThanAnyWindow"],
    ),
    (
        "Consume: the frame is not debited, so the window never empties",
        """	w.n -= int64(n)
	return nil""",
        """	return nil""",
        [
            "TestConsumeSpendsExactlyTheWindowAndNoMore",
            "TestSetInitialSizeAppliesTheChangeAsADelta",
            "TestWindowsDoNotShareState",
        ],
    ),
    (
        "Consume: a refused frame is debited anyway, so it is counted twice on the connection",
        """	if int64(n) > w.n {
		return w.errorf(h2.FlowControlError,""",
        """	if int64(n) > w.n {
		w.n -= int64(n)
		return w.errorf(h2.FlowControlError,""",
        [
            "TestConsumeRefusesOneOctetTooMany",
            "TestConsumeRefusesAFrameLargerThanAnyWindow",
        ],
    ),

    # --- Increase ------------------------------------------------------------
    (
        "Increase: a WINDOW_UPDATE may take the window past 2^31-1 (matrix rows 30 and 31)",
        """	if w.n+int64(n) > MaxWindowSize {
		return w.errorf(h2.FlowControlError,
			"WINDOW_UPDATE of %d takes a window of %d above the maximum %d (RFC 9113 §6.9.1)",
			n, w.n, int64(MaxWindowSize))
	}
""",
        "",
        [
            "TestIncreaseRefusesTheOctetPastTheMaximum",
            "TestIncreaseDoesNotWrapWhenBothHalvesAreAtTheMaximum",
        ],
    ),
    (
        "Increase: the overflow check is 32-bit, so two maxima wrap to a negative window",
        """	if w.n+int64(n) > MaxWindowSize {""",
        """	if int32(w.n)+int32(n) > MaxWindowSize {""",
        ["TestIncreaseDoesNotWrapWhenBothHalvesAreAtTheMaximum"],
    ),
    (
        "Increase: only the increment is checked, so a full window may be credited again",
        """	if w.n+int64(n) > MaxWindowSize {""",
        """	if int64(n) > MaxWindowSize {""",
        [
            "TestIncreaseRefusesTheOctetPastTheMaximum",
            "TestIncreaseDoesNotWrapWhenBothHalvesAreAtTheMaximum",
        ],
    ),
    (
        "Increase: a credit landing exactly on the maximum is refused",
        """	if w.n+int64(n) > MaxWindowSize {""",
        """	if w.n+int64(n) >= MaxWindowSize {""",
        # TestTheWindowStaysInRangeAtBothExtremes reaches the maximum by
        # SetInitialSize rather than by Increase, so it cannot see this one.
        ["TestIncreaseCreditsUpToTheMaximum"],
    ),
    (
        "Increase: the credit is not applied, so a peer's WINDOW_UPDATE grants nothing",
        """	w.n += int64(n)
	return nil""",
        """	return nil""",
        [
            "TestIncreaseCreditsUpToTheMaximum",
            "TestIncreaseFillsADeficitBeforeItPaysForAnything",
            "TestIncreaseRefusesTheOctetPastTheMaximum",
        ],
    ),
    (
        "Increase: a negative window is reset to the credit instead of having its deficit filled",
        """	w.n += int64(n)
	return nil""",
        """	if w.n < 0 {
		w.n = int64(n)
	} else {
		w.n += int64(n)
	}
	return nil""",
        ["TestIncreaseFillsADeficitBeforeItPaysForAnything"],
    ),

    # --- SetInitialSize ------------------------------------------------------
    (
        "SetInitialSize: the peer's setting is applied to the connection window (RFC 9113 6.9.2)",
        """	if w.streamID == 0 {
		// Not reachable from a correct caller, and named rather than ignored.
		// §6.9.2 confines this setting to stream windows and gives WINDOW_UPDATE
		// as the only way to change the connection's, so a server that applies a
		// peer's SETTINGS to the connection window has desynchronised the
		// connection's credit by the delta with nothing to resynchronise it.
		// Silently returning nil would make that a stalled transfer weeks later
		// instead of a failure here.
		return h2.ConnErrorf(h2.InternalError,
			"SETTINGS_INITIAL_WINDOW_SIZE applied to the connection window, "+
				"which only WINDOW_UPDATE may change (RFC 9113 §6.9.2)")
	}

""",
        "",
        ["TestSetInitialSizeRefusesTheConnectionWindow"],
    ),
    (
        "SetInitialSize: the setting is silently ignored on the connection window rather than named",
        """		return h2.ConnErrorf(h2.InternalError,
			"SETTINGS_INITIAL_WINDOW_SIZE applied to the connection window, "+
				"which only WINDOW_UPDATE may change (RFC 9113 §6.9.2)")""",
        """		return nil""",
        ["TestSetInitialSizeRefusesTheConnectionWindow"],
    ),
    (
        "SetInitialSize: the change is an assignment, so every stream is handed back what it spent",
        """	next := w.n + (int64(n) - w.initial)""",
        """	next := int64(n)""",
        [
            "TestSetInitialSizeAppliesTheChangeAsADelta",
            "TestSetInitialSizeIsADeltaAgainstThePreviousSettingNotTheFirst",
            "TestSetInitialSizeTakesTheWindowNegativeAndKeepsItThere",
            "TestConsumeLetsAnEmptyFrameThroughANegativeWindow",
        ],
    ),
    (
        "SetInitialSize: the delta is added rather than subtracted, so a change drifts twice over",
        """	next := w.n + (int64(n) - w.initial)""",
        """	next := w.n + (int64(n) + w.initial)""",
        [
            "TestSetInitialSizeAppliesTheChangeAsADelta",
            "TestSetInitialSizeIsADeltaAgainstThePreviousSettingNotTheFirst",
            "TestSetInitialSizeTakesTheWindowNegativeAndKeepsItThere",
        ],
    ),
    (
        "SetInitialSize: a SETTINGS frame may take a stream's window past the maximum",
        """	if next > MaxWindowSize {""",
        """	if false {""",
        ["TestSetInitialSizeRefusesAChangeThatOverflowsAndChangesNothing"],
    ),
    (
        "SetInitialSize: a change landing exactly on the maximum is refused",
        """	if next > MaxWindowSize {""",
        """	if next >= MaxWindowSize {""",
        # TestTheWindowStaysInRangeAtBothExtremes does set the initial size to the
        # maximum, but from a window of -2147483647, so the change lands on 0 rather
        # than on the boundary. Only the test written for the boundary sees this.
        ["TestSetInitialSizeAcceptsAChangeThatLandsExactlyOnTheMaximum"],
    ),
    (
        "SetInitialSize: an overflowing SETTINGS frame resets one stream instead of ending the connection",
        """		return h2.ConnErrorf(h2.FlowControlError,
			"SETTINGS_INITIAL_WINDOW_SIZE of %d takes stream %d's window of %d "+
				"above the maximum %d (RFC 9113 §6.9.2)",
			n, w.streamID, w.n, int64(MaxWindowSize))""",
        """		return w.errorf(h2.FlowControlError,
			"SETTINGS_INITIAL_WINDOW_SIZE of %d takes stream %d's window of %d "+
				"above the maximum %d (RFC 9113 §6.9.2)",
			n, w.streamID, w.n, int64(MaxWindowSize))""",
        ["TestSetInitialSizeRefusesAChangeThatOverflowsAndChangesNothing"],
    ),
    (
        "SetInitialSize: the new initial size is recorded but the credit is not moved",
        """	w.initial = int64(n)
	w.n = next""",
        """	w.initial = int64(n)""",
        [
            "TestSetInitialSizeAppliesTheChangeAsADelta",
            "TestSetInitialSizeTakesTheWindowNegativeAndKeepsItThere",
            "TestSetInitialSizeAcceptsAChangeThatLandsExactlyOnTheMaximum",
        ],
    ),
    (
        "SetInitialSize: the credit moves but the initial size is not recorded, so the next delta is wrong",
        """	w.initial = int64(n)
	w.n = next""",
        """	w.n = next""",
        ["TestSetInitialSizeIsADeltaAgainstThePreviousSettingNotTheFirst"],
    ),
    (
        "SetInitialSize: a refused change records the new initial size anyway",
        """	next := w.n + (int64(n) - w.initial)
	if next > MaxWindowSize {""",
        """	next := w.n + (int64(n) - w.initial)
	if next > MaxWindowSize {
		w.initial = int64(n)""",
        ["TestSetInitialSizeRefusesAChangeThatOverflowsAndChangesNothing"],
    ),
    (
        "SetInitialSize: a negative window is clamped, so a stream may resend what it withdrew",
        """	w.initial = int64(n)
	w.n = next""",
        """	w.initial = int64(n)
	if next < 0 {
		next = 0
	}
	w.n = next""",
        [
            "TestSetInitialSizeTakesTheWindowNegativeAndKeepsItThere",
            "TestConsumeLetsAnEmptyFrameThroughANegativeWindow",
            "TestTheWindowStaysInRangeAtBothExtremes",
        ],
    ),

    # --- the scope of an error -----------------------------------------------
    #
    # The whole reason a Window carries its own stream identifier: RFC 9113 6.9
    # spells the same arithmetic fault two ways, and which one applies is a property
    # of the window rather than of the caller.
    (
        "errorf: every flow-control fault ends the connection, including one stream's overrun",
        """	if w.streamID == 0 {
		return h2.ConnErrorf(code, format, args...)
	}
	return h2.StreamErrorf(w.streamID, code, format, args...)""",
        """	return h2.ConnErrorf(code, format, args...)""",
        [
            "TestConsumeRefusesOneOctetTooMany",
            "TestConsumeRefusesAFrameLargerThanAnyWindow",
            "TestIncreaseRefusesTheOctetPastTheMaximum",
            "TestConsumeLetsAnEmptyFrameThroughANegativeWindow",
        ],
    ),
    (
        "errorf: a connection-level fault resets stream 0 rather than ending the connection",
        """	if w.streamID == 0 {
		return h2.ConnErrorf(code, format, args...)
	}
	return h2.StreamErrorf(w.streamID, code, format, args...)""",
        """	return h2.StreamErrorf(w.streamID, code, format, args...)""",
        [
            "TestConsumeRefusesOneOctetTooMany",
            "TestIncreaseRefusesTheOctetPastTheMaximum",
        ],
    ),
    (
        "errorf: a stream fault names the connection, so the wrong stream is reset",
        """	return h2.StreamErrorf(w.streamID, code, format, args...)""",
        """	return h2.StreamErrorf(0, code, format, args...)""",
        [
            "TestConsumeRefusesOneOctetTooMany",
            "TestIncreaseRefusesTheOctetPastTheMaximum",
        ],
    ),
    (
        "errorf: an overrun is reported as an internal error rather than a flow-control error",
        """		return w.errorf(h2.FlowControlError,
			"DATA of %d octets on a flow-control window of %d (RFC 9113 §6.9.1)", n, w.n)""",
        """		return w.errorf(h2.InternalError,
			"DATA of %d octets on a flow-control window of %d (RFC 9113 §6.9.1)", n, w.n)""",
        [
            "TestConsumeRefusesOneOctetTooMany",
            "TestConsumeRefusesAFrameLargerThanAnyWindow",
            "TestConsumeLetsAnEmptyFrameThroughANegativeWindow",
        ],
    ),

    # --- what the log says ---------------------------------------------------
    #
    # These strings are read next to h2spec output by someone deciding whether a
    # stalled transfer is this server's fault, so the numbers in them are part of the
    # guard rather than decoration.
    (
        "Consume: an overrun is reported without the frame's size or the window's",
        """			"DATA of %d octets on a flow-control window of %d (RFC 9113 §6.9.1)", n, w.n)""",
        """			"flow control error")""",
        ["TestTheErrorTextNamesTheNumbersAndTheRule"],
    ),
    (
        "Increase: an overflow is reported without the increment or the limit",
        """			"WINDOW_UPDATE of %d takes a window of %d above the maximum %d (RFC 9113 §6.9.1)",
			n, w.n, int64(MaxWindowSize))""",
        """			"flow control error")""",
        ["TestTheErrorTextNamesTheNumbersAndTheRule"],
    ),
    (
        "SetInitialSize: an overflowing setting is reported without naming the stream",
        """			"SETTINGS_INITIAL_WINDOW_SIZE of %d takes stream %d's window of %d "+
				"above the maximum %d (RFC 9113 §6.9.2)",
			n, w.streamID, w.n, int64(MaxWindowSize))""",
        """			"flow control error")""",
        ["TestTheErrorTextNamesTheNumbersAndTheRule"],
    ),
    (
        "SetInitialSize: the connection-window refusal does not say what to use instead",
        """			"SETTINGS_INITIAL_WINDOW_SIZE applied to the connection window, "+
				"which only WINDOW_UPDATE may change (RFC 9113 §6.9.2)")""",
        """			"bad setting")""",
        ["TestTheErrorTextNamesTheNumbersAndTheRule"],
    ),
]

breakage.main(SRC, PKG, BREAKS)
