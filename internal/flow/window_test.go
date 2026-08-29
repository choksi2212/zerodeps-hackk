package flow

import (
	"errors"
	"math"
	"strings"
	"testing"

	"zerodeps/zdh/internal/frame"
	"zerodeps/zdh/internal/h2"
)

// assertConnError checks err is a connection error carrying code, and that it is
// not a stream error.
//
// Both halves matter. The scope of a flow-control error is the thing this package
// exists to get right, and an assertion that only checks the code would pass on an
// error that ends the wrong thing — a stream reset where the connection should
// have died leaves a peer running on a setting the protocol forbids, and the
// reverse kills every other request on the connection over one stream's
// arithmetic.
func assertConnError(t *testing.T, err error, code h2.ErrCode) {
	t.Helper()
	var ce h2.ConnError
	if !errors.As(err, &ce) {
		t.Fatalf("got %v, want a connection error (RFC 9113 §5.4.1)", err)
	}
	if ce.Code != code {
		t.Errorf("the connection error carries %v, want %v", ce.Code, code)
	}
	var se h2.StreamError
	if errors.As(err, &se) {
		t.Errorf("the error is also a stream error on stream %d, so it would reset a "+
			"stream instead of ending the connection", se.StreamID)
	}
}

// assertStreamError checks err is a stream error on id carrying code, and that it
// is not a connection error. See assertConnError for why both are checked.
func assertStreamError(t *testing.T, err error, id uint32, code h2.ErrCode) {
	t.Helper()
	var se h2.StreamError
	if !errors.As(err, &se) {
		t.Fatalf("got %v, want a stream error (RFC 9113 §5.4.2)", err)
	}
	if se.StreamID != id {
		t.Errorf("the stream error names stream %d, want %d: a reset on the wrong "+
			"stream cancels a request that was behaving", se.StreamID, id)
	}
	if se.Code != code {
		t.Errorf("the stream error carries %v, want %v", se.Code, code)
	}
	var ce h2.ConnError
	if errors.As(err, &ce) {
		t.Error("the error is also a connection error, so one stream's fault would " +
			"end every other request on the connection")
	}
}

// assertPanics checks fn panics. Used for the two arguments NewStreamWindow
// refuses: both are conditions a correct caller cannot produce, so the failure
// belongs at construction rather than as an error every later call has to carry.
func assertPanics(t *testing.T, what string, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Errorf("%s did not panic", what)
		}
	}()
	fn()
}

// assertDoesNotPanic checks fn does not panic, and reports it as a failure when it
// does.
//
// The legal side of a boundary needs this as much as the illegal side needs
// assertPanics, and for a reason that is about the break campaign rather than
// about the code. NewStreamWindow's refusal is a panic, so an off-by-one that
// moved it one octet the wrong way would take the test binary down instead of
// failing a test — and the harness reports that as a crash, which is explicitly
// not a sign-off. Recovering here turns the same break into a named failure.
func assertDoesNotPanic(t *testing.T, what string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s panicked: %v", what, r)
		}
	}()
	fn()
}

func TestWindowConstantsAgreeWithTheFrameLayer(t *testing.T) {
	// Two packages name these constants: the SETTINGS validator refuses a value
	// above the maximum, and this package refuses a WINDOW_UPDATE that crosses it.
	// They are separate so that the arithmetic here can be tested without the wire
	// format, which is worth a duplicated number — but only while the two numbers
	// are the same one. A server whose SETTINGS validator and whose window
	// disagreed about the maximum would accept a setting it then could not honour.
	if MaxWindowSize != frame.MaxWindowSize {
		t.Errorf("flow.MaxWindowSize is %d and frame.MaxWindowSize is %d",
			int64(MaxWindowSize), int64(frame.MaxWindowSize))
	}
	if InitialWindowSize != frame.DefaultInitialWindowSize {
		t.Errorf("flow.InitialWindowSize is %d and frame.DefaultInitialWindowSize is %d",
			InitialWindowSize, frame.DefaultInitialWindowSize)
	}

	// The RFC's own numbers, spelled out, because the two pairs above could agree
	// with each other and both be wrong.
	if InitialWindowSize != 65535 {
		t.Errorf("the initial window is %d, want 65535 (RFC 9113 §6.9.2)", InitialWindowSize)
	}
	if MaxWindowSize != 2147483647 {
		t.Errorf("the maximum window is %d, want 2147483647 (RFC 9113 §6.9.1)",
			int64(MaxWindowSize))
	}
}

func TestNewWindowsStartAtTheInitialSize(t *testing.T) {
	if got := NewConnWindow().Available(); got != InitialWindowSize {
		t.Errorf("a new connection window has %d octets, want %d (RFC 9113 §6.9.2)",
			got, InitialWindowSize)
	}
	if got := NewConnWindow().StreamID(); got != 0 {
		t.Errorf("the connection window reports stream %d, want 0", got)
	}
	w := NewStreamWindow(7, InitialWindowSize)
	if got := w.Available(); got != InitialWindowSize {
		t.Errorf("a new stream window has %d octets, want %d", got, InitialWindowSize)
	}
	if got := w.StreamID(); got != 7 {
		t.Errorf("the stream window reports stream %d, want 7", got)
	}
}

func TestNewStreamWindowRefusesWhatCannotBeAStreamWindow(t *testing.T) {
	// Stream 0 is the connection, and a window that thought it was stream 0 would
	// report every error at connection scope — one stream's overrun would end the
	// whole connection.
	assertPanics(t, "NewStreamWindow(0, ...)", func() { NewStreamWindow(0, InitialWindowSize) })

	// A size above the maximum can only arrive if the SETTINGS validator was
	// bypassed, and every bound in this file would then be computed from a number
	// the protocol does not permit.
	assertPanics(t, "NewStreamWindow with an oversize initial", func() {
		NewStreamWindow(1, MaxWindowSize+1)
	})

	// The boundary from the legal side: exactly the maximum is a value a peer may
	// send, so it must not panic. Wrapped rather than called directly because a
	// panic here would kill the binary, and a break campaign reads a dead binary as
	// a crash rather than as a guard that fired.
	assertDoesNotPanic(t, "NewStreamWindow at exactly the maximum", func() {
		if got := NewStreamWindow(1, MaxWindowSize).Available(); got != MaxWindowSize {
			t.Errorf("a stream window at the maximum has %d octets, want %d",
				got, int64(MaxWindowSize))
		}
	})

	// And every stream identifier other than 0 is one this constructor must take,
	// including the largest §5.1.1 allows.
	assertDoesNotPanic(t, "NewStreamWindow on the largest legal stream identifier", func() {
		if got := NewStreamWindow(1<<31-1, 0).StreamID(); got != 1<<31-1 {
			t.Errorf("the window reports stream %d, want %d", got, uint32(1<<31-1))
		}
	})
}

func TestConsumeSpendsExactlyTheWindowAndNoMore(t *testing.T) {
	w := NewStreamWindow(1, 100)

	if err := w.Consume(60); err != nil {
		t.Fatalf("consuming 60 of 100 failed: %v", err)
	}
	if got := w.Available(); got != 40 {
		t.Fatalf("40 octets should be left, got %d", got)
	}

	// Exactly the remainder. The boundary from the legal side, and the one an
	// off-by-one in the comparison gets wrong: a sender is entitled to spend its
	// window down to zero.
	if err := w.Consume(40); err != nil {
		t.Fatalf("consuming the last 40 octets failed: %v", err)
	}
	if got := w.Available(); got != 0 {
		t.Fatalf("the window should be empty, got %d", got)
	}
}

func TestConsumeRefusesOneOctetTooMany(t *testing.T) {
	w := NewStreamWindow(9, 100)

	assertStreamError(t, w.Consume(101), 9, h2.FlowControlError)

	// The window is untouched by a refusal, and that is load-bearing rather than
	// tidy: the caller debits the connection window before this one, so a stream
	// window that debited itself on the way to refusing would have the frame
	// counted twice against a connection that is still running.
	if got := w.Available(); got != 100 {
		t.Errorf("a refused frame moved the window to %d, want it left at 100", got)
	}

	// And the connection window says the same thing at the other scope.
	cw := NewConnWindow()
	assertConnError(t, cw.Consume(InitialWindowSize+1), h2.FlowControlError)
	if got := cw.Available(); got != InitialWindowSize {
		t.Errorf("a refused frame moved the connection window to %d, want %d",
			got, InitialWindowSize)
	}
}

func TestConsumeRefusesAFrameLargerThanAnyWindow(t *testing.T) {
	// The largest length a uint32 can carry, against a window that is nearly
	// empty. Nothing here may wrap: in int32 arithmetic this length is -1, which
	// is less than any window and would be accepted as free.
	w := NewStreamWindow(3, 1)
	assertStreamError(t, w.Consume(math.MaxUint32), 3, h2.FlowControlError)
	if got := w.Available(); got != 1 {
		t.Errorf("the window moved to %d, want it left at 1", got)
	}
}

func TestConsumeLetsAnEmptyFrameThroughAnEmptyWindow(t *testing.T) {
	// §6.9.1: a zero-length DATA frame with END_STREAM MAY be sent when there is
	// no space in either window. It is how a sender closes a stream whose body is
	// finished, and refusing it parks a stream that has nothing left to send
	// behind a WINDOW_UPDATE the peer has no reason to send.
	w := NewStreamWindow(1, 0)
	if err := w.Consume(0); err != nil {
		t.Fatalf("an empty frame was refused on an empty window: %v", err)
	}
	if got := w.Available(); got != 0 {
		t.Errorf("an empty frame moved the window to %d, want 0", got)
	}
}

func TestConsumeLetsAnEmptyFrameThroughANegativeWindow(t *testing.T) {
	// The case the exemption is actually written for: a window only goes negative
	// through a SETTINGS change (§6.9.2), and a stream that has already sent its
	// last octet of body still owes an END_STREAM. Dropping the zero-length branch
	// leaves `int64(0) > w.n`, which is true here, so the empty frame is refused on
	// exactly the window the RFC exempts.
	w := deficitWindow(t, 5)
	if got := w.Available(); got >= 0 {
		t.Fatalf("the window is %d, want it negative for this test", got)
	}
	if err := w.Consume(0); err != nil {
		t.Fatalf("an empty frame was refused on a negative window: %v", err)
	}

	// One octet, though, is refused: the deficit has to be filled first.
	assertStreamError(t, w.Consume(1), 1, h2.FlowControlError)
}

// deficitWindow returns a stream window whose credit is negative by n octets,
// built the only way the protocol allows: spend the window, then have the peer
// lower its initial size (§6.9.2).
func deficitWindow(t *testing.T, n uint32) *Window {
	t.Helper()
	if n > InitialWindowSize {
		t.Fatalf("deficitWindow cannot build a deficit of %d from a window of %d",
			n, InitialWindowSize)
	}
	w := NewStreamWindow(1, InitialWindowSize)
	if err := w.Consume(InitialWindowSize); err != nil {
		t.Fatalf("spending the whole window failed: %v", err)
	}
	if err := w.SetInitialSize(InitialWindowSize - n); err != nil {
		t.Fatalf("lowering the initial size failed: %v", err)
	}
	if got := w.Available(); got != -int64(n) {
		t.Fatalf("the window is %d, want %d", got, -int64(n))
	}
	return w
}

func TestIncreaseCreditsUpToTheMaximum(t *testing.T) {
	w := NewStreamWindow(1, InitialWindowSize)

	if err := w.Increase(100); err != nil {
		t.Fatalf("crediting 100 octets failed: %v", err)
	}
	if got := w.Available(); got != InitialWindowSize+100 {
		t.Errorf("the window is %d, want %d", got, InitialWindowSize+100)
	}

	// Exactly to the maximum, from the legal side. A peer is entitled to fill the
	// window right up.
	w2 := NewStreamWindow(1, 0)
	if err := w2.Increase(MaxWindowSize); err != nil {
		t.Fatalf("crediting the window to exactly the maximum failed: %v", err)
	}
	if got := w2.Available(); got != MaxWindowSize {
		t.Errorf("the window is %d, want the maximum %d", got, int64(MaxWindowSize))
	}
}

func TestIncreaseRefusesTheOctetPastTheMaximum(t *testing.T) {
	// Matrix rows 30 and 31, which internal/frame defers here because the rule
	// needs the window's value and the frame carries only the increment.
	w := NewStreamWindow(5, 0)
	if err := w.Increase(MaxWindowSize); err != nil {
		t.Fatalf("crediting to the maximum failed: %v", err)
	}

	assertStreamError(t, w.Increase(1), 5, h2.FlowControlError)
	if got := w.Available(); got != MaxWindowSize {
		t.Errorf("a refused credit moved the window to %d, want the maximum %d",
			got, int64(MaxWindowSize))
	}

	// Row 30's other half: the same overflow on the connection window ends the
	// connection rather than a stream.
	cw := NewConnWindow()
	if err := cw.Increase(MaxWindowSize - InitialWindowSize); err != nil {
		t.Fatalf("crediting the connection window to the maximum failed: %v", err)
	}
	assertConnError(t, cw.Increase(1), h2.FlowControlError)
	if got := cw.Available(); got != MaxWindowSize {
		t.Errorf("a refused credit moved the connection window to %d, want %d",
			got, int64(MaxWindowSize))
	}
}

func TestIncreaseDoesNotWrapWhenBothHalvesAreAtTheMaximum(t *testing.T) {
	// The sum here is 2^32-2, which is the case that decides whether this
	// arithmetic needed 64 bits. In int32 it wraps to -2: the overflow check would
	// see a window far below the maximum, accept the credit, and leave the window
	// negative — a peer that had just doubled its credit past the legal maximum
	// would be recorded as owing octets, and the check written to refuse it would
	// have licensed it.
	w := NewStreamWindow(1, MaxWindowSize)
	assertStreamError(t, w.Increase(MaxWindowSize), 1, h2.FlowControlError)
	if got := w.Available(); got != MaxWindowSize {
		t.Errorf("the window is %d, want the maximum %d — a negative value here means "+
			"the sum wrapped", got, int64(MaxWindowSize))
	}
}

func TestIncreaseFillsADeficitBeforeItPaysForAnything(t *testing.T) {
	// §6.9.2: a sender must track a negative window and may not send until credit
	// makes it positive. Clamping the deficit to zero would let the stream send
	// the octets it had already spent a second time.
	w := deficitWindow(t, 10)

	if err := w.Increase(4); err != nil {
		t.Fatalf("crediting a negative window failed: %v", err)
	}
	if got := w.Available(); got != -6 {
		t.Fatalf("the window is %d, want -6: credit fills the deficit first", got)
	}
	assertStreamError(t, w.Consume(1), 1, h2.FlowControlError)

	if err := w.Increase(7); err != nil {
		t.Fatalf("crediting a negative window failed: %v", err)
	}
	if got := w.Available(); got != 1 {
		t.Fatalf("the window is %d, want 1", got)
	}
	if err := w.Consume(1); err != nil {
		t.Fatalf("spending the one octet the window now has failed: %v", err)
	}
}

func TestIncreaseByZeroChangesNothing(t *testing.T) {
	// A zero increment cannot arrive from the wire: parseWindowUpdate refuses it,
	// at connection scope on stream 0 and stream scope otherwise (§6.9). Asserted
	// here only so that the split is deliberate — this method does nothing with
	// it, rather than the two packages both having an opinion about what a zero
	// increment means.
	w := NewStreamWindow(1, 42)
	if err := w.Increase(0); err != nil {
		t.Fatalf("a zero increment was rejected here as well as in the frame layer: %v", err)
	}
	if got := w.Available(); got != 42 {
		t.Errorf("a zero increment moved the window to %d, want 42", got)
	}
}

func TestSetInitialSizeAppliesTheChangeAsADelta(t *testing.T) {
	// §6.9.2's central rule, and the one an assignment gets wrong. The stream has
	// spent 60 of its 100 octets; raising the initial size to 1000 grants it
	// another 900 on top of the 40 it has left, for 940. An assignment would give
	// it 1000 and hand back the 60 it already used.
	w := NewStreamWindow(1, 100)
	if err := w.Consume(60); err != nil {
		t.Fatalf("consuming 60 octets failed: %v", err)
	}
	if err := w.SetInitialSize(1000); err != nil {
		t.Fatalf("raising the initial size failed: %v", err)
	}
	if got := w.Available(); got != 940 {
		t.Errorf("the window is %d, want 940: the change is a delta against the "+
			"previous initial size, not an assignment (RFC 9113 §6.9.2)", got)
	}
}

func TestSetInitialSizeIsADeltaAgainstThePreviousSettingNotTheFirst(t *testing.T) {
	// Two changes in a row. The second delta is measured against the value the
	// first one set, so a window that kept its original initial size would apply
	// the wrong difference and drift further out with every SETTINGS frame — the
	// symptom being a transfer that stalls at a size depending on how often the
	// peer reconfigured itself.
	//
	// Something is consumed first, and that is what makes this test a test. With an
	// untouched window every delta lands on the same number an assignment would, so
	// the two are indistinguishable; break-flow.py caught this test passing against
	// an outright `next := int64(n)`. Spending 70 octets is what separates them:
	// each change now has to carry that deficit forward.
	w := NewStreamWindow(1, 100)
	if err := w.Consume(70); err != nil {
		t.Fatalf("consuming 70 octets failed: %v", err)
	}
	for _, n := range []uint32{300, 500} {
		if err := w.SetInitialSize(n); err != nil {
			t.Fatalf("setting the initial size to %d failed: %v", n, err)
		}
	}
	if got := w.Available(); got != 430 {
		t.Errorf("the window is %d, want 430: 30 left, plus 200 from the first change "+
			"and 200 from the second. 500 would mean each change was an assignment, "+
			"and 630 would mean the second delta was measured against the original "+
			"100 rather than against the 300 the first change set", got)
	}
}

func TestSetInitialSizeTakesTheWindowNegativeAndKeepsItThere(t *testing.T) {
	// §6.9.2 permits this and requires the deficit to be carried: the peer has
	// taken back credit the stream already spent.
	w := NewStreamWindow(1, 1000)
	if err := w.Consume(800); err != nil {
		t.Fatalf("consuming 800 octets failed: %v", err)
	}
	if err := w.SetInitialSize(100); err != nil {
		t.Fatalf("lowering the initial size failed: %v", err)
	}
	if got := w.Available(); got != -700 {
		t.Errorf("the window is %d, want -700: 200 left, less the 900 the peer "+
			"withdrew (RFC 9113 §6.9.2)", got)
	}
}

func TestSetInitialSizeAcceptsAChangeThatLandsExactlyOnTheMaximum(t *testing.T) {
	// The legal side of the bound §6.9.2 imposes, which nothing else here covers:
	// a change may take a window right up to the maximum, and only the octet past
	// it is an error. A `>=` in that check would refuse a peer that is behaving.
	//
	// The window starts at 1 and the initial size is 1, so setting the initial size
	// to the maximum is a delta of 2147483646 and lands on 2147483647 exactly.
	w := NewStreamWindow(1, 1)
	if err := w.SetInitialSize(MaxWindowSize); err != nil {
		t.Fatalf("a change landing exactly on the maximum was refused: %v", err)
	}
	if got := w.Available(); got != MaxWindowSize {
		t.Errorf("the window is %d, want the maximum %d", got, int64(MaxWindowSize))
	}
}

func TestSetInitialSizeRefusesAChangeThatOverflowsAndChangesNothing(t *testing.T) {
	w := NewStreamWindow(11, 1)
	if err := w.Increase(MaxWindowSize - 1); err != nil {
		t.Fatalf("crediting the window to the maximum failed: %v", err)
	}

	// A connection error, not a stream error, and this is the one place in the
	// package where the scope does not follow the window. The fault is in a
	// SETTINGS frame, which belongs to the connection and can push any number of
	// streams over at once; resetting the streams it happened to overflow would
	// leave the connection running on a setting the peer may not send.
	assertConnError(t, w.SetInitialSize(MaxWindowSize), h2.FlowControlError)

	// Neither field moved. The window matters because the connection is ending
	// anyway; the initial size matters because a partial change would make every
	// later delta wrong, and it is only observable through a following change.
	if got := w.Available(); got != MaxWindowSize {
		t.Errorf("a refused change moved the window to %d, want the maximum %d",
			got, int64(MaxWindowSize))
	}
	if err := w.SetInitialSize(0); err != nil {
		t.Fatalf("a later change failed after a refused one: %v", err)
	}
	// The initial size is still 1, so this delta is -1 and the window drops by one.
	// Had the refused change set it to the maximum, the delta would have been
	// -2147483647 and the window would now be 0.
	if got := w.Available(); got != MaxWindowSize-1 {
		t.Errorf("the window is %d, want %d: the refused change must not have moved "+
			"the initial size", got, int64(MaxWindowSize)-1)
	}
}

func TestSetInitialSizeRefusesTheConnectionWindow(t *testing.T) {
	// §6.9.2 confines this setting to stream windows and makes WINDOW_UPDATE the
	// only way to change the connection's. A server that applied a peer's SETTINGS
	// here would desynchronise the connection's credit by the delta, permanently,
	// with nothing to resynchronise it — the symptom being a transfer that stalls
	// at a size no test would reproduce.
	cw := NewConnWindow()
	assertConnError(t, cw.SetInitialSize(1000), h2.InternalError)
	if got := cw.Available(); got != InitialWindowSize {
		t.Errorf("the connection window moved to %d, want %d", got, InitialWindowSize)
	}
}

func TestTheWindowStaysInRangeAtBothExtremes(t *testing.T) {
	// The reachable extremes, so that the int64 field is shown to be enough rather
	// than assumed to be.
	//
	// The floor is -MaxWindowSize, and it takes the whole protocol to reach: a
	// window at the maximum, spent to nothing, then an initial size of zero
	// withdrawing all of it. It cannot go lower, and the reason is worth stating
	// because it is what makes the bound a bound rather than a coincidence — once
	// the initial size is zero every later delta is (n - 0), which is never
	// negative, and Consume refuses to spend a window that has nothing in it.
	w := NewStreamWindow(1, MaxWindowSize)
	if err := w.Consume(MaxWindowSize); err != nil {
		t.Fatalf("spending the largest legal window failed: %v", err)
	}
	if err := w.SetInitialSize(0); err != nil {
		t.Fatalf("withdrawing the largest legal window failed: %v", err)
	}
	if got := w.Available(); got != -MaxWindowSize {
		t.Fatalf("the window is %d, want %d", got, -int64(MaxWindowSize))
	}
	if got := w.Available(); got < math.MinInt32 || got > math.MaxInt32 {
		t.Errorf("the window is %d, which is outside the int32 range a window "+
			"nominally occupies", got)
	}

	// And from there the only direction is up, which is the argument that the
	// floor above is the floor.
	if err := w.SetInitialSize(MaxWindowSize); err != nil {
		t.Fatalf("granting the window back failed: %v", err)
	}
	if got := w.Available(); got != 0 {
		t.Errorf("the window is %d, want 0", got)
	}
}

func TestWindowsDoNotShareState(t *testing.T) {
	// A connection holds four kinds of window at once and they move
	// independently. Cheap to assert, and it is the failure a value receiver on
	// any of these methods would produce: the change would land on a copy and the
	// original would never move, which reads as a peer that never spends its
	// credit.
	a := NewStreamWindow(1, 100)
	b := NewStreamWindow(2, 100)
	if err := a.Consume(100); err != nil {
		t.Fatalf("consuming stream 1's window failed: %v", err)
	}
	if got := a.Available(); got != 0 {
		t.Errorf("stream 1's window is %d, want 0 — a value receiver would leave it "+
			"at 100", got)
	}
	if got := b.Available(); got != 100 {
		t.Errorf("stream 2's window is %d, want 100: it is a separate window", got)
	}
}

func TestTheErrorTextNamesTheNumbersAndTheRule(t *testing.T) {
	// These strings are read in a server log next to h2spec output, by someone
	// deciding whether a stalled transfer is this server's fault. An error saying
	// only "flow control error" sends that person to a debugger.

	overflowingSetting := NewStreamWindow(4, 1)
	if err := overflowingSetting.Increase(MaxWindowSize - 1); err != nil {
		t.Fatalf("crediting the window to the maximum failed: %v", err)
	}

	for _, tc := range []struct {
		what string
		err  error
		want []string
	}{
		{
			"an overrun",
			NewStreamWindow(1, 10).Consume(11),
			[]string{"DATA", "11", "10", "§6.9.1"},
		},
		{
			"an overflowing WINDOW_UPDATE",
			NewStreamWindow(1, MaxWindowSize).Increase(2),
			[]string{"WINDOW_UPDATE", "2", "2147483647", "§6.9.1"},
		},
		{
			"an overflowing SETTINGS_INITIAL_WINDOW_SIZE",
			overflowingSetting.SetInitialSize(MaxWindowSize),
			[]string{"SETTINGS_INITIAL_WINDOW_SIZE", "stream 4", "2147483647", "§6.9.2"},
		},
		{
			"that setting applied to the connection window",
			NewConnWindow().SetInitialSize(1),
			[]string{"SETTINGS_INITIAL_WINDOW_SIZE", "WINDOW_UPDATE", "§6.9.2"},
		},
	} {
		if tc.err == nil {
			t.Errorf("%s produced no error", tc.what)
			continue
		}
		for _, want := range tc.want {
			if !strings.Contains(tc.err.Error(), want) {
				t.Errorf("the error for %s does not mention %q: %v", tc.what, want, tc.err)
			}
		}
	}
}
