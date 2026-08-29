package flow

import (
	"errors"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"zerodeps/zdh/internal/h2"
)

// parkDeadline bounds every wait in this file: for a writer to park in Reserve, and
// for a parked writer to come back once something has woken it.
//
// It is only reached when a test is about to fail. On a working Sender a park is a
// few scheduler turns away and a wake-up is one broadcast away, so nothing here
// waits measurably.
//
// Bounding the wake-up side matters more than it looks, and it is why these tests
// do not simply read from a channel. A Sender that never broadcasts does not fail a
// test that blocks on a channel — it hangs it, and the report is then go test's own
// timeout, which names the package and dumps every goroutine in it rather than
// naming the guard that went. scripts/break-sender.py removes each broadcast in
// turn, and a break whose only symptom is a hang is a break the campaign has to
// score as a hole. Failing by name in five seconds is the difference.
const parkDeadline = 5 * time.Second

// waitForWaiters spins until n goroutines are parked in Reserve.
//
// It yields rather than sleeps. A sleep long enough to be reliable is long enough to
// notice across a test suite, and the thing being waited for is a scheduler
// transition rather than the passage of time.
//
// The count cannot be observed mid-transition: Reserve increments it, waits, and
// decrements it without ever releasing the lock in between, so a writer that is
// woken and parks again is never seen as zero.
func waitForWaiters(t *testing.T, s *Sender, n int) {
	t.Helper()

	deadline := time.Now().Add(parkDeadline)
	for s.waiters() < n {
		if time.Now().After(deadline) {
			t.Fatalf("waited %v for %d writers to park in Reserve; %d are", parkDeadline, n, s.waiters())
		}
		runtime.Gosched()
	}
}

// reservation is the outcome of one Reserve call made from another goroutine.
type reservation struct {
	n   int
	err error
}

// reserveAsync calls Reserve from a new goroutine and returns a channel carrying
// its one result.
func reserveAsync(s *Sender, id uint32, want int) <-chan reservation {
	out := make(chan reservation, 1)
	go func() {
		n, err := s.Reserve(id, want)
		out <- reservation{n, err}
	}()
	return out
}

// awaitReservation reads a reservation, failing rather than hanging if it does not
// arrive. See parkDeadline.
func awaitReservation(t *testing.T, out <-chan reservation) reservation {
	t.Helper()

	select {
	case got := <-out:
		return got
	case <-time.After(parkDeadline):
		t.Fatalf("Reserve did not return within %v; nothing woke it", parkDeadline)
		return reservation{}
	}
}

// mustReserve reads a reservation that is expected to have succeeded with exactly n
// octets.
func mustReserve(t *testing.T, out <-chan reservation, n int) {
	t.Helper()

	got := awaitReservation(t, out)
	if got.err != nil {
		t.Fatalf("Reserve: %v, want %d octets", got.err, n)
	}
	if got.n != n {
		t.Errorf("Reserve took %d octets, want %d", got.n, n)
	}
}

// awaitGroup waits for wg, failing rather than hanging if some goroutine in it is
// still parked. See parkDeadline.
func awaitGroup(t *testing.T, wg *sync.WaitGroup, what string) {
	t.Helper()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(parkDeadline):
		t.Fatalf("%s did not finish within %v; something is still parked", what, parkDeadline)
	}
}

func TestNewSenderStartsAtTheSizesBothEndsMustAssume(t *testing.T) {
	// §6.9.2 fixes both at 65535 until a SETTINGS frame says otherwise, and a
	// server that started either one anywhere else would disagree with a peer that
	// had not sent SETTINGS yet — which is every peer, for its first round trip.
	s := NewSender()

	if got := s.ConnAvailable(); got != InitialWindowSize {
		t.Errorf("ConnAvailable is %d, want %d", got, InitialWindowSize)
	}
	if got := s.InitialSize(); got != InitialWindowSize {
		t.Errorf("InitialSize is %d, want %d", got, InitialWindowSize)
	}
}

func TestOpenSizesAStreamAtThePeersInitialWindow(t *testing.T) {
	s := NewSender()
	if err := s.SetInitialSize(1000); err != nil {
		t.Fatalf("SetInitialSize: %v", err)
	}
	s.Open(1)

	n, ok := s.Available(1)
	if !ok {
		t.Fatal("Available says stream 1 is not open, want it open")
	}
	if n != 1000 {
		t.Errorf("stream 1 has %d octets of credit, want the peer's initial window size 1000", n)
	}
}

func TestOpenDoesNotTouchTheConnectionWindow(t *testing.T) {
	// §6.9.2 gives WINDOW_UPDATE as the only way to change the connection window.
	// A stream opening is not a grant of anything, and a Sender that added the
	// initial size per stream would credit itself for every request the peer made.
	s := NewSender()
	for id := uint32(1); id < 20; id += 2 {
		s.Open(id)
	}

	if got := s.ConnAvailable(); got != InitialWindowSize {
		t.Errorf("ConnAvailable is %d after ten streams opened, want it unchanged at %d",
			got, InitialWindowSize)
	}
}

func TestOpenRefusesTheSameStreamTwice(t *testing.T) {
	s := NewSender()
	s.Open(1)

	assertPanics(t, "Open of a stream that is already open", func() { s.Open(1) })
}

func TestOpenRefusesTheConnectionAsAStream(t *testing.T) {
	// Stream 0 is the connection, its window is not a stream window, and
	// NewStreamWindow is the guard. Asserted here so that the guard is known to
	// still be reachable through this path rather than only through that one.
	s := NewSender()

	assertPanics(t, "Open of stream 0", func() { s.Open(0) })
}

func TestAvailableReportsAStreamThatWasNeverOpened(t *testing.T) {
	s := NewSender()

	if n, ok := s.Available(7); ok {
		t.Errorf("Available says stream 7 is open with %d octets, want it absent", n)
	}
}

func TestRetireClosesTheStream(t *testing.T) {
	s := NewSender()
	s.Open(1)
	s.Retire(1)

	if n, ok := s.Available(1); ok {
		t.Errorf("Available says stream 1 is open with %d octets after Retire, want it absent", n)
	}
}

func TestRetireOfAStreamThatIsNotOpenChangesNothing(t *testing.T) {
	// Reached from every path that ends a stream — END_STREAM both ways,
	// RST_STREAM from the peer, a stream error of ours — and none of them checks
	// first whether one of the others got there already.
	s := NewSender()
	s.Open(1)

	assertDoesNotPanic(t, "Retire of a stream that was never open", func() { s.Retire(3) })
	assertDoesNotPanic(t, "Retire of a stream twice", func() { s.Retire(1); s.Retire(1) })

	if got := s.ConnAvailable(); got != InitialWindowSize {
		t.Errorf("ConnAvailable is %d, want the connection window untouched at %d",
			got, InitialWindowSize)
	}
}

func TestReserveTakesWhatWasAskedWhenBothWindowsAllowIt(t *testing.T) {
	s := NewSender()
	s.Open(1)

	n, err := s.Reserve(1, 100)
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if n != 100 {
		t.Errorf("Reserve took %d octets, want the 100 it was asked for", n)
	}
}

func TestReserveDebitsBothWindows(t *testing.T) {
	// The whole point of the type. §6.9.1 spends the stream's credit and the
	// connection's for the same DATA frame, and a sender that debited one of them
	// would overrun the other by the size of every response it sent.
	s := NewSender()
	s.Open(1)

	if _, err := s.Reserve(1, 100); err != nil {
		t.Fatalf("Reserve: %v", err)
	}

	if got := s.ConnAvailable(); got != InitialWindowSize-100 {
		t.Errorf("ConnAvailable is %d, want %d", got, InitialWindowSize-100)
	}
	n, _ := s.Available(1)
	if n != InitialWindowSize-100 {
		t.Errorf("stream 1 has %d octets, want %d", n, InitialWindowSize-100)
	}
}

func TestReserveIsCappedByTheStreamWindow(t *testing.T) {
	s := NewSender()
	if err := s.SetInitialSize(10); err != nil {
		t.Fatalf("SetInitialSize: %v", err)
	}
	s.Open(1)

	n, err := s.Reserve(1, 1000)
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if n != 10 {
		t.Errorf("Reserve took %d octets, want the stream window's 10", n)
	}
}

func TestReserveIsCappedByTheConnectionWindow(t *testing.T) {
	// The case that separates this type from a per-stream window: stream 3 has a
	// full window of its own and may still send only what the connection has left,
	// because stream 1 spent the rest of it. A Sender that clamped to the stream
	// window alone would send 65535 octets against 5535 octets of credit, and
	// §6.9.1 makes that a connection error the peer is entitled to report.
	s := NewSender()
	s.Open(1)
	s.Open(3)

	if _, err := s.Reserve(1, InitialWindowSize-5535); err != nil {
		t.Fatalf("Reserve on stream 1: %v", err)
	}

	n, err := s.Reserve(3, InitialWindowSize)
	if err != nil {
		t.Fatalf("Reserve on stream 3: %v", err)
	}
	if n != 5535 {
		t.Errorf("Reserve on stream 3 took %d octets, want the connection window's remaining 5535", n)
	}
	if got := s.ConnAvailable(); got != 0 {
		t.Errorf("ConnAvailable is %d, want 0", got)
	}
	if got, _ := s.Available(3); got != InitialWindowSize-5535 {
		t.Errorf("stream 3 has %d octets, want %d — only what it spent",
			got, InitialWindowSize-5535)
	}
}

func TestReserveTakesTheSmallerOfTwoCapsWhicheverItIs(t *testing.T) {
	// Both directions of the same comparison, because a clamp written the wrong
	// way round still passes whichever of the two cases happens to be tested.
	tests := []struct {
		name       string
		streamSize uint32
		spendConn  int
		want       int
	}{
		{name: "the stream window is the smaller", streamSize: 40, spendConn: 0, want: 40},
		{name: "the connection window is the smaller", streamSize: 5000, spendConn: InitialWindowSize - 40, want: 40},
		{name: "they are equal", streamSize: 40, spendConn: InitialWindowSize - 40, want: 40},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSender()
			if err := s.SetInitialSize(tt.streamSize); err != nil {
				t.Fatalf("SetInitialSize: %v", err)
			}
			s.Open(1)

			if tt.spendConn > 0 {
				// Spent through a stream whose own window is wide enough not to
				// be the cap, so the only thing this drains is the connection.
				if err := s.SetInitialSize(MaxWindowSize); err != nil {
					t.Fatalf("SetInitialSize: %v", err)
				}
				s.Open(99)
				if _, err := s.Reserve(99, tt.spendConn); err != nil {
					t.Fatalf("draining the connection window: %v", err)
				}
				if err := s.SetInitialSize(tt.streamSize); err != nil {
					t.Fatalf("SetInitialSize: %v", err)
				}
			}

			n, err := s.Reserve(1, 1_000_000)
			if err != nil {
				t.Fatalf("Reserve: %v", err)
			}
			if n != tt.want {
				t.Errorf("Reserve took %d octets, want %d", n, tt.want)
			}
		})
	}
}

func TestReserveRefusesARequestForNothing(t *testing.T) {
	// §6.9.1 exempts an empty DATA frame from flow control, so a caller with
	// nothing to send must send it without asking. Answering zero would look like
	// permission and would put a caller into a loop that never blocks and never
	// progresses.
	s := NewSender()
	s.Open(1)

	assertPanics(t, "Reserve of 0 octets", func() { _, _ = s.Reserve(1, 0) })
	assertPanics(t, "Reserve of a negative number of octets", func() { _, _ = s.Reserve(1, -1) })
}

func TestReserveReportsAStreamThatIsNotOpen(t *testing.T) {
	s := NewSender()

	n, err := s.Reserve(7, 100)
	if !errors.Is(err, ErrStreamGone) {
		t.Errorf("Reserve on a stream that was never open: %d, %v; want ErrStreamGone", n, err)
	}
	if n != 0 {
		t.Errorf("Reserve took %d octets from a stream that is not open, want 0", n)
	}
}

func TestReserveWaitsForAStreamWindowUpdate(t *testing.T) {
	// The reservation cannot be answered with 50 octets until the WINDOW_UPDATE
	// below arrives, so reading 50 from the channel is itself the proof that it
	// waited. Reserve never returns zero octets and a nil error, which is what
	// makes that inference sound rather than merely likely.
	s := NewSender()
	if err := s.SetInitialSize(0); err != nil {
		t.Fatalf("SetInitialSize: %v", err)
	}
	s.Open(1)

	out := reserveAsync(s, 1, 100)
	waitForWaiters(t, s, 1)

	if err := s.CreditStream(1, 50); err != nil {
		t.Fatalf("CreditStream: %v", err)
	}
	mustReserve(t, out, 50)

	// And nothing is parked once it has returned. Asserted because the count is
	// what every wait in this file reads: one that only ever went up would make
	// waitForWaiters return immediately for the rest of the run, and the tests that
	// depend on a writer being asleep would be checking nothing.
	if got := s.waiters(); got != 0 {
		t.Errorf("%d writers are parked in Reserve after the last one returned, want 0", got)
	}
}

func TestReserveWaitsForAConnectionWindowUpdate(t *testing.T) {
	s := NewSender()
	s.Open(1)
	if _, err := s.Reserve(1, InitialWindowSize); err != nil {
		t.Fatalf("draining the connection window: %v", err)
	}
	s.Open(3)

	out := reserveAsync(s, 3, 100)
	waitForWaiters(t, s, 1)

	if err := s.CreditConn(50); err != nil {
		t.Fatalf("CreditConn: %v", err)
	}
	mustReserve(t, out, 50)
}

func TestReserveWaitsForWhicheverWindowIsEmpty(t *testing.T) {
	// Credit on the wrong window is not credit. Stream 1 has a hundred octets of its
	// own and the connection has none, so the only frame that can release this writer
	// is a stream-0 WINDOW_UPDATE — and what it is released for is the connection's
	// thirty rather than its own hundred.
	//
	// The stream's credit is granted before the writer parks rather than after.
	// Granting it afterwards would wake the writer, and a woken writer is
	// indistinguishable from a parked one until it has re-taken the lock: the count
	// waitForWaiters reads does not drop in between, by design. So a test that
	// credited the wrong window while the writer was asleep would be asserting the
	// order the runtime happened to schedule two goroutines in.
	s := NewSender()
	s.Open(1)
	if _, err := s.Reserve(1, InitialWindowSize); err != nil {
		t.Fatalf("draining both windows through stream 1: %v", err)
	}
	if err := s.CreditStream(1, 100); err != nil {
		t.Fatalf("CreditStream: %v", err)
	}

	out := reserveAsync(s, 1, 100)
	waitForWaiters(t, s, 1)

	if err := s.CreditConn(30); err != nil {
		t.Fatalf("CreditConn: %v", err)
	}
	mustReserve(t, out, 30)
}

// TestCreditOnTheConnectionWakesEveryWriterAndNotJustOne is the case that decides
// Broadcast over Signal.
//
// Four writers are parked for two different reasons: three are waiting for their own
// stream windows, one is waiting for the connection's. A stream-0 WINDOW_UPDATE is no
// use at all to the first three and is exactly what the fourth is waiting for, and
// nothing about a parked writer says which kind it is. Waking one and hoping is how
// the credit gets lost: a writer that cannot use it goes back to sleep having spent
// the only notification there was, and the writer that could have used it stays
// asleep with credit sitting unspent on the connection.
//
// The order the writers park in is fixed rather than incidental — each one is known
// to be asleep before the next is started — so that the writer this test is about is
// the last in the queue rather than a coin toss.
func TestCreditOnTheConnectionWakesEveryWriterAndNotJustOne(t *testing.T) {
	s := NewSender()
	if err := s.SetInitialSize(0); err != nil {
		t.Fatalf("SetInitialSize: %v", err)
	}

	// Streams 1, 5 and 7 have nothing and are given nothing. Stream 3 has credit of
	// its own and is short of the connection's.
	for _, id := range []uint32{1, 5, 7, 3} {
		s.Open(id)
	}
	if err := s.CreditStream(3, 100); err != nil {
		t.Fatalf("CreditStream: %v", err)
	}

	// Drained through a stream of its own, and retired again, so that the only
	// window left empty is the connection's.
	s.Open(9)
	if err := s.CreditStream(9, InitialWindowSize); err != nil {
		t.Fatalf("CreditStream: %v", err)
	}
	if _, err := s.Reserve(9, InitialWindowSize); err != nil {
		t.Fatalf("draining the connection window: %v", err)
	}
	s.Retire(9)

	hopeless := make([]<-chan reservation, 0, 3)
	for i, id := range []uint32{1, 5, 7} {
		hopeless = append(hopeless, reserveAsync(s, id, 10))
		waitForWaiters(t, s, i+1)
	}
	waiting := reserveAsync(s, 3, 10)
	waitForWaiters(t, s, 4)

	if err := s.CreditConn(10); err != nil {
		t.Fatalf("CreditConn: %v", err)
	}
	mustReserve(t, waiting, 10)

	// The other three are waiting for a frame this test will not send, and retiring
	// their streams is how the reader goroutine would end them.
	for _, id := range []uint32{1, 5, 7} {
		s.Retire(id)
	}
	for i, out := range hopeless {
		got := awaitReservation(t, out)
		if !errors.Is(got.err, ErrStreamGone) {
			t.Errorf("the writer parked on a stream window returned %d, %v; want ErrStreamGone "+
				"(writer %d)", got.n, got.err, i)
		}
	}
}

func TestReserveWakesWhenTheStreamIsRetired(t *testing.T) {
	s := NewSender()
	if err := s.SetInitialSize(0); err != nil {
		t.Fatalf("SetInitialSize: %v", err)
	}
	s.Open(1)

	out := reserveAsync(s, 1, 100)
	waitForWaiters(t, s, 1)

	s.Retire(1)

	got := awaitReservation(t, out)
	if !errors.Is(got.err, ErrStreamGone) {
		t.Errorf("Reserve after Retire: %d, %v; want ErrStreamGone", got.n, got.err)
	}
}

func TestReserveWakesEveryWriterWhenTheConnectionEnds(t *testing.T) {
	// Without this the writers wait for the life of the process: the WINDOW_UPDATE
	// they want cannot arrive, and a condition variable has no deadline of its own.
	//
	// Four writers rather than one, because Close has to reach all of them and waking
	// a single writer would look correct on a connection carrying a single request.
	// Nothing has woken any of them by the time Close is called — no credit has
	// arrived and no stream has been retired — so each one is genuinely asleep rather
	// than on its way back to the lock, which is what makes the count below mean what
	// it says.
	s := NewSender()
	if err := s.SetInitialSize(0); err != nil {
		t.Fatalf("SetInitialSize: %v", err)
	}
	ids := []uint32{1, 3, 5, 7}
	for _, id := range ids {
		s.Open(id)
	}

	outs := make([]<-chan reservation, len(ids))
	for i, id := range ids {
		outs[i] = reserveAsync(s, id, 100)
		waitForWaiters(t, s, i+1)
	}

	reason := errors.New("the peer stopped reading")
	s.Close(reason)

	for i, out := range outs {
		got := awaitReservation(t, out)
		if !errors.Is(got.err, reason) {
			t.Errorf("the writer on stream %d returned %d, %v; want the reason Close was given",
				ids[i], got.n, got.err)
		}
	}
}

func TestReserveOnAClosedConnectionDoesNotWait(t *testing.T) {
	s := NewSender()
	s.Open(1)
	reason := errors.New("gone")
	s.Close(reason)

	if _, err := s.Reserve(1, 100); !errors.Is(err, reason) {
		t.Errorf("Reserve: %v, want the reason Close was given", err)
	}
}

func TestReserveReportsTheConnectionEndingEvenWhenThereIsCreditToSpend(t *testing.T) {
	// A writer that wakes to find the connection over must not look at the credit
	// first. Octets granted on a connection nobody will write to are not a
	// reservation the caller can act on: returning them puts a frame down a socket
	// that is already finished, and the caller has no way to give them back.
	//
	// The arrangement is the one that separates checking the connection's fate from
	// checking the windows. Stream 1 has a hundred octets and the connection has
	// none, so a Sender that consulted the windows first would find one of them with
	// credit, be unable to spend it because the other is empty, and park again on a
	// connection that has ended — which is a writer that never returns rather than a
	// writer that returns the wrong thing.
	//
	// The credit is granted before the writer parks for the same reason as in
	// TestReserveWaitsForWhicheverWindowIsEmpty, and for one more: credit offered
	// after Close is dropped by CreditStream rather than applied, so a test that
	// tried to arrange this state that way would not be arranging it at all.
	s := NewSender()
	s.Open(1)
	if _, err := s.Reserve(1, InitialWindowSize); err != nil {
		t.Fatalf("draining both windows through stream 1: %v", err)
	}
	if err := s.CreditStream(1, 100); err != nil {
		t.Fatalf("CreditStream: %v", err)
	}

	out := reserveAsync(s, 1, 100)
	waitForWaiters(t, s, 1)

	reason := errors.New("gone")
	s.Close(reason)

	got := awaitReservation(t, out)
	if !errors.Is(got.err, reason) {
		t.Errorf("Reserve: %d, %v; want the reason Close was given", got.n, got.err)
	}
}

func TestReserveFillsADeficitBeforeItPaysForAnything(t *testing.T) {
	// §6.9.2's shrink, from the sending side. The stream spent 1000 octets and the
	// peer then lowered the initial window size to 0, so the window is -1000 and
	// the next 1000 octets of credit are owed rather than available. A Sender that
	// clamped the deficit to zero would let the stream send those 1000 octets
	// twice.
	s := NewSender()
	if err := s.SetInitialSize(1000); err != nil {
		t.Fatalf("SetInitialSize: %v", err)
	}
	s.Open(1)
	if _, err := s.Reserve(1, 1000); err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if err := s.SetInitialSize(0); err != nil {
		t.Fatalf("SetInitialSize: %v", err)
	}
	if got, _ := s.Available(1); got != -1000 {
		t.Fatalf("stream 1 has %d octets, want the deficit -1000", got)
	}

	out := reserveAsync(s, 1, 10)
	waitForWaiters(t, s, 1)

	// Fills the hole exactly, and buys nothing.
	if err := s.CreditStream(1, 1000); err != nil {
		t.Fatalf("CreditStream: %v", err)
	}
	waitForWaiters(t, s, 1)

	if err := s.CreditStream(1, 4); err != nil {
		t.Fatalf("CreditStream: %v", err)
	}
	mustReserve(t, out, 4)
}

func TestSetInitialSizeAppliesToOpenStreamsAsADelta(t *testing.T) {
	s := NewSender()
	if err := s.SetInitialSize(1000); err != nil {
		t.Fatalf("SetInitialSize: %v", err)
	}
	s.Open(1)
	if _, err := s.Reserve(1, 600); err != nil {
		t.Fatalf("Reserve: %v", err)
	}

	if err := s.SetInitialSize(1500); err != nil {
		t.Fatalf("SetInitialSize: %v", err)
	}

	// 400 left, plus the 500 the change granted. Not 1500: the 600 already spent
	// stays spent.
	if got, _ := s.Available(1); got != 900 {
		t.Errorf("stream 1 has %d octets, want 900 — the 400 it had plus the 500 granted", got)
	}
}

func TestSetInitialSizeSizesStreamsOpenedAfterwards(t *testing.T) {
	s := NewSender()
	s.Open(1)
	if err := s.SetInitialSize(1000); err != nil {
		t.Fatalf("SetInitialSize: %v", err)
	}
	s.Open(3)

	if got, _ := s.Available(3); got != 1000 {
		t.Errorf("stream 3 opened with %d octets, want the peer's current 1000", got)
	}
	if got := s.InitialSize(); got != 1000 {
		t.Errorf("InitialSize is %d, want 1000", got)
	}
}

func TestSetInitialSizeLeavesTheConnectionWindowAlone(t *testing.T) {
	// §6.9.2 confines the setting to stream windows. A Sender that applied it to
	// the connection's would desynchronise the connection's credit by the delta,
	// permanently, with nothing able to resynchronise it.
	s := NewSender()
	s.Open(1)

	if err := s.SetInitialSize(MaxWindowSize); err != nil {
		t.Fatalf("SetInitialSize: %v", err)
	}

	if got := s.ConnAvailable(); got != InitialWindowSize {
		t.Errorf("ConnAvailable is %d, want it unchanged at %d", got, InitialWindowSize)
	}
}

func TestSetInitialSizeWakesEveryParkedWriter(t *testing.T) {
	// One frame, several grants. A Sender that signalled one waiter would leave
	// the rest asleep on windows that now have credit.
	s := NewSender()
	if err := s.SetInitialSize(0); err != nil {
		t.Fatalf("SetInitialSize: %v", err)
	}
	ids := []uint32{1, 3, 5, 7}
	for _, id := range ids {
		s.Open(id)
	}

	outs := make([]<-chan reservation, len(ids))
	for i, id := range ids {
		outs[i] = reserveAsync(s, id, 10)
	}
	waitForWaiters(t, s, len(ids))

	if err := s.SetInitialSize(10); err != nil {
		t.Fatalf("SetInitialSize: %v", err)
	}

	for i, out := range outs {
		got := awaitReservation(t, out)
		if got.err != nil {
			t.Errorf("Reserve on stream %d: %v, want 10 octets", ids[i], got.err)
			continue
		}
		if got.n != 10 {
			t.Errorf("Reserve on stream %d took %d octets, want 10", ids[i], got.n)
		}
	}
}

func TestSetInitialSizeRefusesAChangeThatOverflowsAStreamWindow(t *testing.T) {
	// §6.9.2: a change that takes any window past 2^31-1 is a connection error of
	// type FLOW_CONTROL_ERROR — connection-scoped even though the window is one
	// stream's, because the fault is in a frame that belongs to the connection.
	s := NewSender()
	s.Open(1)
	if err := s.CreditStream(1, 1000); err != nil {
		t.Fatalf("CreditStream: %v", err)
	}

	err := s.SetInitialSize(MaxWindowSize)
	assertConnError(t, err, h2.FlowControlError)
}

func TestSetInitialSizeNamesTheLowestStreamItOverflows(t *testing.T) {
	// Several streams overflow at once and the message names one of them. Which
	// one has to be the same on every run, or the log line that explains a dropped
	// connection is not comparable with the one a colleague saw — and no test can
	// assert it. Map iteration order is deliberately random in Go, so the order is
	// imposed here rather than inherited.
	s := NewSender()
	for _, id := range []uint32{9, 7, 5, 3, 1} {
		s.Open(id)
		if err := s.CreditStream(id, 1000); err != nil {
			t.Fatalf("CreditStream on stream %d: %v", id, err)
		}
	}

	for i := 0; i < 20; i++ {
		err := s.SetInitialSize(MaxWindowSize)
		var ce h2.ConnError
		if !errors.As(err, &ce) {
			t.Fatalf("SetInitialSize: %v, want a connection error", err)
		}
		if want := "stream 1's window"; !strings.Contains(ce.Reason, want) {
			t.Fatalf("the reason is %q, want it to name %q — the lowest stream that overflows",
				ce.Reason, want)
		}
	}
}

func TestCreditConnRefusesAnOverflow(t *testing.T) {
	// §6.9.1, at connection scope because the window is the connection's.
	s := NewSender()

	err := s.CreditConn(MaxWindowSize)
	assertConnError(t, err, h2.FlowControlError)
}

func TestCreditStreamRefusesAnOverflow(t *testing.T) {
	// The same arithmetic, reported against the stream, because that is the window
	// it went wrong on.
	s := NewSender()
	s.Open(5)

	err := s.CreditStream(5, MaxWindowSize)
	assertStreamError(t, err, 5, h2.FlowControlError)
}

func TestCreditStreamIgnoresAStreamThatIsNotOpen(t *testing.T) {
	// §5.1 requires an endpoint to tolerate a WINDOW_UPDATE for a stream it has
	// closed, and whether the peer was entitled to name that identifier at all is
	// the stream table's judgement, not this type's. Credit for a stream nobody
	// will write is nothing.
	s := NewSender()

	if err := s.CreditStream(7, 100); err != nil {
		t.Errorf("CreditStream for a stream that is not open: %v, want it dropped", err)
	}
	if err := s.CreditStream(7, MaxWindowSize); err != nil {
		t.Errorf("CreditStream of an overflowing increment for a stream that is not open: %v, "+
			"want it dropped — there is no window to overflow", err)
	}
}

func TestCreditAfterCloseIsDroppedRatherThanReported(t *testing.T) {
	// The reader goroutine is on its way out and the connection already has a
	// reason for ending. A second, invented fault on top of the real one is a log
	// line that sends the next reader after the wrong cause.
	s := NewSender()
	s.Open(1)
	// Credited first so that the calls below have something to overflow. A window
	// still at its initial size can absorb the largest setting there is without
	// complaining, and a nil error from a call that never had anything to report
	// would look exactly like the drop this test is asserting.
	if err := s.CreditStream(1, 1000); err != nil {
		t.Fatalf("CreditStream: %v", err)
	}
	s.Close(errors.New("gone"))

	if err := s.CreditConn(MaxWindowSize); err != nil {
		t.Errorf("CreditConn after Close: %v, want it dropped", err)
	}
	if err := s.CreditStream(1, MaxWindowSize); err != nil {
		t.Errorf("CreditStream after Close: %v, want it dropped", err)
	}
	if err := s.SetInitialSize(MaxWindowSize); err != nil {
		t.Errorf("SetInitialSize after Close: %v, want it dropped", err)
	}
}

func TestCloseKeepsTheFirstReason(t *testing.T) {
	// Teardown is reached from whichever goroutine noticed first, a read error and
	// a shutdown request can arrive together, and the first of the two is the one
	// that explains the other.
	s := NewSender()
	s.Open(1)

	first := errors.New("read: connection reset")
	second := errors.New("shutting down")
	s.Close(first)
	s.Close(second)

	_, err := s.Reserve(1, 100)
	if !errors.Is(err, first) {
		t.Errorf("Reserve: %v, want the first reason %v", err, first)
	}
}

func TestCloseRefusesANilReason(t *testing.T) {
	// Close exists to give parked writers something to return. A nil there is
	// indistinguishable from a successful reservation of nothing.
	s := NewSender()

	assertPanics(t, "Close with a nil reason", func() { s.Close(nil) })
}

func TestTheConnectionWindowIsNeverOverspent(t *testing.T) {
	// The property the whole type exists for, under contention. Eight writers each
	// try to send far more than the connection has, a ninth goroutine grants credit
	// in small pieces, and the sum of what the writers were granted must equal the
	// sum of what was granted to the connection — not one octet more.
	//
	// Any overspend shows up as an error rather than as a wrong total, because
	// Window.Consume refuses a debit larger than the window: a Sender that handed
	// out credit it had not got would fail its own arithmetic on the way past.
	const (
		writers   = 8
		grants    = 200
		perGrant  = 64
		wantTotal = InitialWindowSize + grants*perGrant
	)

	s := NewSender()
	if err := s.SetInitialSize(MaxWindowSize); err != nil {
		t.Fatalf("SetInitialSize: %v", err)
	}

	ids := make([]uint32, writers)
	for i := range ids {
		ids[i] = uint32(2*i + 1)
		s.Open(ids[i])
	}

	var (
		mu    sync.Mutex
		total int
		errs  []error
		wg    sync.WaitGroup
	)

	for _, id := range ids {
		wg.Add(1)
		go func(id uint32) {
			defer wg.Done()
			for {
				n, err := s.Reserve(id, 4096)
				if err != nil {
					mu.Lock()
					if !errors.Is(err, ErrStreamGone) {
						errs = append(errs, err)
					}
					mu.Unlock()
					return
				}
				mu.Lock()
				total += n
				done := total >= wantTotal
				mu.Unlock()
				if done {
					return
				}
			}
		}(id)
	}

	for i := 0; i < grants; i++ {
		if err := s.CreditConn(perGrant); err != nil {
			t.Fatalf("CreditConn: %v", err)
		}
	}

	// Every writer that is still parked is waiting for credit that will not come,
	// and retiring its stream is how the reader goroutine would end it.
	spun := time.Now().Add(parkDeadline)
	for {
		mu.Lock()
		done := total >= wantTotal
		spent := total
		mu.Unlock()
		if done {
			break
		}
		if time.Now().After(spun) {
			t.Fatalf("the writers were granted %d of %d octets within %v and then stopped; "+
				"credit that was granted is not reaching them", spent, wantTotal, parkDeadline)
		}
		runtime.Gosched()
	}
	for _, id := range ids {
		s.Retire(id)
	}
	awaitGroup(t, &wg, "the writers")

	if len(errs) > 0 {
		t.Fatalf("writers reported %d errors, the first being %v; want none", len(errs), errs[0])
	}
	if total != wantTotal {
		t.Errorf("the writers were granted %d octets in total, want exactly %d — "+
			"the connection's initial window plus every increment", total, wantTotal)
	}
	if got := s.ConnAvailable(); got != 0 {
		t.Errorf("ConnAvailable is %d, want 0 — every octet granted was spent and no more", got)
	}
}

func TestTheSenderIsSafeForConcurrentUse(t *testing.T) {
	// Every method at once, for the race detector rather than for an assertion.
	// The one thing asserted is that it all terminates, which Close is responsible
	// for: a Sender that woke nothing would hang here instead of failing.
	//
	// The peers finish before Close, so the contended window is a real one rather
	// than a Sender that was already shut when the goroutines started.
	const rounds = 300

	s := NewSender()

	var writers sync.WaitGroup
	for i := 0; i < 4; i++ {
		id := uint32(2*i + 1)
		s.Open(id)

		writers.Add(1)
		go func(id uint32) {
			defer writers.Done()
			for {
				if _, err := s.Reserve(id, 1024); err != nil {
					return
				}
			}
		}(id)
	}

	var peers sync.WaitGroup
	peers.Add(3)
	go func() {
		defer peers.Done()
		for i := 0; i < rounds; i++ {
			_ = s.CreditConn(128)
		}
	}()
	go func() {
		defer peers.Done()
		for i := 0; i < rounds; i++ {
			id := uint32(2*(i%4) + 1)
			_ = s.CreditStream(id, 128)
			_, _ = s.Available(id)
			_ = s.ConnAvailable()
		}
	}()
	go func() {
		defer peers.Done()
		for i := 0; i < rounds; i++ {
			_ = s.SetInitialSize(uint32(1000 + i))
			_ = s.InitialSize()
		}
	}()
	peers.Wait()

	// Retiring some and closing over the rest, because those are two different
	// wake-ups and a writer left asleep by either one hangs this test.
	s.Retire(1)
	s.Retire(3)
	s.Close(errors.New("done"))
	awaitGroup(t, &writers, "the writers")
}
