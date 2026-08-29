package flow

import (
	"errors"
	"maps"
	"slices"
	"sync"
)

// ErrStreamGone is returned by Reserve when the stream it was waiting for credit
// on was retired while it waited.
//
// It is not a protocol error and carries no error code, because there is nothing
// to report and nobody to report it to: the stream has already been reset or has
// already closed, so a RST_STREAM would name a stream the peer has finished with
// and a GOAWAY would end a connection nothing is wrong with. A writer that sees
// this stops writing and returns.
var ErrStreamGone = errors.New("flow: the stream was retired while waiting for credit")

// Sender owns the send half of one connection's flow control: the connection
// window the peer granted us, and the send window of every stream that is open.
//
// This is the type the package comment says belongs on top of Window rather than
// inside it. Window is the arithmetic of §6.9 and is single-goroutine by design;
// Sender is the part that has to be shared, because the goroutines that spend the
// credit are not the goroutine that receives it. A response body is written by a
// stream goroutine, and the WINDOW_UPDATE frames that pay for it are read by the
// connection's reader goroutine, so something has to stand between them.
//
// # Why one lock and not one per window
//
// Sending a DATA frame spends two windows at once, the stream's and the
// connection's, and §6.9.1 makes that one decision rather than two: a sender may
// send only what both windows admit, and a frame that fits the stream window but
// not the connection's must not be sent at all. Two independent locks would let a
// second stream take the connection credit between the two checks, and the first
// stream would then debit a window it had not been granted — the two ends would
// disagree about the connection's credit for the rest of the connection, and the
// symptom is a transfer that stalls at a size depending on the timing. So the
// reservation of both windows happens under one lock, which is this one.
//
// It is also why Window has no lock of its own. A mutex per Window would make
// every window individually safe and this pair of them still wrong.
//
// # Fairness
//
// Credit is handed out to whichever parked writer the runtime wakes first, and a
// stream asking for a megabyte is served before a stream asking for a hundred
// octets if it wakes first. That is not a scheduler, and a server that needed one
// would have to implement §5.3's replacement (RFC 9218), which this one does not.
// The bound that makes it acceptable is SETTINGS_MAX_CONCURRENT_STREAMS: the
// number of writers that can be parked here at once is a number this server chose,
// so the worst case is bounded by configuration rather than by the peer.
type Sender struct {
	mu sync.Mutex

	// credit is broadcast whenever anything a parked writer might be waiting for
	// changes: credit arrives on either kind of window, a stream is retired, or
	// the connection ends. Broadcast rather than Signal, because the writers are
	// not interchangeable — a writer woken for credit on stream 3 cannot use
	// credit that arrived on stream 5, and Signal would wake exactly one of them
	// and possibly the wrong one, leaving the credit unspent and the right writer
	// asleep.
	credit *sync.Cond

	// conn is the connection's send window: the peer's grant to us for the
	// connection as a whole, which every stream spends from.
	conn *Window

	// stream holds the send window of every stream that is open, keyed by
	// identifier.
	//
	// Keyed by identifier rather than handed out as pointers, so that no *Window
	// ever crosses a goroutine boundary. Every send window in the connection is
	// reachable only through this map and therefore only under this lock, which
	// is a property a reader can check by reading this file rather than by
	// auditing every caller.
	//
	// It is a second map of streams — internal/stream has one too — and that is
	// deliberate rather than an oversight. The two hold different things and are
	// owned by different goroutines: that one is the protocol state machine of
	// §5.1 driven by the reader, this one is flow-control credit spent by
	// writers. Merging them would put the state machine behind this mutex.
	stream map[uint32]*Window

	// initial is the peer's current SETTINGS_INITIAL_WINDOW_SIZE, which sizes the
	// send window of every stream opened from now on (§6.9.2).
	//
	// It lives here rather than in the stream table because this is the only
	// place it is used: it sizes windows this type owns, and the delta form of a
	// change is applied to windows this type owns. A copy of it in the table
	// would be a second version of the same number, updated by the same frame,
	// with nothing checking that the two agree.
	initial uint32

	// err is why the connection is over, or nil. Set once by Close.
	//
	// A parked writer has no other way to learn that the connection it is writing
	// to has gone: it is waiting for a WINDOW_UPDATE that will never arrive,
	// there is no deadline on a condition variable, and the socket error was seen
	// by a different goroutine entirely. This field, and the broadcast that sets
	// it, is what stops that writer from waiting for the rest of the process's
	// life.
	err error

	// waiting is how many goroutines are parked in Reserve.
	//
	// It exists for the tests, and that is worth stating rather than dressing up.
	// Every guard in this file is about a writer that parks and a wake-up that
	// reaches it, and a test cannot assert that a writer parked without being able
	// to see that it did. The alternative is a test that sleeps for long enough to
	// be reasonably sure, which passes slowly on an idle machine and fails at
	// random on a busy one — and a flaky test for a concurrency guard is worse
	// than none, because it teaches the next person to re-run rather than to read.
	//
	// Two integer operations under a lock that is already held, and no production
	// code reads it.
	//
	// Waiters exports it because the same guards are tested from internal/stream,
	// which owns the map of streams this Sender's windows are keyed by and has its
	// own reasons for a writer to be woken. Everything under internal/ is this
	// module's own, so an accessor here commits nothing to anyone outside it.
	waiting int
}

// NewSender returns the send half of a connection's flow control, with the
// connection window and the initial stream window size at the values §6.9.2
// requires both ends to assume before any SETTINGS frame has been exchanged.
func NewSender() *Sender {
	s := &Sender{
		conn:    NewConnWindow(),
		stream:  make(map[uint32]*Window),
		initial: InitialWindowSize,
	}
	s.credit = sync.NewCond(&s.mu)
	return s
}

// Open gives stream id a send window at the peer's current
// SETTINGS_INITIAL_WINDOW_SIZE.
//
// The size is not a parameter. §6.9.2 fixes it as whatever the peer last
// advertised, this type is already holding that value in order to apply changes to
// it, and a caller that could pass a different one could open a stream with credit
// the peer never granted.
//
// Opening the same identifier twice panics. §5.1.1 makes stream identifiers
// strictly increasing, so a repeat means the caller's own state machine has lost
// track of which streams are open — and the effect of silently replacing the
// window would be to hand a stream mid-transfer a fresh grant, which is the peer's
// credit to give and not ours to invent.
func (s *Sender) Open(id uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.stream[id]; ok {
		panic("flow: Sender.Open called twice for the same stream")
	}
	// NewStreamWindow panics on identifier 0, which is the check this method
	// would otherwise have to repeat.
	s.stream[id] = NewStreamWindow(id, s.initial)
}

// Retire drops stream id's send window and wakes anything waiting for credit on
// it, which will see ErrStreamGone.
//
// Idempotent, and called for every stream that leaves the open set however it
// left: END_STREAM in both directions, RST_STREAM from the peer, or a stream error
// of our own. Being idempotent is what makes it safe to call from all of those
// paths without each one first working out whether one of the others got there
// first — and the map already gives that for free, so there is no state here that
// could disagree with the caller's.
func (s *Sender) Retire(id uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.stream[id]; !ok {
		return
	}
	delete(s.stream, id)

	// Broadcast even though no credit arrived. A writer parked on this stream is
	// waiting for something that can no longer happen, and the deletion above is
	// the only news it will ever get.
	s.credit.Broadcast()
}

// CreditConn applies a stream-0 WINDOW_UPDATE of n octets (§6.9).
//
// Called from the connection's reader goroutine. An overflow is a connection error
// of type FLOW_CONTROL_ERROR, which is Window's judgement rather than this
// method's.
func (s *Sender) CreditConn(n uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.err != nil {
		// Not an error to report. The connection is already over and the reader
		// goroutine is on its way out; failing here would make it log a second,
		// invented fault on top of the real one. The credit is simply dropped,
		// because there is nobody left to spend it.
		return nil
	}
	if err := s.conn.Increase(n); err != nil {
		return err
	}
	s.credit.Broadcast()
	return nil
}

// CreditStream applies a WINDOW_UPDATE of n octets to stream id (§6.9).
//
// Called from the connection's reader goroutine. A WINDOW_UPDATE for a stream that
// is not open is not an error here and is dropped: §5.1 requires an endpoint to
// tolerate frames on a stream it has already closed for at least a round trip, and
// the frame is legal on a half-closed or closed stream. Deciding whether this
// identifier is one the peer was allowed to name at all is the stream table's
// business, and it has the state machine to answer it; this type holds credit, and
// credit for a stream nobody will write is nothing.
func (s *Sender) CreditStream(id uint32, n uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.err != nil {
		return nil
	}
	w, ok := s.stream[id]
	if !ok {
		return nil
	}
	if err := w.Increase(n); err != nil {
		return err
	}
	s.credit.Broadcast()
	return nil
}

// SetInitialSize applies the peer's new SETTINGS_INITIAL_WINDOW_SIZE (§6.9.2): it
// becomes the size of every stream opened from now on, and is applied as a delta to
// the send window of every stream already open.
//
// Called from the connection's reader goroutine. An overflow on any one stream is a
// connection error of type FLOW_CONTROL_ERROR, because the fault is in a SETTINGS
// frame and a SETTINGS frame is the connection's — see Window.SetInitialSize.
func (s *Sender) SetInitialSize(n uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.err != nil {
		return nil
	}

	// Sorted, so that a SETTINGS frame overflowing several streams at once names
	// the lowest of them rather than whichever one the map iterated to first. The
	// connection is ending either way, and the difference is whether the log line
	// that explains why is the same on every run: an error message that varies
	// with map iteration order is one no test can assert and no operator can
	// compare against a colleague's.
	//
	// The cost is a slice and a sort per SETTINGS frame that carries this
	// setting, which is a frame a peer sends once or twice in a connection's
	// life. Applying the change is O(streams) regardless.
	for _, id := range slices.Sorted(maps.Keys(s.stream)) {
		if err := s.stream[id].SetInitialSize(n); err != nil {
			// The streams before this one keep the new size. That is not a
			// partial update left lying around: the error is a connection error,
			// so the connection is about to end and every one of these windows is
			// about to be discarded. Rolling back would be work to restore a
			// state nothing will read.
			return err
		}
	}

	s.initial = n

	// A raise grants credit to every open stream at once, and this is the only
	// notification the writers parked on them will get. §6.9.2's delta is a grant
	// exactly as a WINDOW_UPDATE is; the only difference is the frame that
	// carried it.
	s.credit.Broadcast()
	return nil
}

// Close records why the connection is over and wakes every parked writer, each of
// which returns err.
//
// This is the connection's teardown reaching flow control, and without it a writer
// parked for credit on a dead connection waits for the life of the process. The
// WINDOW_UPDATE it is waiting for cannot arrive — the peer is gone, or the reader
// goroutine that would have applied it has returned — and a condition variable has
// no deadline of its own to fall back on.
//
// Idempotent, and the first reason wins: teardown is reached from whichever
// goroutine noticed the problem first, a read error and a shutdown request can
// arrive together, and the first of the two is the one that explains the other.
//
// A nil error panics. Close exists to give parked writers something to return, and
// a nil there would be indistinguishable from a successful reservation of zero
// octets.
func (s *Sender) Close(err error) {
	if err == nil {
		panic("flow: Sender.Close requires a non-nil reason")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.err != nil {
		return
	}
	s.err = err
	s.credit.Broadcast()
}

// Reserve takes up to want octets of credit for stream id from both the stream's
// send window and the connection's, blocking until at least one octet is available
// on both, and returns how many it took.
//
// Called from a stream goroutine. The return is in [1, want] on success, and the
// octets are already debited: the caller has been granted them and must send them,
// because there is no way to give them back. A caller whose Enqueue then fails has
// lost that much credit, which costs nothing — Enqueue fails only once the write
// half is finished, and a connection that is finished has no further use for its
// windows.
//
// want must be positive. Zero is not a request this type can answer, and it is not
// a request a correct caller makes: §6.9.1 exempts the empty DATA frame from both
// windows — "Frames with zero length with the END_STREAM flag set (that is, an empty
// DATA frame) MAY be sent if there is no available space in either flow-control
// window" — so a caller with nothing to send must send it without reserving
// anything, rather than reserving nothing and treating the result as permission.
//
// Errors are the end of writing, not a smaller reservation to retry: ErrStreamGone
// if the stream was retired while waiting, or Close's reason if the connection
// ended. Neither can be waited out.
func (s *Sender) Reserve(id uint32, want int) (int, error) {
	if want <= 0 {
		panic("flow: Sender.Reserve requires a positive number of octets")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for {
		// Checked before the windows, so that a writer parked on a connection
		// that has since ended returns the reason it ended rather than the credit
		// that happened to arrive alongside it.
		if s.err != nil {
			return 0, s.err
		}
		w, ok := s.stream[id]
		if !ok {
			return 0, ErrStreamGone
		}

		// The smallest of the three, and the connection window is one of them.
		// Taking the stream's minimum alone is the mistake §6.9.1 exists to
		// prevent; see the type comment.
		n := int64(want)
		if a := s.conn.Available(); a < n {
			n = a
		}
		if a := w.Available(); a < n {
			n = a
		}

		if n > 0 {
			// Both, and the connection first, in the order Window.Consume
			// documents. Neither can fail: n is positive and no greater than
			// either window's credit, which is the exact condition Consume
			// checks. The results are examined all the same, because an ignored
			// error here would turn a future change to Consume's rules into
			// credit quietly spent twice, and because the clamping above is the
			// kind of arithmetic that is only obviously right until somebody
			// edits it — scripts/break-sender.py removes each clamp in turn and
			// these two checks are what notices.
			if err := s.conn.Consume(uint32(n)); err != nil {
				return 0, err
			}
			if err := w.Consume(uint32(n)); err != nil {
				return 0, err
			}
			return int(n), nil
		}

		// Zero or negative on one of the windows. Negative is legal and is why
		// this waits rather than returning: §6.9.2 lets the peer lower the
		// initial window size below what a stream has already spent, and the
		// deficit has to be filled by later credit before anything new may be
		// sent.
		s.waiting++
		s.credit.Wait()
		s.waiting--
	}
}

// Waiters is how many goroutines are parked in Reserve. See Sender.waiting.
//
// It counts a writer from before it waits until after it returns from waiting, so
// a writer that has been broadcast to but has not yet re-acquired the lock is
// still counted. A test can therefore use this to wait until a writer has reached
// Reserve's park, and cannot use it to detect that a writer has been woken.
func (s *Sender) Waiters() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.waiting
}

// ConnAvailable is the credit remaining on the connection's send window, which may
// be negative.
func (s *Sender) ConnAvailable() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn.Available()
}

// Available is the credit remaining on stream id's send window, and whether that
// stream is open. It may be negative.
func (s *Sender) Available(id uint32) (int64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	w, ok := s.stream[id]
	if !ok {
		return 0, false
	}
	return w.Available(), true
}

// InitialSize is the peer's current SETTINGS_INITIAL_WINDOW_SIZE: the size the
// next stream's send window will be opened at.
func (s *Sender) InitialSize() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.initial
}
