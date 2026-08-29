package server

import (
	"errors"
	"io"
	"os"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"zerodeps/zdh/internal/frame"
	"zerodeps/zdh/internal/h2"
	"zerodeps/zdh/internal/limits"
)

// shortTimeout is every deadline a test is waiting to fire. longTimeout is every
// deadline a test needs out of the way.
//
// Both matter. Four of the six defaults are ten seconds and the idle default is a
// minute, so a test that let them stand would either take a minute or wait on
// whichever deadline happened to be nearest — and "whichever happened to be
// nearest" is how a test ends up asserting the wrong error code and passing.
const (
	shortTimeout = 40 * time.Millisecond
	longTimeout  = time.Hour
)

// errNoReadDeadline is what a testSocket reports when its script is exhausted, no
// more octets are coming, and no read deadline has been set. See Read: the
// alternative is a suite that hangs.
var errNoReadDeadline = errors.New("testSocket: read past the script with no deadline set")

// testSocket is a whole connection under the test's control: the recording write
// half from testTarget, plus a read half fed from a script.
//
// The read half waits on a channel rather than draining a bytes.Reader because
// several of the interesting orderings are only reachable step by step. Proving
// that the peer's SETTINGS are in force before the acknowledgement goes out, for
// instance, needs the frame to arrive at a moment the test chose; a script loaded
// up front is consumed whenever the reader goroutine gets to it, which is a race
// the test would lose about half the time and call a pass.
type testSocket struct {
	*testTarget

	// readMu, not mu: testTarget has a mu of its own for the write half, and
	// although the shallower field wins, two fields of the same name one level
	// apart is a trap for whoever reads this next.
	readMu        sync.Mutex
	pending       []byte
	readDeadlines []time.Time
	closes        int
	eofAtEnd      bool
	readErr       error

	// more carries one token per feed. Buffered by one and sent to without
	// blocking: coalesced tokens are harmless because Read rechecks the buffer
	// after every wake, and a feed must never block on a reader that is not
	// waiting yet.
	more chan struct{}
}

func newTestSocket(tt *testTarget) *testSocket {
	return &testSocket{testTarget: tt, more: make(chan struct{}, 1)}
}

// script loads octets before Serve starts. feed adds them while it is running.
func (ts *testSocket) script(b []byte) *testSocket {
	ts.pending = append(ts.pending, b...)
	return ts
}

// atEOF makes the read half report a clean close once the script runs out.
func (ts *testSocket) atEOF() *testSocket {
	ts.eofAtEnd = true
	return ts
}

// failsWith makes the read half report err once the script runs out, which is a
// broken connection rather than a closed one.
func (ts *testSocket) failsWith(err error) *testSocket {
	ts.readErr = err
	return ts
}

func (ts *testSocket) feed(b []byte) {
	ts.readMu.Lock()
	ts.pending = append(ts.pending, b...)
	ts.readMu.Unlock()
	ts.wake()
}

// end says no more octets are coming, so a waiting read stops waiting and finds
// the clean close.
func (ts *testSocket) end() {
	ts.readMu.Lock()
	ts.eofAtEnd = true
	ts.readMu.Unlock()
	ts.wake()
}

func (ts *testSocket) wake() {
	select {
	case ts.more <- struct{}{}:
	default:
	}
}

func (ts *testSocket) Read(p []byte) (int, error) {
	for {
		ts.readMu.Lock()
		if len(ts.pending) > 0 {
			n := copy(p, ts.pending)
			ts.pending = ts.pending[n:]
			ts.readMu.Unlock()
			return n, nil
		}
		readErr, eof := ts.readErr, ts.eofAtEnd
		var deadline time.Time
		if n := len(ts.readDeadlines); n > 0 {
			deadline = ts.readDeadlines[n-1]
		}
		ts.readMu.Unlock()

		switch {
		case readErr != nil:
			return 0, readErr
		case eof:
			return 0, io.EOF
		case deadline.IsZero():
			// The connection is supposed to set a deadline before every read, and
			// TestServeSetsAReadDeadlineBeforeEveryRead checks that directly.
			// Blocking here forever would turn its absence into a suite that
			// hangs, so this fails the read instead and lets an assertion on the
			// error say what happened.
			return 0, errNoReadDeadline
		}

		select {
		case <-ts.more:
		case <-time.After(time.Until(deadline)):
			// A deadline already in the past fires at once, which is what a real
			// socket does with an overdue one.
			return 0, os.ErrDeadlineExceeded
		}
	}
}

func (ts *testSocket) SetReadDeadline(t time.Time) error {
	ts.readMu.Lock()
	ts.readDeadlines = append(ts.readDeadlines, t)
	ts.readMu.Unlock()
	// Woken because a read already waiting on the previous deadline is now waiting
	// on the wrong one. A real socket applies a new deadline to a read in progress;
	// without this a test that shortened a deadline would keep waiting on the
	// longer one.
	ts.wake()
	return nil
}

func (ts *testSocket) Close() error {
	ts.readMu.Lock()
	ts.closes++
	ts.readMu.Unlock()
	return nil
}

func (ts *testSocket) closeCount() int {
	ts.readMu.Lock()
	defer ts.readMu.Unlock()
	return ts.closes
}

func (ts *testSocket) allReadDeadlines() []time.Time {
	ts.readMu.Lock()
	defer ts.readMu.Unlock()
	return append([]time.Time(nil), ts.readDeadlines...)
}

// handlerFunc adapts a function to streamHandler.
type handlerFunc func(frame.Frame) error

func (h handlerFunc) HandleFrame(f frame.Frame) error { return h(f) }

// recordingHandler keeps every frame it is given and returns err for each.
//
// Locked rather than relying on Serve's return to order the access, because a
// handler is called from the connection's reader goroutine and -race is right to
// object to a slice appended to there and read here.
type recordingHandler struct {
	mu     sync.Mutex
	frames []frame.Frame
	err    error
}

func (h *recordingHandler) HandleFrame(f frame.Frame) error {
	h.mu.Lock()
	h.frames = append(h.frames, f)
	err := h.err
	h.mu.Unlock()
	return err
}

func (h *recordingHandler) seen() []frame.Frame {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]frame.Frame(nil), h.frames...)
}

// rejectingHandler fails the test if the connection hands it anything.
//
// It is the assertion that a connection-level frame stayed at the connection
// level, which is otherwise invisible: routing a PING to the stream layer produces
// no error and no reply, just a connection that quietly stops answering.
//
// Errorf and not Fatalf, because this runs on the connection's reader goroutine
// and Fatalf from a goroutine other than the test's own stops that goroutine
// instead of the test.
func rejectingHandler(t *testing.T) streamHandler {
	return handlerFunc(func(f frame.Frame) error {
		t.Errorf("a %s frame on stream %d reached the stream handler, but it belongs to the connection",
			f.Type(), f.Stream())
		return nil
	})
}

// testTimeouts is the timeouts for a test that is not testing a timeout.
//
// SettingsAck is the exception, and it is deliberate: it is the one deadline that
// runs in the background of a whole connection rather than being reset by each
// read, so a short one would put a 40ms budget on every test in this file and make
// the suite's failures depend on how loaded the machine is. The three tests that
// exercise the §6.5.3 clock shorten it themselves.
func testTimeouts() limits.Timeouts {
	return limits.Timeouts{
		TLSHandshake:  shortTimeout,
		Preface:       shortTimeout,
		Idle:          shortTimeout,
		Write:         shortTimeout,
		SettingsAck:   longTimeout,
		ShutdownGrace: shortTimeout,
	}
}

// clientHello is the client connection preface: the 24 octets of §3.4 followed by
// the SETTINGS frame §3.4 requires to come first. Almost every script starts with
// it, because a connection that has not had it is not yet a connection.
func clientHello(t *testing.T, settings ...frame.Setting) []byte {
	t.Helper()
	return append([]byte(frame.ClientPreface),
		encodeFrames(t, frame.SettingsFrame{Settings: settings})...)
}

// encodeFrames serialises frames to their wire octets using the package's own
// writer, which is the serialiser the frame tests cover. Hand-built octets would
// be a second, untested encoder living in a test file.
func encodeFrames(t *testing.T, fs ...frame.Frame) []byte {
	t.Helper()
	var rec writeRecorder
	w := frame.NewWriter(&rec, frame.WriterConfig{})
	for _, f := range fs {
		if err := w.WriteFrame(f); err != nil {
			t.Fatalf("encoding a %s frame for the script: %v", f.Type(), err)
		}
	}
	return rec.b
}

// writeRecorder is an io.Writer that keeps what it is given.
type writeRecorder struct{ b []byte }

func (w *writeRecorder) Write(p []byte) (int, error) {
	w.b = append(w.b, p...)
	return len(p), nil
}

// serveInBackground starts Serve and returns the channel its result arrives on.
func serveInBackground(c *conn) chan error {
	done := make(chan error, 1)
	go func() { done <- c.Serve() }()
	return done
}

// awaitServe waits for Serve to return, failing by name rather than hanging.
func awaitServe(t *testing.T, done chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(gateWait):
		t.Fatalf("Serve did not return within %v", gateWait)
		return nil
	}
}

// serve runs a connection to completion over ts and returns what Serve returned.
// It is the shape of almost every test here: load a script, run it out, read back
// what the peer received.
func serve(t *testing.T, ts *testSocket, h streamHandler, to limits.Timeouts) error {
	t.Helper()
	return awaitServe(t, serveInBackground(newConn(ts, h, to)))
}

// peerSaw decodes everything the connection wrote.
func peerSaw(t *testing.T, ts *testSocket) []frame.Frame {
	t.Helper()
	return framesWritten(t, ts.testTarget, frame.ReaderConfig{})
}

// goAwayIn returns the single GOAWAY among frames.
//
// Exactly one, not the last one: a connection that sent two has sent a frame after
// announcing it would send no more, and a test looking only at the last would not
// notice.
func goAwayIn(t *testing.T, frames []frame.Frame) frame.GoAwayFrame {
	t.Helper()
	var found []frame.GoAwayFrame
	for _, f := range frames {
		if ga, ok := f.(frame.GoAwayFrame); ok {
			found = append(found, ga)
		}
	}
	if len(found) != 1 {
		t.Fatalf("the peer received %d GOAWAY frames, want exactly 1; it received %s",
			len(found), describe(frames))
	}
	return found[0]
}

// noGoAwayIn fails if the connection said goodbye when it had no way to.
func noGoAwayIn(t *testing.T, frames []frame.Frame) {
	t.Helper()
	for _, f := range frames {
		if _, ok := f.(frame.GoAwayFrame); ok {
			t.Fatalf("the peer received a GOAWAY it could not have read; it received %s",
				describe(frames))
		}
	}
}

// describe names a sequence of frames for an error message. A %#v of a slice of
// frames is several lines of struct literal, and what a failing test needs first is
// the sequence.
func describe(frames []frame.Frame) string {
	if len(frames) == 0 {
		return "nothing"
	}
	names := make([]string, len(frames))
	for i, f := range frames {
		names[i] = f.Type().String()
		switch v := f.(type) {
		case frame.SettingsFrame:
			if v.Ack {
				names[i] += "(ack)"
			}
		case frame.PingFrame:
			if v.Ack {
				names[i] += "(ack)"
			}
		}
	}
	return strings.Join(names, ", ")
}

// connErrorOf asserts that err is a connection error and returns it.
func connErrorOf(t *testing.T, err error) h2.ConnError {
	t.Helper()
	var ce h2.ConnError
	if !errors.As(err, &ce) {
		t.Fatalf("Serve returned %v (%T), want an h2.ConnError", err, err)
	}
	return ce
}

// stopWriter shuts a writer down for a test that drove a conn without Serve, which
// is otherwise a goroutine left behind for TestServeLeaksNoGoroutines to find.
func stopWriter(t *testing.T, c *conn) {
	t.Helper()
	c.w.Close()
	if err := c.w.Wait(); err != nil {
		t.Errorf("stopping the writer: %v", err)
	}
}

// --- configuration -----------------------------------------------------------

// TestReaderConfigSetsEveryField is the check that a new bound cannot be added to
// the frame reader and left at its fallback here.
//
// The reader documents its zero-value defaults as a convenience, not as this
// server's policy, and the difference is the point: internal/limits is where the
// numbers a server runs with are decided and defended, so a field this function
// does not set is a security decision made by whoever wrote the reader's default,
// silently, on behalf of a package that never saw it.
func TestReaderConfigSetsEveryField(t *testing.T) {
	cfg := readerConfig()

	v := reflect.ValueOf(cfg)
	for i := 0; i < v.NumField(); i++ {
		if v.Field(i).IsZero() {
			t.Errorf("frame.ReaderConfig.%s is left at its zero value; readerConfig must set every "+
				"field from internal/limits", v.Type().Field(i).Name)
		}
	}

	want := frame.ReaderConfig{
		MaxFrameSize:          limits.MaxFrameSize,
		MaxHeaderBlockSize:    limits.MaxHeaderBlockSize,
		MaxContinuationFrames: limits.MaxContinuationFrames,
	}
	if cfg != want {
		t.Errorf("readerConfig() = %+v, want %+v", cfg, want)
	}
}

// TestInitialSettingsAdvertiseTheServersLimits pins the server connection preface.
func TestInitialSettingsAdvertiseTheServersLimits(t *testing.T) {
	f := initialSettings()
	if f.Ack {
		t.Error("the server's own SETTINGS carries the ACK flag, but it acknowledges nothing")
	}

	want := map[frame.SettingID]uint32{
		frame.SettingMaxFrameSize:         limits.MaxFrameSize,
		frame.SettingMaxConcurrentStreams: limits.MaxConcurrentStreams,

		// Zero, and it is the one value here that is a promise rather than a limit:
		// §8.4 already makes a client's PUSH_PROMISE a connection error, so this
		// exists to tell the client it need not reserve anything for a push from us.
		frame.SettingEnablePush: 0,
	}
	for id, value := range want {
		got, ok := f.Get(id)
		if !ok {
			t.Errorf("the server's SETTINGS does not carry %s", id)
			continue
		}
		if got != value {
			t.Errorf("the server's SETTINGS says %s = %d, want %d", id, got, value)
		}
	}
	if len(f.Settings) != len(want) {
		t.Errorf("the server's SETTINGS carries %d parameters, want the %d named here; a "+
			"parameter nobody has examined is one nobody has decided the value of",
			len(f.Settings), len(want))
	}
}

// TestApplySettingNamesEverySettingID requires every SETTINGS parameter a peer can
// send to be accounted for in conn.go, including the ones there is nothing to do
// about.
//
// The failure it exists to catch is a parameter added to the frame package and left
// out of applySetting, which is invisible: the switch falls through, the frame is
// acknowledged, and the connection has told the peer a limit is in force that
// nothing enforces. Naming a parameter to record that it is ignored is a decision;
// not naming it is a gap that reads the same from the outside.
func TestApplySettingNamesEverySettingID(t *testing.T) {
	types, err := os.ReadFile("../frame/types.go")
	if err != nil {
		t.Fatalf("reading the frame package's setting identifiers: %v", err)
	}
	decl := regexp.MustCompile(`(?m)^\tSetting(\w+)\s+SettingID = 0x`)
	found := decl.FindAllStringSubmatch(string(types), -1)
	if len(found) == 0 {
		t.Fatal("found no SettingID constants in ../frame/types.go; this test's pattern needs " +
			"updating, and until it does the test proves nothing")
	}

	src, err := os.ReadFile("conn.go")
	if err != nil {
		t.Fatalf("reading conn.go: %v", err)
	}
	for _, m := range found {
		name := "frame.Setting" + m[1]
		if !strings.Contains(string(src), name) {
			t.Errorf("%s is not named in conn.go; applySetting must account for every parameter a "+
				"peer can send, even if only to record that it is ignored", name)
		}
	}
}

// --- the preface -------------------------------------------------------------

// TestServeSendsItsSettingsBeforeReadingThePreface is §3.4 from the server's side,
// and the ordering is deliberate rather than incidental.
//
// The SETTINGS goes out first so that a client which has already pipelined its
// requests learns our limits without a round trip, and — visible here — so that a
// peer which never sends a preface can still be told why the connection ended. A
// server that read first would have nothing on the wire to attach a GOAWAY to.
func TestServeSendsItsSettingsBeforeReadingThePreface(t *testing.T) {
	ts := newTestSocket(&testTarget{})
	err := serve(t, ts, rejectingHandler(t), testTimeouts())

	if ce := connErrorOf(t, err); ce.Code != h2.ProtocolError {
		t.Errorf("Serve returned %s, want PROTOCOL_ERROR for a missing preface", ce.Code)
	}
	if !strings.Contains(err.Error(), "preface") {
		t.Errorf("the error does not mention the preface: %v", err)
	}

	got := peerSaw(t, ts)
	if len(got) == 0 {
		t.Fatal("the peer received nothing; the server's SETTINGS must go out before the preface " +
			"is read, precisely so that a peer which sends none can be told why")
	}
	if _, ok := got[0].(frame.SettingsFrame); !ok {
		t.Fatalf("the first frame the peer received is %s, want SETTINGS (RFC 9113 §3.4); it "+
			"received %s", got[0].Type(), describe(got))
	}
	if ga := goAwayIn(t, got); ga.ErrCode != h2.ProtocolError {
		t.Errorf("the GOAWAY carries %s, want PROTOCOL_ERROR", ga.ErrCode)
	}
}

// TestServeRejectsAnHTTP1Request is the misconfiguration this port will actually
// see: a browser or a curl aimed at an h2c listener.
func TestServeRejectsAnHTTP1Request(t *testing.T) {
	ts := newTestSocket(&testTarget{}).
		script([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")).
		atEOF()

	err := serve(t, ts, rejectingHandler(t), testTimeouts())
	if ce := connErrorOf(t, err); ce.Code != h2.ProtocolError {
		t.Errorf("Serve returned %s, want PROTOCOL_ERROR", ce.Code)
	}
	if !strings.Contains(err.Error(), "HTTP/1.1") {
		t.Errorf("the error does not name the HTTP/1.1 request, which is the whole diagnostic "+
			"value of recognising it: %v", err)
	}
	if ga := goAwayIn(t, peerSaw(t, ts)); ga.ErrCode != h2.ProtocolError {
		t.Errorf("the GOAWAY carries %s, want PROTOCOL_ERROR", ga.ErrCode)
	}
}

// TestServeTreatsAnImmediateCloseAsNoFault is a peer that connects and hangs up —
// a health check, a port scan, a load balancer probe. It is not an error and must
// not be reported as one, or a busy server's log is nothing else.
func TestServeTreatsAnImmediateCloseAsNoFault(t *testing.T) {
	ts := newTestSocket(&testTarget{}).atEOF()

	if err := serve(t, ts, rejectingHandler(t), testTimeouts()); err != nil {
		t.Errorf("Serve returned %v for a peer that closed before saying anything, want nil", err)
	}
	// No GOAWAY: there is nobody to read it, and attempting one produces a write
	// error describing our own reaction rather than anything that happened.
	noGoAwayIn(t, peerSaw(t, ts))
}

// TestServeReportsATruncatedPreface separates a peer that closed at a frame
// boundary from one that closed in the middle of something. The first is polite;
// the second is a broken connection and is reported as one.
func TestServeReportsATruncatedPreface(t *testing.T) {
	ts := newTestSocket(&testTarget{}).
		script([]byte(frame.ClientPreface[:10])).
		atEOF()

	err := serve(t, ts, rejectingHandler(t), testTimeouts())
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("Serve returned %v, want io.ErrUnexpectedEOF for a preface cut in half", err)
	}
}

// --- the first frame (§3.4) --------------------------------------------------

// TestServeRequiresSettingsAsTheFirstFrame is the second half of §3.4: the client's
// preface is the 24 octets and then a SETTINGS frame.
//
// The frame chosen is a PING, because it is one the connection would otherwise
// answer. Asserting that no PING acknowledgement went out is what distinguishes a
// connection that refused the frame from one that handled it and then happened to
// fail for another reason.
func TestServeRequiresSettingsAsTheFirstFrame(t *testing.T) {
	ts := newTestSocket(&testTarget{}).
		script(append([]byte(frame.ClientPreface), encodeFrames(t, ping(1))...)).
		atEOF()

	err := serve(t, ts, rejectingHandler(t), testTimeouts())
	if ce := connErrorOf(t, err); ce.Code != h2.ProtocolError {
		t.Errorf("Serve returned %s, want PROTOCOL_ERROR", ce.Code)
	}
	if !strings.Contains(err.Error(), "SETTINGS") {
		t.Errorf("the error does not say which frame was required: %v", err)
	}

	got := peerSaw(t, ts)
	for _, f := range got {
		if p, ok := f.(frame.PingFrame); ok && p.Ack {
			t.Errorf("the PING was answered before the connection preface was complete; the peer "+
				"received %s", describe(got))
		}
	}
	if ga := goAwayIn(t, got); ga.ErrCode != h2.ProtocolError {
		t.Errorf("the GOAWAY carries %s, want PROTOCOL_ERROR", ga.ErrCode)
	}
}

// TestServeAcceptsAnEmptySettingsAsTheFirstFrame is the other side of the same
// rule: §6.5 makes an empty SETTINGS legal, and it is what a client happy with
// every default sends. Refusing it would break those clients.
func TestServeAcceptsAnEmptySettingsAsTheFirstFrame(t *testing.T) {
	ts := newTestSocket(&testTarget{}).script(clientHello(t)).atEOF()

	if err := serve(t, ts, rejectingHandler(t), testTimeouts()); err != nil {
		t.Fatalf("Serve returned %v for an empty client SETTINGS, want nil", err)
	}
	got := peerSaw(t, ts)
	if len(got) != 2 {
		t.Fatalf("the peer received %s, want the server's SETTINGS and an acknowledgement",
			describe(got))
	}
	if s, ok := got[1].(frame.SettingsFrame); !ok || !s.Ack {
		t.Errorf("the peer received %s, want an acknowledgement second", describe(got))
	}
}

// --- SETTINGS ----------------------------------------------------------------

// TestServeAppliesAndAcknowledgesThePeersSettings is the ordinary case: the peer
// raises the maximum frame size and the writer starts using it.
func TestServeAppliesAndAcknowledgesThePeersSettings(t *testing.T) {
	const raised = 1 << 15

	ts := newTestSocket(&testTarget{}).
		script(clientHello(t, frame.Setting{ID: frame.SettingMaxFrameSize, Value: raised})).
		atEOF()
	c := newConn(ts, rejectingHandler(t), testTimeouts())

	if err := awaitServe(t, serveInBackground(c)); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if got := c.w.fw.MaxFrameSize(); got != raised {
		t.Errorf("the writer's maximum frame size is %d, want the %d the peer advertised",
			got, uint32(raised))
	}

	got := peerSaw(t, ts)
	if len(got) != 2 {
		t.Fatalf("the peer received %s, want the server's SETTINGS and an acknowledgement",
			describe(got))
	}
	if s, ok := got[1].(frame.SettingsFrame); !ok || !s.Ack {
		t.Errorf("the peer received %s, want an acknowledgement second", describe(got))
	}
}

// TestServeAppliesSettingsBeforeAcknowledging is §6.5's ordering requirement: the
// values must be in force before the acknowledgement is sent, because the
// acknowledgement is the peer's licence to assume they are. A server that
// acknowledged first would invite a maximum-size frame it might still refuse.
//
// The ordering is made observable by filling the writer's queue while it is parked
// inside a write. From that point the acknowledgement cannot be enqueued at all —
// Enqueue blocks, which is the backpressure the connection is built on — so a
// connection that acknowledged before applying would be stuck in Enqueue with the
// limit still at its old value, and the poll below would run out. Sampling the
// limit as the acknowledgement went past would not do: the window between the two
// statements is nanoseconds wide, and a test that has to win a race that small is
// a test that reports a pass.
func TestServeAppliesSettingsBeforeAcknowledging(t *testing.T) {
	const raised = 1 << 15

	to := testTimeouts()
	// The reader waits for a frame the test feeds by hand, and the writer is held
	// parked for as long as filling the queue takes. Neither wait is under test, so
	// neither may expire.
	to.Idle, to.Write = longTimeout, longTimeout

	ts := newTestSocket(newGatedTarget()).script([]byte(frame.ClientPreface))
	c := newConn(ts, rejectingHandler(t), to)
	done := serveInBackground(c)

	// Awaited before the queue is filled, not after: the writer drains the queue
	// into its burst before it calls Write, so frames enqueued any earlier would be
	// coalesced into this write instead of waiting behind it.
	letHello := ts.awaitWrite(t)
	for i := 0; i < defaultQueueDepth; i++ {
		if err := c.w.Enqueue(ping(uint64(i))); err != nil {
			t.Fatalf("filling the writer's queue at frame %d: %v", i, err)
		}
	}

	ts.feed(encodeFrames(t, frame.SettingsFrame{
		Settings: []frame.Setting{{ID: frame.SettingMaxFrameSize, Value: raised}},
	}))

	deadline := time.Now().Add(gateWait)
	for c.w.fw.MaxFrameSize() != raised {
		if time.Now().After(deadline) {
			t.Fatalf("the peer's SETTINGS_MAX_FRAME_SIZE was not in force within %v, during which "+
				"the acknowledgement could not be enqueued at all: it is being applied after the "+
				"acknowledgement rather than before it (RFC 9113 §6.5)", gateWait)
		}
		time.Sleep(time.Millisecond)
	}

	// Released only now, so that the failure above cannot be reached by a
	// connection which simply had not got there yet.
	ts.end()
	letHello(nil)
	for {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("Serve: %v", err)
			}
			return
		case <-ts.entered:
			ts.release <- nil
		case <-time.After(gateWait):
			t.Fatalf("Serve did not return within %v after %d writes", gateWait, ts.writeCount())
		}
	}
}

// TestServeAcknowledgesTheSettingsItDoesNotActOnYet is the connection's obligation
// towards parameters whose enforcement lives in another package.
//
// HEADER_TABLE_SIZE and MAX_HEADER_LIST_SIZE are internal/hpack's and
// INITIAL_WINDOW_SIZE is internal/flow's. Until those exist the values are recorded
// nowhere — but §6.5 does not permit a parameter to go unacknowledged, and a peer
// waiting for an acknowledgement that never comes stalls the connection. Ignoring a
// parameter and refusing it are different things.
func TestServeAcknowledgesTheSettingsItDoesNotActOnYet(t *testing.T) {
	ts := newTestSocket(&testTarget{}).
		script(clientHello(t,
			frame.Setting{ID: frame.SettingHeaderTableSize, Value: 8192},
			frame.Setting{ID: frame.SettingInitialWindowSize, Value: 1 << 20},
			frame.Setting{ID: frame.SettingMaxHeaderListSize, Value: 1 << 14},
			frame.Setting{ID: frame.SettingEnablePush, Value: 1},
			frame.Setting{ID: frame.SettingMaxConcurrentStreams, Value: 7},
		)).
		atEOF()

	if err := serve(t, ts, rejectingHandler(t), testTimeouts()); err != nil {
		t.Fatalf("Serve returned %v, want nil: none of these parameters is a reason to refuse the "+
			"connection", err)
	}
	got := peerSaw(t, ts)
	if s, ok := got[len(got)-1].(frame.SettingsFrame); !ok || !s.Ack {
		t.Fatalf("the peer received %s, want an acknowledgement last", describe(got))
	}
}

// TestServeIgnoresAnUnknownSetting is §6.5.2's extension rule. A future parameter
// must be ignored rather than refused, or every extension breaks every server that
// predates it.
func TestServeIgnoresAnUnknownSetting(t *testing.T) {
	ts := newTestSocket(&testTarget{}).
		script(clientHello(t, frame.Setting{ID: 0xbeef, Value: 1})).
		atEOF()

	if err := serve(t, ts, rejectingHandler(t), testTimeouts()); err != nil {
		t.Fatalf("Serve returned %v for an unknown setting identifier, want nil (RFC 9113 §6.5.2)",
			err)
	}
	got := peerSaw(t, ts)
	if s, ok := got[len(got)-1].(frame.SettingsFrame); !ok || !s.Ack {
		t.Fatalf("the peer received %s, want an acknowledgement last", describe(got))
	}
}

// TestServeDoesNotAcknowledgeAnAcknowledgement is the loop this avoids. A server
// that treated the peer's acknowledgement as a fresh SETTINGS would answer it, the
// peer would answer that, and the connection would trade acknowledgements until one
// side gave up.
func TestServeDoesNotAcknowledgeAnAcknowledgement(t *testing.T) {
	ts := newTestSocket(&testTarget{}).
		script(append(clientHello(t), encodeFrames(t,
			frame.SettingsFrame{Ack: true},
			// A second, unsolicited one. §6.5 gives no error code for it, so
			// refusing it would mean inventing a way to break a connection.
			frame.SettingsFrame{Ack: true},
		)...)).
		atEOF()

	if err := serve(t, ts, rejectingHandler(t), testTimeouts()); err != nil {
		t.Fatalf("Serve returned %v, want nil", err)
	}
	acks := 0
	got := peerSaw(t, ts)
	for _, f := range got {
		if s, ok := f.(frame.SettingsFrame); ok && s.Ack {
			acks++
		}
	}
	if acks != 1 {
		t.Errorf("the server sent %d acknowledgements, want the 1 for the client's own SETTINGS; "+
			"the peer received %s", acks, describe(got))
	}
}

// --- PING (validation matrix row 24) -----------------------------------------

// TestServeAnswersAPing is matrix row 24. The eight octets come back unchanged with
// the ACK flag set, and they are the peer's round-trip measurement, so returning
// anything else is worse than not answering.
func TestServeAnswersAPing(t *testing.T) {
	sent := frame.PingFrame{Data: [8]byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}}
	ts := newTestSocket(&testTarget{}).
		script(append(clientHello(t), encodeFrames(t, sent)...)).
		atEOF()

	if err := serve(t, ts, rejectingHandler(t), testTimeouts()); err != nil {
		t.Fatalf("Serve: %v", err)
	}

	got := peerSaw(t, ts)
	var reply *frame.PingFrame
	for i := range got {
		if p, ok := got[i].(frame.PingFrame); ok {
			reply = &p
		}
	}
	if reply == nil {
		t.Fatalf("the peer received %s, want a PING acknowledgement (RFC 9113 §6.7)", describe(got))
	}
	if !reply.Ack {
		t.Error("the PING reply does not carry the ACK flag, so the peer reads it as a new PING")
	}
	if reply.Data != sent.Data {
		t.Errorf("the PING reply carries %x, want the %x that was sent: the payload is the peer's "+
			"round-trip measurement", reply.Data, sent.Data)
	}
}

// TestServeDoesNotAnswerAPingAcknowledgement is the same loop as for SETTINGS, and
// a worse one: two servers each answering the other's acknowledgement would trade
// PINGs at line rate for as long as the connection lasted.
func TestServeDoesNotAnswerAPingAcknowledgement(t *testing.T) {
	acked := ping(9)
	acked.Ack = true

	ts := newTestSocket(&testTarget{}).
		script(append(clientHello(t), encodeFrames(t, acked)...)).
		atEOF()

	if err := serve(t, ts, rejectingHandler(t), testTimeouts()); err != nil {
		t.Fatalf("Serve returned %v for an unsolicited PING acknowledgement, want nil", err)
	}
	got := peerSaw(t, ts)
	for _, f := range got {
		if _, ok := f.(frame.PingFrame); ok {
			t.Errorf("the server answered a PING acknowledgement; the peer received %s",
				describe(got))
		}
	}
}

// TestServeAnswersAPingFloodInOrder is the reason there is no rate limiter on PING
// replies, stated as a test rather than only as a comment in conn.go.
//
// Each reply is enqueued on the writer's bounded queue, and Enqueue blocks when
// that queue is full. The goroutine it blocks is the one reading the flood, so the
// peer's PINGs throttle themselves to the rate we can write them, and nothing
// accumulates per frame. What this checks is that the throttling is the whole
// mechanism: every PING answered exactly once, in order, with nothing dropped.
func TestServeAnswersAPingFloodInOrder(t *testing.T) {
	const flood = 500

	pings := make([]frame.Frame, flood)
	for i := range pings {
		pings[i] = ping(uint64(i))
	}
	to := testTimeouts()
	// Answering five hundred PINGs is not meant to be raced against a deadline;
	// what is under test is the count and the order.
	to.Idle, to.Write = longTimeout, longTimeout

	ts := newTestSocket(&testTarget{}).
		script(append(clientHello(t), encodeFrames(t, pings...)...)).
		atEOF()

	if err := serve(t, ts, rejectingHandler(t), to); err != nil {
		t.Fatalf("Serve: %v", err)
	}

	var replies []frame.PingFrame
	for _, f := range peerSaw(t, ts) {
		if p, ok := f.(frame.PingFrame); ok {
			replies = append(replies, p)
		}
	}
	if len(replies) != flood {
		t.Fatalf("the peer received %d PING replies for %d PINGs", len(replies), flood)
	}
	for i, p := range replies {
		if want := ping(uint64(i)); p.Data != want.Data || !p.Ack {
			t.Fatalf("PING reply %d is %x (ack %t), want %x with the ACK flag: the replies must "+
				"match the requests in order", i, p.Data, p.Ack, want.Data)
		}
	}
}

// --- GOAWAY ------------------------------------------------------------------

// TestServeAnswersAPeerGoAway is a client shutting down cleanly. It is not an error
// on our side, and the reply is the courtesy that tells the peer we noticed.
func TestServeAnswersAPeerGoAway(t *testing.T) {
	ts := newTestSocket(&testTarget{}).
		script(append(clientHello(t), encodeFrames(t, frame.GoAwayFrame{
			LastStreamID: 0,
			ErrCode:      h2.NoError,
			Debug:        []byte("client shutting down"),
		})...)).
		atEOF()

	if err := serve(t, ts, rejectingHandler(t), testTimeouts()); err != nil {
		t.Fatalf("Serve returned %v for a peer's clean GOAWAY, want nil", err)
	}
	if ga := goAwayIn(t, peerSaw(t, ts)); ga.ErrCode != h2.NoError {
		t.Errorf("the reply GOAWAY carries %s, want NO_ERROR", ga.ErrCode)
	}
}

// TestServeDoesNotEchoThePeersDebugData is a habit rather than a vulnerability. The
// debug field is peer-controlled octets; reflecting them back to their sender is the
// shape of a good many real bugs in other protocols, and there is nothing to gain
// here that would justify keeping the habit.
func TestServeDoesNotEchoThePeersDebugData(t *testing.T) {
	const secret = "reflect-me-back"

	ts := newTestSocket(&testTarget{}).
		script(append(clientHello(t), encodeFrames(t, frame.GoAwayFrame{
			ErrCode: h2.EnhanceYourCalm,
			Debug:   []byte(secret),
		})...)).
		atEOF()

	if err := serve(t, ts, rejectingHandler(t), testTimeouts()); err != nil {
		t.Fatalf("Serve returned %v, want nil: the peer's error code describes the peer's reason "+
			"for leaving, not a fault of ours", err)
	}
	ga := goAwayIn(t, peerSaw(t, ts))
	if strings.Contains(string(ga.Debug), secret) {
		t.Errorf("the reply GOAWAY echoes the peer's debug data back at it: %q", ga.Debug)
	}
	if ga.ErrCode != h2.NoError {
		t.Errorf("the reply GOAWAY carries %s, want NO_ERROR", ga.ErrCode)
	}
}

// TestRunReportsWhatThePeersGoAwaySaid keeps the peer's reason in the error even
// though it is not put back on the wire. A client going away with ENHANCE_YOUR_CALM
// is saying something about this server, and a log that recorded only "peer left"
// would lose it.
//
// Driven through run rather than Serve, because Serve's job is precisely to decide
// that this ending is not the caller's problem, and in doing so it discards the
// detail this test is about.
func TestRunReportsWhatThePeersGoAwaySaid(t *testing.T) {
	ts := newTestSocket(&testTarget{}).
		script(append(clientHello(t), encodeFrames(t, frame.GoAwayFrame{
			ErrCode: h2.EnhanceYourCalm,
			Debug:   []byte("slow down"),
		})...)).
		atEOF()

	c := newConn(ts, rejectingHandler(t), testTimeouts())
	defer stopWriter(t, c)

	err := c.run()
	if !errors.Is(err, errPeerGoAway) {
		t.Fatalf("run returned %v, want it to wrap errPeerGoAway", err)
	}
	for _, want := range []string{"ENHANCE_YOUR_CALM", "slow down"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error is %q, want it to mention %q", err, want)
		}
	}
}

// --- PUSH_PROMISE (§8.4) -----------------------------------------------------

// TestServeRefusesAPushPromiseFromAClient is §8.4: a client cannot push, so a
// server must treat a PUSH_PROMISE as a connection error.
//
// It is answered at the connection level and not by the stream table, because what
// is wrong with the frame has nothing to do with the stream it names — it is the
// peer's role that makes it impossible. rejectingHandler is what checks that.
func TestServeRefusesAPushPromiseFromAClient(t *testing.T) {
	ts := newTestSocket(&testTarget{}).
		script(append(clientHello(t), encodeFrames(t, frame.PushPromiseFrame{
			StreamID:   1,
			PromisedID: 2,
			EndHeaders: true,
			Fragment:   []byte{0x82},
		})...)).
		atEOF()

	err := serve(t, ts, rejectingHandler(t), testTimeouts())
	if ce := connErrorOf(t, err); ce.Code != h2.ProtocolError {
		t.Errorf("Serve returned %s, want PROTOCOL_ERROR (RFC 9113 §8.4)", ce.Code)
	}
	if !strings.Contains(err.Error(), "push") {
		t.Errorf("the error does not say what a client may not do: %v", err)
	}
	if ga := goAwayIn(t, peerSaw(t, ts)); ga.ErrCode != h2.ProtocolError {
		t.Errorf("the GOAWAY carries %s, want PROTOCOL_ERROR", ga.ErrCode)
	}
}

// --- stream frames -----------------------------------------------------------

// TestServeHandsStreamFramesToTheHandler is the boundary this file is built around,
// checked from the other side: what the connection does not own, it passes on
// untouched and in arrival order.
func TestServeHandsStreamFramesToTheHandler(t *testing.T) {
	sent := []frame.Frame{
		frame.RSTStreamFrame{StreamID: 1, ErrCode: h2.Cancel},
		frame.WindowUpdateFrame{StreamID: 3, Increment: 1024},
		frame.PriorityFrame{StreamID: 5, StreamDependency: 3, Weight: 15},
	}
	ts := newTestSocket(&testTarget{}).
		script(append(clientHello(t), encodeFrames(t, sent...)...)).
		atEOF()

	h := &recordingHandler{}
	if err := serve(t, ts, h, testTimeouts()); err != nil {
		t.Fatalf("Serve: %v", err)
	}

	got := h.seen()
	if len(got) != len(sent) {
		t.Fatalf("the handler saw %s, want %s", describe(got), describe(sent))
	}
	for i := range sent {
		if got[i] != sent[i] {
			t.Errorf("the handler saw %#v at position %d, want %#v", got[i], i, sent[i])
		}
	}
}

// TestServeKeepsAStreamZeroWindowUpdateFromTheHandler is a special case worth its
// own test because the alternative is so easy to reach: stream 0 names the
// connection, not a stream, so a WINDOW_UPDATE on it has no stream to be handed to.
// Routing it to the stream layer anyway is how flow control ends up entangled with
// the stream table.
func TestServeKeepsAStreamZeroWindowUpdateFromTheHandler(t *testing.T) {
	ts := newTestSocket(&testTarget{}).
		script(append(clientHello(t), encodeFrames(t,
			frame.WindowUpdateFrame{StreamID: 0, Increment: 65535},
			// A stream-bearing one straight after, so that a connection which
			// swallowed both would be caught rather than look like a pass.
			frame.WindowUpdateFrame{StreamID: 1, Increment: 4096},
		)...)).
		atEOF()

	h := &recordingHandler{}
	if err := serve(t, ts, h, testTimeouts()); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	got := h.seen()
	if len(got) != 1 {
		t.Fatalf("the handler saw %s, want only the stream-1 WINDOW_UPDATE", describe(got))
	}
	if wu, ok := got[0].(frame.WindowUpdateFrame); !ok || wu.StreamID != 1 {
		t.Errorf("the handler saw %#v, want the WINDOW_UPDATE on stream 1", got[0])
	}
}

// TestServeResetsOneStreamAndKeepsTheConnection is §5.4.2, and it guards the
// mistake that looks safe: treating a stream error as fatal turns one malformed
// frame into a dropped connection and every other request on it.
//
// The PING after the failure is the assertion. Without it the test would pass on a
// connection that sent the RST_STREAM and then quietly stopped serving.
func TestServeResetsOneStreamAndKeepsTheConnection(t *testing.T) {
	ts := newTestSocket(&testTarget{}).
		script(append(clientHello(t), encodeFrames(t,
			frame.RSTStreamFrame{StreamID: 3, ErrCode: h2.Cancel},
			ping(77),
		)...)).
		atEOF()

	h := &recordingHandler{err: h2.StreamErrorf(3, h2.StreamClosed, "already closed")}
	if err := serve(t, ts, h, testTimeouts()); err != nil {
		t.Fatalf("Serve returned %v, want nil: a stream error ends a stream, not a connection", err)
	}

	got := peerSaw(t, ts)
	var reset *frame.RSTStreamFrame
	answered := false
	for i := range got {
		switch f := got[i].(type) {
		case frame.RSTStreamFrame:
			reset = &f
		case frame.PingFrame:
			answered = answered || f.Ack
		}
	}
	if reset == nil {
		t.Fatalf("the peer received %s, want an RST_STREAM (RFC 9113 §5.4.2)", describe(got))
	}
	if reset.StreamID != 3 || reset.ErrCode != h2.StreamClosed {
		t.Errorf("the RST_STREAM is for stream %d with %s, want stream 3 with STREAM_CLOSED",
			reset.StreamID, reset.ErrCode)
	}
	if !answered {
		t.Errorf("the PING after the stream error went unanswered, so the stream error took the "+
			"connection with it; the peer received %s", describe(got))
	}
	noGoAwayIn(t, got)
}

// TestServeStopsOnAConnectionErrorFromTheHandler is the other half: a stream layer
// reporting a connection error is reporting that the connection cannot continue,
// and the code it chose is the one the peer must be told.
func TestServeStopsOnAConnectionErrorFromTheHandler(t *testing.T) {
	ts := newTestSocket(&testTarget{}).
		script(append(clientHello(t), encodeFrames(t,
			frame.RSTStreamFrame{StreamID: 1, ErrCode: h2.Cancel},
			ping(5),
		)...)).
		atEOF()

	h := &recordingHandler{err: h2.ConnErrorf(h2.EnhanceYourCalm, "too many resets")}
	err := serve(t, ts, h, testTimeouts())

	if ce := connErrorOf(t, err); ce.Code != h2.EnhanceYourCalm {
		t.Errorf("Serve returned %s, want the ENHANCE_YOUR_CALM the handler chose", ce.Code)
	}

	ga := goAwayIn(t, peerSaw(t, ts))
	if ga.ErrCode != h2.EnhanceYourCalm {
		t.Errorf("the GOAWAY carries %s, want ENHANCE_YOUR_CALM", ga.ErrCode)
	}
	if !strings.Contains(string(ga.Debug), "too many resets") {
		t.Errorf("the GOAWAY debug data is %q, want the handler's reason: it is the only thing "+
			"telling the peer which of its own frames caused this", ga.Debug)
	}
	if n := len(h.seen()); n != 1 {
		t.Errorf("the handler saw %d frames, want only the one it refused: the connection must "+
			"stop reading after a connection error", n)
	}
}

// TestServeReportsTheLastStreamItTouched is §6.8's promise. The identifier in a
// GOAWAY is what lets a client know which requests were never looked at and can
// safely be retried on a new connection, so naming too low a stream silently loses
// a request that was in fact processed.
func TestServeReportsTheLastStreamItTouched(t *testing.T) {
	ts := newTestSocket(&testTarget{}).
		script(append(clientHello(t), encodeFrames(t,
			frame.RSTStreamFrame{StreamID: 1, ErrCode: h2.Cancel},
			frame.RSTStreamFrame{StreamID: 7, ErrCode: h2.Cancel},
			// The PUSH_PROMISE is what ends the connection, and it is on stream 3: a
			// connection reporting the stream of the frame that failed rather than
			// the highest it had dispatched would say 3 and be wrong.
			frame.PushPromiseFrame{
				StreamID:   3,
				PromisedID: 2,
				EndHeaders: true,
				Fragment:   []byte{0x82},
			},
		)...)).
		atEOF()

	if err := serve(t, ts, &recordingHandler{}, testTimeouts()); err == nil {
		t.Fatal("Serve returned nil for a client PUSH_PROMISE, want a connection error")
	}
	if ga := goAwayIn(t, peerSaw(t, ts)); ga.LastStreamID != 7 {
		t.Errorf("the GOAWAY names stream %d, want 7: the highest stream the connection "+
			"dispatched (RFC 9113 §6.8)", ga.LastStreamID)
	}
}

// --- timeouts ----------------------------------------------------------------

// TestServeSetsAReadDeadlineBeforeEveryRead is the guard the test socket relies on.
// A read with no deadline is a connection a peer holds open forever by saying
// nothing, and it is invisible: everything works until nobody hangs up.
func TestServeSetsAReadDeadlineBeforeEveryRead(t *testing.T) {
	ts := newTestSocket(&testTarget{}).
		script(append(clientHello(t), encodeFrames(t, ping(1), ping(2))...)).
		atEOF()

	if err := serve(t, ts, rejectingHandler(t), testTimeouts()); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	// One for the preface, one for each of the three frame reads — the SETTINGS and
	// the two PINGs — and one for the read that finds the close. A connection that
	// stopped setting deadlines after the preface would show one.
	got := ts.allReadDeadlines()
	if len(got) < 5 {
		t.Errorf("the connection set %d read deadlines for a preface and 4 reads, want one per read",
			len(got))
	}
	for i, d := range got {
		if d.IsZero() {
			t.Errorf("read deadline %d is the zero time, which clears the deadline rather than "+
				"setting one", i)
		}
	}
}

// TestServeGoesAwayOnTheIdleTimeout is the one timeout a well-behaved client will
// legitimately reach, which is why the ending is NO_ERROR rather than an error: the
// connection is being closed by us, cleanly, and the peer is told so that it opens
// another rather than giving up.
func TestServeGoesAwayOnTheIdleTimeout(t *testing.T) {
	// No atEOF: the peer stays connected and says nothing, which is what an idle
	// connection is.
	ts := newTestSocket(&testTarget{}).script(clientHello(t))

	if err := serve(t, ts, rejectingHandler(t), testTimeouts()); err != nil {
		t.Fatalf("Serve returned %v for an idle connection, want nil: closing an idle connection "+
			"is a decision, not a failure", err)
	}
	ga := goAwayIn(t, peerSaw(t, ts))
	if ga.ErrCode != h2.NoError {
		t.Errorf("the GOAWAY carries %s, want NO_ERROR", ga.ErrCode)
	}
	if !strings.Contains(string(ga.Debug), "idle") {
		t.Errorf("the GOAWAY debug data is %q, want it to say the connection went idle; a bare "+
			"NO_ERROR leaves the client guessing whether to retry", ga.Debug)
	}
}

// TestServeReportsASettingsTimeout is §6.5.3, which gives this one failure its own
// error code. The connection therefore has to know which of its two deadlines
// expired, not merely that one did.
func TestServeReportsASettingsTimeout(t *testing.T) {
	to := testTimeouts()
	to.SettingsAck = shortTimeout
	// The idle deadline is put out of reach so that the deadline which fires is
	// unambiguously the acknowledgement's. At their real defaults the two are ten
	// and sixty seconds apart; with both short here, the winner would be decided by
	// a few microseconds of scheduling.
	to.Idle = longTimeout

	ts := newTestSocket(&testTarget{}).script(clientHello(t))

	err := serve(t, ts, rejectingHandler(t), to)
	if ce := connErrorOf(t, err); ce.Code != h2.SettingsTimeout {
		t.Errorf("Serve returned %s, want SETTINGS_TIMEOUT (RFC 9113 §6.5.3)", ce.Code)
	}
	if ga := goAwayIn(t, peerSaw(t, ts)); ga.ErrCode != h2.SettingsTimeout {
		t.Errorf("the GOAWAY carries %s, want SETTINGS_TIMEOUT", ga.ErrCode)
	}
}

// TestServeReportsASettingsTimeoutToAChattyPeer is the half of §6.5.3 that is easy
// to implement wrongly and impossible to notice: the deadline is measured from the
// moment our SETTINGS went out, not from the last thing the peer said.
//
// A deadline recomputed on each read looks correct — a silent peer still reaches it,
// which is what the test above checks — but a peer that keeps sending frames
// postpones it for ever and never has to acknowledge anything. That is a connection
// held open indefinitely by a peer doing nothing but PING, which is precisely the
// case §6.5.3 exists to close.
func TestServeReportsASettingsTimeoutToAChattyPeer(t *testing.T) {
	const ackWindow = 150 * time.Millisecond

	to := testTimeouts()
	to.SettingsAck = ackWindow
	// Out of reach, so the deadline that fires can only be the acknowledgement's.
	to.Idle, to.Write = longTimeout, longTimeout

	ts := newTestSocket(&testTarget{}).script(clientHello(t))
	done := serveInBackground(newConn(ts, rejectingHandler(t), to))

	// Encoded here rather than in the goroutine below, because encodeFrames reports
	// through t.Fatalf and that may only be called from the goroutine running the
	// test.
	chat := encodeFrames(t, ping(1))

	// A PING every tenth of the acknowledgement window, so a deadline reset by each
	// read is pushed out long before it can expire. stop rather than done, because
	// awaitServe consumes done's single value and a second receive on it would block
	// for ever.
	stop := make(chan struct{})
	chatter := make(chan struct{})
	go func() {
		defer close(chatter)
		for {
			select {
			case <-stop:
				return
			case <-time.After(ackWindow / 10):
				ts.feed(chat)
			}
		}
	}()

	err := awaitServe(t, done)
	close(stop)
	<-chatter

	if ce := connErrorOf(t, err); ce.Code != h2.SettingsTimeout {
		t.Errorf("Serve returned %s for a peer that talked for %v without acknowledging our "+
			"SETTINGS, want SETTINGS_TIMEOUT: the §6.5.3 deadline runs from the moment our "+
			"SETTINGS was sent, not from the peer's last frame", ce.Code, ackWindow)
	}
}

// TestServeStopsTheSettingsClockOnAnAcknowledgement is the other half of §6.5.3,
// and it is asserted on the deadlines rather than by waiting.
//
// Waiting would mean choosing an idle timeout long enough to prove the
// acknowledgement deadline did not fire and short enough that the test still
// finishes, which is a test whose duration is its whole assertion. The deadlines
// the connection set are the direct evidence: after the acknowledgement the next
// read must be running under the idle deadline, an hour away here, and not under an
// acknowledgement deadline that has already passed.
func TestServeStopsTheSettingsClockOnAnAcknowledgement(t *testing.T) {
	to := testTimeouts()
	to.SettingsAck, to.Idle = shortTimeout, longTimeout

	withAck := newTestSocket(&testTarget{}).
		script(append(clientHello(t), encodeFrames(t, frame.SettingsFrame{Ack: true})...)).
		atEOF()
	if err := serve(t, withAck, rejectingHandler(t), to); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if until := time.Until(lastReadDeadline(t, withAck)); until < time.Minute {
		t.Errorf("after the acknowledgement the connection is still reading under a deadline %v "+
			"away, want the idle deadline of %v: the acknowledgement must stop the §6.5.3 clock",
			until, to.Idle)
	}

	// The same script without the acknowledgement, as the control. Without it the
	// assertion above would also pass on a connection that had no acknowledgement
	// clock at all.
	withoutAck := newTestSocket(&testTarget{}).script(clientHello(t)).atEOF()
	if err := serve(t, withoutAck, rejectingHandler(t), to); err != nil {
		t.Fatalf("Serve on the control connection: %v", err)
	}
	if until := time.Until(lastReadDeadline(t, withoutAck)); until > time.Minute {
		t.Errorf("with no acknowledgement received the connection is reading under a deadline %v "+
			"away, want the §6.5.3 deadline of %v: nothing is enforcing it", until, to.SettingsAck)
	}
}

func lastReadDeadline(t *testing.T, ts *testSocket) time.Time {
	t.Helper()
	ds := ts.allReadDeadlines()
	if len(ds) == 0 {
		t.Fatal("the connection set no read deadlines")
	}
	return ds[len(ds)-1]
}

// TestServeDoesNotStartTheSettingsClockBeforeThePreface is a defect this file found
// by arithmetic rather than by failing: the two real defaults are both ten seconds,
// so a connection that started the acknowledgement clock before reading the preface
// would report SETTINGS_TIMEOUT instead of a missing preface, decided by which of
// two calls to time.Now ran first.
//
// A peer cannot acknowledge our SETTINGS before it has sent its own preface, so the
// clock has nothing to measure until the preface is in.
//
// Two configurations, because the first one on its own cannot be relied on to catch
// it. With the deadlines identical the wrong version is a tie, and a tie goes to the
// preface: the two calls to time.Now are a few instructions apart and land in the
// same clock tick often enough that the comparison finds no difference and the test
// passes. That is not the guard working, it is the clock's granularity hiding the
// question — which was confirmed by starting the clock early and watching this test
// pass. The second configuration removes the tie: an acknowledgement deadline well
// inside the preface deadline must still not fire, because it is not running yet.
func TestServeDoesNotStartTheSettingsClockBeforeThePreface(t *testing.T) {
	cases := []struct {
		name                 string
		preface, settingsAck time.Duration
	}{
		// The defaults' own shape, and the case a deployment will actually be in.
		{"identical deadlines", shortTimeout, shortTimeout},
		// Unambiguous: a clock running from before the preface read would expire
		// four short timeouts before the preface deadline is anywhere near.
		{"an acknowledgement deadline well inside the preface deadline", 5 * shortTimeout, shortTimeout},
	}

	for _, tc := range cases {
		to := testTimeouts()
		to.Preface, to.SettingsAck = tc.preface, tc.settingsAck

		err := serve(t, newTestSocket(&testTarget{}), rejectingHandler(t), to)

		ce := connErrorOf(t, err)
		if ce.Code == h2.SettingsTimeout {
			t.Fatalf("%s: Serve returned SETTINGS_TIMEOUT for a peer that never sent a preface: the "+
				"§6.5.3 clock is running before there is anything to acknowledge (%v)", tc.name, err)
		}
		if ce.Code != h2.ProtocolError {
			t.Errorf("%s: Serve returned %s, want PROTOCOL_ERROR for a missing preface", tc.name, ce.Code)
		}
	}
}

// --- endings -----------------------------------------------------------------

// TestServeFlushesWhatIsQueuedWhenThePeerCloses is the difference between the
// writer's two stop signals applied to the commonest ending there is.
//
// The frames still queued when the peer's close arrives are answers to frames the
// peer already sent, and a peer that has closed only its sending half is still
// reading and still owed them. Dropping them would also make the acknowledgement
// §6.5 requires depend on whether the close landed before or after the writer got
// to the queue.
//
// Repeated, because that is exactly what the wrong version looks like: dropping the
// queue loses the acknowledgement only when the writer had not reached it yet, so a
// single attempt passes about half the time and the guard looks present when it is
// not.
func TestServeFlushesWhatIsQueuedWhenThePeerCloses(t *testing.T) {
	for attempt := 0; attempt < 20; attempt++ {
		ts := newTestSocket(&testTarget{}).
			script(append(clientHello(t), encodeFrames(t, ping(42))...)).
			atEOF()

		if err := serve(t, ts, rejectingHandler(t), testTimeouts()); err != nil {
			t.Fatalf("attempt %d: Serve: %v", attempt, err)
		}

		got := peerSaw(t, ts)
		acked, answered := false, false
		for _, f := range got {
			switch v := f.(type) {
			case frame.SettingsFrame:
				acked = acked || v.Ack
			case frame.PingFrame:
				answered = answered || (v.Ack && v.Data == ping(42).Data)
			}
		}
		if !acked || !answered {
			t.Fatalf("attempt %d: the peer received %s, want the SETTINGS acknowledgement and the "+
				"PING reply that were already queued when it closed", attempt, describe(got))
		}
	}
}

// TestServeDoesNotReportAFailedFlushToADepartedPeer is the other half of that
// decision, and it is what keeps a public port's log readable.
//
// A peer that connects and hangs up at once is a health check, a load-balancer
// probe or a port scan, and the write of our own SETTINGS into its closed socket
// fails for a reason that says nothing about this server. Reporting it would mean
// an error line for every one of them.
func TestServeDoesNotReportAFailedFlushToADepartedPeer(t *testing.T) {
	ts := newTestSocket(&testTarget{writeErr: errors.New("connection reset by peer")}).atEOF()

	if err := serve(t, ts, rejectingHandler(t), testTimeouts()); err != nil {
		t.Errorf("Serve returned %v for a peer that hung up before our SETTINGS could be written, "+
			"want nil: the failure describes the peer's departure, not a fault of ours", err)
	}
}

// TestServeAlwaysClosesTheSocket is one leak that no amount of care in the read
// loop prevents. Every ending is enumerated because the one that gets forgotten is
// always an error path.
func TestServeAlwaysClosesTheSocket(t *testing.T) {
	broken := errors.New("connection reset by peer")

	cases := []struct {
		name  string
		build func() *testSocket
	}{
		{"a peer that closes at once", func() *testSocket {
			return newTestSocket(&testTarget{}).atEOF()
		}},
		{"a bad preface", func() *testSocket {
			return newTestSocket(&testTarget{}).script([]byte("not the preface at all!!")).atEOF()
		}},
		{"a clean end", func() *testSocket {
			return newTestSocket(&testTarget{}).script(clientHello(t)).atEOF()
		}},
		{"a connection error", func() *testSocket {
			return newTestSocket(&testTarget{}).
				script(append([]byte(frame.ClientPreface), encodeFrames(t, ping(1))...)).
				atEOF()
		}},
		{"a transport failure", func() *testSocket {
			return newTestSocket(&testTarget{}).script(clientHello(t)).failsWith(broken)
		}},
		{"an idle timeout", func() *testSocket {
			return newTestSocket(&testTarget{}).script(clientHello(t))
		}},
	}

	for _, tc := range cases {
		ts := tc.build()
		// The error is not the subject here; each of these endings has its own test
		// above.
		_ = serve(t, ts, rejectingHandler(t), testTimeouts())
		if got := ts.closeCount(); got != 1 {
			t.Errorf("%s: the socket was closed %d times, want exactly 1", tc.name, got)
		}
	}
}

// TestServeSaysNothingAfterATransportFailure is the difference between Close and
// Shutdown on the writer. A socket that has failed cannot carry a GOAWAY, and
// attempting one produces a second error describing our own reaction, which then
// competes with the real one for the log line.
func TestServeSaysNothingAfterATransportFailure(t *testing.T) {
	broken := errors.New("connection reset by peer")

	ts := newTestSocket(&testTarget{}).script(clientHello(t)).failsWith(broken)

	err := serve(t, ts, rejectingHandler(t), testTimeouts())
	if !errors.Is(err, broken) {
		t.Errorf("Serve returned %v, want the transport error %v: it is the only thing that says "+
			"what happened", err, broken)
	}
	// Not an assertion on how many frames got out — the writer is stopped without
	// flushing, so the server's own SETTINGS may or may not have made it, and either
	// is correct. What must not happen is a GOAWAY.
	noGoAwayIn(t, peerSaw(t, ts))
}

// TestServeReportsATruncatedFrame keeps a peer that vanished mid-frame separate
// from one that closed at a frame boundary. Folding the two together would report a
// broken connection as a clean one, which is exactly the case worth knowing about
// when a request has gone missing.
func TestServeReportsATruncatedFrame(t *testing.T) {
	whole := encodeFrames(t, ping(1))
	ts := newTestSocket(&testTarget{}).
		script(append(clientHello(t), whole[:len(whole)-3]...)).
		atEOF()

	err := serve(t, ts, rejectingHandler(t), testTimeouts())
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("Serve returned %v, want io.ErrUnexpectedEOF for a frame cut in half", err)
	}
}

// TestNewConnRequiresAStreamHandler fails at construction rather than on the first
// HEADERS frame of the first request. The alternative is the same bug reported
// later, from a goroutine further away, with a peer's traffic mixed into the stack
// trace.
func TestNewConnRequiresAStreamHandler(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("newConn accepted a nil stream handler; the connection would instead panic on " +
				"the first stream frame it received")
		}
		if msg, ok := r.(string); !ok || !strings.Contains(msg, "stream handler") {
			t.Errorf("the panic says %v, want it to name the missing handler", r)
		}
	}()
	newConn(newTestSocket(&testTarget{}), nil, testTimeouts())
}

// TestNewConnFillsUnsetTimeouts is the check that a caller cannot get a connection
// with no deadlines by leaving the struct empty. Every field zero would mean every
// deadline being time.Now, which fails every read at once — a failure mode that
// looks exactly like a broken peer.
func TestNewConnFillsUnsetTimeouts(t *testing.T) {
	c := newConn(newTestSocket(&testTarget{}).atEOF(), &recordingHandler{}, limits.Timeouts{})
	defer stopWriter(t, c)

	if c.timeouts != limits.DefaultTimeouts() {
		t.Errorf("newConn with a zero Timeouts gave %+v, want the defaults %+v",
			c.timeouts, limits.DefaultTimeouts())
	}
}

// TestServeLeaksNoGoroutines is the whole-connection version of the writer's leak
// test. One goroutine left behind per connection is not a leak that shows up in
// testing; it is a server that dies after a few hundred thousand requests.
func TestServeLeaksNoGoroutines(t *testing.T) {
	baseline := goroutineBaseline()

	endings := []func() *testSocket{
		func() *testSocket { return newTestSocket(&testTarget{}).atEOF() },
		func() *testSocket { return newTestSocket(&testTarget{}).script(clientHello(t)).atEOF() },
		func() *testSocket {
			return newTestSocket(&testTarget{}).
				script(append(clientHello(t), encodeFrames(t, ping(3))...)).
				atEOF()
		},
		func() *testSocket {
			return newTestSocket(&testTarget{}).
				script(append([]byte(frame.ClientPreface), encodeFrames(t, ping(1))...)).
				atEOF()
		},
		func() *testSocket {
			return newTestSocket(&testTarget{}).
				script(clientHello(t)).
				failsWith(errors.New("connection reset by peer"))
		},
		// The idle timeout, which is the ending that leaves the writer goroutine
		// behind if the graceful shutdown is never waited for.
		func() *testSocket { return newTestSocket(&testTarget{}).script(clientHello(t)) },
	}

	for _, build := range endings {
		_ = serve(t, build(), rejectingHandler(t), testTimeouts())
	}
	assertNoGoroutineLeak(t, baseline)
}
