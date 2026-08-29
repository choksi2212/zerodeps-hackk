package stream

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"zerodeps/zdh/internal/flow"
	"zerodeps/zdh/internal/frame"
	"zerodeps/zdh/internal/h2"
	"zerodeps/zdh/internal/limits"
)

// --- doubles ---------------------------------------------------------------

// testCodec stands in for internal/hpack.
//
// The wire format is deliberately not HPACK: name and value separated by a NUL,
// fields separated by a newline, with 0xff as the octet that fails to decode. NUL
// and not a colon, because a pseudo-header name starts with one (§8.3) and cutting
// ":method" at the first colon yields an empty name — a separator that appears in
// the data is a test double that lies about the data.
//
// What the tests here need from a codec is that a block decodes to known fields,
// that a specific block can be made to fail, and above all that every block
// handed to it is *recorded* —
// because the rule this package has to obey is that a header block is decoded even
// when its stream has been refused (§5.1), and the only evidence of that is the
// codec having seen the octets.
//
// Using the real HPACK here would test internal/hpack instead, and would make
// every assertion about a refused stream's block depend on a second package's
// dynamic-table state.
type testCodec struct {
	// decoded is every block handed to Decode, in order.
	decoded [][]byte

	// tableSizes is every value passed to SetMaxDynamicTableSize.
	tableSizes []int
}

// codecFailure is the byte that makes testCodec refuse a block, standing in for a
// malformed HPACK block. codecSep separates a field's name from its value; both
// octets are ones a real field can never contain.
const (
	codecFailure = 0xff
	codecSep     = "\x00"
)

func (c *testCodec) Encode(fields []h2.Field) []byte { return encodeFields(fields...) }

func (c *testCodec) SetMaxDynamicTableSize(n int) { c.tableSizes = append(c.tableSizes, n) }

func (c *testCodec) Decode(block []byte) ([]h2.Field, error) {
	// Recorded before the failure check, because a block that fails to decode has
	// still been fed to the codec and the tests about ordering care which.
	c.decoded = append(c.decoded, append([]byte(nil), block...))

	for _, b := range block {
		if b == codecFailure {
			return nil, fmt.Errorf("testCodec: octet %#x is not decodable", codecFailure)
		}
	}
	if len(block) == 0 {
		return nil, nil
	}
	var fields []h2.Field
	for _, line := range strings.Split(string(block), "\n") {
		name, value, ok := strings.Cut(line, codecSep)
		if !ok {
			return nil, fmt.Errorf("testCodec: %q has no separator", line)
		}
		fields = append(fields, h2.Field{Name: name, Value: value})
	}
	return fields, nil
}

// blocks is the codec's record as strings, for readable failure messages.
func (c *testCodec) blocks() []string {
	out := make([]string, 0, len(c.decoded))
	for _, b := range c.decoded {
		out = append(out, string(b))
	}
	return out
}

func encodeFields(fields ...h2.Field) []byte {
	lines := make([]string, 0, len(fields))
	for _, f := range fields {
		lines = append(lines, f.Name+codecSep+f.Value)
	}
	return []byte(strings.Join(lines, "\n"))
}

// event is one call the table made on Requests.
//
// One flat type for all four calls, and one flat slice of them, because most of
// what these tests assert is about order and about what did *not* happen — a
// refused stream that was delivered anyway, a request delivered before its block
// was complete. Separate slices per call would make "nothing was delivered" four
// assertions instead of one.
type event struct {
	kind string
	id   uint32

	// state is the stream's state as the callee saw it, which is the only way to
	// check that the table settles the state before it delivers rather than
	// afterwards.
	state State

	fields    []h2.Field
	body      string
	endStream bool
	code      h2.ErrCode
}

func (e event) String() string {
	switch e.kind {
	case "data":
		return fmt.Sprintf("data(%d, %q, end=%v, state=%s)", e.id, e.body, e.endStream, e.state)
	case "canceled":
		return fmt.Sprintf("canceled(%d, %s)", e.id, e.code)
	default:
		return fmt.Sprintf("%s(%d, %v, end=%v, state=%s)", e.kind, e.id, e.fields, e.endStream, e.state)
	}
}

// recorder is a Requests that records and, optionally, fails.
type recorder struct {
	events []event

	// err is returned by every method that can return one, to check that an
	// error from the layer above reaches internal/server unchanged.
	err error
}

func (r *recorder) Headers(s *Stream, fields []h2.Field, endStream bool) error {
	r.events = append(r.events, event{
		kind: "headers", id: s.ID(), state: s.State(), fields: fields, endStream: endStream,
	})
	return r.err
}

func (r *recorder) Data(s *Stream, b []byte, endStream bool) error {
	r.events = append(r.events, event{
		kind: "data", id: s.ID(), state: s.State(), body: string(b), endStream: endStream,
	})
	return r.err
}

func (r *recorder) Trailers(s *Stream, fields []h2.Field) error {
	r.events = append(r.events, event{
		kind: "trailers", id: s.ID(), state: s.State(), fields: fields, endStream: true,
	})
	return r.err
}

func (r *recorder) Canceled(s *Stream, code h2.ErrCode) {
	r.events = append(r.events, event{
		kind: "canceled", id: s.ID(), state: s.State(), code: code,
	})
}

func (r *recorder) String() string {
	out := make([]string, 0, len(r.events))
	for _, e := range r.events {
		out = append(out, e.String())
	}
	return "[" + strings.Join(out, " ") + "]"
}

// testClock is the RST_STREAM rate limit's clock.
//
// A fixed instant rather than time.Now, so that a test about a token bucket is a
// test about the bucket rather than about how long the test took to run. The date
// is arbitrary and only has to be stable.
type testClock struct{ t time.Time }

func newClock() *testClock {
	return &testClock{t: time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)}
}

func (c *testClock) now() time.Time          { return c.t }
func (c *testClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// --- harness ---------------------------------------------------------------

type harness struct {
	t     *testing.T
	tab   *Table
	codec *testCodec
	reqs  *recorder
	clock *testClock
}

func newHarness(t *testing.T, cfg Config) *harness {
	t.Helper()
	h := &harness{t: t, codec: &testCodec{}, reqs: &recorder{}, clock: newClock()}
	if cfg.Codec == nil {
		cfg.Codec = h.codec
	}
	if cfg.Requests == nil {
		cfg.Requests = h.reqs
	}
	if cfg.Now == nil {
		cfg.Now = h.clock.now
	}
	h.tab = New(cfg)
	return h
}

// send hands one frame to the table.
func (h *harness) send(f frame.Frame) error {
	h.t.Helper()
	return h.tab.HandleFrame(f)
}

// mustSend hands one frame to the table and fails the test if it is refused.
func (h *harness) mustSend(f frame.Frame) {
	h.t.Helper()
	if err := h.send(f); err != nil {
		h.t.Fatalf("%s on stream %d: unexpected error: %v", f.Type(), f.Stream(), err)
	}
}

// open opens stream id with a complete header block in one frame.
func (h *harness) open(id uint32, endStream bool) {
	h.t.Helper()
	h.mustSend(request(id, endStream))
}

// sendAvailable is the credit left on stream id's send window, and fails the test
// if the Sender has no window for that stream at all.
//
// Read through the Sender rather than off the Stream because the send direction is
// deliberately not reachable from a *Stream: it is spent by a goroutine the table
// does not own. See Table.sender.
func (h *harness) sendAvailable(id uint32) int64 {
	h.t.Helper()
	n, ok := h.tab.Sender().Available(id)
	if !ok {
		h.t.Fatalf("stream %d has no send window", id)
	}
	return n
}

// spendSend takes n octets of stream id's send credit, which is what writing n
// octets of its response body does.
//
// It cannot block in these tests: every caller has arranged for the credit to be
// there, and a Reserve that returned short would fail here rather than deadlock.
func (h *harness) spendSend(id uint32, n int) {
	h.t.Helper()
	got, err := h.tab.Sender().Reserve(id, n)
	if err != nil {
		h.t.Fatalf("reserving %d octets on stream %d: %v", n, id, err)
	}
	if got != n {
		h.t.Fatalf("reserved %d of the %d octets asked for on stream %d", got, n, id)
	}
}

// events is the recorder's log, formatted.
func (h *harness) events() string { return h.reqs.String() }

// request is a one-frame request on stream id.
func request(id uint32, endStream bool) frame.HeadersFrame {
	return frame.HeadersFrame{
		StreamID:   id,
		EndStream:  endStream,
		EndHeaders: true,
		Fragment: encodeFields(
			h2.Field{Name: ":method", Value: "GET"},
			h2.Field{Name: ":path", Value: fmt.Sprintf("/%d", id)},
		),
	}
}

// data is a DATA frame carrying body on stream id.
func data(id uint32, body string, endStream bool) frame.DataFrame {
	return frame.DataFrame{StreamID: id, EndStream: endStream, Data: []byte(body)}
}

// filler is a DATA frame of n octets, for flow-control arithmetic.
func filler(id uint32, n int, endStream bool) frame.DataFrame {
	return frame.DataFrame{StreamID: id, EndStream: endStream, Data: make([]byte, n)}
}

// --- assertions ------------------------------------------------------------

// assertConnError checks that err is a connection error with code, and that it is
// not also a stream error. Both halves matter: a stream error that happens to
// carry the right code would satisfy the first check while resetting one stream
// where the connection was supposed to end.
func assertConnError(t *testing.T, err error, code h2.ErrCode, what string) {
	t.Helper()
	var ce h2.ConnError
	if !errors.As(err, &ce) {
		t.Fatalf("%s: got %v, want a connection error of type %s", what, err, code)
	}
	if ce.Code != code {
		t.Errorf("%s: got connection error %s (%v), want %s", what, ce.Code, err, code)
	}
	var se h2.StreamError
	if errors.As(err, &se) {
		t.Errorf("%s: %v is also a stream error on stream %d, so the connection would survive", what, err, se.StreamID)
	}
}

// assertStreamError is the mirror: a stream error on id with code, and not a
// connection error.
func assertStreamError(t *testing.T, err error, id uint32, code h2.ErrCode, what string) {
	t.Helper()
	var se h2.StreamError
	if !errors.As(err, &se) {
		t.Fatalf("%s: got %v, want a stream error of type %s on stream %d", what, err, code, id)
	}
	if se.Code != code {
		t.Errorf("%s: got stream error %s (%v), want %s", what, se.Code, err, code)
	}
	if se.StreamID != id {
		t.Errorf("%s: got stream error on stream %d, want stream %d", what, se.StreamID, id)
	}
	var ce h2.ConnError
	if errors.As(err, &ce) {
		t.Errorf("%s: %v is also a connection error, so one stream's fault would end the connection", what, err)
	}
}

func assertPanics(t *testing.T, what string, f func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Errorf("%s: did not panic", what)
		}
	}()
	f()
}

// assertEvents compares the recorder's log against a formatted expectation.
func (h *harness) assertEvents(want string) {
	h.t.Helper()
	if got := h.events(); got != want {
		h.t.Errorf("delivered %s, want %s", got, want)
	}
}

// assertState checks a stream's state as the table derives it.
func (h *harness) assertState(id uint32, want State) {
	h.t.Helper()
	if got := h.tab.StateOf(id); got != want {
		h.t.Errorf("stream %d is %s, want %s", id, got, want)
	}
}

// assertBlocks checks the sequence of blocks the codec was asked to decode.
func (h *harness) assertBlocks(want ...string) {
	h.t.Helper()
	got := h.codec.blocks()
	if len(got) != len(want) {
		h.t.Fatalf("codec decoded %d blocks %q, want %d %q", len(got), got, len(want), want)
	}
	for i := range got {
		if got[i] != want[i] {
			h.t.Errorf("block %d decoded as %q, want %q", i, got[i], want[i])
		}
	}
}

// --- construction ----------------------------------------------------------

func TestNewPanicsWithoutACodec(t *testing.T) {
	assertPanics(t, "New with no codec", func() {
		New(Config{Requests: &recorder{}})
	})
}

func TestNewPanicsWithoutRequests(t *testing.T) {
	assertPanics(t, "New with no Requests", func() {
		New(Config{Codec: &testCodec{}})
	})
}

func TestNewStartsBothConnectionWindowsAtTheProtocolInitialSize(t *testing.T) {
	h := newHarness(t, Config{})
	if got := h.tab.RecvWindow().Available(); got != flow.InitialWindowSize {
		t.Errorf("connection receive window starts at %d, want %d", got, flow.InitialWindowSize)
	}
	if got := h.tab.Sender().ConnAvailable(); got != flow.InitialWindowSize {
		t.Errorf("connection send window starts at %d, want %d", got, flow.InitialWindowSize)
	}
	// §6.9.2 gives the connection window no other starting value and no way to be
	// configured, so a table that took one from Config would be a table whose
	// credit could be set to something the peer did not assume.
	if got := h.tab.RecvWindow().StreamID(); got != 0 {
		t.Errorf("connection receive window belongs to stream %d, want 0", got)
	}
	// And the same for the size the next stream's send window will be opened at,
	// which is the other half of §6.9.2's "both ends must assume".
	if got := h.tab.Sender().InitialSize(); got != flow.InitialWindowSize {
		t.Errorf("the initial stream send window is %d, want %d", got, flow.InitialWindowSize)
	}
}

func TestNewDefaultsTheConcurrencyLimitToThePolicyBound(t *testing.T) {
	h := newHarness(t, Config{})
	var id uint32 = 1
	for i := 0; i < limits.MaxConcurrentStreams; i++ {
		h.open(id, false)
		id += 2
	}
	if got := h.tab.Len(); got != limits.MaxConcurrentStreams {
		t.Fatalf("opened %d streams, want %d", got, limits.MaxConcurrentStreams)
	}
	err := h.send(request(id, false))
	assertStreamError(t, err, id, h2.RefusedStream, "one stream past the default limit")
}

func TestNewDefaultsTheClockToTimeNow(t *testing.T) {
	// Config.Now is nil on every real connection, and the reset bucket is created
	// from it during New. A missing default is therefore not a wrong clock but a
	// nil call in the constructor, which is why this is worth its own test rather
	// than being left to the tests that inject one.
	tab := New(Config{Codec: &testCodec{}, Requests: &recorder{}})
	if err := tab.HandleFrame(request(1, false)); err != nil {
		t.Fatalf("opening a stream on a table with the default clock: %v", err)
	}
	if err := tab.HandleFrame(frame.RSTStreamFrame{StreamID: 1, ErrCode: h2.Cancel}); err != nil {
		t.Fatalf("the reset bucket is not running on a usable clock: %v", err)
	}
}

func TestNewSizesNewStreamWindowsFromTheProtocolInitialSize(t *testing.T) {
	h := newHarness(t, Config{})
	h.open(1, false)
	s := h.tab.Stream(1)
	// Our grant to the peer and the peer's grant to us both start here, because
	// neither end has sent SETTINGS_INITIAL_WINDOW_SIZE yet (§6.9.2).
	if got := s.RecvWindow().Available(); got != flow.InitialWindowSize {
		t.Errorf("stream receive window starts at %d, want %d", got, flow.InitialWindowSize)
	}
	if got := h.sendAvailable(1); got != flow.InitialWindowSize {
		t.Errorf("stream send window starts at %d, want %d", got, flow.InitialWindowSize)
	}
	if got := s.RecvWindow().StreamID(); got != 1 {
		t.Errorf("stream 1's receive window reports stream %d, so its errors would have the wrong scope", got)
	}
}

// --- state derivation ------------------------------------------------------

func TestStateOfIsIdleForAnIdentifierNobodyHasUsed(t *testing.T) {
	h := newHarness(t, Config{})
	h.assertState(1, StateIdle)
	h.assertState(4097, StateIdle)
}

func TestStateOfIsClosedForAnIdentifierThePeerSkipped(t *testing.T) {
	h := newHarness(t, Config{})
	h.open(5, false)
	// §5.1.1: "When a stream transitions out of the idle state, all streams in the
	// idle state that might have been opened by the peer with a lower-valued stream
	// identifier immediately transition to closed."
	h.assertState(1, StateClosed)
	h.assertState(3, StateClosed)
	h.assertState(5, StateOpen)
	h.assertState(7, StateIdle)
}

func TestStateOfIsAlwaysIdleForAnEvenIdentifier(t *testing.T) {
	h := newHarness(t, Config{})
	h.open(99, false)
	// Even identifiers are the server's to open (§5.1.1) and this server never
	// opens one, so no even stream is ever anything but idle — including the ones
	// below an identifier the client has used, which the odd-numbered rule would
	// otherwise call closed.
	for _, id := range []uint32{2, 4, 98, 100} {
		h.assertState(id, StateIdle)
	}
}

func TestStateOfTracksAStreamThroughEveryTransition(t *testing.T) {
	h := newHarness(t, Config{})
	h.assertState(1, StateIdle)

	h.open(1, false)
	h.assertState(1, StateOpen)

	h.mustSend(data(1, "body", true))
	h.assertState(1, StateHalfClosedRemote)

	h.tab.SendEnd(h.tab.Stream(1))
	h.assertState(1, StateClosed)
}

func TestStateOfTracksTheOtherOrderOfClosing(t *testing.T) {
	// The mirror of the test above, and not redundant with it: recvEnd and SendEnd
	// each have two outcomes depending on what the other side has already done, and
	// this is the pair of branches the other test does not reach.
	h := newHarness(t, Config{})
	h.open(1, false)

	h.tab.SendEnd(h.tab.Stream(1))
	h.assertState(1, StateHalfClosedLocal)

	h.mustSend(data(1, "body", true))
	h.assertState(1, StateClosed)
}

func TestStateStringsNameTheRfcsOwnStates(t *testing.T) {
	// These strings appear in protocol error messages, and a reader diagnosing one
	// has §5.1's figure open, so they are spelled the way it spells them.
	for _, tc := range []struct {
		s    State
		want string
	}{
		{StateIdle, "idle"},
		{StateOpen, "open"},
		{StateHalfClosedRemote, "half-closed (remote)"},
		{StateHalfClosedLocal, "half-closed (local)"},
		{StateClosed, "closed"},
		{State(99), "unknown"},
	} {
		if got := tc.s.String(); got != tc.want {
			t.Errorf("State(%d).String() = %q, want %q", int(tc.s), got, tc.want)
		}
	}
}

// --- opening a stream ------------------------------------------------------

func TestHeadersOpensAStreamAndDeliversItsFields(t *testing.T) {
	h := newHarness(t, Config{})
	h.mustSend(frame.HeadersFrame{
		StreamID:   1,
		EndHeaders: true,
		Fragment:   encodeFields(h2.Field{Name: ":method", Value: "POST"}),
	})
	h.assertEvents("[headers(1, [{:method POST false}], end=false, state=open)]")
	if got := h.tab.Len(); got != 1 {
		t.Errorf("table holds %d streams, want 1", got)
	}
}

func TestHeadersWithEndStreamLeavesTheStreamHalfClosed(t *testing.T) {
	h := newHarness(t, Config{})
	h.open(1, true)
	// The state is settled before delivery, so a handler that asks whether the
	// request has a body gets the answer the wire gave.
	h.assertEvents("[headers(1, [{:method GET false} {:path /1 false}], end=true, state=half-closed (remote))]")
	h.assertState(1, StateHalfClosedRemote)
}

func TestHeadersOnAnEvenStreamEndsTheConnection(t *testing.T) {
	h := newHarness(t, Config{})
	err := h.send(request(2, false))
	assertConnError(t, err, h2.ProtocolError, "HEADERS on an even-numbered stream")
	if h.tab.Len() != 0 {
		t.Errorf("stream 2 was admitted")
	}
}

func TestHeadersOnAnIdentifierThatIsStillLiveIsNotIdentifierReuse(t *testing.T) {
	// §5.1.1's rule is about identifiers that are *new*, and the table reaches it
	// only for streams it no longer holds. Checking it first would make trailers
	// impossible: a trailer section arrives on the identifier its request came in
	// on, which is by definition not greater than the highest one seen.
	h := newHarness(t, Config{})
	h.open(1, false)
	h.mustSend(frame.HeadersFrame{
		StreamID: 1, EndStream: true, EndHeaders: true,
		Fragment: encodeFields(h2.Field{Name: "x", Value: "y"}),
	})
	h.assertState(1, StateHalfClosedRemote)

	// The same identifier once the stream has gone, where the rule does apply.
	h.tab.SendEnd(h.tab.Stream(1))
	assertConnError(t, h.send(request(1, false)), h2.ProtocolError, "HEADERS reusing a closed identifier")
}

func TestHeadersOnADecreasingIdentifierEndsTheConnection(t *testing.T) {
	h := newHarness(t, Config{})
	h.open(5, false)
	err := h.send(request(3, false))
	// §5.1.1: "An endpoint that receives an unexpected stream identifier MUST
	// respond with a connection error of type PROTOCOL_ERROR." PROTOCOL_ERROR and
	// not STREAM_CLOSED, even though stream 3 is closed by then, because the
	// identifier rule is the more specific reading of the same fault.
	assertConnError(t, err, h2.ProtocolError, "HEADERS on a lower identifier")
}

func TestHeadersOnAStreamThatHasFinishedEndsTheConnection(t *testing.T) {
	h := newHarness(t, Config{})
	h.open(1, true)
	h.tab.SendEnd(h.tab.Stream(1))
	h.assertState(1, StateClosed)
	err := h.send(request(1, false))
	assertConnError(t, err, h2.ProtocolError, "HEADERS on a stream that has closed")
}

// --- header block assembly -------------------------------------------------

func TestABlockSplitAcrossContinuationsIsDecodedAsOne(t *testing.T) {
	h := newHarness(t, Config{})
	block := encodeFields(
		h2.Field{Name: ":method", Value: "GET"},
		h2.Field{Name: ":path", Value: "/split"},
	)
	h.mustSend(frame.HeadersFrame{StreamID: 1, Fragment: block[:5]})
	h.assertEvents("[]")
	h.mustSend(frame.ContinuationFrame{StreamID: 1, Fragment: block[5:9]})
	h.assertEvents("[]")
	h.mustSend(frame.ContinuationFrame{StreamID: 1, EndHeaders: true, Fragment: block[9:]})

	h.assertBlocks(string(block))
	h.assertEvents("[headers(1, [{:method GET false} {:path /split false}], end=false, state=open)]")
}

func TestABlockIsNotDecodedUntilItIsComplete(t *testing.T) {
	h := newHarness(t, Config{})
	h.mustSend(frame.HeadersFrame{StreamID: 1, Fragment: encodeFields(h2.Field{Name: "a", Value: "b"})})
	// The stream is not in the table either. §5.1 makes a stream open on receipt
	// of HEADERS, but a partial block is not a request yet, and a stream admitted
	// before its block completed would count against the concurrency limit while
	// having nothing to answer.
	h.assertBlocks()
	h.assertEvents("[]")
	if got := h.tab.Len(); got != 0 {
		t.Errorf("table holds %d streams before the block completed, want 0", got)
	}
	// The identifier is nonetheless spent: §5.1.1 is about identifiers a peer has
	// used, and this one has been used, so a later HEADERS on a lower one is still
	// the violation it would have been. That reads as "closed" here because the
	// table stores no stream for a block that is still assembling — a transient the
	// peer cannot extend, since §6.10 admits nothing but CONTINUATION on this
	// connection until the block ends, and one that can only cause a rejection
	// rather than an acceptance.
	h.assertState(1, StateClosed)
}

func TestEmptyContinuationFragmentsStillMakeABlock(t *testing.T) {
	// A zero-length CONTINUATION is legal and a peer is entitled to send a run of
	// them. The block is what the fragments concatenate to, which is nothing here,
	// and an empty block is a valid HPACK block that decodes to no fields.
	h := newHarness(t, Config{})
	h.mustSend(frame.HeadersFrame{StreamID: 1})
	h.mustSend(frame.ContinuationFrame{StreamID: 1})
	h.mustSend(frame.ContinuationFrame{StreamID: 1, EndHeaders: true})
	h.assertBlocks("")
	h.assertEvents("[headers(1, [], end=false, state=open)]")
}

func TestContinuationWithNoBlockOpenEndsTheConnection(t *testing.T) {
	h := newHarness(t, Config{})
	err := h.send(frame.ContinuationFrame{StreamID: 1, EndHeaders: true})
	assertConnError(t, err, h2.ProtocolError, "CONTINUATION with no block open")
}

func TestContinuationOnTheWrongStreamEndsTheConnection(t *testing.T) {
	// Both directions, because the check is an inequality and the two sides of one
	// are not the same guard: a comparison that only refused a higher identifier
	// would let a peer interleave a lower one, which is the same fault with the
	// frames in the other order.
	for _, tc := range []struct {
		what     string
		open, on uint32
	}{
		{"a higher identifier", 1, 3},
		{"a lower identifier", 3, 1},
	} {
		t.Run(tc.what, func(t *testing.T) {
			h := newHarness(t, Config{})
			h.mustSend(frame.HeadersFrame{StreamID: tc.open, Fragment: encodeFields(h2.Field{Name: "a", Value: "b"})})
			err := h.send(frame.ContinuationFrame{StreamID: tc.on, EndHeaders: true, Fragment: encodeFields(h2.Field{Name: "c", Value: "d"})})
			// The one that matters most: these fragments would concatenate into a
			// block that decodes cleanly, so without the check the failure is a
			// request assembled out of two with no symptom at all.
			assertConnError(t, err, h2.ProtocolError, "CONTINUATION on the wrong stream")
			h.assertBlocks()
			h.assertEvents("[]")
		})
	}
}

func TestHeadersWhileABlockIsOpenEndsTheConnection(t *testing.T) {
	h := newHarness(t, Config{})
	h.mustSend(frame.HeadersFrame{StreamID: 1, Fragment: encodeFields(h2.Field{Name: "a", Value: "b"})})
	err := h.send(request(3, false))
	assertConnError(t, err, h2.ProtocolError, "HEADERS while a block is open")
}

func TestABlockThatFailsToDecodeEndsTheConnection(t *testing.T) {
	h := newHarness(t, Config{})
	err := h.send(frame.HeadersFrame{
		StreamID: 1, EndHeaders: true, Fragment: []byte{codecFailure},
	})
	// §4.3: the dynamic table cannot be resynchronised after a block that failed
	// to decode, so there is no stream-scoped answer to this however much the
	// fault looks like one stream's.
	assertConnError(t, err, h2.CompressionError, "a block that fails to decode")
}

// --- the deferred verdict --------------------------------------------------

func TestARefusedStreamsBlockIsStillDecoded(t *testing.T) {
	// The reason a stream-level verdict is deferred at all. §5.1 requires header
	// compression state to be updated for a stream that is closed or refused, so
	// the block has to reach the codec before the refusal is reported. A table
	// that returned the stream error from the HEADERS frame would leave the
	// dynamic table one insertion behind the peer's, and every later request on
	// the connection would decode into fields nobody sent.
	h := newHarness(t, Config{MaxConcurrent: 1})
	h.open(1, false)

	block := encodeFields(h2.Field{Name: ":path", Value: "/refused"})
	h.mustSend(frame.HeadersFrame{StreamID: 3, Fragment: block[:4]})
	h.mustSend(frame.ContinuationFrame{StreamID: 3, Fragment: block[4:6]})
	err := h.send(frame.ContinuationFrame{StreamID: 3, EndHeaders: true, Fragment: block[6:]})

	assertStreamError(t, err, 3, h2.RefusedStream, "a stream past the concurrency limit")
	h.assertBlocks(string(encodeFields(h2.Field{Name: ":method", Value: "GET"}, h2.Field{Name: ":path", Value: "/1"})), string(block))
	h.assertEvents("[headers(1, [{:method GET false} {:path /1 false}], end=false, state=open)]")
}

func TestARefusedStreamIsNotReportedUntilItsBlockIsComplete(t *testing.T) {
	// The other half of the same rule: the refusal must not arrive early either,
	// because internal/server answers a stream error with RST_STREAM and the
	// CONTINUATION frames of the block are still on their way. A RST_STREAM sent
	// mid-block would be a frame §6.10 forbids there.
	h := newHarness(t, Config{MaxConcurrent: 1})
	h.open(1, false)

	if err := h.send(frame.HeadersFrame{StreamID: 3, Fragment: encodeFields(h2.Field{Name: "a", Value: "b"})}); err != nil {
		t.Fatalf("the HEADERS frame of a refused stream reported %v mid-block", err)
	}
	if err := h.send(frame.ContinuationFrame{StreamID: 3, Fragment: encodeFields(h2.Field{Name: "c", Value: "d"})}); err != nil {
		t.Fatalf("a CONTINUATION frame of a refused stream reported %v mid-block", err)
	}
	err := h.send(frame.ContinuationFrame{StreamID: 3, EndHeaders: true})
	assertStreamError(t, err, 3, h2.RefusedStream, "the last frame of a refused stream's block")
}

func TestASelfDependentStreamIsRefusedAndItsBlockDecoded(t *testing.T) {
	h := newHarness(t, Config{})
	f := request(1, false)
	f.Priority = true
	f.StreamDependency = 1
	err := h.send(f)
	// RFC 7540 §5.3.1. internal/frame deliberately does not reject this on a
	// HEADERS frame, because rejecting it there means discarding the block.
	assertStreamError(t, err, 1, h2.ProtocolError, "a stream that depends on itself")
	h.assertBlocks(string(f.Fragment))
	h.assertEvents("[]")
	if h.tab.Len() != 0 {
		t.Errorf("a self-dependent stream was admitted")
	}
}

func TestASelfDependencyIsReportedAheadOfTheConcurrencyLimit(t *testing.T) {
	// Both verdicts apply to this frame and only one can be returned. A malformed
	// frame reported as "too busy" would tell a client to retry something that
	// will be refused every time.
	h := newHarness(t, Config{MaxConcurrent: 1})
	h.open(1, false)
	f := request(3, false)
	f.Priority = true
	f.StreamDependency = 3
	assertStreamError(t, h.send(f), 3, h2.ProtocolError, "self-dependent and over the limit")
}

func TestACompressionErrorBeatsADeferredStreamError(t *testing.T) {
	// A refused stream whose block is also undecodable. The connection error has
	// to win: the stream error would keep a connection running on a dynamic table
	// nobody can agree about.
	h := newHarness(t, Config{MaxConcurrent: 1})
	h.open(1, false)
	err := h.send(frame.HeadersFrame{
		StreamID: 3, EndHeaders: true, Fragment: []byte{codecFailure},
	})
	assertConnError(t, err, h2.CompressionError, "a refused stream with an undecodable block")
}

func TestABlockIsClosedEvenWhenItsStreamIsRefused(t *testing.T) {
	// A refused stream must not leave the assembly state occupied, or the next
	// HEADERS frame on the connection reports the wrong fault entirely.
	h := newHarness(t, Config{MaxConcurrent: 1})
	h.open(1, false)
	assertStreamError(t, h.send(request(3, false)), 3, h2.RefusedStream, "the refused stream")

	h.mustSend(data(1, "x", true)) // frees the slot
	h.assertState(1, StateHalfClosedRemote)
	h.tab.SendEnd(h.tab.Stream(1))
	h.assertState(1, StateClosed)

	if err := h.send(request(5, false)); err != nil {
		t.Fatalf("the next stream after a refused one reported %v", err)
	}
}

func TestARefusedStreamStillSpendsItsIdentifier(t *testing.T) {
	// §5.1.1's promise is about identifiers the peer has *used*, not about streams
	// that went on to succeed. A refusal is an answer to a request the peer sent, and
	// a peer that has one refused does not reuse the number — so every lower idle
	// identifier is closed from that point whatever became of the stream.
	//
	// A table that recorded the identifier only on the accepting path would leave a
	// window after every refusal in which the peer could open a lower stream, which
	// is the state §5.1.1 exists to make impossible.
	h := newHarness(t, Config{MaxConcurrent: 1})
	h.open(1, false)
	assertStreamError(t, h.send(request(5, false)), 5, h2.RefusedStream, "the refused stream")

	h.assertState(3, StateClosed)
	assertConnError(t, h.send(request(3, false)), h2.ProtocolError,
		"HEADERS below the identifier of a refused stream")
}

// --- the concurrency limit -------------------------------------------------

func TestTheConcurrencyLimitRefusesTheStreamPastTheMaximum(t *testing.T) {
	h := newHarness(t, Config{MaxConcurrent: 2})
	h.open(1, false)
	h.open(3, false)
	err := h.send(request(5, false))
	// REFUSED_STREAM rather than PROTOCOL_ERROR, of the two §5.1.2 permits,
	// because §8.7 makes REFUSED_STREAM the code that promises the request was not
	// processed — so a client may retry it even if it was not idempotent.
	assertStreamError(t, err, 5, h2.RefusedStream, "the third of two permitted streams")
}

func TestARefusedStreamDoesNotCountAgainstTheLimit(t *testing.T) {
	h := newHarness(t, Config{MaxConcurrent: 1})
	h.open(1, false)
	assertStreamError(t, h.send(request(3, false)), 3, h2.RefusedStream, "the refused stream")
	if got := h.tab.Len(); got != 1 {
		t.Fatalf("table holds %d streams after a refusal, want 1", got)
	}
	// A refused stream that had consumed a slot would make the limit ratchet down
	// to zero over the life of a connection.
	h.mustSend(frame.RSTStreamFrame{StreamID: 1, ErrCode: h2.Cancel})
	if err := h.send(request(5, false)); err != nil {
		t.Fatalf("a stream opened after the slot was freed reported %v", err)
	}
}

func TestAHalfClosedStreamStillCountsAgainstTheLimit(t *testing.T) {
	// §5.1.2: "Streams that are in the 'open' state or in either of the
	// 'half-closed' states count toward the maximum." A half-closed (remote)
	// stream is one this server still owes a response, so the slot is genuinely in
	// use however finished the request looks.
	h := newHarness(t, Config{MaxConcurrent: 1})
	h.open(1, true)
	h.assertState(1, StateHalfClosedRemote)
	assertStreamError(t, h.send(request(3, false)), 3, h2.RefusedStream, "a stream behind a half-closed one")

	h.tab.SendEnd(h.tab.Stream(1))
	if err := h.send(request(5, false)); err != nil {
		t.Fatalf("a stream opened after the half-closed one closed reported %v", err)
	}
}

func TestTheTableOnlyHoldsStreamsThatCountAsConcurrent(t *testing.T) {
	// The invariant the whole design leans on: a Stream exists only in the three
	// states §5.1.2 counts, so len(streams) is the concurrency answer by
	// construction and Stream.peerDone can compare against one state rather than
	// enumerate the rest. Checked after every kind of transition there is.
	h := newHarness(t, Config{})
	check := func(step string) {
		t.Helper()
		for id, s := range h.tab.streams {
			switch s.state {
			case StateOpen, StateHalfClosedRemote, StateHalfClosedLocal:
			default:
				t.Errorf("after %s: stream %d is in the table in state %s", step, id, s.state)
			}
			if s.id != id {
				t.Errorf("after %s: stream %d is filed under %d", step, s.id, id)
			}
		}
		if got := h.tab.Len(); got != len(h.tab.streams) {
			t.Errorf("after %s: Len is %d, map holds %d", step, got, len(h.tab.streams))
		}

		// And the second map of streams — the send windows in the Sender — holds
		// exactly the same identifiers, in both directions. Two maps updated from two
		// places in this file is the cost of keeping the state machine out from
		// behind the Sender's mutex, and this is what makes the cost visible: a send
		// window left behind by a stream that closed is credit a WINDOW_UPDATE could
		// still reach, and a stream in the table without one is a response that
		// blocks for ever the first time it tries to reserve an octet. 7 is in the
		// list and never opened, so a window invented for an identifier the peer
		// never used shows up here too.
		for _, id := range []uint32{1, 3, 5, 7} {
			_, hasWindow := h.tab.Sender().Available(id)
			_, live := h.tab.streams[id]
			if hasWindow != live {
				t.Errorf("after %s: stream %d is in the table (%v) but has a send window (%v)",
					step, id, live, hasWindow)
			}
		}
	}

	h.open(1, false)
	check("HEADERS opened a stream")
	h.open(3, true)
	check("HEADERS with END_STREAM")
	h.open(5, false)
	check("a third stream")
	h.mustSend(frame.RSTStreamFrame{StreamID: 5, ErrCode: h2.Cancel})
	check("RST_STREAM")
	h.tab.SendEnd(h.tab.Stream(1))
	check("our own END_STREAM")
	h.mustSend(data(1, "done", true))
	check("the peer's END_STREAM on a half-closed (local) stream")
	h.tab.SendEnd(h.tab.Stream(3))
	check("our END_STREAM on a half-closed (remote) stream")

	if got := h.tab.Len(); got != 0 {
		t.Errorf("table holds %d streams after all of them closed, want 0", got)
	}
}

// --- trailers --------------------------------------------------------------

func TestTrailersEndTheStreamAndCarryTheirOwnFields(t *testing.T) {
	h := newHarness(t, Config{})
	h.open(1, false)
	h.mustSend(data(1, "body", false))
	h.mustSend(frame.HeadersFrame{
		StreamID: 1, EndStream: true, EndHeaders: true,
		Fragment: encodeFields(h2.Field{Name: "grpc-status", Value: "0"}),
	})
	h.assertEvents("[headers(1, [{:method GET false} {:path /1 false}], end=false, state=open) " +
		"data(1, \"body\", end=false, state=open) " +
		"trailers(1, [{grpc-status 0 false}], end=true, state=half-closed (remote))]")
	h.assertState(1, StateHalfClosedRemote)
}

func TestTrailersWithoutEndStreamAreAStreamError(t *testing.T) {
	h := newHarness(t, Config{})
	h.open(1, false)
	err := h.send(frame.HeadersFrame{
		StreamID: 1, EndHeaders: true,
		Fragment: encodeFields(h2.Field{Name: "x", Value: "y"}),
	})
	// §8.1: the trailer section is the last thing on a stream. Without END_STREAM
	// this is a third header block waiting to happen, and HTTP/2 has no such thing.
	assertStreamError(t, err, 1, h2.ProtocolError, "trailers without END_STREAM")
	// Decoded all the same, for the reason in ARefusedStreamsBlockIsStillDecoded.
	if len(h.codec.decoded) != 2 {
		t.Errorf("codec saw %d blocks %q, want the request's and the trailers'", len(h.codec.decoded), h.codec.blocks())
	}
}

func TestTrailersOnAHalfClosedStreamAreAStreamError(t *testing.T) {
	h := newHarness(t, Config{})
	h.open(1, true)
	h.assertState(1, StateHalfClosedRemote)
	err := h.send(frame.HeadersFrame{
		StreamID: 1, EndStream: true, EndHeaders: true,
		Fragment: encodeFields(h2.Field{Name: "x", Value: "y"}),
	})
	// §5.1's half-closed (remote): anything but WINDOW_UPDATE, PRIORITY or
	// RST_STREAM is a stream error of type STREAM_CLOSED.
	assertStreamError(t, err, 1, h2.StreamClosed, "a third header block after END_STREAM")
}

func TestTrailersOnAHalfClosedStreamAreClosedRatherThanMalformed(t *testing.T) {
	// A frame that breaks both rules at once: a trailer section on a stream the peer
	// has already finished, and without END_STREAM. Only one verdict can be returned
	// and the state is the one to report, because §5.1 answers the frame's arrival
	// while §8.1 answers its contents — a frame that was not allowed to arrive has no
	// contents worth complaining about, and STREAM_CLOSED is also the code that tells
	// the peer what it actually did wrong.
	h := newHarness(t, Config{})
	h.open(1, true)
	err := h.send(frame.HeadersFrame{
		StreamID: 1, EndHeaders: true,
		Fragment: encodeFields(h2.Field{Name: "x", Value: "y"}),
	})
	assertStreamError(t, err, 1, h2.StreamClosed, "trailers without END_STREAM on a finished stream")
}

func TestTrailersSplitAcrossContinuationsAreDecodedAsOne(t *testing.T) {
	// The trailer path has its own call into the assembler, so a block split across
	// CONTINUATION frames has to be reassembled there too. A path that completed the
	// block on the HEADERS frame would deliver a trailer section that is missing every
	// field after the first fragment, and the CONTINUATION frames that followed would
	// then be reported as arriving with no block open.
	h := newHarness(t, Config{})
	h.open(1, false)
	block := encodeFields(
		h2.Field{Name: "grpc-status", Value: "0"},
		h2.Field{Name: "grpc-message", Value: "ok"},
	)
	h.mustSend(frame.HeadersFrame{StreamID: 1, EndStream: true, Fragment: block[:4]})
	h.mustSend(frame.ContinuationFrame{StreamID: 1, Fragment: block[4:20]})
	h.mustSend(frame.ContinuationFrame{StreamID: 1, EndHeaders: true, Fragment: block[20:]})

	h.assertBlocks(string(request(1, false).Fragment), string(block))
	h.assertEvents("[headers(1, [{:method GET false} {:path /1 false}], end=false, state=open) " +
		"trailers(1, [{grpc-status 0 false} {grpc-message ok false}], end=true, state=half-closed (remote))]")
	h.assertState(1, StateHalfClosedRemote)
}

func TestTrailersCloseAStreamWeHadAlreadyFinished(t *testing.T) {
	h := newHarness(t, Config{})
	h.open(1, false)
	h.tab.SendEnd(h.tab.Stream(1))
	h.assertState(1, StateHalfClosedLocal)
	h.mustSend(frame.HeadersFrame{
		StreamID: 1, EndStream: true, EndHeaders: true,
		Fragment: encodeFields(h2.Field{Name: "x", Value: "y"}),
	})
	h.assertState(1, StateClosed)
	if got := h.tab.Len(); got != 0 {
		t.Errorf("table holds %d streams, want 0", got)
	}
}

// --- DATA ------------------------------------------------------------------

func TestDataIsDeliveredWithoutItsPadding(t *testing.T) {
	h := newHarness(t, Config{})
	h.open(1, false)
	h.mustSend(frame.DataFrame{StreamID: 1, Data: []byte("body"), Padded: true, PadLen: 9})
	h.assertEvents("[headers(1, [{:method GET false} {:path /1 false}], end=false, state=open) " +
		"data(1, \"body\", end=false, state=open)]")
}

func TestPaddedDataIsFlowControlledByItsWholeLength(t *testing.T) {
	// §6.1 counts the padding and the Pad Length octet against both windows. A
	// receiver that counted only the body would drift from the peer's accounting
	// by the padding on every frame, and the drift is silent until a transfer
	// stalls at a size nobody can explain.
	h := newHarness(t, Config{})
	h.open(1, false)
	before := h.tab.RecvWindow().Available()
	h.mustSend(frame.DataFrame{StreamID: 1, Data: []byte("body"), Padded: true, PadLen: 9})

	const want = 4 + 9 + 1 // body, padding, the Pad Length octet
	if got := before - h.tab.RecvWindow().Available(); got != want {
		t.Errorf("padded DATA debited %d octets from the connection window, want %d", got, want)
	}
	if got := flow.InitialWindowSize - h.tab.Stream(1).RecvWindow().Available(); got != want {
		t.Errorf("padded DATA debited %d octets from the stream window, want %d", got, want)
	}
}

func TestDataOnAnIdleStreamEndsTheConnection(t *testing.T) {
	h := newHarness(t, Config{})
	err := h.send(data(1, "body", false))
	// §5.1's idle state: "Receiving any frame other than HEADERS or PRIORITY on a
	// stream in this state MUST be treated as a connection error of type
	// PROTOCOL_ERROR."
	assertConnError(t, err, h2.ProtocolError, "DATA on an idle stream")
}

func TestDataOnAClosedStreamResetsTheStreamAndKeepsTheConnection(t *testing.T) {
	h := newHarness(t, Config{})
	h.open(1, false)
	h.mustSend(frame.RSTStreamFrame{StreamID: 1, ErrCode: h2.Cancel})
	err := h.send(data(1, "body", false))
	// §5.1 permits a connection error here and this server answers with a stream
	// error, because it cannot tell a stream it reset a moment ago from one that
	// finished: the peer's DATA was already on the wire when the reset went out.
	// Ending the connection over that is ending it over a race we started.
	assertStreamError(t, err, 1, h2.StreamClosed, "DATA on a closed stream")
}

func TestDataOnAHalfClosedStreamIsAStreamError(t *testing.T) {
	h := newHarness(t, Config{})
	h.open(1, true)
	err := h.send(data(1, "more", false))
	assertStreamError(t, err, 1, h2.StreamClosed, "DATA after the peer's END_STREAM")
}

func TestDataOnAStreamWeHaveFinishedIsStillAccepted(t *testing.T) {
	// half-closed (local) is our end being done, not the peer's. A request body
	// still arriving after we have answered is normal — a client uploading while
	// the server has already sent a 4xx — and §5.1 keeps the stream receiving.
	h := newHarness(t, Config{})
	h.open(1, false)
	h.tab.SendEnd(h.tab.Stream(1))
	h.mustSend(data(1, "still coming", false))
	h.assertState(1, StateHalfClosedLocal)
}

func TestDataOnAClosedStreamIsStillCountedAgainstTheConnectionWindow(t *testing.T) {
	// §6.9.1: "A receiver that receives a flow-controlled frame MUST always
	// account for its contribution against the connection flow-control window,
	// unless the receiver treats this as a connection error." This is the one that
	// is invisible when it is wrong: the frame is refused either way, and the only
	// difference is whether the two ends still agree about the connection's credit
	// afterwards. They do not, permanently, if the octets are dropped uncounted.
	h := newHarness(t, Config{})
	h.open(1, false)
	h.mustSend(frame.RSTStreamFrame{StreamID: 1, ErrCode: h2.Cancel})

	before := h.tab.RecvWindow().Available()
	err := h.send(filler(1, 500, false))
	assertStreamError(t, err, 1, h2.StreamClosed, "DATA on a closed stream")
	if got := before - h.tab.RecvWindow().Available(); got != 500 {
		t.Errorf("DATA refused on a closed stream debited %d octets from the connection window, want 500", got)
	}
}

func TestDataAfterEndStreamIsStillCountedAgainstTheConnectionWindow(t *testing.T) {
	// The third of §6.9.1's refusals, and the one whose ordering is easiest to get
	// wrong: the state check sits between the two windows, so a connection debit
	// placed after it would skip exactly the frames a peer sends after END_STREAM.
	// Those are the frames a broken or hostile client sends most of.
	h := newHarness(t, Config{})
	h.open(1, true)

	before := h.tab.RecvWindow().Available()
	err := h.send(filler(1, 700, false))
	assertStreamError(t, err, 1, h2.StreamClosed, "DATA after the peer's END_STREAM")
	if got := before - h.tab.RecvWindow().Available(); got != 700 {
		t.Errorf("DATA refused after END_STREAM debited %d octets from the connection window, want 700", got)
	}
}

func TestDataRefusedByAStreamWindowIsStillCountedAgainstTheConnectionWindow(t *testing.T) {
	// The same rule for the other refusal. §6.9.1 does not require the stream
	// window to be debited for a frame that overran it — a stream about to be
	// reset has no further use for one — but the connection window must be.
	h := newHarness(t, Config{})
	h.open(1, false)
	if err := h.tab.RecvWindow().Increase(50_000); err != nil {
		t.Fatalf("crediting the connection window: %v", err)
	}
	for i := 0; i < 3; i++ {
		h.mustSend(filler(1, 16_384, false))
	}
	before := h.tab.RecvWindow().Available()
	err := h.send(filler(1, 16_384, false))
	assertStreamError(t, err, 1, h2.FlowControlError, "DATA past the stream window")
	if got := before - h.tab.RecvWindow().Available(); got != 16_384 {
		t.Errorf("DATA refused by the stream window debited %d octets from the connection window, want 16384", got)
	}
	// The stream window is left as it was, with the octets it could not pay for
	// still owed rather than half spent.
	if got := h.tab.Stream(1).RecvWindow().Available(); got != flow.InitialWindowSize-3*16_384 {
		t.Errorf("the stream window moved to %d on a refused frame, want %d", got, flow.InitialWindowSize-3*16_384)
	}
}

func TestDataPastTheConnectionWindowEndsTheConnection(t *testing.T) {
	h := newHarness(t, Config{})
	h.open(1, false)
	for i := 0; i < 3; i++ {
		h.mustSend(filler(1, 16_384, false))
	}
	// 65535 granted, 49152 spent, so 16384 is one octet too many.
	err := h.send(filler(1, 16_384, false))
	assertConnError(t, err, h2.FlowControlError, "DATA past the connection window")
}

func TestAnEmptyDataFrameWithEndStreamClosesAnExhaustedStream(t *testing.T) {
	// §6.9.1's exemption, end to end: "Frames with zero length with the END_STREAM
	// flag set (that is, an empty DATA frame) MAY be sent if there is no available
	// space in either flow-control window." A server that refused this would park a
	// finished stream behind a WINDOW_UPDATE nobody has a reason to send, and the
	// stream would stay open until the idle timeout.
	h := newHarness(t, Config{})
	h.open(1, false)
	// Spend the stream's whole receive window, and the connection's with it.
	h.mustSend(filler(1, flow.InitialWindowSize, false))
	if got := h.tab.Stream(1).RecvWindow().Available(); got != 0 {
		t.Fatalf("the stream window has %d octets left, want 0", got)
	}
	if got := h.tab.RecvWindow().Available(); got != 0 {
		t.Fatalf("the connection window has %d octets left, want 0", got)
	}

	h.mustSend(data(1, "", true))
	h.assertState(1, StateHalfClosedRemote)
}

func TestDataWithEndStreamClosesAStreamWeHadFinished(t *testing.T) {
	h := newHarness(t, Config{})
	h.open(1, false)
	h.tab.SendEnd(h.tab.Stream(1))
	h.mustSend(data(1, "last", true))
	h.assertState(1, StateClosed)
	if got := h.tab.Len(); got != 0 {
		t.Errorf("table holds %d streams, want 0", got)
	}
	// The last DATA frame is still delivered, and delivered with the state it
	// produced: a handler that watches for the end of the body sees closed.
	h.assertEvents("[headers(1, [{:method GET false} {:path /1 false}], end=false, state=open) " +
		"data(1, \"last\", end=true, state=closed)]")
}

// --- RST_STREAM ------------------------------------------------------------

func TestRstStreamClosesTheStreamAndTellsTheHandler(t *testing.T) {
	h := newHarness(t, Config{})
	h.open(1, false)
	h.mustSend(frame.RSTStreamFrame{StreamID: 1, ErrCode: h2.Cancel})
	h.assertState(1, StateClosed)
	h.assertEvents("[headers(1, [{:method GET false} {:path /1 false}], end=false, state=open) " +
		"canceled(1, CANCEL)]")
}

func TestRstStreamOnAnIdleStreamEndsTheConnection(t *testing.T) {
	// §6.4 in as many words, and frame-layer matrix row 13, which internal/frame
	// defers here because deciding it needs the stream table.
	h := newHarness(t, Config{})
	err := h.send(frame.RSTStreamFrame{StreamID: 1, ErrCode: h2.Cancel})
	assertConnError(t, err, h2.ProtocolError, "RST_STREAM on an idle stream")
}

func TestRstStreamOnASkippedIdentifierIsIgnored(t *testing.T) {
	// Stream 1 is closed rather than idle once stream 5 has been used (§5.1.1), so
	// this is the closed case and not the idle one.
	h := newHarness(t, Config{})
	h.open(5, false)
	h.mustSend(frame.RSTStreamFrame{StreamID: 1, ErrCode: h2.Cancel})
	h.assertEvents("[headers(5, [{:method GET false} {:path /5 false}], end=false, state=open)]")
}

func TestRstStreamOnAClosedStreamIsIgnored(t *testing.T) {
	// §5.1 anticipates this rather than punishing it: we may have reset the stream
	// ourselves a moment ago, and §6.4 tells the sender of a RST_STREAM to be
	// ready for more frames on it for the same reason in the other direction.
	h := newHarness(t, Config{})
	h.open(1, false)
	h.mustSend(frame.RSTStreamFrame{StreamID: 1, ErrCode: h2.Cancel})
	h.mustSend(frame.RSTStreamFrame{StreamID: 1, ErrCode: h2.Cancel})
	// The handler is told once, not twice: the second frame names a stream that no
	// longer exists to cancel.
	h.assertEvents("[headers(1, [{:method GET false} {:path /1 false}], end=false, state=open) " +
		"canceled(1, CANCEL)]")
}

func TestARstStreamFloodEndsTheConnection(t *testing.T) {
	// CVE-2023-44487. A stream reset immediately after its HEADERS frees the
	// concurrency slot at once, so SETTINGS_MAX_CONCURRENT_STREAMS bounds how many
	// requests are in flight and nothing bounds how many arrive per second.
	h := newHarness(t, Config{})
	burst := int(limits.ResetBurst)

	var id uint32 = 1
	for i := 0; i < burst; i++ {
		h.open(id, false)
		h.mustSend(frame.RSTStreamFrame{StreamID: id, ErrCode: h2.Cancel})
		id += 2
	}
	h.open(id, false)
	err := h.send(frame.RSTStreamFrame{StreamID: id, ErrCode: h2.Cancel})
	assertConnError(t, err, h2.EnhanceYourCalm, "one reset past the burst")
}

func TestTheResetBucketRefillsOverTime(t *testing.T) {
	h := newHarness(t, Config{})
	var id uint32 = 1
	for i := 0; i < int(limits.ResetBurst); i++ {
		h.open(id, false)
		h.mustSend(frame.RSTStreamFrame{StreamID: id, ErrCode: h2.Cancel})
		id += 2
	}
	h.open(id, false)
	assertConnError(t, h.send(frame.RSTStreamFrame{StreamID: id, ErrCode: h2.Cancel}),
		h2.EnhanceYourCalm, "the exhausted bucket")

	// A browser cancelling a page of subresources gets its burst back at
	// limits.ResetRefillPerSecond, so one second buys that many resets.
	h.clock.advance(time.Second)
	if err := h.send(frame.RSTStreamFrame{StreamID: id, ErrCode: h2.Cancel}); err != nil {
		t.Fatalf("a reset one second after the burst was refused: %v", err)
	}
}

func TestRstStreamOnAnIdleStreamIsReportedAheadOfTheRateLimit(t *testing.T) {
	// Ordering, and it is a real choice: one malformed frame should be reported as
	// the protocol violation it is rather than as a flood. Checking the map is O(1)
	// so there is no work-bounding argument for the other order.
	h := newHarness(t, Config{})
	var id uint32 = 1
	for i := 0; i < int(limits.ResetBurst); i++ {
		h.open(id, false)
		h.mustSend(frame.RSTStreamFrame{StreamID: id, ErrCode: h2.Cancel})
		id += 2
	}
	// The bucket is empty and stream id+2 has never been used.
	err := h.send(frame.RSTStreamFrame{StreamID: id, ErrCode: h2.Cancel})
	assertConnError(t, err, h2.ProtocolError, "RST_STREAM on an idle stream with the bucket empty")
}

func TestARstStreamOfAClosedStreamStillCostsAToken(t *testing.T) {
	// A limiter with a free case is a limiter with a way around it: a peer that
	// could reset an already-closed stream for nothing would have an unbounded
	// frame-processing cost with no bucket in the way.
	h := newHarness(t, Config{})
	h.open(1, false)
	for i := 0; i < int(limits.ResetBurst); i++ {
		if err := h.send(frame.RSTStreamFrame{StreamID: 1, ErrCode: h2.Cancel}); err != nil {
			t.Fatalf("reset %d of a closed stream: %v", i, err)
		}
	}
	err := h.send(frame.RSTStreamFrame{StreamID: 1, ErrCode: h2.Cancel})
	assertConnError(t, err, h2.EnhanceYourCalm, "one reset past the burst, all on a closed stream")
}

// --- WINDOW_UPDATE ---------------------------------------------------------

func TestWindowUpdateCreditsTheStreamsSendWindow(t *testing.T) {
	h := newHarness(t, Config{})
	h.open(1, false)
	h.mustSend(frame.WindowUpdateFrame{StreamID: 1, Increment: 1000})
	if got := h.sendAvailable(1); got != flow.InitialWindowSize+1000 {
		t.Errorf("stream send window is %d, want %d", got, flow.InitialWindowSize+1000)
	}
	// The receive window is ours to grant and is not touched by the peer's credit.
	if got := h.tab.Stream(1).RecvWindow().Available(); got != flow.InitialWindowSize {
		t.Errorf("stream receive window is %d, want %d", got, flow.InitialWindowSize)
	}
}

func TestWindowUpdateOnAnIdleStreamEndsTheConnection(t *testing.T) {
	h := newHarness(t, Config{})
	err := h.send(frame.WindowUpdateFrame{StreamID: 1, Increment: 1})
	// §6.9's exemption is for a stream that has been used and is over, not for one
	// that has never existed; §5.1's idle state admits only HEADERS and PRIORITY.
	assertConnError(t, err, h2.ProtocolError, "WINDOW_UPDATE on an idle stream")
}

func TestWindowUpdateOnAClosedStreamIsIgnored(t *testing.T) {
	// §6.9 exempts this by name: the peer sent it before it knew the stream was
	// over, and "a receiver MUST NOT treat this as an error".
	h := newHarness(t, Config{})
	h.open(1, false)
	h.mustSend(frame.RSTStreamFrame{StreamID: 1, ErrCode: h2.Cancel})
	h.mustSend(frame.WindowUpdateFrame{StreamID: 1, Increment: 1000})
}

func TestWindowUpdateOnAHalfClosedStreamIsApplied(t *testing.T) {
	// Also §6.9's, and a different case: the stream is still ours to send on, so
	// the credit is real rather than merely tolerated.
	h := newHarness(t, Config{})
	h.open(1, true)
	h.mustSend(frame.WindowUpdateFrame{StreamID: 1, Increment: 7})
	if got := h.sendAvailable(1); got != flow.InitialWindowSize+7 {
		t.Errorf("stream send window is %d, want %d", got, flow.InitialWindowSize+7)
	}
}

func TestWindowUpdateOverflowingAStreamWindowIsAStreamError(t *testing.T) {
	h := newHarness(t, Config{})
	h.open(1, false)
	err := h.send(frame.WindowUpdateFrame{StreamID: 1, Increment: flow.MaxWindowSize})
	// Matrix row 31, deferred from internal/frame because the rule needs the
	// window's current value and the frame carries only the increment.
	assertStreamError(t, err, 1, h2.FlowControlError, "WINDOW_UPDATE past the maximum window")
}

func TestConnWindowUpdateCreditsTheConnectionSendWindow(t *testing.T) {
	h := newHarness(t, Config{})
	if err := h.tab.ConnWindowUpdate(1000); err != nil {
		t.Fatalf("crediting the connection window: %v", err)
	}
	if got := h.tab.Sender().ConnAvailable(); got != flow.InitialWindowSize+1000 {
		t.Errorf("connection send window is %d, want %d", got, flow.InitialWindowSize+1000)
	}
	if got := h.tab.RecvWindow().Available(); got != flow.InitialWindowSize {
		t.Errorf("the peer's credit moved our receive window to %d", got)
	}
}

func TestConnWindowUpdateOverflowEndsTheConnection(t *testing.T) {
	h := newHarness(t, Config{})
	err := h.tab.ConnWindowUpdate(flow.MaxWindowSize)
	// Matrix row 30. The scope comes from the window knowing it is the
	// connection's, not from anything this layer decides.
	assertConnError(t, err, h2.FlowControlError, "a connection WINDOW_UPDATE past the maximum")
}

// --- PRIORITY --------------------------------------------------------------

func TestPriorityIsAcceptedAndChangesNothing(t *testing.T) {
	h := newHarness(t, Config{})
	h.open(1, false)
	h.mustSend(frame.PriorityFrame{StreamID: 1, StreamDependency: 3, Weight: 15})
	h.assertState(1, StateOpen)
	h.assertEvents("[headers(1, [{:method GET false} {:path /1 false}], end=false, state=open)]")
}

func TestPriorityOnAnIdleStreamDoesNotUseUpTheIdentifier(t *testing.T) {
	// The subtle one. §5.1 keeps PRIORITY legal "in any stream state" and does not
	// make it open a stream, so a PRIORITY frame on an idle stream leaves it idle.
	// A table that recorded the identifier as used would refuse the HEADERS frame
	// that arrives next under §5.1.1 — and browsers do send PRIORITY ahead of
	// HEADERS.
	h := newHarness(t, Config{})
	h.mustSend(frame.PriorityFrame{StreamID: 5, StreamDependency: 0, Weight: 200})
	h.assertState(5, StateIdle)
	if err := h.send(request(5, false)); err != nil {
		t.Fatalf("HEADERS after a PRIORITY frame on the same stream: %v", err)
	}
	h.assertState(5, StateOpen)
}

func TestPriorityOnAClosedStreamIsAccepted(t *testing.T) {
	h := newHarness(t, Config{})
	h.open(1, false)
	h.mustSend(frame.RSTStreamFrame{StreamID: 1, ErrCode: h2.Cancel})
	h.mustSend(frame.PriorityFrame{StreamID: 1, StreamDependency: 0, Weight: 1})
}

// --- SETTINGS_INITIAL_WINDOW_SIZE ------------------------------------------

func TestSetInitialWindowSizeSizesStreamsOpenedAfterwards(t *testing.T) {
	h := newHarness(t, Config{})
	if err := h.tab.SetInitialWindowSize(1000); err != nil {
		t.Fatalf("SetInitialWindowSize: %v", err)
	}
	h.open(1, false)
	if got := h.sendAvailable(1); got != 1000 {
		t.Errorf("a stream opened after the setting has a send window of %d, want 1000", got)
	}
	// Our own grant is unaffected: the setting is the peer's, about the direction
	// it sends in.
	if got := h.tab.Stream(1).RecvWindow().Available(); got != flow.InitialWindowSize {
		t.Errorf("the peer's setting moved our receive window to %d", got)
	}
}

func TestSetInitialWindowSizeAppliesADeltaToOpenStreams(t *testing.T) {
	// §6.9.2 makes the change a delta and not an assignment, and this is the test
	// that tells the two apart: a stream that had spent 1000 octets must end up
	// 1000 short of the new size, not at it.
	h := newHarness(t, Config{})
	h.open(1, false)
	h.spendSend(1, 1000)
	if err := h.tab.SetInitialWindowSize(70_000); err != nil {
		t.Fatalf("SetInitialWindowSize: %v", err)
	}
	const want = flow.InitialWindowSize - 1000 + (70_000 - flow.InitialWindowSize)
	if got := h.sendAvailable(1); got != want {
		t.Errorf("send window is %d, want %d (an assignment would give 70000)", got, want)
	}
}

func TestSetInitialWindowSizeCanTakeAStreamWindowNegative(t *testing.T) {
	// Legal and required: a peer that lowers the initial size below what a stream
	// has already spent has taken back credit that was used, and the deficit has
	// to be carried. Clamping to zero would let the stream send that much again.
	h := newHarness(t, Config{})
	h.open(1, false)
	h.spendSend(1, 1000)
	if err := h.tab.SetInitialWindowSize(0); err != nil {
		t.Fatalf("SetInitialWindowSize: %v", err)
	}
	if got := h.sendAvailable(1); got != -1000 {
		t.Errorf("send window is %d, want -1000", got)
	}
}

func TestSetInitialWindowSizeAppliesToEveryOpenStream(t *testing.T) {
	h := newHarness(t, Config{})
	h.open(1, false)
	h.open(3, true)
	h.tab.SendEnd(h.tab.Stream(1))
	if err := h.tab.SetInitialWindowSize(100); err != nil {
		t.Fatalf("SetInitialWindowSize: %v", err)
	}
	// Every state the table holds, including the half-closed ones: this server may
	// still be sending on any of them.
	for _, id := range []uint32{1, 3} {
		if got := h.sendAvailable(id); got != 100 {
			t.Errorf("stream %d's send window is %d, want 100", id, got)
		}
	}
}

func TestSetInitialWindowSizeOverflowEndsTheConnection(t *testing.T) {
	h := newHarness(t, Config{})
	h.open(1, false)
	if err := h.tab.Sender().CreditStream(1, flow.MaxWindowSize-flow.InitialWindowSize); err != nil {
		t.Fatalf("crediting to the maximum: %v", err)
	}
	err := h.tab.SetInitialWindowSize(flow.InitialWindowSize + 1)
	// Connection-scoped even though one stream's window overflowed, because the
	// fault is in a SETTINGS frame: it is the connection's, and one frame can push
	// any number of streams over at once.
	assertConnError(t, err, h2.FlowControlError, "a setting that overflows a stream window")
}

func TestSetInitialWindowSizeLeavesTheConnectionWindowAlone(t *testing.T) {
	// §6.9.2 confines the setting to stream windows and makes WINDOW_UPDATE the
	// only way to change the connection's. A server that applied it to both would
	// desynchronise the connection's credit by the delta with nothing to put it
	// right, and internal/flow refuses the call outright for that reason — so this
	// also pins that the refusal is never provoked.
	h := newHarness(t, Config{})
	if err := h.tab.SetInitialWindowSize(1); err != nil {
		t.Fatalf("SetInitialWindowSize: %v", err)
	}
	if got := h.tab.Sender().ConnAvailable(); got != flow.InitialWindowSize {
		t.Errorf("connection send window is %d, want %d", got, flow.InitialWindowSize)
	}
	if got := h.tab.RecvWindow().Available(); got != flow.InitialWindowSize {
		t.Errorf("connection receive window is %d, want %d", got, flow.InitialWindowSize)
	}
}

func TestSetInitialWindowSizeWithNoStreamsOpenIsRemembered(t *testing.T) {
	// The value has to survive an empty table, because a peer sends its SETTINGS
	// before its first request and that is the only order the preface allows.
	h := newHarness(t, Config{})
	if err := h.tab.SetInitialWindowSize(3); err != nil {
		t.Fatalf("SetInitialWindowSize: %v", err)
	}
	if err := h.tab.SetInitialWindowSize(9); err != nil {
		t.Fatalf("SetInitialWindowSize: %v", err)
	}
	h.open(1, false)
	// 9, not 12 and not 6: the second call replaced the first rather than
	// compounding with it, which is what a delta applied to a nonexistent stream
	// would have done.
	if got := h.sendAvailable(1); got != 9 {
		t.Errorf("send window is %d, want 9", got)
	}
}

// --- the send half, and the seam to it -------------------------------------

func TestTheSenderIsTakenFromConfigWhenOneIsGiven(t *testing.T) {
	// The connection has to be able to reach Sender.Close during teardown, from
	// whichever goroutine noticed the connection was over, and the table is not safe
	// to touch from there. So the Sender is constructed outside and handed in, and
	// this is the test that the table uses the one it was given rather than quietly
	// making its own — which would leave the connection closing a Sender no writer
	// was parked on, and every writer parked on one nothing would ever close.
	sender := flow.NewSender()
	h := newHarness(t, Config{Sender: sender})
	if h.tab.Sender() != sender {
		t.Fatalf("the table is using a Sender other than the one Config named")
	}

	h.open(1, false)
	if _, ok := sender.Available(1); !ok {
		t.Errorf("opening a stream did not give it a send window in the Sender from Config")
	}
	if err := h.tab.ConnWindowUpdate(100); err != nil {
		t.Fatalf("ConnWindowUpdate: %v", err)
	}
	if got := sender.ConnAvailable(); got != flow.InitialWindowSize+100 {
		t.Errorf("the connection window in Config's Sender is %d, want %d",
			got, flow.InitialWindowSize+100)
	}
}

func TestTheTableMakesItsOwnSenderWhenConfigHasNone(t *testing.T) {
	// Nil is the ordinary case for a test and for any caller that has no teardown to
	// wire up, and it must not be a nil dereference on the first request.
	h := newHarness(t, Config{})
	if h.tab.Sender() == nil {
		t.Fatal("Sender is nil, so the first response body on this connection would panic")
	}
	h.open(1, false)
	if got := h.sendAvailable(1); got != flow.InitialWindowSize {
		t.Errorf("stream send window is %d, want %d", got, flow.InitialWindowSize)
	}
}

func TestARefusedStreamNeverGetsASendWindow(t *testing.T) {
	// A stream that never entered the table must not have entered the Sender either.
	// The two maps are updated from two places, so the refusal paths are where they
	// would drift: a window opened for a stream the table refused is credit that
	// outlives the connection's own accounting of it, and Sender.Open panics on a
	// repeat, so the identifier could not even be reused.
	h := newHarness(t, Config{MaxConcurrent: 1})
	h.open(1, false)
	err := h.send(request(3, false))
	assertStreamError(t, err, 3, h2.RefusedStream, "the stream past the concurrency limit")

	if _, ok := h.tab.Sender().Available(3); ok {
		t.Errorf("the refused stream 3 has a send window")
	}
	// And the identifier is spent, so nothing will open one later either.
	h.assertState(3, StateClosed)
}

func TestClosingAStreamTakesAwayItsSendWindow(t *testing.T) {
	// Every route to closed, because retire is called from four places — SendEnd, the
	// trailers branch of completeBlock, data and rstStream — and a missing call in
	// one of them is a leak the peer controls: a connection serving a million
	// requests would hold a million send windows, which is the same shape of
	// footprint the table itself refuses to have.
	//
	// Three of the four need our own END_STREAM as well as the peer's, because that
	// is what closed means. Which of the two arrives last decides which site does the
	// retiring, so both orders are here rather than one standing in for the other.
	for _, tc := range []struct {
		name  string
		close func(h *harness)
	}{
		{"RST_STREAM from the peer", func(h *harness) {
			h.mustSend(frame.RSTStreamFrame{StreamID: 1, ErrCode: h2.Cancel})
		}},
		{"the peer's END_STREAM last", func(h *harness) {
			h.tab.SendEnd(h.tab.Stream(1))
			h.mustSend(data(1, "body", true))
		}},
		{"our END_STREAM last", func(h *harness) {
			h.mustSend(data(1, "body", true))
			h.tab.SendEnd(h.tab.Stream(1))
		}},
		{"a trailer section last", func(h *harness) {
			h.tab.SendEnd(h.tab.Stream(1))
			h.mustSend(frame.HeadersFrame{
				StreamID: 1, EndStream: true, EndHeaders: true,
				Fragment: encodeFields(h2.Field{Name: "grpc-status", Value: "0"}),
			})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, Config{})
			h.open(1, false)
			if _, ok := h.tab.Sender().Available(1); !ok {
				t.Fatalf("stream 1 has no send window to lose")
			}
			tc.close(h)
			h.assertState(1, StateClosed)
			if _, ok := h.tab.Sender().Available(1); ok {
				t.Errorf("stream 1 kept its send window after closing")
			}
		})
	}
}

func TestAHalfClosedStreamKeepsItsSendWindow(t *testing.T) {
	// The other half of the rule above, and the one that matters more: this server
	// still owes a response on a stream the peer has finished sending on, so taking
	// the window away when the *peer* ends its half would strand the response that
	// is the whole point of the request.
	//
	// Both ways the peer can finish, because they retire from different places and
	// the trailers branch is the one where it is easy to write recvEnd and retire
	// next to each other without noticing that only one of them is conditional.
	for _, tc := range []struct {
		name string
		done func(h *harness)
	}{
		{"END_STREAM on the request", func(h *harness) {
			h.open(1, true)
		}},
		{"a trailer section", func(h *harness) {
			h.open(1, false)
			h.mustSend(frame.HeadersFrame{
				StreamID: 1, EndStream: true, EndHeaders: true,
				Fragment: encodeFields(h2.Field{Name: "grpc-status", Value: "0"}),
			})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, Config{})
			tc.done(h)
			h.assertState(1, StateHalfClosedRemote)
			if got := h.sendAvailable(1); got != flow.InitialWindowSize {
				t.Errorf("stream send window is %d, want %d", got, flow.InitialWindowSize)
			}
		})
	}
}

func TestResettingAStreamWakesTheGoroutineWritingItsResponse(t *testing.T) {
	// The reason the send windows are in the Sender rather than on the Stream, in one
	// test. A response body blocked for credit is parked in another goroutine
	// entirely, and the RST_STREAM that ends its stream is read here — so unless
	// retire reaches the Sender, that goroutine waits for a WINDOW_UPDATE the peer
	// has no reason ever to send, for the life of the process.
	h := newHarness(t, Config{})
	h.open(1, false)

	// Nothing left on the stream's window, so the next reservation has to park.
	h.spendSend(1, flow.InitialWindowSize)

	type result struct {
		n   int
		err error
	}
	out := make(chan result, 1)
	go func() {
		n, err := h.tab.Sender().Reserve(1, 1)
		out <- result{n, err}
	}()

	// Parked, rather than merely started: the RST_STREAM has to arrive while the
	// writer is asleep, because a writer that has not reached Reserve yet would find
	// the stream already gone and return for a different reason.
	deadline := time.Now().Add(5 * time.Second)
	for h.tab.Sender().Waiters() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the writer never parked in Reserve")
		}
		runtime.Gosched()
	}

	h.mustSend(frame.RSTStreamFrame{StreamID: 1, ErrCode: h2.Cancel})

	select {
	case got := <-out:
		if !errors.Is(got.err, flow.ErrStreamGone) {
			t.Errorf("the writer returned %d, %v; want flow.ErrStreamGone", got.n, got.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RST_STREAM did not wake the writer within 5s; it would wait for the life of the process")
	}
}

// --- dispatch and error propagation ---------------------------------------

func TestAConnectionFrameReachingTheTableIsAnInternalError(t *testing.T) {
	// Not reachable from internal/server, which answers SETTINGS, PING, GOAWAY,
	// PUSH_PROMISE and the stream-0 WINDOW_UPDATE itself. Named rather than
	// ignored, because the alternative is a frame type added to internal/frame and
	// forgotten here becoming a frame the server accepts and does nothing about.
	h := newHarness(t, Config{})
	err := h.send(frame.PingFrame{})
	assertConnError(t, err, h2.InternalError, "a PING frame reaching the stream table")
}

func TestAnErrorFromTheHandlerIsReturnedUnchanged(t *testing.T) {
	// The scope of an error from the layer above is the layer above's to choose:
	// internal/server reads its type, so wrapping it here would change a stream
	// error into a connection failure.
	h := newHarness(t, Config{})
	h.reqs.err = h2.StreamErrorf(1, h2.InternalError, "the handler said no")

	err := h.send(request(1, false))
	assertStreamError(t, err, 1, h2.InternalError, "an error from Requests.Headers")

	// An error that is not a protocol error at all, which internal/server treats as
	// a connection failure without a GOAWAY. Delivered from Data, because a
	// handler that fails on Headers never gets a stream to send DATA on.
	h.reqs.err = nil
	h.open(3, false)
	h.reqs.err = errors.New("something that is not a protocol error")
	err = h.send(data(3, "x", false))
	if err == nil {
		t.Fatal("an error from Requests.Data was swallowed")
	}
	var ce h2.ConnError
	var se h2.StreamError
	if errors.As(err, &ce) || errors.As(err, &se) {
		t.Errorf("Requests.Data's error came back as %v, which internal/server would read as a protocol fault", err)
	}
}

func TestAnErrorFromTheHandlerDoesNotUndoTheStateChange(t *testing.T) {
	// The state is the wire's, not the handler's. A stream the peer ended is ended
	// whatever the handler thinks of the request, and a table that rolled the
	// transition back would then accept DATA after END_STREAM.
	h := newHarness(t, Config{})
	h.open(1, false)
	h.reqs.err = h2.StreamErrorf(1, h2.InternalError, "no")
	if err := h.send(data(1, "x", true)); err == nil {
		t.Fatal("the handler's error was swallowed")
	}
	h.assertState(1, StateHalfClosedRemote)
	// Still in the table too, because the stream is not over — this server owes it
	// a response, even if that response is now a RST_STREAM.
	if got := h.tab.Len(); got != 1 {
		t.Errorf("table holds %d streams, want 1", got)
	}
}

func TestTheCodecIsDrivenOncePerBlockAndInArrivalOrder(t *testing.T) {
	// HPACK is stateful and order-dependent, so this is the property that makes
	// every other decode correct. Three streams, one of them refused, one block
	// split across CONTINUATION frames.
	h := newHarness(t, Config{MaxConcurrent: 2})
	first := encodeFields(h2.Field{Name: "a", Value: "1"})
	second := encodeFields(h2.Field{Name: "b", Value: "2"})
	third := encodeFields(h2.Field{Name: "c", Value: "3"})

	h.mustSend(frame.HeadersFrame{StreamID: 1, EndHeaders: true, Fragment: first})
	h.mustSend(frame.HeadersFrame{StreamID: 3, Fragment: second[:2]})
	h.mustSend(frame.ContinuationFrame{StreamID: 3, EndHeaders: true, Fragment: second[2:]})
	assertStreamError(t, h.send(frame.HeadersFrame{StreamID: 5, EndHeaders: true, Fragment: third}),
		5, h2.RefusedStream, "the third of two permitted streams")

	h.assertBlocks(string(first), string(second), string(third))
}

// --- what the errors say ---------------------------------------------------

// TestEveryErrorNamesTheRuleAndTheStream is about diagnosability, and it is here
// because an HTTP/2 fault is diagnosed from one line in a log by someone who has the
// RFC open and does not have the connection.
//
// Every error this package returns names the rule it enforces and the stream it is
// about. The section reference is the part that is easy to leave out and impossible
// to reconstruct: "PROTOCOL_ERROR on stream 5" tells a reader which frame was
// refused and nothing about why, and the peer's author cannot tell from it whether
// the fault is theirs. The alternative to a test like this is a set of messages that
// each looked complete when it was written.
func TestEveryErrorNamesTheRuleAndTheStream(t *testing.T) {
	// Each case provokes one error and names the section its message must cite,
	// along with the stream the message has to name. The identifier at fault is 5
	// wherever the case can choose it, and the other cases each say why theirs
	// differs, so a message naming the wrong one — the highest seen, say, instead of
	// the one at fault — is caught rather than merely being a number that happens to
	// be present.
	for _, tc := range []struct {
		what    string
		section string
		stream  string
		provoke func(*harness) error
	}{
		// Stream 6, because the fault is that the identifier is even and 5 is not.
		{"HEADERS on an even stream", "§5.1.1", "stream 6", func(h *harness) error {
			return h.send(request(6, false))
		}},
		{"HEADERS on a used identifier", "§5.1.1", "stream 5", func(h *harness) error {
			h.open(7, false)
			return h.send(request(5, false))
		}},
		{"HEADERS while a block is open", "§6.10", "stream 5", func(h *harness) error {
			h.mustSend(frame.HeadersFrame{StreamID: 5, Fragment: encodeFields(h2.Field{Name: "a", Value: "b"})})
			return h.send(request(7, false))
		}},
		{"a self-dependent stream", "§5.3.1", "stream 5", func(h *harness) error {
			f := request(5, false)
			f.Priority, f.StreamDependency = true, 5
			return h.send(f)
		}},
		{"a stream past the concurrency limit", "§5.1.2", "stream 5", func(h *harness) error {
			h.tab.maxConcurrent = 0
			return h.send(request(5, false))
		}},
		{"trailers on a half-closed stream", "§5.1", "stream 5", func(h *harness) error {
			h.open(5, true)
			return h.send(frame.HeadersFrame{StreamID: 5, EndStream: true, EndHeaders: true})
		}},
		{"trailers without END_STREAM", "§8.1", "stream 5", func(h *harness) error {
			h.open(5, false)
			return h.send(frame.HeadersFrame{StreamID: 5, EndHeaders: true})
		}},
		{"CONTINUATION with no block open", "§6.10", "stream 5", func(h *harness) error {
			return h.send(frame.ContinuationFrame{StreamID: 5, EndHeaders: true})
		}},
		{"CONTINUATION on the wrong stream", "§6.10", "stream 5", func(h *harness) error {
			h.mustSend(frame.HeadersFrame{StreamID: 7, Fragment: encodeFields(h2.Field{Name: "a", Value: "b"})})
			return h.send(frame.ContinuationFrame{StreamID: 5, EndHeaders: true})
		}},
		{"a block that will not decode", "§4.3", "stream 5", func(h *harness) error {
			return h.send(frame.HeadersFrame{StreamID: 5, EndHeaders: true, Fragment: []byte{codecFailure}})
		}},
		{"DATA on an idle stream", "§5.1", "stream 5", func(h *harness) error {
			return h.send(data(5, "x", false))
		}},
		{"DATA on a closed stream", "§5.1", "stream 5", func(h *harness) error {
			h.open(5, false)
			h.mustSend(frame.RSTStreamFrame{StreamID: 5, ErrCode: h2.Cancel})
			return h.send(data(5, "x", false))
		}},
		{"DATA after END_STREAM", "§5.1", "stream 5", func(h *harness) error {
			h.open(5, true)
			return h.send(data(5, "x", false))
		}},
		{"RST_STREAM on an idle stream", "§6.4", "stream 5", func(h *harness) error {
			return h.send(frame.RSTStreamFrame{StreamID: 5, ErrCode: h2.Cancel})
		}},
		{"WINDOW_UPDATE on an idle stream", "§5.1", "stream 5", func(h *harness) error {
			return h.send(frame.WindowUpdateFrame{StreamID: 5, Increment: 1})
		}},
		// Stream 0, and truthfully so: a PING names no stream, and the message
		// says so rather than inventing one. The section reference is replaced by
		// the phrase that says where the frame arrived, because there is no rule in
		// the RFC about a frame reaching the wrong layer of this server.
		{"a frame type that does not belong here", "reached the stream table", "stream 0", func(h *harness) error {
			return h.send(frame.PingFrame{})
		}},
	} {
		t.Run(tc.what, func(t *testing.T) {
			h := newHarness(t, Config{})
			err := tc.provoke(h)
			if err == nil {
				t.Fatalf("%s was accepted", tc.what)
			}
			if !strings.Contains(err.Error(), tc.section) {
				t.Errorf("%s reported %q, which does not cite %s", tc.what, err, tc.section)
			}
			if !strings.Contains(err.Error(), tc.stream) {
				t.Errorf("%s reported %q, which does not name %s", tc.what, err, tc.stream)
			}
		})
	}
}

// TestTheResetFloodErrorNamesTheBurstItExceeded is separated from the table above
// because the CVE-2023-44487 refusal is the one error here that is not about a rule
// in the RFC. It cites the advisory instead, and it names the burst — an operator
// seeing this line needs to know which number to raise, and the number is policy
// rather than protocol.
func TestTheResetFloodErrorNamesTheBurstItExceeded(t *testing.T) {
	h := newHarness(t, Config{})
	var id uint32 = 1
	var err error
	for i := 0; i <= int(limits.ResetBurst); i++ {
		h.open(id, false)
		if err = h.send(frame.RSTStreamFrame{StreamID: id, ErrCode: h2.Cancel}); err != nil {
			break
		}
		id += 2
	}
	if err == nil {
		t.Fatalf("%d resets in a burst were all accepted", limits.ResetBurst+1)
	}
	for _, want := range []string{"CVE-2023-44487", fmt.Sprint(limits.ResetBurst)} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the flood refusal reported %q, which does not mention %s", err, want)
		}
	}
}
