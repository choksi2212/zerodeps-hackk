package exchange

import (
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	"zerodeps/zdh/internal/flow"
	"zerodeps/zdh/internal/frame"
	"zerodeps/zdh/internal/h2"
	"zerodeps/zdh/internal/hpack"
	"zerodeps/zdh/internal/priority"
	"zerodeps/zdh/internal/request"
	"zerodeps/zdh/internal/response"
	"zerodeps/zdh/internal/stream"
)

// The tests in this file drive the real thing: frames into a real stream table, over a
// real HPACK codec, out through a real response encoder, and the frames that come out
// are decoded with a second codec standing in for the peer's. Nothing between the
// header block and the wire is a double.
//
// That is deliberate and it is not thoroughness for its own sake. A *stream.Stream
// cannot be built from outside internal/stream, which is the same constraint a real
// connection has, and the alternative — a fake stream table — would test this package
// against a description of the table's behaviour rather than the behaviour. Two of the
// rules below (§8.1.1's content-length accounting and what a peer's RST_STREAM does to a
// handler) are only interesting because the table does what it does.

// --- the harness -----------------------------------------------------------

// collector is the connection's write half: it keeps every frame the response encoder
// enqueues, in order.
//
// Safe for concurrent use, because it is written from every handler's goroutine at once
// — which is what the real one is too, and for the same reason.
type collector struct {
	mu     sync.Mutex
	frames []frame.Frame
	prios  []prioritized
	max    uint32
	err    error

	// atFirstFrame is how many priority signals had been made when the first frame was
	// enqueued. Zero also means no frame ever arrived, which no assertion has to tell
	// apart: every use of it wants a positive number.
	atFirstFrame int
}

func (c *collector) Enqueue(f frame.Frame) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	if len(c.frames) == 0 {
		c.atFirstFrame = len(c.prios)
	}
	c.frames = append(c.frames, f)
	return nil
}

func (c *collector) MaxFrameSize() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.max
}

// Forget is the stream layer reporting a retirement, and there is nothing here to
// forget: this double holds no per-stream state, and the frames it has collected are
// the test's evidence rather than a queue. The real writer drops the stream's priority.
func (c *collector) Forget(uint32) {}

// Prioritize is the write side being told what a request asked for, kept in order.
//
// Under the same mutex as the frames, and for a reason worth stating rather than
// copying: the real writer is called from every stream goroutine at once, so a double
// that is only safe from one is a double that reports the next test's race as a pass.
// This method happens to be called from the reader goroutine alone — which is the
// property TestThePrioritySignalIsMadeOnTheGoroutineThatDeliveredTheFrame is about — but
// the double does not get to assume that.
func (c *collector) Prioritize(id uint32, p priority.Params) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.prios = append(c.prios, prioritized{id: id, params: p})
}

// prioritized is one call to Prioritize.
type prioritized struct {
	id     uint32
	params priority.Params
}

func (c *collector) signals() []prioritized {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]prioritized(nil), c.prios...)
}

// signalsBeforeTheFirstFrame is the ordering question rather than the goroutine one.
func (c *collector) signalsBeforeTheFirstFrame() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.atFirstFrame
}

func (c *collector) snapshot() []frame.Frame {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]frame.Frame(nil), c.frames...)
}

// fail makes every later Enqueue return err, which is what a connection whose writer has
// stopped looks like from a handler's goroutine.
func (c *collector) fail(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.err = err
}

// reports records what this package hands back to the stream table — the finished
// responses and the request content its handlers have read — and hands both on to the
// real table underneath.
//
// Both halves matter. The record is what a test asserts on; the forwarding is what makes
// the table's state machine, its §5.1.2 concurrency limit and its receive windows behave
// as they would on a connection, so a test about a slot being freed or a window being
// credited is testing the real path.
type reports struct {
	mu       sync.Mutex
	ids      []uint32
	consumed []consumed
	tab      *stream.Table
}

func (r *reports) ReportSendEnd(id uint32) {
	r.mu.Lock()
	r.ids = append(r.ids, id)
	tab := r.tab
	r.mu.Unlock()

	if tab != nil {
		tab.ReportSendEnd(id)
	}
}

func (r *reports) ReportConsumed(id uint32, n int, more bool) {
	r.mu.Lock()
	r.consumed = append(r.consumed, consumed{id: id, n: n, more: more})
	tab := r.tab
	r.mu.Unlock()

	if tab != nil {
		tab.ReportConsumed(id, n, more)
	}
}

// credited is how many octets of content the handlers on stream id have reported reading.
func (r *reports) credited(id uint32) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	var n int
	for _, c := range r.consumed {
		if c.id == id {
			n += c.n
		}
	}
	return n
}

func (r *reports) all() []uint32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]uint32(nil), r.ids...)
}

func (r *reports) count(id uint32) int {
	n := 0
	for _, got := range r.all() {
		if got == id {
			n++
		}
	}
	return n
}

// handlerFunc adapts a function to Handler.
type handlerFunc func(w *response.Writer, r *Request)

func (f handlerFunc) Serve(w *response.Writer, r *Request) { f(w, r) }

// reply is one stream's response as the peer would see it.
type reply struct {
	// interim are the informational header sections, in order.
	interim [][]h2.Field
	// fields is the final header section, nil until one arrives.
	fields []h2.Field
	body   string
	ended  bool
}

func (r *reply) status() string { return value(r.fields, ":status") }

func value(fields []h2.Field, name string) string {
	for _, f := range fields {
		if f.Name == name {
			return f.Value
		}
	}
	return ""
}

type harness struct {
	t    *testing.T
	tab  *stream.Table
	reqs *Requests
	rep  *reports
	out  *collector
	logs *safeBuf

	// up encodes the requests this harness sends, standing in for the peer's encoder;
	// down decodes the responses it receives, standing in for the peer's decoder. Two
	// codecs, because HPACK's two directions are two histories (§4.3), and a single one
	// driven by both would answer each direction's indices with the other's entries.
	up   *hpack.Codec
	down *hpack.Codec

	// The state of the response decode: how many collected frames have been read, and
	// the header block being assembled across CONTINUATION frames.
	at       int
	block    []byte
	blockID  uint32
	blockEnd bool
	replies  map[uint32]*reply
}

func newHarness(t *testing.T, h Handler) *harness {
	t.Helper()
	logs := &safeBuf{}
	return build(t, h, logs, log.New(logs, "", 0))
}

// newSilentHarness has nowhere to log to, which is Config.Log's documented nil case and
// the one no other test can reach: a contained panic still has to be contained when
// there is no logger to describe it.
func newSilentHarness(t *testing.T, h Handler) *harness {
	t.Helper()
	return build(t, h, &safeBuf{}, nil)
}

// newDeafHarness has nowhere to send a priority signal, which is Config.Priorities'
// documented nil case: a server that reads §5 of RFC 9218's field and declines to act
// on it, which §10 permits.
func newDeafHarness(t *testing.T, h Handler) *harness {
	t.Helper()
	logs := &safeBuf{}
	return build(t, h, logs, log.New(logs, "", 0), noPriorities)
}

// noPriorities is the one option build takes, and it exists because the nil case of an
// optional dependency is a case worth exercising through the whole path rather than at
// the constructor.
func noPriorities(cfg *Config) { cfg.Priorities = nil }

func build(t *testing.T, h Handler, logs *safeBuf, lg *log.Logger, opts ...func(*Config)) *harness {
	t.Helper()

	out := &collector{max: 16384}
	enc := response.NewEncoder(hpack.New(), out)
	sender := flow.NewSender()
	rep := &reports{}

	cfg := Config{
		Handler:    h,
		Encoder:    enc,
		Credit:     sender,
		Priorities: out,
		Log:        lg,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	reqs := New(cfg)
	tab := stream.New(stream.Config{
		Codec:    hpack.New(),
		Requests: reqs,
		Encoder:  enc,
		Sender:   sender,
		Writer:   out,
	})
	rep.tab = tab
	reqs.Attach(rep)

	return &harness{
		t: t, tab: tab, reqs: reqs, rep: rep, out: out, logs: logs,
		up: hpack.New(), down: hpack.New(),
		replies: make(map[uint32]*reply),
	}
}

// headers is one HEADERS frame carrying fields, encoded as the peer would encode it.
func (h *harness) headers(id uint32, fields []h2.Field, endStream bool) frame.HeadersFrame {
	return frame.HeadersFrame{
		StreamID:   id,
		EndStream:  endStream,
		EndHeaders: true,
		Fragment:   h.up.Encode(fields),
	}
}

// request is the header section of a GET for /id.
func requestFields(path string) []h2.Field {
	return []h2.Field{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "zdh.test"},
		{Name: ":path", Value: path},
	}
}

func (h *harness) send(f frame.Frame) error { return h.tab.HandleFrame(f) }

func (h *harness) mustSend(f frame.Frame) {
	h.t.Helper()
	if err := h.tab.HandleFrame(f); err != nil {
		h.t.Fatalf("%T on stream %d was refused: %v", f, f.Stream(), err)
	}
}

// get sends a complete GET on id.
func (h *harness) get(id uint32) {
	h.t.Helper()
	h.mustSend(h.headers(id, requestFields(fmt.Sprintf("/%d", id)), true))
}

// post sends the header section of a request with a body on id, with extra appended to
// the standard field list.
func (h *harness) post(id uint32, extra ...h2.Field) {
	h.t.Helper()
	fields := append(requestFields(fmt.Sprintf("/%d", id)), extra...)
	fields[0].Value = "POST"
	h.mustSend(h.headers(id, fields, false))
}

func (h *harness) data(id uint32, s string, endStream bool) frame.DataFrame {
	return frame.DataFrame{StreamID: id, Data: []byte(s), EndStream: endStream}
}

// waitSent blocks until the response on id has been reported as finished.
//
// The barrier every assertion about a response needs: a handler runs on its own
// goroutine, so "the frames are on the wire" is not true when HandleFrame returns, and
// the report is the moment it becomes true. Polling rather than a channel because the
// thing being waited for is a method on an interface the code under test calls, and a
// blocking send from it would change the behaviour under test.
func (h *harness) waitSent(id uint32) {
	h.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for h.rep.count(id) == 0 {
		if time.Now().After(deadline) {
			h.t.Fatalf("the response on stream %d was not reported as finished within 10s; reported: %v",
				id, h.rep.all())
		}
		time.Sleep(time.Millisecond)
	}
}

// reply is the response the peer would have received on id, decoded.
func (h *harness) reply(id uint32) *reply {
	h.t.Helper()
	h.drain()
	r := h.replies[id]
	if r == nil {
		h.t.Fatalf("no response on stream %d; frames so far: %d", id, len(h.out.snapshot()))
	}
	return r
}

// drain decodes every frame collected since the last call.
//
// Incremental because the peer's HPACK decoder is stateful: decoding a block twice, or
// out of order, desynchronises it exactly as it would desynchronise a real client. So
// each frame is decoded once, in the order it was enqueued, whichever stream it belongs
// to.
func (h *harness) drain() {
	h.t.Helper()
	frames := h.out.snapshot()
	for ; h.at < len(frames); h.at++ {
		switch f := frames[h.at].(type) {
		case frame.HeadersFrame:
			h.block = append(h.block[:0], f.Fragment...)
			h.blockID, h.blockEnd = f.StreamID, f.EndStream
			if f.EndHeaders {
				h.finishBlock()
			}
		case frame.ContinuationFrame:
			h.block = append(h.block, f.Fragment...)
			if f.EndHeaders {
				h.finishBlock()
			}
		case frame.DataFrame:
			r := h.replyFor(f.StreamID)
			r.body += string(f.Data)
			if f.EndStream {
				r.ended = true
			}
		}
	}
}

func (h *harness) finishBlock() {
	h.t.Helper()
	fields, err := h.down.Decode(h.block)
	if err != nil {
		h.t.Fatalf("decoding the header block on stream %d: %v", h.blockID, err)
	}
	r := h.replyFor(h.blockID)
	if s := value(fields, ":status"); strings.HasPrefix(s, "1") {
		r.interim = append(r.interim, fields)
	} else {
		r.fields = fields
	}
	if h.blockEnd {
		r.ended = true
	}
}

func (h *harness) replyFor(id uint32) *reply {
	r := h.replies[id]
	if r == nil {
		r = &reply{}
		h.replies[id] = r
	}
	return r
}

// assertStreamError is the table's own assertion, repeated here: a fault the peer caused
// on one stream, which resets that stream and leaves the connection up.
func assertStreamError(t *testing.T, err error, id uint32, code h2.ErrCode, what string) {
	t.Helper()
	var se h2.StreamError
	if !errors.As(err, &se) {
		t.Fatalf("%s gave %v (%T), want a stream error", what, err, err)
	}
	if se.StreamID != id || se.Code != code {
		t.Errorf("%s gave a stream error on %d with %v, want %d with %v", what, se.StreamID, se.Code, id, code)
	}
}

// serve200 is a handler that answers with a fixed body.
func serve200(body string) Handler {
	return handlerFunc(func(w *response.Writer, r *Request) {
		if err := w.WriteHeader([]h2.Field{
			{Name: ":status", Value: "200"},
			{Name: "content-length", Value: fmt.Sprint(len(body))},
		}); err != nil {
			panic(err)
		}
		if _, err := io.WriteString(w, body); err != nil {
			panic(err)
		}
		if err := w.Close(); err != nil {
			panic(err)
		}
	})
}

// --- the ordinary route ----------------------------------------------------

// TestAGetReachesItsHandlerAndItsAnswerReachesThePeer is the whole path once, and the
// assertions are at both ends: what the handler was given, and what a peer decoding the
// frames would read.
func TestAGetReachesItsHandlerAndItsAnswerReachesThePeer(t *testing.T) {
	var got *Request
	h := newHarness(t, handlerFunc(func(w *response.Writer, r *Request) {
		got = r
		serve200("hello").Serve(w, r)
	}))

	h.get(1)
	h.waitSent(1)

	if got == nil {
		t.Fatal("the handler was never called")
	}
	if got.Method != "GET" || got.Path != "/1" || got.Scheme != "https" || got.Authority != "zdh.test" {
		t.Errorf("the handler was given %s %s (scheme %q, authority %q), want GET /1 (https, zdh.test)",
			got.Method, got.Path, got.Scheme, got.Authority)
	}
	if got.ContentLength != request.NoContentLength {
		t.Errorf("a GET arrived with content-length %d, want none declared", got.ContentLength)
	}

	r := h.reply(1)
	if r.status() != "200" || r.body != "hello" || !r.ended {
		t.Errorf("the peer sees status %q, body %q, ended %v; want 200, \"hello\", true",
			r.status(), r.body, r.ended)
	}
}

// TestAGetsBodyIsEmptyRatherThanAbsent is why Request.Body is never nil: a handler that
// reads the body of a GET must get an immediate EOF, not a nil dereference and not a
// wait for content the peer said would not come.
func TestAGetsBodyIsEmptyRatherThanAbsent(t *testing.T) {
	read := make(chan string, 1)
	errs := make(chan error, 1)
	h := newHarness(t, handlerFunc(func(w *response.Writer, r *Request) {
		b, err := io.ReadAll(r.Body)
		read <- string(b)
		errs <- err
		serve200("").Serve(w, r)
	}))

	h.get(1)
	h.waitSent(1)

	if got := recv(t, read, "the handler reading the body of a GET"); got != "" {
		t.Errorf("the body of a GET read back %q, want empty", got)
	}
	if err := recv(t, errs, "the handler's read finishing"); err != nil {
		t.Errorf("reading the body of a GET: %v", err)
	}
}

// TestARequestThatArrivedCompleteIsNotHeldOntoAtAll pins the map's occupancy, which is
// what keeps a connection's footprint proportional to the uploads in flight rather than
// to the requests it has served.
func TestARequestThatArrivedCompleteIsNotHeldOntoAtAll(t *testing.T) {
	h := newHarness(t, serve200("x"))

	for id := uint32(1); id <= 9; id += 2 {
		h.get(id)
	}
	for id := uint32(1); id <= 9; id += 2 {
		h.waitSent(id)
	}

	if n := len(h.reqs.arriving); n != 0 {
		t.Errorf("five complete GETs left %d requests recorded as still arriving, want 0", n)
	}
}

// TestEachRequestIsAnsweredOnItsOwnGoroutine is the promise stream.Requests makes about
// not blocking: two handlers are in Serve at the same time, and the frame that started
// the second was accepted while the first had not returned.
//
// Which is the property the connection depends on. The goroutine calling HandleFrame is
// also the one that answers the peer's PING frames, so a handler that blocks — reading a
// database, or reading its own request body — must not be able to stop it.
//
// Both frames are handed to the table from a goroutine of their own, which is the only
// way to assert that at all: a HandleFrame that ran the handler inline would never
// return, and a test that called it directly would deadlock rather than say so.
func TestEachRequestIsAnsweredOnItsOwnGoroutine(t *testing.T) {
	entered := make(chan string, 2)
	release := make(chan struct{})
	h := newHarness(t, handlerFunc(func(w *response.Writer, r *Request) {
		entered <- r.Path
		<-release
		serve200("done").Serve(w, r)
	}))

	accepted := make(chan error, 1)
	first := h.headers(1, requestFields("/1"), true)
	go func() { accepted <- h.send(first) }()
	if err := recv(t, accepted, "the first request being accepted"); err != nil {
		t.Fatalf("the first request was refused: %v", err)
	}
	if got := recv(t, entered, "the first handler starting"); got != "/1" {
		t.Fatalf("the first handler was given path %q, want /1", got)
	}

	second := h.headers(3, requestFields("/3"), true)
	go func() { accepted <- h.send(second) }()
	if err := recv(t, accepted, "the second request being accepted"); err != nil {
		t.Fatalf("the second request was refused: %v", err)
	}
	if got := recv(t, entered, "the second handler starting"); got != "/3" {
		t.Fatalf("the second handler was given path %q, want /3", got)
	}

	// Both are inside Serve and neither can have finished.
	if got := h.rep.all(); len(got) != 0 {
		t.Errorf("%v was reported as finished while its handler was still blocked", got)
	}
	close(release)

	h.waitSent(1)
	h.waitSent(3)
	if h.reply(1).body != "done" || h.reply(3).body != "done" {
		t.Error("one of the two blocked handlers did not answer once released")
	}
}

// TestAFinishedResponseIsReportedOnceAndOnlyOnce is what frees §5.1.2's concurrency
// slot. Twice would free a slot the connection does not have; not at all would leak one
// per request until the peer could open no more streams.
func TestAFinishedResponseIsReportedOnceAndOnlyOnce(t *testing.T) {
	h := newHarness(t, serve200("x"))

	h.get(1)
	h.waitSent(1)
	time.Sleep(20 * time.Millisecond)

	if n := h.rep.count(1); n != 1 {
		t.Errorf("stream 1 was reported as finished %d times, want 1", n)
	}
}

// TestTheStreamTableSeesTheResponseEnd is the report arriving where it is meant to go,
// through the real table rather than only into the harness's record: the stream is
// closed and gone once the next frame is handled.
func TestTheStreamTableSeesTheResponseEnd(t *testing.T) {
	h := newHarness(t, serve200("x"))

	h.get(1)
	h.waitSent(1)
	h.mustSend(frame.PriorityFrame{StreamID: 2, StreamDependency: 0, Weight: 1})

	if got := h.tab.StateOf(1); got != stream.StateClosed {
		t.Errorf("stream 1 is %v after its response finished, want closed", got)
	}
	if n := h.tab.Len(); n != 0 {
		t.Errorf("the table holds %d streams, want 0", n)
	}
}

// --- the client's own priority signal ---------------------------------------

// RFC 9218 has two carriers and this package handles one of them: §5's Priority header
// field, which arrives inside the request. The other is a PRIORITY_UPDATE frame on
// stream 0 and belongs to internal/server, which never sees a decoded header section.
//
// What these assert is the hand-off, not the scheduling. Whether a signal reorders
// anything on the wire is internal/server/scheduler_test.go's question. Whether it is
// passed on at all, exactly once, with the parameters the client sent, and never for a
// request that is not going to be answered, is this one.

// priorityRequest is the header section of a GET carrying a Priority field value.
func priorityRequest(path, field string) []h2.Field {
	return append(requestFields(path), h2.Field{Name: "priority", Value: field})
}

func TestARequestsPriorityFieldReachesTheWriteSide(t *testing.T) {
	h := newHarness(t, serve200("hello"))
	h.mustSend(h.headers(1, priorityRequest("/1", "u=0, i"), true))
	h.waitSent(1)

	got := h.out.signals()
	if len(got) != 1 {
		t.Fatalf("%d priority signals reached the write side, want 1: %+v", len(got), got)
	}
	if got[0].id != 1 {
		t.Errorf("the signal named stream %d, want 1", got[0].id)
	}
	if u := got[0].params.Urgency(); u != 0 {
		t.Errorf("urgency %d reached the write side, want the 0 the client asked for", u)
	}
	if !got[0].params.Incremental() {
		t.Error("the signal is not incremental, but the client sent i")
	}
}

// A field carrying one parameter is still a complete signal, and the parameter it left
// out has to arrive as its default rather than as nothing. §4 of RFC 9218: "When
// receiving an HTTP request that does not carry these priority parameters, a server
// SHOULD act as if their default values were specified."
func TestAPriorityFieldWithOneParameterResolvesTheOther(t *testing.T) {
	h := newHarness(t, serve200("hello"))
	h.mustSend(h.headers(1, priorityRequest("/1", "u=7"), true))
	h.waitSent(1)

	got := h.out.signals()
	if len(got) != 1 {
		t.Fatalf("%d priority signals reached the write side, want 1: %+v", len(got), got)
	}
	if u := got[0].params.Urgency(); u != 7 {
		t.Errorf("urgency %d, want 7", u)
	}
	if got[0].params.Incremental() {
		t.Error("the signal is incremental, but the client named no i and §4.2's default is not")
	}
}

// The three shapes that carry no signal, and none of them may reach the write side.
//
// A signal that says nothing is not the same as no signal: the write side keeps one
// entry per stream it has been told about, and an entry meaning "the defaults" says
// exactly what having no entry already says. Sending one costs a lock on the reader
// goroutine and a map entry per request, in exchange for nothing.
//
// The third shape is the interesting one. An unparseable field value is not a malformed
// request — internal/request says why — and what it produces is the defaults, which by
// the rule above is nothing to pass on.
func TestARequestThatCarriesNoPriorityIsNotSignalled(t *testing.T) {
	cases := []struct {
		name   string
		fields []h2.Field
	}{
		{"no field at all", requestFields("/1")},
		{"an empty field, which is a Dictionary of no members", priorityRequest("/1", "")},
		{"a field value that does not parse", priorityRequest("/1", "u=??")},
		{"a field naming only parameters this server does not know", priorityRequest("/1", "q=1")},
		{"a field whose urgency is out of §4.1's range", priorityRequest("/1", "u=9")},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, serve200("hello"))
			h.mustSend(h.headers(1, c.fields, true))
			h.waitSent(1)

			if got := h.out.signals(); len(got) != 0 {
				t.Errorf("%d priority signals reached the write side, want none: %+v", len(got), got)
			}
			if got := h.reply(1).status(); got != "200" {
				t.Errorf("status %q, want 200: a priority signal is advice and never makes a request bad", got)
			}
		})
	}
}

// The signal is made on the goroutine that delivered the frame, and that is the fact
// internal/server's arbitration between the two carriers rests on. conn.leftIdle applies
// a buffered PRIORITY_UPDATE after the stream layer has handled the frame that opened
// the stream, so a signal made from here — synchronously, inside HandleFrame — is
// necessarily the earlier of the two, which is what §7 of RFC 9218 wants: "the most
// recently received PRIORITY_UPDATE frame can be considered as the most up-to-date
// information that overrides any other signal."
//
// A signal made from the handler's goroutine instead would be a signal racing the frame
// that is supposed to override it, and it would win about half the time.
//
// The handler is parked to prove that: it has entered Serve and cannot proceed, so
// nothing it does could have produced the call that has already been made.
func TestThePrioritySignalIsMadeOnTheGoroutineThatDeliveredTheFrame(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	h := newHarness(t, handlerFunc(func(w *response.Writer, r *Request) {
		close(entered)
		<-release
		_ = w.WriteBodylessHeader([]h2.Field{{Name: ":status", Value: "204"}})
	}))
	h.mustSend(h.headers(1, priorityRequest("/1", "u=1"), true))

	<-entered
	if got := h.out.signals(); len(got) != 1 {
		t.Errorf("%d priority signals had been made by the time the parked handler was "+
			"reached, want 1", len(got))
	}
	close(release)
	h.waitSent(1)
}

// And made before the goroutine that answers exists, which is the other half of the
// same line's reason for being where it is.
//
// A signal made after start is still on the right goroutine and still ahead of any
// PRIORITY_UPDATE, so the previous test cannot see the difference — but the handler is
// running by then, and the frame it enqueues first is the header section of the very
// response the signal was about. Scheduling that one frame at the default urgency is a
// small wrong answer, and it is one that appears and disappears with the timing of two
// goroutines, which is the kind worth ruling out by construction.
func TestThePrioritySignalIsMadeBeforeTheHandlerCanEnqueueAnything(t *testing.T) {
	h := newHarness(t, serve200("hello"))
	h.mustSend(h.headers(1, priorityRequest("/1", "u=0"), true))
	h.waitSent(1)

	if got := h.out.signalsBeforeTheFirstFrame(); got != 1 {
		t.Errorf("%d priority signals had been made when the response's first frame was "+
			"enqueued, want 1", got)
	}
}

// A malformed request is a stream error and gets no response, so there is nothing to
// schedule and the write side must not be told about it. A signal for a stream that is
// about to be reset is an entry the write side would hold until the connection ended:
// nothing retires a stream that never opened, and nothing would call Forget for it.
func TestAMalformedRequestCarryingAPriorityFieldIsNotSignalled(t *testing.T) {
	h := newHarness(t, serve200("hello"))

	// A connection-specific field, which §8.2.2 makes the request malformed. The
	// Priority field beside it is perfectly good.
	fields := append(priorityRequest("/1", "u=0"), h2.Field{Name: "connection", Value: "keep-alive"})
	err := h.send(h.headers(1, fields, true))
	assertStreamError(t, err, 1, h2.ProtocolError, "a connection-specific field")

	if got := h.out.signals(); len(got) != 0 {
		t.Errorf("%d priority signals reached the write side for a request that was refused, "+
			"want none: %+v", len(got), got)
	}
}

// Config.Priorities is optional, and the nil case is a whole server rather than a
// constructor argument: the request is answered, the field is left in Fields for the
// handler and for the next hop, and nothing is scheduled.
//
// §10 of RFC 9218: "Endpoints cannot depend on particular treatment based on priority
// signals." Which is what makes this conformant rather than broken.
func TestARequestIsAnsweredWithNowhereToSendItsPriority(t *testing.T) {
	var carried string
	h := newDeafHarness(t, handlerFunc(func(w *response.Writer, r *Request) {
		carried = value(r.Fields, "priority")
		_ = w.WriteBodylessHeader([]h2.Field{{Name: ":status", Value: "204"}})
	}))
	h.mustSend(h.headers(1, priorityRequest("/1", "u=0, i"), true))
	h.waitSent(1)

	if got := h.reply(1).status(); got != "204" {
		t.Errorf("status %q, want 204", got)
	}
	if carried != "u=0, i" {
		t.Errorf("the handler saw a Priority field of %q, want the client's %q: §5 of RFC 9218 "+
			"makes it an end-to-end signal, so it is not this server's to strip", carried, "u=0, i")
	}
	if got := h.out.signals(); len(got) != 0 {
		t.Errorf("%d priority signals reached the write side, want none: this harness has "+
			"nowhere to send them: %+v", len(got), got)
	}
}

// --- bodies ----------------------------------------------------------------

// TestAnUploadArrivesAsItWasFramed: three DATA frames become one body, in order, and the
// handler's answer goes out after it.
func TestAnUploadArrivesAsItWasFramed(t *testing.T) {
	body := make(chan string, 1)
	h := newHarness(t, handlerFunc(func(w *response.Writer, r *Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading the body: %v", err)
		}
		body <- string(b)
		serve200("ok").Serve(w, r)
	}))

	h.post(1)
	h.mustSend(h.data(1, "one ", false))
	h.mustSend(h.data(1, "two ", false))
	h.mustSend(h.data(1, "three", true))
	h.waitSent(1)

	if got := recv(t, body, "the handler reading the upload"); got != "one two three" {
		t.Errorf("the handler read %q, want %q", got, "one two three")
	}
}

// TestAHandlerReadingAheadOfThePeerWaitsForIt is the interleaving a real upload has: the
// handler asks for the body before all of it has arrived, and gets it as it does.
func TestAHandlerReadingAheadOfThePeerWaitsForIt(t *testing.T) {
	step := make(chan string)
	h := newHarness(t, handlerFunc(func(w *response.Writer, r *Request) {
		p := make([]byte, 32)
		for {
			n, err := r.Body.Read(p)
			if n > 0 {
				step <- string(p[:n])
			}
			if err != nil {
				close(step)
				return
			}
		}
	}))

	h.post(1)
	h.mustSend(h.data(1, "first", false))
	if got := recv(t, step, "the handler reading the first payload"); got != "first" {
		t.Fatalf("the handler read %q, want %q", got, "first")
	}
	h.mustSend(h.data(1, "second", true))
	if got := recv(t, step, "the handler reading the second payload"); got != "second" {
		t.Fatalf("the handler read %q, want %q", got, "second")
	}
	// A closed channel reads back the zero value, so this is the read that ended rather
	// than a third payload.
	if got := recv(t, step, "the handler's read ending"); got != "" {
		t.Fatalf("the handler read %q as well, want only the two payloads that were sent", got)
	}
}

// TestAnUploadNobodyReadsIsStillAccepted: a handler that answers without reading its
// request body is entitled to, and the frames it ignored must not stall the connection.
// The peer's window is what bounds them, and this server never replenishes a stream's,
// so the most that can accumulate is one window's worth.
func TestAnUploadNobodyReadsIsStillAccepted(t *testing.T) {
	h := newHarness(t, serve200("ignored your body"))

	h.post(1)
	for i := 0; i < 8; i++ {
		h.mustSend(h.data(1, strings.Repeat("x", 1024), false))
	}
	h.mustSend(h.data(1, "", true))
	h.waitSent(1)

	if r := h.reply(1); r.status() != "200" || !r.ended {
		t.Errorf("the peer sees status %q, ended %v; want 200 and an ended stream", r.status(), r.ended)
	}
}

// --- §8.1.1's content-length rule ------------------------------------------

// TestABodyLongerThanItsContentLengthIsMalformedAtTheFrameThatExceedsIt is the rule
// caught early rather than at the end, and the second half of the test is the reason: the
// octets past the declared length are content the peer had no business sending, and a
// handler reading along must not be handed them.
//
// The handler is held at the boundary on purpose. Its first read is taken before the
// surplus frame is sent, so what it saw is fixed rather than a race with the frame that
// invalidates the request — and its next read has only one thing it can be, the failure.
// Reading the whole body with io.ReadAll instead would be a test of scheduling: Read
// reports a failure ahead of buffered content, so it would sometimes see the five octets
// and sometimes see none, and both are correct.
func TestABodyLongerThanItsContentLengthIsMalformedAtTheFrameThatExceedsIt(t *testing.T) {
	reads := make(chan string, 4)
	failed := make(chan error, 1)
	h := newHarness(t, handlerFunc(func(w *response.Writer, r *Request) {
		p := make([]byte, 16)
		for {
			n, err := r.Body.Read(p)
			if n > 0 {
				reads <- string(p[:n])
			}
			if err != nil {
				failed <- err
				return
			}
		}
	}))

	h.post(1, h2.Field{Name: "content-length", Value: "5"})
	h.mustSend(h.data(1, "12345", false))
	if got := recv(t, reads, "the handler reading the content the peer declared"); got != "12345" {
		t.Fatalf("the handler read %q, want the %q the peer was entitled to send", got, "12345")
	}

	err := h.send(h.data(1, "6", false))
	assertStreamError(t, err, 1, h2.ProtocolError, "a sixth octet against a content-length of 5")

	select {
	case err := <-failed:
		var se h2.StreamError
		if !errors.As(err, &se) || se.Code != h2.ProtocolError {
			t.Errorf("the handler's read ended with %v, want a stream error carrying PROTOCOL_ERROR", err)
		}
	case got := <-reads:
		t.Errorf("the handler was handed %q, which is past the content-length the peer declared", got)
	case <-time.After(10 * time.Second):
		t.Fatal("the handler was left parked on the body of a request that had been refused")
	}
}

// TestABodyShorterThanItsContentLengthIsMalformedAtItsEndStream is the same rule failing
// the other way, which cannot be noticed before the end because "short" has no meaning
// until then.
//
// The second assertion is about what a reset leaves behind. A peer that opens streams and
// sends deliberately short bodies gets one stream error each; if the entry for the stream
// outlived it, that peer would also get a map that grows for as long as the connection
// lasts.
func TestABodyShorterThanItsContentLengthIsMalformedAtItsEndStream(t *testing.T) {
	h := newHarness(t, serve200("x"))

	h.post(1, h2.Field{Name: "content-length", Value: "10"})
	h.mustSend(h.data(1, "four", false))
	err := h.send(h.data(1, "", true))
	assertStreamError(t, err, 1, h2.ProtocolError, "four octets against a content-length of 10")

	if n := len(h.reqs.arriving); n != 0 {
		t.Errorf("a malformed request left %d entries recorded as arriving, want 0", n)
	}
}

// TestABodyThatMatchesItsContentLengthIsAccepted is the other side of the two tests
// above, and it is the one that would catch an off-by-one in either: an exact upload
// must not be refused.
func TestABodyThatMatchesItsContentLengthIsAccepted(t *testing.T) {
	h := newHarness(t, serve200("counted"))

	h.post(1, h2.Field{Name: "content-length", Value: "9"})
	h.mustSend(h.data(1, "123456", false))
	h.mustSend(h.data(1, "789", true))
	h.waitSent(1)

	if r := h.reply(1); r.status() != "200" {
		t.Errorf("an upload of exactly its declared length got status %q, want 200", r.status())
	}
}

// TestAnUploadWithNoContentLengthMaySendWhateverItLikes: §8.1.1's rule is about a
// content-length field disagreeing with the content, so a request without one cannot
// break it, however much it sends.
func TestAnUploadWithNoContentLengthMaySendWhateverItLikes(t *testing.T) {
	h := newHarness(t, serve200("fine"))

	h.post(1)
	h.mustSend(h.data(1, strings.Repeat("x", 4096), false))
	h.mustSend(h.data(1, "y", true))
	h.waitSent(1)

	if r := h.reply(1); r.status() != "200" {
		t.Errorf("an upload with no declared length got status %q, want 200", r.status())
	}
}

// TestAnEmptyBodyAgainstANonZeroContentLengthIsMalformed is the boundary between this
// package's half of §8.1.1 and internal/request's: a request whose HEADERS frame carried
// END_STREAM is caught there, and one that ends with an empty DATA frame is caught here.
func TestAnEmptyBodyAgainstANonZeroContentLengthIsMalformed(t *testing.T) {
	h := newHarness(t, serve200("x"))

	h.post(1, h2.Field{Name: "content-length", Value: "3"})
	err := h.send(h.data(1, "", true))
	assertStreamError(t, err, 1, h2.ProtocolError, "an empty body against a content-length of 3")
}

// --- trailers --------------------------------------------------------------

// TestTrailersReachTheHandlerAfterItsBody is §8.1's ordering end to end: the trailer
// section is readable once the body has been read to its end, and not before.
func TestTrailersReachTheHandlerAfterItsBody(t *testing.T) {
	before := make(chan int, 1)
	after := make(chan []h2.Field, 1)
	h := newHarness(t, handlerFunc(func(w *response.Writer, r *Request) {
		p := make([]byte, 4)
		if _, err := r.Body.Read(p); err != nil {
			t.Errorf("reading the body: %v", err)
		}
		before <- len(r.Body.Trailers())
		if _, err := io.ReadAll(r.Body); err != nil {
			t.Errorf("reading to the end: %v", err)
		}
		after <- r.Body.Trailers()
		serve200("ok").Serve(w, r)
	}))

	h.post(1)
	h.mustSend(h.data(1, "body", false))
	if got := recv(t, before, "the handler reading the front of the body"); got != 0 {
		t.Errorf("the handler saw %d trailer fields before finishing the body, want none", got)
	}
	h.mustSend(h.headers(1, []h2.Field{{Name: "checksum", Value: "42"}}, true))

	got := recv(t, after, "the handler reading the body to its end")
	if len(got) != 1 || got[0].Name != "checksum" || got[0].Value != "42" {
		t.Errorf("the handler saw trailers %v, want one checksum: 42", got)
	}
	h.waitSent(1)

	if n := len(h.reqs.arriving); n != 0 {
		t.Errorf("a request that ended with a trailer section left %d entries recorded as arriving, want 0", n)
	}
}

// TestATrailerSectionWithAPseudoHeaderFieldResetsTheStreamAndStopsTheHandler covers the
// pair of things a rejected trailer section has to do. §8.1 forbids pseudo-header fields
// in a trailer section; the stream error is what tells the peer, and failing the body is
// what stops a handler that would otherwise wait for an end that is never coming.
func TestATrailerSectionWithAPseudoHeaderFieldResetsTheStreamAndStopsTheHandler(t *testing.T) {
	failed := make(chan error, 1)
	h := newHarness(t, handlerFunc(func(w *response.Writer, r *Request) {
		_, err := io.ReadAll(r.Body)
		failed <- err
	}))

	h.post(1)
	h.mustSend(h.data(1, "body", false))
	err := h.send(h.headers(1, []h2.Field{{Name: ":method", Value: "GET"}}, true))
	assertStreamError(t, err, 1, h2.ProtocolError, "a pseudo-header field in a trailer section")

	select {
	case err := <-failed:
		if err == nil {
			t.Error("the handler's read ended without an error after the trailer section was refused")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the handler was left parked on a body whose trailer section had been refused")
	}
}

// TestTrailersOnAShortBodyAreMalformed is §8.1.1's accounting at the other place a
// request can end. A peer that declared ten octets, sent four and then sent trailers has
// sent a malformed request, and the trailer section is where that becomes visible.
func TestTrailersOnAShortBodyAreMalformed(t *testing.T) {
	h := newHarness(t, serve200("x"))

	h.post(1, h2.Field{Name: "content-length", Value: "10"})
	h.mustSend(h.data(1, "four", false))
	err := h.send(h.headers(1, []h2.Field{{Name: "checksum", Value: "1"}}, true))
	assertStreamError(t, err, 1, h2.ProtocolError, "trailers after four octets of a declared ten")
}

// --- the stream going away underneath a handler ----------------------------

// TestAPeerResetWakesAHandlerReadingTheBody is the leak this exists to prevent. A
// handler parked in Read on a stream the peer has abandoned would stay parked for the
// life of the connection, and a peer can open a stream, send a byte and reset it as fast
// as it can write frames.
func TestAPeerResetWakesAHandlerReadingTheBody(t *testing.T) {
	failed := make(chan error, 1)
	h := newHarness(t, handlerFunc(func(w *response.Writer, r *Request) {
		_, err := io.ReadAll(r.Body)
		failed <- err
	}))

	h.post(1)
	h.mustSend(h.data(1, "half", false))
	h.mustSend(frame.RSTStreamFrame{StreamID: 1, ErrCode: h2.Cancel})

	select {
	case err := <-failed:
		var se h2.StreamError
		if !errors.As(err, &se) || se.Code != h2.Cancel {
			t.Errorf("the woken handler saw %v, want a stream error carrying CANCEL", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the handler was left parked on the body of a stream the peer had reset")
	}
}

// TestAResetStreamIsNoLongerRecordedAsArriving: the entry goes with the stream, so a
// peer that opens and resets streams all day leaves nothing behind.
func TestAResetStreamIsNoLongerRecordedAsArriving(t *testing.T) {
	h := newHarness(t, handlerFunc(func(w *response.Writer, r *Request) {
		_, _ = io.ReadAll(r.Body)
	}))

	for id := uint32(1); id <= 19; id += 2 {
		h.post(id)
		h.mustSend(h.data(id, "x", false))
		h.mustSend(frame.RSTStreamFrame{StreamID: id, ErrCode: h2.Cancel})
	}

	if n := len(h.reqs.arriving); n != 0 {
		t.Errorf("ten opened-and-reset streams left %d requests recorded as arriving, want 0", n)
	}
}

// TestCanceledForAStreamWithNoBodyIsNothingToDo: a GET's handler cannot be parked on its
// body, so there is nothing for a reset to wake, and the absence has to be an ordinary
// outcome rather than a missing entry worth complaining about.
func TestCanceledForAStreamWithNoBodyIsNothingToDo(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	h := newHarness(t, handlerFunc(func(w *response.Writer, r *Request) {
		close(started)
		<-release
	}))

	h.get(1)
	<-started
	h.mustSend(frame.RSTStreamFrame{StreamID: 1, ErrCode: h2.Cancel})
	close(release)
	h.waitSent(1)
}

// TestTheConnectionEndingWakesEveryHandlerReadingABody is the other half of the same
// leak, and the half stream.Table.Close cannot reach: it wakes the goroutines waiting for
// send credit, and a handler waiting for an upload is not one of them.
func TestTheConnectionEndingWakesEveryHandlerReadingABody(t *testing.T) {
	const streams = 8
	failed := make(chan error, streams)
	h := newHarness(t, handlerFunc(func(w *response.Writer, r *Request) {
		_, err := io.ReadAll(r.Body)
		failed <- err
	}))

	for id := uint32(1); id <= streams*2-1; id += 2 {
		h.post(id)
		h.mustSend(h.data(id, "partial", false))
	}

	gone := errors.New("the connection ended")
	h.tab.Close(gone)
	h.reqs.Close(gone)

	for i := 0; i < streams; i++ {
		select {
		case err := <-failed:
			if !errors.Is(err, gone) {
				t.Errorf("a woken handler saw %v, want %v", err, gone)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("only %d of %d handlers were woken by the connection ending", i, streams)
		}
	}
	if n := len(h.reqs.arriving); n != 0 {
		t.Errorf("%d requests are still recorded as arriving after the connection ended, want 0", n)
	}
}

// --- handlers that misbehave -----------------------------------------------

// TestAHandlerThatWritesNothingGetsA500 is the answer to a stream that would otherwise
// carry no response at all, which from the peer's side is indistinguishable from a
// server that has stopped answering.
func TestAHandlerThatWritesNothingGetsA500(t *testing.T) {
	h := newHarness(t, handlerFunc(func(w *response.Writer, r *Request) {}))

	h.get(1)
	h.waitSent(1)

	r := h.reply(1)
	if r.status() != "500" || !r.ended {
		t.Errorf("a handler that wrote nothing produced status %q, ended %v; want 500 and an ended stream",
			r.status(), r.ended)
	}
	if r.body != "" {
		t.Errorf("the 500 carried a body of %q, want none", r.body)
	}
}

// TestAHandlerThatPanicsBeforeWritingGetsA500AndIsLogged: the panic is contained, the
// stream gets an answer, and the log line carries the stack — which is the only thing
// that turns a contained panic into a bug someone fixes.
func TestAHandlerThatPanicsBeforeWritingGetsA500AndIsLogged(t *testing.T) {
	h := newHarness(t, handlerFunc(func(w *response.Writer, r *Request) {
		panic("nothing written yet")
	}))

	h.get(1)
	h.waitSent(1)

	if got := h.reply(1).status(); got != "500" {
		t.Errorf("a handler that panicked produced status %q, want 500", got)
	}
	if !h.logs.contains("stream 1: the handler panicked: nothing written yet") {
		t.Errorf("the log does not name the panic:\n%s", h.logs.String())
	}
	if !h.logs.contains("exchange.(*Requests).start") {
		t.Errorf("the log line carries no stack:\n%s", h.logs.String())
	}
}

// TestAPanicWithNowhereToLogItIsStillContained is Config.Log's nil case, which is the
// documented way to discard the lines and is what a test that does not care about them
// would leave it as. The panic still has to be caught and the stream still has to get an
// answer — a server whose containment depended on having been given a logger would fail
// in exactly the deployments that forgot one.
func TestAPanicWithNowhereToLogItIsStillContained(t *testing.T) {
	h := newSilentHarness(t, handlerFunc(func(w *response.Writer, r *Request) {
		panic("and nowhere to say so")
	}))

	h.get(1)
	h.waitSent(1)

	if got := h.reply(1).status(); got != "500" {
		t.Errorf("a handler that panicked with no logger produced status %q, want 500", got)
	}
}

// TestAPanickingHandlerDoesNotTakeTheConnectionWithIt is the containment that matters:
// one stream's bug is one stream's problem, and the request after it is served normally.
func TestAPanickingHandlerDoesNotTakeTheConnectionWithIt(t *testing.T) {
	h := newHarness(t, handlerFunc(func(w *response.Writer, r *Request) {
		if r.Path == "/1" {
			panic("only the first one")
		}
		serve200("second").Serve(w, r)
	}))

	h.get(1)
	h.waitSent(1)
	h.get(3)
	h.waitSent(3)

	if got := h.reply(1).status(); got != "500" {
		t.Errorf("the panicking stream got status %q, want 500", got)
	}
	r := h.reply(3)
	if r.status() != "200" || r.body != "second" {
		t.Errorf("the stream after the panic got status %q body %q, want 200 and %q", r.status(), r.body, "second")
	}
}

// TestAHandlerThatPanicsAfterItsHeaderSectionEndsTheStreamWhereItStopped is the case
// with no good answer, pinned so that the answer it does get cannot change by accident.
//
// The response is ended where it stopped. A peer that was told to expect eleven octets
// receives five and an END_STREAM, which §8.1.1 makes a malformed response — and that is
// the truth of what happened. See Requests.finish for why this server does not send
// RST_STREAM here instead.
func TestAHandlerThatPanicsAfterItsHeaderSectionEndsTheStreamWhereItStopped(t *testing.T) {
	h := newHarness(t, handlerFunc(func(w *response.Writer, r *Request) {
		if err := w.WriteHeader([]h2.Field{
			{Name: ":status", Value: "200"},
			{Name: "content-length", Value: "11"},
		}); err != nil {
			t.Errorf("writing the header section: %v", err)
		}
		if _, err := io.WriteString(w, "five "); err != nil {
			t.Errorf("writing: %v", err)
		}
		panic("halfway through the body")
	}))

	h.get(1)
	h.waitSent(1)

	r := h.reply(1)
	if r.status() != "200" {
		t.Errorf("the truncated response has status %q, want the 200 the handler had already sent", r.status())
	}
	if r.body != "five " || !r.ended {
		t.Errorf("the peer sees body %q, ended %v; want %q and an ended stream", r.body, r.ended, "five ")
	}
	if value(r.fields, "content-length") != "11" {
		t.Error("the declared content-length is gone, so the peer cannot tell the response was truncated")
	}
}

// TestAHandlerThatEndedItsOwnResponseIsNotEndedAgain: Close is idempotent and finish
// leans on that, but the frames are what a peer sees, so the assertion is on them. A
// second END_STREAM would be a frame on a closed stream, which §5.1 makes a stream error
// at the peer.
func TestAHandlerThatEndedItsOwnResponseIsNotEndedAgain(t *testing.T) {
	h := newHarness(t, serve200("complete"))

	h.get(1)
	h.waitSent(1)

	ends := 0
	for _, f := range h.out.snapshot() {
		switch v := f.(type) {
		case frame.DataFrame:
			if v.EndStream {
				ends++
			}
		case frame.HeadersFrame:
			if v.EndStream {
				ends++
			}
		}
	}
	if ends != 1 {
		t.Errorf("the response carried %d frames with END_STREAM, want exactly 1", ends)
	}
}

// TestAHandlerThatOnlySentAnInterimResponseStillGetsAFinalOne: §8.1 lets a server send
// any number of interim responses before the final one, so a 1xx is not an answer and a
// handler that stops there has not written a response.
func TestAHandlerThatOnlySentAnInterimResponseStillGetsAFinalOne(t *testing.T) {
	h := newHarness(t, handlerFunc(func(w *response.Writer, r *Request) {
		if err := w.WriteHeader([]h2.Field{{Name: ":status", Value: "103"}}); err != nil {
			t.Errorf("writing the interim response: %v", err)
		}
	}))

	h.get(1)
	h.waitSent(1)

	r := h.reply(1)
	if len(r.interim) != 1 || value(r.interim[0], ":status") != "103" {
		t.Errorf("the peer sees interim responses %v, want one 103", r.interim)
	}
	if r.status() != "500" || !r.ended {
		t.Errorf("the peer sees final status %q, ended %v; want 500 and an ended stream", r.status(), r.ended)
	}
}

// TestAResponseToAConnectionThatHasStoppedWritingIsGivenUpOn: every write a handler makes
// can fail once the connection's writer has stopped, and the outcome has to be an
// ordinary return rather than a goroutine that spins or blocks. The stream is still
// reported as finished — the table it is reported to is being torn down, and a report it
// ignores costs nothing next to a slot that is never freed.
func TestAResponseToAConnectionThatHasStoppedWritingIsGivenUpOn(t *testing.T) {
	h := newHarness(t, handlerFunc(func(w *response.Writer, r *Request) {
		// Neither error is checked, exactly as a handler under no obligation to check
		// them would leave it: the point is that finish copes either way.
		_ = w.WriteHeader([]h2.Field{{Name: ":status", Value: "200"}})
		_, _ = io.WriteString(w, "into the void")
	}))

	h.out.fail(errors.New("the writer has stopped"))
	h.get(1)
	h.waitSent(1)

	if n := len(h.out.snapshot()); n != 0 {
		t.Errorf("%d frames were collected from a connection that was refusing them", n)
	}
}

// --- requests that are not requests ----------------------------------------

// TestAMalformedHeaderSectionIsRefusedBeforeAnyHandlerRuns is the ordering Headers
// documents. §8.1.1 would permit answering a malformed request after having started to
// process it; not needing the permission is better than using it, and a handler that
// never ran cannot have acted on a request that was never valid.
func TestAMalformedHeaderSectionIsRefusedBeforeAnyHandlerRuns(t *testing.T) {
	var called int
	var mu sync.Mutex
	h := newHarness(t, handlerFunc(func(w *response.Writer, r *Request) {
		mu.Lock()
		called++
		mu.Unlock()
	}))

	// No :path, which §8.3.1 makes mandatory for a request that is not CONNECT.
	err := h.send(h.headers(1, []h2.Field{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "zdh.test"},
	}, true))
	assertStreamError(t, err, 1, h2.ProtocolError, "a request with no :path")

	time.Sleep(20 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if called != 0 {
		t.Errorf("the handler ran %d times for a malformed request, want 0", called)
	}
	if n := len(h.reqs.arriving); n != 0 {
		t.Errorf("a refused request left %d entries recorded as arriving, want 0", n)
	}
}

// TestABodyFrameForARequestThatIsNotArrivingIsAConnectionError reaches a guard the stream
// table cannot: it answers a DATA frame after END_STREAM with §5.1's STREAM_CLOSED and
// never delivers one, so the only way to see what this layer would do is to call it the
// way a broken table would.
//
// Which is the point of the guard. If the two layers ever disagree about what is open,
// one of them is wrong about every stream on the connection, and a stream error would
// paper over it on the one stream that happened to show it.
func TestABodyFrameForARequestThatIsNotArrivingIsAConnectionError(t *testing.T) {
	h := newHarness(t, serve200("x"))

	h.post(1)
	h.mustSend(h.data(1, "done", true))
	s := h.tab.Stream(1)
	if s == nil {
		t.Fatal("stream 1 is gone from the table before its response finished")
	}

	var ce h2.ConnError
	if err := h.reqs.Data(s, []byte("more"), false); !errors.As(err, &ce) || ce.Code != h2.InternalError {
		t.Errorf("a DATA frame for a request that is not arriving gave %v, want a connection error with INTERNAL_ERROR", err)
	}
	if err := h.reqs.Trailers(s, nil); !errors.As(err, &ce) || ce.Code != h2.InternalError {
		t.Errorf("a trailer section for a request that is not arriving gave %v, want a connection error with INTERNAL_ERROR", err)
	}
	h.waitSent(1)
}

// --- construction ----------------------------------------------------------

// TestNewRequiresEverythingItWillDereference pins each guard by the message it gives,
// because the alternative to a panic here is a nil method call inside a handler, on a
// goroutine, with a peer's request in the stack trace.
func TestNewRequiresEverythingItWillDereference(t *testing.T) {
	enc := response.NewEncoder(hpack.New(), &collector{max: 16384})
	full := Config{Handler: serve200("x"), Encoder: enc, Credit: flow.NewSender()}

	cases := []struct {
		what string
		cfg  Config
		want string
	}{
		{"no handler", Config{Encoder: full.Encoder, Credit: full.Credit}, "exchange: New requires a handler"},
		{"no encoder", Config{Handler: full.Handler, Credit: full.Credit}, "exchange: New requires a response encoder"},
		{"no credit", Config{Handler: full.Handler, Encoder: full.Encoder}, "exchange: New requires a source of flow-control credit"},
	}
	for _, c := range cases {
		t.Run(c.what, func(t *testing.T) {
			defer func() {
				got := recover()
				if got == nil {
					t.Fatalf("New with %s returned instead of panicking", c.what)
				}
				if got != c.want {
					t.Errorf("New with %s panicked with %q, want %q", c.what, got, c.want)
				}
			}()
			New(c.cfg)
		})
	}
}

// TestAttachRefusesTheTwoWaysOfGettingItWrong. A nil table is the wiring that forgot the
// call; a second one is the wiring that would send one connection's finished responses to
// another connection's table, which is a bug that would show up as concurrency slots
// leaking on a connection nobody was looking at.
func TestAttachRefusesTheTwoWaysOfGettingItWrong(t *testing.T) {
	cfg := Config{
		Handler: serve200("x"),
		Encoder: response.NewEncoder(hpack.New(), &collector{max: 16384}),
		Credit:  flow.NewSender(),
	}

	t.Run("nil", func(t *testing.T) {
		defer func() {
			if got := recover(); got != "exchange: Attach requires a stream table" {
				t.Errorf("Attach(nil) panicked with %v, want the missing-table message", got)
			}
		}()
		New(cfg).Attach(nil)
	})

	t.Run("twice", func(t *testing.T) {
		r := New(cfg)
		r.Attach(&reports{})
		defer func() {
			if got := recover(); got != "exchange: the stream table is already attached" {
				t.Errorf("a second Attach panicked with %v, want the already-attached message", got)
			}
		}()
		r.Attach(&reports{})
	})
}

// --- everything at once ----------------------------------------------------

// TestManyStreamsAtOnce is the race detector's test for this layer. Sixteen streams, each
// with a body arriving in pieces, each answered by a handler reading it as it comes,
// while the reader goroutine interleaves their frames — which is the shape of a real
// connection and the shape no single-stream test has.
//
// The assertion is that every response is complete and correct, and that -race says
// nothing about the two things that cross between the goroutines: the bodies going one
// way and the finished responses coming back.
func TestManyStreamsAtOnce(t *testing.T) {
	h := newHarness(t, handlerFunc(func(w *response.Writer, r *Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("stream %s: reading the body: %v", r.Path, err)
			return
		}
		body := fmt.Sprintf("%s:%s", r.Path, b)
		if err := w.WriteHeader([]h2.Field{
			{Name: ":status", Value: "200"},
			{Name: "content-length", Value: fmt.Sprint(len(body))},
		}); err != nil {
			t.Errorf("stream %s: writing the header section: %v", r.Path, err)
			return
		}
		if _, err := io.WriteString(w, body); err != nil {
			t.Errorf("stream %s: writing the body: %v", r.Path, err)
		}
		if err := w.Close(); err != nil {
			t.Errorf("stream %s: closing: %v", r.Path, err)
		}
	}))

	const streams = 16
	ids := make([]uint32, 0, streams)
	for id := uint32(1); id <= streams*2-1; id += 2 {
		ids = append(ids, id)
		h.post(id, h2.Field{Name: "content-length", Value: "6"})
	}
	// Interleaved rather than one stream at a time: three rounds of two octets each,
	// so every stream is part-way through its body while every other one is too.
	for round := 0; round < 3; round++ {
		for _, id := range ids {
			h.mustSend(h.data(id, fmt.Sprintf("%02d", round), round == 2))
		}
	}

	for _, id := range ids {
		h.waitSent(id)
	}
	for _, id := range ids {
		r := h.reply(id)
		want := fmt.Sprintf("/%d:000102", id)
		if r.status() != "200" || r.body != want || !r.ended {
			t.Errorf("stream %d: status %q body %q ended %v; want 200, %q, true",
				id, r.status(), r.body, r.ended, want)
		}
	}
	if n := len(h.reqs.arriving); n != 0 {
		t.Errorf("%d requests are still recorded as arriving after all %d finished, want 0", n, streams)
	}
}

// --- returning receive-window credit ----------------------------------------

// TestContentAHandlerReadsIsReportedToTheTable pins the wiring between the two halves of
// this package and the stream table above them.
//
// The Body knows how many octets a handler took; only the table can turn that into the
// WINDOW_UPDATE the peer is waiting for. What is easy to get wrong in between is the
// stream identifier — a report is one uint32 and there are three streams here, so a body
// built with the wrong one would return credit on somebody else's window and stall the
// upload it belonged to while inflating a window nobody was spending.
func TestContentAHandlerReadsIsReportedToTheTable(t *testing.T) {
	read := make(chan int, 1)
	h := newHarness(t, handlerFunc(func(w *response.Writer, r *Request) {
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			t.Errorf("the handler could not read its body: %v", err)
		}
		read <- int(n)
		_ = w.WriteBodylessHeader([]h2.Field{{Name: ":status", Value: "204"}})
	}))

	// Three uploads at once, so that a report naming the wrong stream is visible as a
	// wrong total rather than only as a wrong sum.
	const body = "the content of one upload"
	for _, id := range []uint32{1, 3, 5} {
		h.post(id)
		h.mustSend(h.data(id, body, true))
	}
	for range 3 {
		if got := <-read; got != len(body) {
			t.Fatalf("a handler read %d octets, want %d", got, len(body))
		}
	}
	for _, id := range []uint32{1, 3, 5} {
		h.waitSent(id)
		if got, want := h.rep.credited(id), len(body); got != want {
			t.Errorf("stream %d reported %d octets of content consumed, want %d", id, got, want)
		}
	}
}

// TestAHandlerThatReadsNothingReturnsNoCredit.
//
// A handler is not obliged to read the request body — a 405 for a POST is the commonest
// case in this server, and internal/static answers one without looking at the content.
// The octets it did not read are octets the peer's window stays short of, which is
// correct: returning credit for content nobody consumed is how a bound stops being one.
func TestAHandlerThatReadsNothingReturnsNoCredit(t *testing.T) {
	h := newHarness(t, serve200("answered without reading the body"))

	h.post(1)
	h.mustSend(h.data(1, "content the handler will never look at", true))
	h.waitSent(1)

	if got := h.rep.credited(1); got != 0 {
		t.Errorf("a handler that read nothing reported %d octets consumed, want 0", got)
	}
}
