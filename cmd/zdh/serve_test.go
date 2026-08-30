package main

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"zerodeps/zdh/internal/exchange"
	"zerodeps/zdh/internal/frame"
	"zerodeps/zdh/internal/h2"
	"zerodeps/zdh/internal/hpack"
	"zerodeps/zdh/internal/priority"
	"zerodeps/zdh/internal/response"
	"zerodeps/zdh/internal/server"
	"zerodeps/zdh/internal/static"
)

// The tests in this file are the only ones in the module that exercise the whole
// stack at once, and that is what they are for. Every package under internal/ is
// tested against its own interfaces, which is what keeps them independent — and
// which means no unit test anywhere can catch two packages wired to each other
// wrongly. newConn is where that wiring lives, and it is a factory returning a
// closure, so the only honest way to test it is to speak HTTP/2 at what it built
// and read the answer off a socket.

// serveTemp starts a server on an ephemeral port serving a directory holding
// files, and returns the server and its address. Everything is torn down when the
// test ends.
func serveTemp(t *testing.T, files map[string]string) (*server.Server, string) {
	t.Helper()

	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("writing the file to serve: %v", err)
		}
	}

	h, err := static.New(static.Config{Dir: dir})
	if err != nil {
		t.Fatalf("opening the directory to serve: %v", err)
	}
	t.Cleanup(func() { h.Close() })

	return serveHandler(t, h)
}

// serveHandler starts a server on an ephemeral port running one handler.
func serveHandler(t *testing.T, h exchange.Handler) (*server.Server, string) {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}

	// A nil error log discards, which is right here: a test that ends a connection
	// abruptly is a test doing its job, and the lines would be noise. The tests
	// that care about a failure observe it on the wire instead.
	srv := server.New(newConn(h, nil), server.Config{})

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv.Serve(l)
	}()
	t.Cleanup(func() {
		srv.Close()
		wg.Wait()
	})

	return srv, l.Addr().String()
}

// client is a minimal HTTP/2 client built out of this module's own frame layer.
//
// It is deliberately not a general one: it speaks only what these tests need,
// and it fails the test on anything it did not expect rather than trying to
// recover. A lenient test client hides exactly the bugs this file exists to find.
type client struct {
	t  *testing.T
	nc net.Conn
	w  *frame.Writer
	rd *frame.Reader

	// Two codecs for the same reason the server has two: a dynamic table is a
	// history of one direction of one connection. Encoding requests against the
	// table the responses are decoded with would answer index lookups with the
	// other direction's entries.
	enc *hpack.Codec
	dec *hpack.Codec
}

// dial connects and completes the client half of the connection preface (§3.4):
// the 24-octet magic followed by a SETTINGS frame.
func dial(t *testing.T, addr string) *client {
	t.Helper()

	nc, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dialling: %v", err)
	}
	t.Cleanup(func() { nc.Close() })

	c := &client{
		t:   t,
		nc:  nc,
		w:   frame.NewWriter(nc, frame.WriterConfig{}),
		rd:  frame.NewReader(nc, frame.ReaderConfig{}),
		enc: hpack.New(),
		dec: hpack.New(),
	}

	if _, err := nc.Write([]byte(frame.ClientPreface)); err != nil {
		t.Fatalf("writing the connection preface: %v", err)
	}
	c.write(frame.SettingsFrame{})
	return c
}

func (c *client) write(f frame.Frame) {
	c.t.Helper()
	if err := c.w.WriteFrame(f); err != nil {
		c.t.Fatalf("writing a %s frame: %v", f.Type(), err)
	}
}

// get opens a stream with a complete request and no body.
func (c *client) get(id uint32, path string) {
	c.t.Helper()
	c.request(id, []h2.Field{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "http"},
		{Name: ":authority", Value: "127.0.0.1"},
		{Name: ":path", Value: path},
	})
}

func (c *client) request(id uint32, fields []h2.Field) {
	c.t.Helper()
	c.write(frame.HeadersFrame{
		StreamID:   id,
		EndStream:  true,
		EndHeaders: true,
		Fragment:   c.enc.Encode(fields),
	})
}

// resp is one response as the client saw it arrive.
type resp struct {
	fields []h2.Field
	body   []byte
}

func (r resp) get(name string) string {
	for _, f := range r.fields {
		if f.Name == name {
			return f.Value
		}
	}
	return ""
}

// collect reads frames until every stream in want has ended, answering the
// connection-level frames a server is entitled to send in the meantime.
//
// One loop for all of them rather than one call per stream, because that is the
// only way to read a multiplexed connection: the frames of several responses
// arrive interleaved, and a reader that waited for one stream at a time would
// deadlock the moment a server chose to finish them in a different order.
func (c *client) collect(want ...uint32) map[uint32]*resp {
	c.t.Helper()

	out := make(map[uint32]*resp, len(want))
	for _, id := range want {
		out[id] = &resp{}
	}

	for left := len(want); left > 0; {
		f, err := c.rd.ReadFrame()
		if err != nil {
			c.t.Fatalf("reading a frame with %d stream(s) unfinished: %v", left, err)
		}

		stream := func() *resp {
			r := out[f.Stream()]
			if r == nil {
				c.t.Fatalf("a %s frame arrived on stream %d, which this test never opened",
					f.Type(), f.Stream())
			}
			return r
		}

		switch v := f.(type) {
		case frame.SettingsFrame:
			// §6.5.3 requires an acknowledgement, and the server holds a deadline
			// for it. A test client that ignored this would be closed mid-test
			// after ten seconds for a reason that looks like a server bug.
			if !v.Ack {
				c.write(frame.SettingsFrame{Ack: true})
			}

		case frame.PingFrame:
			if !v.Ack {
				c.write(frame.PingFrame{Ack: true, Data: v.Data})
			}

		case frame.WindowUpdateFrame:
			// Credit for a request body. These tests send none, so there is
			// nothing to spend it on.

		case frame.GoAwayFrame:
			c.t.Fatalf("the server sent GOAWAY(%v, last stream %d): %q",
				v.ErrCode, v.LastStreamID, v.Debug)

		case frame.RSTStreamFrame:
			c.t.Fatalf("the server reset stream %d: %v", v.StreamID, v.ErrCode)

		case frame.HeadersFrame:
			r := stream()
			// A fragment is not a block. Decoding one would corrupt the dynamic
			// table and mis-decode every response after it, so this asserts rather
			// than accommodates: these responses are small and a CONTINUATION here
			// would itself be the finding.
			if !v.EndHeaders {
				c.t.Fatalf("stream %d: the header block continued past the HEADERS frame", v.StreamID)
			}
			fields, err := c.dec.Decode(v.Fragment)
			if err != nil {
				c.t.Fatalf("stream %d: decoding the header block: %v", v.StreamID, err)
			}
			r.fields = append(r.fields, fields...)
			if v.EndStream {
				left--
			}

		case frame.DataFrame:
			r := stream()
			r.body = append(r.body, v.Data...)
			if v.EndStream {
				left--
			}

		default:
			c.t.Fatalf("unexpected %s frame on stream %d", f.Type(), f.Stream())
		}
	}
	return out
}

// The wiring test. Three requests on one connection: a file, something absent,
// and the same file again.
//
// One at a time, each response read before the next request is sent, and that
// ordering is the whole test. HPACK's dynamic table is connection state on both
// sides, and an encoder that indexes an entry its peer's table does not hold at
// that index produces field lines nobody sent. Requests written back to back
// cannot show it: the server's reader decodes all three before a handler has
// opened a file, so the tables never get the chance to diverge, and the two
// codecs in newConn could be collapsed into one with every assertion below still
// passing. Sent in sequence — which is what a browser does, one navigation and
// then its subresources — the second response is encoded against a table the
// first request has already been added to, and the client decodes gibberish.
func TestServeOneConnectionManyRequests(t *testing.T) {
	const body = "the body of a file served over a connection nobody wrote net/http for\n"
	_, addr := serveTemp(t, map[string]string{"a.txt": body})

	c := dial(t, addr)

	got := make(map[uint32]*resp, 3)
	for _, rq := range []struct {
		id   uint32
		path string
	}{
		{1, "/a.txt"},
		{3, "/nothing-here.txt"},
		{5, "/a.txt"},
	} {
		c.get(rq.id, rq.path)
		got[rq.id] = c.collect(rq.id)[rq.id]
	}

	for _, id := range []uint32{1, 5} {
		r := got[id]
		if s := r.get(":status"); s != "200" {
			t.Errorf("stream %d: status %q, want 200", id, s)
		}
		if string(r.body) != body {
			t.Errorf("stream %d: body %q, want %q", id, r.body, body)
		}
		if ct := r.get("content-type"); !strings.HasPrefix(ct, "text/plain") {
			t.Errorf("stream %d: content-type %q, want text/plain", id, ct)
		}
		// The length is the file's, and a client that trusted it would hang or
		// truncate if it disagreed with what arrived.
		if cl := r.get("content-length"); cl != strconv.Itoa(len(body)) {
			t.Errorf("stream %d: content-length %q, want %d", id, cl, len(body))
		}
	}

	if s := got[3].get(":status"); s != "404" {
		t.Errorf("stream 3: status %q for an absent file, want 404", s)
	}
	// A stream that produced no response at all also ends with no fields, so the
	// absence of a status would pass the check above as a mismatch rather than as
	// the missing response it is. Worth its own assertion.
	if len(got[3].fields) == 0 {
		t.Error("stream 3: the response carried no header fields at all")
	}
}

// Every stream opened before any response is read. This is the multiplexing the
// entry is about, and it is also the only test here that can catch the stream
// table and the send-side flow control disagreeing: eight concurrent handlers all
// reserve credit from one connection window.
func TestServeConcurrentStreams(t *testing.T) {
	const body = "concurrent\n"
	_, addr := serveTemp(t, map[string]string{"a.txt": body})

	c := dial(t, addr)

	var ids []uint32
	for id := uint32(1); id <= 31; id += 2 {
		c.get(id, "/a.txt")
		ids = append(ids, id)
	}

	got := c.collect(ids...)
	for _, id := range ids {
		if s := got[id].get(":status"); s != "200" {
			t.Errorf("stream %d: status %q, want 200", id, s)
		}
		if string(got[id].body) != body {
			t.Errorf("stream %d: body %q, want %q", id, got[id].body, body)
		}
	}
}

// A request the static handler answers with a status and no file, which is the
// other path through the response encoder: a body it generated rather than one it
// copied from a file handle.
func TestServeRefusesAMethodItCannotAnswer(t *testing.T) {
	_, addr := serveTemp(t, map[string]string{"a.txt": "x\n"})

	c := dial(t, addr)
	c.request(1, []h2.Field{
		{Name: ":method", Value: "DELETE"},
		{Name: ":scheme", Value: "http"},
		{Name: ":authority", Value: "127.0.0.1"},
		{Name: ":path", Value: "/a.txt"},
	})

	r := c.collect(1)[1]
	if s := r.get(":status"); s != "405" {
		t.Errorf("status %q for DELETE, want 405", s)
	}
	// §15.5.6 requires the field, and a 405 without it tells a client it guessed
	// wrong without telling it what to guess next.
	if allow := r.get("allow"); !strings.Contains(allow, "GET") {
		t.Errorf("allow is %q, want it to name GET", allow)
	}
}

// Shutdown must reach a connection that is idle but open, and it must reach it
// with a GOAWAY rather than by dropping the socket: a client that is told is a
// client that can retry on a new connection, and one that is not sees a
// truncated stream.
func TestServeShutdownSendsGoAway(t *testing.T) {
	srv, addr := serveTemp(t, map[string]string{"a.txt": "x\n"})

	c := dial(t, addr)
	c.get(1, "/a.txt")
	if s := c.collect(1)[1].get(":status"); s != "200" {
		t.Fatalf("the connection did not serve a request before shutdown: status %q", s)
	}

	// Shutdown blocks until the connections are gone, and this connection only
	// goes once it has read the GOAWAY below, so the two have to overlap.
	done := make(chan error, 1)
	go func() { done <- srv.Shutdown() }()

	c.awaitGoAway()

	if err := <-done; err != nil {
		t.Errorf("Shutdown = %v, want no error", err)
	}
}

// awaitGoAway reads past whatever is in flight to the connection's GOAWAY and
// checks it says the shutdown was graceful.
//
// Under a deadline, because the failure this guards against is a shutdown that
// never sends one — and a test that hung would report that as a timeout of the
// whole package rather than as the one assertion that failed.
func (c *client) awaitGoAway() {
	c.t.Helper()

	if err := c.nc.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		c.t.Fatalf("setting a read deadline: %v", err)
	}
	defer c.nc.SetReadDeadline(time.Time{})

	for {
		f, err := c.rd.ReadFrame()
		if err != nil {
			c.t.Fatalf("reading frames while shutting down: %v", err)
		}
		g, ok := f.(frame.GoAwayFrame)
		if !ok {
			continue
		}
		// NO_ERROR is what makes it a graceful shutdown rather than a fault: §6.8
		// gives the client the right to retry everything above the last stream,
		// and a different code would tell it not to.
		if g.ErrCode != h2.NoError {
			c.t.Errorf("GOAWAY carried %v, want NO_ERROR", g.ErrCode)
		}
		// Stream 1 was served, so the client must not be told to retry it.
		if g.LastStreamID < 1 {
			c.t.Errorf("GOAWAY names last stream %d, but stream 1 was answered", g.LastStreamID)
		}
		return
	}
}

// lockedBuffer is a buffer written by the server's goroutine and read by the
// test's. The mutex is not decoration: without it this test is the one place in
// the suite where -race has something true to say.
type lockedBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// listening waits for serve to print the line naming the address it bound, and
// returns that address. Polled rather than synchronised, because the thing being
// waited for is a line of output on the way to a judge's terminal and there is no
// channel to wait on that would not exist purely for this test.
func (l *lockedBuffer) listening(t *testing.T) string {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for {
		for _, line := range strings.Split(l.String(), "\n") {
			_, rest, ok := strings.Cut(line, "listening    http://")
			if !ok {
				continue
			}
			addr, _, ok := strings.Cut(rest, "/")
			if ok {
				return addr
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("serve never printed a listening line:\n%s", l.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// serve itself, which is the function a judge runs: the startup lines, a request
// answered on the port it says it bound, and the interrupt bringing it down.
//
// h2c only, so no certificate is generated. What a generated certificate contains
// is certHosts's business and is tested there; what this test is about is that the
// whole of serve holds together, and an RSA key pair in the middle of it would buy
// nothing but seconds.
func TestServeAnswersOnThePortItPrints(t *testing.T) {
	const body = "served by serve\n"

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte(body), 0o600); err != nil {
		t.Fatalf("writing the file to serve: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var out lockedBuffer
	done := make(chan error, 1)
	go func() {
		done <- serve(ctx, &options{dir: dir, h2cAddr: "127.0.0.1:0"}, &out)
	}()

	addr := out.listening(t)

	// The directory is named before the port, because the first question about a
	// server nobody has run is what it is serving.
	if !strings.Contains(out.String(), "serving      ") {
		t.Errorf("serve did not print what it serves:\n%s", out.String())
	}
	// No TLS port was asked for, so no certificate may be generated. A server that
	// wrote a key pair into the working directory for a cleartext run would be
	// leaving files behind for no reason.
	if strings.Contains(out.String(), "certificate") {
		t.Errorf("serve generated a certificate for a cleartext-only run:\n%s", out.String())
	}

	c := dial(t, addr)
	c.get(1, "/a.txt")
	r := c.collect(1)[1]
	if s := r.get(":status"); s != "200" {
		t.Errorf("status %q, want 200", s)
	}
	if string(r.body) != body {
		t.Errorf("body %q, want %q", r.body, body)
	}

	// The interrupt. The connection is still open, so this exercises the path that
	// matters: a shutdown that has to reach a live peer rather than an empty server.
	cancel()
	c.awaitGoAway()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("serve = %v, want no error after an interrupt", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("serve did not return after its context was cancelled")
	}

	if !strings.Contains(out.String(), "shutting down") {
		t.Errorf("serve did not say it was shutting down:\n%s", out.String())
	}
}

// parker is a handler that reads its request body and reports what the read
// returned. It is what makes the second half of streamHandler.Close observable.
type parker struct {
	entered chan struct{}
	woke    chan error
}

func (p parker) Serve(w *response.Writer, r *exchange.Request) {
	close(p.entered)
	_, err := io.Copy(io.Discard, r.Body)
	p.woke <- err
}

// The leak streamHandler.Close exists to prevent, and the only test in the module
// that can see it.
//
// A handler reading an upload waits on a condition variable inside the request
// layer, not on the socket. Closing the socket does not reach it and neither does
// stopping the frame writer, so a peer that hangs up mid-upload would leave the
// goroutine parked for the life of the process, holding a request, a response and
// a stack. Nothing under internal/ can test this: the stream table ends the send
// side and the request layer ends the receive side, the two do not know about each
// other, and cmd/zdh is the only place that holds both.
func TestPeerHangingUpMidUploadWakesTheHandler(t *testing.T) {
	p := parker{entered: make(chan struct{}), woke: make(chan error, 1)}
	_, addr := serveHandler(t, p)

	c := dial(t, addr)

	// No END_STREAM, so the stream stays open expecting content, and no DATA
	// follows it. The handler reaches its first read and stays there.
	c.write(frame.HeadersFrame{
		StreamID:   1,
		EndHeaders: true,
		Fragment: c.enc.Encode([]h2.Field{
			{Name: ":method", Value: "POST"},
			{Name: ":scheme", Value: "http"},
			{Name: ":authority", Value: "127.0.0.1"},
			{Name: ":path", Value: "/"},
		}),
	})

	select {
	case <-p.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the handler was never entered")
	}

	// The peer hangs up mid-upload, which is the ordinary case and not an attack:
	// a browser whose tab is closed during a file upload does exactly this.
	c.nc.Close()

	select {
	case err := <-p.woke:
		if err == nil {
			t.Error("the body reported a clean end for an upload that was cut off")
		}
		// io.EOF would mean the handler was woken by the stream ending normally,
		// which it did not, and would let this test pass with the teardown removed.
		if errors.Is(err, io.EOF) {
			t.Error("the body reported io.EOF rather than the reason the connection ended")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the handler is still parked reading a body from a connection that is gone")
	}
}

// drainer is a handler that reads its whole request body and reports how many
// bytes it saw.
type drainer struct{ got chan int64 }

func (d drainer) Serve(w *response.Writer, r *exchange.Request) {
	n, err := io.Copy(io.Discard, r.Body)
	if err != nil {
		d.got <- -1
		return
	}
	_ = w.WriteBodylessHeader([]h2.Field{{Name: ":status", Value: "204"}})
	d.got <- n
}

// A body larger than one receive window, which is the case that cannot work
// without the server returning credit for what its handler has consumed.
//
// §6.9.2 starts every receive window at 65535 octets, and §6.9 says a peer must
// not send more than it has been granted. So a client that obeys flow control —
// which is every real one — can upload exactly 65535 bytes and then must wait.
// A server that never sends WINDOW_UPDATE does not refuse the rest of that
// upload: it stalls, holding a handler and a stream, until one side gives up.
// That is worse than a 413, because nothing on either end says what happened.
func TestServeReplenishesTheReceiveWindow(t *testing.T) {
	const (
		window = 65535           // §6.9.2's initial value, and what the peer may send
		body   = window + 40_000 // enough that the rest needs credit that has to be returned
	)

	d := drainer{got: make(chan int64, 1)}
	_, addr := serveHandler(t, d)

	c := dial(t, addr)
	c.write(frame.HeadersFrame{
		StreamID:   1,
		EndHeaders: true,
		Fragment: c.enc.Encode([]h2.Field{
			{Name: ":method", Value: "POST"},
			{Name: ":scheme", Value: "http"},
			{Name: ":authority", Value: "127.0.0.1"},
			{Name: ":path", Value: "/"},
		}),
	})

	// Exactly the window, and not one octet more: sending past it would be this
	// client's protocol violation and the server would be right to end the
	// connection, which would hide the thing being tested.
	sent := c.sendData(1, window, false)

	// The credit has to come back on both windows. A server that replenished only
	// the stream would stall the next upload on the connection instead of this one,
	// which is the same bug one connection later.
	c.awaitCredit(1, window)

	c.sendData(1, body-sent, true)

	select {
	case n := <-d.got:
		if n != body {
			t.Errorf("the handler read %d bytes, want %d", n, body)
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("the handler is still reading after %d of %d bytes were sent", sent, body)
	}
}

// sendData writes n bytes of content as DATA frames no larger than the peer is
// obliged to accept (§4.2's 16384 default), and returns how many it sent.
func (c *client) sendData(id uint32, n int, endStream bool) int {
	c.t.Helper()

	const max = 1 << 14
	chunk := make([]byte, max)
	for i := range chunk {
		chunk[i] = byte('a' + i%26)
	}

	for sent := 0; sent < n; {
		size := min(max, n-sent)
		sent += size
		c.write(frame.DataFrame{
			StreamID:  id,
			EndStream: endStream && sent == n,
			Data:      chunk[:size],
		})
	}
	return n
}

// awaitCredit reads frames until the peer has returned at least want octets of
// credit on both the stream and the connection.
//
// Under a deadline, because the failure it guards against is credit that never
// arrives: a test that waited for ever would report this as the package timing
// out rather than as the one window that was not replenished.
func (c *client) awaitCredit(id uint32, want uint32) {
	c.t.Helper()

	if err := c.nc.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		c.t.Fatalf("setting a read deadline: %v", err)
	}
	defer c.nc.SetReadDeadline(time.Time{})

	var conn, stream uint32
	for conn < want || stream < want {
		f, err := c.rd.ReadFrame()
		if err != nil {
			c.t.Fatalf("waiting for credit (connection %d, stream %d of %d octets): %v",
				conn, stream, want, err)
		}
		switch v := f.(type) {
		case frame.SettingsFrame:
			if !v.Ack {
				c.write(frame.SettingsFrame{Ack: true})
			}
		case frame.PingFrame:
			if !v.Ack {
				c.write(frame.PingFrame{Ack: true, Data: v.Data})
			}
		case frame.WindowUpdateFrame:
			if v.StreamID == 0 {
				conn += v.Increment
			} else if v.StreamID == id {
				stream += v.Increment
			}
		case frame.GoAwayFrame:
			c.t.Fatalf("the server sent GOAWAY(%v) instead of credit: %q", v.ErrCode, v.Debug)
		case frame.RSTStreamFrame:
			c.t.Fatalf("the server reset stream %d instead of sending credit: %v", v.StreamID, v.ErrCode)
		}
	}
}

// --- the wiring no other test can see ---------------------------------------

// recorder is a connection's write half that keeps what it was told about priority and
// throws away the frames.
//
// It exists for one assertion, and the assertion needs a double rather than a socket
// because what is being checked is a call and not an octet. Safe from every goroutine,
// because the real writer is: a handler's goroutine reaches Enqueue and Forget while the
// reader goroutine reaches Prioritize.
type recorder struct {
	mu    sync.Mutex
	prios []uint32
}

func (r *recorder) Enqueue(frame.Frame) error { return nil }
func (r *recorder) MaxFrameSize() uint32      { return frame.DefaultMaxFrameSize }
func (r *recorder) Forget(uint32)             {}

func (r *recorder) Prioritize(id uint32, p priority.Params) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prios = append(r.prios, id)
}

func (r *recorder) prioritized() []uint32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]uint32(nil), r.prios...)
}

// The Priority header field is read by internal/exchange and acted on by
// internal/server, and the line that connects them is one field in one composite
// literal in newConn.
//
// Nothing else in the module would notice it missing. exchange.Config.Priorities is
// allowed to be nil — §10 of RFC 9218 makes acting on a priority signal a
// recommendation, so a server that ignores one is conformant — which means a forgotten
// field is not a build failure. It is not a wire-visible failure either: every request
// is still answered, and every response is still scheduled, just all at the same
// urgency. The tests above this one would all pass.
//
// So this one calls newConn with its own write half and watches for the call. No socket,
// no preface and no timing: Headers runs on the goroutine that delivered the frame, so
// by the time HandleFrame has returned the signal has either been made or lost.
func TestNewConnGivesTheRequestLayerSomewhereToSendAPriorityField(t *testing.T) {
	w := &recorder{}
	h := drainer{got: make(chan int64, 1)}
	sh := newConn(h, nil)(w)
	t.Cleanup(func() { sh.Close(errors.New("the test is over")) })

	enc := hpack.New()
	err := sh.HandleFrame(frame.HeadersFrame{
		StreamID:   1,
		EndStream:  true,
		EndHeaders: true,
		Fragment: enc.Encode([]h2.Field{
			{Name: ":method", Value: "GET"},
			{Name: ":scheme", Value: "http"},
			{Name: ":authority", Value: "127.0.0.1"},
			{Name: ":path", Value: "/"},
			{Name: "priority", Value: "u=0"},
		}),
	})
	if err != nil {
		t.Fatalf("delivering the request: %v", err)
	}

	if got := w.prioritized(); len(got) != 1 || got[0] != 1 {
		t.Errorf("the write half was told to prioritize %v, want [1]: newConn has to pass "+
			"itself to exchange.Config.Priorities or the Priority header field of every "+
			"request is read and discarded", got)
	}
}
