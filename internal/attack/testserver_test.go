package attack

import (
	"bytes"
	"encoding/hex"
	"log"
	"net"
	"sync"
	"testing"

	"zerodeps/zdh/internal/exchange"
	"zerodeps/zdh/internal/flow"
	"zerodeps/zdh/internal/h2"
	"zerodeps/zdh/internal/hpack"
	"zerodeps/zdh/internal/response"
	"zerodeps/zdh/internal/server"
	"zerodeps/zdh/internal/stream"
)

// serverLog captures the server's ErrorLog output. It exists because a
// closed-connection race is inherent to the CVE tests, not a bug in them:
// the server closes the socket the instant its defense fires, and on
// Windows a close with unread bytes still in the kernel receive buffer
// becomes a TCP RST, which can reach this process before — and along the
// way discard — the GOAWAY frame that was written first. The log line is
// written by the same code, at the moment it decides, independent of
// however the OS chooses to sequence the socket teardown, so it is the
// deterministic half of the assertion when the wire race goes the wrong
// way. Safe for concurrent use: the server logs from its own connection
// goroutine while the test reads it from the main one.
type serverLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *serverLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *serverLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// minimalHandler answers every request with a bare 200 and no body. The two
// CVEs this package tests both live below the request/response layer — in
// the dynamic table's rate limiting and the frame reader's block limits —
// so a handler only has to be correct enough not to get in the way.
type minimalHandler struct{}

func (minimalHandler) Serve(w *response.Writer, r *exchange.Request) {
	w.WriteHeader([]h2.Field{{Name: ":status", Value: "200"}})
}

// streamHandler adapts internal/stream and internal/exchange to
// server.StreamHandler, mirroring cmd/zdh/serve.go's newConn: the stream
// table is embedded so its methods satisfy the interface directly, and
// Close is overridden to end both the table and the request layer, since
// internal/server holds only one Closer per connection but this stack has
// two things that park goroutines.
type streamHandler struct {
	*stream.Table
	reqs *exchange.Requests
}

var _ server.StreamHandler = streamHandler{}

func (h streamHandler) Close(err error) {
	h.Table.Close(err)
	h.reqs.Close(err)
}

// startTestServer starts a real zdh server — internal/server driving
// internal/stream, internal/exchange and internal/response exactly as
// cmd/zdh wires them, against this package's own internal/hpack.Codec — on
// a loopback port. It returns the address and the captured error log. The
// server is closed when the test ends.
func startTestServer(t *testing.T) (addr string, logs *serverLog) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	logs = &serverLog{}
	srv := server.New(func(w server.ConnWriter) server.StreamHandler {
		enc := response.NewEncoder(hpack.New(), w)
		sender := flow.NewSender()

		reqs := exchange.New(exchange.Config{
			Handler: minimalHandler{},
			Encoder: enc,
			Credit:  sender,
		})

		tab := stream.New(stream.Config{
			Codec:    hpack.New(),
			Requests: reqs,
			Encoder:  enc,
			Writer:   w,
			Sender:   sender,
		})
		reqs.Attach(tab)

		return streamHandler{Table: tab, reqs: reqs}
	}, server.Config{
		ErrorLog: log.New(logs, "", 0),
	})

	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	return ln.Addr().String(), logs
}

// requestBlock is one complete, valid HPACK header block (RFC 7541 Appendix
// C.3.1: :method GET, :scheme http, :path /, :authority www.example.com),
// reused for every stream a test opens. Reusing it is deliberate and
// harmless: each reuse of the literal :authority representation adds
// another entry to the server's dynamic table, which just evicts the oldest
// once the table fills — exactly the kind of repetition a real client
// produces and the server has to cope with regardless.
var requestBlock = mustHexBytes("828684410f7777772e6578616d706c652e636f6d")

func mustHexBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
