package attack

import (
	"bytes"
	"encoding/hex"
	"log"
	"net"
	"sync"
	"testing"

	"zerodeps/zdh/internal/h2"
	"zerodeps/zdh/internal/hpack"
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

// noopRequests is the minimal stream.Requests: request semantics (RFC 9113
// §8, static file handler) are the other half of this project and not built
// yet, but the two CVEs below live entirely below that layer — in the
// dynamic table's rate limiting and the frame reader's block limits — so a
// handler that does nothing is sufficient to prove they fire.
type noopRequests struct{}

func (noopRequests) Headers(s *stream.Stream, fields []h2.Field, endStream bool) error {
	return nil
}
func (noopRequests) Data(s *stream.Stream, b []byte, endStream bool) error { return nil }
func (noopRequests) Trailers(s *stream.Stream, fields []h2.Field) error    { return nil }
func (noopRequests) Canceled(s *stream.Stream, code h2.ErrCode)            {}

// startTestServer starts a real zdh server (Manas's internal/server, driving
// internal/stream against this package's own internal/hpack.Codec) on a
// loopback port and returns its address and its captured error log. The
// server is closed when the test ends.
func startTestServer(t *testing.T) (addr string, logs *serverLog) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	logs = &serverLog{}
	srv := server.New(func(server.FrameEnqueuer) server.StreamHandler {
		return stream.New(stream.Config{
			Codec:    hpack.New(),
			Requests: noopRequests{},
		})
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
