package attack

import (
	"net"
	"testing"
	"time"

	"zerodeps/zdh/internal/frame"
	"zerodeps/zdh/internal/h2"
)

// fakeServer is a minimal stand-in for zdh's real server: just enough of
// RFC 9113's opening handshake to let this package's own client logic be
// tested without depending on internal/server, whose stream layer is still
// being built by the other half of this project (see README in this
// package). It is not a conformance server and makes no claim to be one.
type fakeServer struct {
	ln net.Listener
}

func newFakeServer(t *testing.T) (*fakeServer, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	return &fakeServer{ln: ln}, ln.Addr().String()
}

// acceptOne accepts a single connection, reads the preface and the
// client's SETTINGS frame, and replies with its own SETTINGS frame. It
// returns the accepted connection's reader/writer so the test can keep
// driving the exchange.
func (s *fakeServer) acceptOne(t *testing.T) (*frame.Reader, *frame.Writer, net.Conn) {
	t.Helper()
	nc, err := s.ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	rd := frame.NewReader(nc, frame.ReaderConfig{})
	wr := frame.NewWriter(nc, frame.WriterConfig{})

	if err := rd.ReadPreface(); err != nil {
		t.Fatalf("read preface: %v", err)
	}
	if _, err := rd.ReadFrame(); err != nil { // the client's initial SETTINGS
		t.Fatalf("read client settings: %v", err)
	}
	if err := wr.WriteFrame(frame.SettingsFrame{}); err != nil {
		t.Fatalf("write server settings: %v", err)
	}
	return rd, wr, nc
}

func TestDialCompletesHandshake(t *testing.T) {
	srv, addr := newFakeServer(t)

	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.acceptOne(t)
	}()

	c, err := Dial(addr, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	<-done

	f, err := c.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if _, ok := f.(frame.SettingsFrame); !ok {
		t.Fatalf("got %T, want frame.SettingsFrame", f)
	}
}

func TestOpenStreamThenReset(t *testing.T) {
	srv, addr := newFakeServer(t)

	frames := make(chan frame.Frame, 4)
	go func() {
		_, _, nc := srv.acceptOne(t)
		defer nc.Close()
		rd := frame.NewReader(nc, frame.ReaderConfig{})
		for i := 0; i < 2; i++ {
			f, err := rd.ReadFrame()
			if err != nil {
				return
			}
			frames <- f
		}
	}()

	c, err := Dial(addr, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if err := c.OpenStream(1, []byte{0x82}, false); err != nil { // :method: GET
		t.Fatalf("OpenStream: %v", err)
	}
	if err := c.Reset(1, h2.Cancel); err != nil {
		t.Fatalf("Reset: %v", err)
	}

	got := []frame.Frame{<-frames, <-frames}
	h, ok := got[0].(frame.HeadersFrame)
	if !ok || h.StreamID != 1 || !h.EndHeaders {
		t.Fatalf("first frame = %+v, want a complete HEADERS on stream 1", got[0])
	}
	r, ok := got[1].(frame.RSTStreamFrame)
	if !ok || r.StreamID != 1 || r.ErrCode != h2.Cancel {
		t.Fatalf("second frame = %+v, want RST_STREAM(1, CANCEL)", got[1])
	}
}

func TestOpenStreamWithoutEndHeadersThenContinue(t *testing.T) {
	srv, addr := newFakeServer(t)

	frames := make(chan frame.Frame, 4)
	go func() {
		_, _, nc := srv.acceptOne(t)
		defer nc.Close()
		rd := frame.NewReader(nc, frame.ReaderConfig{})
		for i := 0; i < 2; i++ {
			f, err := rd.ReadFrame()
			if err != nil {
				return
			}
			frames <- f
		}
	}()

	c, err := Dial(addr, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if err := c.OpenStreamWithoutEndHeaders(1, []byte{0x82}); err != nil {
		t.Fatalf("OpenStreamWithoutEndHeaders: %v", err)
	}
	if err := c.Continue(1, []byte{0x86}); err != nil {
		t.Fatalf("Continue: %v", err)
	}

	got := []frame.Frame{<-frames, <-frames}
	h, ok := got[0].(frame.HeadersFrame)
	if !ok || h.EndHeaders {
		t.Fatalf("first frame = %+v, want HEADERS without END_HEADERS", got[0])
	}
	if _, ok := got[1].(frame.ContinuationFrame); !ok {
		t.Fatalf("second frame = %T, want ContinuationFrame", got[1])
	}
}
