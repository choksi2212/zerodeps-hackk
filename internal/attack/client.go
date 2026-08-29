// Package attack is a test-only, minimal raw-frame HTTP/2 client. It exists
// to drive the two well-known HTTP/2 denial-of-service attacks — Rapid
// Reset (CVE-2023-44487) and the CONTINUATION Flood (CVE-2023-45288) —
// against zdh's own server and assert the server defends itself.
//
// It speaks just enough of RFC 9113 to open a connection and push frames:
// the client preface, a SETTINGS exchange, and HEADERS/CONTINUATION/
// RST_STREAM/PING/GOAWAY send and receive. It has no interest in being a
// well-behaved client — an adversarial test client's job is to be exactly
// as rude as the CVE it reproduces.
package attack

import (
	"net"
	"time"

	"zerodeps/zdh/internal/frame"
	"zerodeps/zdh/internal/h2"
)

// Client is one raw HTTP/2 connection to a server under test.
type Client struct {
	conn   net.Conn
	reader *frame.Reader
	writer *frame.Writer
}

// Dial opens a plaintext (h2c, prior-knowledge) TCP connection to addr,
// sends the client preface and an initial empty SETTINGS frame, and waits
// for the server's SETTINGS frame in reply. It does not wait for the
// server's SETTINGS ACK — a hostile client has no obligation to be polite
// about handshake completion either.
func Dial(addr string, timeout time.Duration) (*Client, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}

	c := &Client{
		conn:   conn,
		reader: frame.NewReader(conn, frame.ReaderConfig{}),
		writer: frame.NewWriter(conn, frame.WriterConfig{}),
	}

	if _, err := conn.Write([]byte(frame.ClientPreface)); err != nil {
		conn.Close()
		return nil, err
	}
	if err := c.writer.WriteFrame(frame.SettingsFrame{}); err != nil {
		conn.Close()
		return nil, err
	}

	return c, nil
}

// Close closes the underlying connection.
func (c *Client) Close() error { return c.conn.Close() }

// SetDeadline applies a read/write deadline to the underlying connection,
// so a test never hangs forever waiting on a server that stopped
// responding — which, against a hostile-client test, is sometimes exactly
// the correct server behavior (a silent drop after GOAWAY).
func (c *Client) SetDeadline(t time.Time) error { return c.conn.SetDeadline(t) }

// ReadFrame reads the next frame from the server.
func (c *Client) ReadFrame() (frame.Frame, error) { return c.reader.ReadFrame() }

// SendSettingsAck completes the handshake pleasantly, when a test wants a
// well-behaved connection before it turns hostile.
func (c *Client) SendSettingsAck() error {
	return c.writer.WriteFrame(frame.SettingsFrame{Ack: true})
}

// OpenStream sends a HEADERS frame that both opens and, if endStream is
// set, half-closes streamID, with the header block fully contained in this
// one frame (END_HEADERS set). fragment is a pre-encoded HPACK block — the
// caller owns HPACK encoding via internal/hpack, keeping this client
// ignorant of header compression, exactly as a raw attack tool should be.
func (c *Client) OpenStream(streamID uint32, fragment []byte, endStream bool) error {
	return c.writer.WriteFrame(frame.HeadersFrame{
		StreamID:   streamID,
		EndStream:  endStream,
		EndHeaders: true,
		Fragment:   fragment,
	})
}

// OpenStreamWithoutEndHeaders sends a HEADERS frame that deliberately never
// sets END_HEADERS, leaving the header block open for CONTINUATION frames
// that may never come — the shape of the CONTINUATION Flood
// (CVE-2023-45288).
func (c *Client) OpenStreamWithoutEndHeaders(streamID uint32, fragment []byte) error {
	return c.writer.WriteFrame(frame.HeadersFrame{
		StreamID:   streamID,
		EndHeaders: false,
		Fragment:   fragment,
	})
}

// Continue sends one CONTINUATION frame carrying another slice of a header
// block, without ending it.
func (c *Client) Continue(streamID uint32, fragment []byte) error {
	return c.writer.WriteFrame(frame.ContinuationFrame{
		StreamID:   streamID,
		EndHeaders: false,
		Fragment:   fragment,
	})
}

// Reset sends RST_STREAM(streamID, code) — the second half of the Rapid
// Reset attack: open a stream, then immediately cancel it before the
// server has done more than begin work on it.
func (c *Client) Reset(streamID uint32, code h2.ErrCode) error {
	return c.writer.WriteFrame(frame.RSTStreamFrame{StreamID: streamID, ErrCode: code})
}

// Ping sends a PING frame with the given 8 bytes of opaque data.
func (c *Client) Ping(data [8]byte) error {
	return c.writer.WriteFrame(frame.PingFrame{Data: data})
}
