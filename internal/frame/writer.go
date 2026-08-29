package frame

import (
	"io"
	"sync/atomic"

	"zerodeps/zdh/internal/h2"
)

// DefaultWriteBufferSize is the initial capacity of a Writer's queue. It is a
// starting point rather than a bound: the buffer grows to hold whatever is queued
// before the next flush, and keeps that capacity for the life of the connection.
const DefaultWriteBufferSize = 4 << 10

// WriterConfig configures a Writer. A zero field takes the default.
type WriterConfig struct {
	// MaxFrameSize is the peer's SETTINGS_MAX_FRAME_SIZE: the largest payload it
	// is willing to receive. Defaults to DefaultMaxFrameSize, which §6.5.2 defines
	// as the initial value — before the peer's SETTINGS arrive that is the only
	// figure we are entitled to assume.
	MaxFrameSize uint32

	// BufferSize is the initial queue capacity. Defaults to
	// DefaultWriteBufferSize.
	BufferSize int
}

// Writer serialises frames onto a byte stream.
//
// It is the sole owner of the write half of the connection. Nothing else may
// write to the socket, because a frame is nine octets of header followed by a
// payload and two goroutines interleaving those would produce a stream the peer
// cannot resynchronise — there is no framing marker to resynchronise to. The
// connection layer therefore funnels every frame through one writer goroutine,
// which is also why this type holds no lock.
//
// Queue and Flush are separate so that a burst of frames — a HEADERS, its
// CONTINUATIONs, and the DATA that follows — costs one write syscall rather than
// one per frame. Coalescing into a single buffer costs a copy of each payload;
// that copy is cheaper than the syscall it saves, and much cheaper than the
// several syscalls a scatter/gather write would need to arrange.
//
// One field is the exception to the single-goroutine rule, and it is atomic
// rather than locked because of what the protocol says about it rather than to
// save a mutex. See SetMaxFrameSize.
type Writer struct {
	w   io.Writer
	buf []byte

	// maxFrameSize is set by the connection's reader goroutine when the peer's
	// SETTINGS arrive, and read by the writer goroutine on every frame.
	maxFrameSize atomic.Uint32

	// err latches the first write failure. See Flush.
	err error
}

// NewWriter returns a Writer over w.
func NewWriter(w io.Writer, cfg WriterConfig) *Writer {
	if cfg.MaxFrameSize == 0 {
		cfg.MaxFrameSize = DefaultMaxFrameSize
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = DefaultWriteBufferSize
	}
	wr := &Writer{w: w, buf: make([]byte, 0, cfg.BufferSize)}
	wr.SetMaxFrameSize(cfg.MaxFrameSize)
	return wr
}

// SetMaxFrameSize records the peer's SETTINGS_MAX_FRAME_SIZE.
//
// Safe to call from another goroutine while frames are being written, which is
// what the connection layer needs: a peer may send SETTINGS at any point in a
// connection's life, that frame arrives on the reader goroutine, and the writer
// goroutine is very likely mid-burst when it does.
//
// The value is atomic and nothing more — no lock, no ordering with the frames
// around it — and that is a claim about the protocol, not a shortcut. §6.5.3
// requires a peer to keep honouring the value it previously advertised until it
// receives our acknowledgement, so a frame sent under either the old bound or
// the new one is one the peer has undertaken to accept. What must not happen is a
// torn or invented read of the field, which is exactly what atomic prevents. A
// mutex would buy an ordering guarantee the protocol does not ask for, on the
// hottest path in the server.
//
// The value is clamped into the range §6.5.2 permits rather than trusted. A
// setting below 2^14 or above 2^24-1 is invalid and parseSettings rejects it, so
// a value outside that range here means the setting reached us by some route that
// did not validate it — a bug on our side, not the peer's. Clamping keeps the
// connection working: raising a too-small limit to 2^14 sends frames the peer is
// required by §4.2 to accept, whereas honouring it would make every frame above
// the bogus limit unsendable and wedge the connection.
func (w *Writer) SetMaxFrameSize(n uint32) {
	if n < DefaultMaxFrameSize {
		n = DefaultMaxFrameSize
	}
	if n > MaxLength {
		n = MaxLength
	}
	w.maxFrameSize.Store(n)
}

// MaxFrameSize reports the largest payload this Writer will send.
func (w *Writer) MaxFrameSize() uint32 { return w.maxFrameSize.Load() }

// Buffered reports how many octets are queued and not yet written. The
// connection layer uses it to decide when a burst is worth a syscall.
func (w *Writer) Buffered() int { return len(w.buf) }

// Err reports the latched write error, or nil.
func (w *Writer) Err() error { return w.err }

// Queue appends a frame to the buffer without writing anything.
//
// The three refusals are all internal errors — a frame this Writer cannot send is
// a bug in the layer that built it, not a protocol violation by the peer — and
// none of them leaves a partial frame in the buffer.
func (w *Writer) Queue(f Frame) error {
	if w.err != nil {
		return w.err
	}

	// Loaded once, into a local, so that the comparison and the message it
	// produces cannot quote different numbers. The field is set concurrently by
	// the reader goroutine; two loads could straddle a change and report a limit
	// the frame was never measured against, which is the kind of diagnostic that
	// costs an hour.
	max := w.maxFrameSize.Load()
	if n := f.PayloadLen(); n > max {
		return connErrf(h2.InternalError,
			"refusing to send a %s frame with %d payload octets, above the peer's "+
				"SETTINGS_MAX_FRAME_SIZE of %d (RFC 9113 §4.2): the layer that built it "+
				"should have split it",
			f.Type(), n, max)
	}
	// The header's stream identifier is 31 bits. AppendTo truncates rather than
	// reporting, because a nine-octet serialiser has no useful way to fail — so
	// the check belongs here, and it has to exist: a truncated identifier would
	// send a frame that is valid, deliverable, and about the wrong stream.
	if id := f.Stream(); id > streamIDMask {
		return connErrf(h2.InternalError,
			"refusing to send a %s frame on stream %d, above the 31-bit maximum of %d "+
				"(RFC 9113 §4.1)",
			f.Type(), id, uint32(streamIDMask))
	}

	start := len(w.buf)
	w.buf = HeaderOf(f).AppendTo(w.buf)
	w.buf = f.appendPayload(w.buf)

	// PayloadLen and appendPayload are two computations of the same number, and
	// every frame type has a test sweeping its optional parts to prove they agree,
	// so this cannot fire. It is checked anyway because it is the one mistake a
	// peer cannot recover from: the declared length is how it finds the next frame
	// header, so a frame that lies about its length desynchronises the connection
	// permanently and silently. A local error and an unsent frame are strictly
	// better than a corrupt stream, and the check costs a subtraction.
	if got, want := len(w.buf)-start-HeaderLen, int(f.PayloadLen()); got != want {
		w.buf = w.buf[:start]
		return connErrf(h2.InternalError,
			"%s frame declared %d payload octets but serialised %d; refusing to send a frame "+
				"that would desynchronise the connection (RFC 9113 §4.1)",
			f.Type(), want, got)
	}
	return nil
}

// Flush writes everything queued in one call.
//
// One Write is enough: the io.Writer contract requires an implementation that
// wrote fewer octets than it was given to return an error, so there is no
// partial-success case to loop over. A wrapper that breaks that contract is
// treated as the failure it is, rather than allowed to truncate the frame stream
// quietly.
//
// A failure is latched, and the queue is dropped rather than kept for a retry.
// After a failed write there is no way to know how much of the buffer reached the
// peer, so there is no offset a retry could resume from — anything sent
// afterwards would land in the middle of a half-written frame. The connection is
// finished; every later call says so instead of making it worse.
func (w *Writer) Flush() error {
	if w.err != nil {
		return w.err
	}
	if len(w.buf) == 0 {
		return nil
	}

	n, err := w.w.Write(w.buf)
	if err == nil && n != len(w.buf) {
		err = io.ErrShortWrite
	}
	w.buf = w.buf[:0]
	if err != nil {
		w.err = err
		return err
	}
	return nil
}

// WriteFrame queues one frame and flushes. It is the right call for a frame that
// must reach the peer now — a SETTINGS acknowledgement, a PING reply, a GOAWAY —
// and the wrong one inside a burst, which should queue and flush once.
func (w *Writer) WriteFrame(f Frame) error {
	if err := w.Queue(f); err != nil {
		return err
	}
	return w.Flush()
}
