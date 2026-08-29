// Package server runs the HTTP/2 connection: the preface, the SETTINGS exchange,
// the frame dispatch loop, and the two goroutines that own the connection's halves.
package server

import (
	"errors"
	"io"
	"sync"
	"time"

	"zerodeps/zdh/internal/frame"
)

// writeTarget is the write half of a connection: somewhere to put octets, with a
// deadline. *tls.Conn and net.Conn both satisfy it.
//
// It is an interface so the tests can drive the failure modes that matter — a peer
// that stops reading, a write that times out, a short write — none of which can be
// provoked reliably through a real socket.
type writeTarget interface {
	io.Writer
	SetWriteDeadline(t time.Time) error
}

// errWriterStopped is returned by Enqueue once the writer is shutting down or has
// stopped. It is not a protocol error and not worth a GOAWAY: by the time it can
// be observed, the connection is already going away for some other reason, and
// that reason is the one worth reporting.
var errWriterStopped = errors.New("frame writer stopped")

// defaultQueueDepth is how many frames may wait to be written.
//
// The depth bounds memory: each queued frame holds its own payload, so at the
// default maximum frame size this is half a megabyte per connection in the worst
// case. That worst case needs a peer that has stopped reading, which the write
// timeout resolves within seconds, and it needs the queue to be full of maximum
// size DATA frames — which flow control already prevents, since an unacknowledged
// stream window of 65535 octets admits four of them.
//
// It is not a bound on peer behaviour, so it does not live in internal/limits: a
// peer cannot make this queue longer, only fuller.
const defaultQueueDepth = 32

// coalesceHighWater is how many buffered octets end a coalescing burst.
//
// Combining frames into one Write matters more than it looks: over TLS, each Write
// becomes at least one record, with its own header and authentication tag, and a
// separate record for each of a response's HEADERS and DATA frames wastes both
// bandwidth and a round of the peer's record processing. Above one maximum-size
// frame there is nothing left to gain, because a TLS record cannot exceed 16 KiB
// and the record layer will split anyway.
const coalesceHighWater = frame.DefaultMaxFrameSize

// frameWriter owns the write half of one connection.
//
// Exactly one goroutine writes to a connection, and it is this one. That is not a
// lock avoided but an invariant: two goroutines writing frames to the same socket
// interleave their octets, and an interleaved frame stream is not recoverable —
// the peer reads a header, takes the next Length octets as its payload, and every
// frame after that point is read at the wrong offset. Everything else that wants
// to send a frame calls Enqueue.
//
// Enqueue is safe for concurrent use. Nothing else here is: Shutdown, Close and
// Wait are for the connection that owns the writer.
type frameWriter struct {
	fw      *frame.Writer
	target  writeTarget
	timeout time.Duration

	queue chan frame.Frame

	// graceful is closed to ask the loop to write what is already queued and
	// stop. abrupt is closed to ask it to stop without writing anything more.
	//
	// Two channels rather than a flag and one channel: the flag would be written
	// by whichever goroutine called Shutdown and read by the loop, which needs
	// synchronisation to be well defined, and a closed channel is already exactly
	// that — a one-way signal any number of goroutines can wait on.
	graceful     chan struct{}
	abrupt       chan struct{}
	gracefulOnce sync.Once
	abruptOnce   sync.Once

	// done is closed when the loop has returned. err is written before it closes
	// and read after, so the close orders the two.
	done chan struct{}
	err  error
}

// startFrameWriter starts the writer goroutine for target and returns a handle to
// it. The caller must eventually call Shutdown or Close, then Wait.
//
// The goroutine is started here rather than left to the caller because a
// frameWriter that has not been started accepts frames into its queue and writes
// none of them, and the symptom of that is a connection that hangs.
func startFrameWriter(target writeTarget, timeout time.Duration) *frameWriter {
	w := &frameWriter{
		fw:       frame.NewWriter(target, frame.WriterConfig{}),
		target:   target,
		timeout:  timeout,
		queue:    make(chan frame.Frame, defaultQueueDepth),
		graceful: make(chan struct{}),
		abrupt:   make(chan struct{}),
		done:     make(chan struct{}),
	}
	go w.run()
	return w
}

// SetMaxFrameSize applies the peer's SETTINGS_MAX_FRAME_SIZE.
//
// It must be called from the connection's reader goroutine before the SETTINGS
// frame is acknowledged and while nothing is queued, which is the only moment at
// which it is not a data race: the value is read by the writer goroutine on every
// frame. That is a narrow contract, and it is the right one — the alternative is a
// mutex on the write path to serialise against a value that changes once or twice
// in a connection's life.
func (w *frameWriter) SetMaxFrameSize(size uint32) {
	w.fw.SetMaxFrameSize(size)
}

// Enqueue hands f to the writer goroutine, blocking while the queue is full.
//
// Blocking is correct here, and is the backpressure the connection is built on. A
// full queue means the peer is not reading, and a peer that is not reading cannot
// be helped by producing more frames for it. The wait is bounded without any
// timeout of its own: the writer's own deadline fails the blocked socket write
// within timeout, which stops the loop, which releases everything waiting here.
func (w *frameWriter) Enqueue(f frame.Frame) error {
	// Checked before the send, because a select whose send is ready and whose
	// stop signal is closed picks between them at random — and accepting a frame
	// onto a queue that will never be drained loses it silently.
	select {
	case <-w.graceful:
		return errWriterStopped
	case <-w.abrupt:
		return errWriterStopped
	case <-w.done:
		return w.stoppedErr()
	default:
	}

	select {
	case w.queue <- f:
		return nil
	case <-w.graceful:
		return errWriterStopped
	case <-w.abrupt:
		return errWriterStopped
	case <-w.done:
		return w.stoppedErr()
	}
}

// Shutdown asks the writer to write what is already queued and then stop. It does
// not wait; call Wait for that.
//
// This is how a GOAWAY reaches the peer: enqueue it, then Shutdown. A shutdown
// that dropped the queue would close the connection with the explanation still in
// it, which is the difference between a diagnosable failure and a reset.
func (w *frameWriter) Shutdown() {
	w.gracefulOnce.Do(func() { close(w.graceful) })
}

// Close stops the writer without writing anything further. It is for a connection
// that is already lost — a read error, a hangup — where there is no peer left to
// explain anything to.
func (w *frameWriter) Close() {
	w.abruptOnce.Do(func() { close(w.abrupt) })
}

// Wait blocks until the writer goroutine has stopped and returns the error that
// stopped it, or nil if it was asked to stop.
func (w *frameWriter) Wait() error {
	<-w.done
	return w.err
}

// stoppedErr is the error to report to an Enqueue that arrived after the loop had
// stopped. The loop's own error is more informative than "stopped" when there is
// one, since it says why.
func (w *frameWriter) stoppedErr() error {
	if w.err != nil {
		return w.err
	}
	return errWriterStopped
}

func (w *frameWriter) run() {
	defer close(w.done)
	for {
		// Checked on its own before the main select, and this is not belt and
		// braces: a select whose queue receive is ready and whose abrupt channel
		// is closed picks between them at random, so without this a Close on a
		// connection with frames still queued would write one more burst about
		// half the time. Close's contract is that nothing further is written.
		//
		// It also settles the precedence between the two stop signals, which is
		// the reason it is here rather than folded into the select below with a
		// default: Close after Shutdown stops the flush from starting. It cannot
		// interrupt one already in progress — a write that has reached the socket
		// is out of our hands.
		select {
		case <-w.abrupt:
			return
		default:
		}

		select {
		case f := <-w.queue:
			if err := w.writeBurst(f); err != nil {
				w.err = err
				return
			}
		case <-w.graceful:
			// Whatever is already queued still goes out. Enqueue refuses new
			// frames from this point, so the queue can only shrink and this
			// cannot become an unbounded flush.
			if err := w.flushQueued(); err != nil {
				w.err = err
			}
			return
		case <-w.abrupt:
			return
		}
	}
}

// writeBurst buffers f, then everything else already waiting, and writes the lot
// in one call.
//
// A frame the writer refuses mid-burst takes the frames buffered ahead of it with
// it: they are never written. That is deliberate. frame.Writer only refuses a
// frame that is malformed by our own construction — oversize, or on an
// out-of-range stream — so the refusal means a bug in the layer above, the
// connection is finished, and what is buffered is the front half of a response
// whose back half does not exist. A peer that receives HEADERS and then a GOAWAY
// has been told less accurately what happened than one that receives only the
// GOAWAY.
func (w *frameWriter) writeBurst(f frame.Frame) error {
	if err := w.fw.Queue(f); err != nil {
		return err
	}
	for w.fw.Buffered() < coalesceHighWater {
		select {
		case next := <-w.queue:
			if err := w.fw.Queue(next); err != nil {
				return err
			}
		default:
			return w.flush()
		}
	}
	return w.flush()
}

// flushQueued writes everything waiting in the queue and nothing that arrives
// afterwards.
func (w *frameWriter) flushQueued() error {
	for {
		select {
		case f := <-w.queue:
			if err := w.fw.Queue(f); err != nil {
				return err
			}
			if w.fw.Buffered() >= coalesceHighWater {
				if err := w.flush(); err != nil {
					return err
				}
			}
		default:
			return w.flush()
		}
	}
}

// flush writes the buffered frames under a deadline.
func (w *frameWriter) flush() error {
	if w.fw.Buffered() == 0 {
		// This saves the deadline, not the write: frame.Writer.Flush already
		// returns without calling Write when nothing is buffered, so the octets
		// were never at risk. SetWriteDeadline is the syscall being skipped, and
		// the path that reaches here empty is the graceful shutdown — flushQueued
		// ends with a flush whether or not anything was queued, and on a
		// connection being closed with nothing left to say that syscall buys
		// nothing.
		return nil
	}
	if err := w.target.SetWriteDeadline(time.Now().Add(w.timeout)); err != nil {
		return err
	}
	return w.fw.Flush()
}
