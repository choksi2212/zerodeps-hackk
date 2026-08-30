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
//
// It is also the window the scheduler reorders within. That is worth saying out
// loud, because it bounds what prioritisation can achieve here: a response cannot
// be moved ahead of one whose frames have already been written, and with a peer
// reading as fast as this server produces, the queue is usually near empty and
// there is nothing to reorder. The scheduler earns its keep in the case that
// matters — several responses competing for a connection that is the bottleneck —
// which is exactly when the queue is full.
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
// Every method here is safe for concurrent use, which is not incidental: Enqueue
// is called from every stream goroutine at once, SetMaxFrameSize from the reader
// goroutine, and Shutdown and Close from whichever goroutine noticed the problem
// first — a read error and a shutdown request can arrive together. The stop
// signals are idempotent for the same reason.
//
// # A queue with an order, not a channel
//
// The frames waiting to be written live in a scheduler behind a mutex and a
// condition variable, where a buffered channel would be the obvious Go answer. The
// channel was the first implementation and it cannot express two things this one
// needs.
//
// A channel is a FIFO, and §10 of RFC 9218 asks a server to choose: "It is
// RECOMMENDED that, when possible, servers respect the urgency parameter
// (Section 4.1), sending higher-urgency responses before lower-urgency responses."
// There is no way to take the third frame out of a channel.
//
// And a channel gives no way to hold a group of frames together. §4.3 of RFC 9113
// requires it: "Field blocks MUST be transmitted as a contiguous sequence of
// frames, with no interleaved frames of any other type or from any other stream."
// A PING acknowledgement enqueued by the reader goroutine between a HEADERS frame
// and its CONTINUATION goes out between them, and the peer is entitled to treat
// that as a connection error. See scheduler.go for both.
//
// What the mutex costs is a decision the select statement used to make at random,
// and every one of those decisions is now the visible order of two checks:
// Shutdown refuses a waiting Enqueue rather than racing it, and Close stops a
// pending flush rather than winning about half the time.
type frameWriter struct {
	fw      *frame.Writer
	target  writeTarget
	timeout time.Duration

	// mu guards everything below it. cond is broadcast whenever any of it
	// changes: a stream goroutine blocked in Enqueue is waiting for room, the
	// writer goroutine is waiting for a frame it can write, and both wait for the
	// stop flags. Broadcast rather than Signal because those are different waits
	// on one variable, and Signal could wake the wrong one — a Push that wakes
	// another blocked Enqueue instead of the writer would deadlock a full queue.
	mu    sync.Mutex
	cond  *sync.Cond
	sched *scheduler

	// stopGraceful asks the loop to write what is already queued and stop.
	// stopAbrupt asks it to stop without writing anything more.
	//
	// Flags under the mutex rather than closed channels, now that there is a
	// mutex: setting a bool twice is harmless, so the two sync.Once values that
	// made closing idempotent are gone, and the precedence between the two
	// signals is one ordinary if statement before another instead of a comment
	// explaining which select case wins.
	stopGraceful bool
	stopAbrupt   bool

	// gone is set once the loop has returned, and is what a blocked caller wakes
	// to read. The stop flags are not enough on their own: a failed write ends the
	// loop with neither of them set.
	gone bool

	// done is closed when the loop has returned. err is written before it closes
	// and read after, so the close orders the two for Wait; a caller inside
	// Enqueue instead reads it under mu, having seen gone, which the same loop's
	// critical section orders just as well.
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
		fw:      frame.NewWriter(target, frame.WriterConfig{}),
		target:  target,
		timeout: timeout,
		sched:   newScheduler(),
		done:    make(chan struct{}),
	}
	w.cond = sync.NewCond(&w.mu)
	go w.run()
	return w
}

// SetMaxFrameSize applies the peer's SETTINGS_MAX_FRAME_SIZE.
//
// Safe to call while the writer goroutine is writing, and it has to be: a peer
// may send SETTINGS at any point in a connection's life, that frame is read by
// the connection's reader goroutine, and the writer is as likely as not to be
// mid-burst when it arrives. frame.Writer holds the value atomically for exactly
// this call — see its SetMaxFrameSize for why the protocol makes ordering with
// the surrounding frames unnecessary.
func (w *frameWriter) SetMaxFrameSize(size uint32) {
	w.fw.SetMaxFrameSize(size)
}

// MaxFrameSize is the largest payload this writer will send, which is the peer's
// SETTINGS_MAX_FRAME_SIZE or §6.5.2's 16384, whichever is larger.
//
// Safe to call from any goroutine, and read fresh on every call rather than once
// per response: the value a stream goroutine gets is whatever the peer's most
// recent SETTINGS said, and two calls a moment apart may disagree. That is not a
// race to be closed but the protocol working as specified — a response split at the
// old cap is still legal, because §6.5.3 makes the acknowledgement the point from
// which the new value binds and this writer sends nothing between the two reads
// that depends on them agreeing.
func (w *frameWriter) MaxFrameSize() uint32 {
	return w.fw.MaxFrameSize()
}

// Enqueue hands f to the writer goroutine, blocking while the queue is full.
//
// Blocking is correct here, and is the backpressure the connection is built on. A
// full queue means the peer is not reading, and a peer that is not reading cannot
// be helped by producing more frames for it. The wait is bounded without any
// timeout of its own: the writer's own deadline fails the blocked socket write
// within timeout, which stops the loop, which releases everything waiting here.
//
// The frame is not necessarily written in this order relative to other streams'
// frames — that is what the scheduler decides — but a single caller's frames are
// never reordered against each other, which is the property internal/response
// depends on to keep a response's HEADERS ahead of its DATA.
func (w *frameWriter) Enqueue(f frame.Frame) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	for {
		// Checked before the push rather than after the wait, because a frame
		// accepted onto a queue that will never be drained is lost silently: the
		// layer above is told it was handed over.
		if err := w.stopped(); err != nil {
			return err
		}
		if w.admits(f) {
			w.sched.Push(f)
			w.cond.Broadcast()
			return nil
		}
		w.cond.Wait()
	}
}

// admits reports whether there is room for f. w.mu must be held.
func (w *frameWriter) admits(f frame.Frame) bool {
	return w.sched.ContinuesBlock(f) || w.sched.Len() < defaultQueueDepth
}

// stopped is the error to refuse an Enqueue with, or nil to accept it. w.mu must
// be held.
//
// It cannot promise that no frame is accepted after the writer has stopped, only
// that none is accepted after it is known to have stopped: a socket write that
// fails takes some microseconds to become the flag read here, and a caller in the
// meantime is told its frame was queued. Nothing can close that window — the
// caller's alternative is to ask afterwards, which is the same question later — and
// nothing needs to, because the frame it loses is a frame on a connection that no
// longer has a peer.
func (w *frameWriter) stopped() error {
	// Before the flags, so that a writer stopped by a failed write reports the
	// failure rather than the shutdown that followed it.
	if w.gone {
		return w.stoppedErr()
	}
	if w.stopGraceful || w.stopAbrupt {
		return errWriterStopped
	}
	return nil
}

// Shutdown asks the writer to write what is already queued and then stop. It does
// not wait; call Wait for that.
//
// This is how a GOAWAY reaches the peer: enqueue it, then Shutdown. A shutdown
// that dropped the queue would close the connection with the explanation still in
// it, which is the difference between a diagnosable failure and a reset.
func (w *frameWriter) Shutdown() {
	w.mu.Lock()
	w.stopGraceful = true
	w.mu.Unlock()
	w.cond.Broadcast()
}

// Close stops the writer without writing anything further. It is for a connection
// that is already lost — a read error, a hangup — where there is no peer left to
// explain anything to.
func (w *frameWriter) Close() {
	w.mu.Lock()
	w.stopAbrupt = true
	w.mu.Unlock()
	w.cond.Broadcast()
}

// Wait blocks until the writer goroutine has stopped and returns the error that
// stopped it, or nil if it was asked to stop.
func (w *frameWriter) Wait() error {
	<-w.done
	return w.err
}

// stoppedErr is the error to report to an Enqueue that arrived after the loop had
// stopped. The loop's own error is more informative than "stopped" when there is
// one, since it says why. Only safe once the loop has been observed to have ended,
// through gone under w.mu or through the closed w.done.
func (w *frameWriter) stoppedErr() error {
	if w.err != nil {
		return w.err
	}
	return errWriterStopped
}

func (w *frameWriter) run() {
	defer w.stop()
	for {
		f, ok := w.await()
		if !ok {
			return
		}
		if err := w.writeBurst(f); err != nil {
			w.err = err
			return
		}
	}
}

// stop releases everything waiting on this writer. It is the last thing the loop
// does, and w.err is already final by the time it runs.
func (w *frameWriter) stop() {
	close(w.done)

	w.mu.Lock()
	defer w.mu.Unlock()
	w.gone = true

	// Broadcast while the mutex is still held, not after releasing it. A waiter
	// woken by a broadcast must reacquire the mutex before it can re-examine
	// anything, so holding it here guarantees the flag it wakes to read is already
	// set. The same two statements in the other order leave a window — narrow, and
	// therefore the worst kind — in which a woken caller sees nothing changed and
	// waits again with nothing left to wake it, and the connection's stream
	// goroutines never return.
	w.cond.Broadcast()
}

// await blocks until there is a frame to write, or until the loop should stop.
//
// The order of the three checks is the contract, and each one used to be a comment
// about which select case Go might pick:
//
// stopAbrupt first, so Close drops what is queued. A frame ready to write and a
// closed abrupt channel were two ready select cases, and Go chose uniformly, so
// the old loop needed a separate non-blocking pre-check to stop a Close on a busy
// connection from writing one more burst about half the time.
//
// The queue next, so Shutdown writes what is already there. Nothing new can
// arrive once stopGraceful is set — Enqueue refuses it — so draining to empty and
// then stopping is exactly the old flushQueued's contract, and that whole function
// is now this ordering.
//
// stopGraceful last, and only with the queue empty. An incomplete field block is
// not in the queue, so a connection shutting down mid-block drops it rather than
// writing a HEADERS frame that promises a continuation nobody will send.
func (w *frameWriter) await() (frame.Frame, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for {
		if w.stopAbrupt {
			return nil, false
		}
		if f, ok := w.sched.Pop(); ok {
			w.cond.Broadcast()
			return f, true
		}
		if w.stopGraceful {
			return nil, false
		}
		w.cond.Wait()
	}
}

// takeIf returns the next frame to add to the burst in progress, or reports that
// the burst is over. room is whether the buffer is still below the high water.
//
// A burst continues past the high water while the scheduler is part-way through a
// field block. Stopping there would flush a HEADERS frame whose CONTINUATION
// frames are still queued, and an abrupt Close before the next burst would leave
// that on the wire — the §6.10 violation the scheduler exists to prevent, arrived
// at from the other direction. It cannot block: every frame of a block the
// scheduler has begun handing out is already in the scheduler.
func (w *frameWriter) takeIf(room bool) (frame.Frame, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !room && !w.sched.MidBlock() {
		return nil, false
	}
	f, ok := w.sched.Pop()
	if ok {
		w.cond.Broadcast()
	}
	return f, ok
}

// writeBurst buffers f, then everything else the scheduler will release, and
// writes the lot in one call.
//
// The mutex is taken once per frame and released before the socket write, not held
// across the burst. That is not a micro-optimisation: a write to a peer that has
// stopped reading blocks for the whole write timeout, and holding the mutex across
// it would block every stream goroutine on the connection in Enqueue for those
// seconds — turning a bounded queue into a stalled server. Nothing outside this
// goroutine touches w.fw, so the buffering needs no lock at all.
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
	for {
		next, ok := w.takeIf(w.fw.Buffered() < coalesceHighWater)
		if !ok {
			break
		}
		if err := w.fw.Queue(next); err != nil {
			return err
		}
	}
	return w.flush()
}

// flush writes the buffered frames under a deadline.
//
// It is only ever reached with octets buffered, because writeBurst is the only
// caller and it has already queued a frame: the smallest frame is nine octets, so
// there is no empty case to guard. The old empty guard existed for a graceful
// shutdown path that flushed unconditionally; await absorbed that, and a shutdown
// with nothing queued now performs no syscall at all rather than one that writes
// nothing.
func (w *frameWriter) flush() error {
	if err := w.target.SetWriteDeadline(time.Now().Add(w.timeout)); err != nil {
		return err
	}
	return w.fw.Flush()
}
