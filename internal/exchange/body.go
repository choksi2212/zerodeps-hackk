package exchange

import (
	"io"
	"sync"

	"zerodeps/zdh/internal/h2"
)

// Body is one request's content: the DATA frames the peer sent, as an io.Reader for
// the goroutine running that request's handler.
//
// It is the one thing in this server that a handler blocks on, and the only place two
// goroutines meet over a request. The connection's reader goroutine puts payloads in
// and never waits; the handler takes them out and waits when there are none. So the
// lock is held for an append, a copy and a signal, never across anything that can
// block, and the reader goroutine cannot be stalled by a handler that has stopped
// reading — which matters more than it sounds, because that goroutine is also the one
// answering the peer's PING frames on every other stream of the connection.
//
// How much can accumulate here is not this type's decision and is not unbounded: the
// peer may only send what its stream flow-control window allows, and Table.HandleFrame
// debits that window before this ever sees the payload. This server does not replenish
// a stream's receive window, so a request body is bounded by the initial window of
// 65535 octets (§6.5.2) — a receiver policy §6.9 leaves to "the receiver's discretion",
// and this receiver's discretion is to serve files rather than uploads.
//
// A zero Body is not usable; see newBody. It is not safe to copy one.
type Body struct {
	mu   sync.Mutex
	wake *sync.Cond

	// chunks are the payloads that have arrived and not been fully read, oldest
	// first. Each aliases the frame it came in, which internal/frame has already
	// copied out of the read buffer, so nothing is copied again on the way in — only
	// on the way out, into the handler's own slice.
	chunks [][]byte

	// off is how far Read has got into chunks[0].
	off int

	// ended records the peer's END_STREAM: no further payload will arrive and Read
	// reports io.EOF once what did arrive has been read.
	ended bool

	// err is why this body will never finish — the peer reset the stream, the
	// connection ended, or the request turned out to be malformed. It is reported
	// ahead of anything still buffered: see Read.
	err error

	// trailers is the trailer section, if the request had one.
	trailers []h2.Field
}

// newBody returns an empty body, ready for the reader goroutine to add to.
func newBody() *Body {
	b := &Body{}
	b.wake = sync.NewCond(&b.mu)
	return b
}

// Read fills p from the content that has arrived, blocking until some has or until
// there will be no more.
//
// It is io.Reader, with io.Reader's contract kept in the two places that are easy to
// get wrong. A short read is not an ending: one call returns at most what one DATA
// frame still holds, because the alternative is to block waiting for a frame that
// would fill p and a peer is entitled never to send one. And a zero-length p does not
// block at all — there is nothing to fill, and blocking would turn io.Copy's habit of
// probing with an empty buffer into a deadlock.
//
// An error is preferred over buffered content, not reported after it. A stream the peer
// has reset is a request this server must not act on, and handing a handler the front
// of a body whose end will never come invites it to do exactly that: parse what it has,
// answer, and be wrong. §8.1.1 puts it as "Clients MUST NOT accept a malformed
// response", and the symmetry holds — the octets are still there, and they are not a
// request.
func (b *Body) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	for {
		if b.err != nil {
			return 0, b.err
		}
		if len(b.chunks) > 0 {
			break
		}
		if b.ended {
			return 0, io.EOF
		}
		b.wake.Wait()
	}

	n := copy(p, b.chunks[0][b.off:])
	b.off += n
	if b.off == len(b.chunks[0]) {
		// Dropped rather than left behind the slice header, so the frame's octets
		// are collectable as soon as they are read. A body that has been consumed
		// holds nothing.
		b.chunks[0] = nil
		b.chunks = b.chunks[1:]
		b.off = 0
	}
	return n, nil
}

// Trailers is the request's trailer section, or nil if it had none.
//
// Valid once Read has reported io.EOF, and nil before then, which is not a limitation
// this type invented: §8.1 puts the trailer section after the content, so a trailer
// field a handler could read before finishing the body would be one that had not
// arrived. A handler that wants trailers reads the body to its end first.
func (b *Body) Trailers() []h2.Field {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.trailers
}

// add hands one DATA payload to the handler. Called from the connection's reader
// goroutine, and never blocks.
//
// b is retained rather than copied: internal/frame owns the read buffer and copies
// each payload out of it before the frame is dispatched, which is what makes this
// safe and what makes a second copy here waste.
func (b *Body) add(chunk []byte) {
	b.mu.Lock()
	b.chunks = append(b.chunks, chunk)
	b.mu.Unlock()

	// Signal rather than Broadcast: one payload is one reader's worth. Wait
	// re-checks the condition it woke for, so a second waiter that this misses is a
	// waiter that had nothing to take anyway.
	b.wake.Signal()
}

// end applies the peer's END_STREAM, with the trailer section if there was one. Called
// from the connection's reader goroutine.
func (b *Body) end(trailers []h2.Field) {
	b.mu.Lock()
	b.trailers = trailers
	b.ended = true
	b.mu.Unlock()

	b.wake.Broadcast()
}

// fail reports that the request will never finish, waking a handler parked in Read.
// Called from the connection's reader goroutine.
//
// The first reason wins. A stream can be lost twice in quick succession — a peer's
// RST_STREAM and then the connection ending under it — and the first of those is the
// one that explains the other.
func (b *Body) fail(err error) {
	b.mu.Lock()
	if b.err == nil {
		b.err = err
	}
	b.mu.Unlock()

	b.wake.Broadcast()
}
