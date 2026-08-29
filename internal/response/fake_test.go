package response

import (
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"zerodeps/zdh/internal/frame"
	"zerodeps/zdh/internal/h2"
)

// frameBudget is the most frames one fakeTransport will accept before it starts
// refusing them.
//
// No real transport is unbounded either, but that is not why this is here. A split
// computed against a cap of zero produces fragments of nothing and never reaches the
// end of the block, and without a bound the symptom is two seconds of appending to a
// slice — a gigabyte or so — before a timeout notices. With one, the same break
// surfaces as an error naming the budget, in microseconds. The number is far above
// what any test here needs: the largest legitimate burst below is four frames.
const frameBudget = 4096

// maxFrame is §6.5.2's initial SETTINGS_MAX_FRAME_SIZE.
//
// It is the unit every split in these tests is measured in, because it is the
// smallest cap a Transport may report: Encoder.splitAt floors what the transport
// says at this value, so a test cannot ask for a smaller frame and has no reason to
// — the interesting boundaries are all relative to whatever the cap is.
const maxFrame = frame.DefaultMaxFrameSize

// gateWait bounds every wait in this package's tests. A test that hangs tells you
// nothing until the package times out and dumps every goroutine in the binary; a test
// that fails in two seconds names the step that did not happen.
const gateWait = 2 * time.Second

// fakeCodec is an h2.HeaderCodec that records what it was asked to do.
//
// The "encoding" is the field list written out as name=value lines, which is not
// HPACK and does not need to be. What this package does with a block is measure it,
// cut it into frames and enqueue the pieces in order; what the tests need from a
// codec is therefore a block whose contents they can still recognise after it has
// been cut up, and a record of the order the blocks were produced in.
//
// No lock. Every method here is called with the Encoder's mutex held — that is the
// guarantee h2.HeaderCodec asks its callers for and the reason Encoder has a mutex at
// all — and the tests read these fields after their goroutines have joined. The race
// detector runs over this package and would say so if either half were untrue.
type fakeCodec struct {
	// encodes is every field list Encode was given, in the order it was given them.
	encodes [][]h2.Field

	// tableSizes is every SetMaxDynamicTableSize argument, in order.
	tableSizes []int

	// block, when set, replaces the default encoding. n is the ordinal of the call,
	// counted from zero, which is what lets a test tag each block with the order it
	// was encoded in and then look for that order on the other side.
	block func(n int, fields []h2.Field) []byte
}

func (c *fakeCodec) Encode(fields []h2.Field) []byte {
	n := len(c.encodes)

	// Cloned, because the caller owns the slice and a test that asserted on it later
	// would otherwise be asserting on whatever the caller did next.
	c.encodes = append(c.encodes, slices.Clone(fields))

	if c.block != nil {
		return c.block(n, fields)
	}
	var b []byte
	for _, f := range fields {
		b = append(b, f.Name...)
		b = append(b, '=')
		b = append(b, f.Value...)
		b = append(b, '\n')
	}
	return b
}

// Decode panics. A response encoder decodes nothing: the decoding half of a
// connection is a different table with a different history, driven by the reader
// goroutine, and a call arriving here would mean the two directions had been given
// one codec.
func (c *fakeCodec) Decode([]byte) ([]h2.Field, error) {
	panic("fakeCodec: the response encoder must never decode")
}

func (c *fakeCodec) SetMaxDynamicTableSize(n int) {
	c.tableSizes = append(c.tableSizes, n)
}

// fakeTransport is the connection's write half under the test's control.
//
// This is what the Transport interface is for. The frames a response becomes are the
// whole observable output of this package, and through a real connection they would
// have to be read back off a socket and reparsed — which tests the frame layer over
// again and loses which call produced what.
type fakeTransport struct {
	mu     sync.Mutex
	frames []frame.Frame

	// max is the peer's SETTINGS_MAX_FRAME_SIZE. Atomic because a real one is
	// changed by the connection's reader goroutine while streams are writing, and a
	// test is entitled to do the same.
	max atomic.Uint32

	// maxReads counts MaxFrameSize calls, so that a test can assert the cap is read
	// once for a whole burst rather than once per frame. Atomic for the same reason
	// max is: the reads it counts are concurrent with each other.
	maxReads atomic.Int64

	// refuse, when set, is consulted for every frame; a non-nil result is returned
	// from Enqueue instead of the frame being recorded. n is how many frames have
	// been recorded so far, so a test can refuse the third frame of a burst and then
	// assert on the two that got through.
	//
	// Set before the transport is used and never written again, so it is read
	// without the lock.
	refuse func(n int, f frame.Frame) error

	// entered and release, when non-nil, make every Enqueue a handshake: the caller
	// announces its arrival on entered and waits on release for the result. Set
	// before use and never written again.
	//
	// This is what makes the lock's span testable. While one goroutine is parked
	// here, entered has exactly one possible sender left — a second goroutine that
	// reached Enqueue — so an arrival on it proves a second block was encoded and
	// enqueued while the first was still being written, and no arrival proves the
	// lock spans both.
	entered chan struct{}
	release chan error
}

func newTransport() *fakeTransport {
	t := &fakeTransport{}
	t.max.Store(maxFrame)
	return t
}

// gate makes every Enqueue on t park until the test lets it through.
func (t *fakeTransport) gate() *fakeTransport {
	t.entered, t.release = make(chan struct{}), make(chan error)
	return t
}

func (t *fakeTransport) MaxFrameSize() uint32 {
	t.maxReads.Add(1)
	return t.max.Load()
}

func (t *fakeTransport) Enqueue(f frame.Frame) error {
	if t.entered != nil {
		t.entered <- struct{}{}
		if err := <-t.release; err != nil {
			return err
		}
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if len(t.frames) >= frameBudget {
		return fmt.Errorf("fakeTransport: %d frames enqueued, over the %d budget: "+
			"a split that does not terminate", len(t.frames), frameBudget)
	}
	if t.refuse != nil {
		if err := t.refuse(len(t.frames), f); err != nil {
			return err
		}
	}
	t.frames = append(t.frames, f)
	return nil
}

// taken is a snapshot of the frames enqueued so far.
func (t *fakeTransport) taken() []frame.Frame {
	t.mu.Lock()
	defer t.mu.Unlock()
	return slices.Clone(t.frames)
}

// newEncoder returns an Encoder over a fresh codec and transport, and both of them.
func newEncoder() (*Encoder, *fakeCodec, *fakeTransport) {
	c, t := &fakeCodec{}, newTransport()
	return NewEncoder(c, t), c, t
}

// status is the one pseudo-header field a response must carry.
func status(code string) h2.Field { return h2.Field{Name: pseudoStatus, Value: code} }

// okFields is the shortest field list that passes checkSection as a header section.
func okFields() []h2.Field { return []h2.Field{status("200")} }

// checkBlock holds one header block's frames to §6.2 and §6.10 and returns the
// fragments concatenated.
//
// Every rule about the shape of the burst is here rather than repeated per test,
// because the shape is what almost every test in this file is about and a rule
// checked in one test and forgotten in the next is a rule that is not checked:
// the first frame is HEADERS and the rest are CONTINUATION, all on one stream,
// END_HEADERS on the last and only the last, END_STREAM where the caller asked for
// it, and no fragment above the cap the split was supposed to respect.
func checkBlock(t *testing.T, fs []frame.Frame, id uint32, endStream bool, max int) []byte {
	t.Helper()

	if len(fs) == 0 {
		t.Fatalf("no frames enqueued, want at least a HEADERS frame")
	}
	h, ok := fs[0].(frame.HeadersFrame)
	if !ok {
		t.Fatalf("first frame is %T, want frame.HeadersFrame", fs[0])
	}
	if h.StreamID != id {
		t.Errorf("HEADERS on stream %d, want %d", h.StreamID, id)
	}
	if h.EndStream != endStream {
		t.Errorf("HEADERS END_STREAM is %v, want %v", h.EndStream, endStream)
	}
	if h.Priority || h.Padded {
		// Neither is ever set by this package, and both would change the frame's
		// length and its meaning. Asserted rather than assumed because a zero value
		// that has to stay zero is exactly the kind of field a later edit sets.
		t.Errorf("HEADERS carries priority=%v padded=%v, want neither", h.Priority, h.Padded)
	}
	if want := len(fs) == 1; h.EndHeaders != want {
		t.Errorf("HEADERS END_HEADERS is %v with %d frames in the block, want %v",
			h.EndHeaders, len(fs), want)
	}
	if len(h.Fragment) > max {
		t.Errorf("HEADERS fragment is %d octets, above the %d cap", len(h.Fragment), max)
	}

	block := slices.Clone(h.Fragment)
	for i, f := range fs[1:] {
		c, ok := f.(frame.ContinuationFrame)
		if !ok {
			t.Fatalf("frame %d of the block is %T, want frame.ContinuationFrame", i+1, f)
		}
		if c.StreamID != id {
			t.Errorf("CONTINUATION %d on stream %d, want %d", i+1, c.StreamID, id)
		}
		if want := i == len(fs)-2; c.EndHeaders != want {
			t.Errorf("CONTINUATION %d of %d has END_HEADERS %v, want %v",
				i+1, len(fs)-1, c.EndHeaders, want)
		}
		if len(c.Fragment) > max {
			t.Errorf("CONTINUATION %d fragment is %d octets, above the %d cap",
				i+1, len(c.Fragment), max)
		}
		if len(c.Fragment) == 0 {
			// A CONTINUATION exists to carry what did not fit, so an empty one means
			// the split produced a frame it did not need — and a split that can
			// produce one empty frame is a split that can produce them for ever.
			t.Errorf("CONTINUATION %d carries no fragment", i+1)
		}
		block = append(block, c.Fragment...)
	}
	return block
}

// blocks cuts a recorded frame stream into header blocks, failing the test if any of
// them was interleaved with another.
//
// This is §6.2 and §4.3 as an assertion: "A HEADERS frame without the END_HEADERS
// flag set MUST be followed by a CONTINUATION frame for the same stream. A receiver
// MUST treat the receipt of any other type of frame or a frame on a different stream
// as a connection error [...] of type PROTOCOL_ERROR", and §4.3's requirement that a
// field block be "transmitted as a contiguous sequence of frames, with no interleaved
// frames of any other type or from any other stream". A HEADERS frame opens a block;
// only CONTINUATION frames on the same stream may follow until one sets END_HEADERS;
// anything else — a frame on another stream, or a second HEADERS — means the burst was
// not enqueued as a unit.
func blocks(t *testing.T, fs []frame.Frame) [][]frame.Frame {
	t.Helper()

	var (
		out  [][]frame.Frame
		open []frame.Frame
		id   uint32
	)
	for i, f := range fs {
		switch f := f.(type) {
		case frame.HeadersFrame:
			if open != nil {
				t.Fatalf("frame %d opens a block on stream %d while stream %d's block is still open (RFC 9113 §6.10)",
					i, f.StreamID, id)
			}
			if f.EndHeaders {
				out = append(out, []frame.Frame{f})
				continue
			}
			open, id = []frame.Frame{f}, f.StreamID

		case frame.ContinuationFrame:
			if open == nil {
				t.Fatalf("frame %d is a CONTINUATION on stream %d with no block open (RFC 9113 §6.10)",
					i, f.StreamID)
			}
			if f.StreamID != id {
				t.Fatalf("frame %d continues stream %d while stream %d's block is open (RFC 9113 §6.10)",
					i, f.StreamID, id)
			}
			open = append(open, f)
			if f.EndHeaders {
				out, open = append(out, open), nil
			}

		default:
			if open != nil {
				t.Fatalf("frame %d is a %s while stream %d's block is open (RFC 9113 §6.10)",
					i, f.Type(), id)
			}
		}
	}
	if open != nil {
		t.Fatalf("stream %d's header block was never finished: %d frames and no END_HEADERS",
			id, len(open))
	}
	return out
}
