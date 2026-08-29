package response

import (
	"bytes"
	"errors"
	"io"
	"strconv"
	"sync"
	"testing"
	"time"

	"zerodeps/zdh/internal/frame"
	"zerodeps/zdh/internal/h2"
)

// checkBody holds a run of DATA frames to §6.1 and returns their content concatenated.
//
// The same reasoning as checkBlock: the rules about the shape of a body are what most of
// this file is about, and a rule checked in one test and forgotten in the next is not
// checked. Every frame is DATA on the one stream, none is padded, none is over the cap the
// split was measured against, END_STREAM appears only on the last frame if at all, and no
// frame is both empty and not the end — which would be a frame that says nothing.
func checkBody(t *testing.T, fs []frame.Frame, id uint32, max int) []byte {
	t.Helper()

	var out []byte
	for i, f := range fs {
		d, ok := f.(frame.DataFrame)
		if !ok {
			t.Fatalf("frame %d of the body is %T, want frame.DataFrame", i, f)
		}
		if d.StreamID != id {
			t.Errorf("DATA %d on stream %d, want %d", i, d.StreamID, id)
		}
		if d.Padded {
			// Padding costs the peer flow-control credit for octets that carry nothing,
			// and §6.1's padding is never set by this package. Asserted because a zero
			// value that has to stay zero is exactly the kind of field a later edit sets.
			t.Errorf("DATA %d is padded, and nothing here pads", i)
		}
		if len(d.Data) > max {
			t.Errorf("DATA %d carries %d octets, above the %d cap", i, len(d.Data), max)
		}
		if d.EndStream && i != len(fs)-1 {
			t.Errorf("DATA %d of %d ends the stream, and %d frames follow it",
				i, len(fs), len(fs)-1-i)
		}
		if len(d.Data) == 0 && !d.EndStream {
			t.Errorf("DATA %d carries nothing and does not end the stream, so it says nothing", i)
		}
		out = append(out, d.Data...)
	}
	return out
}

// --- the order §8.1 fixes ---

func TestNothingMayBeWrittenBeforeAHeaderSection(t *testing.T) {
	// §8.1 puts the header section first, and a peer that received a body without one
	// would have content it cannot attribute to a status code. This is the state a Writer
	// starts in and the one a handler that panics early leaves it in, so all three of
	// these are reachable from a handler that did nothing wrong on purpose.
	for _, tc := range []struct {
		name  string
		write func(*Writer) error
	}{
		{"Write", func(w *Writer) error { _, err := w.Write([]byte("hello")); return err }},
		{"Close", (*Writer).Close},
		{"Trailers", func(w *Writer) error { return w.Trailers(nil) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, _, tr, cr := newWriter()

			if err := tc.write(w); !errors.Is(err, ErrNoHeader) {
				t.Errorf("%s with no header section: %v, want %v", tc.name, err, ErrNoHeader)
			}
			if fs := tr.taken(); len(fs) != 0 {
				t.Errorf("%s enqueued %d frames before any header section", tc.name, len(fs))
			}
			if asks := cr.asked(); len(asks) != 0 {
				t.Errorf("%s reserved credit %d times before any header section", tc.name, len(asks))
			}
		})
	}
}

func TestASecondHeaderSectionIsRefused(t *testing.T) {
	// §8.1: "An endpoint that receives a HEADERS frame without the END_STREAM flag set
	// after receiving the HEADERS frame that opens a request or after receiving a final
	// (non-informational) status code MUST treat the corresponding request or response as
	// malformed." So the second one is not merely redundant — it makes the first one
	// unusable, and the peer discards a response it had already begun to act on.
	w, _, tr, _ := newWriter()

	if err := w.WriteHeader(okFields()); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	if err := w.WriteHeader(okFields()); !errors.Is(err, ErrHeaderWritten) {
		t.Errorf("a second WriteHeader: %v, want %v", err, ErrHeaderWritten)
	}
	if err := w.WriteBodylessHeader(okFields()); !errors.Is(err, ErrHeaderWritten) {
		t.Errorf("WriteBodylessHeader after WriteHeader: %v, want %v", err, ErrHeaderWritten)
	}

	if fs := tr.taken(); len(fs) != 1 {
		t.Errorf("%d frames on the wire, want the 1 the accepted header section produced", len(fs))
	}
}

func TestAHeaderSectionThatFailedHalfwayIsNotRetried(t *testing.T) {
	// writeSection can fail with the HEADERS frame already queued and its CONTINUATION
	// frames not, which §6.10 leaves as a stream nothing can finish. What must not happen
	// on top of that is a second header section: a handler that saw the error and tried
	// again would put one field block's fragments behind another's, and §8.1 says "Other
	// frames (from any stream) MUST NOT occur between the HEADERS frame and any
	// CONTINUATION frames that might follow" — so one stream's retry would end the
	// connection for every other stream on it.
	//
	// This is what the response being latched before the enqueue rather than after it
	// buys, and it is the only thing it buys.
	want := errors.New("the write half has stopped")

	enc, c, tr := newEncoder()
	c.block = func(int, []h2.Field) []byte { return filler(2*maxFrame+1, 'x') }
	tr.refuse = func(n int, _ frame.Frame) error {
		if n == 2 {
			return want
		}
		return nil
	}
	w := NewWriter(enc, &fakeCredit{}, 1)

	if err := w.WriteHeader(okFields()); !errors.Is(err, want) {
		t.Fatalf("WriteHeader: %v, want %v", err, want)
	}
	before := len(tr.taken())
	if before != 2 {
		t.Fatalf("%d frames queued before the refusal, want 2", before)
	}

	if err := w.WriteHeader(okFields()); !errors.Is(err, ErrHeaderWritten) {
		t.Errorf("WriteHeader after a burst that failed halfway: %v, want %v",
			err, ErrHeaderWritten)
	}
	if got := len(tr.taken()); got != before {
		t.Errorf("the retry put %d more frames on the wire behind a field block that has "+
			"no END_HEADERS", got-before)
	}
}

func TestNothingFollowsTheFrameThatEndedTheStream(t *testing.T) {
	// Three ways to end a response and four things a handler might do afterwards. Each
	// combination is a handler that thinks it still has a stream, and the frame that would
	// be sent is one §5.1 has no state for: the stream is "half-closed (local)" and this
	// endpoint has said it will send nothing more on it.
	//
	// Close is the exception and returns nil rather than ErrDone. A teardown path calls it
	// on every response it holds without knowing which a handler already finished, and
	// "the stream is ended" is the outcome that path wanted.
	ended := []struct {
		name string
		end  func(*Writer) error
	}{
		{"WriteBodylessHeader", func(w *Writer) error { return w.WriteBodylessHeader(okFields()) }},
		{"Close", func(w *Writer) error {
			if err := w.WriteHeader(okFields()); err != nil {
				return err
			}
			return w.Close()
		}},
		{"Trailers", func(w *Writer) error {
			if err := w.WriteHeader(okFields()); err != nil {
				return err
			}
			return w.Trailers([]h2.Field{{Name: "grpc-status", Value: "0"}})
		}},
	}
	after := []struct {
		name string
		want error
		call func(*Writer) error
	}{
		{"WriteHeader", ErrDone, func(w *Writer) error { return w.WriteHeader(okFields()) }},
		{"WriteBodylessHeader", ErrDone, func(w *Writer) error { return w.WriteBodylessHeader(okFields()) }},
		{"Write", ErrDone, func(w *Writer) error { _, err := w.Write([]byte("more")); return err }},
		{"Trailers", ErrDone, func(w *Writer) error { return w.Trailers(nil) }},
		{"Close", nil, (*Writer).Close},
	}

	for _, end := range ended {
		for _, next := range after {
			t.Run(end.name+" then "+next.name, func(t *testing.T) {
				w, _, tr, _ := newWriter()
				if err := end.end(w); err != nil {
					t.Fatalf("%s: %v", end.name, err)
				}
				before := len(tr.taken())

				if err := next.call(w); !errors.Is(err, next.want) {
					t.Errorf("%s after %s: %v, want %v", next.name, end.name, err, next.want)
				}
				if got := len(tr.taken()); got != before {
					t.Errorf("%s after %s put %d more frames on the wire", next.name, end.name, got-before)
				}
			})
		}
	}
}

// --- interim responses ---

func TestAnInterimResponseDoesNotBecomeTheHeaderSection(t *testing.T) {
	// §8.1: "For a response only, a server MAY send any number of interim responses before
	// the HEADERS frame containing a final response." Any number, so two 103s and then the
	// 200 is one response and not three, and the 200 is the one a body may follow.
	//
	// The interesting half is that a body before the final status is still refused. A
	// handler that sent 103 and started writing has skipped the status code, and the
	// content would arrive on a stream whose only header section promised more to come.
	w, _, tr, _ := newWriter()

	for range 2 {
		if err := w.WriteHeader([]h2.Field{status("103")}); err != nil {
			t.Fatalf("an interim WriteHeader: %v", err)
		}
		if _, err := w.Write([]byte("early")); !errors.Is(err, ErrNoHeader) {
			t.Errorf("Write after an interim response: %v, want %v", err, ErrNoHeader)
		}
	}

	if err := w.WriteHeader(okFields()); err != nil {
		t.Fatalf("the final WriteHeader: %v", err)
	}
	if _, err := w.Write([]byte("body")); err != nil {
		t.Fatalf("Write after the final header section: %v", err)
	}
	// And now it is latched, so the fourth header section is one too many.
	if err := w.WriteHeader(okFields()); !errors.Is(err, ErrHeaderWritten) {
		t.Errorf("WriteHeader after the final one: %v, want %v", err, ErrHeaderWritten)
	}

	// Three header blocks, in order, none of them ending the stream — an interim response
	// that closed the stream would leave nowhere for the final one to go.
	bs := blocks(t, tr.taken())
	if len(bs) != 3 {
		t.Fatalf("%d header blocks on the wire, want 3", len(bs))
	}
	for i, b := range bs {
		if h := b[0].(frame.HeadersFrame); h.EndStream {
			t.Errorf("header block %d ends the stream", i)
		}
	}
}

func TestAnInterimResponseCannotEndTheStream(t *testing.T) {
	// §8.1: "A HEADERS frame with the END_STREAM flag set that carries an informational
	// status code is malformed." Which follows from the rule above rather than standing
	// beside it: an interim response is by definition followed by a final one, and a
	// stream that has ended cannot carry it.
	w, _, tr, _ := newWriter()

	if err := w.WriteBodylessHeader([]h2.Field{status("103")}); !errors.Is(err, ErrInformationalEnd) {
		t.Errorf("WriteBodylessHeader with a 103: %v, want %v", err, ErrInformationalEnd)
	}
	if fs := tr.taken(); len(fs) != 0 {
		t.Fatalf("%d frames on the wire after a refused informational response", len(fs))
	}

	// And the refusal left nothing latched. This is the whole reason the flag is checked
	// before anything is enqueued: a handler that gets this error still has an unstarted
	// response and can send one.
	if err := w.WriteHeader([]h2.Field{status("103")}); err != nil {
		t.Fatalf("WriteHeader with a 103 after the refusal: %v", err)
	}
	if err := w.WriteBodylessHeader(okFields()); err != nil {
		t.Fatalf("WriteBodylessHeader with a 204 after the refusal: %v", err)
	}
	if len(blocks(t, tr.taken())) != 2 {
		t.Errorf("%d header blocks on the wire, want the 2 that were accepted", len(blocks(t, tr.taken())))
	}
}

func TestWhichStatusCodesAreInformational(t *testing.T) {
	// The 1xx class and nothing else, at both edges. 199 is not a status code anybody
	// sends and it is informational; 200 is one everybody sends and it is not. A test that
	// only tried 100 and 200 would pass against a check for "100" and against a check for
	// a first digit below "2", and those two disagree about 150.
	for _, tc := range []struct {
		code   string
		want   error
		reason string
	}{
		{"100", ErrInformationalEnd, "Continue"},
		{"101", ErrInformationalEnd, "Switching Protocols"},
		{"150", ErrInformationalEnd, "unassigned, still 1xx"},
		{"199", ErrInformationalEnd, "the top of the class"},
		{"200", nil, "the bottom of the next class"},
		{"204", nil, "No Content, the case this method exists for"},
		{"304", nil, "Not Modified, the other one"},
		{"404", nil, "a client error is still final"},
		{"599", nil, "the top of the last class §8.3.2 allows"},
	} {
		t.Run(tc.code, func(t *testing.T) {
			w, _, tr, _ := newWriter()

			if err := w.WriteBodylessHeader([]h2.Field{status(tc.code)}); !errors.Is(err, tc.want) {
				t.Errorf("WriteBodylessHeader with a %s (%s): %v, want %v",
					tc.code, tc.reason, err, tc.want)
			}
			// A refusal sends nothing and an acceptance sends one frame, which is what
			// makes the two cases distinguishable from outside: an implementation that
			// returned the right error after enqueuing the frame would pass the check
			// above and have already ended the stream.
			want := 1
			if tc.want != nil {
				want = 0
			}
			if fs := tr.taken(); len(fs) != want {
				t.Errorf("%d frames on the wire for a %s, want %d", len(fs), tc.code, want)
			}
		})
	}
}

func TestAMalformedFieldListIsReportedBeforeTheInformationalRule(t *testing.T) {
	// Two ":status" fields, the first of them a 1xx. Both rules are broken and only one
	// answer is useful: what is wrong with this list is that it has two status codes, and
	// reporting it as an informational response that cannot end the stream would send a
	// handler looking for the 1xx it did not send twice.
	//
	// This is the ordering writeHeader's comment argues for, and it is the reason
	// Encoder.WriteHeaders is not called from here — validation, then a decision, then the
	// enqueue, and there is no arrangement of one call that puts a decision in the middle.
	w, _, tr, _ := newWriter()

	err := w.WriteBodylessHeader([]h2.Field{status("100"), status("200")})
	if err == nil {
		t.Fatalf("WriteBodylessHeader with two :status fields returned nil")
	}
	if errors.Is(err, ErrInformationalEnd) {
		t.Errorf("a list with two :status fields was reported as %v, "+
			"want the malformed-list error", err)
	}
	if fs := tr.taken(); len(fs) != 0 {
		t.Errorf("%d frames on the wire after a malformed field list", len(fs))
	}
}

func TestARefusedHeaderSectionLeavesTheResponseUnstarted(t *testing.T) {
	// A malformed list is the handler's mistake and not the connection's, so the stream is
	// exactly where it was: nothing sent, nothing latched, and a corrected list still
	// works. The alternative — latching on the attempt — turns one bad field name into a
	// stream that can never carry a response.
	w, _, tr, _ := newWriter()

	if err := w.WriteHeader([]h2.Field{{Name: "Content-Type", Value: "text/plain"}}); err == nil {
		t.Fatalf("WriteHeader with an upper-case field name and no :status returned nil")
	}
	if fs := tr.taken(); len(fs) != 0 {
		t.Fatalf("%d frames on the wire after a refused header section", len(fs))
	}

	if err := w.WriteHeader(okFields()); err != nil {
		t.Fatalf("WriteHeader after the refusal: %v", err)
	}
	if _, err := w.Write([]byte("body")); err != nil {
		t.Errorf("Write after the corrected header section: %v", err)
	}
}

// --- the body, and the two limits it is cut to ---

func TestABodyIsSplitAtThePeersFrameSizeCap(t *testing.T) {
	// §4.2: "An endpoint MUST send an error code of FRAME_SIZE_ERROR if a frame exceeds
	// the size defined in SETTINGS_MAX_FRAME_SIZE." One octet over is the whole of the
	// offence, so the sizes below are asserted exactly rather than bounded: a split that
	// produced two frames of half the cap would satisfy every inequality and still be
	// wrong about what a frame is for.
	const size = 2*maxFrame + 7

	w, _, tr, _ := newWriter()
	if err := w.WriteHeader(okFields()); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	want := filler(size, 'b')

	n, err := w.Write(want)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != size {
		t.Errorf("Write returned %d, want %d", n, size)
	}

	fs := tr.taken()
	if len(fs) != 4 {
		t.Fatalf("%d frames for a header section and a %d octet body, want 4", len(fs), size)
	}
	if got := checkBody(t, fs[1:], 1, maxFrame); !bytes.Equal(got, want) {
		t.Errorf("the DATA frames reassemble to %d octets, want %d", len(got), size)
	}
	for i, d := range []int{maxFrame, maxFrame, 7} {
		if got := len(fs[i+1].(frame.DataFrame).Data); got != d {
			t.Errorf("DATA %d carries %d octets, want %d", i, got, d)
		}
	}
}

func TestNoDataFrameEndsTheStreamOnItsOwn(t *testing.T) {
	// Write never sets END_STREAM, however much it is given. A handler writing a body in
	// pieces has not said the response is over, and a Write that guessed otherwise would
	// end the stream in the middle of a file whenever the last piece happened to fit.
	w, _, tr, _ := newWriter()
	if err := w.WriteHeader(okFields()); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	for range 3 {
		if _, err := w.Write(filler(maxFrame, 'b')); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}

	fs := tr.taken()
	checkBody(t, fs[1:], 1, maxFrame)
	for i, f := range fs[1:] {
		if f.Flags()&frame.FlagEndStream != 0 {
			t.Errorf("DATA %d ends the stream and Write was never asked to", i)
		}
	}
}

func TestTheFrameSizeCapIsReadForEveryDataFrame(t *testing.T) {
	// The opposite of TestTheFrameSizeCapIsReadOnceForTheWholeBurst, and for the reason
	// splitAt's comment gives: a field block must be split against one number because the
	// fragments are one block, while consecutive DATA frames are independent frames. So a
	// peer that changes its mind mid-body gets what it asked for from the next frame on.
	//
	// Both directions, because a cap that is only ever raised is a cap that could be
	// cached at the high-water mark and still pass.
	for _, tc := range []struct {
		name  string
		start uint32
		then  uint32
		size  int
		want  []int
	}{
		{"raised mid-body", maxFrame, 2 * maxFrame, 4 * maxFrame,
			[]int{maxFrame, 2 * maxFrame, maxFrame}},
		{"lowered mid-body", 4 * maxFrame, maxFrame, 6 * maxFrame,
			[]int{4 * maxFrame, maxFrame, maxFrame}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			enc, _, tr := newEncoder()
			tr.max.Store(tc.start)
			cr := &fakeCredit{grant: func(n int, _ uint32, want int) (int, error) {
				if n == 0 {
					// After the first frame's size has been decided and before the
					// second's. This is the reader goroutine landing a SETTINGS frame
					// mid-body, which is the only way this happens for real.
					tr.max.Store(tc.then)
				}
				return want, nil
			}}
			w := NewWriter(enc, cr, 1)

			if err := w.WriteHeader(okFields()); err != nil {
				t.Fatalf("WriteHeader: %v", err)
			}
			tr.maxReads.Store(0)

			if _, err := w.Write(filler(tc.size, 'b')); err != nil {
				t.Fatalf("Write: %v", err)
			}

			fs := tr.taken()[1:]
			if len(fs) != len(tc.want) {
				t.Fatalf("%d DATA frames, want %d", len(fs), len(tc.want))
			}
			for i, want := range tc.want {
				if got := len(fs[i].(frame.DataFrame).Data); got != want {
					t.Errorf("DATA %d carries %d octets, want %d", i, got, want)
				}
			}
			if got := tr.maxReads.Load(); got != int64(len(fs)) {
				t.Errorf("the frame size cap was read %d times for %d DATA frames, "+
					"want once each", got, len(fs))
			}
		})
	}
}

func TestAReservationSmallerThanTheChunkIsSentAsItStands(t *testing.T) {
	// flow.Sender.Reserve returns anything in [1, want] and the octets are already
	// debited when it does, so a partial grant cannot be handed back and asked for again
	// at a better time. What is left is to send exactly what was granted and ask for the
	// rest — which is why the loop asks again rather than waiting for a grant it likes.
	//
	// A grant of one octet is the worst case and is the case here: it produces a DATA
	// frame per octet, which is legal, appalling, and exactly what a peer advertising a
	// one-octet window has asked for.
	const size = 40

	w, _, tr, cr := newWriter()
	cr.grant = func(int, uint32, int) (int, error) { return 1, nil }
	if err := w.WriteHeader(okFields()); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	want := filler(size, 'b')

	n, err := w.Write(want)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != size {
		t.Errorf("Write returned %d, want %d", n, size)
	}

	fs := tr.taken()[1:]
	if len(fs) != size {
		t.Fatalf("%d DATA frames for %d octets granted one at a time, want %d",
			len(fs), size, size)
	}
	if got := checkBody(t, fs, 1, 1); !bytes.Equal(got, want) {
		t.Errorf("the DATA frames reassemble to %q, want %q", got, want)
	}
}

func TestOnlyTheContentIsReservedAndTheFrameHeaderIsNot(t *testing.T) {
	// §6.9.1: "For flow-control calculations, the 9-octet frame header is not counted."
	// So a body of n octets costs exactly n whatever it is cut into, and a Writer that
	// charged for its own framing would exhaust a peer's window early — by 9 octets per
	// frame, which at a one-octet grant is ten times the size of the body.
	//
	// Each reservation is also checked against what it should have asked for: the smaller
	// of what is left and the frame size cap, never more.
	const size = 2*maxFrame + 7

	w, _, tr, cr := newWriter()
	if err := w.WriteHeader(okFields()); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	if _, err := w.Write(filler(size, 'b')); err != nil {
		t.Fatalf("Write: %v", err)
	}

	asks, left, total := cr.asked(), size, 0
	for i, a := range asks {
		if want := min(left, maxFrame); a.want != want {
			t.Errorf("reservation %d asked for %d, want %d — the smaller of the %d left "+
				"and the %d cap", i, a.want, want, left, maxFrame)
		}
		if a.id != 1 {
			t.Errorf("reservation %d was made against stream %d, want 1", i, a.id)
		}
		left -= a.got
		total += a.got
	}
	if total != size {
		t.Errorf("%d octets reserved for a %d octet body", total, size)
	}
	if got := len(tr.taken()) - 1; got != len(asks) {
		t.Errorf("%d DATA frames against %d reservations, want one each", got, len(asks))
	}
}

func TestAnEmptyWriteSendsNothingAndReservesNothing(t *testing.T) {
	// io.Copy of an empty file, and the last Write of a body whose length is a multiple of
	// the buffer size. A zero-length DATA frame without END_STREAM says nothing at all,
	// and asking for a reservation of nothing is a panic in flow.Sender — deliberately,
	// because it is a caller that has not worked out what it wants.
	for _, tc := range []struct {
		name string
		p    []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, _, tr, cr := newWriter()
			if err := w.WriteHeader(okFields()); err != nil {
				t.Fatalf("WriteHeader: %v", err)
			}

			n, err := w.Write(tc.p)
			if n != 0 || err != nil {
				t.Errorf("Write(%s) = %d, %v; want 0, nil", tc.name, n, err)
			}
			if fs := tr.taken(); len(fs) != 1 {
				t.Errorf("%d frames on the wire, want the 1 the header section produced", len(fs))
			}
			if asks := cr.asked(); len(asks) != 0 {
				t.Errorf("an empty Write made %d reservations", len(asks))
			}
		})
	}
}

func TestTheContentIsCopiedRatherThanAliased(t *testing.T) {
	// The frames outlive the call: they are handed to the connection's writer goroutine
	// and serialised there. A Writer that kept a view of the caller's slice would be
	// correct for exactly as long as the caller left it alone — and io.Copy refills one
	// buffer, so the very next read would rewrite the frame that had not gone out yet.
	//
	// Overwriting the buffer here is that next read, made deterministic.
	const size = 2 * maxFrame

	w, _, tr, _ := newWriter()
	if err := w.WriteHeader(okFields()); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}

	buf := filler(size, 'b')
	if _, err := w.Write(buf); err != nil {
		t.Fatalf("Write: %v", err)
	}
	for i := range buf {
		buf[i] = 'z'
	}

	got := checkBody(t, tr.taken()[1:], 1, maxFrame)
	if want := filler(size, 'b'); !bytes.Equal(got, want) {
		t.Errorf("the DATA frames became %q...; the caller's buffer was reused and the "+
			"frames were pointing into it", got[:min(len(got), 8)])
	}
}

func TestABodyCanBeWrittenWithIoCopy(t *testing.T) {
	// The reason Write has io.Writer's signature: serving a file is io.Copy and a handler
	// should not have to reimplement the loop. io.Copy uses its own buffer and its own
	// chunk size, neither of which is a multiple of anything here, so this also covers a
	// body arriving in pieces that do not line up with the frame size cap.
	const size = 5*maxFrame + 11

	w, _, tr, _ := newWriter()
	if err := w.WriteHeader(okFields()); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	want := filler(size, 'b')

	n, err := io.Copy(w, bytes.NewReader(want))
	if err != nil {
		t.Fatalf("io.Copy: %v", err)
	}
	if n != size {
		t.Errorf("io.Copy copied %d octets, want %d", n, size)
	}
	if got := checkBody(t, tr.taken()[1:], 1, maxFrame); !bytes.Equal(got, want) {
		t.Errorf("the DATA frames reassemble to %d octets, want %d", len(got), size)
	}
}

// --- what a failure mid-body leaves behind ---

func TestAFailedReservationIsReportedWithTheOctetsAlreadySent(t *testing.T) {
	// Reserve's errors are terminal: the stream was reset, or the connection ended. So
	// there is nothing to retry and the only question is what to tell the caller, and
	// io.Writer's contract answers it — the count is what was written, and it is short
	// because the error is not nil.
	//
	// Getting this wrong in the flattering direction is the failure that matters. A Writer
	// that returned len(p) with an error would satisfy a caller that ignores one of the
	// two, and io.Copy would report a file as fully sent that stopped a third of the way.
	want := errors.New("the stream was reset")

	w, _, tr, cr := newWriter()
	cr.grant = func(n int, _ uint32, ask int) (int, error) {
		if n == 1 {
			return 0, want
		}
		return ask, nil
	}
	if err := w.WriteHeader(okFields()); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}

	n, err := w.Write(filler(3*maxFrame, 'b'))
	if !errors.Is(err, want) {
		t.Errorf("Write: %v, want %v", err, want)
	}
	if n != maxFrame {
		t.Errorf("Write returned %d, want the %d octets the first frame carried", n, maxFrame)
	}
	if fs := tr.taken()[1:]; len(fs) != 1 {
		t.Errorf("%d DATA frames on the wire, want the 1 that was granted", len(fs))
	}
}

func TestARefusedDataFrameIsReportedWithTheOctetsAlreadySent(t *testing.T) {
	// The other way a body stops: the write half has gone. The count is again what
	// reached the queue, which is one frame short of what was reserved — the octets for
	// the refused frame were debited by Reserve and cannot be given back, and that is
	// Reserve's documented contract rather than an oversight here. The connection is
	// ending, so the credit has nothing left to be spent on.
	want := errors.New("the write half has stopped")

	w, _, tr, cr := newWriter()
	tr.refuse = func(n int, _ frame.Frame) error {
		if n == 2 {
			return want
		}
		return nil
	}
	if err := w.WriteHeader(okFields()); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}

	n, err := w.Write(filler(3*maxFrame, 'b'))
	if !errors.Is(err, want) {
		t.Errorf("Write: %v, want %v", err, want)
	}
	if n != maxFrame {
		t.Errorf("Write returned %d, want the %d octets the first frame carried", n, maxFrame)
	}
	if fs := tr.taken()[1:]; len(fs) != 1 {
		t.Fatalf("%d DATA frames on the wire, want the 1 that was accepted", len(fs))
	}
	if got := len(cr.asked()); got != 2 {
		t.Errorf("%d reservations for 1 frame that went out and 1 that was refused, want 2", got)
	}
}

// --- ending the stream ---

func TestCloseSendsAnEmptyDataFrameAndReservesNothing(t *testing.T) {
	// §6.9.1: "Frames with zero length with the END_STREAM flag set (that is, an empty
	// DATA frame) MAY be sent if there is no available space in either flow-control
	// window." Reserving for it would be worse than unnecessary: a stream whose window is
	// exhausted would park here until the peer sent a WINDOW_UPDATE it has no reason to
	// send, because the response is complete and there is nothing left for the credit to
	// carry. The handler has returned and the stream never ends.
	w, _, tr, cr := newWriter()
	if err := w.WriteHeader(okFields()); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	fs := tr.taken()
	if len(fs) != 2 {
		t.Fatalf("%d frames for a header section and a Close, want 2", len(fs))
	}
	d, ok := fs[1].(frame.DataFrame)
	if !ok {
		t.Fatalf("Close enqueued a %T, want frame.DataFrame", fs[1])
	}
	if !d.EndStream {
		t.Errorf("Close's DATA frame does not end the stream, so nothing does")
	}
	if len(d.Data) != 0 {
		t.Errorf("Close's DATA frame carries %d octets, want none", len(d.Data))
	}
	if asks := cr.asked(); len(asks) != 0 {
		t.Errorf("Close made %d reservations for a frame §6.9.1 exempts", len(asks))
	}
}

func TestCloseFollowsTheBodyItEnds(t *testing.T) {
	w, _, tr, _ := newWriter()
	if err := w.WriteHeader(okFields()); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	want := filler(2*maxFrame, 'b')
	if _, err := w.Write(want); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	fs := tr.taken()
	if len(fs) != 4 {
		t.Fatalf("%d frames for a header section, two DATA frames and a Close, want 4", len(fs))
	}
	// checkBody covers the ordering rule that matters here: END_STREAM on the last frame
	// and no other. A body frame carrying it would end the stream with content still to
	// come, which §8.1 gives the peer no way to reconcile.
	if got := checkBody(t, fs[1:], 1, maxFrame); !bytes.Equal(got, want) {
		t.Errorf("the DATA frames reassemble to %d octets, want %d", len(got), len(want))
	}
}

func TestARefusedCloseStillEndsTheResponse(t *testing.T) {
	// The frame did not go out and the error says so, but there is no second attempt to
	// make: the reason an enqueue fails is that the write half has stopped, and a Writer
	// that stayed open would let a teardown path try again for every stream on a dead
	// connection. So the error is reported once and the response is finished.
	want := errors.New("the write half has stopped")

	w, _, tr, _ := newWriter()
	// Keyed on the frame type rather than on a count, so the refusal is in place before
	// the transport is used at all: fakeTransport.refuse is documented as set once and
	// read without the lock, and a test that reached in halfway through would be relying
	// on there being no other goroutine at that moment.
	tr.refuse = func(_ int, f frame.Frame) error {
		if _, ok := f.(frame.DataFrame); ok {
			return want
		}
		return nil
	}
	if err := w.WriteHeader(okFields()); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}

	if err := w.Close(); !errors.Is(err, want) {
		t.Errorf("Close: %v, want %v", err, want)
	}
	if err := w.Close(); err != nil {
		t.Errorf("a second Close: %v, want nil", err)
	}
	if fs := tr.taken(); len(fs) != 1 {
		t.Errorf("%d frames on the wire, want the 1 the header section produced", len(fs))
	}
}

func TestABodylessHeaderSectionNeedsNoClose(t *testing.T) {
	// END_STREAM on the HEADERS frame is nine octets cheaper than a HEADERS frame plus an
	// empty DATA frame, but the reason to prefer it is that it cannot be got wrong. What
	// this asserts is that the stream layer may still call Close afterwards — it does not
	// know which shape a handler chose — and that doing so sends nothing.
	w, _, tr, _ := newWriter()

	if err := w.WriteBodylessHeader(okFields()); err != nil {
		t.Fatalf("WriteBodylessHeader: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("Close after WriteBodylessHeader: %v, want nil", err)
	}

	fs := tr.taken()
	if len(fs) != 1 {
		t.Fatalf("%d frames for a bodyless response, want 1", len(fs))
	}
	checkBlock(t, fs, 1, true, maxFrame)
}

// --- trailers ---

func TestATrailerSectionEndsTheStreamAfterTheBody(t *testing.T) {
	// §8.1: "Trailer fields are carried in a field block that also terminates the
	// stream." So no empty DATA frame is needed and none is sent — the trailer block's
	// END_STREAM is the end of the response, and a Close afterwards is a no-op.
	w, _, tr, _ := newWriter()
	if err := w.WriteHeader(okFields()); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	if _, err := w.Write(filler(maxFrame, 'b')); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Trailers([]h2.Field{{Name: "grpc-status", Value: "0"}}); err != nil {
		t.Fatalf("Trailers: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("Close after Trailers: %v, want nil", err)
	}

	fs := tr.taken()
	if len(fs) != 3 {
		t.Fatalf("%d frames for a header section, a body and trailers, want 3", len(fs))
	}
	checkBody(t, fs[1:2], 1, maxFrame)
	checkBlock(t, fs[2:], 1, true, maxFrame)
}

func TestATrailerSectionNeedsNoBody(t *testing.T) {
	// §8.1's order is header section, content, trailers, and the content is "zero or
	// more DATA frames". A response that has something to say after its header section
	// and nothing to say in between is two field blocks and nothing else.
	w, _, tr, _ := newWriter()
	if err := w.WriteHeader(okFields()); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	if err := w.Trailers([]h2.Field{{Name: "grpc-status", Value: "0"}}); err != nil {
		t.Fatalf("Trailers: %v", err)
	}

	bs := blocks(t, tr.taken())
	if len(bs) != 2 {
		t.Fatalf("%d field blocks, want 2", len(bs))
	}
	if h := bs[0][0].(frame.HeadersFrame); h.EndStream {
		t.Errorf("the header section ends the stream, leaving nowhere for the trailers")
	}
	if h := bs[1][0].(frame.HeadersFrame); !h.EndStream {
		t.Errorf("the trailer section does not end the stream")
	}
}

func TestARefusedTrailerSectionLeavesTheStreamOpen(t *testing.T) {
	// §8.3: "Pseudo-header fields MUST NOT appear in a trailer section." Including
	// ":status", which is the one a header section requires — so a handler that reuses its
	// header list as its trailer list gets this, and gets it before anything is sent.
	//
	// Nothing sent means the stream is not closed, which is the part worth asserting: the
	// handler still owes the peer an END_STREAM and can still deliver one. Marking the
	// response finished on a refusal would leave the stream open on the wire and closed
	// here, and the peer would wait for a frame nobody was going to send.
	w, _, tr, _ := newWriter()
	if err := w.WriteHeader(okFields()); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}

	if err := w.Trailers(okFields()); err == nil {
		t.Fatalf("Trailers with a :status field returned nil")
	}
	if fs := tr.taken(); len(fs) != 1 {
		t.Fatalf("%d frames on the wire after a refused trailer section", len(fs))
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close after the refusal: %v", err)
	}
	fs := tr.taken()
	if len(fs) != 2 {
		t.Fatalf("%d frames after the recovering Close, want 2", len(fs))
	}
	if d := fs[1].(frame.DataFrame); !d.EndStream {
		t.Errorf("the recovering Close did not end the stream")
	}
}

func TestATrailerSectionThatFailedHalfwayIsNotRetried(t *testing.T) {
	// The other half of the rule the test above asserts, and the reason a refused trailer
	// section and a half-sent one are not the same event. A refusal sends nothing, so the
	// response is unfinished and may still be ended. A burst that failed partway has
	// already put a HEADERS frame bearing END_STREAM on the queue, so the response is over
	// whatever happened to the rest of it — and a handler that saw the error and tried
	// again would send a second field block behind the first one's fragments, which §8.1
	// makes a connection error rather than a second chance.
	want := errors.New("the write half has stopped")

	w, c, tr, _ := newWriter()
	c.block = func(n int, _ []h2.Field) []byte {
		if n == 0 {
			return []byte("the header section, in one frame\n")
		}
		return filler(2*maxFrame+1, 'x')
	}
	tr.refuse = func(n int, _ frame.Frame) error {
		if n == 3 {
			return want
		}
		return nil
	}

	if err := w.WriteHeader(okFields()); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	trailer := []h2.Field{{Name: "grpc-status", Value: "0"}}
	if err := w.Trailers(trailer); !errors.Is(err, want) {
		t.Fatalf("Trailers: %v, want %v", err, want)
	}
	before := len(tr.taken())
	if before != 3 {
		t.Fatalf("%d frames queued before the refusal, want 3", before)
	}

	if err := w.Trailers(trailer); !errors.Is(err, ErrDone) {
		t.Errorf("Trailers after a burst that failed halfway: %v, want %v", err, ErrDone)
	}
	if err := w.Close(); err != nil {
		t.Errorf("Close after a burst that failed halfway: %v, want nil", err)
	}
	if got := len(tr.taken()); got != before {
		t.Errorf("%d more frames on the wire behind a field block that has no END_HEADERS",
			got-before)
	}
}

// --- construction ---

func TestNewWriterRefusesToBeBuiltWithoutItsThreeParts(t *testing.T) {
	// All three are dereferenced later and from a stream goroutine, so without these the
	// symptom is a nil method call inside a handler's first write — or, for the stream
	// identifier, a HEADERS frame on stream 0, which §6.2 makes a connection error of type
	// PROTOCOL_ERROR. One broken response would take every other stream down with it.
	enc, _, _ := newEncoder()
	for _, tc := range []struct {
		name  string
		build func()
	}{
		{"no encoder", func() { NewWriter(nil, &fakeCredit{}, 1) }},
		{"no credit", func() { NewWriter(enc, nil, 1) }},
		{"stream 0", func() { NewWriter(enc, &fakeCredit{}, 0) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Errorf("NewWriter with %s returned instead of panicking", tc.name)
				}
			}()
			tc.build()
		})
	}
}

// --- one lock over the frames, and where it is not held ---

func TestAnotherStreamsHeaderSectionGoesOutWhileOneWaitsForCredit(t *testing.T) {
	// Reserve is outside the Encoder's lock, and this is why it has to be. A peer that
	// stops reading one stream leaves that stream parked in Reserve for as long as it
	// likes — there is no timeout that would be correct, because a slow client is not a
	// broken one. If the lock were held across it, every other stream on the connection
	// would be unable to send so much as a header section, and one slow reader would stall
	// forty other responses.
	//
	// Three frames for the second stream's block, so what gets through is a whole burst
	// and not one frame that happened to fit.
	enc, c, tr := newEncoder()
	c.block = func(n int, _ []h2.Field) []byte { return filler(2*maxFrame+1, byte('a'+n)) }
	cr := (&fakeCredit{}).park()
	a, b := NewWriter(enc, cr, 1), NewWriter(enc, cr, 3)

	if err := a.WriteHeader(okFields()); err != nil {
		t.Fatalf("stream 1 WriteHeader: %v", err)
	}

	body := make(chan error, 1)
	go func() { _, err := a.Write(filler(maxFrame, 'b')); body <- err }()
	<-cr.entered // stream 1 is now parked for credit, holding no lock we know of yet

	header := make(chan error, 1)
	go func() { header <- b.WriteHeader(okFields()) }()
	select {
	case err := <-header:
		if err != nil {
			t.Fatalf("stream 3 WriteHeader: %v", err)
		}
	case <-time.After(gateWait):
		t.Fatalf("stream 3's header section could not be sent while stream 1 was waiting " +
			"for flow-control credit: the Encoder's lock is held across Reserve, so one " +
			"slow reader stalls every other stream on the connection")
	}

	cr.release <- nil
	if err := <-body; err != nil {
		t.Fatalf("stream 1 Write: %v", err)
	}
	// And the two streams did not interleave: stream 3's burst went out whole, and stream
	// 1's DATA frame is either before all of it or after all of it.
	if bs := blocks(t, tr.taken()); len(bs) != 2 {
		t.Errorf("%d field blocks, want 2", len(bs))
	}
}

func TestNoHeaderSectionIsEncodedWhileADataFrameIsBeingEnqueued(t *testing.T) {
	// The converse, and the constraint that makes DATA go out through the Encoder at all.
	// A DATA frame needs no HPACK context and no ordering against other streams' bodies,
	// so a Writer with a Transport of its own would send correct DATA — right up to the
	// first frame that landed between a HEADERS frame and its CONTINUATION frames. §8.1:
	// "Other frames (from any stream) MUST NOT occur between the HEADERS frame and any
	// CONTINUATION frames that might follow", and §6.10 makes it a connection error of
	// type PROTOCOL_ERROR.
	//
	// Deterministic in the direction that matters, the same way the Encoder's own lock
	// test is: while one goroutine is parked in Enqueue the gate has exactly one possible
	// sender left, so an arrival is a second goroutine that got past the lock and the
	// absence of one is the guard holding. The wait is a proof of absence — it has to be
	// waited out on the passing path, and a break that drops the lock fires it at once.
	enc, c, tr := newEncoder()
	tr.gate()
	cr := &fakeCredit{}
	a, b := NewWriter(enc, cr, 1), NewWriter(enc, cr, 3)

	head := make(chan error, 1)
	go func() { head <- a.WriteHeader(okFields()) }()
	<-tr.entered
	tr.release <- nil
	if err := <-head; err != nil {
		t.Fatalf("stream 1 WriteHeader: %v", err)
	}

	body := make(chan error, 1)
	go func() { _, err := a.Write(filler(maxFrame, 'b')); body <- err }()
	<-tr.entered // stream 1's DATA frame is now inside Enqueue, holding the lock

	header := make(chan error, 1)
	go func() { header <- b.WriteHeader(okFields()) }()
	select {
	case <-tr.entered:
		t.Fatalf("stream 3's header block reached the transport while stream 1's DATA " +
			"frame was still being enqueued: a body can land inside another stream's " +
			"header burst")
	case <-time.After(gateWait):
	}

	// One encode, because the second goroutine is still waiting for the lock. Read while
	// that goroutine is blocked and the first is parked in the gate, so nothing is writing
	// this field.
	if len(c.encodes) != 1 {
		t.Errorf("%d blocks encoded while a DATA frame was being enqueued, want 1", len(c.encodes))
	}

	tr.release <- nil
	if err := <-body; err != nil {
		t.Fatalf("stream 1 Write: %v", err)
	}
	<-tr.entered
	tr.release <- nil
	if err := <-header; err != nil {
		t.Fatalf("stream 3 WriteHeader: %v", err)
	}
}

func TestBodiesNeverInterleaveWithHeaderSections(t *testing.T) {
	// The same invariant under contention, which is where it is actually at risk: every
	// stream here writes a three-frame header block, a three-frame body and a Close, all
	// at once, and every frame of every burst has to reach the transport as a unit.
	//
	// blocks() is the assertion. It walks the recorded frame stream and fails on a DATA
	// frame, a second HEADERS frame, or a CONTINUATION for another stream while a block is
	// open — which is §8.1's "Other frames (from any stream) MUST NOT occur between the
	// HEADERS frame and any CONTINUATION frames that might follow" read off the wire.
	//
	// The race detector runs over this package, so this is also where a Writer used by one
	// goroutine and an Encoder shared by many is checked to be exactly that.
	const (
		streams = 32
		block   = 2*maxFrame + 1
		body    = 2*maxFrame + 1
	)

	enc, c, tr := newEncoder()
	c.block = func(n int, _ []h2.Field) []byte { return filler(block, byte(n)) }
	cr := &fakeCredit{}

	var wg sync.WaitGroup
	for i := range streams {
		id := uint32(2*i + 1)
		w := NewWriter(enc, cr, id)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := w.WriteHeader(okFields()); err != nil {
				t.Errorf("stream %d WriteHeader: %v", id, err)
				return
			}
			if _, err := w.Write(filler(body, byte(id))); err != nil {
				t.Errorf("stream %d Write: %v", id, err)
				return
			}
			if err := w.Close(); err != nil {
				t.Errorf("stream %d Close: %v", id, err)
			}
		}()
	}
	wg.Wait()

	fs := tr.taken()
	if bs := blocks(t, fs); len(bs) != streams {
		t.Errorf("%d header blocks for %d streams, want one each", len(bs), streams)
	}

	// Every stream's body arrived whole and in order, with its own END_STREAM last. Keyed
	// by stream rather than by position, because the streams are interleaved with each
	// other by design and only a stream's own frames have an order.
	seen := map[uint32][]frame.Frame{}
	for _, f := range fs {
		if d, ok := f.(frame.DataFrame); ok {
			seen[d.StreamID] = append(seen[d.StreamID], d)
		}
	}
	if len(seen) != streams {
		t.Fatalf("%d streams sent DATA frames, want %d", len(seen), streams)
	}
	for id, ds := range seen {
		got := checkBody(t, ds, id, maxFrame)
		if want := filler(body, byte(id)); !bytes.Equal(got, want) {
			// Every stream fills its body with its own identifier, so the first octet of
			// a body that came out wrong names the stream whose content turned up in it.
			t.Errorf("stream %d's body reassembles to %d octets filled with %s, want %d "+
				"octets filled with %d", id, len(got), filled(got), body, byte(id))
		}
		if d := ds[len(ds)-1].(frame.DataFrame); !d.EndStream {
			t.Errorf("stream %d's last DATA frame does not end the stream", id)
		}
	}
}

// filled names the octet a reassembled body begins with, for a failure message that has to
// say which stream's content turned up in another stream's frames.
func filled(b []byte) string {
	if len(b) == 0 {
		return "nothing"
	}
	return strconv.Itoa(int(b[0]))
}
