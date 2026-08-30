// Package exchange runs a request against a handler.
//
// It is the layer above internal/stream and the last one below the handler: the stream
// table hands it a decoded header block, then the body one DATA frame at a time, then
// either the peer's END_STREAM or the news that the peer gave up, and this package
// turns that into one call to a Handler with an io.Reader for the content and an
// internal/response Writer for the answer.
//
// # Where the goroutines are
//
// Here, and nowhere below. Every method of stream.Requests is called from the
// connection's single reader goroutine and none of them may block — that goroutine is
// also the one answering the peer's PING frames and noticing its GOAWAY — while a
// handler is arbitrary code that may block for as long as it likes. So the goroutine
// per request is created here, which is what stream.Requests means by "the goroutine
// boundary is deliberately not here".
//
// One goroutine per stream, bounded by §5.1.2's concurrency limit — this server
// advertises SETTINGS_MAX_CONCURRENT_STREAMS 100 and the table enforces it — so a
// connection holds at most a hundred of them, and a peer that wants more has to open
// more connections and meet limits.MaxConns instead.
//
// # What crosses between them
//
// Three things, and all of them are arranged so that nothing else has to. The request
// body crosses forwards, through Body, which is a buffer behind a mutex and a condition
// variable. Two facts cross back: that a response has finished, through
// Table.ReportSendEnd, and how much request content a handler has read, through
// Table.ReportConsumed — both lists of numbers behind a mutex the stream table applies
// on its own goroutine at the next frame.
//
// The second of those is what lets a request body exceed one flow-control window. The
// peer may only send what its window allows and this server has to give that credit
// back as its handler consumes it (§6.9), so the octets a Read took have to reach the
// reader goroutine, and a Read is a handler's goroutine by definition. See Body.Read for
// why the report is made with Body's own lock released.
//
// Nothing else is shared. The stream table, its map, its windows and the HPACK
// decoding context stay with the reader goroutine; the response encoder and the
// connection's send-side flow control are shared by every stream and are locked
// internally, by internal/response and internal/flow respectively. A *stream.Stream is
// handed to Headers and is deliberately not kept: its state is the reader goroutine's,
// and this package keeps identifiers instead.
package exchange

import (
	"errors"
	"io"
	"log"
	"runtime/debug"

	"zerodeps/zdh/internal/flow"
	"zerodeps/zdh/internal/h2"
	"zerodeps/zdh/internal/priority"
	"zerodeps/zdh/internal/request"
	"zerodeps/zdh/internal/response"
	"zerodeps/zdh/internal/stream"
)

// What this package is on both of its sides, checked at compile time.
//
// The third is the one worth having. The stream table hands out a *flow.Sender for the
// send-side window and internal/response asks for a Credit; neither imports the other,
// on purpose, and this is where the two halves are wired together — so if they ever
// stop fitting, it is a build failure here rather than in whatever wires them next.
var (
	_ stream.Requests = (*Requests)(nil)
	_ Streams         = (*stream.Table)(nil)
	_ response.Credit = (*flow.Sender)(nil)
	_ io.Reader       = (*Body)(nil)
)

// serverError is the response a request gets when its handler did not produce one: a
// bare 500 with no content.
//
// No content-length field. §8.6 of RFC 9110 makes it optional, and a response with
// nothing in it needs no help being understood; the field would only be one more thing
// for a handler-of-last-resort to get wrong.
var serverError = []h2.Field{{Name: ":status", Value: "500"}}

// Handler answers requests.
//
// Serve is called on a goroutine of its own, once per request, with a Writer for the
// stream that request arrived on. It answers by writing a header section and then a
// body, a trailer section or nothing (see response.Writer for the order §8.1 fixes);
// it may return without writing anything at all, and gets a 500 for it.
//
// A panic is contained: it is logged with its stack and the stream it happened on is
// ended, and the connection and every other stream on it carry on. That is a promise
// about this server's behaviour and not an invitation — a handler that panics is a bug
// whose response is truncated, and the log line is there to get it fixed.
type Handler interface {
	Serve(w *response.Writer, r *Request)
}

// Request is one request as its handler sees it: §8.3's control data and field lines,
// already validated by internal/request, and the content as a reader.
type Request struct {
	*request.Request

	// Body is the content, never nil. A request that had none is a Body that reports
	// io.EOF at once, so a handler that reads it needs no special case for a GET.
	Body *Body
}

// Streams is the stream table as this package needs it: the two calls back into it that
// a request in progress has to make.
//
// Declared here rather than imported so that the dependency is a method and not a
// package — but mostly so that a test can watch the calls happen. See stream.Table's
// ReportSendEnd and ReportConsumed for why they are reports rather than state changes.
type Streams interface {
	ReportSendEnd(id uint32)
	ReportConsumed(id uint32, n int, more bool)
}

// Priorities is the write side's scheduler as this package needs it: the one call that
// tells it what a request asked for.
//
// Declared here rather than imported for the same reason Streams is, and with one extra
// reason of its own. The implementation is the connection's frame writer, which lives in
// the package that constructs this one, so importing it to write a compile-time
// assertion would be importing the layer above. The assignment in cmd/zdh is the check,
// and it is a build failure in the four lines that wire a connection.
type Priorities interface {
	// Prioritize is what the client asked for on stream id, and it is a complete
	// signal rather than a partial one: a parameter the client left out is a
	// parameter at its default, not one to carry over from an earlier signal. §4 of
	// RFC 9218: "When receiving an HTTP request that does not carry these priority
	// parameters, a server SHOULD act as if their default values were specified."
	//
	// So the most recent call wins outright, and nothing here merges.
	Prioritize(id uint32, p priority.Params)
}

// Config is what running a request needs.
type Config struct {
	// Handler answers the requests. Required.
	Handler Handler

	// Encoder is the connection's response encoder, shared by every stream on it and
	// locked internally. Required.
	Encoder *response.Encoder

	// Credit is the connection's send-side flow control, which is *flow.Sender.
	// Required.
	Credit response.Credit

	// Priorities receives the priority signal a request carried in its own header
	// section (§5 of RFC 9218). Nil discards them, and every response is then
	// scheduled at §4's defaults.
	//
	// Optional, unlike the three above it, and that is a claim about the protocol
	// rather than a convenience. §10 of RFC 9218: "Endpoints cannot depend on
	// particular treatment based on priority signals." A server that reads the field
	// and does nothing with it is conformant, so a nil here is a configuration and not
	// a wiring mistake — which is why New does not panic on it the way it does on a
	// missing encoder, and why cmd/zdh has a test that it is nevertheless supplied.
	Priorities Priorities

	// Log receives one line for every handler that panicked, with its stack. Nil
	// discards them, which is right for a test and wrong for a deployment: a
	// contained panic that nobody logs is a bug that never gets fixed.
	Log *log.Logger
}

// Requests runs one connection's requests. It satisfies stream.Requests.
type Requests struct {
	handler Handler
	enc     *response.Encoder
	credit  response.Credit
	prios   Priorities
	log     *log.Logger

	// streams is where a finished response is reported. Not in Config, because the
	// stream table is constructed with this value and cannot also be one of its
	// arguments: see Attach.
	streams Streams

	// arriving is the request side of every stream whose content is still coming,
	// keyed by identifier. A request that arrived complete — the common case, every
	// GET — is never in here at all, and one that is leaves the moment its last
	// frame arrives, so the map holds uploads in flight and nothing else.
	//
	// Touched only from the connection's reader goroutine, which is why it is a plain
	// map with no lock: Headers, Data, Trailers, Canceled and Close are all called
	// from there, in frame arrival order. The handler goroutines never see it — they
	// hold their own Body, which has its own lock.
	arriving map[uint32]*inbound
}

// inbound is the request side of one stream while it is still arriving.
type inbound struct {
	body *Body

	// declared is the content-length the request stated, or request.NoContentLength.
	// received is what has arrived. §8.1.1 makes the two disagreeing a malformed
	// request; see Data.
	declared int64
	received int64
}

// New returns the request layer for one connection.
//
// Attach must be called before the first frame reaches it. Every other dependency is
// checked here, and each is checked because each is dereferenced later from a handler's
// goroutine, where a nil would surface as a panic in the middle of a peer's request
// rather than at the line that forgot it.
func New(cfg Config) *Requests {
	if cfg.Handler == nil {
		panic("exchange: New requires a handler")
	}
	if cfg.Encoder == nil {
		panic("exchange: New requires a response encoder")
	}
	if cfg.Credit == nil {
		panic("exchange: New requires a source of flow-control credit")
	}
	return &Requests{
		handler:  cfg.Handler,
		enc:      cfg.Encoder,
		credit:   cfg.Credit,
		prios:    cfg.Priorities,
		log:      cfg.Log,
		arriving: make(map[uint32]*inbound),
	}
}

// Attach supplies the stream table, which does not exist when New is called because it
// is constructed with the value New returns.
//
// A construction cycle, and this is the honest way through it: two objects that each
// need the other, one of them built first and told about the second in the same
// function, before either has seen a frame. The alternative — a closure over a variable
// that is still nil, or a table that made its own request layer — hides the same
// ordering in something harder to read.
//
// Panics on a nil table, and on a second call. Both are wiring mistakes in the few
// lines that build a connection, and a panic there happens once, at startup, in front
// of whoever wrote them. A silent overwrite would instead send one connection's
// finished responses to another connection's table.
func (r *Requests) Attach(s Streams) {
	if s == nil {
		panic("exchange: Attach requires a stream table")
	}
	if r.streams != nil {
		panic("exchange: the stream table is already attached")
	}
	r.streams = s
}

// Headers begins a request: it validates the header section per §8.3 and starts the
// goroutine that answers it.
//
// A request that arrived with END_STREAM is complete, and its Body reports io.EOF from
// the first read. One that did not is recorded in arriving until its last frame.
//
// The order here is the part worth being careful about. Validation happens before the
// goroutine exists, so a malformed request is a stream error this returns and never a
// handler that has already answered it — §8.1.1 permits an endpoint to have "performed
// some processing before identifying a request [...] as malformed", and not needing
// that permission is better than using it.
//
// # Why the Priority field is applied from here
//
// Because here is the connection's reader goroutine, and being on it is the whole
// arbitration between RFC 9218's two carriers. §7 of RFC 9218 settles which wins: "for
// the purposes of scheduling, the most recently received PRIORITY_UPDATE frame can be
// considered as the most up-to-date information that overrides any other signal."
//
// Nothing here compares timestamps or remembers where a signal came from, and it does
// not have to, because both carriers reach the write side from this one goroutine in
// arrival order. A frame that arrived first was buffered and is applied by conn.leftIdle
// after this returns; a frame that arrives later is applied when it arrives. Either way
// the frame's call to Prioritize is the last one, which is what §7 asks for.
//
// That is not luck. leftIdle runs after this because the connection defers it past the
// stream layer's handling of the frame that opened the stream — written that way so a
// stream the table refuses cannot leak a priority nothing will retire, and the override
// falls out of the same line. See conn.handleStreamFrame.
func (r *Requests) Headers(s *stream.Stream, fields []h2.Field, endStream bool) error {
	req, err := request.Parse(s.ID(), fields, endStream)
	if err != nil {
		return err
	}

	body := newBody(s.ID(), r.streams)
	if endStream {
		body.end(nil)
	} else {
		r.arriving[s.ID()] = &inbound{body: body, declared: req.ContentLength}
	}

	// Before the goroutine that answers exists, so the first frame of the response is
	// already scheduled at the urgency the client asked for rather than at the default.
	//
	// The zero Params is skipped rather than applied. It means the field was absent —
	// or present and empty, which §4 of RFC 9218 makes the same thing — and applying it
	// would put an entry in the scheduler's table saying precisely what the absence of
	// an entry already says, once per request, under the writer's lock, on the
	// goroutine that also has to answer the peer's PING frames.
	if r.prios != nil && req.Priority != (priority.Params{}) {
		r.prios.Prioritize(s.ID(), req.Priority)
	}

	r.start(s.ID(), &Request{Request: req, Body: body})
	return nil
}

// Data hands one DATA payload to the handler and holds the request to §8.1.1's
// content-length rule.
//
// The rule is checked in two places because it fails in two ways. A body that has
// already exceeded what it declared is malformed at the frame that exceeds it, and is
// caught there rather than at the end — the octets past the declared length are
// content the peer has no business sending, and a handler that has been reading along
// must not be handed them. A body that ends short of what it declared is malformed at
// its END_STREAM, which is the first moment "short" means anything.
//
// §8.1.1: "A request or response is also malformed if the value of a content-length
// header field does not equal the sum of the DATA frame payload lengths that form the
// content", and malformed requests "MUST be treated as a stream error [...] of type
// PROTOCOL_ERROR".
func (r *Requests) Data(s *stream.Stream, b []byte, endStream bool) error {
	in := r.arriving[s.ID()]
	if in == nil {
		return r.notArriving("DATA", s.ID())
	}

	in.received += int64(len(b))
	if in.declared != request.NoContentLength && in.received > in.declared {
		return r.malformed(s.ID(), in, "content-length %d and %d octets of content so far",
			in.declared, in.received)
	}

	in.body.add(b)

	if endStream {
		if in.declared != request.NoContentLength && in.received != in.declared {
			return r.malformed(s.ID(), in, "content-length %d and %d octets of content",
				in.declared, in.received)
		}
		in.body.end(nil)
		delete(r.arriving, s.ID())
	}
	return nil
}

// Trailers delivers a request's trailer section, which ends it (§8.1).
//
// The content-length check is the same one Data makes at END_STREAM, and it is made
// again here because a trailer section is the other way a request can end: a peer that
// declared ten octets, sent four and then sent trailers has sent a malformed request,
// and the trailer section is where that becomes visible.
func (r *Requests) Trailers(s *stream.Stream, fields []h2.Field) error {
	in := r.arriving[s.ID()]
	if in == nil {
		return r.notArriving("trailers", s.ID())
	}

	if err := request.ValidateTrailers(s.ID(), fields); err != nil {
		in.body.fail(err)
		delete(r.arriving, s.ID())
		return err
	}
	if in.declared != request.NoContentLength && in.received != in.declared {
		return r.malformed(s.ID(), in, "content-length %d and %d octets of content",
			in.declared, in.received)
	}

	in.body.end(fields)
	delete(r.arriving, s.ID())
	return nil
}

// Canceled reports that the peer abandoned a stream, waking a handler parked on its
// body.
//
// Nothing is done about the response, and nothing needs to be: the stream's send window
// has been retired by the stream table, so the next write from that handler returns
// flow.ErrStreamGone, and a handler that is parked waiting for send credit has already
// been woken by the same retirement.
//
// A stream whose request arrived complete is not in arriving and there is nothing here
// to wake — its handler cannot be reading a body, only writing.
func (r *Requests) Canceled(s *stream.Stream, code h2.ErrCode) {
	in := r.arriving[s.ID()]
	if in == nil {
		return
	}
	in.body.fail(h2.StreamErrorf(s.ID(), code, "the peer reset the stream"))
	delete(r.arriving, s.ID())
}

// Close reports that the connection is over, waking every handler parked on a request
// body with err.
//
// The other half of the same job is stream.Table.Close, which wakes the handlers parked
// for send credit, and neither covers the other: a body is waited on here, a window is
// waited on there, and a handler blocked reading an upload is not reachable from flow
// control. A connection whose reader goroutine has stopped and whose handlers are still
// parked is a goroutine leak per connection, which is a leak a peer can arrange as fast
// as it can open sockets.
//
// Called from the reader goroutine after the read loop has stopped, like Table.Close,
// which is what makes touching arriving here safe.
func (r *Requests) Close(err error) {
	for id, in := range r.arriving {
		in.body.fail(err)
		delete(r.arriving, id)
	}
}

// start runs one request's handler on its own goroutine.
func (r *Requests) start(id uint32, req *Request) {
	w := response.NewWriter(r.enc, r.credit, id)

	go func() {
		defer func() {
			if v := recover(); v != nil {
				// The stack is the whole value of this line, as it is in
				// internal/server: a contained panic with no stack is a bug that
				// gets logged for months and never found.
				r.logf("stream %d: the handler panicked: %v\n%s", id, v, debug.Stack())
			}
			r.finish(id, w)
		}()

		r.handler.Serve(w, req)
	}()
}

// finish ends the response, whatever the handler did or failed to do, and reports the
// stream as sent.
//
// Close is the ordinary path and returns nil for a handler that already ended its own
// response. response.ErrNoHeader is the one outcome that needs answering: it means
// nothing was written at all — a handler that returned without writing, or one that
// panicked before it could — and a stream with no response on it is a client waiting
// for its own timeout. So it gets a 500, which is §8.1.1's "a server MAY send an HTTP
// response prior to closing or resetting the stream" put to its most boring use.
//
// A handler that panicked *after* writing a header section is the case with no good
// answer, and it gets the least bad one: the response is ended where it stopped. If it
// declared a content-length — every response from internal/static does — the peer sees
// content shorter than the declaration and §8.1.1 makes that malformed, which is the
// truth. RST_STREAM with INTERNAL_ERROR would say it more directly and is what this
// server does not do, because §5.1 requires an endpoint to ignore frames on a stream it
// has reset, and knowing which streams those are means remembering identifiers a peer
// chose for as long as its frames might still be in flight. That is a peer-controlled
// allocation bought for a case that is a bug on this side of the connection.
//
// Both writes ignore their errors, and the reason is the same for both: the only
// failure either can have left is a connection whose writer has stopped, and a
// response is not the place that gets reported — internal/server already knows, and
// every other stream on the connection is finding out the same way.
func (r *Requests) finish(id uint32, w *response.Writer) {
	if err := w.Close(); errors.Is(err, response.ErrNoHeader) {
		_ = w.WriteBodylessHeader(serverError)
	}
	r.streams.ReportSendEnd(id)
}

// malformed fails the handler's body and returns §8.1.1's stream error.
//
// Both halves are needed and the order is not arbitrary. The stream error is what
// resets the stream; failing the body is what stops the handler, which the reset does
// not do on its own — a handler parked in Read on a request the table is about to
// abandon would park for the rest of the connection. Waking it first means the goroutine
// is already unwinding by the time the RST_STREAM is enqueued.
func (r *Requests) malformed(id uint32, in *inbound, format string, args ...any) error {
	err := h2.StreamErrorf(id, h2.ProtocolError, "malformed request: "+format, args...)
	in.body.fail(err)
	delete(r.arriving, id)
	return err
}

// notArriving is the answer to a frame for a request that is not arriving: a body
// frame on a stream whose request already ended, or one that never had a request.
//
// A connection error, and the type is deliberate. The stream table does not deliver
// either — it answers a DATA frame after END_STREAM with §5.1's STREAM_CLOSED and a
// frame on an unknown stream before that, from its own state machine, and every path
// that leaves this package's map either ends the request or resets the stream. So this
// is not a peer's doing and cannot be answered by resetting the stream the peer named:
// the two layers disagree about what is open, and one of them is wrong about every
// stream on the connection.
func (r *Requests) notArriving(kind string, id uint32) error {
	return h2.ConnErrorf(h2.InternalError,
		"%s for stream %d, whose request is not arriving", kind, id)
}

// logf writes one line, or discards it if there is nowhere to write.
func (r *Requests) logf(format string, args ...any) {
	if r.log == nil {
		return
	}
	r.log.Printf(format, args...)
}
