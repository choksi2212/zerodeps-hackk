// Package static serves files out of one directory.
//
// It is an exchange.Handler, which makes it the top of this server: below it is a
// response Writer and a validated request, and below those the streams, the frames and
// the socket. Everything under this package is HTTP/2; this package is the part that has
// an opinion about what to send.
//
// # What it answers
//
// GET and HEAD, from a single directory tree. A target names a file, which is sent with a
// content-length and a content-type; a target naming a directory is answered with that
// directory's index.html, and one naming a directory without a trailing slash is
// redirected to the same target with one, so that the relative links inside the index
// resolve against the directory rather than against its parent. Anything else — a missing
// file, a directory with no index, a device, a socket, a name that could not be a file —
// is a 404. Any other method is a 405 with an allow field.
//
// # What it does not do
//
// Listed here because a handler's scope is the part of it a reader cannot infer, and
// because each of these is a decision rather than an omission:
//
//   - No directory listings. A listing discloses every name in a directory to anyone who
//     guesses the directory. A server whose root is a build output should not be the
//     thing that publishes the file nobody meant to copy there.
//   - No range requests, and so no accept-ranges field. §14 of RFC 9110: "Range requests
//     are an OPTIONAL feature of HTTP, designed so that recipients not implementing this
//     feature (or not supporting it for the target resource) can respond as if it is a
//     normal GET request without impacting interoperability" — and §14.2 of RFC 9110 says
//     what that looks like from here: "A server MAY ignore the Range header field." A
//     browser seeking in a video re-fetches it from the start.
//   - No conditional requests, and so no last-modified and no ETag. §13.2.2's precondition
//     rules are engaged by a request that carries a precondition, and a response with no
//     validator in it is one no cache can build a precondition from — so the rule is
//     satisfied by having nothing to evaluate, and the cost is that every request
//     transfers the whole file. A validator and the four precondition fields are the next
//     increment, not a missing piece of this one.
//   - No content codings. Nothing is compressed on the way out and no .gz beside a file
//     is served in its place, so §8.4's content-encoding field is never sent and every
//     response carries its representation data as the file holds it.
//   - No caching fields. No cache-control, no expires, no age. A response with none of
//     them is heuristically cacheable per §4.2.2 of [CACHING], which for a static file is
//     the behaviour a deployment wants and would otherwise have to ask for.
//
// # Confinement
//
// Every open goes through an os.Root, which is the standard library's directory handle:
// its methods cannot reach a file outside the tree, a symbolic link inside the tree may
// not point out of it, and on Windows the reserved device names are refused. That is the
// mechanism, and it is not ours — which is the point. What is ours is in path.go, which
// decides what a target means before it becomes a syscall, and refuses on its own the
// names that mean two things on one platform and one thing on another.
//
// # Errors, and where they go
//
// Nowhere. Every write in this package can fail in exactly one way — the stream was reset
// or the connection ended — and a response is not a channel for reporting that a response
// could not be sent. internal/server already knows, internal/exchange will end the stream
// whatever happens here, and every other stream on the connection is finding out the same
// way. So Serve drops the error, once, at the one line that can, and serve returns it for
// the tests that want to see which write stopped.
//
// Nothing about a peer's request is logged, either: not a 404, not a refused target, not a
// traversal attempt. The volume of that log is the peer's to choose, and a log a stranger
// can drive is a disk a stranger can fill.
package static

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"zerodeps/zdh/internal/exchange"
	"zerodeps/zdh/internal/h2"
	"zerodeps/zdh/internal/limits"
	"zerodeps/zdh/internal/response"
)

// What this package is, checked at compile time.
var _ exchange.Handler = (*Handler)(nil)

// The methods this handler has an answer for, and the field that says so.
//
// §15.5.6 of RFC 9110: "The origin server MUST generate an Allow header field in a 405
// response containing a list of the target resource's currently supported methods." The
// list is a constant because the answer does not depend on the target — every file here
// supports the same two methods, and a 405 for one is a 405 for all of them.
//
// OPTIONS is not among them, which is why it gets the 405 rather than an empty 200: §9.3.7
// makes OPTIONS a request about communication options, and a server that answered it with
// this list and nothing else would be claiming to implement a method in order to describe
// the two it does implement.
const (
	methodGet  = "GET"
	methodHead = "HEAD"

	allowedMethods = "GET, HEAD"
)

// The statuses this handler sends, and the sentences that go with them.
//
// A body on an error response rather than a bare status, because the reader of a 404 is
// usually a person with a terminal, and "404 not found" in the content is what curl shows
// them without being asked. Deliberately not the target that produced it: reflecting a
// peer's own bytes into a response body is a habit worth not having, and there is nothing
// here it would explain.
const (
	status200 = "200"
	status301 = "301"
	status404 = "404"
	status405 = "405"
	status414 = "414"

	body404 = "404 not found\n"
	body405 = "405 method not allowed\n"
	body414 = "414 URI too long\n"
)

// serverName is the server field's value.
//
// §10.2.4 of RFC 9110 permits it and warns about it in the same section: the field
// advertises the software to whoever is scanning for a version with a known hole, so this
// one names the program and not its version. Sent because a demonstration server that
// cannot be identified in a packet capture is harder to demonstrate.
const serverName = "zdh"

// imfFixdate is the one date format this server generates.
//
// §5.6.7 of RFC 9110: "When a sender generates a field that contains one or more
// timestamps defined as HTTP-date, the sender MUST generate those timestamps in the
// IMF-fixdate format." Which is this layout, in GMT, with the day zero-padded to two
// digits — hence "02" rather than "2", the difference between a fixed-width date and one
// that is a day narrower for nine days of every month.
const imfFixdate = "Mon, 02 Jan 2006 15:04:05 GMT"

// errFileChanged reports that a file was shorter than its own size by the time it had
// been sent. See Handler.file.
var errFileChanged = errors.New("static: the file was truncated while it was being sent")

// Config is what serving a directory needs.
type Config struct {
	// Dir is the directory served, and the only thing that can be reached through this
	// handler. Required.
	Dir string

	// Now is where the date field's value comes from. Nil means time.Now, which is what
	// a deployment wants.
	//
	// A seam, and it is here for one specific test rather than for generality: with a
	// real clock the only assertion available about a date field is that it parses,
	// which a field generated in the local zone would also pass on a machine whose zone
	// is UTC. Pinned, the field is a constant and the test fails everywhere. A guard
	// that only fires in some time zones is not a guard.
	Now func() time.Time
}

// Handler serves files from one directory. It satisfies exchange.Handler.
type Handler struct {
	root *os.Root
	now  func() time.Time

	// bufs holds the copy buffers, one per response in flight.
	//
	// A 16 KiB buffer per request is 16 KiB of garbage per request, which at any rate
	// worth benchmarking is the largest allocation this server makes and the only one
	// proportional to the number of responses rather than to the number of connections.
	// Pooled pointers rather than slices: a []byte in an interface allocates to store the
	// header, which is the allocation the pool is here to avoid.
	//
	// The size is also what bounds the DATA frames a body arrives in, since io.CopyBuffer
	// hands Write one buffer at a time: a peer advertising a larger frame size than this
	// gets 16 KiB frames anyway, which §4.2 permits — "Endpoints are not obligated to use
	// all available space in a frame". The alternative is a buffer sized by whatever the
	// peer asked for, which is memory per response that the peer is choosing.
	bufs sync.Pool
}

// New opens dir and returns a handler serving it.
//
// An error rather than a panic, unlike New in the layers below. The difference is where
// the value comes from: a nil encoder is a wiring mistake in the twenty lines that build
// a connection, and a directory that does not exist is an operator's typo on a command
// line. The first should stop the program in front of the person who wrote it; the second
// should be a sentence on stderr and a non-zero exit.
func New(cfg Config) (*Handler, error) {
	if cfg.Dir == "" {
		return nil, errors.New("static: New requires a directory to serve")
	}

	// OpenRoot resolves the directory once, here, and every later open is relative to the
	// handle it returns. So a deployment that renames or replaces the directory under a
	// running server keeps serving the tree it started with rather than following the
	// name to whatever now answers to it.
	root, err := os.OpenRoot(cfg.Dir)
	if err != nil {
		return nil, err
	}

	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	return &Handler{
		root: root,
		now:  now,
		bufs: sync.Pool{New: func() any {
			b := make([]byte, limits.MaxFrameSize)
			return &b
		}},
	}, nil
}

// Close releases the served directory's handle.
//
// A handler outlives every connection, so this is the program shutting down and not a
// request ending. Responses in flight hold their own file handles and are unaffected.
func (h *Handler) Close() error {
	return h.root.Close()
}

// Dir is the directory being served, as os.Root reports it.
func (h *Handler) Dir() string {
	return h.root.Name()
}

// Serve answers one request. It satisfies exchange.Handler.
func (h *Handler) Serve(w *response.Writer, r *exchange.Request) {
	// The one place the error goes, and the package doc says why. Written as an
	// assignment to nothing rather than as a bare call so that it is visibly a decision
	// and not an oversight.
	_ = h.serve(w, r)
}

// serve is Serve with its error still in hand, which is how the tests read it.
func (h *Handler) serve(w *response.Writer, r *exchange.Request) error {
	// The method first, before the target is looked at at all. A 405 for a POST to a
	// missing file is a better answer than a 404, because the method is wrong whatever
	// the target was — and checking it here is also what disposes of OPTIONS with a "*"
	// target, which is the one request internal/request allows through with a path that
	// is not a path.
	if r.Method != methodGet && r.Method != methodHead {
		return h.answer(w, r, status405, textPlain, body405,
			h2.Field{Name: "allow", Value: allowedMethods})
	}

	if len(r.Path) > MaxTargetLength {
		return h.answer(w, r, status414, textPlain, body414)
	}

	name, slash, ok := resolve(r.Path)
	if !ok {
		return h.answer(w, r, status404, textPlain, body404)
	}

	f, info, err := h.open(name)
	if err != nil {
		return h.answer(w, r, status404, textPlain, body404)
	}

	if info.IsDir() {
		f.Close()
		if !slash {
			// The location is the peer's own target with a slash on the end, which
			// keeps whatever percent-encoding it used — re-encoding the resolved name
			// would be a second encoder to get wrong. It is a safe value to echo: the
			// path arrived free of control octets and of anything below "!" per
			// §8.3.1's rules in internal/request, and internal/response holds every
			// field line to §8.2.1 again on the way out.
			return h.answer(w, r, status301, "", "",
				h2.Field{Name: "location", Value: withSlash(r.Path)})
		}
		name = join(name, indexFile)
		if f, info, err = h.open(name); err != nil {
			return h.answer(w, r, status404, textPlain, body404)
		}
	}
	defer f.Close()

	// A directory whose index.html is itself a directory lands here, as does a named
	// pipe, a device that os.Root let through, or a symbolic link to one. None of them
	// has a length worth declaring or content worth sending, and a read from some of
	// them would block until the connection died.
	if !info.Mode().IsRegular() {
		return h.answer(w, r, status404, textPlain, body404)
	}

	return h.file(w, r, f, info.Size(), mediaType(name))
}

// open opens a name inside the served directory and stats the handle.
//
// The stat is on the handle rather than on the name, which is what makes the size, the
// mode and the content one file: a name stat'ed and then opened is two lookups with a
// window between them, and the window is where the file becomes a symbolic link to
// something else. os.Root closes the traversal hole; this closes the double-lookup one.
func (h *Handler) open(name string) (*os.File, fs.FileInfo, error) {
	f, err := h.root.Open(name)
	if err != nil {
		return nil, nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, info, nil
}

// file sends f's first size octets as a 200.
//
// size comes from the same handle the content does, so the content-length and the content
// agree unless the file changes underneath the response — a build writing into the served
// directory while a browser reads from it. A file that grew is sent as it was, which is
// what the length says; a file that shrank cannot be, and there is no honest way to fix it
// from here. §8.6 of RFC 9110 makes the short body malformed and a peer will say so, which
// is the truth about what happened. RST_STREAM would say it in the protocol instead, and
// internal/exchange explains at finish why this server does not have one to send.
func (h *Handler) file(w *response.Writer, r *exchange.Request, f *os.File, size int64, kind string) error {
	fields := h.fields(status200, kind, size)

	// §9.3.2 of RFC 9110: "The server SHOULD send the same header fields in response to a
	// HEAD request as it would have sent if the request method had been GET." Including the
	// content-length, which §8.6 of RFC 9110 permits only under this condition — "a server
	// MUST NOT send Content-Length in such a response unless its field value equals the
	// decimal number of octets that would have been sent in the content of a response if
	// the same request had used the GET method" — and which is satisfied by the value
	// being the one the GET would have used, from the same stat.
	//
	// An empty file takes the same path, because a header section with END_STREAM on it is
	// how a response with no content is framed. A zero-length DATA frame would also be
	// legal and would be one frame more than the response needs.
	if r.Method == methodHead || size == 0 {
		return w.WriteBodylessHeader(fields)
	}

	if err := w.WriteHeader(fields); err != nil {
		return err
	}

	buf := h.bufs.Get().(*[]byte)
	n, err := io.CopyBuffer(w, io.LimitReader(f, size), *buf)
	h.bufs.Put(buf)
	if err != nil {
		return err
	}

	// Closed before the mismatch is reported, and in that order deliberately: the stream
	// has to end whatever the file did, or a peer waits for content that is not coming.
	if err := w.Close(); err != nil {
		return err
	}
	if n != size {
		return errFileChanged
	}
	return nil
}

// answer sends a complete response whose content is body, which may be empty.
func (h *Handler) answer(w *response.Writer, r *exchange.Request, status, kind, body string, extra ...h2.Field) error {
	fields := append(h.fields(status, kind, int64(len(body))), extra...)

	// A HEAD gets the fields and no content, for the reason §9.3.2 of RFC 9110 gives above:
	// "The HEAD method is identical to GET except that the server MUST NOT send content in
	// the response." The content-length still describes the body a GET would have had.
	if r.Method == methodHead || body == "" {
		return w.WriteBodylessHeader(fields)
	}

	if err := w.WriteHeader(fields); err != nil {
		return err
	}
	if _, err := io.WriteString(w, body); err != nil {
		return err
	}
	return w.Close()
}

// fields is the header section every response here begins with.
//
// The pseudo-header first, because §8.3 requires it before any field line. The rest is in
// no particular order and is written in the order it is easiest to read.
func (h *Handler) fields(status, kind string, length int64) []h2.Field {
	// Room for the four this builds, the optional content-type, and one extra field
	// without a second allocation — every caller passes at most one.
	fields := make([]h2.Field, 0, 6)

	fields = append(fields,
		h2.Field{Name: ":status", Value: status},
		h2.Field{Name: "content-length", Value: strconv.FormatInt(length, 10)},
	)
	if kind != "" {
		fields = append(fields, h2.Field{Name: "content-type", Value: kind})
	}

	// §6.6.1 of RFC 9110: "An origin server with a clock (as defined in Section 5.6.7)
	// MUST generate a Date header field in all 2xx (Successful), 3xx (Redirection), and
	// 4xx (Client Error) responses, and MAY generate a Date header field in 1xx
	// (Informational) and 5xx (Server Error) responses." This server has a clock and every
	// response it builds here is one of the three, so the field is unconditional — the
	// 500 internal/exchange sends for a handler that wrote nothing is the one response
	// from this program without it, and it is in the paragraph's MAY.
	//
	// UTC, not the host's zone. IMF-fixdate is GMT by definition and the layout ends in a
	// literal "GMT", so formatting a local time would produce a field that lies by
	// whatever the offset is.
	fields = append(fields,
		h2.Field{Name: "date", Value: h.now().UTC().Format(imfFixdate)},
		h2.Field{Name: "server", Value: serverName},
	)
	return fields
}

// withSlash is a target with one appended to its path.
//
// The query stays a query: "/dir?a=1" redirects to "/dir/?a=1" and not to "/dir?a=1/",
// which would move the slash into the query's value and lose the redirect's whole point.
func withSlash(target string) string {
	if i := strings.IndexByte(target, '?'); i >= 0 {
		return target[:i] + "/" + target[i:]
	}
	return target + "/"
}

// join is name/elem, with "." meaning the served directory itself.
//
// Not path.Join, which would also clean the result — there is nothing left to clean here,
// since resolve has already removed every dot segment, and a second cleaning would be a
// second implementation of the rule that has to agree with the first.
func join(name, elem string) string {
	if name == "." {
		return elem
	}
	return name + "/" + elem
}
