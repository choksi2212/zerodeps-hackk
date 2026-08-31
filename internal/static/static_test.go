package static

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"zerodeps/zdh/internal/exchange"
	"zerodeps/zdh/internal/frame"
	"zerodeps/zdh/internal/h2"
	"zerodeps/zdh/internal/hpack"
	"zerodeps/zdh/internal/limits"
	"zerodeps/zdh/internal/request"
	"zerodeps/zdh/internal/response"
)

// The tests in this file drive the handler the way a connection does: a request built by
// internal/request out of a field list, a response written through a real
// response.Encoder over a real HPACK codec, and the frames that come out decoded again by
// a second codec standing in for the peer's. Nothing between the handler and the frames is
// a double, so an assertion here is an assertion about what a browser would receive.
//
// The requests go through request.Parse rather than being built by hand, which is what
// makes the traversal cases below worth anything: a target no peer could have sent fails
// the test loudly instead of being quietly exercised against a handler that will never see
// one.

// --- the harness -----------------------------------------------------------

// collector is the connection's write half: every frame the encoder enqueues, in order.
//
// No mutex, unlike internal/exchange's collector of the same name, and the difference is
// the point: this package's handler is called on the caller's goroutine and every write it
// makes is synchronous, so one response is one goroutine from the first frame to the last.
// TestServeIsConcurrencySafe gives each of its goroutines its own collector for that
// reason, which is also how a real connection's streams each have their own Writer.
type collector struct {
	frames []frame.Frame
	max    uint32

	// failFrom is the index of the first Enqueue to refuse, and err is what it returns.
	// A nil err never refuses; the field pair is how a stream that was reset mid-response
	// is reproduced without a peer.
	failFrom int
	err      error
}

func (c *collector) Enqueue(f frame.Frame) error {
	if c.err != nil && len(c.frames) >= c.failFrom {
		return c.err
	}
	c.frames = append(c.frames, f)
	return nil
}

func (c *collector) MaxFrameSize() uint32 { return c.max }

// grants is send-side flow control with no peer to wait for: every reservation succeeds.
//
// chunk caps what one reservation may grant, which is how a body is forced into more
// frames than its length requires — a peer whose window opens a little at a time.
type grants struct{ chunk int }

func (g *grants) Reserve(id uint32, want int) (int, error) {
	if g.chunk > 0 && g.chunk < want {
		return g.chunk, nil
	}
	return want, nil
}

// clock is the instant every date field in this file is generated at.
//
// Two things about it are deliberate. The zone is not GMT, so that a formatter which forgot
// the UTC conversion produces a different string here rather than the same one — which is
// what it would produce on a machine whose zone is already UTC, and why Config.Now exists.
// And the day of the month is a single digit, so that IMF-fixdate's zero padding is
// load-bearing: a layout of "2" rather than "02" would write "Sun, 9 Aug" and be a
// fixed-width date one octet narrower for nine days of every month.
var clock = time.Date(2026, time.August, 9, 14, 5, 9, 0, time.FixedZone("+0530", 5*3600+1800))

// clockField is that instant as §5.6.7's IMF-fixdate: 14:05:09 at +05:30 is 08:35:09 GMT,
// and 9 August 2026 is a Sunday.
const clockField = "Sun, 09 Aug 2026 08:35:09 GMT"

// fileTime is the modification time tree gives every file it writes, so that a
// last-modified is a fixed string in this file rather than whatever the disk happened to
// record. Well before clock, because the clamp in modTime replaces a future one with the
// response's own date and would hide the field it is supposed to be checking.
var fileTime = time.Date(2026, time.July, 4, 11, 22, 33, 0, time.UTC)

// fileTimeField is fileTime as an IMF-fixdate. 4 July 2026 is a Saturday.
const fileTimeField = "Sat, 04 Jul 2026 11:22:33 GMT"

// newHandler serves a temporary directory holding files. A key ending in "/" is an empty
// directory; every other key is a file with that content, and its parents are created.
func newHandler(t *testing.T, files map[string]string) *Handler {
	t.Helper()
	return handlerFor(t, tree(t, files))
}

// tree writes files into a new temporary directory and returns it.
func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		full := filepath.Join(dir, filepath.FromSlash(name))
		if strings.HasSuffix(name, "/") {
			if err := os.MkdirAll(full, 0o755); err != nil {
				t.Fatalf("creating the directory %q: %v", name, err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("creating the parents of %q: %v", name, err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("writing %q: %v", name, err)
		}

		// Both times, because Chtimes cannot set one without the other and this package
		// never reads the access time. A zero value means "leave it alone", so the write's
		// own timestamps are what would survive — the thing this call exists to replace.
		if err := os.Chtimes(full, fileTime, fileTime); err != nil {
			t.Fatalf("setting the modification time of %q: %v", name, err)
		}
	}
	return dir
}

func handlerFor(t *testing.T, dir string) *Handler {
	t.Helper()
	h, err := New(Config{Dir: dir, Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatalf("New on %q: %v", dir, err)
	}

	// Registered after t.TempDir's own cleanup and therefore run before it, which matters
	// on Windows: a directory with an open handle on it cannot be removed, and the
	// failure would be reported against every test that used one.
	t.Cleanup(func() {
		if err := h.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return h
}

// answer is one response as the peer would have received it.
type answer struct {
	fields []h2.Field
	body   string
	ended  bool
	frames []frame.Frame
	err    error
}

func (a *answer) get(name string) string {
	for _, f := range a.fields {
		if f.Name == name {
			return f.Value
		}
	}
	return ""
}

func (a *answer) status() string { return a.get(":status") }

// data is how many DATA frames carried content, which is what a chunked body is counted
// by. The empty frame Close sends is not one of them.
func (a *answer) data() int {
	n := 0
	for _, f := range a.frames {
		if d, ok := f.(frame.DataFrame); ok && len(d.Data) > 0 {
			n++
		}
	}
	return n
}

func serve(t *testing.T, h *Handler, method, target string) *answer {
	t.Helper()
	return serveWith(t, h, method, target, &collector{max: limits.MaxFrameSize}, 0)
}

func serveWith(t *testing.T, h *Handler, method, target string, out *collector, chunk int) *answer {
	t.Helper()
	w := response.NewWriter(response.NewEncoder(hpack.New(), out), &grants{chunk: chunk}, 1)
	err := h.serve(w, req(t, method, target))
	return read(t, out, err)
}

// req builds one request the way the connection would: through internal/request, so that
// a target this server would have refused before reaching the handler cannot be tested
// against the handler.
//
// Body is left nil, which exchange.Request's own documentation says it never is on a real
// connection. Nothing in this package reads it — GET and HEAD have no content and the
// other methods are refused before the target is looked at — and a nil here is a panic
// rather than a silent pass if that ever stops being true.
func req(t *testing.T, method, target string) *exchange.Request {
	t.Helper()
	return reqWith(t, method, target)
}

// reqWith is req with regular field lines after the pseudo-header fields, which is where
// §8.3 requires them and so the only place a precondition can be tested from.
func reqWith(t *testing.T, method, target string, extra ...h2.Field) *exchange.Request {
	t.Helper()
	fields := append([]h2.Field{
		{Name: ":method", Value: method},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "zdh.test"},
		{Name: ":path", Value: target},
	}, extra...)

	r, err := request.Parse(1, fields, true)
	if err != nil {
		t.Fatalf("internal/request refused %s %.60q, so no peer could have sent it: %v",
			method, target, err)
	}
	return &exchange.Request{Request: r}
}

// serveCond is serve with preconditions on the request.
func serveCond(t *testing.T, h *Handler, method, target string, extra ...h2.Field) *answer {
	t.Helper()
	out := &collector{max: limits.MaxFrameSize}
	w := response.NewWriter(response.NewEncoder(hpack.New(), out), &grants{}, 1)
	err := h.serve(w, reqWith(t, method, target, extra...))
	return read(t, out, err)
}

// read decodes the collected frames into the response they carry, and holds the sequence
// to §8.1 on the way: one header section, content after it and not before, END_STREAM
// exactly once and on the last frame.
func read(t *testing.T, out *collector, err error) *answer {
	t.Helper()

	a := &answer{frames: out.frames, err: err}
	dec := hpack.New()
	var block []byte
	done := false

	for i, f := range out.frames {
		if done {
			t.Errorf("frame %d is a %s after END_STREAM", i, f.Type())
		}
		if f.Stream() != 1 {
			t.Errorf("frame %d (%s) is on stream %d, want 1", i, f.Type(), f.Stream())
		}

		switch f := f.(type) {
		case frame.HeadersFrame:
			if a.fields != nil {
				t.Fatalf("frame %d begins a second header section", i)
			}
			block = append(block, f.Fragment...)
			done = done || f.EndStream
			if f.EndHeaders {
				fields, derr := dec.Decode(block)
				if derr != nil {
					t.Fatalf("decoding the header block: %v", derr)
				}
				a.fields, block = fields, nil
			}
		case frame.ContinuationFrame:
			if a.fields != nil || block == nil {
				t.Fatalf("frame %d continues a header block that is not open", i)
			}
			block = append(block, f.Fragment...)
			if f.EndHeaders {
				fields, derr := dec.Decode(block)
				if derr != nil {
					t.Fatalf("decoding the header block: %v", derr)
				}
				a.fields, block = fields, nil
			}
		case frame.DataFrame:
			if a.fields == nil {
				t.Errorf("frame %d carries content before any header section", i)
			}

			// The bound is the peer's frame size floored at §6.5.2's initial value, which
			// is what Encoder.splitAt applies: §6.5.2 puts the legitimate range at "between
			// this initial value and the maximum allowed frame size", so a collector
			// advertising less is the broken transport that floor is there for.
			if bound := max(out.max, uint32(limits.MaxFrameSize)); uint32(len(f.Data)) > bound {
				t.Errorf("frame %d carries %d octets, over the %d allowed",
					i, len(f.Data), bound)
			}
			a.body += string(f.Data)
			done = done || f.EndStream
		default:
			t.Errorf("frame %d is an unexpected %s", i, f.Type())
		}
	}

	if block != nil {
		t.Errorf("a header block was left unfinished")
	}
	a.ended = done
	return a
}

// assertFields is the whole header section, in order, because the order is part of what
// §8.3 requires and because a response gaining a field nobody asked for is exactly the
// change a looser assertion would not notice.
func assertFields(t *testing.T, a *answer, want []h2.Field) {
	t.Helper()
	if len(a.fields) != len(want) {
		t.Errorf("the response has %d fields, want %d:\n got %v\nwant %v",
			len(a.fields), len(want), a.fields, want)
		return
	}
	for i := range want {
		if a.fields[i] != want[i] {
			t.Errorf("field %d is %q: %q, want %q: %q",
				i, a.fields[i].Name, a.fields[i].Value, want[i].Name, want[i].Value)
		}
	}
}

// ok is the header section of a 200 on a file tree wrote: five fields, the two validators and
// the accept-ranges, in the order the encoder receives them.
func ok(kind, tag string, length int) []h2.Field {
	return []h2.Field{
		{Name: ":status", Value: status200},
		{Name: "content-length", Value: strconv.Itoa(length)},
		{Name: "content-type", Value: kind},
		{Name: "date", Value: clockField},
		{Name: "server", Value: serverName},
		{Name: "etag", Value: tag},
		{Name: "last-modified", Value: fileTimeField},
		{Name: "accept-ranges", Value: bytesUnit},
	}
}

const page = "<!doctype html><title>zdh</title><h1>it works</h1>\n"

// The entity tags of the three fixtures every exact field set below is asserted against,
// written out rather than computed.
//
// A test that hashed the fixture itself would agree with any hash the handler happened to
// implement, including one that hashed the file's name. These are literals, so the algorithm is
// under test too: base64url of the SHA-256 of the content, unpadded, between two DQUOTEs, and
// no weakness indicator. emptyTag is the one a reader can check without running anything — the
// SHA-256 of the empty input is a published constant, e3b0c442… in hex, and 47DEQ… is that same
// digest in the alphabet §5 of RFC 4648 defines.
const (
	pageTag   = `"OXECrR57fKPMyd98UqF6nkDKJ2f71sq6Ag71phW2dYs"`
	moduleTag = `"o7E1vP6qvaXWeAZCzyVgWYia1GScm6T3pNXW6DpotAI"`
	emptyTag  = `"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"`
)

// --- the ordinary answers ---------------------------------------------------

// TestServeFile is one file, from the request to the frames.
func TestServeFile(t *testing.T) {
	h := newHandler(t, map[string]string{"index.html": page})
	a := serve(t, h, methodGet, "/index.html")

	if a.err != nil {
		t.Fatalf("serve: %v", a.err)
	}
	assertFields(t, a, ok("text/html; charset=utf-8", pageTag, len(page)))
	if a.body != page {
		t.Errorf("content = %q, want %q", a.body, page)
	}
	if !a.ended {
		t.Error("the stream was never ended")
	}
	if a.data() != 1 {
		t.Errorf("%d DATA frames carried content, want 1 for %d octets", a.data(), len(page))
	}
}

// TestServeRootIndex is what a browser asks for first.
//
// Every target here ends in a slash after the dot segments have been resolved away, which
// is what makes it a request for the directory rather than for the thing named by it. The
// ones that do not are in TestServeDirectoryRedirects, including "/." and "/..": both name
// the root, neither ends in a slash, and the redirect is the same one "/docs" gets.
func TestServeRootIndex(t *testing.T) {
	h := newHandler(t, map[string]string{"index.html": page, "other.txt": "x"})

	for _, target := range []string{"/", "//", "///", "/./", "/../", "/?v=2", "/a/../", "/%2e%2e/"} {
		a := serve(t, h, methodGet, target)
		if a.status() != status200 || a.body != page {
			t.Errorf("GET %q gave %s %q, want %s the index", target, a.status(), a.body, status200)
		}
	}
}

// TestServeNestedFile is a file below the root, and the media type that goes with it.
func TestServeNestedFile(t *testing.T) {
	h := newHandler(t, map[string]string{"assets/app.js": "export const a = 1\n"})
	a := serve(t, h, methodGet, "/assets/app.js")

	assertFields(t, a, ok("text/javascript; charset=utf-8", moduleTag, len("export const a = 1\n")))
	if a.body != "export const a = 1\n" {
		t.Errorf("content = %q", a.body)
	}
}

// TestServeQueryIsNotPartOfTheName is the query reaching the filesystem, which is the bug
// where "/index.html?v=2" is a 404 on a server that forgot to cut it off.
func TestServeQueryIsNotPartOfTheName(t *testing.T) {
	h := newHandler(t, map[string]string{"index.html": page})

	for _, target := range []string{"/index.html?v=2", "/index.html?", "/index.html?a=b&c=d"} {
		a := serve(t, h, methodGet, target)
		if a.status() != status200 || a.body != page {
			t.Errorf("GET %q gave %s, want %s", target, a.status(), status200)
		}
	}
}

// TestServeEmptyFile is a response with no content at all, which is a header section with
// END_STREAM on it and no DATA frame: there is nothing to carry, and a zero-length DATA
// frame would be a second frame saying so.
func TestServeEmptyFile(t *testing.T) {
	h := newHandler(t, map[string]string{"empty.css": ""})
	a := serve(t, h, methodGet, "/empty.css")

	assertFields(t, a, ok("text/css; charset=utf-8", emptyTag, 0))
	if a.body != "" {
		t.Errorf("content = %q, want none", a.body)
	}
	if !a.ended {
		t.Error("the stream was never ended")
	}
	if len(a.frames) != 1 {
		t.Errorf("the response is %d frames, want 1: %v", len(a.frames), a.frames)
	}
}

// TestServeUnknownTypeIsOctetStream is the file this table has no opinion about, which is
// told to the peer rather than left for it to sniff.
func TestServeUnknownTypeIsOctetStream(t *testing.T) {
	h := newHandler(t, map[string]string{"blob.bin": "\x00\x01\x02", "README": "read me"})

	for _, c := range []struct{ target, body string }{
		{"/blob.bin", "\x00\x01\x02"},
		{"/README", "read me"},
	} {
		a := serve(t, h, methodGet, c.target)
		assertFields(t, a, ok(octetStream, tagOf(c.body), len(c.body)))
		if a.body != c.body {
			t.Errorf("GET %q content = %q, want %q", c.target, a.body, c.body)
		}
	}
}

// --- directories -----------------------------------------------------------

// TestServeDirectoryRedirects is the trailing slash, and why it is worth a round trip: the
// relative links inside an index resolve against the directory the browser thinks it is
// in, so "/docs" serving /docs/index.html directly would make every "a.css" in it resolve
// to "/a.css".
func TestServeDirectoryRedirects(t *testing.T) {
	h := newHandler(t, map[string]string{"docs/index.html": page})

	a := serve(t, h, methodGet, "/docs")
	assertFields(t, a, []h2.Field{
		{Name: ":status", Value: status301},
		{Name: "content-length", Value: "0"},
		{Name: "date", Value: clockField},
		{Name: "server", Value: serverName},
		{Name: "location", Value: "/docs/"},
	})
	if a.body != "" {
		t.Errorf("the redirect carries %q", a.body)
	}
	if !a.ended {
		t.Error("the redirect never ended the stream")
	}
	if len(a.frames) != 1 {
		t.Errorf("the redirect is %d frames, want 1: a response with no content is a header "+
			"section with END_STREAM on it, and a zero-length DATA frame is a frame saying so",
			len(a.frames))
	}

	// The query survives the redirect, on the far side of the slash. A location of
	// "/docs?v=2/" would put the slash inside the query's value.
	//
	// "/." and "/.." are here too: each names the root, neither ends in a slash, and the
	// location is the peer's own target with one appended rather than the resolved name —
	// which is what makes "/./" the next request and the index the answer to it.
	for _, c := range []struct{ target, location string }{
		{"/docs?v=2", "/docs/?v=2"},
		{"/docs?", "/docs/?"},
		{"/./docs", "/./docs/"},
		{"/docs/../docs", "/docs/../docs/"},
		{"/.", "/./"},
		{"/..", "/../"},
		{"/a/..", "/a/../"},
	} {
		a := serve(t, h, methodGet, c.target)
		if a.status() != status301 || a.get("location") != c.location {
			t.Errorf("GET %q gave %s to %q, want %s to %q",
				c.target, a.status(), a.get("location"), status301, c.location)
		}
	}
}

// TestServeDirectoryIndex is the slash being there, which is the request the redirect
// above sends the browser back with.
func TestServeDirectoryIndex(t *testing.T) {
	h := newHandler(t, map[string]string{"docs/index.html": page, "docs/a/index.html": "deep"})

	for _, c := range []struct{ target, body string }{
		{"/docs/", page},
		{"/docs/a/", "deep"},
		{"/docs/a/../", page},
		{"/docs//", page},
	} {
		a := serve(t, h, methodGet, c.target)
		if a.status() != status200 || a.body != c.body {
			t.Errorf("GET %q gave %s %q, want %s %q", c.target, a.status(), a.body, status200, c.body)
		}
	}
}

// TestServeDirectoryWithoutIndex is a 404 and not a listing. A listing is how the file
// nobody meant to copy into a build directory gets found.
func TestServeDirectoryWithoutIndex(t *testing.T) {
	h := newHandler(t, map[string]string{
		"bare/":           "",
		"bare/secret.txt": "the name nobody should learn",
	})

	a := serve(t, h, methodGet, "/bare/")
	assertNotFound(t, a)
	if strings.Contains(a.body, "secret") {
		t.Errorf("the 404 names something in the directory: %q", a.body)
	}
}

// TestServeIndexThatIsADirectory is the mode check earning its place: the index name
// resolves to something that is not a regular file, which has no length to declare and no
// content to send.
func TestServeIndexThatIsADirectory(t *testing.T) {
	h := newHandler(t, map[string]string{"odd/index.html/nested.txt": "x"})
	assertNotFound(t, serve(t, h, methodGet, "/odd/"))
}

// --- HEAD ------------------------------------------------------------------

// TestHeadMatchesGet asserts the equality as an equality rather than as a list of fields.
// §9.3.2 of RFC 9110: "The server SHOULD send the same header fields in response to a HEAD
// request as it would have sent if the request method had been GET." Both responses are
// generated and compared, so a field added to one path and not the other fails here.
func TestHeadMatchesGet(t *testing.T) {
	h := newHandler(t, map[string]string{
		"index.html":   page,
		"empty.txt":    "",
		"a/index.html": "in a",
	})

	for _, target := range []string{"/index.html", "/empty.txt", "/", "/a/", "/a", "/missing", "/.git/config"} {
		get := serve(t, h, methodGet, target)
		head := serve(t, h, methodHead, target)

		assertFields(t, head, get.fields)
		if head.body != "" {
			t.Errorf("HEAD %q carries %d octets of content", target, len(head.body))
		}
		if !head.ended {
			t.Errorf("HEAD %q never ended the stream", target)
		}
		if head.data() != 0 {
			t.Errorf("HEAD %q sent %d DATA frames", target, head.data())
		}
		if len(head.frames) != 1 {
			t.Errorf("HEAD %q is %d frames, want 1", target, len(head.frames))
		}
	}
}

// TestHeadContentLengthIsTheGetLength is the condition §8.6 of RFC 9110 puts on the field
// being there at all: "a server MUST NOT send Content-Length in such a response unless its
// field value equals the decimal number of octets that would have been sent in the content
// of a response if the same request had used the GET method". Asserted against the octets
// the GET actually sent, which is the only number that can prove it.
func TestHeadContentLengthIsTheGetLength(t *testing.T) {
	h := newHandler(t, map[string]string{"index.html": page, "empty.txt": ""})

	for _, target := range []string{"/index.html", "/empty.txt", "/missing"} {
		get := serve(t, h, methodGet, target)
		head := serve(t, h, methodHead, target)

		if got, want := head.get("content-length"), strconv.Itoa(len(get.body)); got != want {
			t.Errorf("HEAD %q declares %q octets; the GET sent %s", target, got, want)
		}
	}
}

// --- the refusals ----------------------------------------------------------

func assertNotFound(t *testing.T, a *answer) {
	t.Helper()
	if a.status() != status404 {
		t.Errorf("status = %s, want %s", a.status(), status404)
	}
	if a.body != body404 {
		t.Errorf("content = %q, want %q", a.body, body404)
	}
	if !a.ended {
		t.Error("the stream was never ended")
	}
}

// TestServeMissingFile is the ordinary 404, whose fields are the ordinary fields.
func TestServeMissingFile(t *testing.T) {
	h := newHandler(t, map[string]string{"index.html": page})
	a := serve(t, h, methodGet, "/nothing/here.txt")

	assertFields(t, a, []h2.Field{
		{Name: ":status", Value: status404},
		{Name: "content-length", Value: strconv.Itoa(len(body404))},
		{Name: "content-type", Value: textPlain},
		{Name: "date", Value: clockField},
		{Name: "server", Value: serverName},
	})
	assertNotFound(t, a)
}

// TestServeMethodNotAllowed is §15.5.6's allow field, on every method that is not one of
// the two.
//
// OPTIONS is in the list twice, once with the asterisk-form target, which is the one
// request internal/request lets through with a ":path" that is not a path — and the reason
// the method is checked before the target is looked at.
func TestServeMethodNotAllowed(t *testing.T) {
	h := newHandler(t, map[string]string{"index.html": page})

	for _, c := range []struct{ method, target string }{
		{"POST", "/index.html"},
		{"PUT", "/index.html"},
		{"DELETE", "/index.html"},
		{"PATCH", "/index.html"},
		{"OPTIONS", "/index.html"},
		{"OPTIONS", "*"},
		{"TRACE", "/index.html"},
		{"POST", "/missing"},
		{"POST", "/../../etc/passwd"},
		{"DELETE", "/.git/config"},
	} {
		a := serve(t, h, c.method, c.target)

		assertFields(t, a, []h2.Field{
			{Name: ":status", Value: status405},
			{Name: "content-length", Value: strconv.Itoa(len(body405))},
			{Name: "content-type", Value: textPlain},
			{Name: "date", Value: clockField},
			{Name: "server", Value: serverName},
			{Name: "allow", Value: allowedMethods},
		})
		if a.body != body405 {
			t.Errorf("%s %q content = %q, want %q", c.method, c.target, a.body, body405)
		}
		if !a.ended {
			t.Errorf("%s %q never ended the stream", c.method, c.target)
		}
	}

	// The field's value is asserted against behaviour and not against the constant that
	// every field list above is built from, which a change to would rescale them all and
	// pass. §15.5.6's list is a promise: each method it names has to be answered, and each
	// method that is answered has to be named. A list without HEAD is a peer that never
	// sends one, and a list naming PUT is a 405 waiting to contradict it.
	named := strings.Split(allowedMethods, ", ")
	if len(named) != 2 {
		t.Errorf("the allow field names %d methods, want the two this handler answers: %q",
			len(named), allowedMethods)
	}
	for _, m := range named {
		if a := serve(t, h, m, "/index.html"); a.status() == status405 {
			t.Errorf("the allow field names %s, which is answered with %s", m, status405)
		}
	}
	for _, m := range []string{methodGet, methodHead} {
		if !strings.Contains(allowedMethods, m) {
			t.Errorf("the allow field %q does not name %s, which this handler answers",
				allowedMethods, m)
		}
	}
}

// TestServeTargetTooLong is the bound, and the octet on either side of it. A target at the
// limit is answered as a target; one octet more is not looked at.
func TestServeTargetTooLong(t *testing.T) {
	h := newHandler(t, map[string]string{"index.html": page})

	// The bound is a constant every case below derives from, so widening it would rescale
	// all of them and pass. Held here to the range the constant's own documentation states:
	// above the longest URL the major browsers will generate, and small enough that one
	// request's working set is not a number the peer picks.
	if MaxTargetLength < 2048 || MaxTargetLength > 4096 {
		t.Errorf("MaxTargetLength is %d, outside the range it is documented for", MaxTargetLength)
	}

	atLimit := "/" + strings.Repeat("a", MaxTargetLength-1)
	if len(atLimit) != MaxTargetLength {
		t.Fatalf("the test's own target is %d octets", len(atLimit))
	}
	if a := serve(t, h, methodGet, atLimit); a.status() != status404 {
		t.Errorf("a target of exactly %d octets gave %s, want %s",
			MaxTargetLength, a.status(), status404)
	}

	over := atLimit + "a"
	a := serve(t, h, methodGet, over)
	assertFields(t, a, []h2.Field{
		{Name: ":status", Value: status414},
		{Name: "content-length", Value: strconv.Itoa(len(body414))},
		{Name: "content-type", Value: textPlain},
		{Name: "date", Value: clockField},
		{Name: "server", Value: serverName},
	})
	if a.body != body414 {
		t.Errorf("content = %q, want %q", a.body, body414)
	}

	// The length is the target's, query and all, and is measured before anything is
	// decoded — so a long query on a short path is refused too, and a target made of
	// escapes is measured as the octets that arrived rather than as what they decode to.
	for _, target := range []string{
		"/a?" + strings.Repeat("b", MaxTargetLength),
		"/" + strings.Repeat("%41", MaxTargetLength/2),
	} {
		if a := serve(t, h, methodGet, target); a.status() != status414 {
			t.Errorf("a %d-octet target gave %s, want %s", len(target), a.status(), status414)
		}
	}
}

// TestServeDotfilesAreNotServed is the disclosure a static server causes most often,
// checked against files that really are on the disk: each of these exists, is readable, and
// is still a 404.
func TestServeDotfilesAreNotServed(t *testing.T) {
	const secret = "AKIAIOSFODNN7EXAMPLE"
	h := newHandler(t, map[string]string{
		".env":             "AWS_SECRET=" + secret,
		".git/config":      "[remote \"origin\"]\n\turl = git@example.test:private.git\n",
		"assets/.htaccess": "Require all denied\n",
		"a/.b/c.txt":       secret,
		"index.html":       page,
	})

	for _, target := range []string{
		"/.env", "/.git/config", "/assets/.htaccess", "/a/.b/c.txt",
		"/%2eenv", "/%2Egit/config", "/a/%2eb/c.txt",
		"/./.env", "/a/../.env", "/.git/", "/.git",
	} {
		a := serve(t, h, methodGet, target)
		assertNotFound(t, a)
		if strings.Contains(a.body, secret) {
			t.Fatalf("GET %q disclosed the file's content", target)
		}
	}
}

// TestServeDeviceNamesAreNotOpened is the Win32 device list, refused on whichever platform
// this runs on. On Linux the names below are simply absent, which is why the assertion that
// matters is the one made on Windows — and why the refusal is in resolve, where it is the
// same refusal on both.
func TestServeDeviceNamesAreNotOpened(t *testing.T) {
	h := newHandler(t, map[string]string{"index.html": page})

	for _, target := range []string{
		"/nul", "/NUL", "/Nul", "/nul.txt", "/con", "/CON.html", "/aux", "/prn",
		"/com1", "/COM9", "/lpt1", "/conin$", "/CONOUT$", "/assets/nul", "/nul/",
	} {
		assertNotFound(t, serve(t, h, methodGet, target))
	}
}

// TestServeTraversalNeverEscapes is the whole point of the package, driven end to end: a
// secret written outside the served directory, and every traversal anyone has tried.
//
// The assertion is about the content and not about the status. Some of these targets are
// legitimately answered — "/../" resolves to the root and gets its index — and a test that
// demanded a 404 for all of them would be asserting the wrong thing. What may never happen
// is the octets of a file outside the tree appearing in a response.
func TestServeTraversalNeverEscapes(t *testing.T) {
	const secret = "the private key nobody outside the tree may read"

	// The layout: a parent holding the secret, and a public directory beside it. This is
	// the shape of every real deployment that has been traversed — the served directory is
	// never the whole disk.
	parent := t.TempDir()
	if err := os.WriteFile(filepath.Join(parent, "secret.txt"), []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(parent, "public", "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, "public", "index.html"), []byte(page), 0o644); err != nil {
		t.Fatal(err)
	}
	h := handlerFor(t, filepath.Join(parent, "public"))

	targets := []string{
		"/../secret.txt",
		"/../../secret.txt",
		"/assets/../../secret.txt",
		"/./../secret.txt",
		"/.././.././secret.txt",
		"/" + strings.Repeat("../", 64) + "secret.txt",
		"/%2e%2e/secret.txt",
		"/%2E%2E%2Fsecret.txt",
		"/.%2e/secret.txt",
		"/%2e%2e%2f%2e%2e%2fsecret.txt",
		"/..%2fsecret.txt",
		"/assets%2f..%2f..%2fsecret.txt",
		`/..\secret.txt`,
		`/assets\..\..\secret.txt`,
		"/....//secret.txt",
		"/..;/secret.txt",
		"/..%00/secret.txt",
		"/%2e%2e/%2e%2e/%2e%2e/%2e%2e/secret.txt",
		"/assets/./../..%2Fsecret.txt",
		"/../public/../secret.txt",
		"/..",
		"/../",
		"/../public/index.html",
		"/secret.txt",
	}

	for _, target := range targets {
		for _, method := range []string{methodGet, methodHead} {
			a := serve(t, h, method, target)

			if strings.Contains(a.body, secret) {
				t.Fatalf("%s %q escaped the served directory", method, target)
			}
			if s := a.status(); s != status200 && s != status301 && s != status404 {
				t.Errorf("%s %q gave %s, which this handler does not send", method, target, s)
			}
			if !a.ended {
				t.Errorf("%s %q never ended the stream", method, target)
			}
		}
	}
}

// TestServeSymlinkOutIsRefused is the traversal no string arithmetic can see: the target
// is an ordinary name and the escape is on the disk. os.Root is what refuses it, which is
// the half of this package's confinement that is not ours — so this test is here to prove
// that half is actually load-bearing rather than assumed.
func TestServeSymlinkOutIsRefused(t *testing.T) {
	const secret = "reachable only by following the link out"

	parent := t.TempDir()
	if err := os.WriteFile(filepath.Join(parent, "secret.txt"), []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	public := filepath.Join(parent, "public")
	if err := os.MkdirAll(public, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(public, "inside.txt"), []byte("inside"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Skipped rather than failed where a symbolic link cannot be created at all, which is
	// an unprivileged Windows account without developer mode. The refusal being tested is
	// os.Root's and is not platform-specific; the ability to build the fixture is.
	if err := os.Symlink(filepath.Join(parent, "secret.txt"), filepath.Join(public, "out.txt")); err != nil {
		t.Skipf("this account cannot create a symbolic link: %v", err)
	}
	if err := os.Symlink("inside.txt", filepath.Join(public, "in.txt")); err != nil {
		t.Fatal(err)
	}

	h := handlerFor(t, public)

	a := serve(t, h, methodGet, "/out.txt")
	assertNotFound(t, a)
	if strings.Contains(a.body, secret) {
		t.Fatal("a symbolic link out of the served directory was followed")
	}

	// The other direction, stated so that the policy is a decision rather than a side
	// effect: a link that stays inside the tree is served, because os.Root follows one and
	// the file it names is a file this handler is allowed to send.
	if b := serve(t, h, methodGet, "/in.txt"); b.status() != status200 || b.body != "inside" {
		t.Errorf("a symbolic link within the tree gave %s %q, want %s %q",
			b.status(), b.body, status200, "inside")
	}
}

// --- the body --------------------------------------------------------------

// content is size octets that no accidental duplication could produce: every 251-octet
// window is distinct, so a body assembled out of order or with a chunk repeated does not
// compare equal to this.
func content(size int) string {
	b := make([]byte, size)
	for i := range b {
		b[i] = byte(i%251) ^ byte(i/251)
	}
	return string(b)
}

// tagOf is the entity tag a body of these octets gets, for the tests whose fixture is
// generated rather than written out and for which a literal would say nothing.
//
// Built out of the standard library directly rather than by calling hashContent, so that it is
// an independent statement of the format and not the same code checking itself. The three
// literal tags above are the ones that hold the algorithm to its definition; this holds the
// generated fixtures to those literals' format.
func tagOf(body string) string {
	sum := sha256.Sum256([]byte(body))
	return `"` + base64.RawURLEncoding.EncodeToString(sum[:]) + `"`
}

// TestServeLargeFileIsSplitByFrameSize is the body arriving in the peer's shape: a file
// larger than SETTINGS_MAX_FRAME_SIZE becomes as many DATA frames as that number requires,
// and every octet is still in the right place.
func TestServeLargeFileIsSplitByFrameSize(t *testing.T) {
	body := content(3*limits.MaxFrameSize + 7)
	h := newHandler(t, map[string]string{"big.bin": body})

	a := serve(t, h, methodGet, "/big.bin")
	assertFields(t, a, ok(octetStream, tagOf(body), len(body)))
	if a.body != body {
		t.Errorf("the content differs from the file: %d octets against %d", len(a.body), len(body))
	}
	if want := 4; a.data() != want {
		t.Errorf("%d DATA frames carried the body, want %d", a.data(), want)
	}
	if !a.ended {
		t.Error("the stream was never ended")
	}
}

// TestServeBodyAgainstSmallCredit is the same file against a peer whose window opens a
// little at a time, which is what a browser with a small initial window actually is.
//
// The frame count is not asserted: how a body is divided is the writer's business and the
// credit's, and this handler's claim is only that the octets are all there and in order
// however the division came out.
func TestServeBodyAgainstSmallCredit(t *testing.T) {
	body := content(20_000)
	h := newHandler(t, map[string]string{"big.bin": body})

	for _, chunk := range []int{1, 7, 1000, limits.MaxFrameSize - 1} {
		out := &collector{max: limits.MaxFrameSize}
		a := serveWith(t, h, methodGet, "/big.bin", out, chunk)

		if a.err != nil {
			t.Fatalf("a %d-octet credit: %v", chunk, a.err)
		}
		if a.body != body {
			t.Errorf("a %d-octet credit delivered %d octets, want %d", chunk, len(a.body), len(body))
		}
		if !a.ended {
			t.Errorf("a %d-octet credit never ended the stream", chunk)
		}
	}
}

// TestServeFrameSizeIsTheCopyBuffer is how large the DATA frames this handler produces
// actually are, which is the copy buffer's size and not the peer's.
//
// A peer that advertises more than 16384 gets 16384-octet frames anyway, because
// io.CopyBuffer hands Write one buffer at a time and the buffer is limits.MaxFrameSize.
// §4.2 permits it — "Endpoints are not obligated to use all available space in a frame" —
// and the alternative is a per-response buffer sized by whatever the peer asked for, which
// is memory the peer would be choosing. A peer that advertises less than the §6.5.2 minimum
// gets the same, because internal/response floors it.
//
// So the frame count is a function of the file's length alone, which is the property this
// asserts across a range of advertised sizes that spans both sides of the floor.
func TestServeFrameSizeIsTheCopyBuffer(t *testing.T) {
	body := content(40_000)
	h := newHandler(t, map[string]string{"big.bin": body})

	want := (len(body) + limits.MaxFrameSize - 1) / limits.MaxFrameSize
	for _, advertised := range []uint32{512, limits.MaxFrameSize, 2 * limits.MaxFrameSize, 1 << 20} {
		out := &collector{max: advertised}
		a := serveWith(t, h, methodGet, "/big.bin", out, 0)

		if a.body != body {
			t.Errorf("at an advertised %d the content differs: %d octets, want %d",
				advertised, len(a.body), len(body))
		}
		if a.data() != want {
			t.Errorf("at an advertised %d the body took %d frames, want %d",
				advertised, a.data(), want)
		}
		for i, f := range a.frames {
			if d, dok := f.(frame.DataFrame); dok && len(d.Data) > limits.MaxFrameSize {
				t.Errorf("at an advertised %d frame %d carries %d octets, over the buffer's %d",
					advertised, i, len(d.Data), limits.MaxFrameSize)
			}
		}
	}
}

// TestFileGrewIsSentAsDeclared is a build writing into the served directory while a browser
// reads out of it. The length was taken from the same handle the content is, so the
// response is the file as it was when the stat happened — which is what the
// content-length says, and what io.LimitReader is there to make true.
func TestFileGrewIsSentAsDeclared(t *testing.T) {
	const first = "the first version\n"
	dir := tree(t, map[string]string{"a.txt": first})
	h := handlerFor(t, dir)

	f, info, err := h.open("a.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte(first+"and a second\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out := &collector{max: limits.MaxFrameSize}
	w := response.NewWriter(response.NewEncoder(hpack.New(), out), &grants{}, 1)
	err = h.file(w, req(t, methodGet, "/a.txt"), f, info.Size(), textPlain, theEntityTag, clock.UTC(), fileTime)
	a := read(t, out, err)

	if a.err != nil {
		t.Fatalf("file: %v", a.err)
	}
	if a.body != first {
		t.Errorf("content = %q, want the %d octets that were declared", a.body, len(first))
	}
	if got := a.get("content-length"); got != strconv.Itoa(len(first)) {
		t.Errorf("content-length = %q, want %d", got, len(first))
	}
}

// TestFileShrankEndsTheStreamFirst is the case there is no honest answer to: the file was
// truncated after its length went out, so the content is shorter than the declaration and
// §8.6 makes that malformed. What this handler controls is the order — the stream is ended
// before the mismatch is reported, because a peer that is told nothing waits for content
// that is not coming.
//
// Driven by calling file with a size the file does not have, which is what a truncation
// between the stat and the copy amounts to and is the only way to produce it without a
// race in the test.
func TestFileShrankEndsTheStreamFirst(t *testing.T) {
	const body = "half a file\n"
	h := newHandler(t, map[string]string{"a.txt": body})

	f, _, err := h.open("a.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	out := &collector{max: limits.MaxFrameSize}
	w := response.NewWriter(response.NewEncoder(hpack.New(), out), &grants{}, 1)
	err = h.file(w, req(t, methodGet, "/a.txt"), f, int64(len(body))+10, textPlain, theEntityTag, clock.UTC(), fileTime)
	a := read(t, out, err)

	if !errors.Is(a.err, errFileChanged) {
		t.Errorf("file returned %v, want %v", a.err, errFileChanged)
	}
	if !a.ended {
		t.Error("the stream was left open, so the peer is still waiting")
	}
	if a.body != body {
		t.Errorf("content = %q, want the %d octets the file had", a.body, len(body))
	}
	if got := a.get("content-length"); got != strconv.Itoa(len(body)+10) {
		t.Errorf("content-length = %q; the response declared what it was asked to", got)
	}
}

// --- the fields ------------------------------------------------------------

// TestDateIsGMT is §5.6.7's format and §6.6.1's requirement to send it, against a clock
// pinned five and a half hours from GMT.
//
// The assertion is the constant. A response generated from a local time would differ from
// it by the offset, where an assertion that the field merely parses would pass either way
// on a machine whose zone happens to be UTC.
func TestDateIsGMT(t *testing.T) {
	h := newHandler(t, map[string]string{"index.html": page})

	for _, c := range []struct{ method, target string }{
		{methodGet, "/index.html"},
		{methodHead, "/index.html"},
		{methodGet, "/missing"},
		{methodGet, "/docs"},
		{"POST", "/index.html"},
		{methodGet, "/" + strings.Repeat("a", MaxTargetLength)},
	} {
		a := serve(t, h, c.method, c.target)
		if got := a.get("date"); got != clockField {
			t.Errorf("%s %q date = %q, want %q", c.method, c.target, got, clockField)
		}
		if _, err := time.Parse(imfFixdate, a.get("date")); err != nil {
			t.Errorf("%s %q date = %q, which is not an IMF-fixdate: %v",
				c.method, c.target, a.get("date"), err)
		}
	}
}

// TestDateFromTheRealClock is Config.Now's documented nil case, which is the only one a
// deployment uses.
func TestDateFromTheRealClock(t *testing.T) {
	dir := tree(t, map[string]string{"index.html": page})
	h, err := New(Config{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })

	before := time.Now().UTC().Add(-2 * time.Second)
	out := &collector{max: limits.MaxFrameSize}
	a := serveWith(t, h, methodGet, "/index.html", out, 0)
	after := time.Now().UTC().Add(2 * time.Second)

	got, err := time.Parse(imfFixdate, a.get("date"))
	if err != nil {
		t.Fatalf("date = %q: %v", a.get("date"), err)
	}

	// Truncated to the second on the way out, so the window is opened by two seconds on
	// each side rather than compared exactly. What is being asserted is that the field
	// came from a clock and not from a zero time.
	if got.Before(before.Truncate(time.Second)) || got.After(after) {
		t.Errorf("date = %v, which is not between %v and %v", got, before, after)
	}
}

// TestFieldsThisHandlerNeverSends is the scope in the package documentation, asserted as the
// absence it is. Each of these fields is a promise this handler does not keep: a cache-control
// invites a deployment to believe this program has an opinion about freshness, and a
// content-encoding claims a transformation nothing here performs.
//
// Neither validator is in the list. last-modified and etag are both sent, and each has its own
// test of which responses carry it: TestValidatorOnlyWhereThereIsARepresentation. accept-ranges
// is not in it either, since ranges.go shipped; TestAcceptRangesOnlyWhereThereIsARepresentation
// is that field's own test. content-range stays, because none of the targets below can produce
// the 206 or the 416 that carry one, so its absence here is still the assertion it was.
func TestFieldsThisHandlerNeverSends(t *testing.T) {
	h := newHandler(t, map[string]string{"index.html": page, "docs/index.html": page})

	unsent := []string{
		"content-range",
		"cache-control", "expires", "age", "vary", "content-encoding",
		"transfer-encoding", "connection", "keep-alive", "upgrade",
	}
	for _, c := range []struct{ method, target string }{
		{methodGet, "/index.html"},
		{methodHead, "/index.html"},
		{methodGet, "/docs"},
		{methodGet, "/docs/"},
		{methodGet, "/missing"},
		{"POST", "/index.html"},
	} {
		a := serveCond(t, h, c.method, c.target, h2.Field{Name: fieldIfNoneMatch, Value: `"x"`})
		for _, name := range unsent {
			if v := a.get(name); v != "" {
				t.Errorf("%s %q sent %s: %q", c.method, c.target, name, v)
			}
		}
	}
}

// TestValidatorOnlyWhereThereIsARepresentation is which responses carry the two validators and
// which do not. §8.8.2.1 of RFC 9110: "An origin server SHOULD send Last-Modified for any
// selected representation for which a last modification date can be reasonably and consistently
// determined", and §8.8.3.1 of RFC 9110 the same for the other one: "An origin server SHOULD
// send an ETag for any selected representation for which detection of changes can be reasonably
// and consistently determined".
//
// Both fields are asserted together because the condition on them is the same phrase in both
// sections, and on the answers below there is no selected representation: a 404 and a 405
// describe no file at all, a 301 describes where one would be found, a 414 refused to look, and
// a 412 is the refusal §15.5.13 of RFC 9110 defines. A validator on any of them would describe a
// representation the peer was not given.
func TestValidatorOnlyWhereThereIsARepresentation(t *testing.T) {
	h := newHandler(t, map[string]string{"index.html": page, "docs/index.html": page})

	for _, c := range []struct {
		method, target string
		status         string
		want           bool
	}{
		{methodGet, "/index.html", status200, true},
		{methodHead, "/index.html", status200, true},
		{methodGet, "/docs/", status200, true},
		{methodGet, "/docs", status301, false},
		{methodGet, "/missing", status404, false},
		{"POST", "/index.html", status405, false},
		{methodGet, "/" + strings.Repeat("a", MaxTargetLength), status414, false},
	} {
		a := serve(t, h, c.method, c.target)
		if a.status() != c.status {
			t.Errorf("%s %q answered %s, want %s", c.method, c.target, a.status(), c.status)
			continue
		}
		for _, v := range []struct{ name, want string }{
			{"last-modified", fileTimeField},
			{"etag", pageTag},
		} {
			got := a.get(v.name)
			switch {
			case c.want && got != v.want:
				t.Errorf("%s %q %s = %q, want %q", c.method, c.target, v.name, got, v.want)
			case !c.want && got != "":
				t.Errorf("%s %q sent %s %q on a %s", c.method, c.target, v.name, got, c.status)
			}
		}
	}

	// The 412 separately, because it is the one status here that needs a request to
	// produce and the only one that is reached with a representation in hand. Which makes it the
	// case worth having: the tag was computed before the precondition was evaluated, and it still
	// does not go out.
	a := serveCond(t, h, methodGet, "/index.html", h2.Field{Name: fieldIfMatch, Value: `"x"`})
	if a.status() != status412 {
		t.Fatalf("a failed if-match answered %s, want %s", a.status(), status412)
	}
	for _, name := range []string{"last-modified", "etag"} {
		if got := a.get(name); got != "" {
			t.Errorf("the 412 sent %s %q", name, got)
		}
	}
}

// TestFieldsAreLowerCaseAndPseudoFirst is §8.3's shape, held here as well as in
// internal/response: the pseudo-header field before every field line, and no upper case
// anywhere. internal/response would refuse a section that broke either, so this is the
// assertion that the refusal is never reached.
func TestFieldsAreLowerCaseAndPseudoFirst(t *testing.T) {
	h := newHandler(t, map[string]string{"index.html": page, "docs/index.html": page})

	for _, c := range []struct{ method, target string }{
		{methodGet, "/index.html"},
		{methodGet, "/docs"},
		{methodGet, "/missing"},
		{"POST", "/index.html"},
		{methodGet, "/" + strings.Repeat("a", MaxTargetLength)},
	} {
		a := serve(t, h, c.method, c.target)
		if len(a.fields) == 0 {
			t.Fatalf("%s %q sent no fields", c.method, c.target)
		}
		if a.fields[0].Name != ":status" {
			t.Errorf("%s %q begins with %q, want :status", c.method, c.target, a.fields[0].Name)
		}
		for i, f := range a.fields[1:] {
			if strings.HasPrefix(f.Name, ":") {
				t.Errorf("%s %q has the pseudo-header %q at position %d",
					c.method, c.target, f.Name, i+1)
			}
			if f.Name != strings.ToLower(f.Name) {
				t.Errorf("%s %q sent %q, which is not lower-cased", c.method, c.target, f.Name)
			}
		}
	}
}

// TestContentLengthIsTheContent is §8.1.1's accounting, which internal/exchange relies on
// this handler getting right: a declared length that does not match the octets sent makes
// the response malformed, and there is no reset available to take it back.
func TestContentLengthIsTheContent(t *testing.T) {
	h := newHandler(t, map[string]string{
		"index.html":      page,
		"empty.txt":       "",
		"big.bin":         content(40_000),
		"docs/index.html": page,
	})

	for _, c := range []struct{ method, target string }{
		{methodGet, "/index.html"},
		{methodGet, "/empty.txt"},
		{methodGet, "/big.bin"},
		{methodGet, "/docs"},
		{methodGet, "/docs/"},
		{methodGet, "/missing"},
		{methodGet, "/.env"},
		{"POST", "/index.html"},
		{methodGet, "/" + strings.Repeat("a", MaxTargetLength)},
	} {
		a := serve(t, h, c.method, c.target)
		want, err := strconv.Atoi(a.get("content-length"))
		if err != nil {
			t.Errorf("%s %q content-length = %q: %v", c.method, c.target, a.get("content-length"), err)
			continue
		}
		if len(a.body) != want {
			t.Errorf("%s %q declared %d octets and sent %d", c.method, c.target, want, len(a.body))
		}
	}
}

// --- what a failed write does ----------------------------------------------

var errGone = errors.New("the connection's writer has stopped")

// TestServeReturnsTheWriteError is what Serve drops and serve returns, at each of the three
// places a response can stop: the header section, a DATA frame, and the empty frame that
// ends the stream.
//
// A reset stream or a closed connection is the only way any of these fails, and the package
// documentation says why nothing is logged and nothing is retried. What is asserted here is
// that the error is not swallowed on the way up — a handler that returned nil after a failed
// write would leave internal/exchange believing a response went out.
func TestServeReturnsTheWriteError(t *testing.T) {
	h := newHandler(t, map[string]string{"index.html": page, "docs/index.html": page})

	for _, c := range []struct {
		what           string
		method, target string
		failFrom       int
	}{
		{"the header section of a file", methodGet, "/index.html", 0},
		{"a DATA frame", methodGet, "/index.html", 1},
		{"the frame that ends the stream", methodGet, "/index.html", 2},
		{"a bodyless header section", methodHead, "/index.html", 0},
		{"a 404's header section", methodGet, "/missing", 0},
		{"a 404's content", methodGet, "/missing", 1},
		{"the frame that ends a 404", methodGet, "/missing", 2},
		{"a 405's header section", "POST", "/index.html", 0},
		{"a redirect", methodGet, "/docs", 0},
	} {
		out := &collector{max: limits.MaxFrameSize, err: errGone, failFrom: c.failFrom}
		w := response.NewWriter(response.NewEncoder(hpack.New(), out), &grants{}, 1)

		err := h.serve(w, req(t, c.method, c.target))
		if !errors.Is(err, errGone) {
			t.Errorf("a write that failed at %s returned %v, want %v", c.what, err, errGone)
		}
		if len(out.frames) != c.failFrom {
			t.Errorf("a write that failed at %s enqueued %d frames, want %d",
				c.what, len(out.frames), c.failFrom)
		}
	}

	// Serve is the same call with the error dropped, which is the line the package
	// documentation is about. Asserted because "it does not panic" is the whole of its
	// contract and a nil dereference on the error path would satisfy no test above.
	out := &collector{max: limits.MaxFrameSize, err: errGone}
	w := response.NewWriter(response.NewEncoder(hpack.New(), out), &grants{}, 1)
	h.Serve(w, req(t, methodGet, "/index.html"))
}

// --- construction ----------------------------------------------------------

// TestNewRefusesWhatItCannotServe is why New returns an error: each of these is an
// operator's typo on a command line, and the answer to it is a sentence on stderr rather
// than a panic in front of a user.
func TestNewRefusesWhatItCannotServe(t *testing.T) {
	dir := tree(t, map[string]string{"a.txt": "x"})

	for _, c := range []struct {
		what, path string
		// ours is whether the error has to be this package's own sentence rather than
		// the operating system's. An absent directory and a file where a directory
		// should be are both refused by the syscall, whose message names the path and is
		// more useful than anything this package could add. No directory at all is not a
		// typo in a path, it is a Dir nobody set, and "open : no such file or directory"
		// describes that badly enough to be worth a sentence of our own.
		ours bool
	}{
		{"no directory at all", "", true},
		{"a directory that does not exist", filepath.Join(dir, "absent"), false},
		{"a regular file", filepath.Join(dir, "a.txt"), false},
		{"a path below a regular file", filepath.Join(dir, "a.txt", "b"), false},
	} {
		h, err := New(Config{Dir: c.path})
		if err == nil {
			h.Close()
			t.Errorf("New with %s returned no error", c.what)
			continue
		}
		if h != nil {
			t.Errorf("New with %s returned a handler as well as %v", c.what, err)
		}
		if c.ours && !strings.Contains(err.Error(), "static: ") {
			t.Errorf("New with %s gave %q, want this package's own sentence", c.what, err)
		}
	}
}

// TestDirIsWhatIsServed is the accessor a command line prints back.
func TestDirIsWhatIsServed(t *testing.T) {
	dir := tree(t, map[string]string{"a.txt": "x"})
	if got := handlerFor(t, dir).Dir(); got != dir {
		t.Errorf("Dir() = %q, want %q", got, dir)
	}
}

// TestClosedHandlerServesNothing is the shutdown order: the handler outlives every
// connection, so a request that arrives after Close is a request during teardown and a 404
// is the right answer to it. What may not happen is a panic on a closed handle.
func TestClosedHandlerServesNothing(t *testing.T) {
	dir := tree(t, map[string]string{"index.html": page})
	h, err := New(Config{Dir: dir, Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	assertNotFound(t, serve(t, h, methodGet, "/index.html"))
}

// --- one handler, many streams ---------------------------------------------

// TestServeIsConcurrencySafe is the deployment: one Handler for the whole program, and a
// goroutine per request on every connection at once.
//
// Two things are shared and both are checked here — the os.Root, which every open goes
// through, and the buffer pool, which is the one piece of mutable state this package has.
// A buffer handed to two responses would put one file's octets into the other's frames,
// which is what the content check below would catch and what the race detector would name.
// Each goroutine has its own collector and Writer, as each stream on a connection does.
func TestServeIsConcurrencySafe(t *testing.T) {
	files := map[string]string{}
	for i := range 8 {
		files["f"+strconv.Itoa(i)+".bin"] = content(1000 + i*7000)
	}
	files["index.html"] = page
	h := newHandler(t, files)

	var wg sync.WaitGroup
	for i := range 8 {
		for range 6 {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				name := "f" + strconv.Itoa(i) + ".bin"
				want := files[name]

				out := &collector{max: limits.MaxFrameSize}
				w := response.NewWriter(response.NewEncoder(hpack.New(), out), &grants{chunk: 3000}, 1)
				if err := h.serve(w, req(t, methodGet, "/"+name)); err != nil {
					t.Errorf("serving %q: %v", name, err)
					return
				}

				// Reassembled here rather than through read, which asserts with a
				// *testing.T from the wrong goroutine's point of view for the fatal
				// paths. The content is the assertion that matters: a shared buffer
				// would show up as another file's octets in this one.
				var body strings.Builder
				for _, f := range out.frames {
					if d, ok := f.(frame.DataFrame); ok {
						body.Write(d.Data)
					}
				}
				if body.String() != want {
					t.Errorf("%q came back as %d octets, want %d", name, body.Len(), len(want))
				}
			}(i)
		}
	}
	wg.Wait()
}
