package static

import (
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"

	"zerodeps/zdh/internal/frame"
	"zerodeps/zdh/internal/h2"
	"zerodeps/zdh/internal/hpack"
	"zerodeps/zdh/internal/limits"
	"zerodeps/zdh/internal/request"
	"zerodeps/zdh/internal/response"
)

// The tests in this file are the range field, from a field value to the octets a peer
// receives. They run through h.serve rather than against parseRangeSet, which is deliberate:
// what §14.2 of RFC 9110 leaves to the server is not how a specifier parses but which of three
// responses a request gets, and only the whole call can be asked that question.
//
// Every field name, media type, status code and line ending below is written as a literal
// rather than as the constant the package defines for it. A test that names the same constant
// the code does agrees with the code by construction, and would keep agreeing after somebody
// changed both.

// --- the harness ------------------------------------------------------------

// The representation every test in this file ranges into: a thousand octets whose every
// 251-octet window is distinct, so a part assembled from the wrong offset does not compare
// equal to the right one.
//
// An .mp4 because that is the request this file exists for — a browser seeking in a video —
// and because a media type with no charset parameter keeps the per-part Content-Type below
// short enough to read.
const (
	filmName = "film.mp4"
	filmType = "video/mp4"
	filmSize = 1000
)

// film is a handler serving filmName, and the octets it holds.
func film(t *testing.T) (*Handler, string) {
	t.Helper()
	body := content(filmSize)
	return newHandler(t, map[string]string{filmName: body}), body
}

// rangeGet is a GET carrying one range field line.
func rangeGet(t *testing.T, h *Handler, target, value string, extra ...h2.Field) *answer {
	t.Helper()
	fields := append([]h2.Field{{Name: "range", Value: value}}, extra...)
	return serveCond(t, h, methodGet, target, fields...)
}

// rangeGetWith is rangeGet against a peer whose window opens chunk octets at a time.
func rangeGetWith(t *testing.T, h *Handler, target, value string, out *collector, chunk int) *answer {
	t.Helper()
	w := response.NewWriter(response.NewEncoder(hpack.New(), out), &grants{chunk: chunk}, 1)
	err := h.serve(w, reqWith(t, methodGet, target, h2.Field{Name: "range", Value: value}))
	return read(t, out, err)
}

// partial206 is the header section of a single-part 206: the seven fields a 200 on a file has,
// and the content-range after them.
func partial206(kind string, length int, contentRange string) []h2.Field {
	return []h2.Field{
		{Name: ":status", Value: "206"},
		{Name: "content-length", Value: strconv.Itoa(length)},
		{Name: "content-type", Value: kind},
		{Name: "date", Value: clockField},
		{Name: "server", Value: serverName},
		{Name: "last-modified", Value: fileTimeField},
		{Name: "accept-ranges", Value: "bytes"},
		{Name: "content-range", Value: contentRange},
	}
}

// boundaryOf is the boundary parameter of a multipart 206's content-type, and fails the test
// if the response was not one.
func boundaryOf(t *testing.T, a *answer) string {
	t.Helper()
	edge, ok := strings.CutPrefix(a.get("content-type"), "multipart/byteranges; boundary=")
	if !ok {
		t.Fatalf("content-type = %q, want a multipart/byteranges type with a boundary",
			a.get("content-type"))
	}
	if edge == "" {
		t.Fatal("the boundary parameter is empty")
	}
	return edge
}

// multipartBody is the [RFC2046] body those spans of file make with that boundary, spelled out
// here rather than obtained from the multipart function so that the assertion is about octets.
func multipartBody(file, edge, kind string, spans []span) string {
	b := &strings.Builder{}
	for i, s := range spans {
		if i > 0 {
			b.WriteString("\r\n")
		}
		b.WriteString("--" + edge + "\r\n")
		b.WriteString("Content-Type: " + kind + "\r\n")
		b.WriteString("Content-Range: bytes " + strconv.FormatInt(s.first, 10) + "-" +
			strconv.FormatInt(s.last, 10) + "/" + strconv.Itoa(len(file)) + "\r\n")
		b.WriteString("\r\n")
		b.WriteString(file[s.first : s.last+1])
	}
	b.WriteString("\r\n--" + edge + "--\r\n")
	return b.String()
}

// assertMultipart is a multipart 206 in full: the field set with the boundary spliced back in,
// the body those spans make, and a content-length that is the length of it.
func assertMultipart(t *testing.T, a *answer, file, kind string, spans []span) {
	t.Helper()
	if a.err != nil {
		t.Fatalf("serve: %v", a.err)
	}

	edge := boundaryOf(t, a)
	assertFields(t, a, []h2.Field{
		{Name: ":status", Value: "206"},
		{Name: "content-length", Value: strconv.Itoa(len(multipartBody(file, edge, kind, spans)))},
		{Name: "content-type", Value: "multipart/byteranges; boundary=" + edge},
		{Name: "date", Value: clockField},
		{Name: "server", Value: serverName},
		{Name: "last-modified", Value: fileTimeField},
		{Name: "accept-ranges", Value: "bytes"},
	})

	if want := multipartBody(file, edge, kind, spans); a.body != want {
		t.Errorf("the multipart body is %d octets, want %d:\n got %q\nwant %q",
			len(a.body), len(want), a.body, want)
	}
	if !a.ended {
		t.Error("the stream was left open")
	}
}

// specs is a range field value asking for n one-octet parts: the cheapest way to build a
// range-set of a chosen size whose octets still add up to less than the file.
func specs(n int) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = strconv.Itoa(i) + "-" + strconv.Itoa(i)
	}
	return "bytes=" + strings.Join(parts, ",")
}

// octets is the spans specs(n) selects.
func octets(n int) []span {
	spans := make([]span, n)
	for i := range spans {
		spans[i] = span{int64(i), int64(i)}
	}
	return spans
}

// huge is a numeral no int64 can hold, which §14.1.2 of RFC 9110 requires a recipient to
// anticipate. Ninety digits, so that the overflow is not marginal.
const huge = "999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999"

// --- the single part --------------------------------------------------------

// TestRangeSinglePart is the whole of one 206, from the field value to the frames.
func TestRangeSinglePart(t *testing.T) {
	h, body := film(t)
	a := rangeGet(t, h, "/"+filmName, "bytes=0-9")

	if a.err != nil {
		t.Fatalf("serve: %v", a.err)
	}
	assertFields(t, a, partial206(filmType, 10, "bytes 0-9/1000"))
	if a.body != body[0:10] {
		t.Errorf("content = %q, want the first ten octets %q", a.body, body[0:10])
	}
	if !a.ended {
		t.Error("the stream was left open")
	}
}

// TestRangeSingleSpecShapes is every spelling of one satisfiable range-spec, each against the
// span §14.1.2 of RFC 9110 says it selects.
//
// The last four are the clamps, and they are the same clamp reached four ways: a last-pos past
// the end, an absent last-pos, an overflowing last-pos, and a suffix-length longer than the
// file all land on §14.1.2 of RFC 9110: "the byte range is interpreted as the remainder of the
// representation".
func TestRangeSingleSpecShapes(t *testing.T) {
	h, body := film(t)

	for _, c := range []struct {
		value string
		first int
		last  int
	}{
		{"bytes=0-0", 0, 0},
		{"bytes=0-9", 0, 9},
		{"bytes=1-1", 1, 1},
		{"bytes=500-500", 500, 500},
		{"bytes=999-999", 999, 999},
		{"bytes=0-999", 0, 999},
		{"bytes=-1", 999, 999},
		{"bytes=-5", 995, 999},
		{"bytes=-1000", 0, 999},
		{"bytes=-1001", 0, 999},
		{"bytes=-" + huge, 0, 999},
		{"bytes=990-", 990, 999},
		{"bytes=0-", 0, 999},
		{"bytes=995-99999", 995, 999},
		{"bytes=0-" + huge, 0, 999},
	} {
		a := rangeGet(t, h, "/"+filmName, c.value)
		if a.err != nil {
			t.Errorf("%s: serve: %v", c.value, a.err)
			continue
		}

		length := c.last - c.first + 1
		want := "bytes " + strconv.Itoa(c.first) + "-" + strconv.Itoa(c.last) + "/1000"
		if got := a.status(); got != "206" {
			t.Errorf("%s answered %s, want 206", c.value, got)
			continue
		}
		if got := a.get("content-range"); got != want {
			t.Errorf("%s content-range = %q, want %q", c.value, got, want)
		}
		if got := a.get("content-length"); got != strconv.Itoa(length) {
			t.Errorf("%s content-length = %q, want %d", c.value, got, length)
		}
		if a.body != body[c.first:c.last+1] {
			t.Errorf("%s sent %d octets from the wrong place", c.value, len(a.body))
		}
	}
}

// TestRangeWholeFileIsStillPartial is the case a 200 would also have answered correctly. It is
// a 206 anyway, because §14.2 of RFC 9110 makes the status a function of the specifier being
// valid and satisfiable rather than of how much of the file it happened to name — and because a
// client that asked for a range and got a 200 has to notice the difference to avoid appending
// the whole file to the part it already had.
func TestRangeWholeFileIsStillPartial(t *testing.T) {
	h, body := film(t)

	for _, value := range []string{"bytes=0-999", "bytes=0-", "bytes=-1000", "bytes=0-" + huge} {
		a := rangeGet(t, h, "/"+filmName, value)
		assertFields(t, a, partial206(filmType, filmSize, "bytes 0-999/1000"))
		if a.body != body {
			t.Errorf("%s sent %d octets, want the whole file", value, len(a.body))
		}
	}
}

// TestRangeOnDirectoryIndex is the range applying to the representation rather than to the
// target: "/docs/" selects docs/index.html, and the content-range describes that file's length
// and that file's media type.
func TestRangeOnDirectoryIndex(t *testing.T) {
	h := newHandler(t, map[string]string{"docs/index.html": page})
	a := rangeGet(t, h, "/docs/", "bytes=0-9")

	assertFields(t, a, partial206("text/html; charset=utf-8", 10,
		"bytes 0-9/"+strconv.Itoa(len(page))))
	if a.body != page[0:10] {
		t.Errorf("content = %q, want %q", a.body, page[0:10])
	}
}

// TestRangeAcrossFrameSize is a part longer than SETTINGS_MAX_FRAME_SIZE: the section reader is
// copied through the same pooled buffer a whole file is, so the part becomes as many DATA
// frames as its length requires and every octet is still at the offset the content-range named.
func TestRangeAcrossFrameSize(t *testing.T) {
	body := content(3*limits.MaxFrameSize + 7)
	h := newHandler(t, map[string]string{filmName: body})

	out := &collector{max: limits.MaxFrameSize}
	a := rangeGetWith(t, h, "/"+filmName, "bytes=1-", out, 0)

	if a.err != nil {
		t.Fatalf("serve: %v", a.err)
	}
	if got := a.get("content-range"); got != "bytes 1-"+strconv.Itoa(len(body)-1)+"/"+strconv.Itoa(len(body)) {
		t.Errorf("content-range = %q", got)
	}
	if a.body != body[1:] {
		t.Errorf("the part is %d octets, want %d", len(a.body), len(body)-1)
	}
	if want := 4; a.data() != want {
		t.Errorf("the part arrived in %d DATA frames, want %d", a.data(), want)
	}
}

// TestRangeAgainstSmallCredit is a peer whose flow-control window opens seven octets at a time.
// A 206 has the same obligation a 200 does — every octet, in order — and the multipart framing
// is content like any other, so it is subject to the same window.
func TestRangeAgainstSmallCredit(t *testing.T) {
	h, body := film(t)

	out := &collector{max: limits.MaxFrameSize}
	a := rangeGetWith(t, h, "/"+filmName, "bytes=100-199", out, 7)
	if a.err != nil {
		t.Fatalf("serve: %v", a.err)
	}
	if a.body != body[100:200] {
		t.Errorf("the part is wrong under a small window: %d octets", len(a.body))
	}
	if a.data() < 100/7 {
		t.Errorf("a hundred octets against a seven-octet window arrived in %d frames", a.data())
	}

	// Multipart under the same window, where the parts and their framing interleave.
	out = &collector{max: limits.MaxFrameSize}
	b := rangeGetWith(t, h, "/"+filmName, "bytes=0-4,10-14", out, 7)
	assertMultipart(t, b, body, filmType, []span{{0, 4}, {10, 14}})
}

// --- the multipart body -----------------------------------------------------

// TestRangeMultipart is a range-set of two, as the multipart/byteranges body §14.6 of RFC 9110
// defines it.
func TestRangeMultipart(t *testing.T) {
	h, body := film(t)
	a := rangeGet(t, h, "/"+filmName, "bytes=0-4,10-14")
	assertMultipart(t, a, body, filmType, []span{{0, 4}, {10, 14}})
}

// TestRangeMultipartHasNoTopLevelContentRange is §15.3.7.2 of RFC 9110's prohibition, asserted
// as the absence it is: a content-range out here would be a single-part response's field on a
// body that is not one, and a client reading it would take the multipart framing for content.
func TestRangeMultipartHasNoTopLevelContentRange(t *testing.T) {
	h, _ := film(t)

	for _, value := range []string{"bytes=0-4,10-14", "bytes=0-0,1-1,2-2", specs(maxRanges)} {
		a := rangeGet(t, h, "/"+filmName, value)
		if got := a.status(); got != "206" {
			t.Fatalf("%s answered %s, want 206", value, got)
		}
		if got := a.get("content-range"); got != "" {
			t.Errorf("%s sent a top-level content-range %q", value, got)
		}
	}
}

// TestRangeSpansAreNeitherReorderedNorMerged is §15.3.7.2 of RFC 9110's SHOULD about part
// order, and the coalescing MAY declined.
//
// Three shapes a server might be tempted to tidy: a descending pair, an overlapping pair, and
// sixteen requests for the same octet. Each is answered with exactly the parts that were asked
// for, in the order they were asked for. The last is the one that would be most tempting to
// collapse and the one where collapsing would be most wrong — a peer that asked for the first
// octet sixteen times gets sixteen parts, because a response is an answer to a request and not
// an improvement on it.
func TestRangeSpansAreNeitherReorderedNorMerged(t *testing.T) {
	h, body := film(t)

	for _, c := range []struct {
		value string
		spans []span
	}{
		{"bytes=100-199,0-99", []span{{100, 199}, {0, 99}}},
		{"bytes=0-99,50-149", []span{{0, 99}, {50, 149}}},
		{"bytes=-1,0-0", []span{{999, 999}, {0, 0}}},
		{"bytes=" + strings.TrimPrefix(strings.Repeat(",0-0", maxRanges), ","),
			[]span{{0, 0}, {0, 0}, {0, 0}, {0, 0}, {0, 0}, {0, 0}, {0, 0}, {0, 0},
				{0, 0}, {0, 0}, {0, 0}, {0, 0}, {0, 0}, {0, 0}, {0, 0}, {0, 0}}},
	} {
		assertMultipart(t, rangeGet(t, h, "/"+filmName, c.value), body, filmType, c.spans)
	}
}

// TestRangeOneSatisfiableSpecOfManyIsSinglePart is the choice §15.3.7.2 of RFC 9110 leaves
// open. The request asked for three ranges and the file can supply one, so the response could
// be a multipart body with a single part in it; it is a single-part 206 instead, because the
// shape of a response follows what is in it.
//
// Which also means the unsatisfiable specs are skipped rather than being an error, and that the
// part that survived is the one that was satisfiable and not merely the first.
func TestRangeOneSatisfiableSpecOfManyIsSinglePart(t *testing.T) {
	h, body := film(t)

	for _, c := range []struct {
		value string
		first int
		last  int
	}{
		{"bytes=5000-,0-9", 0, 9},
		{"bytes=0-9,5000-", 0, 9},
		{"bytes=1000-,2000-,995-", 995, 999},
		{"bytes=-0,-5", 995, 999},
		{"bytes=" + huge + "-,0-0", 0, 0},
	} {
		a := rangeGet(t, h, "/"+filmName, c.value)
		length := c.last - c.first + 1
		want := "bytes " + strconv.Itoa(c.first) + "-" + strconv.Itoa(c.last) + "/1000"
		assertFields(t, a, partial206(filmType, length, want))
		if a.body != body[c.first:c.last+1] {
			t.Errorf("%s sent the wrong %d octets", c.value, len(a.body))
		}
	}
}

// TestRangeBoundaryIsUnpredictable is the defence boundary describes. A delimiter a peer could
// guess is a delimiter a peer could plant in a served file, and the response would then parse
// as more parts than the server described.
//
// Three properties, because the defence needs all of them: the boundary differs between
// responses, it is drawn from an alphabet that needs no quoting to be a parameter value, and it
// carries enough of it to be worth calling unpredictable. Sixty-four draws all distinct is not a
// test of the generator's strength — crypto/rand's is not this package's to prove — but it does
// fail loudly if this function is ever replaced by a counter or a constant.
func TestRangeBoundaryIsUnpredictable(t *testing.T) {
	h, _ := film(t)

	first := boundaryOf(t, rangeGet(t, h, "/"+filmName, "bytes=0-4,10-14"))
	second := boundaryOf(t, rangeGet(t, h, "/"+filmName, "bytes=0-4,10-14"))
	if first == second {
		t.Errorf("two responses shared the boundary %q", first)
	}

	seen := make(map[string]bool, 64)
	for range 64 {
		edge := boundary()
		if seen[edge] {
			t.Fatalf("boundary repeated %q within 64 draws", edge)
		}
		seen[edge] = true

		// The base32 alphabet of [RFC4648], which is what makes the parameter safe unquoted:
		// every octet is a MIME bchar, so there is nothing in it for a parser to end the
		// parameter on and nothing that needs escaping.
		if len(edge) < 26 {
			t.Errorf("boundary %q is %d characters, under the 26 that 128 bits of base32 needs",
				edge, len(edge))
		}
		for i := 0; i < len(edge); i++ {
			if c := edge[i]; (c < 'A' || c > 'Z') && (c < '2' || c > '7') {
				t.Errorf("boundary %q holds %q, which is not in the base32 alphabet", edge, c)
				break
			}
		}
	}
}

// TestRangeMultipartContentLengthIsTheContent is the invariant plan exists for: the declared
// length is the sum of what will be written, framing included, so it cannot disagree with what
// arrives. Asserted across every part count this server will produce, because the framing is
// what scales with that number.
func TestRangeMultipartContentLengthIsTheContent(t *testing.T) {
	h, _ := film(t)

	for n := 2; n <= maxRanges; n++ {
		a := rangeGet(t, h, "/"+filmName, specs(n))
		if got := a.status(); got != "206" {
			t.Fatalf("%d ranges answered %s, want 206", n, got)
		}
		if got := a.get("content-length"); got != strconv.Itoa(len(a.body)) {
			t.Errorf("%d ranges declared content-length %q and sent %d octets",
				n, got, len(a.body))
		}
		if got := strings.Count(a.body, "Content-Range: "); got != n {
			t.Errorf("%d ranges produced %d per-part content-range fields", n, got)
		}
	}
}

// TestRangeMaxRangesIsTheLastAcceptedCount is the bound at its edge, in both directions and in
// the same test so that the pair cannot drift: maxRanges parts is a 206 and one more is the 416
// §15.5.17 of RFC 9110 names for an excessive number of ranges.
func TestRangeMaxRangesIsTheLastAcceptedCount(t *testing.T) {
	h, body := film(t)

	assertMultipart(t, rangeGet(t, h, "/"+filmName, specs(maxRanges)), body, filmType,
		octets(maxRanges))

	a := rangeGet(t, h, "/"+filmName, specs(maxRanges+1))
	assertNotSatisfiable(t, a, filmSize)
}

// TestRangeStopsCountingAtTheBound is the loop in parseRangeSet ending where it says it does. A
// range-set of maxRanges+1 whose last spec is unparseable is a 416, which can only be true if
// that spec was never parsed — parsing it would have made the whole specifier invalid, and an
// invalid specifier is ignored rather than refused.
//
// The same garbage one position earlier is the control: there it is inside the bound, it is
// parsed, and the answer is the file. So the pair pins both the bound and the fact that nothing
// past it is read.
func TestRangeStopsCountingAtTheBound(t *testing.T) {
	h, body := film(t)

	beyond := specs(maxRanges) + ",not-a-range"
	assertNotSatisfiable(t, rangeGet(t, h, "/"+filmName, beyond), filmSize)

	within := specs(maxRanges-1) + ",not-a-range"
	a := rangeGet(t, h, "/"+filmName, within)
	assertFields(t, a, ok(filmType, filmSize))
	if a.body != body {
		t.Errorf("an invalid spec inside the bound sent %d octets, want the whole file", len(a.body))
	}
}

// --- the 416 ----------------------------------------------------------------

// assertNotSatisfiable is a 416 in full: five fields, the content-range that carries the length
// the peer guessed wrong about, and the one sentence of content.
func assertNotSatisfiable(t *testing.T, a *answer, size int) {
	t.Helper()
	if a.err != nil {
		t.Fatalf("serve: %v", a.err)
	}
	assertFields(t, a, []h2.Field{
		{Name: ":status", Value: "416"},
		{Name: "content-length", Value: strconv.Itoa(len(body416))},
		{Name: "content-type", Value: "text/plain; charset=utf-8"},
		{Name: "date", Value: clockField},
		{Name: "server", Value: serverName},
		{Name: "content-range", Value: "bytes */" + strconv.Itoa(size)},
	})
	if a.body != body416 {
		t.Errorf("content = %q, want %q", a.body, body416)
	}
	if !a.ended {
		t.Error("the stream was left open")
	}
}

// TestRangeNotSatisfiable is every valid specifier this file cannot answer. Each is a 416 rather
// than the file, because §14.2 of RFC 9110 asks for one where the specifier is valid and
// unsatisfiable, and because the content-range on it tells a client that guessed at the length
// what the length actually is.
func TestRangeNotSatisfiable(t *testing.T) {
	h, _ := film(t)

	for _, value := range []string{
		"bytes=1000-",
		"bytes=1000-2000",
		"bytes=5000-",
		"bytes=" + huge + "-",
		"bytes=" + huge + "-" + huge,
		"bytes=-0",
		"bytes=1000-,2000-,3000-",
		"bytes=-0,-0",
		"bytes=1000-1000,-0",
		specs(maxRanges + 1),
	} {
		a := rangeGet(t, h, "/"+filmName, value)
		if got := a.status(); got != "416" {
			t.Errorf("%s answered %s, want 416", value, got)
			continue
		}
		assertNotSatisfiable(t, a, filmSize)
	}
}

// TestRangeNotSatisfiableCarriesTheRealLength is the field's use: a client that guessed too high
// learns the length from the refusal and can ask again without a second wasted round trip.
// Asserted on three file sizes so that the value is the representation's and not a constant that
// happens to match.
func TestRangeNotSatisfiableCarriesTheRealLength(t *testing.T) {
	for _, size := range []int{1, 51, 1000} {
		h := newHandler(t, map[string]string{filmName: content(size)})
		a := rangeGet(t, h, "/"+filmName, "bytes="+strconv.Itoa(size)+"-")
		if got, want := a.get("content-range"), "bytes */"+strconv.Itoa(size); got != want {
			t.Errorf("a %d-octet file answered content-range %q, want %q", size, got, want)
		}
	}
}

// TestRangeSuffixZeroIsUnsatisfiableAndNotInvalid is the distinction §14.1.2 of RFC 9110 draws
// with the word "non-zero": bytes=-0 is well-formed syntax that selects nothing, so it is
// skipped rather than voiding the specifier around it. On its own that leaves a valid specifier
// with nothing satisfiable in it, which is a 416; beside a satisfiable spec it disappears, which
// TestRangeOneSatisfiableSpecOfManyIsSinglePart asserts. If it were read as invalid instead,
// both of those would be a 200.
func TestRangeSuffixZeroIsUnsatisfiableAndNotInvalid(t *testing.T) {
	h, _ := film(t)
	assertNotSatisfiable(t, rangeGet(t, h, "/"+filmName, "bytes=-0"), filmSize)
	assertNotSatisfiable(t, rangeGet(t, h, "/"+filmName, "bytes=-0,-0,-0"), filmSize)
}

// --- the field disregarded --------------------------------------------------

// TestRangeInvalidIsIgnored is §14.2 of RFC 9110's permission taken: a specifier this server
// cannot parse produces the response the request would have got without it.
//
// Ignoring rather than refusing, and the difference is what the peer is told. A 416 says the
// file cannot supply what was asked for, which is a claim about the file; a malformed value is a
// request that never said what it was asking for, which is a claim about the request. The file
// answers both, and it answers the second one honestly.
func TestRangeInvalidIsIgnored(t *testing.T) {
	h, body := film(t)

	for _, value := range []string{
		// Not a ranges-specifier at all: no unit, or no "=" to end one.
		"0-9",
		"bytes 0-9",
		"bytes:0-9",
		"=0-9",
		"",

		// A unit this server does not understand, which §14.2 of RFC 9110 makes a MUST to
		// ignore. The second is a registered unit that is not implemented here, and it takes
		// the same branch as the invented one — an unimplemented unit is an unknown unit.
		"items=0-9",
		"seconds=0-9",
		"bytez=0-9",
		"kilobytes=0-9",
		"bytes bytes=0-9",

		// A last-pos below the first-pos, which §14.1.1 of RFC 9110 makes invalid outright.
		"bytes=9-5",
		"bytes=999-0",
		"bytes=1-0",
		"bytes=" + huge + "-0",

		// Something that is not a decimal numeral where the grammar has 1*DIGIT.
		"bytes=abc",
		"bytes=a-b",
		"bytes=0x10-0x20",
		"bytes=+5-9",
		"bytes=5-+9",
		"bytes=-+5",
		"bytes=0.5-9",
		"bytes=0-9.5",
		"bytes=１-９",

		// Whitespace inside a range-spec, which is not the OWS §5.6.1 of RFC 9110 attaches to
		// the comma. Three things where the grammar has room for one.
		"bytes=0 - 5",
		"bytes=0- 5",
		"bytes=0 -5",
		"bytes= 0- 5",

		// A separator in the wrong place, or too many of them.
		"bytes=-",
		"bytes=--5",
		"bytes=0-5-9",
		"bytes=0--5",
		"bytes==0-9",
		"bytes=0-9=",

		// One invalid spec voiding the whole specifier, which is §14.1.1 of RFC 9110's rule.
		// The valid neighbour is satisfiable in every one of these, so a server that skipped
		// the bad spec instead would answer a 206 and be caught here.
		"bytes=0-1,9-5",
		"bytes=9-5,0-1",
		"bytes=0-1,abc",
		"bytes=0-1,abc,2-3",
		"bytes=0-1,,,9-5",

		// No separator at all, so there is neither an int-range nor a suffix-range: the
		// grammar has no production a bare numeral fits. Worth pinning because a parser
		// that read one as a first-pos with an absent last-pos would answer a 206 for
		// the remainder of the file and look entirely reasonable doing it.
		"bytes=5",
		"bytes=0",
	} {
		a := rangeGet(t, h, "/"+filmName, value)
		if a.err != nil {
			t.Errorf("%q: serve: %v", value, a.err)
			continue
		}
		assertFields(t, a, ok(filmType, filmSize))
		if a.body != body {
			t.Errorf("%q sent %d octets, want the whole file", value, len(a.body))
		}
	}
}

// TestRangeEmptyElementsAreParsedAndNotCounted is §5.6.1.2 of RFC 9110 on both halves at once.
//
// Parsed and ignored, so a sender that merged two values into one field line is understood; and
// not counted, so the merge cannot be used to get past maxRanges and ten thousand commas is a
// range-set of nothing rather than ten thousand specs to reject. The last case is the one that
// matters: a specifier whose only elements are empty is not a valid ranges-specifier, so it is
// the field being ignored rather than a 416.
func TestRangeEmptyElementsAreParsedAndNotCounted(t *testing.T) {
	h, body := film(t)

	// Empty elements around, between and inside a satisfiable set. Still a 206, still two parts.
	for _, value := range []string{
		"bytes=,0-4,10-14",
		"bytes=0-4,,10-14",
		"bytes=0-4,10-14,",
		"bytes=,,,0-4,,,10-14,,,",
		"bytes=0-4" + strings.Repeat(",", 10000) + "10-14",
	} {
		assertMultipart(t, rangeGet(t, h, "/"+filmName, value), body, filmType,
			[]span{{0, 4}, {10, 14}})
	}

	// maxRanges specs with ten thousand empty elements mixed in is still maxRanges specs, so the
	// bound is a count of ranges and not a count of commas.
	padded := "bytes="
	for i := range maxRanges {
		padded += strconv.Itoa(i) + "-" + strconv.Itoa(i) + strings.Repeat(",", 625)
	}
	a := rangeGet(t, h, "/"+filmName, padded)
	assertMultipart(t, a, body, filmType, octets(maxRanges))

	// And a specifier that is nothing but empty elements holds no ranges-specifier, so it is
	// ignored rather than refused.
	for _, value := range []string{"bytes=", "bytes=,", "bytes=,,,,", "bytes=" + strings.Repeat(",", 10000)} {
		b := rangeGet(t, h, "/"+filmName, value)
		assertFields(t, b, ok(filmType, filmSize))
		if b.body != body {
			t.Errorf("%.20q sent %d octets, want the whole file", value, len(b.body))
		}
	}
}

// TestRangeListWhitespaceIsAccepted is the specifier §14.1.2 of RFC 9110 prints as its own
// example — bytes= 0-999, 4500-5499, -1000 — which has a space the list grammar does not put
// there. It is in the RFC, so it is in the wild, and refusing it would cost a peer the transfer
// it asked for in order to enforce a distinction between two spellings of one request.
//
// The file here is six thousand octets so that the RFC's own example is satisfiable against it.
func TestRangeListWhitespaceIsAccepted(t *testing.T) {
	const size = 6000
	body := content(size)
	h := newHandler(t, map[string]string{filmName: body})

	for _, c := range []struct {
		value string
		spans []span
	}{
		{"bytes= 0-999, 4500-5499, -1000", []span{{0, 999}, {4500, 5499}, {5000, 5999}}},
		{"bytes=0-4 , 10-14", []span{{0, 4}, {10, 14}}},
		{"bytes=\t0-4,\t10-14", []span{{0, 4}, {10, 14}}},
		{"bytes= 0-4 ,\t10-14", []span{{0, 4}, {10, 14}}},
	} {
		assertMultipart(t, rangeGet(t, h, "/"+filmName, c.value), body, filmType, c.spans)
	}

	// The whitespace a range field may not carry is at its two ends, and it is refused a layer
	// below this package: §8.2.1 of RFC 9113 forbids a field value that starts or ends with an
	// ASCII whitespace character, so internal/request rejects the request as malformed and this
	// handler never sees one. Asserted here because it is the reason evaluateRange compares the
	// unit token without trimming it.
	for _, value := range []string{" bytes=0-9", "bytes=0-9 ", "\tbytes=0-9", "bytes=0-9\t"} {
		fields := []h2.Field{
			{Name: ":method", Value: methodGet},
			{Name: ":scheme", Value: "https"},
			{Name: ":authority", Value: "zdh.test"},
			{Name: ":path", Value: "/" + filmName},
			{Name: "range", Value: value},
		}
		if _, err := request.Parse(1, fields, true); err == nil {
			t.Errorf("internal/request accepted the range value %q", value)
		}
	}

	// One spec with the same whitespace, which takes the single-part path instead.
	a := rangeGet(t, h, "/"+filmName, "bytes= 0-9")
	assertFields(t, a, partial206(filmType, 10, "bytes 0-9/6000"))
}

// TestRangeUnitIsCaseInsensitive is §14.1 of RFC 9110 on unit names, which is the one place in a
// range field where case does not matter. A browser sends "bytes" and a hand-written client may
// well send anything.
func TestRangeUnitIsCaseInsensitive(t *testing.T) {
	h, body := film(t)

	for _, value := range []string{"bytes=0-9", "BYTES=0-9", "Bytes=0-9", "bYtEs=0-9", "byteS=0-9"} {
		a := rangeGet(t, h, "/"+filmName, value)
		assertFields(t, a, partial206(filmType, 10, "bytes 0-9/1000"))
		if a.body != body[0:10] {
			t.Errorf("%s sent the wrong octets", value)
		}
	}

	// The response's own unit token is lower case whatever the request used, since it is this
	// server's spelling and not an echo of the peer's.
	if got := rangeGet(t, h, "/"+filmName, "BYTES=0-9").get("accept-ranges"); got != "bytes" {
		t.Errorf("accept-ranges = %q after an upper-case unit, want %q", got, "bytes")
	}
}

// TestRangeInvalidBeatsUnsatisfiable is the order the two questions are asked in, which is only
// visible where a spec is both. bytes=9-5 against a three-octet file is invalid — the last-pos
// is below the first-pos — and it is also unsatisfiable, since the first-pos is past the end. It
// is answered with the file, because validity is decided first.
//
// A server that asked about satisfiability first would send a 416 here, and the 416 would be a
// claim that the file is too short for a request whose real problem was that it was malformed.
func TestRangeInvalidBeatsUnsatisfiable(t *testing.T) {
	const tiny = "abc"
	h := newHandler(t, map[string]string{filmName: tiny})

	for _, value := range []string{"bytes=9-5", "bytes=1000-999", "bytes=" + huge + "-0"} {
		a := rangeGet(t, h, "/"+filmName, value)
		if got := a.status(); got != status200 {
			t.Errorf("%s answered %s, want %s", value, got, status200)
		}
		if a.body != tiny {
			t.Errorf("%s sent %q, want %q", value, a.body, tiny)
		}
	}

	// The satisfiability question on its own, for contrast: a valid spec past the end of the
	// same file is the 416 the shapes above are not.
	assertNotSatisfiable(t, rangeGet(t, h, "/"+filmName, "bytes=9-"), len(tiny))
}

// TestRangeOverflowingNumeralIsNotASyntaxError is why parsePos maps an overflow to the largest
// int64 rather than refusing it, and the test that shows the difference is the second one.
//
// bytes=<ninety digits>- alone is a client asking for a file larger than any that exists, and
// answering it with a 416 or with the file are both defensible. Beside a valid spec it is not:
// bytes=0-0,<ninety digits>- is a client asking for the first octet and a tail this file does
// not have, and reading the second spec as malformed would void the first one too. So the
// overflow is unsatisfiable, it is skipped, and the peer gets the octet it asked for.
func TestRangeOverflowingNumeralIsNotASyntaxError(t *testing.T) {
	h, body := film(t)

	// A first-pos that overflows is past the end of every file: unsatisfiable, skipped, and the
	// valid spec beside it survives as a single part.
	a := rangeGet(t, h, "/"+filmName, "bytes=0-0,"+huge+"-")
	assertFields(t, a, partial206(filmType, 1, "bytes 0-0/1000"))
	if a.body != body[0:1] {
		t.Errorf("content = %q, want %q", a.body, body[0:1])
	}

	// A last-pos that overflows is clamped to the end, exactly as an absent one is.
	b := rangeGet(t, h, "/"+filmName, "bytes=995-"+huge)
	assertFields(t, b, partial206(filmType, 5, "bytes 995-999/1000"))

	// A suffix-length that overflows selects the whole file, exactly as one longer than the file
	// does. Both of these are the same clamp as bytes=-1000.
	c := rangeGet(t, h, "/"+filmName, "bytes=-"+huge)
	assertFields(t, c, partial206(filmType, filmSize, "bytes 0-999/1000"))

	// And the numeral is read as a number rather than truncated to one, so a spec that would be
	// satisfiable at some shorter prefix of those digits is not.
	assertNotSatisfiable(t, rangeGet(t, h, "/"+filmName, "bytes="+huge+"-"), filmSize)
}

// TestRangeSumOverRepresentationIsIgnored is the second of the two bounds maxRanges describes,
// and it is the one that closes the hole the count bound leaves: sixteen requests for the whole
// file are sixteen ranges, well inside the count, and sixteen times the bandwidth.
//
// The remedy is the field being ignored, which costs the attacker its leverage without costing
// an honest peer anything: a request whose parts add up to more than the file is answered with
// the file, once, which is no more work than the same peer would have caused by sending no range
// field at all.
func TestRangeSumOverRepresentationIsIgnored(t *testing.T) {
	h, body := film(t)

	for _, value := range []string{
		"bytes=0-999,0-999",
		"bytes=0-,0-",
		"bytes=-1000,-1000",
		"bytes=0-500,0-500,0-500",
		"bytes=" + strings.TrimPrefix(strings.Repeat(",0-999", maxRanges), ","),
		"bytes=" + strings.TrimPrefix(strings.Repeat(",0-99", 11), ","),
	} {
		a := rangeGet(t, h, "/"+filmName, value)
		assertFields(t, a, ok(filmType, filmSize))
		if a.body != body {
			t.Errorf("%.40q sent %d octets, want the whole file once", value, len(a.body))
		}
	}
}

// TestRangeSumAtTheRepresentationIsPartial is the same bound from the other side. A range-set
// whose parts add up to exactly the file is inside the cap and is answered as the 206 it asks
// for, so the test above is a bound and not an accident of the shapes it happens to use.
func TestRangeSumAtTheRepresentationIsPartial(t *testing.T) {
	h, body := film(t)

	assertMultipart(t, rangeGet(t, h, "/"+filmName, "bytes=0-499,500-999"), body, filmType,
		[]span{{0, 499}, {500, 999}})
	assertMultipart(t, rangeGet(t, h, "/"+filmName, "bytes=0-499,0-499"), body, filmType,
		[]span{{0, 499}, {0, 499}})

	// One octet more than the file, which is the first value on the other side of the bound.
	a := rangeGet(t, h, "/"+filmName, "bytes=0-499,0-500")
	assertFields(t, a, ok(filmType, filmSize))

	// And the unsatisfiable specs do not contribute, since they are not parts. Ten requests for
	// the whole file past the end of it plus one real range is one part.
	b := rangeGet(t, h, "/"+filmName, "bytes="+
		strings.TrimPrefix(strings.Repeat(",1000-", 10), ",")+",0-9")
	assertFields(t, b, partial206(filmType, 10, "bytes 0-9/1000"))
}

// TestRangeIgnoredOnHead is §14.2 of RFC 9110's MUST about methods: GET is the only one range
// handling is defined for. So a HEAD carrying a range gets the field set of the whole file,
// which is also what §9.3.2 of RFC 9110 requires of a HEAD independently — the fields have to be
// the ones a GET would have sent, and a GET with no range field is what the same paragraph makes
// this HEAD equivalent to.
func TestRangeIgnoredOnHead(t *testing.T) {
	h, _ := film(t)

	for _, value := range []string{"bytes=0-9", "bytes=-5", "bytes=5000-", specs(maxRanges + 1)} {
		a := serveCond(t, h, methodHead, "/"+filmName, h2.Field{Name: "range", Value: value})
		assertFields(t, a, ok(filmType, filmSize))
		if a.body != "" {
			t.Errorf("HEAD with %q sent %d octets of content", value, len(a.body))
		}
		if !a.ended {
			t.Errorf("HEAD with %q left the stream open", value)
		}
	}
}

// TestRangeIgnoredOnEmptyFile is §14.2 of RFC 9110's permission for a representation with no
// content, taken for the reason the package documentation gives: one range-spec is satisfiable
// against a zero-length representation — §14.1.2 of RFC 9110 makes bytes=-1 one — and §14.4 of
// RFC 9110's grammar has no way to describe the nothing that would be sent for it.
//
// So every shape gets the empty 200, whose own framing is a header section with END_STREAM on it
// and no DATA frame at all.
func TestRangeIgnoredOnEmptyFile(t *testing.T) {
	h := newHandler(t, map[string]string{filmName: ""})

	for _, value := range []string{"bytes=0-0", "bytes=-1", "bytes=0-", "bytes=-0", "bytes=abc"} {
		a := rangeGet(t, h, "/"+filmName, value)
		assertFields(t, a, ok(filmType, 0))
		if a.body != "" {
			t.Errorf("%q against an empty file sent %q", value, a.body)
		}
		if a.data() != 0 {
			t.Errorf("%q against an empty file sent %d DATA frames", value, a.data())
		}
		if !a.ended {
			t.Errorf("%q left the stream open", value)
		}
	}
}

// TestRangeRepeatedFieldLinesAreIgnored is §5.3 of RFC 9110's rule about a field name appearing
// twice, read against §14.2 of RFC 9110's grammar. Two lines are one comma-separated list, and a
// list of two ranges-specifiers is not a ranges-specifier — the unit appears once in the
// grammar, and bytes=0-4,bytes=10-14 is a range-set whose second element no range-spec can
// hold.
//
// Ignored rather than refused, and ignored rather than answered from the last line, which is
// what lookup would have handed over. The pair below is the whole of the argument: each value
// alone is a perfectly good 206, so a handler that took either one would be caught here.
func TestRangeRepeatedFieldLinesAreIgnored(t *testing.T) {
	h, body := film(t)

	for _, c := range [][]string{
		{"bytes=0-9", "bytes=100-199"},
		{"bytes=0-9", "bytes=0-9"},
		{"bytes=0-9", "not-a-range"},
		{"not-a-range", "bytes=0-9"},
		{"bytes=0-9", "bytes=100-199", "bytes=-5"},
	} {
		fields := make([]h2.Field, 0, len(c))
		for _, value := range c {
			fields = append(fields, h2.Field{Name: "range", Value: value})
		}

		a := serveCond(t, h, methodGet, "/"+filmName, fields...)
		assertFields(t, a, ok(filmType, filmSize))
		if a.body != body {
			t.Errorf("%d range lines sent %d octets, want the whole file", len(c), len(a.body))
		}
	}
}

// --- if-range ---------------------------------------------------------------

// TestIfRangeCancelsTheRange is ifRangeIsFalse in the response. This server has no strong
// validator, so §13.1.5 of RFC 9110's condition is false down both of its branches, and the same
// section says what follows: the range field is ignored and the peer gets the whole
// representation.
//
// The values below are chosen so that no plausible implementation of the field would agree with
// all of them. The file's own last-modified is the one a client resuming a download would send,
// and a server comparing dates would find it equal and answer a 206; a date after the file's
// would satisfy an implementation that compared the wrong way round; and an entity tag can match
// nothing, since none is ever sent.
func TestIfRangeCancelsTheRange(t *testing.T) {
	h, body := film(t)

	for _, value := range []string{
		fileTimeField,
		clockField,
		"Thu, 01 Jan 1970 00:00:00 GMT",
		`"x"`,
		`W/"x"`,
		"",
		"not a date and not a tag",
	} {
		a := rangeGet(t, h, "/"+filmName, "bytes=0-9", h2.Field{Name: "if-range", Value: value})
		if a.err != nil {
			t.Errorf("%q: serve: %v", value, a.err)
			continue
		}
		assertFields(t, a, ok(filmType, filmSize))
		if a.body != body {
			t.Errorf("if-range %q sent %d octets, want the whole file", value, len(a.body))
		}
	}
}

// TestIfRangeWithoutARangeIsIgnored is §13.1.5 of RFC 9110's other MUST: "A server MUST ignore
// an If-Range header field received in a request that does not contain a Range header field."
//
// Which this server gets from the order inside evaluateRange's condition rather than from a
// second check, so the assertion is that the field changes nothing at all — the response is the
// ordinary 200, not a 206 and not a 412. The precondition fields are the contrast: an if-range
// is not one, and an if-match with the same value is a 412.
func TestIfRangeWithoutARangeIsIgnored(t *testing.T) {
	h, body := film(t)

	for _, value := range []string{`"x"`, fileTimeField, ""} {
		a := serveCond(t, h, methodGet, "/"+filmName, h2.Field{Name: "if-range", Value: value})
		assertFields(t, a, ok(filmType, filmSize))
		if a.body != body {
			t.Errorf("if-range %q alone sent %d octets, want the whole file", value, len(a.body))
		}
	}

	// The same value in an if-match, which is a precondition and does refuse the request. Here
	// so that the test above is a statement about if-range and not about this handler ignoring
	// every field it is sent.
	b := serveCond(t, h, methodGet, "/"+filmName, h2.Field{Name: fieldIfMatch, Value: `"x"`})
	if b.status() != status412 {
		t.Errorf("if-match \"x\" answered %s, want %s", b.status(), status412)
	}
}

// TestIfRangeDoesNotAffectAHead is the two ignore rules meeting. A HEAD's range is ignored for
// the method, so there is nothing for the if-range to cancel, and the response is the same field
// set either way.
func TestIfRangeDoesNotAffectAHead(t *testing.T) {
	h, _ := film(t)

	a := serveCond(t, h, methodHead, "/"+filmName,
		h2.Field{Name: "range", Value: "bytes=0-9"},
		h2.Field{Name: "if-range", Value: fileTimeField})
	assertFields(t, a, ok(filmType, filmSize))
}

// TestIfRangeRepeatedIsStillFalse is the field counted rather than read. ifRangeIsFalse asks
// lookup for the number of lines and not for a value, so two if-range lines cancel the range
// exactly as one does — which is the answer whatever the values were, and is the reason not
// parsing them is safe.
func TestIfRangeRepeatedIsStillFalse(t *testing.T) {
	h, body := film(t)

	a := serveCond(t, h, methodGet, "/"+filmName,
		h2.Field{Name: "range", Value: "bytes=0-9"},
		h2.Field{Name: "if-range", Value: `"x"`},
		h2.Field{Name: "if-range", Value: fileTimeField})
	assertFields(t, a, ok(filmType, filmSize))
	if a.body != body {
		t.Errorf("two if-range lines sent %d octets, want the whole file", len(a.body))
	}
}

// --- the order against the preconditions ------------------------------------

// TestRangeIsEvaluatedAfterThePreconditions is §14.2 of RFC 9110 on where this field sits: it is
// read after the preconditions and only where the result without it would be a 200. The
// paragraph draws the consequence itself, per §14.2 of RFC 9110: "In other words, Range is
// ignored when a conditional GET would result in a 304" — and this server gets it by calling in
// that order, so what is asserted here is the order.
//
// Both of the statuses that come before the range field are exercised, each with a range that
// would have been a 206 on its own and each with one that would have been a 416. Neither
// changes the answer, and neither response carries a content-range: a 304 describes a
// representation the peer already has, and a 412 describes none at all.
func TestRangeIsEvaluatedAfterThePreconditions(t *testing.T) {
	h, _ := film(t)

	for _, value := range []string{"bytes=0-9", "bytes=5000-", specs(maxRanges + 1), "bytes=-0"} {
		notModified := serveCond(t, h, methodGet, "/"+filmName,
			h2.Field{Name: fieldIfModifiedSince, Value: fileTimeField},
			h2.Field{Name: "range", Value: value})
		if got := notModified.status(); got != status304 {
			t.Errorf("a fresh if-modified-since with %q answered %s, want %s",
				value, got, status304)
		}
		if got := notModified.get("content-range"); got != "" {
			t.Errorf("the 304 for %q sent content-range %q", value, got)
		}
		if got := notModified.get("accept-ranges"); got != "" {
			t.Errorf("the 304 for %q sent accept-ranges %q", value, got)
		}

		failed := serveCond(t, h, methodGet, "/"+filmName,
			h2.Field{Name: fieldIfMatch, Value: `"x"`},
			h2.Field{Name: "range", Value: value})
		if got := failed.status(); got != status412 {
			t.Errorf("a failed if-match with %q answered %s, want %s", value, got, status412)
		}
		if got := failed.get("content-range"); got != "" {
			t.Errorf("the 412 for %q sent content-range %q", value, got)
		}
	}
}

// TestRangeSurvivesAPreconditionThatPasses is the other half of the order, without which the
// test above would also pass on a handler that ignored every range field it was sent. A
// precondition that comes out as a 200 leaves the range to be evaluated, so the answer is the
// 206 the range asked for.
func TestRangeSurvivesAPreconditionThatPasses(t *testing.T) {
	h, body := film(t)

	for _, extra := range []h2.Field{
		{Name: fieldIfNoneMatch, Value: `"x"`},
		{Name: fieldIfModifiedSince, Value: "Thu, 01 Jan 1970 00:00:00 GMT"},
		{Name: fieldIfUnmodifiedSince, Value: clockField},
	} {
		a := rangeGet(t, h, "/"+filmName, "bytes=0-9", extra)
		assertFields(t, a, partial206(filmType, 10, "bytes 0-9/1000"))
		if a.body != body[0:10] {
			t.Errorf("%s: %q sent the wrong octets", extra.Name, extra.Value)
		}
	}
}

// TestRangeOnAStatusThatHasNoRepresentation is the range field never being reached at all,
// because every one of these is a status §13.2.1 of RFC 9110 puts ahead of the preconditions and
// so ahead of the range. A content-range on any of them would describe a representation the peer
// was not given.
func TestRangeOnAStatusThatHasNoRepresentation(t *testing.T) {
	h := newHandler(t, map[string]string{filmName: content(filmSize), "docs/index.html": page})

	for _, c := range []struct {
		method, target string
		status         string
	}{
		{methodGet, "/missing", status404},
		{"POST", "/" + filmName, status405},
		{methodGet, "/docs", status301},
		{methodGet, "/" + strings.Repeat("a", MaxTargetLength), status414},
	} {
		a := serveCond(t, h, c.method, c.target, h2.Field{Name: "range", Value: "bytes=0-9"})
		if a.status() != c.status {
			t.Errorf("%s %.20q answered %s, want %s", c.method, c.target, a.status(), c.status)
			continue
		}
		if got := a.get("content-range"); got != "" {
			t.Errorf("%s %.20q sent content-range %q on a %s", c.method, c.target, got, c.status)
		}
	}
}

// --- accept-ranges ----------------------------------------------------------

// TestAcceptRangesOnlyWhereThereIsARepresentation is which responses carry the field withRanges
// appends and which do not, and it is the same shape as
// TestValidatorOnlyWhereThereIsARepresentation for the same reason: the set is a decision rather
// than a side effect of where the call happens to sit.
//
// §14.3 of RFC 9110 calls the field "advice for the sake of improving performance and reducing
// unnecessary network transfers", so it goes on the responses that carry a representation — the
// 200, the 206, and the field set of a HEAD, which is the request a client makes in order to find
// out before asking for a range. A 404 or a 301 is not where a peer looks for advice about
// ranging into a representation it was not given.
//
// The 416 is the interesting exclusion, and it is deliberate rather than an omission: a peer that
// got one has already learned that this server supports ranges, since a server that did not
// would have answered with the file.
func TestAcceptRangesOnlyWhereThereIsARepresentation(t *testing.T) {
	h := newHandler(t, map[string]string{filmName: content(filmSize), "docs/index.html": page})

	for _, c := range []struct {
		what           string
		method, target string
		extra          []h2.Field
		status         string
		want           bool
	}{
		{"a file", methodGet, "/" + filmName, nil, status200, true},
		{"a HEAD", methodHead, "/" + filmName, nil, status200, true},
		{"a directory index", methodGet, "/docs/", nil, status200, true},
		{"a single-part 206", methodGet, "/" + filmName,
			[]h2.Field{{Name: "range", Value: "bytes=0-9"}}, "206", true},
		{"a multipart 206", methodGet, "/" + filmName,
			[]h2.Field{{Name: "range", Value: "bytes=0-4,10-14"}}, "206", true},
		{"a HEAD with a range", methodHead, "/" + filmName,
			[]h2.Field{{Name: "range", Value: "bytes=0-9"}}, status200, true},

		{"a redirect", methodGet, "/docs", nil, status301, false},
		{"a missing file", methodGet, "/missing", nil, status404, false},
		{"a refused method", "POST", "/" + filmName, nil, status405, false},
		{"a target too long", methodGet, "/" + strings.Repeat("a", MaxTargetLength), nil,
			status414, false},
		{"a 304", methodGet, "/" + filmName,
			[]h2.Field{{Name: fieldIfModifiedSince, Value: fileTimeField}}, status304, false},
		{"a 412", methodGet, "/" + filmName,
			[]h2.Field{{Name: fieldIfMatch, Value: `"x"`}}, status412, false},
		{"a 416", methodGet, "/" + filmName,
			[]h2.Field{{Name: "range", Value: "bytes=5000-"}}, status416, false},
	} {
		a := serveCond(t, h, c.method, c.target, c.extra...)
		if a.status() != c.status {
			t.Errorf("%s answered %s, want %s", c.what, a.status(), c.status)
			continue
		}

		got := a.get("accept-ranges")
		switch {
		case c.want && got != "bytes":
			t.Errorf("%s accept-ranges = %q, want %q", c.what, got, "bytes")
		case !c.want && got != "":
			t.Errorf("%s sent accept-ranges %q on a %s", c.what, got, c.status)
		}
	}
}

// --- the write path ---------------------------------------------------------

// TestPartialReturnsTheWriteError is every place a 206 can stop, which is more places than a 200
// has: a multipart body alternates framing and content, so a reset stream can land between two
// parts as well as inside one.
//
// A response that returned nil after a failed write would leave internal/exchange believing a
// response went out, and the frame count is asserted beside the error so that a handler which
// kept writing past the refusal is caught too.
func TestPartialReturnsTheWriteError(t *testing.T) {
	h, _ := film(t)

	for _, c := range []struct {
		what     string
		value    string
		failFrom int
	}{
		{"the header section of a single part", "bytes=0-9", 0},
		{"the content of a single part", "bytes=0-9", 1},
		{"the frame that ends a single part", "bytes=0-9", 2},
		{"the header section of a multipart", "bytes=0-4,10-14", 0},
		{"the first part's framing", "bytes=0-4,10-14", 1},
		{"the first part's content", "bytes=0-4,10-14", 2},
		{"the second part's framing", "bytes=0-4,10-14", 3},
		{"the second part's content", "bytes=0-4,10-14", 4},
		{"the closing delimiter", "bytes=0-4,10-14", 5},
		{"the frame that ends a multipart", "bytes=0-4,10-14", 6},
		{"a 416's header section", "bytes=5000-", 0},
		{"a 416's content", "bytes=5000-", 1},
		{"the frame that ends a 416", "bytes=5000-", 2},
	} {
		out := &collector{max: limits.MaxFrameSize, err: errGone, failFrom: c.failFrom}
		w := response.NewWriter(response.NewEncoder(hpack.New(), out), &grants{}, 1)

		err := h.serve(w, reqWith(t, methodGet, "/"+filmName,
			h2.Field{Name: "range", Value: c.value}))
		if !errors.Is(err, errGone) {
			t.Errorf("a write that failed at %s returned %v, want %v", c.what, err, errGone)
		}
		if len(out.frames) != c.failFrom {
			t.Errorf("a write that failed at %s enqueued %d frames, want %d",
				c.what, len(out.frames), c.failFrom)
		}
	}
}

// TestPartialShrankEndsTheStreamFirst is send's final comparison, which is file's guard applied
// to a plan: the length went out before the octets did, and a file truncated in between cannot
// supply them.
//
// Driven by handing send a plan whose span runs past the end of the file, which is what a
// truncation between the stat and the read amounts to and is the only way to produce it without
// a race. What this asserts is the order — the stream is ended before the mismatch is reported,
// because a peer told nothing waits for content that is not coming.
func TestPartialShrankEndsTheStreamFirst(t *testing.T) {
	h, body := film(t)

	f, _, err := h.open(filmName)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	out := &collector{max: limits.MaxFrameSize}
	w := response.NewWriter(response.NewEncoder(hpack.New(), out), &grants{}, 1)

	// A span ten octets longer than the file, and a plan whose length agrees with the span. The
	// section reader stops at the end of the file, so ten fewer octets are written than declared.
	over := span{0, filmSize + 9}
	fields := partial206(filmType, int(over.length()), over.contentRange(filmSize+10))
	err = h.send(w, f, fields, plan{
		lead:   []string{"", ""},
		spans:  []span{over},
		length: over.length(),
	})
	a := read(t, out, err)

	if !errors.Is(a.err, errFileChanged) {
		t.Errorf("send returned %v, want %v", a.err, errFileChanged)
	}
	if !a.ended {
		t.Error("the stream was left open, so the peer is still waiting")
	}
	if a.body != body {
		t.Errorf("content is %d octets, want the %d the file had", len(a.body), filmSize)
	}
}

// TestPartialIsConcurrencySafe is many streams ranging into one file at once, each through the
// handle its own call opened and each writing to a collector of its own.
//
// The property being tested is that a part is independent of every other part: send reads
// through io.NewSectionReader, whose ReadAt does not move the file offset, and it borrows a
// buffer from the pool for the length of one response. A handler that seeked a shared handle, or
// that held one buffer across responses, would produce parts here with another stream's octets in
// them — which the distinctness of content's windows is what catches.
func TestPartialIsConcurrencySafe(t *testing.T) {
	h, body := film(t)

	type job struct {
		value string
		spans []span
	}
	jobs := []job{
		{"bytes=0-99", []span{{0, 99}}},
		{"bytes=500-599", []span{{500, 599}}},
		{"bytes=-100", []span{{900, 999}}},
		{"bytes=0-49,900-949", []span{{0, 49}, {900, 949}}},
		{"bytes=250-299,750-799", []span{{250, 299}, {750, 799}}},
		{"bytes=0-0,1-1,2-2,3-3", []span{{0, 0}, {1, 1}, {2, 2}, {3, 3}}},
	}

	var wg sync.WaitGroup
	for range 16 {
		for _, j := range jobs {
			wg.Add(1)
			go func(j job) {
				defer wg.Done()

				out := &collector{max: limits.MaxFrameSize}
				w := response.NewWriter(response.NewEncoder(hpack.New(), out), &grants{chunk: 37}, 1)
				if err := h.serve(w, reqWith(t, methodGet, "/"+filmName,
					h2.Field{Name: "range", Value: j.value})); err != nil {
					t.Errorf("%s: %v", j.value, err)
					return
				}

				// Reassembled here rather than through read, which asserts against §8.1 with
				// a *testing.T on paths that are fatal, and a Fatalf from a goroutine the test
				// is not on is a call the testing package does not allow.
				var got strings.Builder
				for _, f := range out.frames {
					if d, ok := f.(frame.DataFrame); ok {
						got.Write(d.Data)
					}
				}

				// The octets of each part, which is the assertion a shared handle or a shared
				// buffer would fail: content's every 251-octet window is distinct, so another
				// stream's part does not compare equal to this one's.
				for _, s := range j.spans {
					if want := body[s.first : s.last+1]; !strings.Contains(got.String(), want) {
						t.Errorf("%s is missing the octets of %d-%d", j.value, s.first, s.last)
					}
				}
				if n := len(j.spans); n > 1 {
					if c := strings.Count(got.String(), "Content-Range: "); c != n {
						t.Errorf("%s produced %d parts, want %d", j.value, c, n)
					}
					if !strings.HasSuffix(got.String(), "--\r\n") {
						t.Errorf("%s left the multipart body unterminated", j.value)
					}
				}
			}(j)
		}
	}
	wg.Wait()
}
