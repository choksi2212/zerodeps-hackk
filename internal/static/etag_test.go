package static

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"zerodeps/zdh/internal/h2"
)

// The tests in this file are about the entity tag: what it is, when it changes, what the cache in
// front of it is allowed to remember, and how a peer's tag is compared against it.
//
// Every entity-tag literal below is written out with its quotation marks visible, because the marks
// are part of the value everywhere in this package — a test that compared bare opaque values would
// pass against a handler that sent the field unquoted, which no cache would then match.

// --- what the tag is --------------------------------------------------------

// TestFixtureTagsAreTheLiteralsWrittenOut holds tagOf to the three tags the other files assert as
// literals, which is what makes tagOf usable for the fixtures that are generated rather than typed.
//
// The empty one is the case a reader can check without running anything. The SHA-256 of no input is
// a published constant — e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 — and
// 47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU is those thirty-two octets in the alphabet §5 of
// RFC 4648 defines, with the padding §3.2 of RFC 4648 permits to be omitted left off.
func TestFixtureTagsAreTheLiteralsWrittenOut(t *testing.T) {
	for _, c := range []struct{ name, body, want string }{
		{"page", page, pageTag},
		{"module", "export const a = 1\n", moduleTag},
		{"empty", "", emptyTag},
	} {
		if got := tagOf(c.body); got != c.want {
			t.Errorf("tagOf(%s) = %s, want %s", c.name, got, c.want)
		}
	}
}

// TestEtagIsTheHashOfTheContentAndNotOfAnythingElse is the field on the wire against the digest of
// the octets, for files chosen so that no other input would produce the same answer.
//
// The three pairs are the substitutions a tag built from the wrong thing would survive. Two names
// with one content must give one tag, so the name is not in the hash; two contents at one length
// must give two tags, so the length is not the hash; and a file whose content is its own name must
// not tag as though the name were the content.
func TestEtagIsTheHashOfTheContentAndNotOfAnythingElse(t *testing.T) {
	h := newHandler(t, map[string]string{
		"a.txt":    "the same content\n",
		"b.txt":    "the same content\n",
		"c.txt":    "the SAME content\n",
		"self.txt": "self.txt",
	})

	tags := map[string]string{}
	for _, name := range []string{"a.txt", "b.txt", "c.txt", "self.txt"} {
		a := serve(t, h, methodGet, "/"+name)
		if a.status() != status200 {
			t.Fatalf("GET /%s answered %s", name, a.status())
		}
		if got, want := a.get("etag"), tagOf(a.body); got != want {
			t.Errorf("/%s sent etag %s, want %s — the hash of the %d octets it sent",
				name, got, want, len(a.body))
		}
		tags[name] = a.get("etag")
	}

	if tags["a.txt"] != tags["b.txt"] {
		t.Errorf("two names with one content tagged differently: %s and %s",
			tags["a.txt"], tags["b.txt"])
	}
	if tags["a.txt"] == tags["c.txt"] {
		t.Errorf("two contents of %d octets share the tag %s", len("the same content\n"), tags["a.txt"])
	}
	if tags["self.txt"] == tagOf("") {
		t.Error("the tag is of the empty string, so nothing was read")
	}
}

// TestEtagIsSyntacticallyAnEntityTag applies to what this server generates the grammar §8.8.3 of
// RFC 9110 gives for what it receives: "entity-tag = [ weak ] opaque-tag".
//
// Strong, because §8.8.3 of RFC 9110 makes that the default and a hash has earned it; quoted at both
// ends, because an opaque-tag is; and every character between the marks inside etagc, which §8.8.3 of
// RFC 9110 gives as "etagc = %x21 / %x23-7E / obs-text". The DQUOTE is the one visible character that
// rule excludes, and it is the one a base64 alphabet cannot produce — which is the whole reason the
// tag needs no escaping and splitEntityTag needs no unescaping.
func TestEtagIsSyntacticallyAnEntityTag(t *testing.T) {
	h := newHandler(t, map[string]string{"a.bin": content(300), "empty": ""})

	for _, name := range []string{"a.bin", "empty"} {
		tag := serve(t, h, methodGet, "/"+name).get("etag")

		if strings.HasPrefix(tag, weakPrefix) {
			t.Errorf("/%s sent the weak tag %s; a hash is a strong validator", name, tag)
		}
		if len(tag) < 2 || tag[0] != '"' || tag[len(tag)-1] != '"' {
			t.Fatalf("/%s sent %q, which is not an opaque-tag", name, tag)
		}
		for i, b := range []byte(tag[1 : len(tag)-1]) {
			if b == '"' || b < 0x21 || b > 0x7e {
				t.Errorf("/%s: octet %d of the opaque-tag is %#02x, outside etagc", name, i, b)
			}
		}
		if got, want := len(tag), 43+2; got != want {
			t.Errorf("/%s sent a %d-character tag, want %d: 256 bits is 43 base64 characters",
				name, got, want)
		}
	}
}

// TestEtagOnHeadIsTheOneAGetWouldSend is the rule about HEAD in §9.3.2 of RFC 9110, at the field
// that makes the rule cost something. §9.3.2 of RFC 9110: "the server SHOULD send the same header
// fields in response to a HEAD request as it would have sent if the request method had been GET".
//
// A HEAD used to be a stat. It is now a read of the file, because a field that describes the content
// cannot be produced without the content, and a HEAD that answered with no tag would break the one
// exchange HEAD is good for — ask for the metadata, then fetch conditionally.
func TestEtagOnHeadIsTheOneAGetWouldSend(t *testing.T) {
	h := newHandler(t, map[string]string{"index.html": page})

	head := serve(t, h, methodHead, "/index.html")
	if got := head.get("etag"); got != pageTag {
		t.Errorf("HEAD sent etag %s, want %s", got, pageTag)
	}
	if head.body != "" {
		t.Errorf("HEAD sent %d octets of content", len(head.body))
	}

	// And the tag it sent is one the server will act on, which is the exchange this field is for.
	a := serveCond(t, h, methodGet, "/index.html",
		h2.Field{Name: fieldIfNoneMatch, Value: head.get("etag")})
	if a.status() != status304 {
		t.Errorf("a conditional GET carrying the tag from the HEAD answered %s, want %s",
			a.status(), status304)
	}
}

// --- when the tag changes ---------------------------------------------------

// TestEtagChangesWhenTheContentChangesUnderTheSameLengthAndSecond is the case the whole construction
// exists for, and the one a size-and-timestamp tag cannot answer.
//
// The file is rewritten to a different content of the same length, immediately, so that the second
// version's modification time is in the same second as the first's and on a coarse filesystem the
// same value entirely. A validator built from the metadata would be unchanged across the rewrite,
// and a cache holding the old copy would be told it was still current — which §8.8.1 of RFC 9110
// rules out for a strong validator: "A strong validator is unique across all versions of all
// representations associated with a particular resource over time".
//
// The handler's clock is the real one here, not this package's pinned one, because that is what
// tagSettleWindow is measured against: a file written a moment ago has not settled, so the cache
// declines to speak for it and the second request hashes the file again. Which is the point — the
// guarantee is not "the tag changes when the cache notices", it is "the tag changes".
func TestEtagChangesWhenTheContentChangesUnderTheSameLengthAndSecond(t *testing.T) {
	const first = "version one\n"
	const second = "version two\n"
	if len(first) != len(second) {
		t.Fatalf("the two versions are %d and %d octets; this test needs one length",
			len(first), len(second))
	}

	dir := t.TempDir()
	name := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(name, []byte(first), 0o644); err != nil {
		t.Fatal(err)
	}
	h, err := New(Config{Dir: dir, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := h.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	before := serve(t, h, methodGet, "/a.txt")
	if before.body != first {
		t.Fatalf("the first response is %q, want %q", before.body, first)
	}

	if err := os.WriteFile(name, []byte(second), 0o644); err != nil {
		t.Fatal(err)
	}

	after := serve(t, h, methodGet, "/a.txt")
	if after.body != second {
		t.Fatalf("the second response is %q, want %q", after.body, second)
	}
	if before.get("etag") == after.get("etag") {
		t.Errorf("both versions tagged %s, so a cache holding the first would keep it",
			before.get("etag"))
	}
	if got, want := after.get("etag"), tagOf(second); got != want {
		t.Errorf("the second tag is %s, want %s", got, want)
	}

	// The content-length is identical across the rewrite, which is the assertion that makes the
	// one above mean something: nothing cheaper than the content could have told these apart.
	if before.get("content-length") != after.get("content-length") {
		t.Errorf("the two versions have lengths %s and %s; the test did not reproduce its case",
			before.get("content-length"), after.get("content-length"))
	}
}

// TestEtagIsStableAcrossRequests is the other half: a file nothing has touched keeps its tag, over
// enough requests that a per-response nonce or a cache that missed every time would show up.
//
// A tag that changed when the representation did not would be worse than no tag at all. Every
// conditional request would be a transfer, every if-range would be cancelled, and the field would
// cost a read on both ends to accomplish nothing.
func TestEtagIsStableAcrossRequests(t *testing.T) {
	h := newHandler(t, map[string]string{"index.html": page})

	for i := range 20 {
		if got := serve(t, h, methodGet, "/index.html").get("etag"); got != pageTag {
			t.Fatalf("request %d sent etag %s, want %s", i, got, pageTag)
		}
	}
}

// TestEtagSurvivesTheFileBeingReadTwice is the offset of the open handle after a hash.
//
// The tag is computed by reading the whole file, and the content is sent from the same handle
// afterwards. If the hash had read through the handle's own offset rather than through a section
// reader, the body would be empty and the content-length would still say otherwise — a response
// §8.6 of RFC 9110 makes malformed, sent to every peer, for every file, invisibly to a test that
// only looked at the fields.
func TestEtagSurvivesTheFileBeingReadTwice(t *testing.T) {
	h := newHandler(t, map[string]string{"a.bin": content(5000)})
	body := content(5000)

	for i := range 3 {
		a := serve(t, h, methodGet, "/a.bin")
		if a.body != body {
			t.Fatalf("request %d sent %d octets, want %d", i, len(a.body), len(body))
		}
		if got := a.get("content-length"); got != strconv.Itoa(len(body)) {
			t.Errorf("request %d declared content-length %s", i, got)
		}
	}

	// The range path reads from the same handle through a second section reader, so it is the
	// case where two of them are live at once.
	a := serveCond(t, h, methodGet, "/a.bin", h2.Field{Name: "range", Value: "bytes=4990-"})
	if want := body[4990:]; a.body != want {
		t.Errorf("the tail is %q, want %q", a.body, want)
	}
	if got := a.get("etag"); got != tagOf(body) {
		t.Errorf("the 206 sent etag %s, want the whole file's %s", got, tagOf(body))
	}
}

// TestEtagIsAbsentWhenTheContentCannotBeRead is the failure etag turns into no field rather than
// into a 500: a read that fails costs the response one validator and nothing else.
//
// The failure is produced by closing the handle after it has been stat'ed, which is the one way to
// get a real read error out of a real os.File on every platform this builds for. It is also the
// closest available stand-in for the failure that actually happens in production — a file whose
// storage went away between the open and the read — and it is honest about the size, since the stat
// happened while the handle was live and reports the octets that are no longer reachable.
//
// A directory would not do. It is what the handler stats as unreadable on Unix, and on Windows a
// directory stats at a size of zero, so the section reader would be empty and the hash would succeed
// with the tag of no content at all: a test that passed for the wrong reason on one platform and the
// right one on the other.
func TestEtagIsAbsentWhenTheContentCannotBeRead(t *testing.T) {
	h := newHandler(t, map[string]string{"index.html": page})

	f, info, err := h.open("index.html")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if info.Size() == 0 {
		t.Fatal("the fixture is empty, so an unread file and a read one would tag alike")
	}

	if got := h.etag("index.html", f, info, clock.UTC()); got != "" {
		t.Errorf("etag on an unreadable file = %q, want no tag at all", got)
	}

	// And nothing was filed under the name, so a later request does not inherit the failure.
	h.tags.mu.Lock()
	_, cached := h.tags.entries["index.html"]
	h.tags.mu.Unlock()
	if cached {
		t.Error("a failed hash was cached")
	}

	// The response the handler builds for the same file is unaffected: it opens its own handle,
	// and the validator is back.
	if got := serve(t, h, methodGet, "/index.html").get("etag"); got != pageTag {
		t.Errorf("the next request sent etag %s, want %s", got, pageTag)
	}
}

// --- the cache --------------------------------------------------------------

// TestVersionOfIsTheWholeOfWhatTheFilesystemKnows is the cache key: every part of the stat that a
// rewrite could change, in the form it is compared in.
//
// A tagVersion is compared with ==, so this struct is the whole of what "the same file" means to
// the cache. Anything a rewrite can change that is not in here is a stale tag until the entry is
// evicted, and the length is the field that carries that weight — a timestamp can be forced back
// to what it was, by hand or by a filesystem too coarse to tell two writes apart, and the length
// then is all that is left to notice with.
//
// The second and the nanosecond are separate fields rather than one count of nanoseconds because
// time.Time.UnixNano is only defined for the years 1678 to 2262, and a file whose date falls
// outside that range is not an exotic case: an archive unpacked with its original stamps, or a
// Windows tree whose timestamps were zeroed to the 1601 epoch, both land there. Folding them
// would give every such file the same version as every other one.
func TestVersionOfIsTheWholeOfWhatTheFilesystemKnows(t *testing.T) {
	for _, c := range []struct {
		name string
		info stamped
		want tagVersion
	}{
		{
			name: "an empty file at the epoch, which is a version like any other",
			info: stamped{mod: time.Unix(0, 0).UTC(), size: 0},
			want: tagVersion{},
		}, {
			name: "the second and the nanosecond are both carried",
			info: stamped{mod: time.Date(1970, time.January, 1, 0, 0, 1, 2, time.UTC), size: 1},
			want: tagVersion{size: 1, sec: 1, nsec: 2},
		}, {
			// 134774 days from 1601-01-01 to 1970-01-01, which is where a Windows
			// timestamp of zero lands.
			name: "the 1601 epoch, which has no UnixNano",
			info: stamped{mod: time.Date(1601, time.January, 1, 0, 0, 0, 0, time.UTC), size: 12},
			want: tagVersion{size: 12, sec: -11644473600, nsec: 0},
		}, {
			name: "one second past the 32-bit rollover, at a length past it too",
			info: stamped{mod: time.Date(2038, time.January, 19, 3, 14, 8, 0, time.UTC), size: 1 << 32},
			want: tagVersion{size: 1 << 32, sec: 2147483648, nsec: 0},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := versionOf(c.info); got != c.want {
				t.Errorf("versionOf = %+v, want %+v", got, c.want)
			}
		})
	}
}

// TestTagCacheHashesOncePerVersion is the cache doing the job it exists for, counted rather than
// assumed: a hash per version of the file, however many times it is asked for.
func TestTagCacheHashesOncePerVersion(t *testing.T) {
	c := newTagCache(maxTagCacheEntries)
	calls := 0
	hash := func(tag string) func() (string, error) {
		return func() (string, error) { calls++; return tag, nil }
	}

	v1 := tagVersion{size: 10, sec: 100, nsec: 0}
	v2 := tagVersion{size: 10, sec: 100, nsec: 1}

	for range 5 {
		if got, err := c.get("a", v1, hash(`"one"`)); got != `"one"` || err != nil {
			t.Fatalf("get = %q, %v", got, err)
		}
	}
	if calls != 1 {
		t.Errorf("%d hashes for one version, want 1", calls)
	}

	// One nanosecond of difference is a different version, and the old entry is replaced rather
	// than kept alongside — the entries map is keyed by name, so a file cannot accumulate.
	if got, _ := c.get("a", v2, hash(`"two"`)); got != `"two"` {
		t.Errorf("a new version returned %q, want the new hash", got)
	}
	if calls != 2 {
		t.Errorf("%d hashes for two versions, want 2", calls)
	}
	if got, _ := c.get("a", v1, hash(`"three"`)); got != `"three"` {
		t.Errorf("the superseded version returned %q, want a fresh hash", got)
	}
	c.mu.Lock()
	n := len(c.entries)
	c.mu.Unlock()
	if n != 1 {
		t.Errorf("one name holds %d entries, want 1", n)
	}
}

// TestTagCacheDoesNotKeepAFailure is a read that failed not becoming the answer for every request
// after it. A cached empty tag would turn one bad read into a file with no validator for as long as
// its timestamp held.
func TestTagCacheDoesNotKeepAFailure(t *testing.T) {
	c := newTagCache(maxTagCacheEntries)
	v := tagVersion{size: 1, sec: 1}
	boom := errors.New("read failed")

	if _, err := c.get("a", v, func() (string, error) { return "", boom }); !errors.Is(err, boom) {
		t.Fatalf("get returned %v, want the read's own error", err)
	}
	if got, err := c.get("a", v, func() (string, error) { return `"ok"`, nil }); got != `"ok"` || err != nil {
		t.Errorf("get after a failure = %q, %v; want the retry's answer", got, err)
	}

	// An empty tag with no error is not filed either. hashContent cannot produce one — the shortest
	// tag it returns is two quotation marks around forty-three characters — but the cache does not
	// know that, and a stored empty string would be indistinguishable from a stored failure.
	if got, _ := c.get("b", v, func() (string, error) { return "", nil }); got != "" {
		t.Fatalf("get = %q", got)
	}
	c.mu.Lock()
	_, cached := c.entries["b"]
	c.mu.Unlock()
	if cached {
		t.Error("an empty tag was cached")
	}
}

// TestTagCacheStaysInsideItsBound is the limit holding against more distinct names than it, which is
// the shape of a peer filling a map by asking for files.
//
// Four hundred names against a limit of eight. What is asserted is only the bound: which entries
// survive is the map's iteration order, and tagCache.store says why that is a legitimate policy
// rather than an oversight.
func TestTagCacheStaysInsideItsBound(t *testing.T) {
	const limit = 8
	c := newTagCache(limit)
	v := tagVersion{size: 1, sec: 1}

	for i := range 400 {
		name := "f" + strconv.Itoa(i)
		if _, err := c.get(name, v, func() (string, error) { return `"` + name + `"`, nil }); err != nil {
			t.Fatal(err)
		}
		c.mu.Lock()
		n := len(c.entries)
		c.mu.Unlock()
		if n > limit {
			t.Fatalf("after %d names the cache holds %d entries, over its limit of %d", i+1, n, limit)
		}
	}
}

// TestTagCacheWithNoRoomForAnythingStillAnswers is the degenerate limit, which is not reachable
// through New and is here because it is where an off-by-one in the bound becomes visible.
//
// A limit of zero is a cache that answers every question by hashing, which is slow and correct. The
// naive way to write the eviction — delete until the map is small enough, then insert — passes for
// every limit above zero and stores one entry for a limit of zero, because the insert happens after
// the loop has stopped looking. That is the same off-by-one at every limit; it is only observable
// here, where the bound leaves nowhere for the entry to go.
func TestTagCacheWithNoRoomForAnythingStillAnswers(t *testing.T) {
	c := newTagCache(0)
	v := tagVersion{size: 1, sec: 1}

	for i := range 3 {
		got, err := c.get("a", v, func() (string, error) { return `"tag"`, nil })
		if got != `"tag"` || err != nil {
			t.Fatalf("request %d: get = %q, %v", i, got, err)
		}
	}
	c.mu.Lock()
	n := len(c.entries)
	c.mu.Unlock()
	if n != 0 {
		t.Errorf("a cache with a limit of zero holds %d entries", n)
	}
}

// TestTagCacheHoldsItsBoundExactly is the same off-by-one at the limits a real cache runs at: for
// every small bound, more distinct names than it, and never one entry more than it was given room
// for.
//
// TestTagCacheStaysInsideItsBound asserts the same property at one limit, which a bound of limit+1
// would satisfy at every step but the last. This sweeps the small limits, where the difference
// between "at most the limit" and "at most one more than the limit" is a whole entry.
func TestTagCacheHoldsItsBoundExactly(t *testing.T) {
	v := tagVersion{size: 1, sec: 1}

	for limit := 1; limit <= 5; limit++ {
		c := newTagCache(limit)
		for i := range limit * 3 {
			name := "f" + strconv.Itoa(i)
			if _, err := c.get(name, v, func() (string, error) { return `"` + name + `"`, nil }); err != nil {
				t.Fatal(err)
			}
			c.mu.Lock()
			n := len(c.entries)
			c.mu.Unlock()
			if want := min(i+1, limit); n != want {
				t.Fatalf("limit %d, %d names in: the cache holds %d entries, want %d",
					limit, i+1, n, want)
			}
		}

		// And re-asking for a name the cache still holds does not grow it, which is the branch
		// eviction has to skip: a replacement is not an insertion.
		c.mu.Lock()
		var held string
		for k := range c.entries {
			held = k
			break
		}
		c.mu.Unlock()
		if _, err := c.get(held, tagVersion{size: 2, sec: 2}, func() (string, error) {
			return `"rewritten"`, nil
		}); err != nil {
			t.Fatal(err)
		}
		c.mu.Lock()
		n := len(c.entries)
		c.mu.Unlock()
		if n != limit {
			t.Errorf("limit %d: rewriting %q left %d entries, want %d", limit, held, n, limit)
		}
	}
}

// TestTagCacheHashesOnceUnderConcurrentRequests is tagCall: sixty-four goroutines asking for one
// cold file, and one read of it.
//
// The hash is held open until every caller has arrived, which is what makes the count meaningful —
// without the gate the first call could finish before the last goroutine started, and a cache with
// no single-flight in it would pass. With the gate, a handler that read the file per request would
// deadlock rather than fail, which is why the barrier is a WaitGroup the hash waits on and not a
// sleep.
func TestTagCacheHashesOnceUnderConcurrentRequests(t *testing.T) {
	const callers = 64

	c := newTagCache(maxTagCacheEntries)
	v := tagVersion{size: 7, sec: 7, nsec: 7}

	var arrived sync.WaitGroup
	arrived.Add(callers)

	var mu sync.Mutex
	hashes := 0

	var done sync.WaitGroup
	got := make([]string, callers)
	errs := make([]error, callers)
	for i := range callers {
		done.Add(1)
		go func() {
			defer done.Done()
			arrived.Done()
			got[i], errs[i] = c.get("a", v, func() (string, error) {
				mu.Lock()
				hashes++
				mu.Unlock()

				// Every caller has been created; wait until every one of them has also
				// reached this get, so that none can arrive after the hash is filed.
				arrived.Wait()
				return `"the one hash"`, nil
			})
		}()
	}
	done.Wait()

	for i := range callers {
		if errs[i] != nil {
			t.Fatalf("caller %d: %v", i, errs[i])
		}
		if got[i] != `"the one hash"` {
			t.Errorf("caller %d got %q", i, got[i])
		}
	}
	if hashes != 1 {
		t.Errorf("%d reads of one cold file, want 1", hashes)
	}
}

// TestTagCacheJoinsOnlyTheSameVersion is the version being part of the in-flight key.
//
// Two concurrent requests for one name at two versions must not share an answer. A single-flight
// keyed on the name alone would hand the second caller the first caller's hash, which is a tag for
// content that request is not sending — the exact failure the cache is supposed to prevent, arrived
// at through the mechanism meant to prevent it.
func TestTagCacheJoinsOnlyTheSameVersion(t *testing.T) {
	cache := newTagCache(maxTagCacheEntries)

	// Both hashes are held until both have started, so the two calls are genuinely in flight at
	// once and neither can be answered from a completed entry.
	//
	// The wait is bounded, because the fault this test looks for is the one that stops the second
	// hash from ever starting: a single-flight keyed on the name alone would park the second
	// caller on the first caller's channel, leaving the first waiting for a partner that cannot
	// arrive. An unbounded barrier would deadlock there, and a deadlock reports a minute of
	// nothing and then every goroutine in the binary, instead of the two answers this test has
	// already caught. Nothing correct waits here at all.
	const pairing = 5 * time.Second
	var both sync.WaitGroup
	both.Add(2)
	paired := make(chan struct{})
	go func() {
		both.Wait()
		close(paired)
	}()

	answers := make([]string, 2)
	var done sync.WaitGroup
	for i, c := range []struct {
		version tagVersion
		tag     string
	}{
		{tagVersion{size: 4, sec: 1}, `"old"`},
		{tagVersion{size: 4, sec: 2}, `"new"`},
	} {
		done.Add(1)
		go func() {
			defer done.Done()
			answers[i], _ = cache.get("a", c.version, func() (string, error) {
				both.Done()
				select {
				case <-paired:
				case <-time.After(pairing):
				}
				return c.tag, nil
			})
		}()
	}
	done.Wait()

	if answers[0] != `"old"` || answers[1] != `"new"` {
		t.Errorf("two versions in flight answered %q and %q, want the two different hashes",
			answers[0], answers[1])
	}
}

// TestTagCacheDoesNotHoldItsLockAcrossTheHash is the property that keeps one slow file from
// stopping every other connection.
//
// One goroutine is inside a hash that will not return until a second goroutine has been answered
// for a different name. If the lock were held across the call the second would block on it, this
// test would never finish, and the timeout would report it — which is the only way to observe a
// lock held too long, since a program that holds one is not wrong, only serial.
func TestTagCacheDoesNotHoldItsLockAcrossTheHash(t *testing.T) {
	c := newTagCache(maxTagCacheEntries)
	v := tagVersion{size: 1, sec: 1}

	other := make(chan struct{})
	slow := make(chan struct{})
	go func() {
		defer close(slow)
		c.get("slow", v, func() (string, error) {
			<-other
			return `"slow"`, nil
		})
	}()

	// Not synchronised with the goroutine above starting its hash, and it does not need to be:
	// if this get can complete at all, it completes.
	if got, err := c.get("fast", v, func() (string, error) { return `"fast"`, nil }); got != `"fast"` || err != nil {
		t.Fatalf("the second name got %q, %v", got, err)
	}
	close(other)
	<-slow
}

// TestTagCacheForgetsAFinishedCall is the in-flight map being emptied rather than accumulated.
//
// Nothing a peer can see depends on this, which is why it is asserted here: an abandoned entry is
// a live *tagCall holding a closed channel, one for every version of every file ever asked for,
// and a map that only grows is the shape of every slow leak. The entries map has a bound because
// it is meant to hold things; this one needs none, on the single condition that it is empty
// whenever no read is in progress.
func TestTagCacheForgetsAFinishedCall(t *testing.T) {
	c := newTagCache(maxTagCacheEntries)

	for i := range 3 {
		v := tagVersion{size: int64(i), sec: 1}
		if _, err := c.get("a", v, func() (string, error) { return `"tag"`, nil }); err != nil {
			t.Fatalf("version %d: %v", i, err)
		}
	}

	c.mu.Lock()
	n := len(c.calls)
	c.mu.Unlock()
	if n != 0 {
		t.Errorf("%d calls still in flight after three finished reads, want 0", n)
	}
}

// TestTagCacheSurvivesAPanicInTheHash is the worst thing that can happen inside the single-flight,
// and the reason the bookkeeping is deferred rather than written after the call.
//
// A hash that panics has no business stopping the server, but the shape of a single-flight makes
// it able to: one goroutine has published a channel that every later request for that file waits
// on, and if it leaves without closing that channel, every one of those requests waits forever.
// A panic here would be a bug in this package, so the tag the survivors get does not matter much
// — that they get one at all is the whole point.
func TestTagCacheSurvivesAPanicInTheHash(t *testing.T) {
	const answering = 5 * time.Second

	c := newTagCache(maxTagCacheEntries)
	v := tagVersion{size: 1, sec: 1}

	died := make(chan struct{})
	go func() {
		defer close(died)
		defer func() { _ = recover() }()
		c.get("a", v, func() (string, error) { panic("the read panicked") })
	}()
	<-died

	answered := make(chan string, 1)
	go func() {
		tag, _ := c.get("a", v, func() (string, error) { return `"after"`, nil })
		answered <- tag
	}()
	select {
	case got := <-answered:
		if got != `"after"` {
			t.Errorf("the request after a panic got %q, want the fresh hash", got)
		}
	case <-time.After(answering):
		t.Fatal("a request for a file whose hash panicked never returned")
	}

	c.mu.Lock()
	n := len(c.calls)
	c.mu.Unlock()
	if n != 0 {
		t.Errorf("%d calls still in flight, want 0; the panicking call was not cleared", n)
	}
}

// --- the settle window ------------------------------------------------------

// TestEtagIsNotCachedBeforeItsTimestampHasSettled is tagSettleWindow at the two files either side of
// it, through the cache's own contents rather than through a response.
//
// The tag is the same either way — a hash is a hash — so the observable difference is only whether
// the answer was filed. A test that looked at the field could not tell the two apart, which is why
// this one looks at the map.
func TestEtagIsNotCachedBeforeItsTimestampHasSettled(t *testing.T) {
	h := newHandler(t, map[string]string{"a.txt": "some content\n"})

	f, info, err := h.open("a.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	// tree stamps every file with fileTime, so "now" is arranged relative to that rather than the
	// other way round. Just inside the window and just outside it, from the same file.
	for _, c := range []struct {
		name   string
		now    time.Time
		cached bool
	}{
		{"written this instant", fileTime, false},
		{"one nanosecond inside the window", fileTime.Add(tagSettleWindow - 1), false},
		{"exactly the window", fileTime.Add(tagSettleWindow), true},
		{"long settled", fileTime.Add(24 * time.Hour), true},
		{"stamped in the future", fileTime.Add(-time.Hour), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			h.tags = newTagCache(maxTagCacheEntries)

			if got, want := h.etag("a.txt", f, info, c.now), tagOf("some content\n"); got != want {
				t.Errorf("etag = %s, want %s; the tag itself does not depend on the clock", got, want)
			}

			h.tags.mu.Lock()
			_, cached := h.tags.entries["a.txt"]
			h.tags.mu.Unlock()
			if cached != c.cached {
				t.Errorf("cached = %v, want %v", cached, c.cached)
			}
		})
	}
}

// TestEtagOfAnUnsettledFileIsRecomputed is the consequence of the rule above, stated as behaviour: a
// file rewritten in place, at the same length and with its modification time forced back to the
// value the first version had, still tags correctly as long as the timestamp is inside the window.
//
// Which is the strongest form of the case: the filesystem has been made to lie about the change, in
// exactly the way a coarse-grained timestamp lies about it by accident, and the answer is still the
// hash of what was sent. Outside the window the same lie is believed, and tagSettleWindow says so —
// that is the boundary of what any server can do without reading every file on every request.
func TestEtagOfAnUnsettledFileIsRecomputed(t *testing.T) {
	const first = "aaaa\n"
	const second = "bbbb\n"

	dir := tree(t, map[string]string{"a.txt": first})
	name := filepath.Join(dir, "a.txt")

	// The handler's clock is one window minus a nanosecond after the file's stamp, so the file is
	// permanently unsettled however long the test takes.
	h, err := New(Config{Dir: dir, Now: func() time.Time {
		return fileTime.Add(tagSettleWindow - 1)
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := h.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	if got := serve(t, h, methodGet, "/a.txt").get("etag"); got != tagOf(first) {
		t.Fatalf("etag = %s, want %s", got, tagOf(first))
	}

	if err := os.WriteFile(name, []byte(second), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(name, fileTime, fileTime); err != nil {
		t.Fatal(err)
	}

	a := serve(t, h, methodGet, "/a.txt")
	if a.body != second {
		t.Fatalf("the response is %q, want %q", a.body, second)
	}
	if got := a.get("etag"); got != tagOf(second) {
		t.Errorf("etag = %s, want %s — the metadata is identical, so only a read could tell",
			got, tagOf(second))
	}
	if got := a.get("last-modified"); got != fileTimeField {
		t.Errorf("last-modified = %q, want %q; the date validator is the one that was fooled",
			got, fileTimeField)
	}
}

// TestTagSettleWindowCoversTheCoarsestFilesystem pins the one number in this file that no other
// test can see.
//
// Every other assertion about the window is written relative to the constant, deliberately: they
// are about the rule, and a test that hard-coded two seconds into the rule would have to be
// rewritten to tune the value. The cost is that all of them would also pass with the window
// shortened to a nanosecond, which would leave the cache trusting a timestamp for a file that
// was written this instant.
//
// So the value is asserted once, here, against what the number is for: the coarsest modification
// time a served directory is likely to sit on. FAT records two seconds, so two writes a second
// apart can carry one identical stamp, and a cache that settled sooner than the granularity of
// the clock underneath it would file the first write's tag and then serve the second write's
// content beside it.
func TestTagSettleWindowCoversTheCoarsestFilesystem(t *testing.T) {
	const fatGranularity = 2 * time.Second

	if tagSettleWindow < fatGranularity {
		t.Errorf("tagSettleWindow is %v, want at least %v, which is what FAT records",
			tagSettleWindow, fatGranularity)
	}
}

// TestTagCacheNoticesALengthChangeUnderARestoredTimestamp is the far side of the boundary the
// window draws. Outside it the stat is trusted, and the length is the part of the stat that a
// rewrite cannot quietly keep.
//
// The file here is a month settled, so the answer comes from the cache, and its modification time
// has been forced back to the value the first version carried — the lie tagSettleWindow admits to
// believing. The length is different, the length is part of the version, and so the lie is caught
// anyway. This is the strongest thing the cache can promise about a settled file, and it is one
// field of one struct away from not being true.
func TestTagCacheNoticesALengthChangeUnderARestoredTimestamp(t *testing.T) {
	const first = "aaaa\n"
	const second = "bbbbbbbb\n"

	dir := tree(t, map[string]string{"a.txt": first})
	h := handlerFor(t, dir)
	name := filepath.Join(dir, "a.txt")

	if got := serve(t, h, methodGet, "/a.txt").get("etag"); got != tagOf(first) {
		t.Fatalf("etag = %s, want %s", got, tagOf(first))
	}

	if err := os.WriteFile(name, []byte(second), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(name, fileTime, fileTime); err != nil {
		t.Fatal(err)
	}

	a := serve(t, h, methodGet, "/a.txt")
	if a.body != second {
		t.Fatalf("the response is %q, want %q", a.body, second)
	}
	if got := a.get("etag"); got != tagOf(second) {
		t.Errorf("etag = %s, want %s; the timestamp was restored, but the length is part of "+
			"the version too", got, tagOf(second))
	}
}

// --- splitting one entity-tag off a list ------------------------------------

// TestSplitEntityTag is §8.8.3 of RFC 9110's grammar as a parser, including the character that makes
// the parser necessary.
//
// The comma cases are the ones a strings.Split would fail. §8.8.3 of RFC 9110's etagc rule is
// "%x21 / %x23-7E / obs-text", the comma is %x2C, and so "a,b" between two quotation marks is one
// entity tag containing a comma rather than two tags — which the last two rows assert from both
// directions at once.
func TestSplitEntityTag(t *testing.T) {
	for _, c := range []struct {
		in     string
		opaque string
		weak   bool
		rest   string
		ok     bool
	}{
		{in: `"x"`, opaque: `"x"`, ok: true},
		{in: `W/"x"`, opaque: `"x"`, weak: true, ok: true},
		{in: `""`, opaque: `""`, ok: true},
		{in: `W/""`, opaque: `""`, weak: true, ok: true},
		{in: `"x", "y"`, opaque: `"x"`, rest: `, "y"`, ok: true},
		{in: `"x"junk`, opaque: `"x"`, rest: "junk", ok: true},

		// A comma inside the marks belongs to the tag.
		{in: `"a,b"`, opaque: `"a,b"`, ok: true},
		{in: `"a,b","c"`, opaque: `"a,b"`, rest: `,"c"`, ok: true},

		// A backslash is an ordinary character: opaque-tag is not a quoted-string, so the mark
		// after it closes the tag.
		{in: `"a\"`, opaque: `"a\"`, ok: true},

		// Nothing that is an entity tag.
		{in: ``},
		{in: `*`},
		{in: `x`},
		{in: `"unterminated`},
		{in: `W/`},
		{in: `W/x`},
		{in: `W/W/"x"`},
		{in: `w/"x"`},
		{in: ` "x"`},
		{in: `'x'`},
	} {
		opaque, weak, rest, ok := splitEntityTag(c.in)
		if ok != c.ok {
			t.Errorf("splitEntityTag(%q) ok = %v, want %v", c.in, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		if opaque != c.opaque || weak != c.weak || rest != c.rest {
			t.Errorf("splitEntityTag(%q) = %q, %v, %q; want %q, %v, %q",
				c.in, opaque, weak, rest, c.opaque, c.weak, c.rest)
		}
	}
}

// TestSplitEntityTagKeepsTheQuotationMarks is the invariant every comparison in this package rests
// on: what comes back is the opaque-tag with its marks, so comparing two of them is comparing
// "the opaque-tags" of §8.8.3.2 of RFC 9110 and nothing more.
//
// If the marks were stripped, a strong tag and a weak one would differ only in the flag, which is
// still enough — but so would the opaque-tag "x" and the three-character value x", and a list
// element that was never a legal entity tag would compare equal to one that was.
func TestSplitEntityTagKeepsTheQuotationMarks(t *testing.T) {
	for _, in := range []string{`"x"`, `W/"x"`, `""`, `"a,b"`} {
		opaque, _, _, ok := splitEntityTag(in)
		if !ok {
			t.Fatalf("splitEntityTag(%q) refused a valid entity tag", in)
		}
		if !strings.HasPrefix(opaque, `"`) || !strings.HasSuffix(opaque, `"`) || len(opaque) < 2 {
			t.Errorf("splitEntityTag(%q) returned %q, which is not a quoted opaque-tag", in, opaque)
		}
	}
}

// --- the two comparison functions -------------------------------------------

// TestMatchesIsTheTwoComparisonFunctions is §8.8.3.2 of RFC 9110's table, both columns, over lists
// rather than over single tags.
//
// The four rows of that table are the first four cases: strong against strong, strong against weak,
// weak against strong, weak against weak. Everything after them is the list around the tag, and the
// rule that a list this function cannot fully read matches nothing — which matters because the two
// callers want opposite things from a refusal and both get the safe one. matches says which.
func TestMatchesIsTheTwoComparisonFunctions(t *testing.T) {
	const tag = `"x"`

	for _, c := range []struct {
		value  string
		strong bool
		weak   bool
		notes  string
	}{
		// §8.8.3.2's table.
		{value: `"x"`, strong: true, weak: true},
		{value: `W/"x"`, weak: true, notes: "no match under strong comparison"},
		{value: `"y"`, notes: "different opaque-tags never match"},
		{value: `W/"y"`, notes: "weak comparison ignores the indicator, not the tag"},

		// Lists.
		{value: `"a", "b", "x"`, strong: true, weak: true},
		{value: `"x","a"`, strong: true, weak: true, notes: "no whitespace is required"},
		{value: `  "x"  `, strong: true, weak: true, notes: "OWS either side of a member"},
		{value: "\t\"x\"\t", strong: true, weak: true},
		{value: `"a", W/"x"`, weak: true},
		{value: `"a", "b"`, notes: "a list with no match in it"},
		{value: ``, notes: "an empty value is a list of no tags"},
		{value: `,`, notes: "and so is a value of separators"},
		{value: `,,, ,,`, notes: "§5.6.1.2 asks for empty elements to be ignored"},
		{value: `, "x" ,`, strong: true, weak: true},

		// A comma inside a tag is not a separator, so the whole thing is one member.
		{value: `"a,x"`, notes: "one tag containing a comma, and it is not this one"},
		{value: `"a", "b,x"`, notes: "the same, inside a list"},

		// Malformed lists match nothing, whether or not the tag is in them.
		{value: `*`, notes: "the wildcard is not an entity tag and is handled by the callers"},
		{value: `"x", *`, notes: "so a list containing one is syntactically invalid"},
		{value: `*, "x"`, notes: "and the answer does not depend on where it sits"},
		{value: `"x", ~`, notes: "a member that is not an entity tag fails the whole field"},
		{value: `~, "x"`, notes: "which is the same answer in the other order"},
		{value: `"x" "x"`, notes: "two tags with no comma between them"},
		{value: `"x"junk`, notes: "a tag with a tail"},
		{value: `"unterminated`},
		{value: `"x", "unterminated`},
		{value: `w/"x"`, notes: "the weakness indicator is case-sensitive"},
		{value: `W /"x"`},
		{value: `W/ "x"`},
	} {
		if got := matchesStrong(c.value, tag); got != c.strong {
			t.Errorf("matchesStrong(%q, %s) = %v, want %v %s", c.value, tag, got, c.strong, c.notes)
		}
		if got := matchesWeak(c.value, tag); got != c.weak {
			t.Errorf("matchesWeak(%q, %s) = %v, want %v %s", c.value, tag, got, c.weak, c.notes)
		}
	}
}

// TestMatchesAgainstNoTagIsAlwaysFalse is the representation that has no entity tag, against every
// list that could be sent about it — including the empty entity tag, which is a legal one and is the
// example §8.8.3 of RFC 9110 gives.
//
// A comparison that treated the empty tag as a value would make ETag: "" equivalent to a
// representation with no ETag at all, and an if-match carrying it would succeed against a file the
// server cannot identify.
func TestMatchesAgainstNoTagIsAlwaysFalse(t *testing.T) {
	for _, value := range []string{`""`, `W/""`, `"x"`, `*`, ``, `,`, `"a", ""`} {
		if matchesStrong(value, "") {
			t.Errorf("matchesStrong(%q, no tag) matched", value)
		}
		if matchesWeak(value, "") {
			t.Errorf("matchesWeak(%q, no tag) matched", value)
		}
	}
}

// TestMatchesFindsATagAnywhereInALongList is the loop over a list at the length internal/limits
// allows, which is longer than any client sends and is what a peer would send to find a quadratic.
//
// The tag is last, so every element before it is parsed. What is asserted is the answer; the reason
// to write it at this size is that the scan is a single pass over the value with no allocation in it,
// and a rewrite that lost that property would show up here as a test that stopped finishing.
func TestMatchesFindsATagAnywhereInALongList(t *testing.T) {
	const tag = `"needle"`

	parts := make([]string, 4000)
	for i := range parts {
		parts[i] = `"h` + strconv.Itoa(i) + `"`
	}
	haystack := strings.Join(parts, ", ")

	if matchesStrong(haystack, tag) {
		t.Error("a list without the tag matched")
	}
	if !matchesStrong(haystack+", "+tag, tag) {
		t.Error("a tag at the end of a long list was not found")
	}
	if !matchesStrong(tag+", "+haystack, tag) {
		t.Error("a tag at the start of a long list was not found")
	}

	// And a malformed element anywhere in it still fails the field, which is the case that proves
	// the scan does not stop at the first match.
	if matchesStrong(tag+", "+haystack+", ~", tag) {
		t.Error("a list with a malformed tail matched because the tag was found first")
	}
}

// --- the exchange, end to end -----------------------------------------------

// TestConditionalGetRoundTrip is the exchange this whole file exists to make work, driven the way a
// browser drives it: fetch, keep the tag, ask again with it.
//
// Both validators are taken from the first response and sent back on the second, which is what a
// cache does — §13.1.2 of RFC 9110 has the client send both when it has both — and the 304 that comes
// back carries them again, so the next request can be conditional too.
func TestConditionalGetRoundTrip(t *testing.T) {
	h := newHandler(t, map[string]string{"index.html": page})

	first := serve(t, h, methodGet, "/index.html")
	if first.status() != status200 || first.body != page {
		t.Fatalf("the first response is %s with %d octets", first.status(), len(first.body))
	}

	second := serveCond(t, h, methodGet, "/index.html",
		h2.Field{Name: fieldIfNoneMatch, Value: first.get("etag")},
		h2.Field{Name: fieldIfModifiedSince, Value: first.get("last-modified")})

	if second.status() != status304 {
		t.Fatalf("the conditional GET answered %s, want %s", second.status(), status304)
	}
	if second.body != "" {
		t.Errorf("the 304 carried %d octets", len(second.body))
	}
	if got := second.get("etag"); got != first.get("etag") {
		t.Errorf("the 304 sent etag %s, want the %s the 200 sent", got, first.get("etag"))
	}
	if got := second.get("last-modified"); got != first.get("last-modified") {
		t.Errorf("the 304 sent last-modified %q, want %q", got, first.get("last-modified"))
	}
}

// TestResumeAfterAnInterruptedDownload is the whole point of a strong validator, as the exchange it
// enables: a client that has the first part of a file asks for the rest and names the tag it holds.
//
// §13.1.5 of RFC 9110 is what makes the tag necessary rather than nice: if-range is compared "using
// the strong comparison function", so a server whose only validator was a modification date could
// never satisfy this request and would answer the whole file every time. The last case is that same
// request with a stale tag, which must be the whole file — the peer's partial copy is of a
// representation that no longer exists, and splicing the new tail onto it would corrupt it silently.
func TestResumeAfterAnInterruptedDownload(t *testing.T) {
	body := content(2000)
	h := newHandler(t, map[string]string{"big.bin": body})

	// The interrupted download: the client has the first thousand octets.
	first := serveCond(t, h, methodGet, "/big.bin", h2.Field{Name: "range", Value: "bytes=0-999"})
	if first.status() != status206 {
		t.Fatalf("the first range answered %s, want %s", first.status(), status206)
	}
	tag := first.get("etag")
	if tag != tagOf(body) {
		t.Fatalf("the 206 sent etag %s, want %s", tag, tagOf(body))
	}

	// The resume, guarded by the tag it was given.
	rest := serveCond(t, h, methodGet, "/big.bin",
		h2.Field{Name: "range", Value: "bytes=1000-"},
		h2.Field{Name: fieldIfRange, Value: tag})
	if rest.status() != status206 {
		t.Fatalf("the resume answered %s, want %s", rest.status(), status206)
	}
	if got := rest.get("content-range"); got != "bytes 1000-1999/2000" {
		t.Errorf("content-range = %q", got)
	}
	if first.body+rest.body != body {
		t.Errorf("the two parts assemble to %d octets, want %d", len(first.body+rest.body), len(body))
	}

	// The same resume against a tag the file does not have.
	stale := serveCond(t, h, methodGet, "/big.bin",
		h2.Field{Name: "range", Value: "bytes=1000-"},
		h2.Field{Name: fieldIfRange, Value: anEntityTag})
	if stale.status() != status200 {
		t.Errorf("a resume with a stale tag answered %s, want the whole file at %s",
			stale.status(), status200)
	}
	if stale.body != body {
		t.Errorf("it sent %d octets, want the whole %d", len(stale.body), len(body))
	}

	// And against the server's own tag, weakened. §13.1.5 takes the strong comparison function, so
	// this is a false condition and not a match — a weak validator promises equivalence, and
	// splicing octets together needs identity.
	weak := serveCond(t, h, methodGet, "/big.bin",
		h2.Field{Name: "range", Value: "bytes=1000-"},
		h2.Field{Name: fieldIfRange, Value: weakPrefix + tag})
	if weak.status() != status200 {
		t.Errorf("a resume with the tag weakened answered %s, want %s", weak.status(), status200)
	}
}

// TestLostUpdateIsRefused is if-match doing the job §13.1.1 of RFC 9110 describes, against a file
// that changed under the client.
//
// A strong tag is what makes this answerable at all: the client names the exact representation it
// read, and a server comparing modification dates could only say whether the file was older than
// some second. The 412 is the answer §15.5.13 of RFC 9110 defines and the whole of what this server
// does with the field — there is no state here to guard, which is why the test is about the refusal
// rather than about an update.
func TestLostUpdateIsRefused(t *testing.T) {
	h := newHandler(t, map[string]string{"a.txt": "the content the client read\n"})

	tag := serve(t, h, methodGet, "/a.txt").get("etag")

	for _, c := range []struct {
		name   string
		value  string
		status string
	}{
		{"the tag the client holds", tag, status200},
		{"a wildcard, since a representation exists", "*", status200},
		{"a list containing the tag", anEntityTag + ", " + tag, status200},
		{"a tag from a representation that is gone", anEntityTag, status412},
		{"the right tag, weakened", weakPrefix + tag, status412},
		{"a list this server cannot parse", tag + ", ~", status412},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := serveCond(t, h, methodGet, "/a.txt", h2.Field{Name: fieldIfMatch, Value: c.value})
			if a.status() != c.status {
				t.Errorf("if-match: %s answered %s, want %s", c.value, a.status(), c.status)
			}
		})
	}
}

// TestEtagIsNotEchoedFromTheRequest is the field being the server's own answer rather than the
// peer's value repeated back.
//
// A handler that filled the ETag of a 304 from the If-None-Match it matched would look correct for
// every well-behaved client and would hand an attacker a field value of their choosing on a response
// every cache stores. internal/response holds every field line to §8.2.1 of RFC 9113 on the way out,
// so the injection would be refused rather than sent — but the field would still be wrong, and this
// asserts that it is computed.
func TestEtagIsNotEchoedFromTheRequest(t *testing.T) {
	h := newHandler(t, map[string]string{"index.html": page})

	// A wildcard, so the 304 is reached without the peer naming a tag at all.
	a := serveCond(t, h, methodGet, "/index.html", h2.Field{Name: fieldIfNoneMatch, Value: "*"})
	if a.status() != status304 {
		t.Fatalf("answered %s, want %s", a.status(), status304)
	}
	if got := a.get("etag"); got != pageTag {
		t.Errorf("the 304 sent etag %s, want the file's own %s", got, pageTag)
	}

	// And a list with the file's tag among values that are not it: the field is still the file's.
	b := serveCond(t, h, methodGet, "/index.html",
		h2.Field{Name: fieldIfNoneMatch, Value: `"a", ` + pageTag + `, "b"`})
	if b.status() != status304 {
		t.Fatalf("answered %s, want %s", b.status(), status304)
	}
	if got := b.get("etag"); got != pageTag {
		t.Errorf("the 304 sent etag %s, want %s", got, pageTag)
	}
}

// TestEtagUnderConcurrentRequestsIsOneAnswer is the handler's own concurrency, rather than the
// cache's: many goroutines serving one file through one Handler, each with its own writer, and one
// tag on all of them.
//
// The cache is the only mutable state a request in this package can see another request's writes to,
// so this is where a data race would be. Run under -race by the gate script, where a missing lock is
// a failure rather than a flake.
func TestEtagUnderConcurrentRequestsIsOneAnswer(t *testing.T) {
	h := newHandler(t, map[string]string{"index.html": page, "a.bin": content(4000)})

	var wg sync.WaitGroup
	for range 32 {
		for _, target := range []string{"/index.html", "/a.bin"} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				a := serve(t, h, methodGet, target)
				if got, want := a.get("etag"), tagOf(a.body); got != want {
					t.Errorf("GET %s sent etag %s, want %s", target, got, want)
				}
			}()
		}
	}
	wg.Wait()
}

// --- the hash itself --------------------------------------------------------

// TestHashContentReportsAReadFailure is the error path of the hash, which the handler turns into no
// field at all.
//
// A reader that fails part way through, so that the digest has already absorbed octets when the
// error arrives: the result must be no tag rather than the hash of the prefix. A tag over half a
// file would be a strong validator for a representation that does not exist, and two different
// files truncated at the same point would share it.
func TestHashContentReportsAReadFailure(t *testing.T) {
	boom := errors.New("the disk went away")
	r := io.MultiReader(strings.NewReader("the first half"), failingReader{boom})

	got, err := hashContent(r, make([]byte, 8))
	if !errors.Is(err, boom) {
		t.Errorf("hashContent returned %v, want the reader's error", err)
	}
	if got != "" {
		t.Errorf("hashContent returned the tag %q alongside an error", got)
	}
}

// failingReader is a reader that has nothing but an error.
type failingReader struct{ err error }

func (f failingReader) Read([]byte) (int, error) { return 0, f.err }

// TestHashContentIsIndependentOfTheBufferSize is the pooled buffer not being part of the answer.
//
// io.CopyBuffer reads in buffer-sized pieces, so a hash that folded the piece boundaries into the
// digest — by hashing each read separately, or by writing a length prefix — would give a different
// answer for a different buffer. The buffer this package uses comes from a sync.Pool and its size is
// a tuning decision, so the tag must not depend on it.
func TestHashContentIsIndependentOfTheBufferSize(t *testing.T) {
	body := content(1000)

	want := tagOf(body)
	for _, size := range []int{1, 2, 3, 7, 64, 999, 1000, 1001, 1 << 16} {
		got, err := hashContent(strings.NewReader(body), make([]byte, size))
		if err != nil {
			t.Fatalf("a %d-octet buffer: %v", size, err)
		}
		if got != want {
			t.Errorf("a %d-octet buffer gave %s, want %s", size, got, want)
		}
	}
}
