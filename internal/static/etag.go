package static

import (
	"crypto/sha256"
	"encoding/base64"
	"io"
	"io/fs"
	"os"
	"strings"
	"sync"
	"time"
)

// weakPrefix is the weakness indicator of §8.8.3 of RFC 9110's entity-tag grammar.
//
// Compared case-sensitively, which the grammar makes explicit twice. Once in the rule itself,
// where the %s sigil means a case-sensitive literal — weak = %s"W/" — and once in the prose that
// requires it, §8.8.3 of RFC 9110: "then the origin server MUST mark the entity tag as weak by
// prefixing its opaque value with W/." So a lowercase w is not a weakness indicator, and a value
// beginning with one is not an entity tag at all: no opaque-tag can start with a w either, since
// §8.8.3 of RFC 9110 says "An entity tag consists of an opaque quoted string, possibly prefixed by
// a weakness indicator." and a quoted string starts with a DQUOTE.
const weakPrefix = "W/"

// maxTagCacheEntries bounds the entity-tag cache.
//
// The cache exists so that the hash of a file is computed once per version of it rather than once
// per request, and a cache with no bound would be a map a peer fills by asking for names: the
// entries are keyed by the resolved name, whose length path.go caps at MaxTargetLength, so an
// unbounded cache is four kilobytes of memory per distinct name a stranger chooses to request.
// Bounded, the whole structure cannot exceed a few megabytes whatever the peer does, and the tree
// being served does not have to be small for that to hold.
//
// A thousand is not tuned, and the number matters less than it looks: the cache is an optimisation
// and never a correctness mechanism, so an entry that is evicted costs one re-read of one file and
// changes no answer. That is also why eviction is arbitrary rather than least-recently-used — see
// tagCache.store.
const maxTagCacheEntries = 1024

// tagSettleWindow is how far in the past a file's modification time must be before the cache will
// trust it to identify one version of that file.
//
// The cache is keyed on the size and the modification time — the same pair etag declines to use as
// the tag itself, and for the same reason: two writes can produce one timestamp. A cache keyed on it
// unconditionally would hand back the hash of the old content for exactly the rewrite the hash was
// chosen to catch, which would make the whole mechanism no stronger than the shortcut it rejects.
//
// So the key is used only once no later write could produce the timestamp already recorded, and that
// is decidable rather than a matter of taste. If the filesystem records to a granularity of G, a
// write at instant T is recorded as the multiple of G at or below T, and a second write can be
// recorded at that same value only if it happens before that multiple plus G. Once the clock has
// passed the recorded time by G, every write that could have collided with it is already over — and
// the read that produced the cached hash came after all of them.
//
// Two seconds because G is not knowable from here and is not small everywhere. NTFS records to a
// hundred nanoseconds and ext4 to the nanosecond, but HFS+ records to the second, some network
// filesystems to the second, and FAT to two of them, which is the coarsest a served directory is
// likely to sit on and therefore the number.
//
// A file whose modification time is inside the window, or ahead of the server's clock, is hashed on
// every request and cached not at all. That is the price of the guarantee, and it is paid by the
// operator rather than by the peer: a deployment that has just written its files re-reads each one
// for two seconds, and a file stamped in the future re-reads for as long as it is stamped that way —
// the same anomaly modTime clamps the last-modified for. No request can change a file's timestamp,
// so neither case is an amplification a peer can reach for.
//
// What no window can cover is a writer that restores the modification time after a rewrite. The
// filesystem has then been told the file did not change, and every validator cheap enough to compute
// without reading the file believes it. A server can read every file on every request or it can take
// the filesystem's word; this takes the word, inside the window where the word is sound, and says so
// here rather than leaving it to be found.
const tagSettleWindow = 2 * time.Second

// tagVersion identifies one version of one file, as cheaply as a filesystem can be asked.
//
// The size and the modification time, at the full resolution the filesystem keeps rather than the
// second an HTTP-date has: this value decides when a cached hash is stale, so every bit of change
// detection available is worth having here. modTime truncates for the field it sends and this does
// not, and the two are deliberately different numbers for different jobs.
//
// The pair is not enough on its own — a timestamp a second write could still be given identifies
// nothing — which is what tagSettleWindow is about and where the argument for this type being a
// sound cache key lives.
//
// The seconds and the nanoseconds separately rather than a single UnixNano, because UnixNano is
// documented as undefined outside 1678 to 2262 and a file can be stamped with anything. Two fields
// are exact for every instant a filesystem can report, and a struct of comparable fields is a map
// key without a string being built for it.
//
// Not the inode or the device. os.Root gives every open a path relative to one directory handle, so
// a name identifies a file for as long as the handler lives; and fs.FileInfo does not carry either
// number portably, which is the reason that matters.
type tagVersion struct {
	size int64
	sec  int64
	nsec int
}

// versionOf is info's identity as the cache understands it.
func versionOf(info fs.FileInfo) tagVersion {
	mod := info.ModTime()
	return tagVersion{size: info.Size(), sec: mod.Unix(), nsec: mod.Nanosecond()}
}

// tagEntry is a computed entity tag and the version of the file it was computed from.
type tagEntry struct {
	version tagVersion
	tag     string
}

// tagCall is one hash in progress, and the mechanism by which it is only ever one.
//
// A hash is a full read of a file, so two requests that arrive together for the same cold file
// would otherwise read it twice — and a hundred would read it a hundred times, which is a hundred
// times the work for one answer and the shape of an amplification a peer chooses. The channel is
// closed when the read is over; whoever finds a call already in the map waits on it and takes its
// result instead of starting a second read.
//
// tag and err are written by the goroutine that owns the call, before the channel is closed, and
// read by the others only after they have received from it. The close is the synchronisation, so
// there is no lock on these two fields and no race for the detector to find.
type tagCall struct {
	done chan struct{}
	tag  string
	err  error
}

// tagCallKey names one in-progress hash: the file, and which version of it.
//
// The version is in the key so that a waiter cannot be handed the answer to a different question.
// Two requests joined on this key are asking about the same name at the same size and the same
// modification time, which is the whole of what a hash is a function of.
type tagCallKey struct {
	name    string
	version tagVersion
}

// tagCache remembers the entity tag of each file it has hashed.
//
// Safe for concurrent use, and it has to be: a handler is shared by every connection, and the
// responses that reach it run on one goroutine per stream. Everything else in this package is
// either immutable after New or a sync.Pool, so this is the only mutable state a request can see
// another request's writes to.
//
// The lock is never held across the hash. It is taken to look an entry up, released for as long as
// the file is being read, and taken again to file the result — which is the only arrangement that
// keeps a slow read on one connection from stopping every other connection's requests.
type tagCache struct {
	mu      sync.Mutex
	entries map[string]tagEntry
	calls   map[tagCallKey]*tagCall

	// limit is maxTagCacheEntries, held as a field so that a test can fill the cache without
	// creating a thousand files. store honours any value of it, including none.
	limit int
}

// newTagCache is an empty cache holding at most limit entries.
func newTagCache(limit int) *tagCache {
	return &tagCache{
		entries: make(map[string]tagEntry),
		calls:   make(map[tagCallKey]*tagCall),
		limit:   limit,
	}
}

// get is the entity tag of the named file at version v, computing it with hash if it is not already
// known.
//
// hash is called at most once for any (name, version) pair that is asked about concurrently, and
// not at all when the answer is already in hand.
func (c *tagCache) get(name string, v tagVersion, hash func() (string, error)) (string, error) {
	key := tagCallKey{name: name, version: v}

	c.mu.Lock()
	if e, ok := c.entries[name]; ok && e.version == v {
		c.mu.Unlock()
		return e.tag, nil
	}
	if call, ok := c.calls[key]; ok {
		c.mu.Unlock()
		<-call.done
		return call.tag, call.err
	}
	call := &tagCall{done: make(chan struct{})}
	c.calls[key] = call
	c.mu.Unlock()

	// Deferred rather than written out after the call, so that a panic in hash cannot leave the
	// channel unclosed. An unclosed channel here is worse than the panic that caused it: every
	// request that joined the call would wait on it for as long as the process lived, which is a
	// deadlock on a connection's reader goroutine rather than one failed response. Recovering is
	// not this function's business — the empty tag the waiters then read is the same "no validator"
	// every other failure produces, and the panic goes on up.
	defer func() {
		c.mu.Lock()
		delete(c.calls, key)
		if call.err == nil && call.tag != "" {
			c.store(name, tagEntry{version: v, tag: call.tag})
		}
		c.mu.Unlock()
		close(call.done)
	}()

	call.tag, call.err = hash()
	return call.tag, call.err
}

// store files e under name, evicting to stay inside the limit. The lock is held.
//
// Eviction takes whichever entry the map's iteration order offers first, which in Go is not the
// insertion order and not the same order twice. That is a deliberate choice of the cheapest policy
// rather than the best one, and it is available because of what the cache is: every entry can be
// recomputed from the file it names, so evicting the wrong one costs one read and cannot produce a
// wrong answer. A least-recently-used policy would need a list threaded through every entry and a
// write on every hit — a lock held longer on the common path, to save a read on the rare one.
//
// The limit is honoured exactly, which takes the first of the three branches below. A cache with no
// room stores nothing at all: evicting until the map is empty and then inserting would leave one
// entry behind, so the bound would be off by one for every limit and the degenerate case would hold
// an entry it had just been told it could not have. Replacing an entry under a name already present
// changes nothing about the size and so needs no eviction, which is also the common case for a file
// that has been rewritten. Only a new name evicts, and the loop cannot spin: each pass removes one
// entry, and with a limit of at least one the condition fails by the time the map is empty.
func (c *tagCache) store(name string, e tagEntry) {
	if c.limit <= 0 {
		return
	}
	if _, replacing := c.entries[name]; !replacing {
		for len(c.entries) >= c.limit {
			for k := range c.entries {
				delete(c.entries, k)
				break
			}
		}
	}
	c.entries[name] = e
}

// etag is the entity tag of the open file f, or the empty string if there is none to be had.
//
// # Why there is one at all, and why it is a hash
//
// §8.8.3.1 of RFC 9110 asks for it: "An origin server SHOULD send an ETag for any selected
// representation for which detection of changes can be reasonably and consistently determined". A
// file is such a representation, and the field is worth more here than anywhere else, because it is
// the only validator this server has that §8.8.1 of RFC 9110's definition of a strong one survives:
// "A strong validator is unique across all versions of all representations associated with a
// particular resource over time". A modification time is not — modTime explains why at length, and
// the short form is that a file rewritten twice inside one second is two representations with one
// timestamp.
//
// So the tag is a hash of the content, which is the alternative that section offers by name. §8.8.1
// of RFC 9110: "A collision-resistant hash function applied to the representation data is also
// sufficient if the data is available prior to the response header fields being sent". The
// field-attribute shortcut is in §8.8.3.1 of RFC 9110's next breath: "Other implementations might
// use a collision-resistant hash of representation content, a combination of various file
// attributes, or a modification timestamp that has sub-second resolution". And it is declined. A
// size with a nanosecond timestamp is cheaper and is not strong: it is a guess that no two writes
// landed in the same tick at the same length, and an origin server that cannot prove that is
// required by §8.8.3 of RFC 9110 to say so, since "An entity tag can be either a weak or
// strong validator, with strong being the default." A weak tag would not satisfy if-range, which is
// the field this whole mechanism exists to make answerable.
//
// # What the read costs, and the bound on it
//
// A hash is a full read of the file, and the first request for a file pays for one. Every request
// after it pays nothing, because the tag is cached against the file's size and modification time,
// so the total cost of serving a tree is one extra read per version of each file in it — the same
// order of work as a peer fetching every file once, which is a thing any peer may do.
//
// Two consequences are worth stating rather than discovered. A HEAD, which used to be a stat, is
// now a read of the file it names on a cold cache: that is the price of §9.3.2's rule that a HEAD
// carries the fields a GET would have, and it is what makes the HEAD-then-conditional-GET exchange
// work at all. And two requests for the same cold file do not read it twice; see tagCall.
//
// # Where the octets come from, and why the offset does not move
//
// The same handle the content will be sent from, through an io.SectionReader, which reads by ReadAt
// and leaves the file offset alone. So hashing does not disturb file or send, neither of which
// seeks, and the tag describes the octets this response is about to write rather than whatever the
// name resolves to a moment later. That is the same guarantee open already gives the size and the
// mode by stat'ing the handle instead of the name, and it fails in the same one way: a file rewritten
// underneath a live handle. errFileChanged is what that looks like from the other end.
//
// # A failure is not an error
//
// A read that fails produces no tag and no error to the caller. An entity tag is metadata a response
// is better with, not a thing a response is about, and a 500 for a file whose content could not be
// hashed would be a worse answer than the file with one field fewer. Every part of this package
// already treats the empty tag as "no validator": conditional.go answers if-match and if-none-match
// from their wildcard forms alone, ifRangeIsFalse cancels the range, and withValidator leaves the
// field out.
//
// # The file the cache will not speak for
//
// A file whose modification time has not settled — see tagSettleWindow — takes neither the cache nor
// the single-flight, and is hashed here and now. Joining an in-flight call would be the same bet the
// cache key is: the other request opened the name at the same size and the same timestamp, which
// inside the window is not yet evidence that it opened the same octets. The cost of declining is a
// re-read per concurrent request for two seconds after a write, and the peer cannot cause a write.
func (h *Handler) etag(name string, f *os.File, info fs.FileInfo, now time.Time) string {
	v := versionOf(info)
	hash := func() (string, error) {
		buf := h.bufs.Get().(*[]byte)
		defer h.bufs.Put(buf)
		return hashContent(io.NewSectionReader(f, 0, v.size), *buf)
	}

	var tag string
	var err error
	if now.Sub(info.ModTime()) < tagSettleWindow {
		tag, err = hash()
	} else {
		tag, err = h.tags.get(name, v, hash)
	}
	if err != nil {
		return ""
	}
	return tag
}

// hashContent is the entity tag for the octets r yields, quoted and ready to be a field value.
//
// SHA-256 truncated to nothing: the whole digest, base64 in the URL alphabet without padding, which
// is forty-three characters of the fifty-seven §8.8.3 of RFC 9110's etagc rule allows — "etagc =
// %x21 / %x23-7E / obs-text" is every visible character but the DQUOTE, and the alphabet used here
// is letters, digits, "-" and "_". No DQUOTE to terminate the string early, and no backslash, which
// a note in the same section asks for: §8.8.3 of RFC 9110, "Servers therefore ought to avoid
// backslash characters in entity tags." because a recipient written against RFC 2616 may still
// unescape them.
//
// The quotes are part of the value this returns, and they stay part of it everywhere: the field is
// sent with them, and matches compares them. An opaque-tag is a quoted string by grammar, so
// comparing the quoted forms is comparing "the opaque-tags" of §8.8.3.2 of RFC 9110 exactly — the
// marks are at the same two places in both operands or one of them was not an entity tag.
//
// buf is the caller's pooled copy buffer, so hashing a file allocates nothing beyond the digest
// state and the string it returns.
func hashContent(r io.Reader, buf []byte) (string, error) {
	sum := sha256.New()
	if _, err := io.CopyBuffer(sum, r, buf); err != nil {
		return "", err
	}
	return `"` + base64.RawURLEncoding.EncodeToString(sum.Sum(nil)) + `"`, nil
}

// splitEntityTag takes one entity-tag off the front of s.
//
// It returns the opaque-tag with its quotation marks, whether a weakness indicator preceded it, what
// is left of s, and whether the front of s was an entity-tag at all. §8.8.3 of RFC 9110's grammar is
// the whole of the rule: "entity-tag = [ weak ] opaque-tag", where the opaque-tag is a DQUOTE, then
// any number of characters that are not a DQUOTE, then a DQUOTE.
//
// # The comma is inside the tag, not a separator
//
// This is why the scan is written out rather than left to strings.Split. A comma is a legal
// character of an opaque-tag — §8.8.3 of RFC 9110's etagc rule is "%x21 / %x23-7E / obs-text",
// which is every visible character except the DQUOTE, and the comma is %x2C — so the field value
// "a,b" is one entity tag containing a comma and not two tags. Splitting on commas first would read
// it as the two invalid fragments "a and b", and a list whose first element is invalid is a list
// that matches nothing. The result would be an if-none-match that quietly failed to match its own
// server's tag for every file whose hash contained a comma, which for a base64 alphabet is never —
// and for a peer echoing back a tag from somewhere else is whenever it feels like it.
//
// There is no escaping to undo. §8.8.3 of RFC 9110 notes that opaque-tag was a quoted-string in RFC
// 2616 and is not one now, so a backslash is an ordinary character of the tag and the first DQUOTE
// after the opening one ends it, whatever precedes it.
func splitEntityTag(s string) (opaque string, weak bool, rest string, ok bool) {
	if after, found := strings.CutPrefix(s, weakPrefix); found {
		weak, s = true, after
	}
	if !strings.HasPrefix(s, `"`) {
		return "", false, "", false
	}
	end := strings.IndexByte(s[1:], '"')
	if end < 0 {
		return "", false, "", false
	}
	return s[:end+2], weak, s[end+2:], true
}

// matchesStrong reports whether the entity-tag list value holds a tag equivalent to tag under the
// Strong comparison of §8.8.3.2 of RFC 9110: "two entity tags are equivalent if both are not weak
// and their opaque-tags match character-by-character."
//
// Which is the comparison if-match is required to use — §13.1.1 of RFC 9110: "An origin server MUST
// use the strong comparison function when comparing entity tags for If-Match" — and the one if-range
// is required to use, per §13.1.5 of RFC 9110's "using the strong comparison function".
//
// Every tag this server generates is strong, so "both are not weak" reduces to the peer's tag not
// being weak. A W/ in a request is therefore a value that cannot match, which is not an error and is
// the entry in §8.8.3.2 of RFC 9110's own table where a weak tag and a strong one with the same
// opaque-tag are "no match" under strong comparison and "match" under weak.
func matchesStrong(value, tag string) bool { return matches(value, tag, false) }

// matchesWeak is the same for the other function of §8.8.3.2 of RFC 9110, Weak comparison: "two
// entity tags are equivalent if their opaque-tags match character-by-character, regardless of either
// or both being tagged as weak."
//
// Which is what if-none-match takes. §13.1.2 of RFC 9110: "A recipient MUST use the weak comparison
// function when comparing entity tags for If-None-Match". The reason the two fields differ is what
// each is for: if-none-match asks whether a cached copy is still good enough to reuse, and a weak
// tag is a promise that it is semantically equivalent, which is enough. if-match asks whether the
// representation being acted on is the exact one, and equivalent is not exact.
func matchesWeak(value, tag string) bool { return matches(value, tag, true) }

// matches is both comparison functions over a list of entity tags, weakOK selecting which.
//
// # The whole list has to parse
//
// A malformed element fails the field rather than being skipped over, and the match is not reported
// early because of it: the scan runs to the end of the value even after it has found its tag. So
// if-match: "x", ~ behaves the same as if-match: ~, "x", which is worth the extra pass — an
// order-dependent answer to a precondition is a difference between two servers that no client can
// see coming, and a client that sends a list this server cannot fully read has not said what it
// means. §13.1.1 of RFC 9110 defines the field over a list of entity tags and gives no reading for
// half of one.
//
// The safe direction for that strictness is not the same for the two fields, and neither is unsafe.
// An unparsable if-match matches nothing, so it is a 412: a client that meant to guard an action
// gets a refusal rather than the action. An unparsable if-none-match matches nothing either, which
// makes the condition true, so it is the file: a client that meant to revalidate a cache entry gets
// a transfer rather than a wrong 304. Both failures cost bytes and neither is a wrong answer.
//
// # Empty elements
//
// Skipped and not counted, which is what every list a recipient parses does — §5.6.1.2 of RFC 9110:
// "A recipient MUST parse and ignore a reasonable number of empty list elements: enough to handle
// common mistakes by senders that merge values, but not so much that they could be used as a
// denial-of-service mechanism." A value of nothing but commas is a list of no tags, which matches
// nothing, and finding that out is one pass over a field whose length internal/limits has already
// bounded. parseRangeSet makes the same argument about the same rule.
//
// # The wildcard is not here
//
// "*" is not an entity tag and does not appear in the grammar of one. §13.1.1 of RFC 9110 makes it
// an alternative to the whole list rather than a member of it, so it is recognised by the callers in
// conditional.go, against the entire field value, and a list with a "*" in it reaches this function
// and matches nothing. Which is the answer that section asks for anyway, since it calls such a value
// one that "is syntactically invalid".
//
// An empty tag matches nothing at all, whatever the list says. That is the no-validator case etag
// describes, and a peer's "" — a legal entity tag, and one §8.8.3 of RFC 9110 gives as an example —
// must not be equivalent to a representation that has no tag.
func matches(value, tag string, weakOK bool) bool {
	if tag == "" {
		return false
	}

	found, rest := false, value
	for {
		rest = strings.TrimLeft(rest, " \t")
		if rest == "" {
			return found
		}
		if rest[0] == ',' {
			rest = rest[1:]
			continue
		}

		opaque, weak, after, ok := splitEntityTag(rest)
		if !ok {
			return false
		}
		if (weakOK || !weak) && opaque == tag {
			found = true
		}

		// What follows an entity-tag is the end of the value or the comma before the next one.
		// Anything else — a second quoted string, a stray character, an unquoted word — is a list
		// this function has not understood, whether or not the tag was already found.
		rest = strings.TrimLeft(after, " \t")
		if rest == "" {
			return found
		}
		if rest[0] != ',' {
			return false
		}
		rest = rest[1:]
	}
}
