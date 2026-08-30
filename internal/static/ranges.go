package static

import (
	"crypto/rand"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"zerodeps/zdh/internal/exchange"
	"zerodeps/zdh/internal/h2"
	"zerodeps/zdh/internal/response"
)

// The two request fields §14 of RFC 9110 defines, and the one this server acts on.
//
// range is honoured. §14.2 of RFC 9110 leaves that to the server — "A server MAY ignore the
// Range header field" — and then says which way to lean. §14.2 of RFC 9110: "origin servers and
// intermediate caches ought to support byte ranges when possible, since they support efficient
// recovery from partially failed transfers and partial retrieval of large representations". A
// file server is the case that paragraph is about. A browser seeking in a video sends one range
// per seek and a download resumed after a dropped connection sends one for the tail, and neither
// costs this server a re-read of the part the peer already has.
//
// if-range is read, and its presence is all that is read: the condition it asks about cannot be
// true here, so the field's effect is to cancel the range. See ifRangeIsFalse.
const (
	fieldRange   = "range"
	fieldIfRange = "if-range"
)

// bytesUnit is the one range unit this server understands, and the one every browser sends.
//
// It is the unit §14.1.2 of RFC 9110 defines, and the name is compared case-insensitively
// because §14.1 of RFC 9110 says it is: "All range unit names are case-insensitive and ought to
// be registered within the HTTP Range Unit Registry". Every other unit — a registered one this
// server has not implemented, or an invented one — takes the branch §14.2 of RFC 9110 requires:
// "An origin server MUST ignore a Range header field that contains a range unit it does not
// understand."
//
// The same string is the accept-ranges value and the leading token of every content-range, so
// there is one constant rather than three literals that have to agree.
const bytesUnit = "bytes"

// multipartByteranges is the content-type of a 206 carrying more than one part, up to its
// boundary.
//
// §15.3.7.2 of RFC 9110 makes both halves a MUST: "the server generating the 206 response MUST
// generate multipart/byteranges content", and in the same sentence, per §15.3.7.2 of RFC 9110: "a
// Content-Type header field containing the multipart/byteranges media type and its required
// boundary parameter". The parameter is appended by the caller because it is generated per
// response; see boundary.
//
// Unquoted, which is the second of §14.6 of RFC 9110's implementation notes: "some existing
// implementations handle a quoted boundary string incorrectly". A boundary drawn from the base32
// alphabet needs no quoting to be a valid parameter value, so declining the permission costs
// nothing.
const multipartByteranges = "multipart/byteranges; boundary="

// crlf ends every line of a multipart body.
//
// The line ending is MIME's and not HTTP/2's — a multipart body is content, and its internal
// structure is [RFC2046]'s. Which is why it appears in this file and nowhere else in this
// program: the framing layer under this package has no lines in it at all.
const crlf = "\r\n"

// maxRanges is how many range-specs one request may ask for before the answer is a 416.
//
// A bound is required rather than prudent. §17.15 of RFC 9110: "Unconstrained multiple range
// requests are susceptible to denial-of-service attacks because the effort required to request
// many overlapping ranges of the same data is tiny compared to the time, memory, and bandwidth
// consumed by attempting to serve the requested data in many parts." The same section says what
// a server should do about it — §17.15 of RFC 9110: "Servers ought to ignore, coalesce, or
// reject egregious range requests, such as requests for more than two overlapping ranges or for
// many small ranges in a single set, particularly when the ranges are requested out of order for
// no apparent reason."
//
// Rejecting, and with the status §15.5.17 of RFC 9110 names for exactly this: a 416 is sent
// "because the client has requested an excessive number of small or overlapping ranges". It is
// also the cheapest of the three answers to send, which is the property that matters when the
// request is an attack rather than a mistake.
//
// # Why sixteen, and what the other bound does
//
// The cost this caps is per-part framing, which §15.3.7.2 of RFC 9110 quantifies: "Since the
// typical overhead between each part of a multipart/byteranges is around 80 bytes, depending on
// the selected representation's media type and the chosen boundary parameter length, it can be
// less efficient to transfer many small disjoint parts than it is to transfer the entire
// selected representation." Sixteen parts is on the order of a kilobyte and a half of framing,
// which no file worth ranging into will notice, and it is well above what a document viewer or a
// media player asks for in one request.
//
// The octets themselves are capped separately and tighter, in evaluateRange: a range-set whose
// satisfiable parts add up to more than the file is answered with the file. So the two bounds
// together say that a range request can cost this server one read of the representation plus a
// kilobyte, whatever it asks for. Neither bound alone says that — the count cap admits sixteen
// copies of the whole file, and the octet cap admits ten thousand one-octet parts.
const maxRanges = 16

// span is one satisfiable byte range: an offset and a last offset, both inclusive.
//
// Inclusive because that is how the wire spells it, and converting to a half-open pair here
// would mean converting back in contentRange. §14.1.2 of RFC 9110: "The first-pos value in a
// bytes int-range gives the offset of the first byte in a range. The last-pos value gives the
// offset of the last byte in the range; that is, the byte positions specified are inclusive."
//
// A span is only ever built by parseRangeSpec, and only from a spec that is both valid and
// satisfiable, so every span in existence lies inside the representation and covers at least one
// octet. length is therefore always positive and contentRange always describes real octets.
type span struct{ first, last int64 }

// length is how many octets the span covers.
func (s span) length() int64 { return s.last - s.first + 1 }

// contentRange is the content-range field value describing this span of a representation of
// size octets.
//
// The range-resp form of §14.4 of RFC 9110's grammar, with the complete-length spelled out
// rather than the asterisk that may stand in for it. §14.4 of RFC 9110: "For byte ranges, a
// sender SHOULD indicate the complete length of the representation from which the range has
// been extracted, unless the complete length is unknown or difficult to determine." It is
// neither here — the size came from the same stat as the content — so the asterisk is never
// sent.
func (s span) contentRange(size int64) string {
	return bytesUnit + " " + strconv.FormatInt(s.first, 10) + "-" +
		strconv.FormatInt(s.last, 10) + "/" + strconv.FormatInt(size, 10)
}

// unsatisfiedRange is the content-range field value of a 416: the size of the representation
// and no range at all.
//
// §15.5.17 of RFC 9110: "A server that generates a 416 response to a byte-range request SHOULD
// generate a Content-Range header field specifying the current length of the selected
// representation". Which is the whole of what the field carries here, per §14.4 of RFC 9110:
// "The complete-length in a 416 response indicates the current length of the selected
// representation." A client that guessed at a file's length and guessed too high learns the real
// one from this, and can ask again without a second wasted round trip.
func unsatisfiedRange(size int64) string {
	return bytesUnit + " */" + strconv.FormatInt(size, 10)
}

// rangeVerdict is what reading a request's range field decided.
type rangeVerdict int

const (
	// rangeIgnore: the response is the one the request would have got with no range field on
	// it at all. Every refusal in this file lands here rather than on an error status, and that
	// is a legitimate answer and not a shortcut. §14.2 of RFC 9110: "A server MAY ignore the
	// Range header field."
	rangeIgnore rangeVerdict = iota

	// rangePartial: the accompanying spans are satisfiable and the response is a 206. §14.2 of
	// RFC 9110: "If all of the preconditions are true, the server supports the Range header
	// field for the target resource, the received Range field-value contains a valid
	// ranges-specifier with a range-unit supported for that target resource, and that
	// ranges-specifier is satisfiable with respect to the selected representation, the server
	// SHOULD send a 206".
	rangePartial

	// rangeNotSatisfiable: the field was understood and cannot be answered, which is a 416.
	// §14.2 of RFC 9110: "the received Range field-value contains a valid ranges-specifier, and
	// either the range-unit is not supported for that target resource or the ranges-specifier
	// is unsatisfiable with respect to the selected representation, the server SHOULD send a
	// 416".
	rangeNotSatisfiable
)

// evaluateRange reads r's range field against a representation of size octets, and reports
// which of the three responses it asks for.
//
// # Where this is called from
//
// After the preconditions, and only where they came out as a 200. §14.2 of RFC 9110: "The Range
// header field is evaluated after evaluating the precondition header fields defined in Section
// 13.1, and only if the result in absence of the Range header field would be a 200". The same
// paragraph draws the consequence this server gets for free by calling in that order — §14.2 of
// RFC 9110: "In other words, Range is ignored when a conditional GET would result in a 304".
// serve returns the 304 and the 412 before reaching here, so there is no second place that rule
// has to be remembered.
//
// # The five reasons a range field is disregarded
//
// Each is a MAY or a MUST, and none of them can send a peer the wrong octets — the worst outcome
// of ignoring a range is a transfer larger than it needed to be, which is exactly what a peer
// that sent no range field would have got.
//
//  1. The method is not GET. §14.2 of RFC 9110: "A server MUST ignore a Range header field
//     received with a request method that is unrecognized or for which range handling is not
//     defined. For this specification, GET is the only method for which range handling is
//     defined." So a HEAD carrying a range gets the field set of the whole file, which is also
//     what §9.3.2's rule about HEAD and GET agreeing requires.
//  2. There is not exactly one range field line. Two lines carrying one name are one
//     comma-separated list by §5.3 of RFC 9110, and a list of two ranges-specifiers is not a
//     ranges-specifier: §14.2 of RFC 9110's grammar makes Range one ranges-specifier, singular,
//     with the unit named once.
//  3. if-range is present. See ifRangeIsFalse.
//  4. The representation is empty. §14.2 of RFC 9110: "A server that supports range requests
//     MAY ignore a Range header field when the selected representation has no content". Taking
//     that permission also disposes of a shape this server could not spell, since one range-spec
//     is satisfiable even against a zero-length representation. §14.1.2 of RFC 9110: "When a
//     selected representation has zero length, the only satisfiable form of range-spec in a GET
//     request is a suffix-range with a non-zero suffix-length" — and §14.4 of RFC 9110's
//     incl-range grammar has no way to describe the nothing that would be sent for it.
//  5. Anything about the ranges-specifier is invalid: the unit, the syntax, an empty range-set,
//     or one range-spec of many. §14.2 of RFC 9110: "A server that supports range requests MAY
//     ignore or reject a Range header field that contains an invalid ranges-specifier". Ignoring
//     rather than rejecting, because the two failures are not the same failure and only one of
//     them is worth a status code: a 416 says the file cannot supply what was asked for, and a
//     malformed value is a request that never said what it was asking for. The file answers both.
//
// # And the two that are answered rather than ignored
//
// A range-set that is understood, valid, and satisfied by nothing is a 416, which is the one case
// where saying so is more useful than sending the file: the content-range on it carries the
// length the peer guessed wrong about. Too many range-specs is the other, and maxRanges says why
// that is a 416 too.
func evaluateRange(r *exchange.Request, size int64) ([]span, rangeVerdict) {
	value, lines := lookup(r.Fields, fieldRange)
	if lines != 1 || r.Method != methodGet || size == 0 || ifRangeIsFalse(r) {
		return nil, rangeIgnore
	}

	// The unit and the range-set, split at the one "=" between them. A value with none is not a
	// ranges-specifier; a value with two has the second inside its range-set, where no range-spec
	// can hold it and parseRangeSpec will refuse it.
	//
	// The unit is compared without trimming, because the grammar has no whitespace on either side
	// of the "=" and none can have arrived: §8.2.1 of RFC 9113 forbids a field value that "MUST
	// NOT start or end with an ASCII whitespace character", and internal/request refuses one that
	// does as malformed before this package sees the request.
	unit, set, found := strings.Cut(value, "=")
	if !found || !strings.EqualFold(unit, bytesUnit) {
		return nil, rangeIgnore
	}

	spans, specs, ok := parseRangeSet(set, size)
	switch {
	case !ok, specs == 0:
		return nil, rangeIgnore
	case specs > maxRanges, len(spans) == 0:
		return nil, rangeNotSatisfiable
	}

	// The octet cap maxRanges describes: a range-set asking for more than the representation
	// holds is answered with the representation, once. Summed rather than compared span by span,
	// because the request that needs this asks for a thousand copies of the same kilobyte and
	// every one of those is individually smaller than the file.
	//
	// Overflow cannot arise. Each span covers at most size octets and there are at most maxRanges
	// of them, and the loop stops at the first total above size — so the running sum never
	// exceeds twice a number that was a file's size.
	total := int64(0)
	for _, s := range spans {
		if total += s.length(); total > size {
			return nil, rangeIgnore
		}
	}
	return spans, rangePartial
}

// ifRangeIsFalse reports whether r carries an if-range field whose condition this server cannot
// satisfy, which is any if-range field at all.
//
// # The condition is false, and it is false for the same reason there is no ETag
//
// §13.1.5 of RFC 9110 gives if-range two forms and this server loses both.
//
// The entity-tag form needs an entity tag to compare against — §13.1.5 of RFC 9110: "If the
// entity-tag validator provided exactly matches the ETag field value for the selected
// representation using the strong comparison function" — and the package comment explains why
// this server has none. Nothing matches a field that is never sent.
//
// The HTTP-date form fails one step earlier, before any comparison happens. §13.1.5 of RFC 9110:
// "If the HTTP-date validator provided is not a strong validator in the sense defined by Section
// 8.8.2.2, the condition is false." And the burden runs the other way round from what a server
// might hope. §8.8.2.2 of RFC 9110: "A Last-Modified time, when used as a validator in a request,
// is implicitly weak unless it is possible to deduce that it is strong". The deduction available
// to an origin server requires, per §8.8.2.2 of RFC 9110, that "That origin server reliably knows
// that the associated representation did not change twice during the second covered by the
// presented validator" — which a server whose representations are files that somebody else is free
// to rewrite cannot know about any second. modTime makes the same argument about the same
// validator from the other end.
//
// # What that costs, and what it does not
//
// §13.1.5 of RFC 9110 is explicit about the outcome: "A recipient of an If-Range header field
// MUST ignore the Range header field if the If-Range condition evaluates to false." So the peer
// gets the whole representation with a 200. That is not a failure — it is the branch if-range
// exists to select, and it is how the same section glosses the field. §13.1.5 of RFC 9110: "if the
// representation is unchanged, send me the part(s) that I am requesting in Range; otherwise, send
// me the entire representation." A client resuming a download of a file this server cannot prove
// is unchanged is sent the file, which is what it asked for in the second half of that sentence.
//
// What it does not cost is seeking. A browser scrubbing through a video sends range with no
// if-range on it, because it is not resuming a partial copy of anything; those requests never
// reach this function's true branch and are answered with a 206.
//
// # Ignored when there is nothing to cancel
//
// This is only consulted when a range field is present, which is a rule and not an optimisation.
// §13.1.5 of RFC 9110: "A server MUST ignore an If-Range header field received in a request that
// does not contain a Range header field." The caller has already established the range field, so
// the ordering inside its condition is what implements this.
//
// The value is not looked at either, and there are two reasons not to. The field's two forms are
// distinguished by inspection — §13.1.5 of RFC 9110: "A valid entity-tag can be distinguished from
// a valid HTTP-date by examining the first three characters for a DQUOTE" — and this server would
// be doing that in order to reach the same answer down both branches. A parser whose output
// cannot change an outcome is a parser that can only be wrong.
func ifRangeIsFalse(r *exchange.Request) bool {
	_, lines := lookup(r.Fields, fieldIfRange)
	return lines > 0
}

// parseRangeSet reads a range-set, returning the spans of the satisfiable range-specs in it, how
// many range-specs it held, and whether all of them were valid.
//
// The count is separate from the spans because the two answer different questions. A whole
// specifier is unsatisfiable only when every spec in it is — §14.1.1 of RFC 9110: "A valid
// ranges-specifier is satisfiable if it contains at least one range-spec that is satisfiable" —
// so a set of three where one is satisfiable is a 206 with one part, and a set of three where
// none is is a 416. A caller holding only the spans could not tell the second from an empty set.
//
// An invalid spec fails the whole set rather than being skipped, which is §14.1.1 of RFC 9110's
// own rule: "A ranges-specifier is invalid if it contains any range-spec that is invalid or
// undefined for the indicated range-unit."
//
// # Empty elements, and the comma that is not a range
//
// A range-set is a list, so it inherits the requirement §5.6.1.2 of RFC 9110 puts on every list
// a recipient parses. §5.6.1.2 of RFC 9110: "A recipient MUST parse and ignore a reasonable
// number of empty list elements: enough to handle common mistakes by senders that merge values,
// but not so much that they could be used as a denial-of-service mechanism." Skipping them
// satisfies the first half. The second half is satisfied by not counting them — §5.6.1.2 of RFC
// 9110: "Empty elements do not contribute to the count of elements present." — so a value that is
// ten thousand commas is a range-set of nothing, which is not a valid ranges-specifier, and the
// work spent finding that out is one pass over a field value whose length internal/limits has
// already bounded.
//
// Which leaves the case where the count itself is the attack, and that is what stops the loop:
// once a set holds one spec more than maxRanges permits, nothing about the specs after it can
// change the answer, so they are not parsed at all.
func parseRangeSet(set string, size int64) ([]span, int, bool) {
	var spans []span
	specs := 0

	for set != "" {
		var spec string
		spec, set, _ = strings.Cut(set, ",")

		// §5.6.3 of RFC 9110: "OWS and RWS have the same semantics as a single SP. Any content
		// known to be defined as OWS or RWS MAY be replaced with a single SP before interpreting
		// it or forwarding the message downstream." Removed rather than replaced, because a
		// range-spec has no room for a space anywhere inside it — parsePos refuses one — and a
		// list element surrounded by OWS is the element.
		//
		// The leading OWS of the first element is trimmed too, which the list grammar does not
		// strictly put there: §5.6.1 of RFC 9110 attaches OWS to the comma, so the whitespace in
		// the specifier §14.1.2 of RFC 9110 prints for the first, middle and last 1000 bytes —
		// bytes= 0-999, 4500-5499, -1000 — is not in the grammar it is an example of. It is in
		// the RFC, so it is in the wild, and refusing it would cost a peer the transfer it asked
		// for in order to enforce a distinction between two spellings of one request.
		if spec = strings.Trim(spec, " \t"); spec == "" {
			continue
		}

		if specs++; specs > maxRanges {
			return nil, specs, true
		}

		s, satisfiable, ok := parseRangeSpec(spec, size)
		if !ok {
			return nil, specs, false
		}
		if satisfiable {
			spans = append(spans, s)
		}
	}
	return spans, specs, true
}

// parseRangeSpec reads one range-spec against a representation of size octets. It reports the
// span the spec selects, whether the spec is satisfiable, and whether it is valid at all.
//
// Three outcomes rather than two, because §14.1.1 of RFC 9110 keeps them apart and so does the
// response: an invalid spec voids the whole field and the peer gets the file, an unsatisfiable
// one is skipped and may still leave a 206 to send, and a satisfiable one is a part.
// Satisfiability is a question about the representation and validity is not — bytes=9-5 is
// invalid against every file there has ever been, and bytes=5000- is a perfectly good spec that
// this particular file happens to be too short for.
//
// # The order the two questions are asked in
//
// Validity first, always, and the difference shows in what a peer is told. bytes=9-5 against a
// three-octet file is invalid, so the field is ignored and the answer is the file; if
// satisfiability were tested first it would be unsatisfiable, and the answer would be a 416 for
// a request whose real problem was that it was malformed.
//
// # Spans are neither reordered nor merged
//
// §15.3.7.2 of RFC 9110 permits both — "a server MAY coalesce any of the ranges that overlap, or
// that are separated by a gap that is smaller than the overhead of sending multiple parts" — and
// this server does neither, so the parts of a 206 are the specs of the request in the order they
// arrived. Which is what §15.3.7.2 of RFC 9110 asks for: "A server that generates a multipart
// response SHOULD send the parts in the same order that the corresponding range-spec appeared in
// the received Range header field, excluding those ranges that were deemed unsatisfiable or that
// were coalesced into other ranges."
//
// Out-of-order is not treated as suspicious, because a client may well mean it. §14.2 of RFC 9110
// says that a user agent "might need to request later parts first, particularly if the
// representation consists of pages stored in reverse order and the user agent wishes to transfer
// one page at a time." Coalescing would also mean answering with ranges nobody asked for, which
// is not a thing to do to a peer for the sake of saving eighty octets.
func parseRangeSpec(spec string, size int64) (span, bool, bool) {
	// A suffix-range, which is the only range-spec that begins with the separator. §14.1.2 of
	// RFC 9110: "A suffix-range is a range expressed as a suffix of the representation data with
	// the provided non-negative integer maximum length".
	if length, ok := strings.CutPrefix(spec, "-"); ok {
		n, ok := parsePos(length)
		if !ok {
			return span{}, false, false
		}

		// §14.1.2 of RFC 9110's second satisfiability clause: "a suffix-range with a non-zero
		// suffix-length". A suffix of nothing is valid syntax that selects no octets, so it is
		// skipped rather than refused — and a set that is nothing but bytes=-0 has no satisfiable
		// spec in it, which is a 416.
		if n == 0 {
			return span{}, false, true
		}

		// §14.1.2 of RFC 9110: "If the selected representation is shorter than the specified
		// suffix-length, the entire representation is used." A peer asking for the last megabyte
		// of a hundred-octet file is asking for the file, and gets it as a 206 rather than as a
		// refusal.
		if n >= size {
			return span{0, size - 1}, true, true
		}
		return span{size - n, size - 1}, true, true
	}

	// An int-range, whose last-pos is optional.
	from, to, found := strings.Cut(spec, "-")
	if !found {
		return span{}, false, false
	}
	first, ok := parsePos(from)
	if !ok {
		return span{}, false, false
	}

	// An absent last-pos is the largest one, which makes it the same code path as a last-pos past
	// the end of the file — and §14.1.2 of RFC 9110 makes them the same rule: "If the last-pos
	// value is absent, or if the value is greater than or equal to the current length of the
	// representation data, the byte range is interpreted as the remainder of the representation".
	// The clamp below is where both become the remainder.
	last := int64(math.MaxInt64)
	if to != "" {
		if last, ok = parsePos(to); !ok {
			return span{}, false, false
		}

		// §14.1.1 of RFC 9110: "An int-range is invalid if the last-pos value is present and
		// less than the first-pos." Present is the condition for being inside this branch; the
		// absent case cannot be invalid, since MaxInt64 is below no first-pos.
		if last < first {
			return span{}, false, false
		}
	}

	// §14.1.2 of RFC 9110's first satisfiability clause: "an int-range with a first-pos that is
	// less than the current length of the selected representation". Asked after the validity
	// check and before the clamp, so that a spec starting past the end is skipped rather than
	// turned into a span that ends before it begins.
	if first >= size {
		return span{}, false, true
	}
	return span{first, min(last, size-1)}, true, true
}

// parsePos reads a first-pos, a last-pos or a suffix-length: one or more decimal digits, and
// nothing else at all.
//
// # Digits, checked here rather than left to strconv
//
// The grammar is 1*DIGIT in all three of §14.1.1 of RFC 9110's productions, and ParseInt is
// looser than that: it takes a leading sign, so bytes=+5-+9 would parse, and a sign is not a
// digit. The scan is also what makes the error handling below honest — after it, the only thing
// that can be wrong with the value is its magnitude.
//
// Refusing a space is part of the same rule. Whitespace inside a range-spec is not OWS, which
// §5.6.1 of RFC 9110 attaches to the comma between list elements and nowhere else, so 0 - 5 is
// three things where the grammar has room for one. parseRangeSet has already removed the
// whitespace that is allowed to be there.
//
// # An overflowing numeral is a large number, not a syntax error
//
// §14.1.2 of RFC 9110: "Since there is no predefined limit to the length of content, recipients
// MUST anticipate potentially large decimal numerals and prevent parsing errors due to integer
// conversion overflows." A ninety-digit first-pos is a well-formed range-spec for a file larger
// than any that exists, so it is read as the largest number this server can hold and it flows
// through the satisfiability rules as itself: a first-pos of MaxInt64 is past the end of every
// file, so the spec is unsatisfiable; a last-pos of MaxInt64 is clamped to the end of the file,
// exactly as an absent one is; and a suffix-length of MaxInt64 selects the whole file.
//
// Reading it as invalid instead would be the more obvious mistake, and it would be wrong in a way
// a peer can feel. bytes=0-99999999999999999999999 is a client asking for as much of the file as
// there is, and the difference between answering it with the file and answering it with a 206 for
// the whole file is small. But bytes=0-0,-99999999999999999999999 is a client asking for the
// first octet and a very long tail, and treating the second spec as malformed voids the first one
// too.
func parsePos(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}

	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		// The only failure reachable from here. Every octet is a digit and there is at least
		// one, so the value is a non-negative decimal numeral and ParseInt can object to nothing
		// about it except that it does not fit.
		return math.MaxInt64, true
	}
	return n, true
}

// plan is the content of a 206 response, worked out before a single octet of it is sent: the
// literal text that surrounds each part, and the spans of the file that go between them.
//
// lead has one more element than spans: lead[i] precedes the content of spans[i], and the last
// element closes the body. Both are written by send, alternating, which is the reason the type
// exists — the alternative is a writer that computes its own framing as it goes and a length
// computed beside it by a second expression that has to agree with the first. Here the length is
// the sum of what will be written, so a content-length that disagrees with the content is not a
// bug this code can have.
//
// A single-part 206 is a plan too, with two empty strings around one span. Empty writes cost
// nothing and send needs no branch: response.Writer documents that a zero-length write enqueues
// no frame at all, rather than a zero-length DATA frame.
type plan struct {
	lead   []string
	spans  []span
	length int64
}

// single is the plan for a 206 carrying one range: the octets, and nothing around them.
//
// One part rather than a multipart body with one part in it, and that is a MUST when the request
// asked for one range — §15.3.7.2 of RFC 9110: "A server MUST NOT generate a multipart response
// to a request for a single range, since a client that does not request multiple parts might not
// support multipart responses." When the request asked for several and only one was satisfiable
// the choice would be free, since §15.3.7.2 of RFC 9110 also allows that "a server MAY generate
// a multipart/byteranges response with only a single body part if multiple ranges were requested
// and only one range was found to be satisfiable" — and it is still made the same way, because
// the shape of a response is better decided by what is in it than by what was asked for.
func single(s span) plan {
	return plan{lead: []string{"", ""}, spans: []span{s}, length: s.length()}
}

// multipart is the plan for a 206 carrying several ranges, as the multipart/byteranges body
// §14.6 of RFC 9110 defines: "The multipart/byteranges media type includes one or more body
// parts, each with its own Content-Type and Content-Range fields. The required boundary
// parameter specifies the boundary string used to separate each body part."
//
// The per-part content-range is a MUST, and it is the field that makes the body readable at all.
// §15.3.7.2 of RFC 9110: "Within the header area of each body part in the multipart content, the
// server MUST generate a Content-Range header field corresponding to the range being enclosed in
// that body part." The per-part content-type is the SHOULD beside it — §15.3.7.2 of RFC 9110:
// "the server SHOULD generate that same Content-Type header field in the header area of each
// body part" — and it is the representation's own type, the one a 200 would have carried, not the
// multipart type of the response around it.
//
// Those two field names are capitalised, which no other field name in this program is. They are
// MIME header fields inside content rather than HTTP/2 field lines, so §8.2 of RFC 9113's rule
// that "Field names MUST be converted to lowercase when constructing an HTTP/2 message" does not
// reach them: they are octets of a body, and internal/response never sees them. Spelled the way
// §14.6 of RFC 9110's own example spells them.
//
// # The body, written out
//
// The delimiter is [RFC2046]'s: two hyphens, the boundary, and a line ending. It opens the body
// with no line ending before it, which §14.6 of RFC 9110 permits either way — "Additional CRLFs
// might precede the first boundary string in the body" — and every later delimiter carries the
// line ending that terminates the part before it. The body ends with the delimiter and two more
// hyphens.
func multipart(spans []span, size int64, kind, boundary string) plan {
	p := plan{lead: make([]string, 0, len(spans)+1), spans: spans}

	for i, s := range spans {
		lead := "--" + boundary + crlf +
			"Content-Type: " + kind + crlf +
			"Content-Range: " + s.contentRange(size) + crlf +
			crlf
		if i > 0 {
			lead = crlf + lead
		}
		p.lead = append(p.lead, lead)
	}
	p.lead = append(p.lead, crlf+"--"+boundary+"--"+crlf)

	for _, lead := range p.lead {
		p.length += int64(len(lead))
	}
	for _, s := range spans {
		p.length += s.length()
	}
	return p
}

// boundary is a fresh multipart delimiter.
//
// Unpredictable rather than absent from the content, and that is the whole of the defence. A
// boundary a peer could guess is a boundary a peer could plant: get a file containing the
// delimiter into the served directory, ask for two ranges of it, and the response parses as more
// parts than it has, with content the server never described. Scanning the file for the string
// instead is the obvious alternative, and it is a second full read of the representation to
// answer a question that 128 bits of randomness answers for free — the odds of a file containing
// a boundary nothing has ever seen before are the odds of guessing it.
//
// crypto/rand.Text is the standard library's answer to exactly this: at least 128 bits, drawn
// from the base32 alphabet, which is letters and digits and so needs neither quoting nor escaping
// to be a parameter value. It cannot fail, because crypto/rand is documented to panic rather than
// return an error, so there is no error path here and no response that has to fall back to
// sending one range because the machine had no entropy.
func boundary() string {
	return rand.Text()
}

// partial sends the spans of f as a 206, single-part or multipart according to how many there
// are.
//
// now is the response's origination date and mod its last-modified, exactly as in file: a 206 is
// a response carrying a representation, so it carries the metadata a 200 would have. That is a
// MUST twice over. §15.3.7 of RFC 9110: "A server that generates a 206 response MUST generate the
// following header fields, in addition to those required in the subsections below" — of which
// this server sends Date and none of the rest on a 200 either. And §15.3.7 of RFC 9110:
// "Otherwise, a sender MUST generate all of the representation header fields that would have been
// sent in a 200", which is the last-modified and the content-type.
//
// The content-length is the plan's and not the file's. §15.3.7 of RFC 9110: "A Content-Length
// header field present in a 206 response indicates the number of octets in the content of this
// message, which is usually not the complete length of the selected representation. Each
// Content-Range header field includes information about the selected representation's complete
// length." So the length describes what is being sent, multipart framing included, and the size
// of the file is carried by the content-range fields instead.
func (h *Handler) partial(w *response.Writer, f *os.File, spans []span, size int64, kind string, now, mod time.Time) error {
	if len(spans) == 1 {
		s := spans[0]

		// §15.3.7.1 of RFC 9110: "If a single part is being transferred, the server generating
		// the 206 response MUST generate a Content-Range header field, describing what range of
		// the selected representation is enclosed, and a content consisting of the range."
		fields := withRanges(withValidator(h.fields(now, status206, kind, s.length()), mod))
		fields = append(fields, h2.Field{Name: "content-range", Value: s.contentRange(size)})
		return h.send(w, f, fields, single(s))
	}

	// No content-range field out here, and that is a prohibition rather than an omission.
	// §15.3.7.2 of RFC 9110: "To avoid confusion with single-part responses, a server MUST NOT
	// generate a Content-Range header field in the HTTP header section of a multiple part
	// response". Each part carries its own; multipart is where.
	edge := boundary()
	p := multipart(spans, size, kind, edge)
	fields := withRanges(withValidator(h.fields(now, status206, multipartByteranges+edge, p.length), mod))
	return h.send(w, f, fields, p)
}

// send writes a header section and then the plan's content: each part's framing, then the octets
// of the file that part describes.
//
// The final comparison is file's, for the same reason and with the same outcome. A file that
// shrank between the stat and the read is sent short, the content-length says otherwise, and
// §8.6 of RFC 9110 makes that a malformed message the peer will complain about — which is the
// truth about what happened. The stream is ended first regardless, because a peer waiting for
// octets that are not coming is worse off than a peer told the response was wrong.
//
// A section reader per span rather than seeks on the shared handle: ReadAt does not move the file
// offset, so the parts are independent of each other and of any other response reading the same
// file through a handle of its own.
func (h *Handler) send(w *response.Writer, f *os.File, fields []h2.Field, p plan) error {
	if err := w.WriteHeader(fields); err != nil {
		return err
	}

	buf := h.bufs.Get().(*[]byte)
	defer h.bufs.Put(buf)

	sent := int64(0)
	for i, s := range p.spans {
		n, err := io.WriteString(w, p.lead[i])
		sent += int64(n)
		if err != nil {
			return err
		}

		m, err := io.CopyBuffer(w, io.NewSectionReader(f, s.first, s.length()), *buf)
		sent += m
		if err != nil {
			return err
		}
	}

	n, err := io.WriteString(w, p.lead[len(p.spans)])
	sent += int64(n)
	if err != nil {
		return err
	}

	if err := w.Close(); err != nil {
		return err
	}
	if sent != p.length {
		return errFileChanged
	}
	return nil
}

// withRanges appends the accept-ranges field to fields.
//
// §14.3 of RFC 9110: "The Accept-Ranges field in a response indicates whether an upstream server
// supports range requests for the target resource." This one does, for every target it serves, so
// the field is on every response that carries a representation — the 200, the 206, and the field
// set of a HEAD, which is the request a client makes in order to find this out before asking for
// a range.
//
// Not on the 304, the 404, the 405, the 412, the 414, the 416 or the redirect. §14.3 of RFC 9110
// calls the field "advice for the sake of improving performance and reducing unnecessary network
// transfers", and a response carrying no representation is not where a peer looks for advice
// about ranging into one. The 416 is the interesting exclusion: a peer that got one has already
// learned that ranges are supported, since an unsupported range field would have produced the
// file.
//
// The value is a single unit, and that is the whole of what this server promises — the field is
// not a guarantee, and §14.3 of RFC 9110 says so: "a client MUST NOT assume that receiving an
// Accept-Ranges field means that future range requests will return partial responses". Which is
// just as well, since a request for too many ranges gets a 416 and one carrying an if-range gets
// the file.
//
// It is also nearly free on the wire: accept-ranges is entry 18 of Appendix A of RFC 7541's
// static table, so the name costs one octet of a field block and only the value is literal.
func withRanges(fields []h2.Field) []h2.Field {
	return append(fields, h2.Field{Name: "accept-ranges", Value: bytesUnit})
}
