package static

import (
	"io/fs"
	"strings"
	"time"

	"zerodeps/zdh/internal/exchange"
	"zerodeps/zdh/internal/h2"
)

// The two obsolete HTTP-date formats. imfFixdate, in static.go, is the third.
//
// All three are parsed and one is generated, which is what §5.6.7 of RFC 9110 asks for on
// each side. Reading, §5.6.7 of RFC 9110: "A recipient that parses a timestamp value in an
// HTTP field MUST accept all three HTTP-date formats." Writing, the same section's rule is
// quoted at imfFixdate — so these two layouts appear nowhere but in the parser below, and no
// response field is ever built from one.
//
// The layouts are Go's spelling of that section's grammar: day-name-l spelled out in full,
// then date2 with its two-digit year, and for asctime the space-padded day of date3 — the one
// field in either obsolete format that is not fixed width. What a Go layout cannot express is
// date2's two-digit year, which Go resolves by a rule that is not the RFC's; see slideCentury.
const (
	rfc850Date  = "Monday, 02-Jan-06 15:04:05 GMT"
	asctimeDate = "Mon Jan _2 15:04:05 2006"
)

// The conditional request fields this handler evaluates. The order that matters is §13.2.2's,
// and it is in evaluate.
//
// Named constants because each is found by an exact comparison against a field name, and that
// comparison is only correct because the names arrive folded — §8.2 of RFC 9113: "Field names
// MUST be converted to lowercase when constructing an HTTP/2 message". internal/request refuses
// a request spelling one of these with a capital as malformed, so nothing reaching here needs a
// case-folding lookup.
const (
	fieldIfMatch           = "if-match"
	fieldIfNoneMatch       = "if-none-match"
	fieldIfModifiedSince   = "if-modified-since"
	fieldIfUnmodifiedSince = "if-unmodified-since"
)

// noContentLength tells fields to leave the content-length field out.
//
// Only a 304 uses it, and the field would have been permitted there. §8.6 of RFC 9110: "A
// server MAY send a Content-Length header field in a 304 (Not Modified) response to a
// conditional GET request" — under a condition this server could meet, since the size of the
// file is in hand. The permission is declined, because §15.4.5 of RFC 9110 argues the other
// way: "a sender SHOULD NOT generate representation metadata other than the above listed fields
// unless said metadata exists for the purpose of guiding cache updates". A length guides no
// cache update. A validator does, which is why last-modified is on a 304 and content-length and
// content-type are not.
const noContentLength = -1

// verdict is what evaluating a request's preconditions decided.
type verdict int

const (
	// verdictSend: no precondition failed, so the response is the one the request would have
	// got without them.
	verdictSend verdict = iota

	// verdictNotModified: a precondition says the peer already has this representation. The
	// status code is the one in §15.4.5 of RFC 9110, which "indicates that a conditional GET
	// or HEAD request has been received and would have resulted in a 200 (OK) response if it
	// were not for the fact that the condition evaluated to false".
	verdictNotModified

	// verdictFailed: a precondition says the representation is not the one the peer was
	// acting on. The status code is the one in §15.5.13 of RFC 9110, which "indicates that one
	// or more conditions given in the request header fields evaluated to false when tested on
	// the server".
	verdictFailed
)

// evaluate applies §13.2.2 of RFC 9110 to r's conditional request fields.
//
// mod is the representation's last modification date as modTime computed it, and the zero time
// means the file has none. now is this response's origination date, the same instant the date
// field carries.
//
// The six steps below are that section's own, in its order, and the order is a MUST — §13.2.2
// of RFC 9110: "A recipient cache or origin server MUST evaluate the request preconditions
// defined by this specification in the following order". The same section says why the order is
// what it is: entity tags before dates because tags are the more accurate validator, and the
// lost-update preconditions before the cache-validating ones because they are the ones a client
// is relying on to refuse.
//
// # Where this is called from, and why not earlier
//
// The section that puts it last says so twice. Once positively, in §13.2.1 of RFC 9110:
// preconditions are evaluated "just before it would process the request content (if any) or
// perform the action associated with the request method". And once as a prohibition, which is
// what decides the shape of serve — §13.2.1 of RFC 9110: "A server MUST ignore all received
// preconditions if its response to the same request without those conditions, prior to
// processing the request content, would have been a status code other than a 2xx (Successful) or
// 412 (Precondition Failed)." So the 404, the 405, the 414 and the directory redirect all take
// precedence over every field read here, and this runs at the one point in serve where a
// representation has actually been selected: an open handle on a regular file.
//
// # The two entity-tag fields, and the two comparison functions
//
// tag is the representation's entity tag as etag computed it, and the empty string means there is
// none — a file whose content could not be hashed. Each field is compared against it by the
// function §13.2.2 of RFC 9110's steps name for it, and the two are not the same function.
//
//   - If-Match takes the strong one. §13.1.1 of RFC 9110: "An origin server MUST use the strong
//     comparison function when comparing entity tags for If-Match". So a W/ tag in an if-match
//     never matches, whatever its opaque-tag says.
//   - If-None-Match takes the weak one. §13.1.2 of RFC 9110: "A recipient MUST use the weak
//     comparison function when comparing entity tags for If-None-Match". So a client holding a
//     weak copy of this representation is told it is still current, which is what a weak validator
//     is for.
//
// matchesStrong and matchesWeak are both, and etag.go argues the difference. The wildcard is
// handled here rather than there, because §13.1.1 of RFC 9110 makes it an alternative to the whole
// list rather than a member of one: If-Match with a value of * asks about existence, and the answer
// is yes. §13.1.1 of RFC 9110: "the condition is true if the origin server has a current
// representation for the target resource", and the caller is holding one open. §13.1.2 of RFC 9110
// inverts both halves: "the condition is false if the origin server has a current representation for
// the target resource" — which for a GET or a HEAD is a 304.
//
// A repeated field line is a failure in both. Two lines carrying one name are a single
// comma-separated list by §5.3 of RFC 9110, and of a list holding the wildcard §13.1.1 of RFC 9110
// says it "is syntactically invalid (therefore not allowed to be generated) and furthermore is
// unlikely to be interoperable". So two if-match lines are not two wildcards, they are one invalid
// value — and an invalid value is neither the wildcard nor a matching tag. Which is why the wildcard
// is recognised on a single line only, and why the comparison is too: a list assembled from two
// lines is a list this server has been given no reading for.
//
// The file with no tag at all still answers both fields, and it answers them the way it did before
// there were any: the wildcard forms work, since they are questions about existence, and every list
// of tags matches nothing. matches returns false for an empty tag for exactly that reason.
func evaluate(r *exchange.Request, tag string, mod, now time.Time) verdict {
	// Step 1 and step 2 are one branch because §13.2.2 of RFC 9110 makes them one: the second
	// is reached only when, per §13.2.2 of RFC 9110, "When recipient is the origin server,
	// If-Match is not present". §13.1.4 of RFC 9110 says it the other way round: "A recipient
	// MUST ignore If-Unmodified-Since if the request contains an If-Match header field".
	if value, lines := lookup(r.Fields, fieldIfMatch); lines > 0 {
		if lines > 1 || (value != "*" && !matchesStrong(value, tag)) {
			return verdictFailed
		}
	} else if date, ok := condDate(r, fieldIfUnmodifiedSince, mod, now); ok && mod.After(date) {
		// §13.1.4 of RFC 9110: "If the selected representation's last modification date is
		// earlier than or equal to the date provided in the field value, the condition is
		// true." So the condition is false exactly when the file is newer than the date, which
		// is what After asks.
		return verdictFailed
	}

	// Step 3, entered on the presence of the field and not on its value. A false condition is a
	// 304 here and never a 412, because §13.1.2 of RFC 9110 splits on the method: "the origin
	// server MUST respond with either a) the 304 (Not Modified) status code if the request
	// method is GET or HEAD or b) the 412 (Precondition Failed) status code for all other
	// request methods". serve has already answered every other method with a 405, so no request
	// can reach a b) branch from here and there is none to write.
	if value, lines := lookup(r.Fields, fieldIfNoneMatch); lines > 0 {
		if lines == 1 && (value == "*" || matchesWeak(value, tag)) {
			return verdictNotModified
		}

		// The condition is true, and step 4 is skipped rather than evaluated. §13.1.3 of RFC
		// 9110: "A recipient MUST ignore If-Modified-Since if the request contains an
		// If-None-Match header field". Returning here is that rule. Falling through to the date
		// would be a server answering a cache-validating request with the less accurate of the
		// two conditions it was given — and worse, one that could contradict the tag it has just
		// compared, since a file restored to an earlier content has an older date and a
		// different tag.
		return verdictSend
	}

	// Step 4. The method is a GET or a HEAD, which serve has already settled, and that is the
	// rest of what §13.2.2 of RFC 9110 requires of this step: "When the method is GET or HEAD,
	// If-None-Match is not present, and If-Modified-Since is present".
	if date, ok := condDate(r, fieldIfModifiedSince, mod, now); ok && !mod.After(date) {
		// §13.1.3 of RFC 9110: "If the selected representation's last modification date is
		// earlier or equal to the date provided in the field value, the condition is false." A
		// false condition here is the ordinary cache hit, and the 304 it produces is what makes
		// conditional requests worth having at all.
		return verdictNotModified
	}

	// Step 5 is the range request, and it is not evaluated here. §13.2.2 of RFC 9110 reaches it
	// only "When the method is GET and both Range and If-Range are present", and both of its
	// outcomes are decisions about the range field rather than about the preconditions — §13.2.2
	// of RFC 9110: "if true and the Range is applicable to the selected representation, respond
	// 206 (Partial Content)". The other outcome, from §13.2.2 of RFC 9110: "otherwise, ignore
	// the Range header field and respond 200 (OK)". So serve makes it after this function has
	// returned verdictSend, by calling evaluateRange, and ifRangeIsFalse is where the condition
	// itself is evaluated. Step 6 is the file.
	return verdictSend
}

// condDate reads the HTTP-date carried by the field named name, reporting whether it is one
// this handler may act on.
//
// Three of the four reasons to disregard such a field are here, and the fourth is the request
// method, which serve has already settled. All four are one sentence — §13.1.3 of RFC 9110: "A
// recipient MUST ignore the If-Modified-Since header field if the received field value is not a
// valid HTTP-date, the field value has more than one member, or if the request method is neither
// GET nor HEAD." Plus a second sentence, for the case a file server meets most often — §13.1.3
// of RFC 9110: "A recipient MUST ignore the If-Modified-Since header field if the resource does
// not have a modification date available."
//
// The count from lookup is what implements the field value having more than one member, and it
// is a count of field lines rather than of commas because §5.3 of RFC 9110 makes those the same
// thing: two lines with one name are one list. If-Unmodified-Since is held to the identical
// rule, which §13.1.4 of RFC 9110 puts in a parenthesis: "A recipient MUST ignore the
// If-Unmodified-Since header field if the received field value is not a valid HTTP-date
// (including when the field value appears to be a list of dates)."
//
// Ignoring is the safe failure in all of them: the request is answered as though it had carried
// no condition at all, which costs a transfer and cannot produce a wrong 304.
func condDate(r *exchange.Request, name string, mod, now time.Time) (time.Time, bool) {
	if mod.IsZero() {
		return time.Time{}, false
	}
	value, lines := lookup(r.Fields, name)
	if lines != 1 {
		return time.Time{}, false
	}
	return parseHTTPDate(value, now)
}

// lookup is the value of the field named name and how many lines carried it.
//
// The count is the point. A single line is the only shape any of the four conditional fields is
// defined for here, and the value returned is the last of them, so that a caller which ignored
// the count could not quietly act on the first of several.
func lookup(fields []h2.Field, name string) (string, int) {
	value, lines := "", 0
	for _, f := range fields {
		if f.Name == name {
			value, lines = f.Value, lines+1
		}
	}
	return value, lines
}

// modTime is the last modification date of the representation info describes, in the one form
// this handler both sends and compares against.
//
// The zero time means there is none, which is the case described in §13.1.3 of RFC 9110 as when
// "the resource does not have a modification date available". It is why nothing here returns an
// error: a filesystem that does not keep the timestamp is not a failure to report to a peer, it
// is a response with no validator in it.
//
// # Truncated to the second, and that is not cosmetic
//
// An HTTP-date has no sub-second field, so the value on the wire is the file's modification time
// with its fraction dropped. Comparing a peer's date against the untruncated time would compare
// it against a value the peer was never shown: a file modified at 08:49:37.5 is sent as
// 08:49:37, the peer echoes 08:49:37 back in if-modified-since, and an untruncated comparison
// finds the file half a second newer than the date it had itself published — so it answers 200,
// and goes on answering 200 for ever. Truncating here, once, is what makes the field and the
// comparison the same number.
//
// The second is also the resolution at which this validator can be trusted at all. A
// Last-Modified time is strong only where, per §8.8.2.2 of RFC 9110, the origin server
// "reliably knows that the associated representation did not change twice during the second
// covered by the presented validator" — and a file rewritten twice inside one second is exactly
// the case a static server cannot rule out. Which is why the comparison below is an ordering
// and never an equality: this validator is the weak one, and it is used the way a weak one may
// be.
//
// # Clamped to the response's own date
//
// A file can be stamped in the future: clock skew on a build machine, an archive unpacked with
// the timestamps it carried, a directory something else is still writing into. §8.8.2.1 of RFC
// 9110 is a MUST about exactly that: "An origin server with a clock (as defined in Section
// 5.6.7) MUST NOT generate a Last-Modified date that is later than the server's time of message
// origination". The same paragraph says what to do instead, and it is not to drop the field —
// §8.8.2.1 of RFC 9110: "then the origin server MUST replace that value with the message
// origination date."
//
// The clamp is also what keeps the comparison sane. A validator ahead of the server's own clock
// makes every if-modified-since false, which turns a future timestamp into an unconditional
// transfer of the file for as long as it stays in the future.
func modTime(info fs.FileInfo, now time.Time) time.Time {
	mod := info.ModTime()
	if mod.IsZero() {
		return time.Time{}
	}

	mod = mod.UTC().Truncate(time.Second)
	if origin := now.Truncate(time.Second); mod.After(origin) {
		return origin
	}
	return mod
}

// parseHTTPDate is an HTTP-date in any of its three formats, as an instant in UTC. It reports
// false for anything that is not one.
//
// now is the server's clock, which the rfc850 format needs and the other two do not. That the
// server's own clock is the right one to resolve it against is the rule in §13.1.3 of RFC 9110:
// "A recipient MUST interpret an If-Modified-Since field value's timestamp in terms of the
// origin server's clock." See slideCentury.
//
// # What Go's parser accepts that the grammar does not describe
//
// §5.6.7 of RFC 9110 asks for three fixed shapes, and then in the same section asks a recipient
// to be forgiving about them. §5.6.7 of RFC 9110: "Recipients of timestamp values are encouraged
// to be robust in parsing timestamps unless otherwise restricted by the field definition."
// time.Parse is forgiving in four ways, each measured rather than assumed, and each inside that
// paragraph:
//
//   - Day and month names are matched without regard to case, though the literal GMT is not. So
//     a value beginning sun, 06 nov 1994 parses and one ending in a lowercase gmt does not,
//     which is a distinction the grammar does not draw. §5.6.7 of RFC 9110: "HTTP-date is case
//     sensitive. Note that Section 4.2 of [CACHING] relaxes this for cache recipients." That
//     relaxation is for caches and this is an origin server, so it is not a licence — but it is
//     which way the specification leans where the two readings meet. Accepting a case-shifted
//     name is accepting a timestamp a stricter parser would have discarded, and discarding one
//     could only produce a 200 where a 304 was correct.
//   - A run of spaces satisfies a single SP in the layout, so the whitespace a sender is
//     forbidden to generate is still understood on the way in. §5.6.7 of RFC 9110: "A sender
//     MUST NOT generate additional whitespace in an HTTP-date beyond that specifically included
//     as SP in the grammar."
//   - A day name that disagrees with the date is accepted, and the date wins. That field's
//     meaning is taken from elsewhere by §5.6.7 of RFC 9110: "The semantics of day-name, day,
//     month, year, and time-of-day are the same as those defined for the Internet Message Format
//     constructs with the corresponding name ([RFC5322], Section 3.3)" — where day-name is not a
//     check on the numbers.
//   - The asctime day may be one digit with a single space before it as well as with two.
//
// It is strict in the ways that matter. Trailing text is refused rather than ignored, so a value
// with an extra octet after its GMT is not a date; and a day, hour, minute or second outside its
// range is refused rather than normalised, so the thirty-first of November is not the first of
// December.
//
// # The one thing it gets wrong for HTTP
//
// A second of 60 is inside the grammar's own stated range, which runs from 00:00:00 to 23:59:60
// to admit the leap second, and time.Parse refuses it as out of range. That is handled here
// rather than worked around at the call site, and it is handled only after every layout has
// failed — which is the property worth stating. A timestamp that parses is never touched by
// leapSecond, so the retry cannot change the meaning of a valid date. Only an invalid one gets a
// second chance.
func parseHTTPDate(s string, now time.Time) (time.Time, bool) {
	if t, ok := parseExact(s, now); ok {
		return t, true
	}

	// The leap second, folded onto the instant that follows it: 23:59:60 is the second before
	// the next day begins and the second after 23:59:59. A peer sending one in an
	// if-modified-since means as of the end of that day, and that is what this is.
	if v, ok := leapSecond(s); ok {
		if t, ok := parseExact(v, now); ok {
			return t.Add(time.Second), true
		}
	}
	return time.Time{}, false
}

// parseExact is the three layouts, tried in the order §5.6.7 of RFC 9110 lists them:
// IMF-fixdate first, because it is the only one a conforming sender generates, and the two
// obsolete formats after it, because a request carrying one is old rather than common.
//
// No layout can accept a value another layout would have taken. The three differ in what
// follows the day name — a comma and a space after three letters, the same after a name spelled
// out in full, or a month where the comma would have been — so an rfc850 date is not a truncated
// IMF-fixdate, and an asctime date is not an rfc850 one with its zone missing.
func parseExact(s string, now time.Time) (time.Time, bool) {
	if t, err := time.Parse(imfFixdate, s); err == nil {
		return t, true
	}
	if t, err := time.Parse(rfc850Date, s); err == nil {
		return slideCentury(t, now)
	}
	if t, err := time.Parse(asctimeDate, s); err == nil {
		// The one layout of the three that names no zone, and the RFC supplies it rather than
		// leaving it to be guessed — §5.6.7 of RFC 9110: "values in the asctime format are
		// assumed to be in UTC". time.Parse returns a zoneless value as UTC, which is the same
		// answer. The other two layouts end in a literal GMT carrying no offset, so they land in
		// UTC as well.
		return t, true
	}
	return time.Time{}, false
}

// slideCentury puts a two-digit rfc850 year in the century the RFC requires, which is not the
// century Go chose.
//
// The rule is a MUST and it is relative to the server's clock — §5.6.7 of RFC 9110: "Recipients
// of a timestamp value in rfc850-date format, which uses a two-digit year, MUST interpret a
// timestamp that appears to be more than 50 years in the future as representing the most recent
// year in the past that had the same last two digits." So the candidate is the year with those
// two digits in the clock's own century, moved back one century if that lands more than fifty
// years out. One subtraction is always enough: the candidate starts within 99 years of the clock
// either way, so anything over the threshold is inside a century of it.
//
// time.Parse resolves the same two digits by a fixed table — 69 through 99 are 1900s, 00 through
// 68 are 2000s — which is a reasonable rule for a general date parser and is not this one. In
// August 2026 the two disagree about eight of the hundred: a two-digit 70 is 1970 to time.Parse
// and 2070 here, because 2070 is forty-four years away and forty-four is not more than fifty.
// Nothing of Go's answer survives the handoff except the month, the day and the time of day.
//
// # The date that exists in one century and not the other
//
// The twenty-ninth of February is why this reports failure at all. time.Parse validated the day
// against the year it guessed, and time.Date normalises rather than refuses — a 29 February
// asked for in a year with 28 of them comes back as 1 March, silently. So the day and the month
// are read back out of the result, and a date that moved is not a date: it is not a valid
// HTTP-date, which is one of the conditions in §13.1.3 of RFC 9110 for ignoring the field
// entirely, and a request asking about 29 February 2100 is asking about a day that will not
// happen.
func slideCentury(t, now time.Time) (time.Time, bool) {
	year := now.Year() - now.Year()%100 + t.Year()%100
	if year-now.Year() > 50 {
		year -= 100
	}

	slid := time.Date(year, t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.UTC)
	if slid.Month() != t.Month() || slid.Day() != t.Day() {
		return time.Time{}, false
	}
	return slid, true
}

// leapSecond rewrites a timestamp whose seconds are 60 to one whose seconds are 59, reporting
// whether it found one. Its caller adds the second back.
//
// The seconds are the two octets after the last colon, which is the same place in all three
// formats: each ends its time-of-day with a colon and two digits, and none of the three has a
// colon anywhere else. Those two octets need not be the end of the value — asctime puts its year
// after them, and the two obsolete formats put a zone.
//
// A value this rejects is one parseExact has already refused, so a false here is nothing but the
// absence of a second chance.
func leapSecond(s string) (string, bool) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 || i+3 > len(s) || s[i+1:i+3] != "60" {
		return "", false
	}
	return s[:i+1] + "59" + s[i+3:], true
}
