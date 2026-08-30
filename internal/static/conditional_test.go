package static

import (
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"zerodeps/zdh/internal/h2"
	"zerodeps/zdh/internal/hpack"
	"zerodeps/zdh/internal/limits"
	"zerodeps/zdh/internal/response"
)

// String names a verdict, so that a failing table reads as a status and not as an integer.
//
// Here rather than in conditional.go because nothing outside a test formats one: the three
// values are consumed by a switch in serve, and a String method in the production file would be
// code that only the tests reach.
func (v verdict) String() string {
	switch v {
	case verdictSend:
		return "send"
	case verdictNotModified:
		return "not-modified"
	case verdictFailed:
		return "failed"
	}
	return "verdict(" + strconv.Itoa(int(v)) + ")"
}

// The dates every table below is built from, all of them relative to fileTime — which is
// what tree stamps every file with, and so what a precondition is compared against.
//
// The two one-second neighbours are the interesting pair. Both comparisons in evaluate are
// orderings with the boundary included on one side, so the second either side of the file's
// own timestamp is where an off-by-one lives: a >= written as > turns every cache hit into a
// transfer, and a > written as >= turns a lost update into a 200.
const (
	oneSecondBefore = "Sat, 04 Jul 2026 11:22:32 GMT"
	oneSecondAfter  = "Sat, 04 Jul 2026 11:22:34 GMT"
	aDayBefore      = "Fri, 03 Jul 2026 11:22:33 GMT"
	aDayAfter       = "Sun, 05 Jul 2026 11:22:33 GMT"
)

// anEntityTag is a syntactically valid entity tag that cannot match anything this server
// sends, because this server sends none. Every If-Match and If-None-Match test below uses it
// rather than a plausible-looking value, so that no reader mistakes a passing test for
// evidence that tags are compared here.
const anEntityTag = `"cafe"`

// stamped is an fs.FileInfo that reports one modification time and nothing else worth
// reading.
//
// modTime is tested through this rather than through a real file because the three cases that
// matter cannot be produced on disk. A sub-second timestamp survives on NTFS and is quietly
// truncated by some filesystems, a future timestamp would have to be written relative to the
// test's own clock rather than the handler's, and a zero one cannot be set at all: os.Chtimes
// reads the zero time as "leave this alone".
type stamped struct{ mod time.Time }

func (s stamped) Name() string       { return "stamped" }
func (s stamped) Size() int64        { return 0 }
func (s stamped) Mode() fs.FileMode  { return 0o644 }
func (s stamped) ModTime() time.Time { return s.mod }
func (s stamped) IsDir() bool        { return false }
func (s stamped) Sys() any           { return nil }

// --- the order of the steps ---------------------------------------------------

// TestEvaluateFollowsSectionOrder is the whole of the precedence this handler implements,
// held to the section that requires it — §13.2.2 of RFC 9110: "A recipient cache or origin
// server MUST evaluate the request preconditions defined by this specification in the
// following order".
//
// The cases that only an ordering can distinguish are the ones with two fields in them. Each
// pair is chosen so that the two conditions disagree: taken alone the second field would
// change the answer, and the right answer is the one the earlier field gives. A handler that
// read its fields in the order the peer happened to send them would pass every single-field
// case here and fail four of these.
func TestEvaluateFollowsSectionOrder(t *testing.T) {
	for _, c := range []struct {
		name  string
		when  []h2.Field
		want  verdict
		notes string
	}{
		{
			name: "nothing",
			want: verdictSend,
		}, {
			name:  "if-match wildcard",
			when:  []h2.Field{{Name: fieldIfMatch, Value: "*"}},
			want:  verdictSend,
			notes: "a representation exists, so the condition is true",
		}, {
			name:  "if-match entity tag",
			when:  []h2.Field{{Name: fieldIfMatch, Value: anEntityTag}},
			want:  verdictFailed,
			notes: "no tag can match a representation that has none",
		}, {
			name:  "if-unmodified-since older than the file",
			when:  []h2.Field{{Name: fieldIfUnmodifiedSince, Value: aDayBefore}},
			want:  verdictFailed,
			notes: "the file changed after the date the peer was acting on",
		}, {
			name: "if-unmodified-since exactly the file",
			when: []h2.Field{{Name: fieldIfUnmodifiedSince, Value: fileTimeField}},
			want: verdictSend,
		}, {
			name: "if-unmodified-since one second before the file",
			when: []h2.Field{{Name: fieldIfUnmodifiedSince, Value: oneSecondBefore}},
			want: verdictFailed,
		}, {
			name: "if-unmodified-since one second after the file",
			when: []h2.Field{{Name: fieldIfUnmodifiedSince, Value: oneSecondAfter}},
			want: verdictSend,
		}, {
			name: "if-none-match wildcard",
			when: []h2.Field{{Name: fieldIfNoneMatch, Value: "*"}},
			want: verdictNotModified,
		}, {
			name:  "if-none-match entity tag",
			when:  []h2.Field{{Name: fieldIfNoneMatch, Value: anEntityTag}},
			want:  verdictSend,
			notes: "no listed tag matches, so the condition is true",
		}, {
			name: "if-modified-since older than the file",
			when: []h2.Field{{Name: fieldIfModifiedSince, Value: aDayBefore}},
			want: verdictSend,
		}, {
			name:  "if-modified-since exactly the file",
			when:  []h2.Field{{Name: fieldIfModifiedSince, Value: fileTimeField}},
			want:  verdictNotModified,
			notes: "the peer echoing back what it was sent is the ordinary cache hit",
		}, {
			name: "if-modified-since one second before the file",
			when: []h2.Field{{Name: fieldIfModifiedSince, Value: oneSecondBefore}},
			want: verdictSend,
		}, {
			name: "if-modified-since one second after the file",
			when: []h2.Field{{Name: fieldIfModifiedSince, Value: oneSecondAfter}},
			want: verdictNotModified,
		}, {
			name: "if-modified-since newer than the file",
			when: []h2.Field{{Name: fieldIfModifiedSince, Value: aDayAfter}},
			want: verdictNotModified,
		},

		// The pairs. Step 1 beats step 2, step 3 beats step 4, and the two halves do not
		// interfere with each other.
		{
			name: "if-match wildcard silences a failing if-unmodified-since",
			when: []h2.Field{
				{Name: fieldIfMatch, Value: "*"},
				{Name: fieldIfUnmodifiedSince, Value: aDayBefore},
			},
			want:  verdictSend,
			notes: "the date alone would be a 412",
		}, {
			name: "a failing if-match is not rescued by a passing if-unmodified-since",
			when: []h2.Field{
				{Name: fieldIfMatch, Value: anEntityTag},
				{Name: fieldIfUnmodifiedSince, Value: aDayAfter},
			},
			want: verdictFailed,
		}, {
			name: "if-none-match silences a passing if-modified-since",
			when: []h2.Field{
				{Name: fieldIfNoneMatch, Value: anEntityTag},
				{Name: fieldIfModifiedSince, Value: fileTimeField},
			},
			want:  verdictSend,
			notes: "the date alone would be a 304",
		}, {
			name: "if-none-match wildcard silences a failing if-modified-since",
			when: []h2.Field{
				{Name: fieldIfNoneMatch, Value: "*"},
				{Name: fieldIfModifiedSince, Value: aDayBefore},
			},
			want:  verdictNotModified,
			notes: "the date alone would be a 200",
		}, {
			name: "the lost-update half runs before the cache half",
			when: []h2.Field{
				{Name: fieldIfUnmodifiedSince, Value: aDayBefore},
				{Name: fieldIfNoneMatch, Value: "*"},
			},
			want:  verdictFailed,
			notes: "a 412 rather than the 304 the second field asks for",
		}, {
			name: "all four at once",
			when: []h2.Field{
				{Name: fieldIfMatch, Value: "*"},
				{Name: fieldIfUnmodifiedSince, Value: aDayBefore},
				{Name: fieldIfNoneMatch, Value: "*"},
				{Name: fieldIfModifiedSince, Value: aDayBefore},
			},
			want:  verdictNotModified,
			notes: "steps 1 and 3 decide it; steps 2 and 4 are never reached",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := reqWith(t, methodGet, "/a.txt", c.when...)
			if got := evaluate(r, fileTime, clock.UTC()); got != c.want {
				t.Errorf("evaluate = %v, want %v %s", got, c.want, c.notes)
			}
		})
	}
}

// TestEvaluateWithoutAValidator is the same order on a file whose modification time the
// filesystem did not keep. Both date conditions are then unanswerable and are ignored, which
// is one of the cases §13.1.3 of RFC 9110 names: "A recipient MUST ignore the If-Modified-Since
// header field if the resource does not have a modification date available."
//
// The two entity-tag fields are unaffected, because neither of them asks about a date. That
// asymmetry is the whole content of this test: a handler that gave up on all four
// preconditions the moment it had no validator would answer 200 to an if-none-match of *, and
// send a representation the peer had just said it already had.
func TestEvaluateWithoutAValidator(t *testing.T) {
	for _, c := range []struct {
		name string
		when []h2.Field
		want verdict
	}{
		{"if-modified-since is ignored", []h2.Field{{Name: fieldIfModifiedSince, Value: aDayAfter}}, verdictSend},
		{"if-unmodified-since is ignored", []h2.Field{{Name: fieldIfUnmodifiedSince, Value: aDayBefore}}, verdictSend},
		{"if-match wildcard still holds", []h2.Field{{Name: fieldIfMatch, Value: "*"}}, verdictSend},
		{"if-match tag still fails", []h2.Field{{Name: fieldIfMatch, Value: anEntityTag}}, verdictFailed},
		{"if-none-match wildcard still holds", []h2.Field{{Name: fieldIfNoneMatch, Value: "*"}}, verdictNotModified},
		{"if-none-match tag still holds", []h2.Field{{Name: fieldIfNoneMatch, Value: anEntityTag}}, verdictSend},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := reqWith(t, methodGet, "/a.txt", c.when...)
			if got := evaluate(r, time.Time{}, clock.UTC()); got != c.want {
				t.Errorf("evaluate against no validator = %v, want %v", got, c.want)
			}
		})
	}
}

// TestEvaluateIgnoresRepeatedFieldLines is two lines carrying one field name, which §5.3 of
// RFC 9110 makes a single comma-separated list rather than two values.
//
// A list is not a shape any of these four fields is defined for here. Two dates are a value
// with more than one member and are ignored; two wildcards are a list containing one, which
// the specification calls out as invalid and not interoperable, so it is neither a wildcard
// nor a matching tag and the condition is false. Ignoring is the safe failure and refusing is
// the safe failure, and each field gets the one its own definition names.
func TestEvaluateIgnoresRepeatedFieldLines(t *testing.T) {
	for _, c := range []struct {
		name string
		when []h2.Field
		want verdict
	}{
		{
			name: "two if-modified-since lines that would each be a 304",
			when: []h2.Field{
				{Name: fieldIfModifiedSince, Value: fileTimeField},
				{Name: fieldIfModifiedSince, Value: aDayAfter},
			},
			want: verdictSend,
		}, {
			name: "two if-unmodified-since lines that would each be a 412",
			when: []h2.Field{
				{Name: fieldIfUnmodifiedSince, Value: aDayBefore},
				{Name: fieldIfUnmodifiedSince, Value: oneSecondBefore},
			},
			want: verdictSend,
		}, {
			name: "two if-match wildcards are not a wildcard",
			when: []h2.Field{
				{Name: fieldIfMatch, Value: "*"},
				{Name: fieldIfMatch, Value: "*"},
			},
			want: verdictFailed,
		}, {
			name: "two if-none-match wildcards are not a wildcard",
			when: []h2.Field{
				{Name: fieldIfNoneMatch, Value: "*"},
				{Name: fieldIfNoneMatch, Value: "*"},
			},
			want: verdictSend,
		}, {
			name: "a repeated if-match still hides if-unmodified-since",
			when: []h2.Field{
				{Name: fieldIfMatch, Value: "*"},
				{Name: fieldIfMatch, Value: "*"},
				{Name: fieldIfUnmodifiedSince, Value: aDayAfter},
			},
			want: verdictFailed,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := reqWith(t, methodGet, "/a.txt", c.when...)
			if got := evaluate(r, fileTime, clock.UTC()); got != c.want {
				t.Errorf("evaluate = %v, want %v", got, c.want)
			}
		})
	}
}

// TestLookupCountsLinesAndTakesTheLast is the helper the three tables above depend on, tested
// directly so that a failure there is not read as a failure of the ordering.
//
// The value returned for a repeated name is the last line rather than the first, which no
// caller in this package uses — every one of them checks the count first. It is deliberate all
// the same: a caller added later that forgot the count would act on the last of several
// values, which is the noisier bug of the two and the one a test notices.
func TestLookupCountsLinesAndTakesTheLast(t *testing.T) {
	fields := []h2.Field{
		{Name: "accept", Value: "*/*"},
		{Name: fieldIfMatch, Value: "first"},
		{Name: "accept-encoding", Value: "gzip"},
		{Name: fieldIfMatch, Value: "second"},
	}

	if value, lines := lookup(fields, fieldIfMatch); value != "second" || lines != 2 {
		t.Errorf("lookup = %q, %d lines; want %q, 2", value, lines, "second")
	}
	if value, lines := lookup(fields, fieldIfNoneMatch); value != "" || lines != 0 {
		t.Errorf("lookup of an absent name = %q, %d lines; want %q, 0", value, lines, "")
	}
	if value, lines := lookup(nil, fieldIfMatch); value != "" || lines != 0 {
		t.Errorf("lookup in no fields = %q, %d lines; want %q, 0", value, lines, "")
	}
}

// TestPreconditionFieldNamesAreTheWireNames is the one thing the three tables above cannot
// assert. Every case in them builds its request from these same four constants, so a name
// spelled wrongly would be spelled wrongly in the request as well and every case would still
// pass — while a real peer's field would then match nothing.
//
// The literals are §13.1 of RFC 9110's four field names, lower-cased, which is not a
// convention: §8.2 of RFC 9113 requires that "field names MUST be converted to lowercase
// when constructing an HTTP/2 message", and a name with a capital in it is one internal/request
// refuses before this package sees it.
func TestPreconditionFieldNamesAreTheWireNames(t *testing.T) {
	for _, c := range []struct{ got, want string }{
		{fieldIfMatch, "if-match"},
		{fieldIfNoneMatch, "if-none-match"},
		{fieldIfModifiedSince, "if-modified-since"},
		{fieldIfUnmodifiedSince, "if-unmodified-since"},
	} {
		if c.got != c.want {
			t.Errorf("the constant is %q, want the wire name %q", c.got, c.want)
		}
	}
}

// --- the date parser ---------------------------------------------------------

// TestParseHTTPDateAcceptsAllThreeFormats is the requirement in §5.6.7 of RFC 9110: "A
// recipient that parses a timestamp value in an HTTP field MUST accept all three HTTP-date
// formats."
//
// One instant, spelled three ways, asserted to be the same instant. The rfc850 spelling is
// the one that needs the clock, and 94 resolves to 1994 under both the rule in slideCentury
// and the fixed table Go would have applied, so this case says nothing about which of the two
// is in use — TestSlideCenturyFollowsTheFiftyYearRule is where that is decided.
func TestParseHTTPDateAcceptsAllThreeFormats(t *testing.T) {
	want := time.Date(1994, time.November, 6, 8, 49, 37, 0, time.UTC)

	for _, s := range []string{
		"Sun, 06 Nov 1994 08:49:37 GMT",
		"Sunday, 06-Nov-94 08:49:37 GMT",
		"Sun Nov  6 08:49:37 1994",
	} {
		got, ok := parseHTTPDate(s, clock)
		if !ok {
			t.Errorf("parseHTTPDate(%q) refused a valid HTTP-date", s)
			continue
		}
		if !got.Equal(want) {
			t.Errorf("parseHTTPDate(%q) = %v, want %v", s, got, want)
		}

		// UTC and not merely equal to it. A value carrying some other zone would compare
		// correctly against the file's modification time and then format wrongly if it were
		// ever sent back out, which is a bug that hides until the day it does not.
		if got.Location() != time.UTC {
			t.Errorf("parseHTTPDate(%q) is in %v, want UTC", s, got.Location())
		}
	}
}

// TestParseHTTPDateRefusesWhatIsNotADate is the strictness half, and every case is one a peer
// can send. A value refused here is a field ignored, and an ignored If-Modified-Since costs a
// transfer; a value wrongly accepted here is a 304 sent against a date the server invented,
// and that is a stale page in a browser with no way to notice.
func TestParseHTTPDateRefusesWhatIsNotADate(t *testing.T) {
	for _, c := range []struct{ value, why string }{
		{"", "empty"},
		{"0", "not a date at all"},
		{"Sun, 06 Nov 1994 08:49:37 gmt", "the zone is a literal and its case is not folded"},
		{"Sun, 06 Nov 1994 08:49:37 UTC", "GMT is the only zone the grammar spells"},
		{"Sun, 06 Nov 1994 08:49:37", "no zone"},
		{"Sun, 6 Nov 1994 08:49:37 GMT", "the day is fixed width in this format"},
		{"Sun, 06 Nov 1994 08:49:37 GMT ", "trailing space"},
		{"Sun, 06 Nov 1994 08:49:37 GMTx", "trailing text"},
		{"xSun, 06 Nov 1994 08:49:37 GMT", "leading text"},
		{"Sun, 31 Nov 1994 08:49:37 GMT", "November has thirty days and this is not the first of December"},
		{"Sun, 00 Nov 1994 08:49:37 GMT", "there is no zeroth"},
		{"Sun, 06 Nov 1994 24:00:00 GMT", "the hour is out of range"},
		{"Sun, 06 Nov 1994 08:60:37 GMT", "the minute is out of range, and only a second may be 60"},
		{"Sun, 06 Nov 1994 08:49:37 GMT, Mon, 07 Nov 1994 08:49:37 GMT", "a list of dates"},
		{"Sunday, 06-Nov-1994 08:49:37 GMT", "the rfc850 year is two digits"},
		{"Sunday, 29-Feb-70 08:49:37 GMT", "1970 had twenty-eight days in February"},
		{"Sun Nov  6 08:49:37 1994 GMT", "asctime names no zone"},
		{"1994-11-06T08:49:37Z", "the wrong specification's timestamp"},
		{"784111777", "seconds since the epoch"},
	} {
		if got, ok := parseHTTPDate(c.value, clock); ok {
			t.Errorf("parseHTTPDate(%q) = %v, want a refusal: %s", c.value, got, c.why)
		}
	}
}

// TestParseHTTPDateIsRobustWhereItSaysItIs is the four documented leniencies, each one
// measured against the running toolchain rather than assumed of it. They are what §5.6.7 of
// RFC 9110 asks for: "Recipients of timestamp values are encouraged to be robust in parsing
// timestamps unless otherwise restricted by the field definition."
//
// This test exists because the leniencies are inherited rather than written. A future
// toolchain that tightened any of them would not break a line of this package's code, and
// this is the only place that would say so.
func TestParseHTTPDateIsRobustWhereItSaysItIs(t *testing.T) {
	want := time.Date(1994, time.November, 6, 8, 49, 37, 0, time.UTC)

	for _, c := range []struct{ value, why string }{
		{"sun, 06 Nov 1994 08:49:37 GMT", "a lower-case day name"},
		{"Sun, 06 nov 1994 08:49:37 GMT", "a lower-case month"},
		{"Sun,  06 Nov 1994 08:49:37 GMT", "whitespace a sender is forbidden to generate"},
		{"Mon, 06 Nov 1994 08:49:37 GMT", "a day name that disagrees with the date"},
		{"Sun Nov 6 08:49:37 1994", "the asctime day with one digit and one space"},
		{"Sun Nov   6 08:49:37 1994", "the asctime day with one digit and three spaces"},
	} {
		got, ok := parseHTTPDate(c.value, clock)
		if !ok {
			t.Errorf("parseHTTPDate(%q) was refused; %s is documented as accepted", c.value, c.why)
			continue
		}
		if !got.Equal(want) {
			t.Errorf("parseHTTPDate(%q) = %v, want %v (%s)", c.value, got, want, c.why)
		}
	}
}

// TestParseHTTPDateTakesTheLeapSecond is the one place the grammar is wider than time.Parse.
// A second of 60 is in range for an HTTP-date and out of range for the standard library, so
// the value is retried with 59 and the second added back — which lands on the instant that
// follows the leap second, in every one of the three formats.
func TestParseHTTPDateTakesTheLeapSecond(t *testing.T) {
	for _, c := range []struct {
		value string
		want  time.Time
	}{
		{"Sun, 06 Nov 1994 08:49:60 GMT", time.Date(1994, time.November, 6, 8, 50, 0, 0, time.UTC)},
		{"Sun, 06 Nov 1994 23:59:60 GMT", time.Date(1994, time.November, 7, 0, 0, 0, 0, time.UTC)},
		{"Sat, 31 Dec 1994 23:59:60 GMT", time.Date(1995, time.January, 1, 0, 0, 0, 0, time.UTC)},
		{"Sunday, 06-Nov-94 08:49:60 GMT", time.Date(1994, time.November, 6, 8, 50, 0, 0, time.UTC)},
		{"Sun Nov  6 08:49:60 1994", time.Date(1994, time.November, 6, 8, 50, 0, 0, time.UTC)},
	} {
		got, ok := parseHTTPDate(c.value, clock)
		if !ok {
			t.Errorf("parseHTTPDate(%q) refused a leap second", c.value)
			continue
		}
		if !got.Equal(c.want) {
			t.Errorf("parseHTTPDate(%q) = %v, want %v", c.value, got, c.want)
		}
	}
}

// TestLeapSecondRetryCannotAlterAValidDate is the property the retry rests on: it runs only
// after every layout has failed, so no timestamp that parses is ever rewritten.
//
// Tested at the level of the rewriter, because that is where the mistake would be. The two
// octets it replaces are the ones after the last colon, and each of the three formats puts
// its seconds there — but an implementation that searched for the first colon would find the
// hour, and one that searched the whole value for 60 would find the minute in 08:60:37 or the
// year in a date from 1960. Every case below is a value with a 60 somewhere other than the
// seconds.
func TestLeapSecondRetryCannotAlterAValidDate(t *testing.T) {
	for _, s := range []string{
		"Sun, 06 Nov 1994 08:49:37 GMT",
		"Sun, 06 Nov 1960 08:49:37 GMT",
		"Sun, 06 Nov 1994 08:60:37 GMT",
		"Sun, 60 Nov 1994 08:49:37 GMT",
		"Sun Nov  6 08:49:37 1960",
	} {
		if got, ok := leapSecond(s); ok {
			t.Errorf("leapSecond(%q) = %q, want no rewrite: the seconds are not 60", s, got)
		}
	}

	// And the shapes that would index out of the value if the bound were wrong. A trailing
	// colon has no two octets after it, and a value ending in a single 6 has one.
	for _, s := range []string{":", "08:", "08:6", "", "60"} {
		if got, ok := leapSecond(s); ok {
			t.Errorf("leapSecond(%q) = %q, want no rewrite", s, got)
		}
	}

	// The one shape it does rewrite, spelled out so that the two-octet replacement is visible:
	// the seconds change and nothing after them moves.
	if got, ok := leapSecond("Sun Nov  6 08:49:60 1994"); !ok || got != "Sun Nov  6 08:49:59 1994" {
		t.Errorf("leapSecond of an asctime leap second = %q, %v", got, ok)
	}
}

// TestSlideCenturyFollowsTheFiftyYearRule is the rule in §5.6.7 of RFC 9110, which is a MUST
// and is relative to the server's clock. §5.6.7 of RFC 9110: "MUST interpret a timestamp that
// appears to be more than 50 years in the future as representing the most recent year in the
// past that had the same last two digits."
//
// The table is written as two-digit years resolved against a clock in August 2026, and the
// eight in the middle are the ones this rule and Go's own disagree about. time.Parse resolves
// 69 through 99 into the 1900s from a fixed table; the rule here resolves 77 through 99 into
// them, because 2077 is fifty-one years away and 2076 is fifty. So a case marked below with
// its Go answer is a case that fails outright if slideCentury is removed, rather than one
// that merely stops being justified.
func TestSlideCenturyFollowsTheFiftyYearRule(t *testing.T) {
	for _, c := range []struct {
		digits string
		want   int
		note   string
	}{
		{"26", 2026, "the clock's own year"},
		{"00", 2000, ""},
		{"68", 2068, ""},
		{"69", 2069, "Go's table says 1969"},
		{"70", 2070, "Go's table says 1970"},
		{"75", 2075, "Go's table says 1975"},
		{"76", 2076, "fifty years away, which is not more than fifty; Go's table says 1976"},
		{"77", 1977, "fifty-one years away"},
		{"99", 1999, ""},
	} {
		value := "Sunday, 06-Nov-" + c.digits + " 08:49:37 GMT"
		got, ok := parseHTTPDate(value, clock)
		if !ok {
			t.Errorf("parseHTTPDate(%q) refused a valid rfc850 date", value)
			continue
		}
		if got.Year() != c.want {
			t.Errorf("parseHTTPDate(%q) is in %d, want %d %s", value, got.Year(), c.want, c.note)
		}
		if got.Month() != time.November || got.Day() != 6 {
			t.Errorf("parseHTTPDate(%q) = %v, which is not the sixth of November", value, got)
		}
	}
}

// TestSlideCenturyRefusesADayThatTheCenturyDoesNotHave is the reason slideCentury reports
// failure at all.
//
// time.Parse validated 29 February against the year it guessed, and time.Date normalises
// rather than refuses — so a day that exists in Go's century and not in the one the rule
// chooses would come back silently as the first of March. The clock is pinned to 2126 to
// produce it: a two-digit 00 is then 2100, which is a century year that is not divisible by
// 400 and so has twenty-eight days in February, while Go had already accepted the value as
// the twenty-ninth of February 2000.
//
// This is the case that cannot be reached from a clock in this decade at all, and it is why
// the guard is not written as a comment saying it cannot happen.
func TestSlideCenturyRefusesADayThatTheCenturyDoesNotHave(t *testing.T) {
	far := time.Date(2126, time.August, 9, 14, 5, 9, 0, time.UTC)

	const value = "Sunday, 29-Feb-00 08:49:37 GMT"
	if got, ok := parseHTTPDate(value, far); ok {
		t.Errorf("parseHTTPDate(%q) against a clock in 2126 = %v, want a refusal: 2100 has no twenty-ninth of February",
			value, got)
	}

	// The same value against this file's clock is a real date, so the refusal above is the
	// century arithmetic and not a parser that has stopped accepting 29 February.
	if _, ok := parseHTTPDate(value, clock); !ok {
		t.Errorf("parseHTTPDate(%q) against the 2026 clock was refused; 2000 was a leap year", value)
	}

	// And a leap day that survives the slide, so that the guard is known to be a guard rather
	// than a refusal of every 29 February: a two-digit 72 against the 2126 clock is 2172,
	// which is divisible by four and is not a century year.
	if _, ok := parseHTTPDate("Sunday, 29-Feb-72 08:49:37 GMT", far); !ok {
		t.Error("parseHTTPDate refused the twenty-ninth of February 2172, which exists")
	}
}

// --- the validator ------------------------------------------------------------

// TestModTimeTruncatesToTheSecond is the property that makes the field and the comparison the
// same number. An HTTP-date has no sub-second field, so a modification time with a fraction
// is published without it, and comparing a peer's echo of that field against the untruncated
// time would find the file newer than the date it had itself sent out — for ever.
func TestModTimeTruncatesToTheSecond(t *testing.T) {
	fraction := time.Date(2026, time.July, 4, 11, 22, 33, 500_000_000, time.UTC)

	got := modTime(stamped{mod: fraction}, clock.UTC())
	if !got.Equal(fileTime) {
		t.Errorf("modTime = %v, want %v", got.Format(time.RFC3339Nano), fileTime.Format(time.RFC3339Nano))
	}
	if got.Nanosecond() != 0 {
		t.Errorf("modTime kept %d nanoseconds", got.Nanosecond())
	}

	// The round trip that motivates it: the field this produces, parsed back, is not earlier
	// than the value it was produced from — so the peer that echoes it gets a 304.
	echo, ok := parseHTTPDate(got.Format(imfFixdate), clock)
	if !ok {
		t.Fatalf("the last-modified this handler generates does not parse: %q", got.Format(imfFixdate))
	}
	if got.After(echo) {
		t.Errorf("the file is newer than the field it published: %v against %v", got, echo)
	}
}

// TestModTimeClampsAFutureFile is the MUST in §8.8.2.1 of RFC 9110, which does not say to
// drop the field: "then the origin server MUST replace that value with the message
// origination date."
//
// A file stamped in the future is ordinary — clock skew on a build machine, an archive
// unpacked with the timestamps it carried — and an unclamped validator ahead of the server's
// own clock makes every If-Modified-Since false, so the file transfers in full on every
// request for as long as it stays in the future.
func TestModTimeClampsAFutureFile(t *testing.T) {
	now := clock.UTC()
	origin := now.Truncate(time.Second)

	for _, c := range []struct {
		name string
		mod  time.Time
		want time.Time
	}{
		{"a second ahead", origin.Add(time.Second), origin},
		{"a century ahead", origin.AddDate(100, 0, 0), origin},
		{"a fraction ahead", origin.Add(500 * time.Millisecond), origin},
		{"exactly now", origin, origin},
		{"a second behind", origin.Add(-time.Second), origin.Add(-time.Second)},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := modTime(stamped{mod: c.mod}, now); !got.Equal(c.want) {
				t.Errorf("modTime = %v, want %v", got, c.want)
			}
		})
	}

	// And the same clamp against a clock with a fraction in it, which the real one always has
	// and this file's fixed one never does. The date that replaces a future timestamp is
	// published as a validator, so it has to be the whole second the field will carry: an
	// unrounded one is later than its own formatted form, and the peer's echo of that form is
	// then earlier than the file for ever, which is the transfer this clamp exists to stop.
	fraction := now.Add(500 * time.Millisecond)
	got := modTime(stamped{mod: fraction.AddDate(0, 0, 1)}, fraction)
	if got.Nanosecond() != 0 {
		t.Errorf("the clamped validator kept %d nanoseconds", got.Nanosecond())
	}
	if !got.Equal(origin) {
		t.Errorf("the clamped validator is %v, want the truncated second %v", got, origin)
	}

	echo, ok := parseHTTPDate(got.Format(imfFixdate), fraction)
	if !ok {
		t.Fatalf("the clamped validator does not parse: %q", got.Format(imfFixdate))
	}
	if got.After(echo) {
		t.Errorf("the clamped file is newer than the field it published: %v against %v", got, echo)
	}
}

// TestModTimeConvertsToUTC is the conversion that a machine already running in UTC would hide.
// The zone the filesystem reports is the local one, and IMF-fixdate carries no offset — so a
// formatter handed a value in +05:30 writes the wall clock of that zone and calls it GMT,
// which is a validator five and a half hours out.
func TestModTimeConvertsToUTC(t *testing.T) {
	local := fileTime.In(time.FixedZone("+0530", 5*3600+1800))

	got := modTime(stamped{mod: local}, clock.UTC())
	if !got.Equal(fileTime) {
		t.Errorf("modTime = %v, want %v", got, fileTime)
	}
	if got.Location() != time.UTC {
		t.Errorf("modTime is in %v, want UTC", got.Location())
	}
	if formatted := got.Format(imfFixdate); formatted != fileTimeField {
		t.Errorf("the field is %q, want %q", formatted, fileTimeField)
	}
}

// TestModTimeOfAFileWithoutOneIsZero is the filesystem that does not keep the timestamp. It is
// not an error to report to a peer — it is a response with no validator in it, and the zero
// time is how that travels the two functions between here and withValidator.
//
// The formatted zero time is in the message on purpose. It is a real date, the first of
// January in year one, and it is what a handler that forgot this check would put on the wire.
func TestModTimeOfAFileWithoutOneIsZero(t *testing.T) {
	got := modTime(stamped{}, clock.UTC())
	if !got.IsZero() {
		t.Errorf("modTime = %v, want the zero time; a formatted one reads %q",
			got, got.Format(imfFixdate))
	}
}

// TestWithValidatorLeavesTheFieldOutWhenThereIsNone is the other half of the same case, at the
// point where the decision becomes a field or no field.
func TestWithValidatorLeavesTheFieldOutWhenThereIsNone(t *testing.T) {
	base := []h2.Field{{Name: ":status", Value: status200}}

	if got := withValidator(base, time.Time{}); len(got) != 1 {
		t.Errorf("withValidator added %d fields for a file with no modification time: %v",
			len(got)-1, got[1:])
	}

	got := withValidator(base, fileTime)
	if len(got) != 2 {
		t.Fatalf("withValidator produced %d fields, want 2: %v", len(got), got)
	}
	if want := (h2.Field{Name: "last-modified", Value: fileTimeField}); got[1] != want {
		t.Errorf("withValidator added %v, want %v", got[1], want)
	}
}

// --- the responses ------------------------------------------------------------

// TestServeNotModifiedIsTheWholeFieldSet is a 304 as the peer receives it, asserted field by
// field and in order.
//
// What is absent is the point. §15.4.5 of RFC 9110 lists the fields a 304 may carry, and of
// anything else says, in §15.4.5 of RFC 9110: "a sender SHOULD NOT generate representation
// metadata other than the above listed fields unless said metadata exists for the purpose of
// guiding cache updates".
// A content-length and a content-type describe a representation this response does not carry
// and guide no cache update, so neither is here — while the validator, which is what the cache
// revalidates against, is.
func TestServeNotModifiedIsTheWholeFieldSet(t *testing.T) {
	h := newHandler(t, map[string]string{"index.html": page})

	a := serveCond(t, h, methodGet, "/index.html",
		h2.Field{Name: fieldIfModifiedSince, Value: fileTimeField})

	assertFields(t, a, []h2.Field{
		{Name: ":status", Value: status304},
		{Name: "date", Value: clockField},
		{Name: "server", Value: serverName},
		{Name: "last-modified", Value: fileTimeField},
	})
}

// TestServeNotModifiedCarriesNothing is the other rule §15.4.5 of RFC 9110 has about a 304, and
// this one is not a SHOULD. §15.4.5 of RFC 9110: "A 304 response is terminated by the end of the
// header section; it cannot contain content or trailers."
//
// Three assertions, because there are three ways to get this wrong and only one of them is a
// DATA frame. A response that ends the stream on the header frame is the correct one; a
// response that leaves the stream open sends nothing either, and a peer waits for content that
// is never coming.
func TestServeNotModifiedCarriesNothing(t *testing.T) {
	h := newHandler(t, map[string]string{"index.html": page})

	for _, method := range []string{methodGet, methodHead} {
		a := serveCond(t, h, method, "/index.html", h2.Field{Name: fieldIfNoneMatch, Value: "*"})
		if a.status() != status304 {
			t.Errorf("%s answered %s, want %s", method, a.status(), status304)
			continue
		}
		if a.body != "" {
			t.Errorf("%s sent %d octets of content on a 304", method, len(a.body))
		}
		if a.data() != 0 {
			t.Errorf("%s sent %d DATA frames on a 304", method, a.data())
		}
		if !a.ended {
			t.Errorf("%s left the stream open on a 304", method)
		}
	}
}

// TestServeNotModifiedWithoutAValidator is the 304 that carries no last-modified, which is
// reachable only through an entity-tag field: the two date fields are ignored when there is no
// modification time to compare them against, so an if-none-match of * is the one precondition
// that can produce this response.
//
// Driven through notModified directly, because the zero modification time cannot be arranged
// on disk — os.Chtimes reads the zero time as a request to leave the file alone.
func TestServeNotModifiedWithoutAValidator(t *testing.T) {
	h := newHandler(t, map[string]string{"index.html": page})

	out := &collector{max: limits.MaxFrameSize}
	w := response.NewWriter(response.NewEncoder(hpack.New(), out), &grants{}, 1)
	a := read(t, out, h.notModified(w, clock.UTC(), time.Time{}))

	if a.err != nil {
		t.Fatalf("notModified: %v", a.err)
	}
	assertFields(t, a, []h2.Field{
		{Name: ":status", Value: status304},
		{Name: "date", Value: clockField},
		{Name: "server", Value: serverName},
	})
	if !a.ended {
		t.Error("the stream was left open")
	}
}

// TestServePreconditionFailedIsAnOrdinaryError is the 412 in §15.5.13 of RFC 9110, which this
// handler sends the way it sends every other refusal: a status, a sentence, and the two fields
// that describe the sentence rather than the file.
//
// No validator on it, and that is the interesting absence. A 412 declines to say anything
// about the representation — the peer's precondition was about a state of the resource this
// server is not confirming — so a modification time on it would be metadata for a
// representation that was not sent.
func TestServePreconditionFailedIsAnOrdinaryError(t *testing.T) {
	h := newHandler(t, map[string]string{"index.html": page})

	a := serveCond(t, h, methodGet, "/index.html", h2.Field{Name: fieldIfMatch, Value: anEntityTag})

	assertFields(t, a, []h2.Field{
		{Name: ":status", Value: status412},
		{Name: "content-length", Value: strconv.Itoa(len(body412))},
		{Name: "content-type", Value: textPlain},
		{Name: "date", Value: clockField},
		{Name: "server", Value: serverName},
	})
	if a.body != body412 {
		t.Errorf("content = %q, want %q", a.body, body412)
	}
	if !a.ended {
		t.Error("the stream was left open")
	}
}

// TestServeConditionalRoundTrip is the exchange every browser makes on its second visit, in
// full: fetch the file, send back the last-modified it was given, receive a 304.
//
// This is the test that fails if any one of four things drifts apart — the truncation in
// modTime, the format the field is written in, the format the parser reads, and the direction
// of the comparison in evaluate. Each of them is tested on its own above; none of those tests
// would notice if two of them were wrong in the same direction.
func TestServeConditionalRoundTrip(t *testing.T) {
	h := newHandler(t, map[string]string{"index.html": page})

	first := serve(t, h, methodGet, "/index.html")
	if first.status() != status200 {
		t.Fatalf("the first request answered %s, want %s", first.status(), status200)
	}
	validator := first.get("last-modified")
	if validator == "" {
		t.Fatal("the first response carried no last-modified, so there is nothing to send back")
	}
	if first.body != page {
		t.Fatalf("the first response carried %d octets, want %d", len(first.body), len(page))
	}

	second := serveCond(t, h, methodGet, "/index.html",
		h2.Field{Name: fieldIfModifiedSince, Value: validator})
	if second.status() != status304 {
		t.Errorf("sending back %q answered %s, want %s", validator, second.status(), status304)
	}
	if second.get("last-modified") != validator {
		t.Errorf("the 304 carried %q, want the same validator %q", second.get("last-modified"), validator)
	}
	if second.body != "" {
		t.Errorf("the 304 carried %d octets of content", len(second.body))
	}
}

// TestServeValidatorIsTheFileOnDisk parses the field back out of the response and compares it
// to what the filesystem says, which is the assertion that survives a change of clock, zone or
// platform.
//
// The comparison is against the file's own modification time truncated to the second, read
// through the same os.Stat any other program would use. A dropped conversion to UTC passes
// every other test in this package on a machine whose zone is already UTC; it fails here on
// every machine, because the parsed field is an instant and the instant is wrong.
func TestServeValidatorIsTheFileOnDisk(t *testing.T) {
	dir := tree(t, map[string]string{"index.html": page})
	h := handlerFor(t, dir)

	a := serve(t, h, methodGet, "/index.html")
	sent, ok := parseHTTPDate(a.get("last-modified"), clock)
	if !ok {
		t.Fatalf("last-modified = %q, which this server's own parser refuses", a.get("last-modified"))
	}

	_, info, err := h.open("index.html")
	if err != nil {
		t.Fatal(err)
	}
	if want := info.ModTime().UTC().Truncate(time.Second); !sent.Equal(want) {
		t.Errorf("last-modified is %v, but the file was modified at %v", sent, want)
	}
}

// TestServeIfUnmodifiedSinceGuardsAgainstAnEditRace is the lost-update precondition doing what
// it is for, on the only method this server accepts it with.
//
// A GET is a strange place to see it and it is legal there, and the answer is the one it would
// get on a PUT: the file changed after the date the peer was acting on, so the request is
// refused rather than answered with a representation the peer did not expect. The three cases
// are the boundary — the second before, the second itself, and the second after.
func TestServeIfUnmodifiedSinceGuardsAgainstAnEditRace(t *testing.T) {
	h := newHandler(t, map[string]string{"index.html": page})

	for _, c := range []struct{ value, want string }{
		{aDayBefore, status412},
		{oneSecondBefore, status412},
		{fileTimeField, status200},
		{oneSecondAfter, status200},
		{aDayAfter, status200},

		// The same instant in the obsolete format, which is the only case in this file that
		// drives the century arithmetic through the whole handler: the clock serve reads is
		// what resolves "26", and a handler that passed a zero time down instead would put
		// this date in the first century and refuse the request.
		{"Saturday, 04-Jul-26 11:22:33 GMT", status200},
	} {
		a := serveCond(t, h, methodGet, "/index.html",
			h2.Field{Name: fieldIfUnmodifiedSince, Value: c.value})
		if a.status() != c.want {
			t.Errorf("if-unmodified-since %q answered %s, want %s", c.value, a.status(), c.want)
		}
	}
}

// TestServeIgnoresAnUnusableDate is every way a peer can send a date this handler will not act
// on, asserted through the whole handler rather than through the parser: the answer is the
// response the request would have got with no precondition on it at all.
//
// Ignoring is the safe failure. Each of these values would be a 304 if it were acted on
// carelessly — a garbage date that parsed as the zero time is earlier than every file, and a
// list of dates whose first member is valid is a 304 to a parser that took the first member —
// so every case here costs a transfer and none of them can produce a stale page.
//
// A value with whitespace around it is not among them, and cannot be: §8.2.1 of RFC 9113 makes
// one malformed, and internal/request refuses the request before this handler is reached. The
// parser refuses it too, which TestParseHTTPDateRefusesWhatIsNotADate asserts at the level
// where it is reachable.
func TestServeIgnoresAnUnusableDate(t *testing.T) {
	h := newHandler(t, map[string]string{"index.html": page})

	for _, c := range []struct{ value, why string }{
		{"", "empty"},
		{"0", "not a date"},
		{"Sat, 04 Jul 2026 11:22:33 gmt", "the zone is case sensitive"},
		{"Sat, 4 Jul 2026 11:22:33 GMT", "the day is fixed width"},
		{fileTimeField + ", " + aDayAfter, "a list of dates"},
		{fileTimeField + " (GMT)", "a comment the grammar has no room for"},
	} {
		a := serveCond(t, h, methodGet, "/index.html",
			h2.Field{Name: fieldIfModifiedSince, Value: c.value})
		if a.status() != status200 {
			t.Errorf("if-modified-since %q answered %s, want %s: %s",
				c.value, a.status(), status200, c.why)
		}
		if a.body != page {
			t.Errorf("if-modified-since %q sent %d octets, want the file", c.value, len(a.body))
		}
	}
}

// TestServeIgnoresPreconditionsOnEverythingButA2xx is the prohibition in §13.2.1 of RFC 9110:
// "A server MUST ignore all received preconditions if its response to the same request without
// those conditions, prior to processing the request content, would have been a status code
// other than a 2xx (Successful) or 412 (Precondition Failed)."
//
// An if-none-match of * is the precondition used, because it is the one that would otherwise
// turn each of these into a 304 — and a 304 in place of a 404 tells a peer that the
// representation it has cached for a file that does not exist is still good.
func TestServeIgnoresPreconditionsOnEverythingButA2xx(t *testing.T) {
	h := newHandler(t, map[string]string{"index.html": page, "docs/index.html": page})

	for _, c := range []struct {
		method, target, want string
	}{
		{methodGet, "/missing", status404},
		{methodGet, "/docs", status301},
		{"POST", "/index.html", status405},
		{methodGet, "/" + strings.Repeat("a", MaxTargetLength), status414},
	} {
		for _, when := range []h2.Field{
			{Name: fieldIfNoneMatch, Value: "*"},
			{Name: fieldIfModifiedSince, Value: aDayAfter},
			{Name: fieldIfMatch, Value: anEntityTag},
			{Name: fieldIfUnmodifiedSince, Value: aDayBefore},
		} {
			a := serveCond(t, h, c.method, c.target, when)
			if a.status() != c.want {
				t.Errorf("%s %.20q with %s answered %s, want %s",
					c.method, c.target, when.Name, a.status(), c.want)
			}
		}
	}
}

// TestServeConditionalOnADirectoryIndex is the same evaluation one level down, on the
// representation a request for a directory is answered with.
//
// Worth its own test because the file whose modification time is published is not the one
// named in the target: the validator describes the index inside the directory, and a
// conditional request about it has to be compared against that file rather than against the
// directory. A handler that stat'ed the directory would send a validator for one thing and
// evaluate against another.
func TestServeConditionalOnADirectoryIndex(t *testing.T) {
	h := newHandler(t, map[string]string{"docs/index.html": page})

	a := serve(t, h, methodGet, "/docs/")
	if got := a.get("last-modified"); got != fileTimeField {
		t.Errorf("last-modified = %q, want %q", got, fileTimeField)
	}

	b := serveCond(t, h, methodGet, "/docs/", h2.Field{Name: fieldIfModifiedSince, Value: a.get("last-modified")})
	if b.status() != status304 {
		t.Errorf("the round trip on a directory index answered %s, want %s", b.status(), status304)
	}
}

// TestServeConditionalOnAnEmptyFile is the zero-length representation, which has a validator
// like any other and is the case where a 304 and a 200 carry the same number of octets.
//
// A handler that decided whether to send content by looking at the length rather than at the
// status would pass every other test in this file.
func TestServeConditionalOnAnEmptyFile(t *testing.T) {
	h := newHandler(t, map[string]string{"empty.txt": ""})

	a := serve(t, h, methodGet, "/empty.txt")
	if got := a.get("content-length"); got != "0" {
		t.Errorf("content-length = %q, want 0", got)
	}
	if got := a.get("last-modified"); got != fileTimeField {
		t.Errorf("last-modified = %q, want %q", got, fileTimeField)
	}

	b := serveCond(t, h, methodGet, "/empty.txt", h2.Field{Name: fieldIfNoneMatch, Value: "*"})
	if b.status() != status304 {
		t.Fatalf("an empty file answered %s, want %s", b.status(), status304)
	}
	if got := b.get("content-length"); got != "" {
		t.Errorf("the 304 carried content-length %q", got)
	}
}

// TestServeNotModifiedAfterTheFileChanges is the invalidation, which is the half of a
// conditional request that a server gets wrong silently: a 304 for a file that has since been
// rewritten is a stale page with no way for the peer to find out.
//
// The file is stamped forward by one second rather than rewritten, because one second is the
// smallest change this validator can represent and so the hardest case for it. The content is
// changed as well, so that a handler which answered from the old timestamp would be sending a
// validator for content it no longer has.
func TestServeNotModifiedAfterTheFileChanges(t *testing.T) {
	dir := tree(t, map[string]string{"index.html": page})
	h := handlerFor(t, dir)

	a := serveCond(t, h, methodGet, "/index.html",
		h2.Field{Name: fieldIfModifiedSince, Value: fileTimeField})
	if a.status() != status304 {
		t.Fatalf("the unchanged file answered %s, want %s", a.status(), status304)
	}

	const second = "<!doctype html><title>zdh</title><h1>and now this</h1>\n"
	touch(t, dir, "index.html", second, fileTime.Add(time.Second))

	b := serveCond(t, h, methodGet, "/index.html",
		h2.Field{Name: fieldIfModifiedSince, Value: fileTimeField})
	if b.status() != status200 {
		t.Fatalf("the rewritten file answered %s, want %s", b.status(), status200)
	}
	if b.body != second {
		t.Errorf("content = %q, want the new version", b.body)
	}
	if got, want := b.get("last-modified"), "Sat, 04 Jul 2026 11:22:34 GMT"; got != want {
		t.Errorf("last-modified = %q, want %q", got, want)
	}

	// And the new validator is a 304 in its turn, so the peer's next request is cheap again.
	c := serveCond(t, h, methodGet, "/index.html",
		h2.Field{Name: fieldIfModifiedSince, Value: b.get("last-modified")})
	if c.status() != status304 {
		t.Errorf("the new validator answered %s, want %s", c.status(), status304)
	}
}

// TestServeClampsAFileFromTheFuture is the §8.8.2.1 clamp through the whole handler, on the
// file a build machine with a fast clock produces.
//
// The response's own date is what the validator becomes, which is the substitution that
// section requires — and the consequence is the one worth asserting: the date field and the
// last-modified field are then the same string, so the peer's echo of it is a 304 rather than
// a request that transfers the file for as long as its timestamp stays ahead.
func TestServeClampsAFileFromTheFuture(t *testing.T) {
	dir := tree(t, map[string]string{"index.html": page})
	h := handlerFor(t, dir)

	touch(t, dir, "index.html", page, clock.Add(48*time.Hour))

	a := serve(t, h, methodGet, "/index.html")
	if got := a.get("last-modified"); got != clockField {
		t.Errorf("last-modified = %q, want the response's own date %q", got, clockField)
	}
	if a.get("date") != a.get("last-modified") {
		t.Errorf("date is %q and last-modified is %q; the clamp should make them one value",
			a.get("date"), a.get("last-modified"))
	}

	b := serveCond(t, h, methodGet, "/index.html",
		h2.Field{Name: fieldIfModifiedSince, Value: clockField})
	if b.status() != status304 {
		t.Errorf("the clamped validator sent back answered %s, want %s", b.status(), status304)
	}
}

// touch replaces a file's content and its modification time in one step, which is what a build
// writing into a served directory does and what neither os.WriteFile nor os.Chtimes does alone.
func touch(t *testing.T, dir, name, content string, mod time.Time) {
	t.Helper()
	full := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatalf("rewriting %q: %v", name, err)
	}
	if err := os.Chtimes(full, mod, mod); err != nil {
		t.Fatalf("stamping %q: %v", name, err)
	}
}
