package request

import (
	"errors"
	"strings"
	"testing"

	"zerodeps/zdh/internal/h2"
	"zerodeps/zdh/internal/priority"
)

// testStream is the identifier every test in this file parses on.
//
// Five rather than one, and odd rather than even: a stream error carries the
// identifier it belongs to, and an implementation that hardcoded 0 or 1 — or that
// lost the argument somewhere and defaulted — would look correct against a test that
// parsed on stream 1.
const testStream = 5

// secret is the value the no-leak test hides in a field it expects to be refused.
// Nothing in an error message may echo it. See TestParseKeepsFieldValuesOutOfItsErrors.
const secret = "s3cr3t-value"

// fields builds a field list from name, value pairs, in the order they arrive on the
// wire. Order is most of what these tests are about — §8.3's rules are all about
// position — so the input is a flat list rather than a map.
func fields(nv ...string) []h2.Field {
	if len(nv)%2 != 0 {
		panic("request: fields takes name, value pairs")
	}
	f := make([]h2.Field, 0, len(nv)/2)
	for i := 0; i < len(nv); i += 2 {
		f = append(f, h2.Field{Name: nv[i], Value: nv[i+1]})
	}
	return f
}

// req is a minimal valid request, with any extra regular field lines appended.
func req(extra ...string) []h2.Field {
	return append(fields(
		pseudoMethod, "GET",
		pseudoScheme, "https",
		pseudoAuthority, "example.test",
		pseudoPath, "/",
	), fields(extra...)...)
}

// with is req with one pseudo-header field's value replaced, for the tests whose
// subject is a value rather than a list. It panics on a name the base request does
// not have, so that a renamed constant is a failure here rather than a test that
// silently checks a request nobody changed.
func with(name, value string) []h2.Field {
	f := req()
	for i := range f {
		if f[i].Name == name {
			f[i].Value = value
			return f
		}
	}
	panic("request: " + name + " is not in the base request")
}

// without is req with one pseudo-header field removed.
func without(name string) []h2.Field {
	f := req()
	out := make([]h2.Field, 0, len(f))
	for _, x := range f {
		if x.Name != name {
			out = append(out, x)
		}
	}
	if len(out) == len(f) {
		panic("request: " + name + " is not in the base request")
	}
	return out
}

// mustParse parses f and fails if it was refused.
func mustParse(t *testing.T, f []h2.Field, endStream bool) *Request {
	t.Helper()
	r, err := Parse(testStream, f, endStream)
	if err != nil {
		t.Fatalf("Parse(%v, endStream=%v): %v, want it accepted", f, endStream, err)
	}
	return r
}

// refuse asserts that Parse treated f as malformed and returns the reason it gave.
//
// It checks the whole of §8.1.1's verdict and not merely that something came back:
// the error's type, the stream it names, and its code. Every refusal in this file
// goes through here, so the scope of the error is asserted once per rule rather than
// once in a single test about scope — and an implementation that answered any of
// these faults with a connection error fails every one of them.
func refuse(t *testing.T, f []h2.Field, endStream bool) string {
	t.Helper()
	r, err := Parse(testStream, f, endStream)
	if err == nil {
		t.Fatalf("Parse accepted %v as %+v, want it treated as malformed (RFC 9113 §8.1.1)", f, r)
	}
	return reasonOf(t, err)
}

// reasonOf asserts that err is §8.1.1's verdict and returns its reason.
func reasonOf(t *testing.T, err error) string {
	t.Helper()
	var se h2.StreamError
	if !errors.As(err, &se) {
		t.Fatalf("the error is %T (%v), want an h2.StreamError: §8.1.1 makes a malformed "+
			"request a stream error, not a connection error", err, err)
	}
	if se.StreamID != testStream {
		t.Errorf("the stream error names stream %d, want stream %d", se.StreamID, testStream)
	}
	if se.Code != h2.ProtocolError {
		t.Errorf("the stream error carries %v, want %v (RFC 9113 §8.1.1)", se.Code, h2.ProtocolError)
	}
	if !strings.Contains(se.Reason, "malformed request") {
		t.Errorf("the reason is %q, want it to name §8.1.1's term", se.Reason)
	}
	return se.Reason
}

// wantReason asserts that a refusal named the rule it was made under.
func wantReason(t *testing.T, reason, want string) {
	t.Helper()
	if !strings.Contains(reason, want) {
		t.Errorf("the reason is %q, want it to mention %q", reason, want)
	}
}

// --- §8.2.1, field validity ------------------------------------------------

func TestParseAcceptsAMinimalRequest(t *testing.T) {
	r := mustParse(t, req(), true)
	if r.Method != "GET" || r.Scheme != "https" || r.Authority != "example.test" || r.Path != "/" {
		t.Errorf("parsed %+v, want the four pseudo-header fields lifted out as they arrived", r)
	}
	if len(r.Fields) != 0 {
		t.Errorf("Fields is %v, want it empty: the request had no regular field lines", r.Fields)
	}
	if r.ContentLength != NoContentLength {
		t.Errorf("ContentLength is %d, want NoContentLength (%d): the request declared none",
			r.ContentLength, NoContentLength)
	}
}

func TestParseAcceptsATypicalBrowserRequest(t *testing.T) {
	f := req(
		"user-agent", "Mozilla/5.0",
		"accept", "text/html,application/xhtml+xml",
		"accept-encoding", "gzip, deflate, br",
		"accept-language", "en-GB,en;q=0.9",
		"cookie", "a=b",
		"cookie", "c=d",
	)
	r := mustParse(t, f, true)
	if len(r.Fields) != 6 {
		t.Fatalf("Fields is %v, want the six regular field lines", r.Fields)
	}
	if r.Fields[4].Value != "a=b" || r.Fields[5].Value != "c=d" {
		t.Errorf("the two cookie field lines came out as %q and %q, want them in arrival order: "+
			"§5.3 of RFC 9110 makes the order of one field name's values significant",
			r.Fields[4].Value, r.Fields[5].Value)
	}
}

func TestParseRejectsAnUppercaseFieldName(t *testing.T) {
	for _, name := range []string{"X-Foo", "Host", ":Method"} {
		t.Run(name, func(t *testing.T) {
			var f []h2.Field
			if strings.HasPrefix(name, ":") {
				f = fields(name, "GET", pseudoScheme, "https", pseudoPath, "/")
			} else {
				f = req(name, "1")
			}
			wantReason(t, refuse(t, f, true), "not lowercase")
		})
	}
}

func TestParseRejectsAFieldNameWithAProhibitedOctet(t *testing.T) {
	// §8.2.1's ranges are 0x00-0x20 and 0x7f-0xff. The boundaries are in the table
	// deliberately: 0x20 and 0x7f are both prohibited and both are one octet from a
	// legal name character, which is exactly where an off-by-one lands.
	for _, name := range []string{"x\x00foo", "x foo", "x\tfoo", "x\x7ffoo", "x\xfffoo", "x\x1ffoo"} {
		t.Run(name, func(t *testing.T) {
			wantReason(t, refuse(t, req(name, "1"), true), "§8.2.1")
		})
	}
}

func TestParseRejectsAFieldNameWithAColon(t *testing.T) {
	// The exception in §8.2.1 is for a name that starts with "a single colon", so a
	// colon anywhere else is prohibited — including the second of two leading ones,
	// which is what makes "::method" a field name rather than a pseudo-header field.
	for _, name := range []string{"x:foo", "foo:", "::method", ":x:y"} {
		t.Run(name, func(t *testing.T) {
			f := append(fields(name, "1"), req()...)
			wantReason(t, refuse(t, f, true), "colon")
		})
	}
}

func TestParseRejectsAFieldLineWithAnEmptyName(t *testing.T) {
	wantReason(t, refuse(t, req("", "1"), true), "empty name")
}

func TestParseRejectsAFieldValueWithAProhibitedOctet(t *testing.T) {
	// §8.2.1: NUL, LF and CR, "at any position". CR and LF are the smuggling
	// payload — a value carrying either becomes two field lines the moment it is
	// written into an HTTP/1.1 message — so both are checked at the front, in the
	// middle and at the end.
	for _, value := range []string{"a\x00b", "a\nb", "a\rb", "\ra", "a\n", "a\r\nb: c"} {
		t.Run(value, func(t *testing.T) {
			wantReason(t, refuse(t, req("x-foo", value), true), "§8.2.1")
		})
	}
}

func TestParseRejectsAFieldValueSurroundedByWhitespace(t *testing.T) {
	for _, value := range []string{" a", "a ", "\ta", "a\t", " ", "\t"} {
		t.Run(value, func(t *testing.T) {
			reason := refuse(t, req("x-foo", value), true)
			if !strings.Contains(reason, "starts with whitespace") &&
				!strings.Contains(reason, "ends with whitespace") {
				t.Errorf("the reason is %q, want it to name which end (RFC 9113 §8.2.1)", reason)
			}
		})
	}
}

func TestParseAcceptsAnEmptyFieldValue(t *testing.T) {
	// §8.2.1 forbids a value that "starts or ends with" whitespace, and an empty
	// value has neither end. A check that indexed the first octet unconditionally
	// would panic here rather than fail.
	r := mustParse(t, req("x-empty", ""), true)
	if len(r.Fields) != 1 || r.Fields[0].Value != "" {
		t.Errorf("Fields is %v, want the empty-valued field kept", r.Fields)
	}
}

func TestParseAcceptsInteriorWhitespaceInAFieldValue(t *testing.T) {
	// §8.2.1 bans whitespace only at the ends. A value with a space in it is
	// ordinary — "gzip, deflate" is one — and refusing it would break every client.
	for _, value := range []string{"a b", "a\tb", "gzip, deflate"} {
		t.Run(value, func(t *testing.T) {
			mustParse(t, req("x-foo", value), true)
		})
	}
}

// --- §8.2.2, connection-specific header fields -----------------------------

func TestParseRejectsAConnectionSpecificHeaderField(t *testing.T) {
	// §8.2.2's list in full. transfer-encoding is the one that matters: HTTP/2 has
	// no chunked encoding, so a peer sending it is arranging for this server and the
	// next hop to disagree about where the body ends.
	for _, name := range []string{"connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade"} {
		t.Run(name, func(t *testing.T) {
			wantReason(t, refuse(t, req(name, "close"), true), "§8.2.2")
		})
	}
}

func TestParseAcceptsTEWithTrailers(t *testing.T) {
	// §8.2.2's only exception, and case-folded because a transfer-coding name is
	// case-insensitive (§10.1.4 of RFC 9110).
	for _, value := range []string{"trailers", "Trailers", "TRAILERS", "TrAiLeRs"} {
		t.Run(value, func(t *testing.T) {
			mustParse(t, req("te", value), true)
		})
	}
}

func TestParseRejectsTEWithAnyOtherValue(t *testing.T) {
	// "MUST NOT contain any value other than 'trailers'" — so not a list with
	// trailers in it, not a q-value, and not a near miss.
	for _, value := range []string{"trailers, deflate", "gzip", "", "trailers;q=0.5", "trailersx", "railers"} {
		t.Run(value, func(t *testing.T) {
			wantReason(t, refuse(t, req("te", value), true), "§8.2.2")
		})
	}
}

// --- §8.3, pseudo-header field rules ---------------------------------------

func TestParseRejectsAPseudoHeaderFieldAfterARegularFieldLine(t *testing.T) {
	f := fields(
		pseudoMethod, "GET",
		pseudoScheme, "https",
		pseudoPath, "/",
		"x-foo", "1",
		pseudoAuthority, "example.test",
	)
	wantReason(t, refuse(t, f, true), "§8.3")
}

func TestParseRejectsARepeatedPseudoHeaderField(t *testing.T) {
	for _, name := range []string{pseudoMethod, pseudoScheme, pseudoAuthority, pseudoPath} {
		t.Run(name, func(t *testing.T) {
			// The repeat carries a value the first one did not, so a check that
			// compared the destination against "" rather than tracking presence
			// would still have to notice this one. The empty-valued case is below.
			f := append(req(), h2.Field{Name: name, Value: "x"})
			wantReason(t, refuse(t, f, true), "more than once")
		})
	}
}

func TestParseRejectsARepeatedPseudoHeaderFieldWithAnEmptyValue(t *testing.T) {
	// The case that distinguishes "was this field present" from "does it have a
	// value". ":authority" twice, empty both times, repeats a pseudo-header field —
	// and an implementation whose duplicate check was "the destination is not empty"
	// would accept it.
	f := fields(
		pseudoMethod, "GET",
		pseudoScheme, "https",
		pseudoAuthority, "",
		pseudoAuthority, "",
		pseudoPath, "/",
	)
	wantReason(t, refuse(t, f, true), "more than once")
}

func TestParseRejectsAnUndefinedPseudoHeaderField(t *testing.T) {
	// ":status" is the one that matters: it is defined, for responses, and §8.3 says
	// "pseudo-header fields defined for responses MUST NOT appear in requests".
	// ":protocol" is RFC 8441's, which this server has not negotiated, and ":" is
	// the degenerate case — a name that is nothing but the colon.
	for _, name := range []string{":status", ":protocol", ":", ":path2", ":Authority"} {
		t.Run(name, func(t *testing.T) {
			f := append(fields(name, "200"), req()...)
			reason := refuse(t, f, true)
			if !strings.Contains(reason, "not a pseudo-header field defined for a request") &&
				!strings.Contains(reason, "not lowercase") {
				t.Errorf("the reason is %q, want it to say the name is not a request "+
					"pseudo-header field (RFC 9113 §8.3)", reason)
			}
		})
	}
}

// --- §8.3.1, the required set and the values -------------------------------

func TestParseRequiresMethodSchemeAndPath(t *testing.T) {
	// §8.3.1: "All HTTP/2 requests MUST include exactly one valid value for the
	// ':method', ':scheme', and ':path' pseudo-header fields, unless they are
	// CONNECT requests."
	for _, name := range []string{pseudoMethod, pseudoScheme, pseudoPath} {
		t.Run(name, func(t *testing.T) {
			reason := refuse(t, without(name), true)
			// The refusal has to be *this* one and not a downstream consequence of
			// it. A missing pseudo-header field and an empty one are different
			// faults with different fixes, and a required-set check that was
			// removed would leave the value checks below it refusing the zero value
			// instead: ":path" absent would be reported as ":path" empty, and
			// ":method" absent as a method that is not a token. Both are refusals,
			// and both send a client's author looking for the wrong bug.
			wantReason(t, reason, "no "+name)
			wantReason(t, reason, "§8.3.1")
		})
	}
}

func TestParseDoesNotRequireAnAuthority(t *testing.T) {
	// ":authority" is not in §8.3.1's mandatory list, and a request translated from
	// HTTP/1.1 by an intermediary may carry a Host instead. A server that required
	// it would refuse requests the RFC permits.
	r := mustParse(t, without(pseudoAuthority), true)
	if r.Authority != "" {
		t.Errorf("Authority is %q, want it empty: the request carried neither ':authority' nor Host", r.Authority)
	}
}

func TestParseRejectsAMethodThatIsNotAToken(t *testing.T) {
	// A method is a token (§9 of RFC 9110). The value that matters is the one with a
	// space in it: "GET /admin HTTP/1.1" is a request line, and an intermediary that
	// pasted a method containing a space into one would smuggle a request nobody
	// sent. The 0x01 case is here because §8.2.1's value rules let it through — they
	// ban NUL, CR and LF and nothing else — so the token check is the only thing
	// that catches it.
	for _, method := range []string{"", "GE T", "GET,POST", "GET/", "GET\x01", "GET HTTP/1.1"} {
		t.Run(method, func(t *testing.T) {
			wantReason(t, refuse(t, with(pseudoMethod, method), true), "token")
		})
	}
}

func TestParseAcceptsAnUnrecognisedMethod(t *testing.T) {
	// §9 of RFC 9110 makes the method extensible, so an unknown one is a 501 from
	// the layer that routes requests and not a malformed request. Parse's job is the
	// syntax.
	//
	// The three cover the tchar set a real method actually uses: letters, a hyphen
	// (M-SEARCH is SSDP's, and it is a token), and a digit. A token check narrowed
	// to letters would pass every test a browser's traffic produces and refuse
	// these.
	for _, method := range []string{"PROPFIND", "M-SEARCH", "BREW2"} {
		t.Run(method, func(t *testing.T) {
			r := mustParse(t, with(pseudoMethod, method), true)
			if r.Method != method {
				t.Errorf("Method is %q, want the method as it arrived", r.Method)
			}
		})
	}
}

func TestParseRejectsASchemeThatIsNotAScheme(t *testing.T) {
	// §3.1 of RFC 3986: ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ). The interior
	// space is the case §8.2.1 does not catch.
	for _, scheme := range []string{"", "1http", "ht tp", "http:", "http://", "-http"} {
		t.Run(scheme, func(t *testing.T) {
			wantReason(t, refuse(t, with(pseudoScheme, scheme), true), "scheme")
		})
	}
}

func TestParseAcceptsASchemeThatIsNotHTTP(t *testing.T) {
	// §8.3.1 in as many words: "':scheme' is not restricted to 'http' and 'https'
	// schemed URIs." Refusing another scheme is a policy decision for the routing
	// layer, not a §8 fault.
	//
	// The four between them use every character class §3.1 of RFC 3986 allows after
	// the first: a letter, a digit, and each of "+", "-" and ".". A scheme check
	// narrowed to letters and digits would accept "ftp" and refuse the three that
	// follow it, and no test built on http or https would notice.
	for _, scheme := range []string{"ftp", "coap+tcp", "view-source", "z39.50r"} {
		t.Run(scheme, func(t *testing.T) {
			r := mustParse(t, with(pseudoScheme, scheme), true)
			if r.Scheme != scheme {
				t.Errorf("Scheme is %q, want the scheme as it arrived", r.Scheme)
			}
		})
	}
}

func TestParseRejectsAnEmptyPath(t *testing.T) {
	wantReason(t, refuse(t, with(pseudoPath, ""), true), "empty")
}

func TestParseRejectsAPathThatIsNotAnAbsolutePath(t *testing.T) {
	// The ":path" of an "http" or "https" request carries, per §8.3.1, "the path and
	// query parts of the target URI (the absolute-path production and, optionally, a
	// '?' character followed by the query production; see Section 4.1 of [HTTP])".
	// The absolute-URI case is the one with teeth: a ":path" of "https://elsewhere/"
	// is how a request gets routed somewhere its authority never named.
	for _, path := range []string{"foo", "https://elsewhere/", "?q=1", "index.html", "../etc"} {
		t.Run(path, func(t *testing.T) {
			reason := refuse(t, with(pseudoPath, path), true)
			wantReason(t, reason, "absolute path")
			// The target is named on purpose: it is bounded, it is not a secret,
			// and it is what an access log records anyway. See malformedf.
			wantReason(t, reason, path)
		})
	}
}

func TestParseAcceptsAPathOfTwoSlashes(t *testing.T) {
	// An absolute-path of "//" is odd and syntactically legal — path-absolute in
	// §3.3 of RFC 3986 is "/" [ segment-nz *( "/" segment ) ] and an empty first
	// segment is a segment. It is here because "not an absolute path" is a
	// temptingly short check to write as "contains no double slash".
	r := mustParse(t, with(pseudoPath, "//elsewhere/x"), true)
	if r.Path != "//elsewhere/x" {
		t.Errorf("Path is %q, want the target as it arrived", r.Path)
	}
}

func TestParseAcceptsAPathWithAQuery(t *testing.T) {
	r := mustParse(t, with(pseudoPath, "/search?q=a+b&lang=en"), true)
	if r.Path != "/search?q=a+b&lang=en" {
		t.Errorf("Path is %q, want the target as it arrived, query and all", r.Path)
	}
}

func TestParseRejectsAPathWithAControlOctet(t *testing.T) {
	// Not covered by §8.2.1, which bans whitespace at the ends of a value and NUL,
	// CR and LF anywhere. An interior space passes all of it and is still a request
	// target no two implementations agree on: written into an HTTP/1.1 request line
	// it produces a line with three spaces.
	for _, path := range []string{"/a b", "/a\tb", "/a\x7fb", "/a\x1fb"} {
		t.Run(path, func(t *testing.T) {
			wantReason(t, refuse(t, with(pseudoPath, path), true), "octet")
		})
	}
}

func TestParseAcceptsANonASCIIPath(t *testing.T) {
	// RFC 3986 requires these octets to be percent-encoded, and curl sends them
	// raw. They are unambiguous to route on and mean nothing to a downstream
	// parser, so the control check stops below 0x21 rather than at 0x7f.
	r := mustParse(t, with(pseudoPath, "/caf\xc3\xa9"), true)
	if r.Path != "/caf\xc3\xa9" {
		t.Errorf("Path is %q, want the raw octets kept", r.Path)
	}
}

func TestParseAcceptsTheAsteriskFormForOptions(t *testing.T) {
	f := with(pseudoMethod, methodOptions)
	for i := range f {
		if f[i].Name == pseudoPath {
			f[i].Value = "*"
		}
	}
	r := mustParse(t, f, true)
	if r.Path != "*" {
		t.Errorf("Path is %q, want %q (RFC 9113 §8.3.1)", r.Path, "*")
	}
}

func TestParseRejectsTheAsteriskFormForAnyOtherMethod(t *testing.T) {
	// §8.3.1 scopes the asterisk form to "an OPTIONS request for an 'http' or
	// 'https' URI that does not include a path component". A GET for "*" is a
	// request for no resource at all.
	for _, method := range []string{"GET", "POST", "HEAD"} {
		t.Run(method, func(t *testing.T) {
			f := with(pseudoPath, "*")
			for i := range f {
				if f[i].Name == pseudoMethod {
					f[i].Value = method
				}
			}
			wantReason(t, refuse(t, f, true), "asterisk-form")
		})
	}
}

func TestParseLeavesTheTargetShapeAloneForANonHTTPScheme(t *testing.T) {
	// §8.3.1 scopes the ":path" shape rules to "http" and "https" URIs by name. A
	// gateway scheme may have a target this server has no grammar for, and inventing
	// one would refuse requests §8.3.1 permits. Only the rules that are not scoped
	// still apply, which is why an empty path is refused above whatever the scheme.
	for _, path := range []string{"*", "not-a-path", "opaque:thing"} {
		t.Run(path, func(t *testing.T) {
			f := with(pseudoScheme, "ftp")
			for i := range f {
				if f[i].Name == pseudoPath {
					f[i].Value = path
				}
			}
			mustParse(t, f, true)
		})
	}
}

func TestParseRejectsAnEmptyPathWhateverTheScheme(t *testing.T) {
	f := with(pseudoScheme, "ftp")
	for i := range f {
		if f[i].Name == pseudoPath {
			f[i].Value = ""
		}
	}
	wantReason(t, refuse(t, f, true), "empty")
}

// --- §8.3.1, the authority -------------------------------------------------

func TestParseRejectsUserinfoInTheAuthority(t *testing.T) {
	// §8.3.1: "':authority' MUST NOT include the deprecated userinfo subcomponent
	// for 'http' or 'https' schemed URIs." Both schemes, because the rule names both.
	for _, scheme := range []string{"http", "https", "HTTPS"} {
		t.Run(scheme, func(t *testing.T) {
			f := with(pseudoScheme, scheme)
			for i := range f {
				if f[i].Name == pseudoAuthority {
					f[i].Value = "user:pw@example.test"
				}
			}
			wantReason(t, refuse(t, f, true), "userinfo")
		})
	}
}

func TestParseAcceptsUserinfoForAnotherScheme(t *testing.T) {
	// The rule is scoped to "http" and "https" by the RFC, and a gateway scheme that
	// still uses userinfo keeps it. This test is what pins the condition: without
	// it, a check that ignored the scheme would look correct.
	f := with(pseudoScheme, "ftp")
	for i := range f {
		if f[i].Name == pseudoAuthority {
			f[i].Value = "user@example.test"
		}
	}
	r := mustParse(t, f, true)
	if r.Authority != "user@example.test" {
		t.Errorf("Authority is %q, want it as it arrived", r.Authority)
	}
}

func TestParseRejectsAnAuthorityThatDoesNotStopWhereAnAuthorityStops(t *testing.T) {
	// An authority ends at the first "/", "?" or "#" in every URI grammar there is,
	// so one containing any of them is two components being read as one — and which
	// one wins depends on whose parser reads it.
	for _, authority := range []string{"example.test/admin", "example.test?q=1", "example.test#f"} {
		t.Run(authority, func(t *testing.T) {
			wantReason(t, refuse(t, with(pseudoAuthority, authority), true), "ends an authority")
		})
	}
}

func TestParseRejectsAnAuthorityWithAControlOctet(t *testing.T) {
	for _, authority := range []string{"ex ample.test", "example\ttest", "example.test\x7f"} {
		t.Run(authority, func(t *testing.T) {
			wantReason(t, refuse(t, with(pseudoAuthority, authority), true), "octet")
		})
	}
}

func TestParseAcceptsAnIPv6Authority(t *testing.T) {
	// The colons inside the literal are legal in an authority and would break any
	// check that split on the last colon to find a port.
	for _, authority := range []string{"[::1]", "[::1]:8443", "[2001:db8::1]:443"} {
		t.Run(authority, func(t *testing.T) {
			r := mustParse(t, with(pseudoAuthority, authority), true)
			if r.Authority != authority {
				t.Errorf("Authority is %q, want %q", r.Authority, authority)
			}
		})
	}
}

// --- §8.3.1, Host against :authority --------------------------------------

func TestParseRejectsMoreThanOneHostField(t *testing.T) {
	// §7.2 of RFC 9110 permits exactly one. Two that disagree are a smuggled
	// request: this server would route by one and the next hop by the other.
	f := req("host", "example.test", "host", "elsewhere.test")
	wantReason(t, refuse(t, f, true), "Host header fields")
}

func TestParseRejectsAHostThatDiffersFromTheAuthority(t *testing.T) {
	f := req("host", "elsewhere.test")
	reason := refuse(t, f, true)
	wantReason(t, reason, "differs")
	wantReason(t, reason, "§8.3.1")
}

func TestParseAcceptsAHostThatMatchesTheAuthorityAfterNormalization(t *testing.T) {
	// §8.3.1 requires the two to be normalized before they are compared, and points
	// at the scheme-based normalization of §6.2.3 of RFC 3986: case folding, and the
	// scheme's default port is not part of the authority.
	for _, tc := range []struct{ scheme, authority, host string }{
		{"https", "example.test", "EXAMPLE.TEST"},
		{"https", "Example.Test", "example.test"},
		{"https", "example.test:443", "example.test"},
		{"https", "example.test", "example.test:443"},
		{"http", "example.test:80", "example.test"},
		{"https", "[::1]:443", "[::1]"},
	} {
		t.Run(tc.scheme+" "+tc.authority+" "+tc.host, func(t *testing.T) {
			f := fields(
				pseudoMethod, "GET",
				pseudoScheme, tc.scheme,
				pseudoAuthority, tc.authority,
				pseudoPath, "/",
				"host", tc.host,
			)
			r := mustParse(t, f, true)
			if r.Authority != tc.authority {
				t.Errorf("Authority is %q, want the ':authority' as it arrived (%q): "+
					"normalization is for the comparison, not for the request", r.Authority, tc.authority)
			}
		})
	}
}

func TestParseRejectsAHostThatDiffersOnlyByPort(t *testing.T) {
	// The other side of the normalization: a port that is not the scheme's default
	// is part of the authority, so these two identify different entities.
	for _, tc := range []struct{ scheme, authority, host string }{
		{"https", "example.test:8443", "example.test"},
		{"https", "example.test", "example.test:80"},
		{"http", "example.test:443", "example.test"},
	} {
		t.Run(tc.scheme+" "+tc.authority+" "+tc.host, func(t *testing.T) {
			f := fields(
				pseudoMethod, "GET",
				pseudoScheme, tc.scheme,
				pseudoAuthority, tc.authority,
				pseudoPath, "/",
				"host", tc.host,
			)
			wantReason(t, refuse(t, f, true), "differs")
		})
	}
}

func TestParseTakesTheAuthorityFromHostWhenThereIsNoPseudoHeader(t *testing.T) {
	// §8.3.1 forbids using Host "to determine the target URI if ':authority' is
	// present", which is also permission to use it when there is not. That is what a
	// request translated from HTTP/1.1 by an intermediary looks like.
	f := append(without(pseudoAuthority), fields("host", "example.test")...)
	r := mustParse(t, f, true)
	if r.Authority != "example.test" {
		t.Errorf("Authority is %q, want the Host field's value", r.Authority)
	}
}

func TestParseHoldsAHostStandingInForTheAuthorityToTheSameRules(t *testing.T) {
	// A Host that becomes the authority is the authority, so §8.3.1's rules about
	// one apply to it. An implementation that checked only the pseudo-header field
	// would accept a userinfo through the back door.
	for _, tc := range []struct{ host, want string }{
		{"user:pw@example.test", "userinfo"},
		{"example.test/admin", "ends an authority"},
		{"example test", "octet"},
	} {
		t.Run(tc.host, func(t *testing.T) {
			f := append(without(pseudoAuthority), fields("host", tc.host)...)
			reason := refuse(t, f, true)
			wantReason(t, reason, tc.want)
			// And it says so of Host, not of a ":authority" the request never
			// carried: a message that named the wrong field would send a reader
			// looking for a field that is not there.
			wantReason(t, reason, "Host")
			if strings.Contains(reason, pseudoAuthority) {
				t.Errorf("the reason is %q, want it not to blame %s: the request had none",
					reason, pseudoAuthority)
			}
		})
	}
}

func TestParseIgnoresHostWhenTheAuthorityIsPresentAndTheyAgree(t *testing.T) {
	f := req("host", "example.test")
	r := mustParse(t, f, true)
	if r.Authority != "example.test" {
		t.Errorf("Authority is %q, want %q", r.Authority, "example.test")
	}
	if len(r.Fields) != 1 || r.Fields[0].Name != "host" {
		t.Errorf("Fields is %v, want the Host field line kept: it is a regular field and "+
			"nothing in §8 removes it", r.Fields)
	}
}

// --- §8.1.1 and §8.6 of RFC 9110, content-length ---------------------------

func TestParseReadsAContentLength(t *testing.T) {
	r := mustParse(t, req("content-length", "42"), false)
	if r.ContentLength != 42 {
		t.Errorf("ContentLength is %d, want 42", r.ContentLength)
	}
}

func TestParseReportsNoContentLengthWhenThereIsNone(t *testing.T) {
	// A request with no content-length may still have a body, so the absence has to
	// be distinguishable from a declared zero.
	r := mustParse(t, req(), false)
	if r.ContentLength != NoContentLength {
		t.Errorf("ContentLength is %d, want NoContentLength (%d)", r.ContentLength, NoContentLength)
	}
}

func TestParseRejectsMoreThanOneContentLengthField(t *testing.T) {
	// §8.6 of RFC 9110 lets a recipient reject or collapse identical values. This
	// server rejects, so the identical pair is refused as well as the disagreeing
	// one: a rule with two possible answers is a rule two implementations answer
	// differently.
	for _, values := range [][]string{{"1", "2"}, {"1", "1"}} {
		t.Run(strings.Join(values, ","), func(t *testing.T) {
			f := req("content-length", values[0], "content-length", values[1])
			wantReason(t, refuse(t, f, false), "content-length header fields")
		})
	}
}

func TestParseRejectsAContentLengthThatIsNotADecimal(t *testing.T) {
	// §8.6 of RFC 9110 defines it as 1*DIGIT. The signed forms are the ones that
	// matter: strconv.ParseInt accepts both, and a receiver that read "+0" as zero
	// while the next hop read it as invalid disagrees about the whole body.
	for _, value := range []string{"", "abc", "+1", "-1", "1.0", "0x10", "1e3", "1,2", "١٢٣"} {
		t.Run(value, func(t *testing.T) {
			wantReason(t, refuse(t, req("content-length", value), false), "not a decimal")
		})
	}
}

func TestParseRejectsAContentLengthThatDoesNotFitInAnInt64(t *testing.T) {
	for _, value := range []string{"9223372036854775808", "18446744073709551616", strings.Repeat("9", 40)} {
		t.Run(value, func(t *testing.T) {
			wantReason(t, refuse(t, req("content-length", value), false), "larger than")
		})
	}
}

func TestParseAcceptsTheLargestContentLength(t *testing.T) {
	// The boundary on the other side of the range check.
	r := mustParse(t, req("content-length", "9223372036854775807"), false)
	if r.ContentLength != 9223372036854775807 {
		t.Errorf("ContentLength is %d, want 2^63-1", r.ContentLength)
	}
}

func TestParseAcceptsAContentLengthWithLeadingZeros(t *testing.T) {
	// 1*DIGIT, so "007" is a content-length of seven. Refusing it would be stricter
	// than §8.6 of RFC 9110 allows.
	r := mustParse(t, req("content-length", "007"), false)
	if r.ContentLength != 7 {
		t.Errorf("ContentLength is %d, want 7", r.ContentLength)
	}
}

func TestParseRejectsAContentLengthOnARequestWithNoContent(t *testing.T) {
	// §8.1.1: a request is malformed if content-length "does not equal the sum of
	// the DATA frame payload lengths that form the content". END_STREAM on the
	// HEADERS frame means there will be no DATA frames, so the sum is zero and known
	// without waiting for a body.
	reason := refuse(t, req("content-length", "5"), true)
	wantReason(t, reason, "no content")
	wantReason(t, reason, "§8.1.1")
}

func TestParseAcceptsAZeroContentLengthOnARequestWithNoContent(t *testing.T) {
	r := mustParse(t, req("content-length", "0"), true)
	if r.ContentLength != 0 {
		t.Errorf("ContentLength is %d, want 0", r.ContentLength)
	}
}

func TestParseAcceptsAContentLengthOnARequestWithABodyToCome(t *testing.T) {
	// endStream false, so the sum of the DATA payloads is not known yet and the
	// comparison belongs to whoever sees the body. A check that fired on any
	// non-zero length would refuse every upload.
	r := mustParse(t, req("content-length", "5"), false)
	if r.ContentLength != 5 {
		t.Errorf("ContentLength is %d, want 5", r.ContentLength)
	}
}

// --- §8.5, CONNECT ---------------------------------------------------------

func TestParseAcceptsAConnectRequest(t *testing.T) {
	// §8.5: ":method" is CONNECT, ":scheme" and ":path" are omitted, and
	// ":authority" is the host and port to tunnel to. The shape is checked even
	// though this server does not tunnel, because a conforming CONNECT is a 501 from
	// the routing layer and a non-conforming one is malformed — and those are
	// different answers to give a client.
	f := fields(pseudoMethod, methodConnect, pseudoAuthority, "example.test:443")
	r := mustParse(t, f, false)
	if r.Method != methodConnect || r.Authority != "example.test:443" {
		t.Errorf("parsed %+v, want the method and authority as they arrived", r)
	}
	if r.Scheme != "" || r.Path != "" {
		t.Errorf("Scheme is %q and Path is %q, want both empty (RFC 9113 §8.5)", r.Scheme, r.Path)
	}
}

func TestParseRejectsAConnectRequestWithASchemeOrPath(t *testing.T) {
	for _, extra := range []struct{ name, value string }{
		{pseudoScheme, "https"},
		{pseudoPath, "/"},
	} {
		t.Run(extra.name, func(t *testing.T) {
			f := fields(pseudoMethod, methodConnect, pseudoAuthority, "example.test:443",
				extra.name, extra.value)
			wantReason(t, refuse(t, f, false), "§8.5")
		})
	}
}

func TestParseRejectsAConnectRequestWithoutAnAuthority(t *testing.T) {
	for _, tc := range []struct {
		name string
		f    []h2.Field
	}{
		{"absent", fields(pseudoMethod, methodConnect)},
		{"present and empty", fields(pseudoMethod, methodConnect, pseudoAuthority, "")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wantReason(t, refuse(t, tc.f, false), "§8.5")
		})
	}
}

func TestParseHoldsAConnectAuthorityToTheAuthorityRules(t *testing.T) {
	// §8.5 says what the authority is for and §8.3.1 still says what it may contain.
	// The userinfo rule is scoped to "http" and "https", and a CONNECT has no
	// scheme, so what is left for this to catch is the shape: an authority that ends
	// where an authority ends, and no control octets in it.
	for _, authority := range []string{"example.test:443/x", "example test:443"} {
		t.Run(authority, func(t *testing.T) {
			f := fields(pseudoMethod, methodConnect, pseudoAuthority, authority)
			refuse(t, f, false)
		})
	}
}

// --- the shape of the result ----------------------------------------------

func TestParseKeepsTheRegularFieldsWithoutThePseudoHeaders(t *testing.T) {
	f := fields(
		pseudoMethod, "POST",
		pseudoScheme, "https",
		pseudoAuthority, "example.test",
		pseudoPath, "/upload",
		"content-type", "text/plain",
		"x-first", "1",
		"x-second", "2",
	)
	r := mustParse(t, f, false)
	want := []h2.Field{
		{Name: "content-type", Value: "text/plain"},
		{Name: "x-first", Value: "1"},
		{Name: "x-second", Value: "2"},
	}
	if len(r.Fields) != len(want) {
		t.Fatalf("Fields is %v, want %v", r.Fields, want)
	}
	for i := range want {
		if r.Fields[i] != want[i] {
			t.Errorf("Fields[%d] is %v, want %v", i, r.Fields[i], want[i])
		}
	}
}

func TestParseDoesNotRetainTheFieldsItWasGiven(t *testing.T) {
	// The contract Parse documents, and the reason it matters: internal/stream hands
	// up a slice it says nothing about the lifetime of, and a Request that aliased it
	// would change under a handler if that ever became a reused buffer.
	f := req("x-foo", "original")
	r := mustParse(t, f, true)
	f[len(f)-1].Value = "overwritten"
	if r.Fields[0].Value != "original" {
		t.Errorf("Fields[0] is now %v, want the value as it was parsed: Parse retained "+
			"the caller's slice", r.Fields[0])
	}
}

func TestParseSensitiveFieldsSurviveUnchanged(t *testing.T) {
	// h2.Field.Sensitive is the HPACK never-indexed marker, and a field carrying it
	// has to reach the response path still carrying it, or a value the peer asked
	// never to be indexed would be indexed on the way back.
	f := append(req(), h2.Field{Name: "authorization", Value: "Bearer x", Sensitive: true})
	r := mustParse(t, f, true)
	if len(r.Fields) != 1 || !r.Fields[0].Sensitive {
		t.Errorf("Fields is %+v, want the sensitive marker kept", r.Fields)
	}
}

func TestParseKeepsFieldValuesOutOfItsErrors(t *testing.T) {
	// The rule malformedf documents: no regular field line's value reaches a
	// message, and neither does ":authority". These strings are logged on a path a
	// peer controls, and a regular value is where a credential lives — an
	// authorization field, a cookie, a bearer token. ":authority" is on the list
	// because the userinfo this package refuses is "user:password@host", so the
	// error that refuses it is the one most likely to write a password to a log.
	for _, tc := range []struct {
		name string
		f    []h2.Field
	}{
		{"te", req("te", secret)},
		{"a value with a CR in it", req("authorization", "Bearer \r"+secret)},
		{"a value with leading whitespace", req("cookie", " "+secret)},
		{"a content-length that is not a number", req("content-length", secret)},
		{"a Host that differs from the authority", req("host", secret+".example")},
		{"an authority with a userinfo", with(pseudoAuthority, secret+"@example.test")},
		{"an authority with a control octet", with(pseudoAuthority, secret+" x")},
		{"an authority that does not stop where one stops", with(pseudoAuthority, "example.test/"+secret)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reason := refuse(t, tc.f, false)
			if strings.Contains(reason, secret) {
				t.Errorf("the reason is %q, want it not to echo a field value", reason)
			}
		})
	}
}

// --- §8.1, trailers -------------------------------------------------------

func TestValidateTrailersAcceptsARegularFieldSection(t *testing.T) {
	if err := ValidateTrailers(testStream, fields("x-checksum", "abc123", "x-duration", "12ms")); err != nil {
		t.Errorf("ValidateTrailers: %v, want it accepted", err)
	}
}

func TestValidateTrailersAcceptsAnEmptySection(t *testing.T) {
	// A trailer section with no fields is legal and arrives as an empty block. There
	// is nothing to check and nothing to refuse.
	if err := ValidateTrailers(testStream, nil); err != nil {
		t.Errorf("ValidateTrailers(nil): %v, want it accepted", err)
	}
}

func TestValidateTrailersRejectsAPseudoHeaderField(t *testing.T) {
	// §8.1: "Trailers MUST NOT include pseudo-header fields. An endpoint that
	// receives pseudo-header fields in trailers MUST treat the request or response
	// as malformed." §8.3 says it again. It applies to a pseudo-header field that
	// would have been valid in a header section as much as to one that would not.
	for _, name := range []string{pseudoMethod, pseudoPath, ":status", ":"} {
		t.Run(name, func(t *testing.T) {
			err := ValidateTrailers(testStream, fields(name, "GET"))
			if err == nil {
				t.Fatalf("ValidateTrailers accepted %s in a trailer section (RFC 9113 §8.1)", name)
			}
			reason := reasonOf(t, err)
			if !strings.Contains(reason, "trailer section") && !strings.Contains(reason, "not lowercase") {
				t.Errorf("the reason is %q, want it to name the trailer section (RFC 9113 §8.1)", reason)
			}
		})
	}
}

func TestValidateTrailersRejectsAConnectionSpecificField(t *testing.T) {
	// §8.2.2 is a rule about a message, and a trailer section is part of one. This
	// is the classic smuggling payload: a transfer-encoding that a receiver reading
	// only the header section would never see.
	for _, name := range []string{"connection", "transfer-encoding", "upgrade", "keep-alive", "proxy-connection"} {
		t.Run(name, func(t *testing.T) {
			err := ValidateTrailers(testStream, fields(name, "chunked"))
			if err == nil {
				t.Fatalf("ValidateTrailers accepted %s in a trailer section (RFC 9113 §8.2.2)", name)
			}
			wantReason(t, reasonOf(t, err), "§8.2.2")
		})
	}
}

func TestValidateTrailersRejectsAnInvalidField(t *testing.T) {
	// §8.2.1 applies to a trailer section for the same reason §8.2.2 does.
	for _, tc := range []struct{ name, value string }{
		{"X-Checksum", "abc"},
		{"x checksum", "abc"},
		{"x-checksum", "a\rb"},
		{"x-checksum", " a"},
		{"", "abc"},
	} {
		t.Run(tc.name+"="+tc.value, func(t *testing.T) {
			if err := ValidateTrailers(testStream, fields(tc.name, tc.value)); err == nil {
				t.Fatalf("ValidateTrailers accepted %q: %q (RFC 9113 §8.2.1)", tc.name, tc.value)
			}
		})
	}
}

func TestValidateTrailersAcceptsTEWithTrailers(t *testing.T) {
	// Nonsense, and not malformed: §8.2.2's exception is not scoped to the header
	// section, and a rule that is enforced in one place and invented in another is
	// worse than either. §6.5.1 of RFC 9110 is what makes a field in a trailer
	// section ignorable, and this server ignores it by never merging the section.
	//
	// The folded spellings are here for the same reason they are in the header-section
	// test: both paths call the same checker, and the way that stops being true is a
	// change that folds in one of them.
	for _, value := range []string{"trailers", "Trailers", "TRAILERS", "TrAiLeRs"} {
		t.Run(value, func(t *testing.T) {
			if err := ValidateTrailers(testStream, fields("te", value)); err != nil {
				t.Errorf("ValidateTrailers: %v, want it accepted", err)
			}
		})
	}
}

func TestValidateTrailersRejectsTEWithAnyOtherValue(t *testing.T) {
	if err := ValidateTrailers(testStream, fields("te", "gzip")); err == nil {
		t.Fatal("ValidateTrailers accepted a TE field with a value other than \"trailers\" (RFC 9113 §8.2.2)")
	}
}

// --- the Priority header field (§5 of RFC 9218) -------------------------------

// TestParseTakesNoPriorityFromARequestWithoutTheField is the case that must cost
// nothing: no field line, no signal, and the zero Params — which §4 of RFC 9218
// resolves to urgency 3 and non-incremental without anything here saying so.
func TestParseTakesNoPriorityFromARequestWithoutTheField(t *testing.T) {
	r := mustParse(t, req(), true)

	if r.Priority != (priority.Params{}) {
		t.Errorf("Priority = %+v for a request with no Priority field, want the zero Params",
			r.Priority)
	}
	if r.Priority.Urgency() != priority.DefaultUrgency {
		t.Errorf("Priority.Urgency() = %d, want the default %d",
			r.Priority.Urgency(), priority.DefaultUrgency)
	}
	if r.Priority.HasUrgency() || r.Priority.HasIncremental() {
		t.Error("a request with no Priority field reports a parameter present")
	}
}

func TestParseReadsThePriorityField(t *testing.T) {
	tests := []struct {
		value string
		want  priority.Params
	}{
		{"u=0", priority.Params{}.WithUrgency(0)},
		{"u=7", priority.Params{}.WithUrgency(7)},
		{"i", priority.Params{}.WithIncremental(true)},
		{"u=1, i", priority.Params{}.WithUrgency(1).WithIncremental(true)},
		{"i=?0, u=6", priority.Params{}.WithUrgency(6).WithIncremental(false)},

		// An empty field line is a legal Dictionary of no members, and means what
		// sending nothing means.
		{"", priority.Params{}},

		// §4 of RFC 9218's ignore rule reaches this far: the field is read, the
		// parameter is not usable, and the request is not malformed.
		{"u=9", priority.Params{}},
		{"u=abc", priority.Params{}},
		{"unknown=1", priority.Params{}},

		// And a value that is not a Dictionary at all is the same outcome by a
		// different route — internal/priority returns an error, and this package
		// declines the MAY in §7 of RFC 9218 that would make it a connection error.
		{"u=", priority.Params{}},
		{"???", priority.Params{}},
		{"u=1 i", priority.Params{}},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			r := mustParse(t, req(fieldPriority, tt.value), true)
			if r.Priority != tt.want {
				t.Errorf("Priority = %+v, want %+v", r.Priority, tt.want)
			}
		})
	}
}

// TestParseKeepsThePriorityFieldInTheFieldList is §5 of RFC 9218's end-to-end
// property. Content-length is lifted out of the list because it describes the
// transfer; this describes what the client wants of every hop, so removing it would
// answer for the next one.
func TestParseKeepsThePriorityFieldInTheFieldList(t *testing.T) {
	r := mustParse(t, req(fieldPriority, "u=2"), true)

	var n int
	for _, f := range r.Fields {
		if f.Name == fieldPriority {
			n++
			if f.Value != "u=2" {
				t.Errorf("the Priority field line in Fields has value %q, want %q; it must be "+
					"exactly what the peer sent", f.Value, "u=2")
			}
		}
	}
	if n != 1 {
		t.Errorf("Fields carries the Priority field line %d times, want 1", n)
	}
	if !r.Priority.HasUrgency() {
		t.Error("the field was kept in Fields and not parsed into Priority; it must be both")
	}
}

// TestParseCombinesPriorityFieldLines is a MUST that belongs to the structured-field
// layer and can only be obeyed here, because this is the only place that sees more
// than one field line at a time.
//
// §4.2 of RFC 9651: "When generating input_bytes, parsers MUST combine all field lines
// in the same section (header or trailer) that case-insensitively match the field name
// into one comma-separated field-value, as per Section 5.2 of [HTTP]; this assures that
// the entire field value is processed correctly."
func TestParseCombinesPriorityFieldLines(t *testing.T) {
	tests := []struct {
		name  string
		lines []string
		want  priority.Params
	}{
		{
			name:  "two lines, one parameter each",
			lines: []string{"u=1", "i"},
			want:  priority.Params{}.WithUrgency(1).WithIncremental(true),
		},
		{
			// The combination is "u=1, u=5", and §4.2.2 of RFC 9651 keeps the last —
			// so the second line wins, exactly as a second member in one line would.
			name:  "the later line wins a duplicate",
			lines: []string{"u=1", "u=5"},
			want:  priority.Params{}.WithUrgency(5),
		},
		{
			name:  "three lines",
			lines: []string{"u=0", "i=?0", "unknown=1"},
			want:  priority.Params{}.WithUrgency(0).WithIncremental(false),
		},
		{
			// A line that does not parse takes the whole combined value with it,
			// which is what a conforming parser does: it parses the concatenation,
			// not the lines.
			name:  "one broken line breaks the field",
			lines: []string{"u=1", "u="},
			want:  priority.Params{},
		},
		{
			// The case §4.2 of RFC 9651 warns about. Combining an empty line with a
			// real one yields ", u=1", which begins with a comma and is not a
			// Dictionary — so a client that splits this field loses it.
			name:  "an empty line poisons the rest",
			lines: []string{"", "u=1"},
			want:  priority.Params{},
		},
		{
			// And the same the other way round: "u=1, " has a trailing comma.
			name:  "a trailing empty line does too",
			lines: []string{"u=1", ""},
			want:  priority.Params{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := req()
			for _, v := range tt.lines {
				f = append(f, h2.Field{Name: fieldPriority, Value: v})
			}
			r := mustParse(t, f, true)
			if r.Priority != tt.want {
				t.Errorf("Priority = %+v from lines %q, want %+v", r.Priority, tt.lines, tt.want)
			}
		})
	}
}

// TestParseIsLinearInThePriorityFieldLines is the reason the combination goes through
// a Builder. A peer may spend its whole header list on this one field name, and a
// parser that appended to a string once per line would do quadratic work on it.
//
// The assertion is the result rather than the timing — a benchmark would be a flake
// waiting to happen — so this is a correctness test with a performance argument in its
// name: it fails loudly if the combination is ever rewritten in a way that drops or
// reorders lines at scale, and it runs in the time the linear version takes.
func TestParseIsLinearInThePriorityFieldLines(t *testing.T) {
	const lines = 50000

	f := req()
	for range lines - 1 {
		f = append(f, h2.Field{Name: fieldPriority, Value: "unknown=1"})
	}
	f = append(f, h2.Field{Name: fieldPriority, Value: "u=4, i"})

	r := mustParse(t, f, true)
	want := priority.Params{}.WithUrgency(4).WithIncremental(true)
	if r.Priority != want {
		t.Errorf("Priority = %+v after %d Priority field lines, want %+v", r.Priority, lines, want)
	}
}

// TestParseIgnoresPriorityInATrailerSection records a decision rather than a rule.
// §5 of RFC 9218 puts the field in requests and responses without saying which
// section, and ValidateTrailers produces no request to hold a priority anyway — but
// the deciding argument is that a trailer arrives after the request body, which is
// after the response has been scheduled and usually after it has begun. A priority
// signal that cannot be acted on is better ignored than half applied.
func TestParseIgnoresPriorityInATrailerSection(t *testing.T) {
	if err := ValidateTrailers(testStream, fields(fieldPriority, "u=0")); err != nil {
		t.Errorf("ValidateTrailers rejected a Priority trailer field: %v; it is an ordinary "+
			"field line there and must not be an error", err)
	}
}
