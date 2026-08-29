package request

import (
	"errors"
	"strconv"
	"strings"

	"zerodeps/zdh/internal/h2"
)

// checkField holds one field line to §8.2.1's minimal validation, which is the
// short list the RFC marks MUST rather than the full grammar of §5.1 and §5.5 of
// RFC 9110 that it marks SHOULD.
//
// The list is short because it is aimed at one attack. §8.2.1 names it: "Failure to
// validate fields can be exploited for request smuggling attacks. In particular,
// unvalidated fields might enable attacks when messages are forwarded using
// HTTP/1.1, where characters such as carriage return (CR), line feed (LF), and
// COLON are used as delimiters." Every octet refused below is one that means
// something to an HTTP/1.1 parser, and HPACK will carry all of them happily.
//
// No message in this file quotes a field value. A value is where a credential
// lives — an authorization field, a cookie, a bearer token — and an error line that
// echoed it would put it in a log, on a path a peer can trigger at will. Field
// names are quoted, because a name is not a secret and is the whole diagnosis.
// h2.Field.Sensitive is honoured by this rule rather than by consulting it: no
// value reaches a message, so no sensitive one can.
func checkField(id uint32, f h2.Field) error {
	if f.Name == "" {
		// Not in §8.2.1's list, and refused all the same: a field name is a token
		// (§5.1 of RFC 9110) and a token is at least one character. §8.2.1 asks for
		// the definitions in §5.1 to be validated, and this is the part of that
		// definition an octet check cannot express.
		return malformedf(id, "a field line with an empty name (RFC 9110 §5.1)")
	}

	// The one colon a name may contain, and only as its first octet. §8.2.1 phrases
	// the exception as being for "pseudo-header fields, which have a name that
	// starts with a single colon" — so a name beginning "::" is not a pseudo-header
	// field and falls under the ban, which is what dropping exactly one leading
	// colon here leaves the loop below to catch.
	name := f.Name
	if name[0] == ':' {
		name = name[1:]
	}
	for i := 0; i < len(name); i++ {
		switch c := name[i]; {
		case c >= 'A' && c <= 'Z':
			// §8.2's own rule — "Field names MUST be converted to lowercase when
			// constructing an HTTP/2 message" — and one of §8.1.1's named forms of
			// malformed. Reported separately from the octet range it belongs to
			// (0x41-0x5a) because it is the one a client hits by accident, and
			// "not lowercase" is the answer its author needs.
			return malformedf(id, "field name %q is not lowercase (RFC 9113 §8.2)", f.Name)
		case c <= 0x20, c >= 0x7f:
			// §8.2.1's remaining ranges: 0x00-0x20 and 0x7f-0xff. Between them they
			// cover CR, LF, NUL, SP, HTAB and every non-visible octet.
			return malformedf(id, "field name %q contains the octet 0x%02x (RFC 9113 §8.2.1)", f.Name, c)
		case c == ':':
			return malformedf(id, "field name %q contains a colon (RFC 9113 §8.2.1)", f.Name)
		}
	}

	for i := 0; i < len(f.Value); i++ {
		switch c := f.Value[i]; c {
		case 0x00, 0x0a, 0x0d:
			// §8.2.1: NUL, LF and CR are forbidden "at any position". These three
			// are the smuggling payload itself — a value carrying CRLF becomes two
			// field lines the moment it is written into an HTTP/1.1 message.
			return malformedf(id, "the value of field %q contains the octet 0x%02x (RFC 9113 §8.2.1)", f.Name, c)
		}
	}
	if len(f.Value) > 0 {
		// §8.2.1: "A field value MUST NOT start or end with an ASCII whitespace
		// character". An empty value has no first or last octet and is legal; the
		// length check is what keeps this from being an index into nothing.
		if c := f.Value[0]; c == ' ' || c == '\t' {
			return malformedf(id, "the value of field %q starts with whitespace (RFC 9113 §8.2.1)", f.Name)
		}
		if c := f.Value[len(f.Value)-1]; c == ' ' || c == '\t' {
			return malformedf(id, "the value of field %q ends with whitespace (RFC 9113 §8.2.1)", f.Name)
		}
	}
	return nil
}

// checkRegular holds a regular field line to §8.2.2, which bans the fields whose
// meaning belongs to one hop of an HTTP/1.1 connection and has no place in a
// protocol that multiplexes.
//
// Only regular field lines reach here. A pseudo-header field cannot be one of these
// names — every one of them would need a leading colon to be a pseudo-header field,
// and with one it is an undefined pseudo-header field instead.
func checkRegular(id uint32, f h2.Field) error {
	switch f.Name {
	case "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade":
		// §8.2.2's list, verbatim: the Connection header field "and those listed as
		// having connection-specific semantics in Section 7.6.1 of [HTTP] (that is,
		// Proxy-Connection, Keep-Alive, Transfer-Encoding, and Upgrade)". Any
		// message containing one is malformed.
		//
		// transfer-encoding is the one that matters most. HTTP/2 has no chunked
		// encoding — §8.1 says the HTTP/1.1 one "cannot be used in HTTP/2" — so a
		// peer sending it is either confused or arranging for this server and the
		// next hop to disagree about where the body ends, which is the original
		// request-smuggling primitive.
		return malformedf(id, "the connection-specific header field %q (RFC 9113 §8.2.2)", f.Name)

	case "te":
		// §8.2.2's single exception: TE "MAY be present in an HTTP/2 request; when
		// it is, it MUST NOT contain any value other than 'trailers'". So one value,
		// that value, and no list — "trailers, deflate" is a transfer coding being
		// requested through the one field HTTP/2 left open.
		//
		// Folded case, because a transfer-coding name is case-insensitive (§10.1.4
		// of RFC 9110). Nothing else about the value is normalized: a value with
		// surrounding whitespace has already been refused by checkField, so the
		// comparison is against exactly what arrived.
		if !asciiEqualFold(f.Value, "trailers") {
			return malformedf(id, "a TE header field with a value other than \"trailers\" (RFC 9113 §8.2.2)")
		}
	}
	return nil
}

// validToken reports whether s is a non-empty HTTP token (§5.6.2 of RFC 9110),
// which is what a method name is.
func validToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !tokenChar(s[i]) {
			return false
		}
	}
	return true
}

// tokenChar reports whether c is a tchar (§5.6.2 of RFC 9110).
//
// The set is spelled out rather than expressed as "visible ASCII minus the
// delimiters", because the delimiters are the point: every one of "(),/:;<=>?@[\]{}
// and the double quote is excluded, and those are exactly the octets that would let
// a method be read as more than a method by something downstream.
func tokenChar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	switch c {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}
	return false
}

// validScheme reports whether s is a URI scheme (§3.1 of RFC 3986):
// ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ).
func validScheme(s string) bool {
	if s == "" {
		return false
	}
	if c := s[0]; !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
		return false
	}
	for i := 1; i < len(s); i++ {
		switch c := s[i]; {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '+', c == '-', c == '.':
		default:
			return false
		}
	}
	return true
}

// controlOctet returns the first octet of s that no part of a URI may contain
// unencoded, and whether there was one.
//
// The set is the ASCII controls, SP and DEL — everything at or below 0x20, plus
// 0x7f. It stops there rather than at 0x7f-0xff for the reason given in
// Request.checkPath: those octets are ambiguous to a strict URI parser and
// unambiguous to route on, and real clients send them.
func controlOctet(s string) (byte, bool) {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= 0x20 || c == 0x7f {
			return c, true
		}
	}
	return 0, false
}

// isHTTPScheme reports whether scheme is "http" or "https", the two §8.3.1 scopes
// several of its rules to.
//
// Folded case, because a scheme is case-insensitive (§3.1 of RFC 3986) and §8.2's
// lowercase rule is about field *names*: ":scheme" is a name, "HTTPS" is a value,
// and nothing requires a peer to lowercase it. A comparison that missed that would
// silently exempt "HTTP" from the ":path" and userinfo rules, which is the exemption
// an attacker would ask for.
func isHTTPScheme(scheme string) bool {
	return asciiEqualFold(scheme, "http") || asciiEqualFold(scheme, "https")
}

// sameAuthority reports whether an ":authority" and a Host header field identify
// the same entity, under the normalization §8.3.1 requires.
//
// §8.3.1: "The values of fields need to be normalized to compare them (see
// Section 6.2 of [RFC3986]). An origin server can apply any normalization method,
// whereas other servers MUST perform scheme-based normalization (see Section 6.2.3
// of [RFC3986]) of the two fields." This server is an origin server, so the licence
// is broad; what it does is the narrow thing the stricter clause names, which is
// case folding of the authority and dropping the scheme's default port.
//
// It is deliberately not more clever than that. Every additional normalization —
// resolving a name, folding percent-encodings, comparing IP literals numerically —
// makes two authorities that differ textually compare equal, and this comparison
// exists to catch a request whose two authorities differ. A false "same" here is a
// smuggled request; a false "different" is a malformed-request error for a client
// that sent an unusual but consistent pair, which no client does.
func sameAuthority(scheme, authority, host string) bool {
	return normalizeAuthority(scheme, authority) == normalizeAuthority(scheme, host)
}

// normalizeAuthority folds an authority's case and removes the port if it is the
// default for scheme (§6.2.3 of RFC 3986).
func normalizeAuthority(scheme, authority string) string {
	a := asciiLower(authority)
	switch {
	case asciiEqualFold(scheme, "http"):
		// TrimSuffix and not a split on the last colon, which would need a rule for
		// the colons inside an IPv6 literal. "[::1]:80" ends with ":80" and trims to
		// "[::1]"; "[::1]" does not and is left alone.
		return strings.TrimSuffix(a, ":80")
	case asciiEqualFold(scheme, "https"):
		return strings.TrimSuffix(a, ":443")
	}
	return a
}

// asciiEqualFold reports whether s and t are equal with ASCII case folded.
//
// Here rather than strings.EqualFold, which folds Unicode: it reports the Kelvin
// sign equal to "k" and the Latin long s equal to "s". For a protocol comparison
// that is the wrong answer twice over — a peer could spell "trailers" or "https" in
// a way no other HTTP/2 implementation would accept, and a name that folded to a
// forbidden one would slip past a check aimed at it.
func asciiEqualFold(s, t string) bool {
	if len(s) != len(t) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if asciiLowerByte(s[i]) != asciiLowerByte(t[i]) {
			return false
		}
	}
	return true
}

// asciiLower is s with its ASCII uppercase letters folded down, and every other
// octet left exactly as it arrived.
func asciiLower(s string) string {
	upper := false
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			upper = true
			break
		}
	}
	if !upper {
		// The common case by a wide margin: an authority a client sent in lowercase,
		// which is every browser and every curl. Returning s avoids a copy per
		// comparison.
		return s
	}
	b := []byte(s)
	for i := range b {
		b[i] = asciiLowerByte(b[i])
	}
	return string(b)
}

// asciiLowerByte folds one ASCII letter down and leaves everything else alone.
func asciiLowerByte(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

// The two ways a content-length can fail to be one. Sentinels rather than strings
// built at the call site, so that a test can name the case it is asserting.
var (
	errNotDecimal = errors.New("not a decimal number")
	errTooLarge   = errors.New("larger than 2^63-1")
)

// parseContentLength reads a content-length field value, which §8.6 of RFC 9110
// defines as 1*DIGIT and nothing else.
//
// The digit check is by hand rather than left to strconv, which accepts a leading
// sign and an underscore separator in some bases. "+0" is not a content-length, and
// a receiver that read it as one would disagree with a receiver that did not — by
// the whole length of the body, which is the disagreement smuggling is made of.
func parseContentLength(s string) (int64, error) {
	if s == "" {
		return 0, errNotDecimal
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < '0' || c > '9' {
			return 0, errNotDecimal
		}
	}
	// bitSize 63 rather than 64: the value becomes an int64 that is compared against
	// a sum of frame lengths, and a length that does not fit in one is not a length
	// this server can account for. It is also, at 9.2 exabytes, not a body.
	n, err := strconv.ParseUint(s, 10, 63)
	if err != nil {
		return 0, errTooLarge
	}
	return int64(n), nil
}
