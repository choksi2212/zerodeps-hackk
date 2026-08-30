"""Deliberately break internal/request/fields.go, one guard at a time, and report
which tests notice.

Each entry below removes exactly one guard and names the tests that must fail as a
result. See breakage.py for the harness and for what the five outcomes mean.

fields.go is where §8.2.1's octet rules live, and it is the file in this project with
the highest ratio of consequence to line count. The whole of checkField is four loops
and two comparisons, and every one of them stands between a peer's field line and an
HTTP/1.1 message written downstream. §8.2.1 says why in one sentence: "Failure to
validate fields can be exploited for request smuggling attacks."

So the breaks here are mostly off-by-one, and deliberately so. Removing a check
outright is the mistake nobody makes twice; narrowing one by a single octet is the
mistake that ships. Each of these pairs a removal with the narrowing next to it:

  0x20 and 0x7f are both prohibited name octets and both sit one step from a legal
  one, so `c <= 0x20` becomes `c < 0x20` and `c >= 0x7f` becomes `c == 0x7f`. The
  first accepts a space in a field name; the second accepts every octet from 0x80 up.

  The whitespace rule is about "ASCII whitespace", which is two characters. Dropping
  the HTAB half of either end leaves a server that refuses " a" and accepts "\ta".

  A loop over a value becomes a look at its first octet. That one is worth its place
  because it passes the obvious test: a value that *starts* with CR is still caught,
  and the smuggling payload does not start with CR, it contains one.

  ParseUint's bitSize goes from 63 to 64. Nothing is removed and nothing is narrowed:
  a content-length of 2^63 now parses, becomes a negative int64, and is accepted as
  the declared length of a body. The comment on that line is the only thing standing
  between this server and a negative length, which is why it has a break.

Three guards are detected as panics rather than as failures, and all three are load-
bearing for that reason. checkField's empty-name check is what keeps `name[0]` from
indexing nothing; its `len(f.Value) > 0` is what keeps the whitespace check from
indexing an empty value, which a peer can send at will; and asciiEqualFold's length
check is what keeps `t[i]` inside t when a peer sends a TE of "trailersx". A guard
whose absence is a panic is a guard whose absence is a denial of service.

Two regions have no break, and the reasoning is the point.

  asciiLower's fast path -- `if !upper { return s }` -- has one on the condition but
  none on the return itself, because returning s when s has no uppercase letter and
  folding s when it has none produce the same string. It is a copy avoided, not a
  rule, and the only way to observe it is with an allocation count.

  normalizeAuthority's final `return a` for a scheme that is neither http nor https
  is unreachable from this package's tests: sameAuthority is only called when there
  is both an ":authority" and a Host, and no test builds that pair on a third scheme.
  Naming it here is cheaper than a test that asserts nothing.

Run from the repository root. Restores the file on the way out, including on error.
"""

import breakage

SRC = "internal/request/fields.go"
PKG = "./internal/request/"

# (name, old, new, tests that must fail)
BREAKS = [
    # --- checkField: 8.2.1's minimal validation ------------------------------
    (
        "checkField accepts a field line with no name, and indexes its first octet",
        """	if f.Name == "" {""",
        """	if false {""",
        ["TestParseRejectsAFieldLineWithAnEmptyName"],
    ),
    (
        "checkField holds a pseudo-header field's leading colon against it",
        """	if name[0] == ':' {
		name = name[1:]
	}
""",
        "",
        ["TestParseAcceptsAMinimalRequest"],
    ),
    (
        "checkField strips every leading colon, so \"::method\" becomes a legal name",
        """	if name[0] == ':' {""",
        """	for name != "" && name[0] == ':' {""",
        ["TestParseRejectsAFieldNameWithAColon"],
    ),
    (
        "checkField exempts a pseudo-header field's name from every octet rule",
        """		name = name[1:]""",
        """		name = \"\"""",
        ["TestParseRejectsAnUppercaseFieldName"],
    ),
    (
        "checkField accepts an uppercase field name, which 8.2 forbids a peer to send",
        """		case c >= 'A' && c <= 'Z':""",
        """		case false:""",
        ["TestParseRejectsAnUppercaseFieldName"],
    ),
    (
        "checkField accepts every prohibited octet in a field name",
        """		case c <= 0x20, c >= 0x7f:""",
        """		case false:""",
        ["TestParseRejectsAFieldNameWithAProhibitedOctet"],
    ),
    (
        "checkField accepts a space in a field name, one octet inside 8.2.1's range",
        """		case c <= 0x20, c >= 0x7f:""",
        """		case c < 0x20, c >= 0x7f:""",
        ["TestParseRejectsAFieldNameWithAProhibitedOctet"],
    ),
    (
        "checkField accepts every octet above DEL in a field name",
        """		case c <= 0x20, c >= 0x7f:""",
        """		case c <= 0x20, c == 0x7f:""",
        ["TestParseRejectsAFieldNameWithAProhibitedOctet"],
    ),
    (
        "checkField accepts a colon inside a field name, which is a delimiter downstream",
        """		case c == ':':""",
        """		case false:""",
        ["TestParseRejectsAFieldNameWithAColon"],
    ),
    (
        "checkField checks only the first octet of a field name",
        """	for i := 0; i < len(name); i++ {""",
        """	for i := 0; i < 1 && i < len(name); i++ {""",
        [
            "TestParseRejectsAFieldNameWithAProhibitedOctet",
            "TestParseRejectsAFieldNameWithAColon",
        ],
    ),
    (
        "checkField accepts a NUL in a field value",
        """		case 0x00, 0x0a, 0x0d:""",
        """		case 0x0a, 0x0d:""",
        ["TestParseRejectsAFieldValueWithAProhibitedOctet"],
    ),
    (
        "checkField accepts an LF in a field value, which ends a line downstream",
        """		case 0x00, 0x0a, 0x0d:""",
        """		case 0x00, 0x0d:""",
        ["TestParseRejectsAFieldValueWithAProhibitedOctet"],
    ),
    (
        "checkField accepts a CR in a field value, which is half of a CRLF downstream",
        """		case 0x00, 0x0a, 0x0d:""",
        """		case 0x00, 0x0a:""",
        ["TestParseRejectsAFieldValueWithAProhibitedOctet"],
    ),
    (
        "checkField checks only the first octet of a field value",
        """	for i := 0; i < len(f.Value); i++ {""",
        """	for i := 0; i < 1 && i < len(f.Value); i++ {""",
        ["TestParseRejectsAFieldValueWithAProhibitedOctet"],
    ),
    (
        "checkField indexes the ends of a value that has no ends",
        """	if len(f.Value) > 0 {""",
        """	if true {""",
        ["TestParseAcceptsAnEmptyFieldValue"],
    ),
    (
        "checkField accepts a field value that starts with whitespace",
        r"""		if c := f.Value[0]; c == ' ' || c == '\t' {""",
        """		if false {""",
        ["TestParseRejectsAFieldValueSurroundedByWhitespace"],
    ),
    (
        "checkField reads only a space as leading whitespace, and not a tab",
        r"""		if c := f.Value[0]; c == ' ' || c == '\t' {""",
        """		if c := f.Value[0]; c == ' ' {""",
        ["TestParseRejectsAFieldValueSurroundedByWhitespace"],
    ),
    (
        "checkField accepts a field value that ends with whitespace",
        r"""		if c := f.Value[len(f.Value)-1]; c == ' ' || c == '\t' {""",
        """		if false {""",
        ["TestParseRejectsAFieldValueSurroundedByWhitespace"],
    ),
    (
        "checkField reads only a space as trailing whitespace, and not a tab",
        r"""		if c := f.Value[len(f.Value)-1]; c == ' ' || c == '\t' {""",
        """		if c := f.Value[len(f.Value)-1]; c == ' ' {""",
        ["TestParseRejectsAFieldValueSurroundedByWhitespace"],
    ),

    # --- checkRegular: 8.2.2's connection-specific fields --------------------
    (
        "checkRegular accepts a transfer-encoding, the original smuggling primitive",
        """	case "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade":""",
        """	case "connection", "proxy-connection", "keep-alive", "upgrade":""",
        ["TestParseRejectsAConnectionSpecificHeaderField"],
    ),
    (
        "checkRegular accepts a Connection header field",
        """	case "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade":""",
        """	case "proxy-connection", "keep-alive", "transfer-encoding", "upgrade":""",
        [
            "TestParseRejectsAConnectionSpecificHeaderField",
            "TestValidateTrailersRejectsAConnectionSpecificField",
        ],
    ),
    (
        "checkRegular accepts a Proxy-Connection header field",
        """	case "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade":""",
        """	case "connection", "keep-alive", "transfer-encoding", "upgrade":""",
        ["TestParseRejectsAConnectionSpecificHeaderField"],
    ),
    (
        "checkRegular accepts a Keep-Alive header field",
        """	case "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade":""",
        """	case "connection", "proxy-connection", "transfer-encoding", "upgrade":""",
        ["TestParseRejectsAConnectionSpecificHeaderField"],
    ),
    (
        "checkRegular accepts an Upgrade header field",
        """	case "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade":""",
        """	case "connection", "proxy-connection", "keep-alive", "transfer-encoding":""",
        ["TestParseRejectsAConnectionSpecificHeaderField"],
    ),
    (
        "checkRegular looks for a TE field name 8.2 forbids a peer to send",
        """	case "te":""",
        """	case "TE":""",
        [
            "TestParseRejectsTEWithAnyOtherValue",
            "TestValidateTrailersRejectsTEWithAnyOtherValue",
        ],
    ),
    (
        "checkRegular accepts a TE requesting any transfer coding it likes",
        """		if !asciiEqualFold(f.Value, "trailers") {""",
        """		if false {""",
        [
            "TestParseRejectsTEWithAnyOtherValue",
            "TestValidateTrailersRejectsTEWithAnyOtherValue",
        ],
    ),
    (
        "checkRegular compares a TE value case-sensitively, though a coding name folds",
        """		if !asciiEqualFold(f.Value, "trailers") {""",
        """		if f.Value != "trailers" {""",
        [
            "TestParseAcceptsTEWithTrailers",
            "TestValidateTrailersAcceptsTEWithTrailers",
        ],
    ),
    (
        "checkRegular accepts a TE that contains trailers rather than one that is it",
        """		if !asciiEqualFold(f.Value, "trailers") {""",
        """		if !strings.Contains(asciiLower(f.Value), "trailers") {""",
        ["TestParseRejectsTEWithAnyOtherValue"],
    ),

    # --- validToken: a method is a token ------------------------------------
    (
        "validToken calls the empty string a token, so a request may have no method",
        """func validToken(s string) bool {
	if s == "" {
		return false
	}
""",
        """func validToken(s string) bool {
""",
        ["TestParseRejectsAMethodThatIsNotAToken"],
    ),
    (
        "validToken accepts any octet in a method, including the space in a request line",
        """		if !tokenChar(s[i]) {""",
        """		if false {""",
        ["TestParseRejectsAMethodThatIsNotAToken"],
    ),
    (
        "validToken checks only the first octet of a method",
        """	for i := 0; i < len(s); i++ {
		if !tokenChar(s[i]) {""",
        """	for i := 0; i < 1 && i < len(s); i++ {
		if !tokenChar(s[i]) {""",
        ["TestParseRejectsAMethodThatIsNotAToken"],
    ),

    # --- tokenChar: 5.6.2's tchar set, narrowed --------------------------------
    (
        "tokenChar excludes digits, so a versioned method is malformed",
        """	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':""",
        """	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':""",
        ["TestParseAcceptsAnUnrecognisedMethod"],
    ),
    (
        "tokenChar excludes the hyphen, so M-SEARCH is malformed",
        """'*', '+', '-', '.', '^'""",
        """'*', '+', '.', '^'""",
        ["TestParseAcceptsAnUnrecognisedMethod"],
    ),

    # --- validScheme: 3.1 of RFC 3986 ----------------------------------------
    (
        "validScheme indexes the first octet of a scheme that has none",
        """func validScheme(s string) bool {
	if s == "" {
		return false
	}
""",
        """func validScheme(s string) bool {
""",
        ["TestParseRejectsASchemeThatIsNotAScheme"],
    ),
    (
        "validScheme lets a scheme start with anything a scheme may contain",
        """	if c := s[0]; !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
		return false
	}
""",
        "",
        ["TestParseRejectsASchemeThatIsNotAScheme"],
    ),
    (
        "validScheme checks only the first octet of a scheme",
        """	for i := 1; i < len(s); i++ {""",
        """	for i := 1; i < 1; i++ {""",
        ["TestParseRejectsASchemeThatIsNotAScheme"],
    ),
    (
        "validScheme allows only letters and digits after the first octet",
        """		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '+', c == '-', c == '.':""",
        """		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':""",
        ["TestParseAcceptsASchemeThatIsNotHTTP"],
    ),

    # --- controlOctet: what no part of a URI may carry unencoded ---------------
    (
        "controlOctet allows a space, so a request target can carry a request line",
        """		if c := s[i]; c <= 0x20 || c == 0x7f {""",
        """		if c := s[i]; c < 0x20 || c == 0x7f {""",
        [
            "TestParseRejectsAPathWithAControlOctet",
            "TestParseRejectsAnAuthorityWithAControlOctet",
        ],
    ),
    (
        "controlOctet allows DEL",
        """		if c := s[i]; c <= 0x20 || c == 0x7f {""",
        """		if c := s[i]; c <= 0x20 {""",
        ["TestParseRejectsAPathWithAControlOctet"],
    ),
    (
        "controlOctet looks at the first octet only",
        """	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= 0x20 || c == 0x7f {""",
        """	for i := 0; i < 1 && i < len(s); i++ {
		if c := s[i]; c <= 0x20 || c == 0x7f {""",
        ["TestParseRejectsAPathWithAControlOctet"],
    ),

    # --- isHTTPScheme: the two schemes 8.3.1 scopes its rules to ---------------
    (
        "isHTTPScheme compares case-sensitively, exempting \"HTTPS\" from 8.3.1's rules",
        """	return asciiEqualFold(scheme, "http") || asciiEqualFold(scheme, "https")""",
        """	return scheme == "http" || scheme == "https\"""",
        ["TestParseRejectsUserinfoInTheAuthority"],
    ),
    (
        "isHTTPScheme does not count https, exempting every TLS request from 8.3.1",
        """	return asciiEqualFold(scheme, "http") || asciiEqualFold(scheme, "https")""",
        """	return asciiEqualFold(scheme, "http")""",
        [
            "TestParseRejectsUserinfoInTheAuthority",
            "TestParseRejectsAPathThatIsNotAnAbsolutePath",
        ],
    ),
    (
        "isHTTPScheme counts every scheme, applying http's shape rules to all of them",
        """	return asciiEqualFold(scheme, "http") || asciiEqualFold(scheme, "https")""",
        """	return true""",
        [
            "TestParseLeavesTheTargetShapeAloneForANonHTTPScheme",
            "TestParseAcceptsUserinfoForAnotherScheme",
        ],
    ),

    # --- sameAuthority: 8.3.1's comparison -----------------------------------
    (
        "sameAuthority compares two authorities without normalizing either",
        """	return normalizeAuthority(scheme, authority) == normalizeAuthority(scheme, host)""",
        """	return authority == host""",
        ["TestParseAcceptsAHostThatMatchesTheAuthorityAfterNormalization"],
    ),
    (
        "sameAuthority normalizes the authority and not the Host it is compared with",
        """	return normalizeAuthority(scheme, authority) == normalizeAuthority(scheme, host)""",
        """	return normalizeAuthority(scheme, authority) == host""",
        ["TestParseAcceptsAHostThatMatchesTheAuthorityAfterNormalization"],
    ),
    (
        "sameAuthority answers backwards, so agreeing fields are the malformed ones",
        """	return normalizeAuthority(scheme, authority) == normalizeAuthority(scheme, host)""",
        """	return normalizeAuthority(scheme, authority) != normalizeAuthority(scheme, host)""",
        [
            "TestParseIgnoresHostWhenTheAuthorityIsPresentAndTheyAgree",
            "TestParseAcceptsAHostThatMatchesTheAuthorityAfterNormalization",
        ],
    ),

    # --- normalizeAuthority: 6.2.3 of RFC 3986 -------------------------------
    (
        "normalizeAuthority does not fold case, so Example.Test is another entity",
        """	a := asciiLower(authority)""",
        """	a := authority""",
        ["TestParseAcceptsAHostThatMatchesTheAuthorityAfterNormalization"],
    ),
    (
        "normalizeAuthority keeps http's default port, so :80 differs from no port",
        """		return strings.TrimSuffix(a, ":80")""",
        """		return a""",
        ["TestParseAcceptsAHostThatMatchesTheAuthorityAfterNormalization"],
    ),
    (
        "normalizeAuthority keeps https's default port, so :443 differs from no port",
        """		return strings.TrimSuffix(a, ":443")""",
        """		return a""",
        ["TestParseAcceptsAHostThatMatchesTheAuthorityAfterNormalization"],
    ),
    (
        "normalizeAuthority drops the other scheme's default port from an https authority",
        """		return strings.TrimSuffix(a, ":443")""",
        """		return strings.TrimSuffix(a, ":80")""",
        [
            "TestParseAcceptsAHostThatMatchesTheAuthorityAfterNormalization",
            "TestParseRejectsAHostThatDiffersOnlyByPort",
        ],
    ),
    (
        "normalizeAuthority drops a port by cutting at the last colon, and IPv6 has many",
        """		return strings.TrimSuffix(a, ":443")""",
        """		if i := strings.LastIndexByte(a, ':'); i >= 0 {
			return a[:i]
		}
		return a""",
        [
            "TestParseAcceptsAHostThatMatchesTheAuthorityAfterNormalization",
            "TestParseRejectsAHostThatDiffersOnlyByPort",
        ],
    ),

    # --- asciiEqualFold and the two functions under it -----------------------
    (
        "asciiEqualFold reads past the end of the shorter string",
        """	if len(s) != len(t) {
		return false
	}
""",
        "",
        ["TestParseRejectsTEWithAnyOtherValue"],
    ),
    (
        "asciiEqualFold does not fold, so it is strings.Compare with extra steps",
        """		if asciiLowerByte(s[i]) != asciiLowerByte(t[i]) {""",
        """		if s[i] != t[i] {""",
        [
            "TestParseAcceptsTEWithTrailers",
            "TestParseRejectsUserinfoInTheAuthority",
        ],
    ),
    (
        "asciiLower takes the fast path exactly when there is uppercase to fold",
        """	if !upper {""",
        """	if upper {""",
        ["TestParseAcceptsAHostThatMatchesTheAuthorityAfterNormalization"],
    ),
    (
        "asciiLower copies the string and folds nothing",
        """	for i := range b {
		b[i] = asciiLowerByte(b[i])
	}
""",
        "",
        ["TestParseAcceptsAHostThatMatchesTheAuthorityAfterNormalization"],
    ),
    (
        "asciiLowerByte returns every octet as it arrived",
        """	if c >= 'A' && c <= 'Z' {""",
        """	if false {""",
        ["TestParseAcceptsAHostThatMatchesTheAuthorityAfterNormalization"],
    ),

    # --- parseContentLength: 8.6 of RFC 9110 is 1*DIGIT ----------------------
    (
        "parseContentLength reports an empty content-length as one too large to hold",
        """	if s == "" {
		return 0, errNotDecimal
	}
""",
        "",
        ["TestParseRejectsAContentLengthThatIsNotADecimal"],
    ),
    (
        "parseContentLength leaves the digits to strconv, which takes a sign",
        """	for i := 0; i < len(s); i++ {
		if c := s[i]; c < '0' || c > '9' {
			return 0, errNotDecimal
		}
	}
""",
        "",
        ["TestParseRejectsAContentLengthThatIsNotADecimal"],
    ),
    (
        "parseContentLength checks only the first digit",
        """	for i := 0; i < len(s); i++ {
		if c := s[i]; c < '0' || c > '9' {""",
        """	for i := 0; i < 1 && i < len(s); i++ {
		if c := s[i]; c < '0' || c > '9' {""",
        ["TestParseRejectsAContentLengthThatIsNotADecimal"],
    ),
    (
        "parseContentLength ignores the range error and keeps the clamped value",
        """	if err != nil {
		return 0, errTooLarge
	}""",
        """	if err != nil && false {
		return 0, errTooLarge
	}""",
        ["TestParseRejectsAContentLengthThatDoesNotFitInAnInt64"],
    ),
    (
        "parseContentLength parses into 64 bits, so 2^63 becomes a negative length",
        """	n, err := strconv.ParseUint(s, 10, 63)""",
        """	n, err := strconv.ParseUint(s, 10, 64)""",
        ["TestParseRejectsAContentLengthThatDoesNotFitInAnInt64"],
    ),
    (
        "parseContentLength returns zero for every content-length it accepts",
        """	return int64(n), nil""",
        # The discard keeps `n` read: without it the break is a compile error, which
        # the harness reports as a hole in the campaign rather than in the tests.
        """	_ = n
	return 0, nil""",
        [
            "TestParseReadsAContentLength",
            "TestParseAcceptsTheLargestContentLength",
            "TestParseAcceptsAContentLengthWithLeadingZeros",
        ],
    ),
]

breakage.main(SRC, PKG, BREAKS)
