"""Deliberately break internal/request/request.go, one guard at a time, and report
which tests notice.

Each entry below removes exactly one guard and names the tests that must fail as a
result. See breakage.py for the harness and for what the five outcomes mean.

request.go is RFC 9113 §8's gate, and almost every line of it is a rule with a section
number attached. That makes it the easiest file in the project to break convincingly
and the hardest to break *interestingly*: removing a check that refuses a malformed
request leaves a server that serves every well-formed request perfectly, and the only
thing that changed is what an attacker can get through it. There is no crash, no
slowdown and no failing browser. The whole value of these breaks is that each one
names a request that would then be accepted.

Three shapes of break recur, and they are worth naming because the third is the one a
green suite is least likely to catch.

  A guard removed outright -- `if false {`. The peer's fault is accepted. Every one of
  these has a test that sends exactly that fault.

  A guard narrowed by one -- `hosts > 2` where `hosts > 1` was meant, `if endStream`
  where `endStream && n != 0` was meant. These are the plausible mistakes: each leaves
  a server that refuses the obvious case and accepts the one next to it.

  A verdict changed rather than removed. malformedf's four breaks are of this kind: a
  §8.1.1 fault answered with a connection error rather than a stream error takes down
  the five other requests a browser had in flight, which is a denial of service a peer
  can trigger with one bad header field. Nothing about the refusal itself changes, so
  a test that only asked "was it refused" would pass all four. Every refusal in this
  package's tests goes through one helper that asserts the type, the stream and the
  code, which is what turns those four into failures rather than holes.

Two results are measurements rather than catches, and both stay here because the
reasoning is what a reader would otherwise have to reconstruct.

  checkAuthority's early return on an empty authority has no break, because it guards
  nothing: controlOctet("") finds no octet, IndexAny finds no delimiter and IndexByte
  finds no '@', so every check below it is already vacuous on an empty string. It is
  there to say that an absent authority is not a fault -- which §8.3.1 settles by not
  listing ":authority" as mandatory -- and removing it changes no answer this server
  gives.

  Removing checkPath's empty-path guard is detected as a panic rather than as a
  failure, on an "http" or "https" request: with the guard gone, `r.Path[0]` indexes
  a string of length zero. That is worth knowing rather than tidying away -- a peer
  can send `:path` with an empty value, so the guard is what stands between that
  field and a panicking stream goroutine. The test that reports it through the suite
  rather than through a stack trace is the one that uses a scheme other than http,
  where §8.3.1's shape rules do not apply and the empty check is the only refusal.

Run from the repository root. Restores the file on the way out, including on error.
"""

import breakage

SRC = "internal/request/request.go"
PKG = "./internal/request/"

# (name, old, new, tests that must fail)
BREAKS = [
    # --- Parse: what the walk over the field list is for ---------------------
    (
        "Parse starts a request at a declared content-length of zero rather than at none",
        """	r := &Request{ContentLength: NoContentLength}""",
        """	r := &Request{}""",
        [
            "TestParseReportsNoContentLengthWhenThereIsNone",
            "TestParseAcceptsAMinimalRequest",
        ],
    ),
    (
        "Parse holds no field line to 8.2.1, so a smuggling payload arrives intact",
        """		if err := checkField(id, f); err != nil {
			return nil, err
		}
""",
        "",
        [
            "TestParseRejectsAnUppercaseFieldName",
            "TestParseRejectsAFieldValueWithAProhibitedOctet",
            "TestParseRejectsAFieldValueSurroundedByWhitespace",
        ],
    ),
    (
        "Parse holds no regular field line to 8.2.2, so transfer-encoding gets through",
        """		if err := checkRegular(id, f); err != nil {
			return nil, err
		}
""",
        "",
        [
            "TestParseRejectsAConnectionSpecificHeaderField",
            "TestParseRejectsTEWithAnyOtherValue",
        ],
    ),
    (
        "Parse treats no field as a pseudo-header field, so no request has control data",
        """		if strings.HasPrefix(f.Name, ":") {
			if regular {""",
        """		if false {
			if regular {""",
        ["TestParseAcceptsAMinimalRequest"],
    ),
    (
        "Parse accepts a pseudo-header field hidden behind a regular field line",
        """			if regular {""",
        # And not "if false", which would leave `regular` assigned and never read --
        # a compile error, so the break would be reported as a hole in the campaign
        # rather than as a hole in the tests.
        """			if regular && false {""",
        ["TestParseRejectsAPseudoHeaderFieldAfterARegularFieldLine"],
    ),
    (
        "Parse never notices that a regular field line has been seen",
        """		regular = true
""",
        "",
        ["TestParseRejectsAPseudoHeaderFieldAfterARegularFieldLine"],
    ),
    (
        "Parse ignores a pseudo-header field 8.3.1 does not define instead of refusing it",
        """			if bit == 0 {
				return nil, malformedf(id,
					"%s is not a pseudo-header field defined for a request (RFC 9113 §8.3)", f.Name)
			}""",
        """			if bit == 0 {
				continue
			}""",
        ["TestParseRejectsAnUndefinedPseudoHeaderField"],
    ),
    (
        "Parse accepts a pseudo-header field that appears twice, last value winning",
        """			if seen&bit != 0 {""",
        """			if false {""",
        [
            "TestParseRejectsARepeatedPseudoHeaderField",
            "TestParseRejectsARepeatedPseudoHeaderFieldWithAnEmptyValue",
        ],
    ),
    (
        "Parse never records that a pseudo-header field was present",
        """			seen |= bit
""",
        "",
        [
            "TestParseAcceptsAMinimalRequest",
            "TestParseRejectsARepeatedPseudoHeaderField",
        ],
    ),
    (
        "Parse discards every pseudo-header field's value",
        """			*dst = f.Value""",
        """			_ = dst""",
        ["TestParseAcceptsAMinimalRequest"],
    ),
    (
        "Parse counts two content-length field lines as one",
        """			clen, clens = f.Value, clens+1""",
        """			clen, clens = f.Value, 1""",
        ["TestParseRejectsMoreThanOneContentLengthField"],
    ),
    (
        "Parse looks for a content-length field name 8.2 forbids a peer to send",
        """		case "content-length":""",
        """		case "Content-Length":""",
        [
            "TestParseReadsAContentLength",
            "TestParseRejectsAContentLengthOnARequestWithNoContent",
        ],
    ),
    (
        "Parse counts two Host field lines as one",
        """			host, hosts = f.Value, hosts+1""",
        """			host, hosts = f.Value, 1""",
        ["TestParseRejectsMoreThanOneHostField"],
    ),
    (
        "Parse looks for a Host field name 8.2 forbids a peer to send",
        """		case "host":""",
        """		case "Host":""",
        [
            "TestParseRejectsAHostThatDiffersFromTheAuthority",
            "TestParseTakesTheAuthorityFromHostWhenThereIsNoPseudoHeader",
            "TestParseRejectsMoreThanOneHostField",
        ],
    ),
    (
        "Parse keeps none of the regular field lines, so a handler sees no header fields",
        """		r.Fields = append(r.Fields, f)""",
        "",
        [
            "TestParseKeepsTheRegularFieldsWithoutThePseudoHeaders",
            "TestParseAcceptsATypicalBrowserRequest",
            "TestParseSensitiveFieldsSurviveUnchanged",
        ],
    ),
    (
        "Parse never checks the set of pseudo-header fields as a whole",
        """	if err := r.checkControlData(id, seen); err != nil {
		return nil, err
	}
""",
        "",
        [
            "TestParseRequiresMethodSchemeAndPath",
            "TestParseRejectsASchemeThatIsNotAScheme",
            "TestParseRejectsAnEmptyPath",
        ],
    ),
    (
        "Parse never settles what the authority is, so Host is neither used nor checked",
        """	if err := r.resolveAuthority(id, seen, host, hosts); err != nil {
		return nil, err
	}
""",
        """	_ = host
""",
        [
            "TestParseRejectsMoreThanOneHostField",
            "TestParseRejectsAHostThatDiffersFromTheAuthority",
            "TestParseTakesTheAuthorityFromHostWhenThereIsNoPseudoHeader",
        ],
    ),
    (
        "Parse never reads the content-length it collected",
        """	if err := r.setContentLength(id, clen, clens, endStream); err != nil {
		return nil, err
	}
""",
        """	_ = clen
""",
        [
            "TestParseReadsAContentLength",
            "TestParseRejectsAContentLengthOnARequestWithNoContent",
            "TestParseRejectsMoreThanOneContentLengthField",
        ],
    ),

    # --- ValidateTrailers: 8.1's one extra rule, and the two it shares -------
    (
        "ValidateTrailers holds no trailer field to 8.2.1",
        """		if err := checkField(id, f); err != nil {
			return err
		}
""",
        "",
        ["TestValidateTrailersRejectsAnInvalidField"],
    ),
    (
        "ValidateTrailers accepts a pseudo-header field in a trailer section",
        """		if strings.HasPrefix(f.Name, ":") {
			return malformedf(id,
				"the pseudo-header field %s appears in a trailer section (RFC 9113 §8.1)", f.Name)
		}
""",
        "",
        ["TestValidateTrailersRejectsAPseudoHeaderField"],
    ),
    (
        "ValidateTrailers accepts a transfer-encoding a header section would have refused",
        """		if err := checkRegular(id, f); err != nil {
			return err
		}
""",
        "",
        [
            "TestValidateTrailersRejectsAConnectionSpecificField",
            "TestValidateTrailersRejectsTEWithAnyOtherValue",
        ],
    ),

    # --- pseudo: four names, four bits, four destinations --------------------
    (
        "pseudo sends the method to the scheme, so no request has a method",
        """	case pseudoMethod:
		return hasMethod, &r.Method""",
        """	case pseudoMethod:
		return hasMethod, &r.Scheme""",
        ["TestParseAcceptsAMinimalRequest"],
    ),
    (
        "pseudo marks the scheme with the method's bit, so a valid request repeats one",
        """	case pseudoScheme:
		return hasScheme, &r.Scheme""",
        """	case pseudoScheme:
		return hasMethod, &r.Scheme""",
        ["TestParseAcceptsAMinimalRequest"],
    ),
    (
        "pseudo sends the authority to the path",
        """	case pseudoAuthority:
		return hasAuthority, &r.Authority""",
        """	case pseudoAuthority:
		return hasAuthority, &r.Path""",
        ["TestParseAcceptsAMinimalRequest"],
    ),
    (
        "pseudo marks the path with the authority's bit",
        """	case pseudoPath:
		return hasPath, &r.Path""",
        """	case pseudoPath:
		return hasAuthority, &r.Path""",
        ["TestParseAcceptsAMinimalRequest"],
    ),
    (
        "pseudo reads an undefined pseudo-header field as the method",
        """	return 0, nil""",
        """	return hasMethod, &r.Method""",
        ["TestParseRejectsAnUndefinedPseudoHeaderField"],
    ),

    # --- checkControlData: 8.3.1's required set ------------------------------
    (
        "checkControlData accepts a request with no method",
        """	if seen&hasMethod == 0 {""",
        """	if false {""",
        ["TestParseRequiresMethodSchemeAndPath"],
    ),
    (
        "checkControlData accepts a method that is not a token",
        """	if !validToken(r.Method) {""",
        """	if false {""",
        ["TestParseRejectsAMethodThatIsNotAToken"],
    ),
    (
        "checkControlData holds a CONNECT request to the rules for every other method",
        """	if r.Method == methodConnect {""",
        """	if false {""",
        [
            "TestParseAcceptsAConnectRequest",
            "TestParseRejectsAConnectRequestWithASchemeOrPath",
        ],
    ),
    (
        "checkControlData accepts a request with no scheme",
        """	if seen&hasScheme == 0 {""",
        """	if false {""",
        ["TestParseRequiresMethodSchemeAndPath"],
    ),
    (
        "checkControlData accepts a scheme that is not a scheme",
        """	if !validScheme(r.Scheme) {""",
        """	if false {""",
        ["TestParseRejectsASchemeThatIsNotAScheme"],
    ),
    (
        "checkControlData accepts a request with no path",
        """	if seen&hasPath == 0 {""",
        """	if false {""",
        ["TestParseRequiresMethodSchemeAndPath"],
    ),
    (
        "checkControlData never checks the shape of the request target",
        """	if err := r.checkPath(id); err != nil {
		return err
	}
	return r.checkAuthority(id, pseudoAuthority)""",
        """	return r.checkAuthority(id, pseudoAuthority)""",
        [
            "TestParseRejectsAnEmptyPath",
            "TestParseRejectsAPathThatIsNotAnAbsolutePath",
            "TestParseRejectsAPathWithAControlOctet",
            "TestParseRejectsTheAsteriskFormForAnyOtherMethod",
        ],
    ),
    (
        "checkControlData never checks the authority",
        """	if err := r.checkPath(id); err != nil {
		return err
	}
	return r.checkAuthority(id, pseudoAuthority)""",
        """	if err := r.checkPath(id); err != nil {
		return err
	}
	return nil""",
        [
            "TestParseRejectsUserinfoInTheAuthority",
            "TestParseRejectsAnAuthorityThatDoesNotStopWhereAnAuthorityStops",
            "TestParseRejectsAnAuthorityWithAControlOctet",
        ],
    ),

    # --- checkConnect: 8.5's shape ------------------------------------------
    (
        "checkConnect accepts a CONNECT request carrying a scheme",
        """	if seen&hasScheme != 0 {""",
        """	if false {""",
        ["TestParseRejectsAConnectRequestWithASchemeOrPath"],
    ),
    (
        "checkConnect accepts a CONNECT request carrying a path",
        """	if seen&hasPath != 0 {""",
        """	if false {""",
        ["TestParseRejectsAConnectRequestWithASchemeOrPath"],
    ),
    (
        "checkConnect accepts a CONNECT request that names nothing to tunnel to",
        """	if seen&hasAuthority == 0 || r.Authority == "" {""",
        """	if false {""",
        ["TestParseRejectsAConnectRequestWithoutAnAuthority"],
    ),
    (
        "checkConnect accepts a CONNECT request whose authority is present and empty",
        """	if seen&hasAuthority == 0 || r.Authority == "" {""",
        """	if seen&hasAuthority == 0 {""",
        ["TestParseRejectsAConnectRequestWithoutAnAuthority"],
    ),
    (
        "checkConnect never checks the authority it just insisted on",
        """		return malformedf(id, "a CONNECT request with no %s pseudo-header field (RFC 9113 §8.5)", pseudoAuthority)
	}
	return r.checkAuthority(id, pseudoAuthority)""",
        """		return malformedf(id, "a CONNECT request with no %s pseudo-header field (RFC 9113 §8.5)", pseudoAuthority)
	}
	return nil""",
        ["TestParseHoldsAConnectAuthorityToTheAuthorityRules"],
    ),

    # --- checkPath: 8.3.1's request target ----------------------------------
    (
        "checkPath accepts an empty request target",
        """	if r.Path == "" {""",
        """	if false {""",
        [
            "TestParseRejectsAnEmptyPathWhateverTheScheme",
            "TestParseRejectsAnEmptyPath",
        ],
    ),
    (
        "checkPath accepts a request target with a space in it",
        """	if c, bad := controlOctet(r.Path); bad {""",
        """	if c, bad := controlOctet(""); bad {""",
        ["TestParseRejectsAPathWithAControlOctet"],
    ),
    (
        "checkPath applies 8.3.1's http shape rules to a scheme they are not scoped to",
        """	if !isHTTPScheme(r.Scheme) {""",
        """	if false {""",
        ["TestParseLeavesTheTargetShapeAloneForANonHTTPScheme"],
    ),
    (
        "checkPath does not know the asterisk-form target, so OPTIONS * is refused",
        """	if r.Path == "*" {""",
        """	if false {""",
        ["TestParseAcceptsTheAsteriskFormForOptions"],
    ),
    (
        "checkPath accepts the asterisk-form target on a method that has no use for it",
        """		if r.Method != methodOptions {""",
        """		if false {""",
        ["TestParseRejectsTheAsteriskFormForAnyOtherMethod"],
    ),
    (
        "checkPath accepts an absolute URI as the request target, which routes elsewhere",
        """	if r.Path[0] != '/' {""",
        """	if false {""",
        ["TestParseRejectsAPathThatIsNotAnAbsolutePath"],
    ),

    # --- checkAuthority: 3986's authority, whichever field carried it -------
    (
        "checkAuthority accepts an authority with a space in it",
        """	if c, bad := controlOctet(r.Authority); bad {""",
        """	if c, bad := controlOctet(""); bad {""",
        [
            "TestParseRejectsAnAuthorityWithAControlOctet",
            "TestParseHoldsAConnectAuthorityToTheAuthorityRules",
            "TestParseHoldsAHostStandingInForTheAuthorityToTheSameRules",
        ],
    ),
    (
        "checkAuthority accepts an authority with a path glued to it",
        """	if i := strings.IndexAny(r.Authority, "/?#"); i >= 0 {""",
        """	if i := strings.IndexAny(r.Authority, ""); i >= 0 {""",
        [
            "TestParseRejectsAnAuthorityThatDoesNotStopWhereAnAuthorityStops",
            "TestParseHoldsAConnectAuthorityToTheAuthorityRules",
            "TestParseHoldsAHostStandingInForTheAuthorityToTheSameRules",
        ],
    ),
    (
        "checkAuthority does not treat a query as ending an authority",
        """strings.IndexAny(r.Authority, "/?#")""",
        """strings.IndexAny(r.Authority, "/#")""",
        ["TestParseRejectsAnAuthorityThatDoesNotStopWhereAnAuthorityStops"],
    ),
    (
        "checkAuthority refuses a userinfo for a scheme 8.3.1 scopes the rule away from",
        """	if isHTTPScheme(r.Scheme) && strings.IndexByte(r.Authority, '@') >= 0 {""",
        """	if strings.IndexByte(r.Authority, '@') >= 0 {""",
        ["TestParseAcceptsUserinfoForAnotherScheme"],
    ),
    (
        "checkAuthority accepts the deprecated userinfo subcomponent",
        """	if isHTTPScheme(r.Scheme) && strings.IndexByte(r.Authority, '@') >= 0 {""",
        """	if isHTTPScheme(r.Scheme) && false {""",
        [
            "TestParseRejectsUserinfoInTheAuthority",
            "TestParseHoldsAHostStandingInForTheAuthorityToTheSameRules",
        ],
    ),
    (
        "checkAuthority blames :authority for a userinfo the Host field carried",
        """		return malformedf(id, "%s includes a userinfo subcomponent (RFC 9113 §8.3.1)", field)""",
        """		return malformedf(id, "%s includes a userinfo subcomponent (RFC 9113 §8.3.1)", pseudoAuthority)""",
        ["TestParseHoldsAHostStandingInForTheAuthorityToTheSameRules"],
    ),
    (
        "fieldHost names the wrong field, so every Host fault is reported as :authority's",
        """const fieldHost = "the Host header field\"""",
        """const fieldHost = pseudoAuthority""",
        ["TestParseHoldsAHostStandingInForTheAuthorityToTheSameRules"],
    ),

    # --- resolveAuthority: Host against :authority --------------------------
    (
        "resolveAuthority accepts a request with two Host field lines",
        """	if hosts > 1 {""",
        """	if false {""",
        ["TestParseRejectsMoreThanOneHostField"],
    ),
    (
        "resolveAuthority permits two Host field lines and refuses three",
        """	if hosts > 1 {""",
        """	if hosts > 2 {""",
        ["TestParseRejectsMoreThanOneHostField"],
    ),
    (
        "resolveAuthority never lets Host stand in for an absent :authority",
        """	if seen&hasAuthority == 0 {""",
        """	if false {""",
        [
            "TestParseTakesTheAuthorityFromHostWhenThereIsNoPseudoHeader",
            "TestParseHoldsAHostStandingInForTheAuthorityToTheSameRules",
        ],
    ),
    (
        "resolveAuthority checks the Host it was going to use and then does not use it",
        """		r.Authority = host
		return r.checkAuthority(id, fieldHost)""",
        """		_ = host
		return r.checkAuthority(id, fieldHost)""",
        [
            "TestParseTakesTheAuthorityFromHostWhenThereIsNoPseudoHeader",
            "TestParseHoldsAHostStandingInForTheAuthorityToTheSameRules",
        ],
    ),
    (
        "resolveAuthority uses a Host as the authority without checking it first",
        """		return r.checkAuthority(id, fieldHost)""",
        """		return nil""",
        ["TestParseHoldsAHostStandingInForTheAuthorityToTheSameRules"],
    ),
    (
        "resolveAuthority accepts a Host that names a different entity from :authority",
        """	if hosts == 1 && !sameAuthority(r.Scheme, r.Authority, host) {""",
        """	if false && !sameAuthority(r.Scheme, r.Authority, host) {""",
        [
            "TestParseRejectsAHostThatDiffersFromTheAuthority",
            "TestParseRejectsAHostThatDiffersOnlyByPort",
        ],
    ),
    (
        "resolveAuthority compares Host against :authority without normalizing either",
        """	if hosts == 1 && !sameAuthority(r.Scheme, r.Authority, host) {""",
        """	if hosts == 1 && r.Authority != host {""",
        ["TestParseAcceptsAHostThatMatchesTheAuthorityAfterNormalization"],
    ),
    (
        "resolveAuthority compares :authority against a Host field that was never sent",
        """	if hosts == 1 && !sameAuthority(r.Scheme, r.Authority, host) {""",
        """	if !sameAuthority(r.Scheme, r.Authority, host) {""",
        ["TestParseAcceptsAMinimalRequest"],
    ),

    # --- setContentLength: 8.6 of RFC 9110, and half of 8.1.1 ---------------
    (
        "setContentLength permits two content-length field lines and refuses three",
        """	case clens > 1:""",
        """	case clens > 2:""",
        ["TestParseRejectsMoreThanOneContentLengthField"],
    ),
    (
        "setContentLength reads a content-length that is not a number as zero",
        """	if err != nil {
		return malformedf(id, "content-length: %v (RFC 9110 §8.6)", err)
	}""",
        """	_ = err""",
        [
            "TestParseRejectsAContentLengthThatIsNotADecimal",
            "TestParseRejectsAContentLengthThatDoesNotFitInAnInt64",
        ],
    ),
    (
        "setContentLength discards the length it parsed",
        """	r.ContentLength = n
""",
        "",
        [
            "TestParseReadsAContentLength",
            "TestParseAcceptsTheLargestContentLength",
            "TestParseAcceptsAContentLengthWithLeadingZeros",
        ],
    ),
    (
        "setContentLength accepts a content-length on a request that can have no content",
        """	if endStream && n != 0 {""",
        """	if false {""",
        ["TestParseRejectsAContentLengthOnARequestWithNoContent"],
    ),
    (
        "setContentLength refuses every content-length, body to come or not",
        """	if endStream && n != 0 {""",
        """	if n != 0 {""",
        [
            "TestParseAcceptsAContentLengthOnARequestWithABodyToCome",
            "TestParseReadsAContentLength",
        ],
    ),
    (
        "setContentLength refuses a declared zero on a request with no content",
        """	if endStream && n != 0 {""",
        """	if endStream {""",
        ["TestParseAcceptsAZeroContentLengthOnARequestWithNoContent"],
    ),

    # --- malformedf: 8.1.1's verdict, which is not the same as a refusal -----
    (
        "malformedf ends the connection over one stream's malformed request",
        """	return h2.StreamErrorf(id, h2.ProtocolError, "malformed request: "+format, args...)""",
        """	return h2.ConnErrorf(h2.ProtocolError, "malformed request: "+format, args...)""",
        [
            "TestParseRejectsAnUppercaseFieldName",
            "TestParseRejectsAContentLengthOnARequestWithNoContent",
        ],
    ),
    (
        "malformedf reports the peer's fault as this server's",
        """	return h2.StreamErrorf(id, h2.ProtocolError, "malformed request: "+format, args...)""",
        """	return h2.StreamErrorf(id, h2.InternalError, "malformed request: "+format, args...)""",
        [
            "TestParseRejectsAnUppercaseFieldName",
            "TestParseRejectsUserinfoInTheAuthority",
        ],
    ),
    (
        "malformedf resets stream 1 whatever stream the request arrived on",
        """	return h2.StreamErrorf(id, h2.ProtocolError, "malformed request: "+format, args...)""",
        """	return h2.StreamErrorf(1, h2.ProtocolError, "malformed request: "+format, args...)""",
        [
            "TestParseRejectsAnUppercaseFieldName",
            "TestValidateTrailersRejectsAPseudoHeaderField",
        ],
    ),
    (
        "malformedf drops the term 8.1.1 defines, so no log line leads back to the section",
        """	return h2.StreamErrorf(id, h2.ProtocolError, "malformed request: "+format, args...)""",
        """	return h2.StreamErrorf(id, h2.ProtocolError, format, args...)""",
        [
            "TestParseRejectsAnUppercaseFieldName",
            "TestValidateTrailersRejectsAConnectionSpecificField",
        ],
    ),
]

breakage.main(SRC, PKG, BREAKS)
