package response

import (
	"errors"
	"fmt"
	"strings"

	"zerodeps/zdh/internal/h2"
)

// ErrMalformedResponse is returned when a field list this server built breaks one of
// the rules in §8.2 or §8.3. Every message from checkSection wraps it.
//
// One sentinel for the lot, because there is only one thing a caller does about them:
// the response cannot be sent, the fault is on this side, and the stream layer's
// answer is a 500 or a RST_STREAM. It is separate from ErrHeaderListTooLarge for the
// same reason in reverse — that one is not a fault at all, and a caller can respond to
// it by sending something shorter.
var ErrMalformedResponse = errors.New("response: malformed response")

// section is which of §8.1's two field lists is being checked. The rules differ in
// exactly one place, and it is the place a mistake is dangerous: §8.3 requires a
// ":status" in a header section and forbids every pseudo-header field in a trailer
// section, so one function with one bool is what keeps the two from being checked
// against each other's rules.
type section int

const (
	sectionHeader section = iota
	sectionTrailer
)

// pseudoStatus is the only pseudo-header field §8.3.2 defines for a response.
//
// The set is closed. §8.3 makes any other pseudo-header field in a response malformed
// — including the four request ones, which a handler could reach for by copying a
// request's field list into its reply, and which would tell the client something about
// its own request rather than about the response.
const pseudoStatus = ":status"

// checkSection holds one of a response's field lists to §8.2 and §8.3.
//
// # Why this is not internal/request's checkField
//
// The two overlap in the eight lines that refuse the octets §8.2.1 names, and diverge
// everywhere else. The pseudo-header sets are disjoint — §8.3.1's four against
// §8.3.2's one — the required set differs, §8.2.2's TE exception is for requests only,
// and the trailer rule exists on this side because a response is the only message this
// server sends one on. Most of all the *outcome* differs: internal/request produces an
// h2.StreamError, because a malformed request is the peer's and is answered on the
// wire with the code §8.1.1 names, while a malformed response is this server's own bug
// and produces a plain error that must never be turned into a frame. Sharing the code
// would mean sharing the error, and the error is the part that says whose fault it is.
//
// The value of a field never appears in a message here, and that rule is worth as
// much on this side as on the request side: a response value is a Set-Cookie, an
// authorization challenge, a signed URL. Names are quoted, because a name is not a
// secret and is the whole diagnosis. h2.Field.Sensitive is honoured by construction
// rather than consulted — no value reaches a message, so no sensitive one can.
func checkSection(kind section, fields []h2.Field) error {
	var (
		status  bool
		regular bool
	)
	for _, f := range fields {
		if err := checkFieldLine(f); err != nil {
			return err
		}

		// A pseudo-header field is one whose name starts with a colon, and an empty
		// name has already been refused by checkFieldLine — so this needs no length
		// guard of its own, and does not carry one. A guard on a case that cannot
		// happen is a guard no test can reach, and this file's rule is that every
		// branch here is one the table in fields_test.go can drive.
		if !strings.HasPrefix(f.Name, ":") {
			regular = true
			if err := checkRegular(f); err != nil {
				return err
			}
			continue
		}

		// §8.3: "All pseudo-header fields MUST appear in a field block before all
		// regular field lines." Checked as "no pseudo-header field after a regular
		// one", which is the same rule stated in the order the list arrives in, and
		// so needs no second pass.
		if regular {
			return malformedf("the pseudo-header field %q after a regular field line (RFC 9113 §8.3)", f.Name)
		}
		if kind == sectionTrailer {
			// §8.3: "Pseudo-header fields MUST NOT appear in a trailer section." The
			// reason is §8.1's: a trailer section arrives after the response has been
			// acted on, so a ":status" in one would be a second answer to a question
			// already answered.
			return malformedf("the pseudo-header field %q in a trailer section (RFC 9113 §8.3)", f.Name)
		}
		if f.Name != pseudoStatus {
			return malformedf("the undefined pseudo-header field %q; a response defines only %q (RFC 9113 §8.3.2)",
				f.Name, pseudoStatus)
		}
		if status {
			// §8.3: a pseudo-header field may appear once. Checked by presence rather
			// than by comparing values, so that two ":status" fields carrying the same
			// code are still refused — a receiver is entitled to take either, and two
			// receivers taking different ones is the response half of smuggling.
			return malformedf("a repeated %q pseudo-header field (RFC 9113 §8.3)", pseudoStatus)
		}
		status = true
		if err := checkStatus(f.Value); err != nil {
			return err
		}
	}

	if kind == sectionHeader && !status {
		// §8.3.2: ":status" is the one pseudo-header field a response must include.
		// Reported by name rather than as "a missing pseudo-header field", because
		// this is the failure a handler that built its field list by hand will hit and
		// the name is the fix.
		return malformedf("no %q pseudo-header field (RFC 9113 §8.3.2)", pseudoStatus)
	}
	return nil
}

// checkFieldLine holds one field line to §8.2.1's minimal validation, the short list
// that section marks MUST.
//
// Every octet refused below means something to an HTTP/1.1 parser, and HPACK will
// carry all of them happily. §8.2.1 names the attack: "unvalidated fields might enable
// attacks when messages are forwarded using HTTP/1.1, where characters such as
// carriage return (CR), line feed (LF), and COLON are used as delimiters". On the
// response side that is response splitting rather than request smuggling — a handler
// that reflects part of a request into a header value, a value carrying CRLF, and the
// next hop reading one response as two.
func checkFieldLine(f h2.Field) error {
	if f.Name == "" {
		// A field name is a token (§5.1 of RFC 9110) and a token is at least one
		// character. This is the part of that definition an octet check cannot state.
		return malformedf("a field line with an empty name (RFC 9110 §5.1)")
	}

	// The one colon a name may contain, and only as its first octet. §8.2.1 phrases
	// the exception as being for "pseudo-header fields, which have a name that starts
	// with a single colon", so a name beginning "::" is not a pseudo-header field and
	// falls under the ban — which is what dropping exactly one leading colon leaves
	// the loop below to catch.
	name := f.Name
	if name[0] == ':' {
		name = name[1:]
	}
	for i := 0; i < len(name); i++ {
		switch c := name[i]; {
		case c >= 'A' && c <= 'Z':
			// §8.2: "Field names MUST be converted to lowercase when constructing an
			// HTTP/2 message." Reported separately from the octet range it belongs to,
			// because it is the one a handler hits by accident — "Content-Type" is
			// what every other HTTP API in the world spells it — and "not lowercase"
			// is the answer its author needs.
			return malformedf("field name %q is not lowercase (RFC 9113 §8.2)", f.Name)
		case c <= 0x20, c >= 0x7f:
			// §8.2.1's ranges: 0x00-0x20 and 0x7f-0xff, which between them cover CR,
			// LF, NUL, SP, HTAB and every non-visible octet.
			return malformedf("field name %q contains the octet 0x%02x (RFC 9113 §8.2.1)", f.Name, c)
		case c == ':':
			return malformedf("field name %q contains a colon (RFC 9113 §8.2.1)", f.Name)
		}
	}

	for i := 0; i < len(f.Value); i++ {
		switch c := f.Value[i]; c {
		case 0x00, 0x0a, 0x0d:
			// §8.2.1 forbids NUL, LF and CR "at any position". These three are the
			// splitting payload itself.
			return malformedf("the value of field %q contains the octet 0x%02x (RFC 9113 §8.2.1)", f.Name, c)
		}
	}
	if len(f.Value) > 0 {
		// §8.2.1: "A field value MUST NOT start or end with an ASCII whitespace
		// character." An empty value has no first or last octet and is legal; the
		// length check is what keeps this from indexing into nothing.
		if c := f.Value[0]; c == ' ' || c == '\t' {
			return malformedf("the value of field %q starts with whitespace (RFC 9113 §8.2.1)", f.Name)
		}
		if c := f.Value[len(f.Value)-1]; c == ' ' || c == '\t' {
			return malformedf("the value of field %q ends with whitespace (RFC 9113 §8.2.1)", f.Name)
		}
	}
	return nil
}

// checkRegular holds a regular field line to §8.2.2, which bans the fields whose
// meaning belongs to one hop of an HTTP/1.1 connection.
//
// Six names rather than the request side's five, and the sixth is the interesting one.
// §8.2.2's TE exception is written as "the TE header field, which MAY be present in an
// HTTP/2 request", so a TE field in a response is not covered by it and is a
// connection-specific field like the rest — the request-side check that accepts TE with
// the value "trailers" would be wrong here.
// The field a response uses to announce a trailer section is Trailer (§6.6.2 of RFC
// 9110), which is a regular field and needs no exception.
func checkRegular(f h2.Field) error {
	switch f.Name {
	case "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade", "te":
		// §8.2.2's list — Connection "and those listed as having connection-specific
		// semantics in Section 7.6.1 of [HTTP] (that is, Proxy-Connection, Keep-Alive,
		// Transfer-Encoding, and Upgrade)" — plus TE for the reason above.
		//
		// transfer-encoding is the one that matters most. HTTP/2 has no chunked
		// encoding, so a response carrying it is either confused or arranging for the
		// next hop and the client to disagree about where the body ends.
		return malformedf("the connection-specific header field %q (RFC 9113 §8.2.2)", f.Name)
	}
	return nil
}

// checkStatus holds a ":status" value to §8.3.2, which defines it as "the numeric HTTP
// status code (see Section 15 of [HTTP])" — and §15 of RFC 9110 makes that "a
// three-digit integer code".
//
// So three digits exactly, and a first digit in 1-5. That pair is the whole of the
// range: §15 assigns 1xx through 5xx and says a client "MUST understand the class of
// any status code, as indicated by the first digit", which a 6xx code makes impossible.
// Length is checked before the digits so that a value of "200 OK" — the HTTP/1.1 status
// line, which is the mistake a handler makes — is refused as the wrong length rather
// than as an unexpected space.
func checkStatus(v string) error {
	if len(v) != 3 {
		return malformedf("a %q of %d octets, want three digits (RFC 9113 §8.3.2)", pseudoStatus, len(v))
	}
	for i := 0; i < len(v); i++ {
		if c := v[i]; c < '0' || c > '9' {
			return malformedf("a %q containing the octet 0x%02x, want three digits (RFC 9113 §8.3.2)",
				pseudoStatus, c)
		}
	}
	if c := v[0]; c < '1' || c > '5' {
		return malformedf("a %q of class %cxx; RFC 9110 §15 defines 1xx through 5xx", pseudoStatus, c)
	}
	return nil
}

// malformedf wraps ErrMalformedResponse with a formatted reason.
//
// The wording is the RFC's. "Malformed" is a term §8.1.1 defines, and a reader who
// finds one of these in a log and searches for the word lands on the section that
// explains it. §8.1.1 is written about requests; the definition is symmetrical and the
// vocabulary is worth sharing with the request half of this server, whose messages
// read the same way.
func malformedf(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrMalformedResponse}, args...)...)
}
