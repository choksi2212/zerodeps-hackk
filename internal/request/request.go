// Package request turns a decoded header block into an HTTP request. It is where
// RFC 9113 §8 is enforced, and so where a field list stops being opaque.
//
// Everything below this package is framing: internal/frame reads octets,
// internal/stream owns identifiers, states and windows, and neither knows what a
// method or a path is. §8 is the seam — "Expressing HTTP Semantics in HTTP/2" — and
// this package is that seam. It holds a field list to §8.2.1's field validity
// rules, §8.2.2's ban on connection-specific fields, §8.3's pseudo-header rules,
// §8.3.1's required set and §8.5's shape for CONNECT, and produces either a Request
// or the stream error that says why there is none.
//
// # Why every fault here is a stream error
//
// §8.1.1 settles it in one sentence: a malformed request "MUST be treated as a
// stream error (Section 5.4.2) of type PROTOCOL_ERROR". So not one rule in this
// package ends a connection, which is a deliberate asymmetry with the layers below
// it, where a framing fault or a failed HPACK decode takes the whole connection
// down. The difference is whether the connection can carry on being understood: a
// desynchronised dynamic table makes every later request unreadable, whereas an
// uppercase field name on stream 7 tells you nothing about stream 9. A browser with
// six requests in flight should not lose five of them to the sixth's mistake.
//
// The same section explains why the rules are as unforgiving as they are, and the
// sentence is worth reproducing because it is the justification for every refusal
// in this file. §8.1.1: "These requirements are intended to protect against
// several types of common attacks against HTTP; they are deliberately strict
// because being permissive can expose implementations to these vulnerabilities."
// The vulnerability is request smuggling, and the mechanism is a field that this
// server and the next hop read differently.
//
// # What is not here
//
// The other half of §8.1.1's content-length rule. A declared length that does not
// equal the sum of the DATA payloads is malformed, and the sum is not known until
// the body has arrived, so the comparison belongs to whatever holds a stream's
// state across frames. What is here is the part that is a property of the field
// list alone: that the value is a decimal at all, that there is only one of it, and
// that it is zero on a request whose HEADERS frame already ended the stream.
//
// SETTINGS_MAX_HEADER_LIST_SIZE (§6.5.2). This server does not advertise one, so
// there is no announced bound to enforce; the bound that exists is on the
// compressed block, held by internal/frame as limits.MaxHeaderBlockSize and
// limits.MaxContinuationFrames, which is the pair that answers CVE-2023-45288.
//
// Cookie concatenation. It is a MAY, and §8.2.3 asks for it only before a field
// list is passed "into a non-HTTP/2 context, such as an HTTP/1.1 connection, or a
// generic HTTP server application". This server has no such context: it is not a
// proxy, and its handler reads the fields as they arrived.
//
// Server push (§8.4). SETTINGS_ENABLE_PUSH is 0 and this server never sends
// PUSH_PROMISE, so §8.4's request and response rules describe frames that cannot
// exist on a connection it serves.
//
// The trailer field list of §6.5.1 of RFC 9110 — the fields a sender must not put
// in a trailer section. Those are ignored rather than rejected, and this server
// ignores them by construction: ValidateTrailers does not merge a trailer section
// into the header section, so a content-length or a host arriving in one changes
// nothing that was already decided.
package request

import (
	"strings"

	"zerodeps/zdh/internal/h2"
	"zerodeps/zdh/internal/priority"
)

// The pseudo-header fields §8.3.1 defines for a request.
//
// The set is closed. §8.3 makes any other pseudo-header field in a request
// malformed, including ":status", which is defined for responses and so may not
// appear in one — and including anything an extension might add, because §8.3
// permits those only once they have been negotiated and this server negotiates
// nothing.
const (
	pseudoMethod    = ":method"
	pseudoScheme    = ":scheme"
	pseudoAuthority = ":authority"
	pseudoPath      = ":path"
)

// fieldHost names the Host header field in an error message, for the one case where
// a rule about the authority is broken by Host rather than by ":authority": when the
// peer sent no ":authority" and Host stood in for it. The two are held to the same
// rules, so they share the checks, and a message that named the wrong one would send
// a reader looking for a field the request did not contain.
const fieldHost = "the Host header field"

// fieldPriority is the Priority header field (§5 of RFC 9218), lowercase because
// §8.2.1 of RFC 9113 requires every field name on the wire to be, and named as a
// constant because the switch that collects it and the test that sends it must agree
// on the spelling of a field whose name is not a pseudo-header field and so is not
// checked against anything.
const fieldPriority = "priority"

// The two methods whose §8.3.1 requirements differ from every other method's:
// CONNECT omits three of the four pseudo-header fields (§8.5), and OPTIONS is the
// one method that may carry the asterisk-form target.
const (
	methodConnect = "CONNECT"
	methodOptions = "OPTIONS"
)

// The bits of Parse's seen set, one per pseudo-header field §8.3.1 defines.
//
// A bit each rather than a bool each because the presence of a field and its value
// are different questions, and only the first answers §8.3's rule against
// repetition: a peer that sends ":authority" twice with an empty value both times
// has repeated a pseudo-header field, and a check that compared the destination
// against "" would not notice.
const (
	hasMethod uint8 = 1 << iota
	hasScheme
	hasAuthority
	hasPath
)

// NoContentLength is Request.ContentLength when the request declared none, which is
// a different thing from declaring zero: a request with no content-length may still
// carry a body, and one that declared zero may not.
const NoContentLength = -1

// Request is one validated HTTP request: §8.3.1's control data lifted out of the
// field list, and the regular field lines that remain.
//
// Every field is exactly what the peer sent, with no normalization beyond what a
// rule in §8 required in order to be checked at all. In particular Method is
// case-sensitive and is not compared against any list of known methods here — §9 of
// RFC 9110 makes the method an extensible token, and refusing an unrecognised one is
// a 501 from the layer that routes requests, not a malformed request.
type Request struct {
	// Method is ":method": a token (§5.6.2 of RFC 9110), never empty.
	Method string

	// Scheme is ":scheme", empty only for a CONNECT request. It is not restricted
	// to "http" and "https" — §8.3.1 says so in as many words — so a handler that
	// cares must ask.
	Scheme string

	// Authority is the authority the request is for: ":authority" if the peer sent
	// one, and otherwise the Host header field, which is the only case §8.3.1
	// permits Host to determine the target URI in. It is empty when the peer sent
	// neither, which is not malformed and is for the routing layer to answer.
	Authority string

	// Path is ":path": either an absolute path with an optional query, or "*" on an
	// OPTIONS request. Empty only for a CONNECT request.
	Path string

	// Fields are the regular field lines, in the order they arrived, with the
	// pseudo-header fields removed. Order is kept because §5.3 of RFC 9110 makes
	// the order of the values of one field name significant.
	Fields []h2.Field

	// ContentLength is the length the request declared, or NoContentLength if it
	// declared none. Never negative otherwise: a value that is not a decimal is
	// malformed rather than parsed.
	ContentLength int64

	// Priority is the client's view of how this response should be prioritized,
	// from the Priority header field (§5 of RFC 9218). The zero value is every
	// parameter absent, which §4 of RFC 9218 resolves to every default — so a
	// request that sent no signal needs no special case here or in the scheduler.
	//
	// Lifted out of the field list like ContentLength is, and for the same reason:
	// it is control data that something other than a handler acts on. Unlike
	// content-length the field line is also left in Fields, because §5 of RFC 9218
	// makes it an end-to-end signal — "It is an end-to-end signal that indicates the
	// endpoint's view of how HTTP responses should be prioritized." — and a server
	// that stripped it would be answering for the next hop as well as itself.
	//
	// A Priority field that does not parse leaves this at its zero value and does
	// not make the request malformed. §7 of RFC 9218 makes treating that as a
	// connection error a MAY, and internal/priority declines it: a priority signal is
	// advice, and refusing a request over malformed advice is worse service than
	// serving it at the default urgency.
	Priority priority.Params
}

// Parse validates the header section of a request on stream id and returns it.
//
// endStream is the END_STREAM flag of the HEADERS frame that carried the section,
// so it reports that the request has no content — which is what makes one of
// §8.1.1's two content-length rules answerable here rather than after the body.
//
// The order of the checks is not arbitrary. Field validity comes first, per field,
// because §8.2.1's rules are about octets and hold whatever the field turns out to
// mean; a field name with a CR in it is malformed before anyone asks whether it was
// a pseudo-header field. The rules about the set as a whole — what is required,
// what may not repeat, whether Host agrees with ":authority" — can only be answered
// once the whole list has been walked, so they come after it.
//
// fields is not retained: the regular field lines are copied into Request.Fields.
func Parse(id uint32, fields []h2.Field, endStream bool) (*Request, error) {
	r := &Request{ContentLength: NoContentLength}

	var (
		seen    uint8
		regular bool

		// The two field names whose *number* of occurrences is a rule rather than
		// a list, so each is held with its count instead of being read back out of
		// r.Fields afterwards.
		clen  string
		clens int
		host  string
		hosts int

		// The Priority header field is the third, and it is neither a value nor a
		// count but a concatenation. §4.2 of RFC 9651: "When generating input_bytes,
		// parsers MUST combine all field lines in the same section (header or
		// trailer) that case-insensitively match the field name into one
		// comma-separated field-value, as per Section 5.2 of [HTTP]; this assures
		// that the entire field value is processed correctly." Case-insensitively is
		// exactly here, because §8.2.1 of RFC 9113 has already required every field
		// name to be lowercase and checkField has already enforced it.
		//
		// A Builder rather than string concatenation: a peer may send as many field
		// lines as the header list size allows, and appending to a string once per
		// line is quadratic in the total. The zero Builder allocates nothing, so a
		// request without the field pays nothing for this.
		prio  strings.Builder
		prios int
	)

	for _, f := range fields {
		if err := checkField(id, f); err != nil {
			return nil, err
		}

		if strings.HasPrefix(f.Name, ":") {
			if regular {
				// §8.3: "All pseudo-header fields MUST appear in a field block
				// before all regular field lines." The rule is worth more than it
				// looks — a receiver that tolerated a late pseudo-header field
				// would let a peer hide a second ":path" behind a regular field
				// from anything that stopped reading at the first one.
				return nil, malformedf(id,
					"the pseudo-header field %s appears after a regular field line (RFC 9113 §8.3)", f.Name)
			}
			bit, dst := r.pseudo(f.Name)
			if bit == 0 {
				return nil, malformedf(id,
					"%s is not a pseudo-header field defined for a request (RFC 9113 §8.3)", f.Name)
			}
			if seen&bit != 0 {
				return nil, malformedf(id,
					"the pseudo-header field %s appears more than once (RFC 9113 §8.3)", f.Name)
			}
			seen |= bit
			*dst = f.Value
			continue
		}

		regular = true
		if err := checkRegular(id, f); err != nil {
			return nil, err
		}
		switch f.Name {
		case "content-length":
			clen, clens = f.Value, clens+1
		case "host":
			host, hosts = f.Value, hosts+1
		case fieldPriority:
			// The separator goes in once per line after the first, counted rather
			// than inferred from the Builder's length: a first line with an empty
			// value has a length of zero and still took a line, and §4.2 of RFC 9651
			// says to combine the lines rather than the non-empty ones. So a peer
			// that sends an empty Priority field and then a real one produces
			// ", u=1", which is not a Dictionary — which is the answer a conforming
			// parser gives, and the whole reason that paragraph warns about splitting
			// a field across lines.
			if prios > 0 {
				prio.WriteString(", ")
			}
			prio.WriteString(f.Value)
			prios++
		}
		r.Fields = append(r.Fields, f)
	}

	if err := r.checkControlData(id, seen); err != nil {
		return nil, err
	}
	if err := r.resolveAuthority(id, seen, host, hosts); err != nil {
		return nil, err
	}
	if err := r.setContentLength(id, clen, clens, endStream); err != nil {
		return nil, err
	}
	r.setPriority(prios, prio.String())
	return r, nil
}

// setPriority reads the combined Priority field value, or leaves the zero Params if
// there was no such field line.
//
// The error is deliberately dropped, and this is the one place in this package where
// that is the right thing to do. Every other rule here is a rule about whether a
// message is well formed; this is not. §7 of RFC 9218 makes failing to parse a
// priority field value a MAY-treat-as-connection-error, internal/priority declines
// that MAY, and the zero Params it returns alongside the error is the defaults — which
// is what §4 of RFC 9218 says to schedule a request with when it carries no priority
// parameters at all. A request whose advice was unreadable is served exactly like a
// request that offered none.
//
// prios rather than a non-empty string is the test for whether the field was there,
// because an empty Priority field line is a legal Dictionary of no members and means
// the same thing as no field line at all — but only after this has decided not to
// distinguish them, which is what makes it worth saying.
func (r *Request) setPriority(prios int, field string) {
	if prios == 0 {
		return
	}
	r.Priority, _ = priority.Parse(field)
}

// ValidateTrailers holds a trailer section on stream id to the rules of §8.1.
//
// It returns nothing but an error because a trailer section produces nothing: this
// server does not merge trailers into the header section, and the fields are handed
// to a handler as they arrived. There is therefore no control data to lift out, and
// exactly one rule that a header section does not have — §8.1's "Trailers MUST NOT
// include pseudo-header fields", which §8.3 repeats.
//
// Everything else that applies to a header section applies here too, because §8.2.1
// and §8.2.2 are rules about a message and a trailer section is part of one. A
// transfer-encoding in a trailer is the classic smuggling payload, and it is caught
// by the same check that catches it in a header section.
func ValidateTrailers(id uint32, fields []h2.Field) error {
	for _, f := range fields {
		if err := checkField(id, f); err != nil {
			return err
		}
		if strings.HasPrefix(f.Name, ":") {
			return malformedf(id,
				"the pseudo-header field %s appears in a trailer section (RFC 9113 §8.1)", f.Name)
		}
		if err := checkRegular(id, f); err != nil {
			return err
		}
	}
	return nil
}

// pseudo maps a pseudo-header field name to its bit in Parse's seen set and to the
// field of r its value belongs in, or to zero and nil for a name §8.3.1 does not
// define for a request.
//
// One switch rather than four cases spelled out at the call site, because the two
// facts about each name — which bit, which destination — then appear once each. The
// version with four cases is four copies of the same five lines, and the mistake it
// invites is a copy that sets the wrong bit, which reads as correct and silently
// stops one of the four from being checked for repetition.
func (r *Request) pseudo(name string) (uint8, *string) {
	switch name {
	case pseudoMethod:
		return hasMethod, &r.Method
	case pseudoScheme:
		return hasScheme, &r.Scheme
	case pseudoAuthority:
		return hasAuthority, &r.Authority
	case pseudoPath:
		return hasPath, &r.Path
	}
	return 0, nil
}

// checkControlData holds the pseudo-header fields that were present to §8.3.1's
// requirements, and a CONNECT request to §8.5's.
func (r *Request) checkControlData(id uint32, seen uint8) error {
	if seen&hasMethod == 0 {
		return malformedf(id, "no %s pseudo-header field (RFC 9113 §8.3.1)", pseudoMethod)
	}
	if !validToken(r.Method) {
		// §8.3.1 requires "exactly one valid value" for ":method", and §9 of
		// RFC 9110 defines a method as a token. The value that matters most here is
		// the one this rejects: a method containing a space is the front half of an
		// HTTP/1.1 request line, and an intermediary that pasted it into one would
		// be smuggling a request it never received.
		return malformedf(id, "%s %q is not a token (RFC 9110 §9)", pseudoMethod, r.Method)
	}

	if r.Method == methodConnect {
		return r.checkConnect(id, seen)
	}

	if seen&hasScheme == 0 {
		return malformedf(id, "no %s pseudo-header field (RFC 9113 §8.3.1)", pseudoScheme)
	}
	if !validScheme(r.Scheme) {
		return malformedf(id, "%s %q is not a scheme (RFC 3986 §3.1)", pseudoScheme, r.Scheme)
	}
	if seen&hasPath == 0 {
		return malformedf(id, "no %s pseudo-header field (RFC 9113 §8.3.1)", pseudoPath)
	}
	if err := r.checkPath(id); err != nil {
		return err
	}
	return r.checkAuthority(id, pseudoAuthority)
}

// checkConnect holds a CONNECT request to §8.5: no ":scheme", no ":path", and an
// ":authority" that names the host and port to tunnel to.
//
// The shape is checked even though this server does not tunnel. A CONNECT request
// that conforms to §8.5 is answered by the routing layer, with a 501, and one that
// does not is malformed — and those are different answers. Refusing every CONNECT
// as malformed would report a client's correct request as its mistake.
func (r *Request) checkConnect(id uint32, seen uint8) error {
	if seen&hasScheme != 0 {
		return malformedf(id, "a CONNECT request with a %s pseudo-header field (RFC 9113 §8.5)", pseudoScheme)
	}
	if seen&hasPath != 0 {
		return malformedf(id, "a CONNECT request with a %s pseudo-header field (RFC 9113 §8.5)", pseudoPath)
	}
	if seen&hasAuthority == 0 || r.Authority == "" {
		return malformedf(id, "a CONNECT request with no %s pseudo-header field (RFC 9113 §8.5)", pseudoAuthority)
	}
	return r.checkAuthority(id, pseudoAuthority)
}

// checkPath holds ":path" to §8.3.1.
func (r *Request) checkPath(id uint32) error {
	if r.Path == "" {
		// §8.3.1 spells this one out for "http" and "https" URIs, which "MUST
		// include a value of '/'" when the target has no path component. It is
		// refused for every other scheme too, under the same section's requirement
		// of "exactly one valid value": an empty target is not a value a request
		// can be routed by, whatever the scheme.
		return malformedf(id, "an empty %s pseudo-header field (RFC 9113 §8.3.1)", pseudoPath)
	}
	if c, bad := controlOctet(r.Path); bad {
		// Not covered by §8.2.1's value rules, which forbid NUL, CR and LF anywhere
		// and whitespace only at the ends. An interior space passes all of them and
		// is still a request target that no two implementations agree on: RFC 3986
		// has no production for it, and an intermediary writing it into a request
		// line would produce a line with three spaces in it. That is smuggling.
		//
		// The check deliberately stops at the ASCII controls rather than rejecting
		// every octet above 0x7f, which the strict reading of RFC 3986 would: a
		// path is required to be percent-encoded, but curl passes a non-ASCII path
		// through as raw UTF-8, and those bytes are unambiguous to route on. The
		// octets that are worth refusing are the ones that mean something to a
		// parser downstream, and they are all below 0x21.
		return malformedf(id, "%s %q contains the octet 0x%02x (RFC 3986 §3.3)", pseudoPath, r.Path, c)
	}

	if !isHTTPScheme(r.Scheme) {
		// §8.3.1's shape rules below are scoped to "http" and "https" URIs by the
		// RFC itself. A gateway scheme may have a target this server has no
		// grammar for, and inventing one would refuse requests §8.3.1 permits.
		return nil
	}
	if r.Path == "*" {
		// §8.3.1: the asterisk form belongs to "an OPTIONS request for an 'http' or
		// 'https' URI that does not include a path component", and to nothing else.
		if r.Method != methodOptions {
			return malformedf(id, "the asterisk-form %s on a %s request (RFC 9113 §8.3.1)",
				pseudoPath, r.Method)
		}
		return nil
	}
	if r.Path[0] != '/' {
		// The ":path" of an "http" or "https" request carries, per §8.3.1, "the path
		// and query parts of the target URI (the absolute-path production and,
		// optionally, a '?' character followed by the query production; see Section
		// 4.1 of [HTTP])". An absolute-path begins with a slash, so anything else is
		// an absolute URI or a relative reference in a place neither belongs — and a
		// ":path" of "http://elsewhere/" is how a request gets routed somewhere its
		// authority never named.
		return malformedf(id, "%s %q is not an absolute path (RFC 9113 §8.3.1)", pseudoPath, r.Path)
	}
	return nil
}

// checkAuthority holds the request's authority to §8.3.1, when there is one. field
// names the header field the value came from, which is ":authority" unless Host stood
// in for it.
//
// None of these messages carries the value, and that is deliberate rather than
// terse. The userinfo subcomponent this rejects is "user:password@host", so an
// error line quoting the authority it refused would write a password into the log —
// which is the same mistake as logging a credential from a regular field, made
// where it looks harmless because the field is a pseudo-header. A peer that sent it
// knows what it sent.
func (r *Request) checkAuthority(id uint32, field string) error {
	if r.Authority == "" {
		// Absent, or present and empty. §8.3.1 requires ":authority" of no request
		// but CONNECT, whose own check has already refused an empty one.
		return nil
	}
	if c, bad := controlOctet(r.Authority); bad {
		return malformedf(id, "%s contains the octet 0x%02x (RFC 3986 §3.2)", field, c)
	}
	if i := strings.IndexAny(r.Authority, "/?#"); i >= 0 {
		// An authority ends at the first of these in every URI grammar there is, so
		// one that contains any of them is two components being read as one, and
		// which one wins depends on whose parser reads it.
		return malformedf(id, "%s contains %q, which ends an authority (RFC 3986 §3.2)",
			field, r.Authority[i])
	}
	if isHTTPScheme(r.Scheme) && strings.IndexByte(r.Authority, '@') >= 0 {
		// §8.3.1: "':authority' MUST NOT include the deprecated userinfo
		// subcomponent for 'http' or 'https' schemed URIs." Scoped to those two
		// schemes by the RFC, so a gateway scheme that still uses userinfo keeps it.
		return malformedf(id, "%s includes a userinfo subcomponent (RFC 9113 §8.3.1)", field)
	}
	return nil
}

// resolveAuthority settles what the request's authority is, and whether the Host
// header field agrees with it (§8.3.1).
func (r *Request) resolveAuthority(id uint32, seen uint8, host string, hosts int) error {
	if hosts > 1 {
		// §7.2 of RFC 9110 permits exactly one Host, and §3.2 of RFC 9112 makes a
		// second one a 400 in HTTP/1.1. Two that disagree are a smuggled request:
		// this server would route by one and the next hop by the other.
		return malformedf(id, "%d Host header fields (RFC 9110 §7.2)", hosts)
	}
	if seen&hasAuthority == 0 {
		// §8.3.1 forbids using Host "to determine the target URI if ':authority' is
		// present", which is also permission to use it when there is not: that is
		// what a request translated from HTTP/1.1 by an intermediary looks like. An
		// empty result — neither field sent — is left for the routing layer, because
		// §8.3.1's list of mandatory pseudo-header fields does not include this one.
		r.Authority = host
		return r.checkAuthority(id, fieldHost)
	}
	if hosts == 1 && !sameAuthority(r.Scheme, r.Authority, host) {
		// §8.3.1: "A server SHOULD treat a request as malformed if it contains a
		// Host header field that identifies an entity that differs from the entity
		// in the ':authority' pseudo-header field." A SHOULD taken as written,
		// because the request it describes is one that two hops route differently,
		// and because a client has no reason to send a Host that disagrees.
		return malformedf(id,
			"a Host header field that differs from the %s pseudo-header field (RFC 9113 §8.3.1)",
			pseudoAuthority)
	}
	return nil
}

// setContentLength records the declared length of the body, if there was one.
func (r *Request) setContentLength(id uint32, clen string, clens int, endStream bool) error {
	switch {
	case clens == 0:
		return nil
	case clens > 1:
		// §8.6 of RFC 9110 gives a recipient the choice of rejecting a message with
		// several content-length fields or collapsing identical values into one.
		// Rejecting, because §8.1.1 asks for the strict reading, and because the
		// value is about to be compared against the body: a rule with two possible
		// answers is a rule two implementations answer differently, which is the
		// shape of every content-length smuggling bug there is.
		return malformedf(id, "%d content-length header fields (RFC 9110 §8.6)", clens)
	}

	n, err := parseContentLength(clen)
	if err != nil {
		return malformedf(id, "content-length: %v (RFC 9110 §8.6)", err)
	}
	r.ContentLength = n

	if endStream && n != 0 {
		// §8.1.1: a request is malformed if content-length "does not equal the sum
		// of the DATA frame payload lengths that form the content". END_STREAM on
		// the HEADERS frame means there will be no DATA frames, so the sum is zero
		// and known now. The other direction — a body that turns out not to match a
		// length that was plausible — is the caller's, once it has the body.
		return malformedf(id, "content-length %d on a request with no content (RFC 9113 §8.1.1)", n)
	}
	return nil
}

// malformedf is §8.1.1's verdict, which is the same for every rule in this package:
// a stream error of type PROTOCOL_ERROR, leaving the connection alone.
//
// The wording is the RFC's. "Malformed" is a term §8.1.1 defines, and a reader who
// finds one of these in a log and searches for the word lands on the section that
// explains it.
//
// One rule holds for every message that reaches here: the value of a regular field
// line never appears in it, and neither does ":authority". A regular value is where
// a credential lives, ":authority" can carry the userinfo this package refuses, and
// these strings end up in a log on a path a peer controls. The values that do appear
// are ":method", ":scheme" and ":path" — the request target, which is bounded, is
// what an access log records anyway, and is the whole diagnosis when one of them is
// the fault.
func malformedf(id uint32, format string, args ...any) error {
	return h2.StreamErrorf(id, h2.ProtocolError, "malformed request: "+format, args...)
}
