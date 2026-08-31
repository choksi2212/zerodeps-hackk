// Package priority holds the priority parameters of RFC 9218 and reads them out of a
// structured field value.
//
// RFC 9113 §5.3 withdrew HTTP/2's original priority scheme and put nothing in its place.
// RFC 9218 is the replacement, and it is a far smaller thing than what it replaces: two
// parameters in a Dictionary, where RFC 7540 had a mutable tree of dependencies and
// weights per connection. This package is that pair of parameters and nothing else. The
// frames that carry them are internal/frame, the Dictionary grammar is internal/sfv, and
// the scheduling they are an input to is internal/server.
//
// # Absence is a value
//
// A Params records, for each parameter, whether the peer sent it and what it said — not
// the value to schedule at. The distinction is forced by the specification, which resolves
// an absent parameter two different ways depending on where it was absent from.
//
// §4 of RFC 9218: "When receiving an HTTP request that does not carry these priority
// parameters, a server SHOULD act as if their default values were specified."
//
// §8 of RFC 9218: "The absence of a priority parameter in an HTTP response indicates the
// server's disinterest in changing the client-provided value.  This is different from the
// request header field, in which omission of a priority parameter implies the use of its
// default value (see Section 4)."
//
// A type that resolved absence on the way in could not hold a response's opinion about
// the urgency together with its silence about the incremental: it would have to invent
// false for the second, which is the client's value to choose. So absence is kept, Urgency
// and Incremental resolve on the way out, and Merge is §8's rule written once.
//
// The zero Params is every parameter absent, which resolves to every default. That makes
// it the right thing for a request that carried no priority signal at all, and it is why
// nothing here has a constructor that must be remembered.
//
// # What is ignored, and what is not
//
// §4 of RFC 9218: "Where the Dictionary is successfully parsed, this document places the
// additional requirement that unknown priority parameters, priority parameters with
// out-of-range values, or values of unexpected types MUST be ignored."
//
// All three are ignored, and ignored means absent rather than corrected: "u=9" leaves the
// urgency at its default of 3, not at 7. That is what the sentence requires — a value out
// of range is not a value — and it is the safer reading anyway, since a client whose
// signal was quietly clamped would be scheduled at an urgency it never asked for and
// could not observe.
//
// A Dictionary that does not parse is the one case the specification leaves open. §7 of
// RFC 9218: "Failure to parse the Priority Field Value MAY be treated as a connection
// error." Parse returns the error and a usable Params together, so a caller that takes the
// MAY has something to report and a caller that declines it has something to schedule
// with. This server declines it: a priority signal is advice, and refusing a request over
// malformed advice is worse service than serving it at the default urgency.
package priority

import (
	"fmt"
	"strings"

	"zerodeps/zdh/internal/sfv"
)

// The two parameter keys this document defines. §4.3.1 of RFC 9218 governs the rest, and
// a key registered later arrives here as an unknown parameter, which is to say ignored.
const (
	keyUrgency     = "u"
	keyIncremental = "i"
)

const (
	// DefaultUrgency is the urgency of a request that does not name one.
	//
	// §4.1 of RFC 9218: "The urgency (u) parameter value is Integer (see Section 3.3.1 of
	// [STRUCTURED-FIELDS]), between 0 and 7 inclusive, in descending order of priority.
	// The default is 3."
	DefaultUrgency = 3

	// MaxUrgency is the numerically largest urgency, and so the least urgent. §4.1 of RFC
	// 9218: "The smaller the value, the higher the precedence."
	//
	// §4.1 of RFC 9218: "The lowest urgency level (7) is reserved for background tasks
	// such as delivery of software updates.  This urgency level SHOULD NOT be used for
	// fetching responses that have any impact on user interaction."
	MaxUrgency = 7
)

// Params is a set of priority parameters (§4 of RFC 9218): the urgency and the
// incremental parameter, each either present with a value or absent.
//
// Comparable, and comparison means what it looks like — two Params are equal when they
// carry the same signal, which is not the same as resolving to the same schedule. A
// request that said nothing and a request that said "u=3" both schedule at urgency 3 and
// are different Params, because §8 gives them different answers when a response comes to
// merge over them.
//
// The fields are unexported and read through methods, because the signalled value and the
// resolved one are different questions with different answers and a caller reading a
// struct field would silently get whichever one the field happened to hold.
type Params struct {
	urgency    uint8
	hasUrgency bool

	incremental    bool
	hasIncremental bool
}

// Urgency is the urgency to schedule at: the parameter's value if it was sent, and
// DefaultUrgency if it was not.
//
// Always between 0 and MaxUrgency, so it indexes a table of that many entries without a
// bounds check of its own. Parse is what keeps that true from the wire — an out-of-range
// value is ignored rather than stored — and WithUrgency is what keeps it true from here.
func (p Params) Urgency() int {
	if !p.hasUrgency {
		return DefaultUrgency
	}
	return int(p.urgency)
}

// Incremental is whether the response may be delivered a chunk at a time: the parameter's
// value if it was sent, and false if it was not.
//
// §4.2 of RFC 9218: "The incremental (i) parameter value is Boolean (see Section 3.3.6 of
// [STRUCTURED-FIELDS]).  It indicates if an HTTP response can be processed incrementally,
// i.e., provide some meaningful output as chunks of the response arrive."
//
// §4.2 of RFC 9218: "The default value of the incremental parameter is false (0)."
func (p Params) Incremental() bool { return p.incremental }

// HasUrgency reports whether the urgency parameter was present.
//
// Present is not the same as non-default, and this is the only way to tell them apart:
// §8 of RFC 9218 makes an absent parameter in a response a decision not to change the
// client's value, so a Merge that could not distinguish absent from 3 would overwrite a
// client's "u=0" with a default nobody sent.
func (p Params) HasUrgency() bool { return p.hasUrgency }

// HasIncremental reports whether the incremental parameter was present, for the same
// reason HasUrgency exists.
func (p Params) HasIncremental() bool { return p.hasIncremental }

// WithUrgency returns p with the urgency parameter present and set to u.
//
// It panics if u is outside 0 to MaxUrgency. That is not a mistake a peer can cause:
// Parse ignores an out-of-range value rather than storing it, so the only way to arrive
// here with a bad argument is for this server's own code to have computed one, and a
// schedule quietly built on urgency 9 would be a defect that never announced itself.
// Urgency's range is this type's invariant, and this is where it is kept.
func (p Params) WithUrgency(u int) Params {
	if u < 0 || u > MaxUrgency {
		panic(fmt.Sprintf("priority: urgency %d is outside 0..%d (RFC 9218 §4.1)", u, MaxUrgency))
	}
	p.urgency, p.hasUrgency = uint8(u), true
	return p
}

// WithIncremental returns p with the incremental parameter present and set to i.
//
// Setting it to false is not the same as leaving it out, which is why this takes an
// argument rather than being a WithIncremental with no false case: a response that says
// "i=?0" is overriding a client's "i", and one that says nothing is letting it stand.
func (p Params) WithIncremental(i bool) Params {
	p.incremental, p.hasIncremental = i, true
	return p
}

// Merge returns p with each parameter that over provides taken from over, and each one it
// omits left as it was. It is §8 of RFC 9218's rule, and §8's example is its test: a
// request of "u=5, i" under a response of "u=1" is "u=1, i".
//
// Only for merging a response's signal over a request's. A PRIORITY_UPDATE frame is not a
// merge and must not be applied with this. §7 of RFC 9218: "A PRIORITY_UPDATE frame
// communicates a complete set of all priority parameters in the Priority Field Value
// field.  Omitting a priority parameter is a signal to use its default value." So a frame
// replaces a stream's Params outright, and an "i" the client sent in a header field is
// gone the moment it sends a frame that does not repeat it.
func (p Params) Merge(over Params) Params {
	if over.hasUrgency {
		p.urgency, p.hasUrgency = over.urgency, true
	}
	if over.hasIncremental {
		p.incremental, p.hasIncremental = over.incremental, true
	}
	return p
}

// Field is p as a Priority Field Value: the parameters that are present, as a Dictionary,
// in the order §4 of RFC 9218 defines them. The empty string is the correct answer for a
// Params with nothing present, and is a legal Dictionary of no members.
//
// The inverse of Parse for everything Parse retains, which is what the round-trip test
// asserts. It is not the inverse of the input to Parse, and cannot be: the parameters
// Parse ignores are gone, and a peer's spelling of the ones it keeps is not preserved —
// "i=?1" comes back as "i", which §4.2.2 of RFC 9651 makes the same value and the shorter
// spelling of it.
func (p Params) Field() string {
	var b strings.Builder
	if p.hasUrgency {
		b.WriteString(keyUrgency)
		b.WriteByte('=')
		// One digit, because Urgency's range is an invariant rather than a hope. A
		// conversion through strconv would be the same octet and an import.
		b.WriteByte('0' + p.urgency)
	}
	if p.hasIncremental {
		if b.Len() > 0 {
			b.WriteString(", ")
		}
		b.WriteString(keyIncremental)
		if !p.incremental {
			// §4.2.2 of RFC 9651 makes a member written with no "=" Boolean true, so
			// true is the bare key and false has to be spelled out.
			b.WriteString("=?0")
		}
	}
	return b.String()
}

// Parse reads a Priority Field Value: the value of a Priority header field (§5 of RFC
// 9218) or the Priority Field Value of a PRIORITY_UPDATE frame (§7.1 of RFC 9218). They
// are the same Dictionary in the same two grammars, so they are read by the same function.
//
// The returned Params is usable whatever the error. A Dictionary that does not parse
// yields the zero Params, which resolves to the defaults, and that is the whole of what
// this server does about it — see the package comment for why the MAY in §7 of RFC 9218 is
// declined. A caller that wants to take it has the error to take it on.
func Parse(field string) (Params, error) {
	d, err := sfv.ParseDictionary(field)
	if err != nil {
		return Params{}, err
	}

	var p Params

	// Three of §4's four ignore rules are in these two conditions. An unknown parameter
	// is ignored by never being asked for; a value of an unexpected type by the Kind
	// test, which is why sfv reports the kind rather than a Go any that would have to be
	// asserted; and an out-of-range one by the bounds test. The fourth rule — a
	// Dictionary that does not parse at all — is the error above.
	//
	// Duplicate keys are already resolved: §4.2.2 of RFC 9651 keeps the last of them and
	// sfv does that while parsing, so "u=0, u=7" arrives here as urgency 7 and this code
	// has no opinion about it.
	if it, ok := d.Get(keyUrgency); ok &&
		it.Kind == sfv.KindInteger && it.Integer >= 0 && it.Integer <= MaxUrgency {
		p.urgency, p.hasUrgency = uint8(it.Integer), true
	}

	// A Boolean and nothing else. "i=1" is an Integer and is ignored, which looks harsh
	// until you notice that accepting it would mean deciding whether "i=2" is true.
	if it, ok := d.Get(keyIncremental); ok && it.Kind == sfv.KindBoolean {
		p.incremental, p.hasIncremental = it.Boolean, true
	}

	return p, nil
}
