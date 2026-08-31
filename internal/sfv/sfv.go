// Package sfv parses HTTP structured field values, per §4.2 of RFC 9651.
//
// It exists because RFC 9218's priority signal is a Dictionary, and a Dictionary cannot
// be read by splitting on commas: a String member may contain one, and so may a Byte
// Sequence. Nor can it be read by looking only for the two members this server acts on,
// because skipping a member whose value is of a type we do not use still means finding
// where that value ends — which is parsing it. So the whole of the Dictionary grammar is
// here, including the six bare item types the priority field never carries.
//
// The Go standard library has no structured-fields parser, in any package. This one
// replaces the third-party dependency that would otherwise be the only alternative.
//
// # What is here and what is not
//
// ParseDictionary is the only entry point. §4.2 of RFC 9651 defines three, one per field
// type — "dictionary", "list", and "item" — and the other two are absent because nothing
// in this server reads a field of those types. The machinery underneath is shared and
// complete regardless: a Dictionary member's value may be an Inner List, an Inner List
// holds Items, an Item is a bare item with Parameters, and a Parameter's value is a bare
// item of any of the eight types. Adding List or Item would be a dozen lines over the
// same parser, and they are not written because unused code is not tested code.
//
// # Errors are total
//
// A failure anywhere fails the whole value. §4.2 of RFC 9651: "If parsing fails, either
// the entire field value MUST be ignored (i.e., treated as if the field were not present
// in the section), or alternatively the complete HTTP message MUST be treated as
// malformed." There is no partial result, and the parser never returns one — a caller
// that got an error has a Dictionary it must not read. Which of the two permitted
// responses this server takes is the caller's decision, not this package's: internal
// priority ignores the field, because a priority signal is advice and refusing a request
// over malformed advice would be worse service than serving it at the default urgency.
package sfv

import "fmt"

// Kind is which of the eight bare item types an Item holds, or that it holds an Inner
// List. §3.3 of RFC 9651 defines the eight; §3.1.1 defines the Inner List, which is not a
// bare item and can only appear as a member or list value, never as a parameter value.
//
// The zero value is deliberately not a type. An Item that was never parsed reads as
// KindNone rather than as an Integer of zero, so a caller that forgets to check whether a
// member was present cannot mistake its absence for a value.
type Kind uint8

const (
	KindNone Kind = iota
	KindInteger
	KindDecimal
	KindString
	KindToken
	KindByteSequence
	KindBoolean
	KindDate
	KindDisplayString
	KindInnerList
)

var kindNames = [...]string{
	"none",
	"integer",
	"decimal",
	"string",
	"token",
	"byte sequence",
	"boolean",
	"date",
	"display string",
	"inner list",
}

func (k Kind) String() string {
	if int(k) < len(kindNames) {
		return kindNames[k]
	}
	return fmt.Sprintf("unknown kind(%d)", uint8(k))
}

// Item is one value with its parameters: a bare item of one of the eight types, or an
// Inner List.
//
// Kind says which field carries the value, and the others are zero. A tagged struct
// rather than an any: a caller reads Kind and then the field that Kind names, which is
// checkable by the compiler, where a type switch over an any is checkable only by a test
// that remembers to cover every branch. It also closes the set — no value of a type this
// package does not parse can be put in one of these, so a caller's switch over Kind is
// exhaustive by construction.
type Item struct {
	Kind Kind

	// Integer is the value of an Integer, and the seconds since the Unix epoch of a
	// Date. §4.2.9 of RFC 9651 parses a Date as an Integer and rejects a Decimal one, so
	// the two share a field and are told apart by Kind. §3.3.1 bounds an Integer to
	// fifteen digits, which is why no value here can overflow.
	Integer int64

	// Thousandths is the value of a Decimal, multiplied by 1000.
	//
	// Not a float64. §3.3.2 of RFC 9651 admits at most twelve integer digits and three
	// fractional ones, so every legal Decimal is an exact multiple of a thousandth and
	// the largest is 10^15 — inside an int64 and outside the 2^53 that a float64 holds
	// exactly. Scaling by 1000 is therefore lossless where a float is not, and a
	// comparison for equality means what it says.
	Thousandths int64

	// Text is the value of a String, a Token, or a Display String. A String arrives
	// unquoted and unescaped, a Display String percent-decoded and validated as UTF-8,
	// and a Token exactly as it appeared. Kind is what distinguishes them, and it has to
	// be: "?0" is a Boolean and "\"?0\"" is a String whose text is those two characters.
	Text string

	// Bytes is the decoded content of a Byte Sequence. It is a fresh slice, never a view
	// into the field value.
	Bytes []byte

	// Boolean is the value of a Boolean. It is also the value of a Dictionary member or
	// a parameter written with no "=" at all, which §4.2.2 and §4.2.3.2 of RFC 9651 both
	// define as Boolean true — "i" and "i=?1" are the same signal.
	Boolean bool

	// List is the members of an Inner List, each with its own parameters. It is empty for
	// "()", which is a legal Inner List of nothing, and nil for every other Kind. An
	// Inner List cannot contain another: §3.1.1 of RFC 9651 makes its members bare items,
	// so this nests exactly one level and no input can drive this package into recursion
	// deeper than that.
	List []Item

	// Params is the parameters attached to this item, in the order they appeared. An
	// Inner List's own parameters are here too; the parameters of its members are on the
	// members.
	Params Params
}

// Param is one parameter: a key and a bare item. §4.2.3.2 of RFC 9651 makes a parameter
// with no value Boolean true, so Value is always a value and never an absence.
type Param struct {
	Key   string
	Value Item
}

// Params is an item's parameters in field order.
//
// A slice and not a map, for three reasons. Order is part of the value — two dictionaries
// differing only in parameter order are different field values, and a map would lose
// that. Duplicate keys are already resolved at parse time, so there is nothing a map
// would deduplicate. And the parameter lists this server reads have none or one member,
// where a linear scan is faster than hashing a key and an allocation cheaper than a map
// header.
type Params []Param

// Get returns the parameter with this key. Exactly one can match, because duplicates were
// resolved while parsing, as §4.2.3.2 of RFC 9651 requires: "Note that when duplicate
// parameter keys are encountered, all but the last instance are ignored." The parser
// overwrites in place, so no key appears twice in a Params.
func (ps Params) Get(key string) (Item, bool) {
	for _, p := range ps {
		if p.Key == key {
			return p.Value, true
		}
	}
	return Item{}, false
}

// Member is one Dictionary member: a key and its value.
type Member struct {
	Key   string
	Value Item
}

// Dictionary is a structured field Dictionary (§3.2 of RFC 9651), in field order.
//
// A slice for the same reasons as Params, and one more: §4.2.2 of RFC 9651 calls for "an
// empty, ordered map", and the ordered part is the half that a Go map does not have.
type Dictionary []Member

// Get returns the member with this key. As with Params, at most one can match, because
// parsing overwrote any earlier member with the same key.
func (d Dictionary) Get(key string) (Item, bool) {
	for _, m := range d {
		if m.Key == key {
			return m.Value, true
		}
	}
	return Item{}, false
}

// SyntaxError is a parse failure: what the algorithm required, and where the input stopped
// meeting it.
//
// The offset is where the parser could not continue. For a rule about a single octet — a
// key that begins with a capital, a control character inside a String, a Boolean that is
// neither 0 nor 1 — it is that octet. For a rule about a whole value — a number too long to
// be an Integer, a Decimal where a Date needed whole seconds, base64 that will not decode —
// it is the first octet of that value, because pointing at the digit that crossed a length
// limit says less than pointing at the number that broke it.
//
// It is reported because a field value is peer-supplied and a log line saying only that it
// did not parse is a log line that cannot be acted on — and because a test that asserts the
// offset is asserting which rule fired, where a test that asserts only failure would pass on
// a parser that failed for the wrong reason at the wrong place.
type SyntaxError struct {
	// At is the octet offset into the field value. It is between zero and the length
	// inclusive: the length itself means the input ended while something was still
	// required.
	At int

	// Msg says what was required there. It never contains any of the input: a field
	// value is under a peer's control, and a parser that interpolated it would let a peer
	// write lines into our log.
	Msg string
}

func (e *SyntaxError) Error() string {
	return fmt.Sprintf("structured field: %s at offset %d (RFC 9651 §4.2)", e.Msg, e.At)
}
