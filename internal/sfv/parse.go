package sfv

import (
	"encoding/base64"
	"strings"
	"unicode/utf8"
)

// ParseDictionary parses a Dictionary field value, per §4.2 of RFC 9651 with a field_type
// of dictionary.
//
// An empty value is an empty Dictionary and not an error: §4.2.2 of RFC 9651 ends "No
// structured data has been found; return dictionary (which is empty)", which is what a
// field present but carrying nothing means. A caller that needs to tell "no members" from
// "no field" has to know whether the field was there, and this package cannot tell it.
//
// The two SP-discarding steps that bracket the top-level algorithm are not symmetrical
// here. The leading one is done, because a value may begin with a space and a key may not.
// The trailing one, and §4.2's step 7 with it — a field value with anything left over
// fails — is absent, because a Dictionary cannot leave anything over: the loop below ends
// each member by discarding OWS and then either returning on an empty input or requiring a
// comma. Writing that check would be writing a branch no input can reach, and the reason
// it cannot be reached is worth more here than the branch.
func ParseDictionary(value string) (Dictionary, error) {
	p := &parser{s: value}
	p.skipSP()
	return p.dictionary()
}

// parser is a cursor over one field value.
//
// The value is never modified — the algorithms in §4.2 of RFC 9651 are written as
// destructive consumption of input_string, and an index is the same thing without the
// copying. i is always a valid index or len(s), so every method below is safe to call in
// any order and none of them can be driven off the end.
type parser struct {
	s string
	i int

	// memberAt and paramAt are the lazily built key indexes described on setKeyed.
	// memberAt covers the whole value, because a Dictionary has one key space; paramAt is
	// reset for each parameter list, because each item has its own.
	memberAt map[string]int
	paramAt  map[string]int
}

// empty reports whether the input is exhausted.
func (p *parser) empty() bool { return p.i >= len(p.s) }

// peek is the octet at the cursor, or zero at the end of the input.
//
// Zero for the end is safe rather than merely convenient, and the reason is that NUL is
// not a legal octet anywhere in a structured field: every caller of peek compares it
// against a specific character and treats anything else as the end of a token or as a
// failure, so a NUL in the input takes the same branch the end of input takes, which is
// the branch it belongs in. The one place the difference would matter — the bare item
// dispatch, where the end of input must fail rather than pick a type — fails on both.
func (p *parser) peek() byte {
	if p.empty() {
		return 0
	}
	return p.s[p.i]
}

// skipSP discards spaces. Used where the algorithms say SP, which is inside an Inner List
// and after a parameter's semicolon.
func (p *parser) skipSP() {
	for p.i < len(p.s) && p.s[p.i] == ' ' {
		p.i++
	}
}

// skipOWS discards spaces and horizontal tabs.
//
// Used where the algorithms say OWS, which is around the commas separating members. The
// tab is there for a reason worth keeping: §4.2 of RFC 9651 says the parsing algorithms
// "allow tab characters, since these might be used to combine field lines by some
// implementations", so a value assembled from two field lines by an intermediary parses
// where a stricter reading would reject it.
func (p *parser) skipOWS() {
	for p.i < len(p.s) && (p.s[p.i] == ' ' || p.s[p.i] == '\t') {
		p.i++
	}
}

// errf is a failure at the cursor.
func (p *parser) errf(msg string) error { return &SyntaxError{At: p.i, Msg: msg} }

// dictionary parses a Dictionary, per §4.2.2 of RFC 9651.
func (p *parser) dictionary() (Dictionary, error) {
	var d Dictionary
	for !p.empty() {
		key, err := p.key()
		if err != nil {
			return nil, err
		}

		var value Item
		if p.peek() == '=' {
			p.i++
			if value, err = p.itemOrInnerList(); err != nil {
				return nil, err
			}
		} else {
			// A member written as a bare key is Boolean true, and its parameters
			// belong to that Boolean. This is the form RFC 9218's incremental
			// parameter is usually sent in, so it is the shape most of these values
			// take in practice rather than an obscure corner.
			value = Item{Kind: KindBoolean, Boolean: true}
			if value.Params, err = p.params(); err != nil {
				return nil, err
			}
		}
		d = setKeyed(d, &p.memberAt, Member{Key: key, Value: value})

		p.skipOWS()
		if p.empty() {
			return d, nil
		}
		if p.peek() != ',' {
			return nil, p.errf("a comma between dictionary members")
		}
		p.i++
		p.skipOWS()
		if p.empty() {
			// The whole value fails on a trailing comma. §4.2.2 of RFC 9651 spells
			// this out as its own step rather than leaving it to the next iteration,
			// and the difference is not cosmetic: a loop that simply went round again
			// would find the input empty, exit, and return the members it had — so a
			// truncated field value would parse as a shorter one.
			return nil, p.errf("a dictionary member after the comma")
		}
	}
	return d, nil
}

// keyed is a thing with a key: a Dictionary member, or one parameter.
type keyed interface {
	key() string
}

func (m Member) key() string { return m.Key }
func (p Param) key() string  { return p.Key }

// indexThreshold is the length at which a list starts carrying a key index.
//
// Below it a scan is the cheaper way to find a repeated key: sixteen comparisons of short
// keys that mostly differ in their first octet cost less than hashing one key and touching
// a bucket. The number is not delicate — anything in this region works — and it is a power
// of two only because it reads as a threshold rather than as a measurement.
const indexThreshold = 16

// setKeyed adds or replaces an entry, keeping the position of the first occurrence.
//
// §4.2.2 and §4.2.3.2 of RFC 9651 both resolve a repeated key by overwriting the value in
// an ordered map, which leaves the key where it was; appending instead would move a
// repeated key to the end and so change the order of a value that is only allowed to differ
// in its last occurrence's value.
//
// The index exists because the input is peer-supplied and the obvious implementation is
// quadratic. §3.2 of RFC 9651 requires support for at least 1024 members and §3.1.2 for at
// least 256 parameters, so a conforming parser cannot simply cap the count — and the count
// is bounded only by the length of the field value, which for a PRIORITY_UPDATE payload is
// SETTINGS_MAX_FRAME_SIZE. The shortest possible member is two octets ("a,"), so a 16 KiB
// payload can hold 8192 of them, and scanning for each would be 33 million comparisons for
// one frame — a few tens of milliseconds of CPU that a peer buys for 16 KiB, repeatable for
// as long as the connection lives. With the index it is 8192 hashes, and the map is never
// allocated at all for the two-member values this server actually reads.
func setKeyed[E keyed](list []E, at *map[string]int, e E) []E {
	if *at != nil {
		if i, ok := (*at)[e.key()]; ok {
			list[i] = e
			return list
		}
		(*at)[e.key()] = len(list)
		return append(list, e)
	}

	for i := range list {
		if list[i].key() == e.key() {
			list[i] = e
			return list
		}
	}
	list = append(list, e)

	// Built once, on the entry that crosses the threshold. Every key in the list is
	// distinct by now — that is what the scan above guarantees — so each goes in at its own
	// position and no earlier entry is lost.
	if len(list) == indexThreshold {
		*at = make(map[string]int, 2*indexThreshold)
		for i := range list {
			(*at)[list[i].key()] = i
		}
	}
	return list
}

// itemOrInnerList parses a member or list value, per §4.2.1.1 of RFC 9651.
func (p *parser) itemOrInnerList() (Item, error) {
	if p.peek() == '(' {
		return p.innerList()
	}
	return p.item()
}

// innerList parses an Inner List, per §4.2.1.2 of RFC 9651.
//
// The opening parenthesis is consumed rather than checked. §4.2.1.2's first step is that
// check, and it cannot fail here: itemOrInnerList is the only caller and it dispatches on
// that octet, so a check would be a branch no input can reach.
func (p *parser) innerList() (Item, error) {
	p.i++

	// Empty rather than nil, so that "()" — a legal Inner List of no items — is
	// distinguishable from every other Kind, whose List field is nil.
	list := []Item{}
	for !p.empty() {
		p.skipSP()
		if p.peek() == ')' {
			p.i++
			params, err := p.params()
			if err != nil {
				return Item{}, err
			}
			return Item{Kind: KindInnerList, List: list, Params: params}, nil
		}

		it, err := p.item()
		if err != nil {
			return Item{}, err
		}
		list = append(list, it)

		// A space or the closing parenthesis, and nothing else. Without this an Inner
		// List would accept two items with no separator at all, because the next
		// iteration's skipSP tolerates the absence of the space it is meant to skip.
		//
		// The end of the input is left to the loop, which will report the parenthesis it
		// never found: that is the same failure described better.
		if c := p.peek(); !p.empty() && c != ' ' && c != ')' {
			return Item{}, p.errf("a space between inner list items, or a closing parenthesis")
		}
	}
	return Item{}, p.errf("a closing parenthesis")
}

// item parses a bare item and its parameters, per §4.2.3 of RFC 9651.
func (p *parser) item() (Item, error) {
	it, err := p.bareItem()
	if err != nil {
		return Item{}, err
	}
	if it.Params, err = p.params(); err != nil {
		return Item{}, err
	}
	return it, nil
}

// params parses parameters, per §4.2.3.2 of RFC 9651.
//
// Parameters are optional everywhere they appear, so a value with none is not an error and
// this returns nil for it. A parameter's value is a bare item and never an Inner List,
// which is why bareItem is called here directly rather than itemOrInnerList: "(1 2)" as a
// parameter value is a parse failure and not a list.
func (p *parser) params() (Params, error) {
	// Each item has its own key space, so the previous item's index — if it grew one — must
	// not be consulted for this one. Reset rather than allocated: the map is built only if
	// this list gets long enough to need it, which for a parameter list it almost never is.
	p.paramAt = nil

	var ps Params
	for p.peek() == ';' {
		p.i++
		p.skipSP()

		key, err := p.key()
		if err != nil {
			return nil, err
		}

		value := Item{Kind: KindBoolean, Boolean: true}
		if p.peek() == '=' {
			p.i++
			if value, err = p.bareItem(); err != nil {
				return nil, err
			}
		}
		ps = setKeyed(ps, &p.paramAt, Param{Key: key, Value: value})
	}
	return ps, nil
}

// key parses a key, per §4.2.3.3 of RFC 9651.
//
// A key may begin with a lower-case letter or an asterisk, and may continue with those,
// digits, and four punctuation marks. Upper case is not a key: a Dictionary is
// case-sensitive, and a peer that sends "U=1" has not sent an urgency.
func (p *parser) key() (string, error) {
	if c := p.peek(); !isLCAlpha(c) && c != '*' {
		return "", p.errf("a key beginning with a lower-case letter or an asterisk")
	}
	start := p.i
	for !p.empty() {
		c := p.s[p.i]
		if !isLCAlpha(c) && !isDigit(c) && c != '_' && c != '-' && c != '.' && c != '*' {
			break
		}
		p.i++
	}
	return p.s[start:p.i], nil
}

// bareItem parses a bare item, per §4.2.3.1 of RFC 9651.
//
// The dispatch is on the first octet, and it is total: every octet that begins a legal
// bare item selects exactly one type, and everything else — including the end of the
// input, which peek reports as a zero octet — fails here rather than deeper in. That is
// what makes the failure message worth reading: a value the parser cannot begin is a
// different mistake from one it began and could not finish.
func (p *parser) bareItem() (Item, error) {
	switch c := p.peek(); {
	case c == '-' || isDigit(c):
		return p.number()
	case c == '"':
		return p.text()
	case isAlpha(c) || c == '*':
		return p.token()
	case c == ':':
		return p.byteSequence()
	case c == '?':
		return p.boolean()
	case c == '@':
		return p.date()
	case c == '%':
		return p.displayString()
	default:
		return Item{}, p.errf("a value of one of the eight item types")
	}
}

// Bounds from §3.3.1 and §3.3.2 of RFC 9651, which are what keep every value in this
// package inside an int64.
const (
	// maxIntegerDigits is the digits an Integer may have.
	maxIntegerDigits = 15

	// maxDecimalIntegerDigits is the digits a Decimal may have before the point, and
	// maxDecimalFractionDigits the digits after it.
	maxDecimalIntegerDigits  = 12
	maxDecimalFractionDigits = 3

	// thousand is the scale Item.Thousandths is held at.
	thousand = 1000
)

// number parses an Integer or a Decimal, per §4.2.4 of RFC 9651.
//
// The digits are scanned first and the length rules applied to the run afterwards, where
// the algorithm applies them as it goes. The set of values accepted is the same, because a
// failure is total either way and no other rule depends on which octet the parser stopped
// at; what differs is the offset in the error, and the offset of the digit that broke a
// length rule is less use than the position of the number that broke it.
//
// §4.2.4's sixteen-character cap on a Decimal is not written out, because these two are
// what it is made of: twelve digits, a point, and three digits is sixteen characters, so a
// Decimal that satisfies both of the caps below satisfies that one too, and one that fails
// either of them is refused here whatever its length.
func (p *parser) number() (Item, error) {
	at := p.i

	sign := int64(1)
	if p.peek() == '-' {
		p.i++
		if p.empty() {
			return Item{}, p.errf("digits after the minus sign")
		}
		sign = -1
	}
	if !isDigit(p.peek()) {
		// Also the end of the input, which peek reports as a zero octet: a Date written
		// as a bare at sign arrives here, and what it is missing is a digit.
		return Item{}, p.errf("a number beginning with a digit")
	}

	start := p.i
	point := -1
	for !p.empty() {
		c := p.s[p.i]
		if isDigit(c) {
			p.i++
			continue
		}
		// The first point turns an Integer into a Decimal. A second one ends the number
		// and is left for the caller to fail on, which is what §4.2.4 does by falling
		// through to its step that puts the character back: "1.2.3" is the Decimal 1.2
		// followed by ".3", and ".3" is not a comma.
		if c == '.' && point < 0 {
			point = p.i
			p.i++
			continue
		}
		break
	}
	run := p.s[start:p.i]

	if point < 0 {
		if len(run) > maxIntegerDigits {
			p.i = at
			return Item{}, p.errf("an integer of at most fifteen digits")
		}
		return Item{Kind: KindInteger, Integer: sign * digits(run)}, nil
	}

	whole, frac := run[:point-start], run[point-start+1:]
	if len(whole) > maxDecimalIntegerDigits {
		p.i = at
		return Item{}, p.errf("a decimal with at most twelve digits before the point")
	}
	if len(frac) == 0 {
		p.i = at
		return Item{}, p.errf("a decimal with a digit after the point")
	}
	if len(frac) > maxDecimalFractionDigits {
		p.i = at
		return Item{}, p.errf("a decimal with at most three digits after the point")
	}

	// Scaled by hand rather than parsed as a float. Three digits of fraction are exactly a
	// thousandth each, so the value is an integer count of them: 1.5 is 1500 thousandths,
	// and so is 1.500. Padding the fraction out to three digits is what makes those two
	// the same number, which is what they are.
	scale := int64(thousand)
	for range len(frac) {
		scale /= 10
	}
	return Item{Kind: KindDecimal, Thousandths: sign * (digits(whole)*thousand + digits(frac)*scale)}, nil
}

// digits is the value of a run of ASCII digits.
//
// No overflow check, and none is needed: every caller has already bounded the run at
// fifteen characters, and 10^15 is four thousand times smaller than the largest int64. It
// is written out rather than handed to strconv because the error strconv would return
// cannot happen here, and a discarded error is a worse thing to leave in a parser than
// four lines of arithmetic.
func digits(s string) int64 {
	n := int64(0)
	for i := range len(s) {
		n = n*10 + int64(s[i]-'0')
	}
	return n
}

// text parses a String, per §4.2.5 of RFC 9651.
//
// The quotation marks are not part of the value and the two escapes are undone, so what
// comes back is what the sender meant rather than what it wrote. Only DQUOTE and backslash
// may be escaped: §4.2.5 fails on any other escape rather than passing it through, which is
// the difference between one canonical spelling of a string and several.
func (p *parser) text() (Item, error) {
	p.i++ // the opening DQUOTE, which bareItem dispatched on

	// Nothing is copied until an escape forces it. A String with no backslash in it —
	// which is nearly all of them — is a slice of the field value and costs no allocation.
	start := p.i
	var b strings.Builder
	for !p.empty() {
		c := p.s[p.i]
		switch {
		case c == '\\':
			if b.Len() == 0 {
				b.Grow(len(p.s) - start)
			}
			b.WriteString(p.s[start:p.i])
			p.i++
			if p.empty() {
				return Item{}, p.errf("a character after the backslash")
			}
			esc := p.s[p.i]
			if esc != '"' && esc != '\\' {
				return Item{}, p.errf("a quotation mark or a backslash after the backslash")
			}
			b.WriteByte(esc)
			p.i++
			start = p.i
		case c == '"':
			p.i++
			// An empty builder means no escape has been seen, because the branch above
			// writes exactly one octet for every escape it accepts. So the value is a
			// slice of the field value, and the only copy is the one the caller keeps.
			if b.Len() == 0 {
				return Item{Kind: KindString, Text: p.s[start : p.i-1]}, nil
			}
			b.WriteString(p.s[start : p.i-1])
			return Item{Kind: KindString, Text: b.String()}, nil
		case c < 0x20 || c >= 0x7f:
			// §4.2.5 of RFC 9651 fails on any octet outside VCHAR and SP. A control
			// character in a field value is either a mistake or an attempt to write a
			// line into somebody's log, and neither is a string.
			return Item{}, p.errf("a printable character or a space inside the string")
		default:
			p.i++
		}
	}
	return Item{}, p.errf("a closing quotation mark")
}

// token parses a Token, per §4.2.6 of RFC 9651.
//
// A Token is returned as it appeared, case and all: §3.3.4 makes no claim that two tokens
// differing in case are the same token, and a parser that lowered the case would be
// deciding a question the field's own specification owns.
func (p *parser) token() (Item, error) {
	start := p.i
	p.i++ // the ALPHA or asterisk bareItem dispatched on
	for !p.empty() && isTChar(p.s[p.i]) {
		p.i++
	}
	return Item{Kind: KindToken, Text: p.s[start:p.i]}, nil
}

// byteSequence parses a Byte Sequence, per §4.2.7 of RFC 9651.
//
// Two of that section's requirements pull in opposite directions and both are met here.
// Padding is optional, because §4.2.7 of RFC 9651 tells a parser not to fail on encoded
// data that arrives without it — so the padding is stripped and the unpadded decoder used,
// which accepts either spelling. The alphabet is not optional. §4.2.7 of RFC 9651: "parsers
// MUST fail on characters outside the base64 alphabet and on line feeds in encoded data",
// so the content is checked against the alphabet before it is decoded, and a padding
// character anywhere but the end is left in place for the decoder to refuse.
func (p *parser) byteSequence() (Item, error) {
	at := p.i
	p.i++ // the opening colon

	end := strings.IndexByte(p.s[p.i:], ':')
	if end < 0 {
		p.i = at
		return Item{}, p.errf("a closing colon on the byte sequence")
	}
	content := p.s[p.i : p.i+end]
	p.i += end + 1

	for i := range len(content) {
		if c := content[i]; !isAlpha(c) && !isDigit(c) && c != '+' && c != '/' && c != '=' {
			p.i = at
			return Item{}, p.errf("base64 content in the base64 alphabet")
		}
	}

	// The padding this strips has already been checked to be padding characters, and what
	// is left is decoded by the unpadded encoding — which is the same alphabet with the
	// length rule relaxed, so a value sent either way decodes to the same octets.
	//
	// Stripping is the whole of the leniency, and it is deliberately not selective: ":=:"
	// and ":abcd=:" are accepted, as an empty Byte Sequence and as three octets, where a
	// parser that demanded canonical padding would refuse both. Nothing in §4.2.7 of RFC
	// 9651 requires refusing them, the section's advice runs the other way, and the
	// alternative is a rule about how much padding is too much for a value whose length was
	// already established by its content. What is not relaxed is the alphabet, checked
	// above, and the length: three characters of base64 are two octets, and a group of one
	// is not a group, so the decoder still refuses it.
	b, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(content, "="))
	if err != nil {
		p.i = at
		return Item{}, p.errf("base64 content that decodes")
	}
	return Item{Kind: KindByteSequence, Bytes: b}, nil
}

// boolean parses a Boolean, per §4.2.8 of RFC 9651.
func (p *parser) boolean() (Item, error) {
	p.i++ // the question mark

	switch p.peek() {
	case '1':
		p.i++
		return Item{Kind: KindBoolean, Boolean: true}, nil
	case '0':
		p.i++
		return Item{Kind: KindBoolean, Boolean: false}, nil
	default:
		return Item{}, p.errf("a zero or a one after the question mark")
	}
}

// date parses a Date, per §4.2.9 of RFC 9651.
//
// A Date is an Integer of seconds and may be negative, which is a moment before 1970 and
// not an error. A Decimal is refused: a Date is a whole number of seconds, and a sender
// that means half of one has to mean something else.
func (p *parser) date() (Item, error) {
	at := p.i
	p.i++ // the at sign

	n, err := p.number()
	if err != nil {
		return Item{}, err
	}
	if n.Kind != KindInteger {
		p.i = at
		return Item{}, p.errf("whole seconds in the date")
	}
	return Item{Kind: KindDate, Integer: n.Integer}, nil
}

// displayString parses a Display String, per §4.2.10 of RFC 9651.
//
// Two things separate this from a String, and both are in the loop below. The escape is
// percent-encoding rather than a backslash, with lower-case hexadecimal only, so a
// backslash inside a Display String is an ordinary character. And the result is octets
// that must decode as UTF-8, which is checked once at the end: a Display String is defined
// as a sequence of Unicode code points, and a percent escape can produce an octet sequence
// that is not one.
func (p *parser) displayString() (Item, error) {
	at := p.i
	if !strings.HasPrefix(p.s[p.i:], `%"`) {
		return Item{}, p.errf("a quotation mark after the percent sign")
	}
	p.i += 2

	var b strings.Builder
	for !p.empty() {
		c := p.peek()
		switch {
		case c < 0x20 || c >= 0x7f:
			return Item{}, p.errf("a printable character or a space inside the display string")
		case c == '%':
			if p.i+3 > len(p.s) {
				p.i++
				return Item{}, p.errf("two hexadecimal digits after the percent sign")
			}
			hi, lo := unhex(p.s[p.i+1]), unhex(p.s[p.i+2])
			if hi < 0 || lo < 0 {
				p.i++
				return Item{}, p.errf("two lower-case hexadecimal digits after the percent sign")
			}
			b.WriteByte(byte(hi<<4 | lo))
			p.i += 3
		case c == '"':
			p.i++
			if !utf8.ValidString(b.String()) {
				p.i = at
				return Item{}, p.errf("display string content that decodes as UTF-8")
			}
			return Item{Kind: KindDisplayString, Text: b.String()}, nil
		default:
			b.WriteByte(c)
			p.i++
		}
	}
	return Item{}, p.errf("a closing quotation mark on the display string")
}

// unhex is the value of one lower-case hexadecimal digit, or -1.
//
// Lower case only, and that is §4.2.10 of RFC 9651's rule rather than an omission: it
// refuses an escape outside 0-9 and a-f, so "%2F" is a failure where "%2f" is a solidus.
// One canonical spelling is worth having, and a Display String has one.
func unhex(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	default:
		return -1
	}
}

func isDigit(c byte) bool   { return c >= '0' && c <= '9' }
func isLCAlpha(c byte) bool { return c >= 'a' && c <= 'z' }
func isAlpha(c byte) bool   { return isLCAlpha(c) || (c >= 'A' && c <= 'Z') }

// isTChar reports whether c may continue a Token: a tchar from §5.6.2 of RFC 9110, or a
// colon or a solidus, which §3.3.4 of RFC 9651 adds so that a Token can hold a media type
// or a scheme-relative reference.
func isTChar(c byte) bool {
	switch c {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~', ':', '/':
		return true
	default:
		return isAlpha(c) || isDigit(c)
	}
}
