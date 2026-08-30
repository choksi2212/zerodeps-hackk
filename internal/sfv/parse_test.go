package sfv

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The constructors below exist so that a table row reads as the value it means rather than
// as four struct fields, three of which are zero. They are not a second implementation of
// anything: each one sets Kind and the single field Kind names, which is the whole of the
// invariant an Item has.

func integer(n int64) Item           { return Item{Kind: KindInteger, Integer: n} }
func decimal(th int64) Item          { return Item{Kind: KindDecimal, Thousandths: th} }
func str(s string) Item              { return Item{Kind: KindString, Text: s} }
func token(s string) Item            { return Item{Kind: KindToken, Text: s} }
func boolean(b bool) Item            { return Item{Kind: KindBoolean, Boolean: b} }
func date(n int64) Item              { return Item{Kind: KindDate, Integer: n} }
func display(s string) Item          { return Item{Kind: KindDisplayString, Text: s} }
func param(k string, v Item) Param   { return Param{Key: k, Value: v} }
func member(k string, v Item) Member { return Member{Key: k, Value: v} }

// bytesOf builds a Byte Sequence from the octets it decodes to. The slice is always
// non-nil, including for the empty sequence, because that is what the decoder returns and
// a comparison that treated nil and empty as different would fail on ":​:" for a reason
// that has nothing to do with parsing.
func bytesOf(s string) Item {
	return Item{Kind: KindByteSequence, Bytes: append(make([]byte, 0, len(s)), s...)}
}

// inner builds an Inner List. The list is non-nil even when empty, for the same reason.
func inner(items ...Item) Item {
	if items == nil {
		items = []Item{}
	}
	return Item{Kind: KindInnerList, List: items}
}

// with attaches parameters to an item.
func with(it Item, ps ...Param) Item {
	it.Params = ps
	return it
}

func wantNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// syntaxErrorFrom asserts the error is one of ours and hands back its detail. A parser
// that returned a bare errors.New would satisfy a test that only checked for non-nil, and
// then no caller could tell where the value went wrong.
func syntaxErrorFrom(t *testing.T, err error) *SyntaxError {
	t.Helper()
	if err == nil {
		t.Fatal("want a parse failure, got none")
	}
	se, ok := err.(*SyntaxError)
	if !ok {
		t.Fatalf("error is %T (%v), want *SyntaxError", err, err)
	}
	return se
}

func showItem(it Item) string {
	var s string
	switch it.Kind {
	case KindInteger, KindDate:
		s = fmt.Sprintf("%s %d", it.Kind, it.Integer)
	case KindDecimal:
		s = fmt.Sprintf("decimal %d/1000", it.Thousandths)
	case KindString, KindToken, KindDisplayString:
		s = fmt.Sprintf("%s %q", it.Kind, it.Text)
	case KindByteSequence:
		s = fmt.Sprintf("byte sequence %q", it.Bytes)
	case KindBoolean:
		s = fmt.Sprintf("boolean %t", it.Boolean)
	case KindInnerList:
		parts := make([]string, len(it.List))
		for i, m := range it.List {
			parts[i] = showItem(m)
		}
		s = "(" + strings.Join(parts, " ") + ")"
		if it.List == nil {
			s = "(nil)"
		}
	default:
		s = it.Kind.String()
	}
	for _, pr := range it.Params {
		s += fmt.Sprintf(";%s=%s", pr.Key, showItem(pr.Value))
	}
	return s
}

func show(d Dictionary) string {
	if d == nil {
		return "<nil dictionary>"
	}
	parts := make([]string, len(d))
	for i, m := range d {
		parts[i] = m.Key + "=" + showItem(m.Value)
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

func wantDictionary(t *testing.T, in string, want Dictionary) {
	t.Helper()
	got, err := ParseDictionary(in)
	wantNoErr(t, err)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseDictionary(%q) =\n\t%s\nwant\n\t%s", in, show(got), show(want))
	}
}

// TestParseDictionaryFromTheExamplesInTheSpecifications parses the field values that RFC
// 9651 and RFC 9218 print as examples.
//
// These are the cases a parser cannot argue with. Everything else in this file is a rule
// read out of an algorithm and turned into a table; these are values the specifications
// themselves chose to show, so a disagreement here is a disagreement about the whole
// grammar rather than about one branch.
func TestParseDictionaryFromTheExamplesInTheSpecifications(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want Dictionary
	}{
		{
			name: "a string and a byte sequence (§3.2 of RFC 9651)",
			in:   `en="Applepie", da=:w4ZibGV0w6ZydGU=:`,
			want: Dictionary{
				member("en", str("Applepie")),
				member("da", bytesOf("Æbletærte")),
			},
		},
		{
			name: "an explicit false and two omitted trues (§3.2 of RFC 9651)",
			in:   `a=?0, b, c; foo=bar`,
			want: Dictionary{
				member("a", boolean(false)),
				member("b", boolean(true)),
				member("c", with(boolean(true), param("foo", token("bar")))),
			},
		},
		{
			name: "a decimal and an inner list of tokens (§3.2 of RFC 9651)",
			in:   `rating=1.5, feelings=(joy sadness)`,
			want: Dictionary{
				member("rating", decimal(1500)),
				member("feelings", inner(token("joy"), token("sadness"))),
			},
		},
		{
			name: "items and inner lists, some parameterised (§3.2 of RFC 9651)",
			in:   `a=(1 2), b=3, c=4;aa=bb, d=(5 6);valid`,
			want: Dictionary{
				member("a", inner(integer(1), integer(2))),
				member("b", integer(3)),
				member("c", with(integer(4), param("aa", token("bb")))),
				member("d", with(inner(integer(5), integer(6)), param("valid", boolean(true)))),
			},
		},
		{
			name: "an item with two parameters, one false (§3.1.2 of RFC 9651)",
			in:   `x=1; a; b=?0`,
			want: Dictionary{
				member("x", with(integer(1), param("a", boolean(true)), param("b", boolean(false)))),
			},
		},
		{
			name: "a parameterised integer (§3.3.1 of RFC 9651)",
			in:   `x=5; foo=bar`,
			want: Dictionary{member("x", with(integer(5), param("foo", token("bar"))))},
		},
		{
			name: "a decimal (§3.3.2 of RFC 9651)",
			in:   `x=4.5`,
			want: Dictionary{member("x", decimal(4500))},
		},
		{
			name: "a string with a space in it (§3.3.3 of RFC 9651)",
			in:   `x="hello world"`,
			want: Dictionary{member("x", str("hello world"))},
		},
		{
			name: "a token with a solidus and digits (§3.3.4 of RFC 9651)",
			in:   `x=foo123/456`,
			want: Dictionary{member("x", token("foo123/456"))},
		},
		{
			name: "the byte sequence example, padded (§3.3.5 of RFC 9651)",
			in:   `x=:cHJldGVuZCB0aGlzIGlzIGJpbmFyeSBjb250ZW50Lg==:`,
			want: Dictionary{member("x", bytesOf("pretend this is binary content."))},
		},
		{
			name: "a true boolean written out (§3.3.6 of RFC 9651)",
			in:   `x=?1`,
			want: Dictionary{member("x", boolean(true))},
		},
		{
			name: "a date (§3.3.7 of RFC 9651)",
			in:   `x=@1659578233`,
			want: Dictionary{member("x", date(1659578233))},
		},
		{
			name: "a display string with a percent escape (§3.3.8 of RFC 9651)",
			in:   `x=%"This is intended for display to %c3%bcsers."`,
			want: Dictionary{member("x", display("This is intended for display to üsers."))},
		},
		{
			name: "the lowest urgency (§2.1 of RFC 9218)",
			in:   `u=0`,
			want: Dictionary{member("u", integer(0))},
		},
		{
			name: "an urgency and an incremental flag (§5 of RFC 9218)",
			in:   `u=5, i`,
			want: Dictionary{
				member("u", integer(5)),
				member("i", boolean(true)),
			},
		},
		{
			name: "a reprioritisation to the highest urgency (§8 of RFC 9218)",
			in:   `u=1`,
			want: Dictionary{member("u", integer(1))},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantDictionary(t, tt.in, tt.want)
		})
	}
}

// TestParseDictionaryOmittedValueIsBooleanTrue covers the form RFC 9218's incremental
// parameter arrives in, which is the one a naive parser gets wrong: there is no "=" and no
// value, and the member is still true rather than absent or empty.
func TestParseDictionaryOmittedValueIsBooleanTrue(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want Dictionary
	}{
		{
			name: "on its own",
			in:   `i`,
			want: Dictionary{member("i", boolean(true))},
		},
		{
			name: "the same thing written out",
			in:   `i=?1`,
			want: Dictionary{member("i", boolean(true))},
		},
		{
			name: "before another member",
			in:   `i, u=3`,
			want: Dictionary{member("i", boolean(true)), member("u", integer(3))},
		},
		{
			name: "after another member",
			in:   `u=3, i`,
			want: Dictionary{member("u", integer(3)), member("i", boolean(true))},
		},
		{
			name: "with parameters of its own",
			in:   `i;q=1;r`,
			want: Dictionary{member("i", with(boolean(true), param("q", integer(1)), param("r", boolean(true))))},
		},
		{
			name: "a parameter with no value is true as well",
			in:   `u=3;background`,
			want: Dictionary{member("u", with(integer(3), param("background", boolean(true))))},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantDictionary(t, tt.in, tt.want)
		})
	}
}

// TestParseDictionaryLastOccurrenceOfAKeyWinsAndKeepsItsPlace is the rule from §4.2.2 of
// RFC 9651 that an ordered map has and a slice does not get for free.
//
// Both halves matter and they are easy to get half right. A parser that appended would
// have the right value in the wrong place, and one that ignored the second occurrence
// would have the right place and the wrong value.
func TestParseDictionaryLastOccurrenceOfAKeyWinsAndKeepsItsPlace(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want Dictionary
	}{
		{
			name: "two values for one key",
			in:   `u=1, u=7`,
			want: Dictionary{member("u", integer(7))},
		},
		{
			name: "the position of the first occurrence is kept",
			in:   `u=1, i, u=7`,
			want: Dictionary{member("u", integer(7)), member("i", boolean(true))},
		},
		{
			name: "three occurrences",
			in:   `a=1, b=2, a=3, a=4`,
			want: Dictionary{member("a", integer(4)), member("b", integer(2))},
		},
		{
			name: "the later value replaces the parameters too",
			in:   `a=1;x=1, a=2`,
			want: Dictionary{member("a", integer(2))},
		},
		{
			name: "an omitted value replaces a written one",
			in:   `i=?0, i`,
			want: Dictionary{member("i", boolean(true))},
		},
		{
			name: "a repeated parameter key resolves the same way",
			in:   `a=1;p=1;q=2;p=3`,
			want: Dictionary{member("a", with(integer(1), param("p", integer(3)), param("q", integer(2))))},
		},
		{
			name: "keys are case sensitive, so this is not a repeat",
			in:   `a=1, a*=2`,
			want: Dictionary{member("a", integer(1)), member("a*", integer(2))},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantDictionary(t, tt.in, tt.want)
		})
	}
}

// TestParseDictionaryAcceptsSpacesAndTabsAroundCommas covers the OWS rule, including the
// tab that §4.2 of RFC 9651 admits so that a value reassembled from two field lines parses.
func TestParseDictionaryAcceptsSpacesAndTabsAroundCommas(t *testing.T) {
	want := Dictionary{member("u", integer(3)), member("i", boolean(true))}
	for _, in := range []string{
		"u=3, i",
		"u=3,i",
		"u=3 , i",
		"u=3\t,\ti",
		"u=3   ,   i",
		"u=3,\t \ti",
		" u=3, i",
		"   u=3, i",
		"u=3, i ",
		"u=3, i\t",
		"u=3 , i \t ",
	} {
		t.Run(fmt.Sprintf("%q", in), func(t *testing.T) {
			wantDictionary(t, in, want)
		})
	}
}

// TestParseDictionaryLeadingTabIsNotWhitespaceHere is the asymmetry in §4.2 of RFC 9651
// that is easy to smooth over by accident: the leading discard is SP only, where the
// discards around commas are OWS. A value that begins with a tab is malformed, and a
// parser that trimmed both would accept it.
func TestParseDictionaryLeadingTabIsNotWhitespaceHere(t *testing.T) {
	_, err := ParseDictionary("\tu=3")
	se := syntaxErrorFrom(t, err)
	if se.At != 0 {
		t.Fatalf("offset %d, want 0: %v", se.At, se)
	}
}

// TestParseDictionaryEmptyValueHasNoMembers covers §4.2.2 of RFC 9651's last step. The
// result is an empty Dictionary and not an error, because a field that is present and
// carries nothing is a legal thing for a peer to send.
func TestParseDictionaryEmptyValueHasNoMembers(t *testing.T) {
	for _, in := range []string{"", " ", "   "} {
		t.Run(fmt.Sprintf("%q", in), func(t *testing.T) {
			got, err := ParseDictionary(in)
			wantNoErr(t, err)
			if len(got) != 0 {
				t.Fatalf("ParseDictionary(%q) = %s, want no members", in, show(got))
			}
			if _, ok := got.Get("u"); ok {
				t.Fatal("Get found a member in an empty dictionary")
			}
		})
	}
}

// messages is every failure a *SyntaxError can carry.
//
// The set is closed on purpose and this test file is where that is enforced: the sweep at
// the end of the file parses hundreds of thousands of malformed values and asserts that
// every message it sees is in here. A parser that interpolated any part of a peer-supplied
// field value into an error — which is how a peer writes a line into somebody's log —
// could not pass that, because the interpolated message would not be one of these.
var messages = map[string]bool{
	"a comma between dictionary members":                         true,
	"a dictionary member after the comma":                        true,
	"a space between inner list items, or a closing parenthesis": true,
	"a closing parenthesis":                                      true,
	"a key beginning with a lower-case letter or an asterisk":    true,
	"a value of one of the eight item types":                     true,
	"digits after the minus sign":                                true,
	"a number beginning with a digit":                            true,
	"an integer of at most fifteen digits":                       true,
	"a decimal with at most twelve digits before the point":      true,
	"a decimal with a digit after the point":                     true,
	"a decimal with at most three digits after the point":        true,
	"a character after the backslash":                            true,
	"a quotation mark or a backslash after the backslash":        true,
	"a printable character or a space inside the string":         true,
	"a closing quotation mark":                                   true,
	"a closing colon on the byte sequence":                       true,
	"base64 content in the base64 alphabet":                      true,
	"base64 content that decodes":                                true,
	"a zero or a one after the question mark":                    true,
	"whole seconds in the date":                                  true,
	"a quotation mark after the percent sign":                    true,
	"a printable character or a space inside the display string": true,
	"two hexadecimal digits after the percent sign":              true,
	"two lower-case hexadecimal digits after the percent sign":   true,
	"display string content that decodes as UTF-8":               true,
	"a closing quotation mark on the display string":             true,
}

// TestParseDictionaryRejects is the negative table, and every row asserts the offset as
// well as the failure.
//
// The offset is what says which rule fired. Without it a row like "1.2.3" would pass on a
// parser that failed for the right reason and on one that failed three characters early
// for the wrong one, and the difference between those two parsers is whether the error
// tells a reader anything.
func TestParseDictionaryRejects(t *testing.T) {
	tests := []struct {
		name string
		in   string
		at   int
		msg  string
	}{
		// Keys.
		{"an upper-case key", `A=1`, 0, "a key beginning with a lower-case letter or an asterisk"},
		{"a key beginning with a digit", `1=1`, 0, "a key beginning with a lower-case letter or an asterisk"},
		{"a key beginning with an underscore", `_a=1`, 0, "a key beginning with a lower-case letter or an asterisk"},
		{"an upper-case letter inside a key", `aA=1`, 1, "a comma between dictionary members"},
		{"nothing before the equals", `=1`, 0, "a key beginning with a lower-case letter or an asterisk"},
		{"a comma and then only whitespace", `a=1, `, 5, "a dictionary member after the comma"},

		// Structure.
		{"a trailing comma", `a=1,`, 4, "a dictionary member after the comma"},
		{"a leading comma", `,a=1`, 0, "a key beginning with a lower-case letter or an asterisk"},
		{"two commas", `a=1,,b=2`, 4, "a key beginning with a lower-case letter or an asterisk"},
		{"a missing comma", `a=1 b=2`, 4, "a comma between dictionary members"},
		{"nothing after the equals", `a=`, 2, "a value of one of the eight item types"},
		{"an equals after the equals", `a==1`, 2, "a value of one of the eight item types"},
		{"whitespace after the equals", `a= 1`, 2, "a value of one of the eight item types"},
		{"whitespace before the equals", `a =1`, 2, "a comma between dictionary members"},

		// Parameters.
		{"a semicolon with no parameter", `a=1;`, 4, "a key beginning with a lower-case letter or an asterisk"},
		{"two semicolons", `a=1;;p`, 4, "a key beginning with a lower-case letter or an asterisk"},
		{"a parameter with no value after the equals", `a=1;p=`, 6, "a value of one of the eight item types"},
		{"a parameter whose value is an inner list", `a=1;p=(1 2)`, 6, "a value of one of the eight item types"},
		{"whitespace before a parameter's semicolon", `a=1 ;p=2`, 4, "a comma between dictionary members"},

		// Inner lists.
		{"an unterminated inner list", `a=(1 2`, 6, "a closing parenthesis"},
		{"an unterminated empty inner list", `a=(`, 3, "a closing parenthesis"},
		{"a nested inner list", `a=((1))`, 3, "a value of one of the eight item types"},
		{"no separator between items", `a=(1"x")`, 4, "a space between inner list items, or a closing parenthesis"},
		{"a comma as a separator", `a=(1,2)`, 4, "a space between inner list items, or a closing parenthesis"},
		{"a closing parenthesis with nothing open", `a=)`, 2, "a value of one of the eight item types"},

		// Integers and decimals.
		{"sixteen digits", `a=1234567890123456`, 2, "an integer of at most fifteen digits"},
		{"sixteen digits, negative", `a=-1234567890123456`, 2, "an integer of at most fifteen digits"},
		{"a minus sign with no digits", `a=-`, 3, "digits after the minus sign"},
		{"a minus sign and a point", `a=-.1`, 3, "a number beginning with a digit"},
		{"a point with no digits before it", `a=.1`, 2, "a value of one of the eight item types"},
		{"a point with no digits after it", `a=1.`, 2, "a decimal with a digit after the point"},
		{"four digits after the point", `a=1.2345`, 2, "a decimal with at most three digits after the point"},
		{"thirteen digits before the point", `a=1234567890123.4`, 2, "a decimal with at most twelve digits before the point"},
		{"two points", `a=1.2.3`, 5, "a comma between dictionary members"},

		// Strings.
		{"an unterminated string", `a="x`, 4, "a closing quotation mark"},
		{"a backslash at the end", `a="x\`, 5, "a character after the backslash"},
		{"an escaped n", `a="x\n"`, 5, "a quotation mark or a backslash after the backslash"},
		{"a tab inside a string", "a=\"x\ty\"", 4, "a printable character or a space inside the string"},
		{"a delete inside a string", "a=\"x\x7fy\"", 4, "a printable character or a space inside the string"},
		{"a high octet inside a string", "a=\"x\xc3\xa9y\"", 4, "a printable character or a space inside the string"},

		// Byte sequences.
		{"an unterminated byte sequence", `a=:aGk`, 2, "a closing colon on the byte sequence"},
		{"a character outside the alphabet", `a=:a*k:`, 2, "base64 content in the base64 alphabet"},
		{"a line feed inside the content", "a=:aG\nk:", 2, "base64 content in the base64 alphabet"},
		{"a group of one character", `a=:a:`, 2, "base64 content that decodes"},
		{"padding in the middle", `a=:a=k=:`, 2, "base64 content that decodes"},

		// Booleans, dates, display strings.
		{"a boolean that is neither", `a=?2`, 3, "a zero or a one after the question mark"},
		{"a question mark on its own", `a=?`, 3, "a zero or a one after the question mark"},
		{"a fractional date", `a=@1.5`, 2, "whole seconds in the date"},
		{"an at sign on its own", `a=@`, 3, "a number beginning with a digit"},
		{"a display string with no quotation mark", `a=%x`, 2, "a quotation mark after the percent sign"},
		{"a percent sign on its own", `a=%`, 2, "a quotation mark after the percent sign"},
		{"an unterminated display string", `a=%"x`, 5, "a closing quotation mark on the display string"},
		{"one hexadecimal digit", `a=%"%c"`, 5, "two lower-case hexadecimal digits after the percent sign"},
		{"upper-case hexadecimal", `a=%"%C3%A9"`, 5, "two lower-case hexadecimal digits after the percent sign"},
		{"a percent escape at the end", `a=%"%`, 5, "two hexadecimal digits after the percent sign"},
		{"an escape that is not UTF-8", `a=%"%ff"`, 2, "display string content that decodes as UTF-8"},
		{"a truncated UTF-8 sequence", `a=%"%c3"`, 2, "display string content that decodes as UTF-8"},

		// Values that are not any type at all.
		{"an octet that begins nothing", `a=!`, 2, "a value of one of the eight item types"},
		{"a NUL where a value goes", "a=\x00", 2, "a value of one of the eight item types"},
		{"a high octet where a value goes", "a=\xff", 2, "a value of one of the eight item types"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseDictionary(tt.in)
			if err == nil {
				t.Fatalf("ParseDictionary(%q) = %s, want a failure", tt.in, show(got))
			}
			if got != nil {
				t.Fatalf("ParseDictionary(%q) returned %s alongside its error, want nothing", tt.in, show(got))
			}
			se := syntaxErrorFrom(t, err)
			if se.At != tt.at || se.Msg != tt.msg {
				t.Fatalf("ParseDictionary(%q) failed with %q at %d, want %q at %d",
					tt.in, se.Msg, se.At, tt.msg, tt.at)
			}
			if !messages[se.Msg] {
				t.Fatalf("message %q is not in the closed set", se.Msg)
			}
			if !strings.Contains(se.Error(), tt.msg) {
				t.Fatalf("Error() = %q, want it to contain %q", se.Error(), tt.msg)
			}
		})
	}
}

// TestParseIntegerBoundaries walks the edge of §3.3.1 of RFC 9651's fifteen digits from
// both sides, and covers the two spellings of zero that a sign makes possible.
func TestParseIntegerBoundaries(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want int64
	}{
		{"zero", `a=0`, 0},
		{"minus zero", `a=-0`, 0},
		{"leading zeroes", `a=000000000000005`, 5},
		{"one", `a=1`, 1},
		{"minus one", `a=-1`, -1},
		{"fifteen digits", `a=999999999999999`, 999999999999999},
		{"fifteen digits, negative", `a=-999999999999999`, -999999999999999},
		{"fifteen digits of leading zero", `a=000000000000000`, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantDictionary(t, tt.in, Dictionary{member("a", integer(tt.want))})
		})
	}
}

// TestParseDecimalIsExactInThousandths is the reason Item does not hold a float64.
//
// Two spellings of the same number must give the same value, and the largest legal Decimal
// must survive being scaled — both of which a float64 fails at, the first because 1.1 is
// not representable and the second because 10^15 needs more than 53 bits of mantissa.
func TestParseDecimalIsExactInThousandths(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want int64
	}{
		{"one digit of fraction", `a=1.5`, 1500},
		{"two digits", `a=1.50`, 1500},
		{"three digits", `a=1.500`, 1500},
		{"a fraction that no float64 holds exactly", `a=0.1`, 100},
		{"the smallest step", `a=0.001`, 1},
		{"negative", `a=-1.5`, -1500},
		{"negative zero", `a=-0.0`, 0},
		{"twelve digits and three", `a=999999999999.999`, 999999999999999},
		{"twelve digits and one", `a=999999999999.9`, 999999999999900},
		{"twelve digits and three, negative", `a=-999999999999.999`, -999999999999999},
		{"a whole number written as a decimal", `a=5.0`, 5000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantDictionary(t, tt.in, Dictionary{member("a", decimal(tt.want))})
		})
	}
}

// TestParseDecimalAndIntegerAreDifferentKinds is the distinction a caller acts on: 3 and
// 3.0 are the same quantity and not the same item, and RFC 9218's urgency is an Integer,
// so a peer that sends u=3.0 has not sent an urgency.
func TestParseDecimalAndIntegerAreDifferentKinds(t *testing.T) {
	d, err := ParseDictionary(`whole=3, fractional=3.0`)
	wantNoErr(t, err)

	whole, _ := d.Get("whole")
	fractional, _ := d.Get("fractional")
	if whole.Kind != KindInteger || fractional.Kind != KindDecimal {
		t.Fatalf("kinds are %s and %s, want integer and decimal", whole.Kind, fractional.Kind)
	}
	if whole.Integer != 3 || fractional.Integer != 0 {
		t.Fatalf("Integer fields are %d and %d: a decimal must not fill the integer field",
			whole.Integer, fractional.Integer)
	}
	if whole.Thousandths != 0 || fractional.Thousandths != 3000 {
		t.Fatalf("Thousandths fields are %d and %d: an integer must not fill the decimal field",
			whole.Thousandths, fractional.Thousandths)
	}
}

// TestParseStringUnescapes covers §4.2.5 of RFC 9651, including the two escapes that exist
// and the fact that everything else printable passes through untouched.
func TestParseStringUnescapes(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", `a=""`, ""},
		{"plain", `a="hello"`, "hello"},
		{"an escaped quotation mark", `a="\""`, `"`},
		{"an escaped backslash", `a="\\"`, `\`},
		{"both escapes together", `a="\\\""`, `\"`},
		{"an escape at the start", `a="\"x"`, `"x`},
		{"an escape at the end", `a="x\""`, `x"`},
		{"two escapes apart", `a="\"x\""`, `"x"`},
		{"a space", `a=" "`, " "},
		{"the printable extremes", `a="!~"`, "!~"},
		{"characters that mean something elsewhere", `a="a=1, b;c()@%?:"`, "a=1, b;c()@%?:"},
		{"a comma inside a string is not a separator", `a="x,y"`, "x,y"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantDictionary(t, tt.in, Dictionary{member("a", str(tt.want))})
		})
	}
}

// TestParseStringWithACommaIsOneMember is the case that rules out reading a Dictionary by
// splitting on commas, which is the shortcut this package exists to avoid.
func TestParseStringWithACommaIsOneMember(t *testing.T) {
	d, err := ParseDictionary(`a="x,y", b=2`)
	wantNoErr(t, err)
	if len(d) != 2 {
		t.Fatalf("got %s, want two members", show(d))
	}
	if v, _ := d.Get("a"); v.Text != "x,y" {
		t.Fatalf("first member is %q, want %q", v.Text, "x,y")
	}
}

// TestParseTokenKeepsCaseAndPunctuation covers §4.2.6 of RFC 9651. A Token is the one text
// type that arrives exactly as it was sent.
func TestParseTokenKeepsCaseAndPunctuation(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"lower case", `a=bar`, "bar"},
		{"upper case is kept", `a=Bar`, "Bar"},
		{"all upper case", `a=BAR`, "BAR"},
		{"one letter", `a=b`, "b"},
		{"beginning with an asterisk", `a=*`, "*"},
		{"a media type", `a=text/html`, "text/html"},
		{"a colon", `a=foo:bar`, "foo:bar"},
		{"every other tchar", "a=t!#$%&'*+-.^_`|~09", "t!#$%&'*+-.^_`|~09"},
		{"a digit inside", `a=h2c`, "h2c"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantDictionary(t, tt.in, Dictionary{member("a", token(tt.want))})
		})
	}
}

// TestParseTokenStopsAtACharacterItCannotHold checks that a Token ends without consuming
// what follows it, which is what lets a parameter or a comma come next.
func TestParseTokenStopsAtACharacterItCannotHold(t *testing.T) {
	wantDictionary(t, `a=bar;p=1, b=baz`, Dictionary{
		member("a", with(token("bar"), param("p", integer(1)))),
		member("b", token("baz")),
	})
}

// TestParseByteSequenceAcceptsEitherPadding covers §4.2.7 of RFC 9651's advice not to fail
// on padding, and the leniency this parser takes from it.
func TestParseByteSequenceAcceptsEitherPadding(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", `a=::`, ""},
		{"two octets, padded", `a=:aGk=:`, "hi"},
		{"two octets, unpadded", `a=:aGk:`, "hi"},
		{"three octets need no padding", `a=:aGkh:`, "hi!"},
		{"five octets, padded", `a=:aGVsbG8=:`, "hello"},
		{"five octets, unpadded", `a=:aGVsbG8:`, "hello"},
		{"non-zero pad bits are not a failure", `a=:aa:`, "i"},
		{"more padding than a value needs", `a=:aGk==:`, "hi"},
		{"padding with nothing to pad", `a=:=:`, ""},
		{"the whole alphabet", `a=:/+ab:`, "\xff\xe6\x9b"},
		{"octets that are not text", `a=:AAECAw:`, "\x00\x01\x02\x03"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantDictionary(t, tt.in, Dictionary{member("a", bytesOf(tt.want))})
		})
	}
}

// TestParseByteSequenceIsACopy checks that the octets do not alias the field value. A
// caller that kept a Byte Sequence would otherwise keep the whole field alive with it.
func TestParseByteSequenceIsACopy(t *testing.T) {
	d, err := ParseDictionary(`a=:aGVsbG8=:`)
	wantNoErr(t, err)
	v, _ := d.Get("a")
	if len(v.Bytes) != 5 {
		t.Fatalf("decoded %d octets, want 5", len(v.Bytes))
	}
	if cap(v.Bytes) > 16 {
		t.Fatalf("capacity %d for five octets, which suggests a slice of the field value", cap(v.Bytes))
	}
}

// TestParseBooleanIsOnlyZeroOrOne covers §4.2.8 of RFC 9651.
func TestParseBooleanIsOnlyZeroOrOne(t *testing.T) {
	wantDictionary(t, `t=?1, f=?0`, Dictionary{
		member("t", boolean(true)),
		member("f", boolean(false)),
	})
}

// TestParseDateSpansTheYearsTheSpecificationRequires covers §4.2.9 and the range in §3.3.7
// of RFC 9651, which reaches from year 1 to year 9999 and so needs a signed value.
func TestParseDateSpansTheYearsTheSpecificationRequires(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want int64
	}{
		{"the epoch", `a=@0`, 0},
		{"the example date", `a=@1659578233`, 1659578233},
		{"one second before the epoch", `a=@-1`, -1},
		{"the first day of year 1", `a=@-62135596800`, -62135596800},
		{"the last day of year 9999", `a=@253402214400`, 253402214400},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantDictionary(t, tt.in, Dictionary{member("a", date(tt.want))})
		})
	}
}

// TestParseDisplayStringDecodesPercentEscapes covers §4.2.10 of RFC 9651: the escape is
// percent-encoding, the hexadecimal is lower case, and the result has to be UTF-8.
func TestParseDisplayStringDecodesPercentEscapes(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", `a=%""`, ""},
		{"no escapes", `a=%"hello"`, "hello"},
		{"a two-octet rune", `a=%"%c3%bc"`, "ü"},
		{"a three-octet rune", `a=%"%e2%82%ac"`, "€"},
		{"a four-octet rune", `a=%"%f0%9f%94%92"`, "🔒"},
		{"an escape among text", `a=%"b%c3%bcsers"`, "büsers"},
		{"an escaped percent sign", `a=%"100%25"`, "100%"},
		{"an escaped quotation mark", `a=%"%22"`, `"`},
		{"a backslash is not an escape here", `a=%"a\b"`, `a\b`},
		{"an escaped NUL", `a=%"%00"`, "\x00"},
		{"a space", `a=%" "`, " "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantDictionary(t, tt.in, Dictionary{member("a", display(tt.want))})
		})
	}
}

// TestParseInnerListStructure covers §4.2.1.2 of RFC 9651: where the spaces go, what an
// empty list looks like, and which parameters belong to the list rather than to its
// members.
func TestParseInnerListStructure(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want Item
	}{
		{"empty", `a=()`, inner()},
		{"empty with a space in it", `a=( )`, inner()},
		{"one item", `a=(1)`, inner(integer(1))},
		{"two items", `a=(1 2)`, inner(integer(1), integer(2))},
		{"extra spaces between items", `a=(1   2)`, inner(integer(1), integer(2))},
		{"spaces at the edges", `a=( 1 2 )`, inner(integer(1), integer(2))},
		{"mixed types", `a=(1 1.5 "s" tok :aGk: ?1 @0 %"d")`, inner(
			integer(1), decimal(1500), str("s"), token("tok"),
			bytesOf("hi"), boolean(true), date(0), display("d"),
		)},
		{"a parameter on a member", `a=(1;p=2 3)`, inner(with(integer(1), param("p", integer(2))), integer(3))},
		{"a parameter on the list", `a=(1 2);p=3`, with(inner(integer(1), integer(2)), param("p", integer(3)))},
		{"parameters on both", `a=(1;p 2);q`, with(
			inner(with(integer(1), param("p", boolean(true))), integer(2)),
			param("q", boolean(true)),
		)},
		{"a parameter on an empty list", `a=();p`, with(inner(), param("p", boolean(true)))},
		{"a string with a space in it is one member", `a=("x y")`, inner(str("x y"))},
		{"a string with a parenthesis in it", `a=("x)y")`, inner(str("x)y"))},
		{"the inner list example from §3.1.1 of RFC 9651", `a=("foo"; b=1;c=2);lvl=5`, with(
			inner(with(str("foo"), param("b", integer(1)), param("c", integer(2)))),
			param("lvl", integer(5)),
		)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantDictionary(t, tt.in, Dictionary{member("a", tt.want)})
		})
	}
}

// TestEmptyInnerListIsNotAnAbsentOne checks the one place a nil and an empty slice mean
// different things: every Kind but KindInnerList has a nil List, and an Inner List of no
// members has an empty one.
func TestEmptyInnerListIsNotAnAbsentOne(t *testing.T) {
	d, err := ParseDictionary(`list=(), number=1`)
	wantNoErr(t, err)

	list, _ := d.Get("list")
	if list.List == nil {
		t.Fatal("an empty inner list has a nil List, so a caller cannot tell it from an item")
	}
	if len(list.List) != 0 {
		t.Fatalf("an empty inner list has %d members", len(list.List))
	}
	number, _ := d.Get("number")
	if number.List != nil {
		t.Fatalf("an integer has a non-nil List of %d", len(number.List))
	}
}

// TestParametersOnEveryKindOfValue checks that parameters attach to all eight bare item
// types and to an Inner List, since the parser reaches them by nine different paths.
func TestParametersOnEveryKindOfValue(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want Item
	}{
		{"integer", `a=1;p=1`, with(integer(1), param("p", integer(1)))},
		{"decimal", `a=1.5;p=1`, with(decimal(1500), param("p", integer(1)))},
		{"string", `a="s";p=1`, with(str("s"), param("p", integer(1)))},
		{"token", `a=tok;p=1`, with(token("tok"), param("p", integer(1)))},
		{"byte sequence", `a=:aGk:;p=1`, with(bytesOf("hi"), param("p", integer(1)))},
		{"boolean", `a=?0;p=1`, with(boolean(false), param("p", integer(1)))},
		{"date", `a=@0;p=1`, with(date(0), param("p", integer(1)))},
		{"display string", `a=%"d";p=1`, with(display("d"), param("p", integer(1)))},
		{"inner list", `a=(1);p=1`, with(inner(integer(1)), param("p", integer(1)))},
		{"an omitted value", `a;p=1`, with(boolean(true), param("p", integer(1)))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantDictionary(t, tt.in, Dictionary{member("a", tt.want)})
		})
	}
}

// TestParameterValuesCanBeAnyBareItem checks the other half: a parameter's value reaches
// all eight types, and a space after the semicolon is allowed where one before it is not.
func TestParameterValuesCanBeAnyBareItem(t *testing.T) {
	wantDictionary(t, `a=1; p1=1; p2=1.5; p3="s"; p4=tok; p5=:aGk:; p6=?0; p7=@0; p8=%"d"; p9`,
		Dictionary{member("a", with(integer(1),
			param("p1", integer(1)),
			param("p2", decimal(1500)),
			param("p3", str("s")),
			param("p4", token("tok")),
			param("p5", bytesOf("hi")),
			param("p6", boolean(false)),
			param("p7", date(0)),
			param("p8", display("d")),
			param("p9", boolean(true)),
		))})
}

// TestGetReadsMembersAndParameters covers the two lookups a caller uses, including what
// they say about a key that is not there: KindNone, which is not a value of any type.
func TestGetReadsMembersAndParameters(t *testing.T) {
	d, err := ParseDictionary(`u=3;fallback=7, i`)
	wantNoErr(t, err)

	u, ok := d.Get("u")
	if !ok || u.Kind != KindInteger || u.Integer != 3 {
		t.Fatalf(`Get("u") = %s, %t`, showItem(u), ok)
	}
	fallback, ok := u.Params.Get("fallback")
	if !ok || fallback.Integer != 7 {
		t.Fatalf(`Get("fallback") = %s, %t`, showItem(fallback), ok)
	}
	if _, ok := u.Params.Get("i"); ok {
		t.Fatal("a member's key was found among another member's parameters")
	}

	absent, ok := d.Get("q")
	if ok {
		t.Fatalf(`Get("q") found %s`, showItem(absent))
	}
	if absent.Kind != KindNone {
		t.Fatalf("an absent member reads as %s, want none", absent.Kind)
	}
	if _, ok := Dictionary(nil).Get("u"); ok {
		t.Fatal("Get found a member in a nil dictionary")
	}
	if _, ok := Params(nil).Get("u"); ok {
		t.Fatal("Get found a parameter in a nil parameter list")
	}
}

// TestKindStringNamesEveryKind keeps the names in step with the constants. A Kind is in
// failure messages and in tests, so a name that belonged to the next constant along would
// mislead in exactly the situation someone is reading it.
func TestKindStringNamesEveryKind(t *testing.T) {
	tests := []struct {
		kind Kind
		want string
	}{
		{KindNone, "none"},
		{KindInteger, "integer"},
		{KindDecimal, "decimal"},
		{KindString, "string"},
		{KindToken, "token"},
		{KindByteSequence, "byte sequence"},
		{KindBoolean, "boolean"},
		{KindDate, "date"},
		{KindDisplayString, "display string"},
		{KindInnerList, "inner list"},
	}
	if len(tests) != len(kindNames) {
		t.Fatalf("%d kinds named here, %d in the package", len(tests), len(kindNames))
	}
	for _, tt := range tests {
		if got := tt.kind.String(); got != tt.want {
			t.Errorf("Kind(%d).String() = %q, want %q", uint8(tt.kind), got, tt.want)
		}
	}
	if got := Kind(len(kindNames)).String(); !strings.Contains(got, "unknown") {
		t.Errorf("Kind(%d).String() = %q, want it to say the kind is unknown", len(kindNames), got)
	}
}

// TestParseSupportsTheMinimaTheSpecificationRequires builds the values §3 of RFC 9651 says
// a parser MUST handle. Every one of these is a size a peer is entitled to send, so a
// parser that fell over on any of them would be refusing a legal field.
func TestParseSupportsTheMinimaTheSpecificationRequires(t *testing.T) {
	t.Run("1024 dictionary members", func(t *testing.T) {
		var b strings.Builder
		for i := range 1024 {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "k%d=%d", i, i)
		}
		d, err := ParseDictionary(b.String())
		wantNoErr(t, err)
		if len(d) != 1024 {
			t.Fatalf("parsed %d members, want 1024", len(d))
		}
		// In order, and each with its own value: the index that makes this linear must
		// not have crossed two keys over.
		for i, m := range d {
			if m.Key != fmt.Sprintf("k%d", i) || m.Value.Integer != int64(i) {
				t.Fatalf("member %d is %s=%s", i, m.Key, showItem(m.Value))
			}
		}
		if v, ok := d.Get("k1023"); !ok || v.Integer != 1023 {
			t.Fatalf(`Get("k1023") = %s, %t`, showItem(v), ok)
		}
	})

	t.Run("a key of 64 characters", func(t *testing.T) {
		key := "k" + strings.Repeat("e", 63)
		d, err := ParseDictionary(key + "=1")
		wantNoErr(t, err)
		if _, ok := d.Get(key); !ok {
			t.Fatalf("a 64-character key parsed as %s", show(d))
		}
	})

	t.Run("256 parameters", func(t *testing.T) {
		var b strings.Builder
		b.WriteString("a=1")
		for i := range 256 {
			fmt.Fprintf(&b, ";p%d=%d", i, i)
		}
		d, err := ParseDictionary(b.String())
		wantNoErr(t, err)
		v, _ := d.Get("a")
		if len(v.Params) != 256 {
			t.Fatalf("parsed %d parameters, want 256", len(v.Params))
		}
		for i, pr := range v.Params {
			if pr.Key != fmt.Sprintf("p%d", i) || pr.Value.Integer != int64(i) {
				t.Fatalf("parameter %d is %s=%s", i, pr.Key, showItem(pr.Value))
			}
		}
	})

	t.Run("256 inner list members", func(t *testing.T) {
		var b strings.Builder
		b.WriteString("a=(")
		for i := range 256 {
			if i > 0 {
				b.WriteByte(' ')
			}
			fmt.Fprintf(&b, "%d", i)
		}
		b.WriteString(")")
		d, err := ParseDictionary(b.String())
		wantNoErr(t, err)
		v, _ := d.Get("a")
		if len(v.List) != 256 {
			t.Fatalf("parsed %d members, want 256", len(v.List))
		}
	})

	t.Run("a string of 1024 characters", func(t *testing.T) {
		want := strings.Repeat("s", 1024)
		d, err := ParseDictionary(`a="` + want + `"`)
		wantNoErr(t, err)
		if v, _ := d.Get("a"); v.Text != want {
			t.Fatalf("parsed %d characters, want 1024", len(v.Text))
		}
	})

	t.Run("a string of 1024 characters after unescaping", func(t *testing.T) {
		d, err := ParseDictionary(`a="` + strings.Repeat(`\\`, 1024) + `"`)
		wantNoErr(t, err)
		if v, _ := d.Get("a"); v.Text != strings.Repeat(`\`, 1024) {
			t.Fatalf("parsed %d characters, want 1024", len(v.Text))
		}
	})

	t.Run("a token of 512 characters", func(t *testing.T) {
		want := strings.Repeat("t", 512)
		d, err := ParseDictionary("a=" + want)
		wantNoErr(t, err)
		if v, _ := d.Get("a"); v.Text != want {
			t.Fatalf("parsed %d characters, want 512", len(v.Text))
		}
	})

	t.Run("a byte sequence of 16384 octets", func(t *testing.T) {
		want := strings.Repeat("\x00\x01\x02", 5462) // 16386 octets, a multiple of three
		d, err := ParseDictionary("a=:" + base64Of(want) + ":")
		wantNoErr(t, err)
		if v, _ := d.Get("a"); string(v.Bytes) != want {
			t.Fatalf("decoded %d octets, want %d", len(v.Bytes), len(want))
		}
	})
}

// base64Of is the standard base64 of a string, written here rather than imported into the
// package under test, so that the test's expectation does not come from the same call the
// parser makes.
func base64Of(s string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var b strings.Builder
	for i := 0; i < len(s); i += 3 {
		var group [3]byte
		n := copy(group[:], s[i:])
		v := uint32(group[0])<<16 | uint32(group[1])<<8 | uint32(group[2])
		out := []byte{
			alphabet[v>>18&0x3f],
			alphabet[v>>12&0x3f],
			alphabet[v>>6&0x3f],
			alphabet[v&0x3f],
		}
		switch n {
		case 1:
			out[2], out[3] = '=', '='
		case 2:
			out[3] = '='
		}
		b.Write(out)
	}
	return b.String()
}

// TestKeyIndexAgreesWithTheScanItReplaces walks the count of keys across the threshold at
// which duplicate resolution stops scanning and starts hashing.
//
// The two paths have to agree exactly, and the boundary is where they would not: an index
// built one entry early would miss the key that crossed it, and one built late would let a
// duplicate through. So every count from one to well past the threshold is checked, with
// the duplicate at the front, in the middle, and at the back of each.
func TestKeyIndexAgreesWithTheScanItReplaces(t *testing.T) {
	for n := 1; n <= indexThreshold*3; n++ {
		// Front, middle, and back, without repeating a position when the three coincide:
		// two subtests of the same name are one subtest run twice and a name Go has to
		// invent.
		ats := []int{0}
		if n/2 != 0 {
			ats = append(ats, n/2)
		}
		if n-1 != 0 && n-1 != n/2 {
			ats = append(ats, n-1)
		}
		for _, at := range ats {
			t.Run(fmt.Sprintf("%d keys, repeating the one at %d", n, at), func(t *testing.T) {
				var b strings.Builder
				for i := range n {
					if i > 0 {
						b.WriteString(", ")
					}
					fmt.Fprintf(&b, "k%d=%d", i, i)
				}
				fmt.Fprintf(&b, ", k%d=%d", at, 9000+at)

				d, err := ParseDictionary(b.String())
				wantNoErr(t, err)
				if len(d) != n {
					t.Fatalf("parsed %d members, want %d: %s", len(d), n, show(d))
				}
				for i, m := range d {
					want := int64(i)
					if i == at {
						want = int64(9000 + at)
					}
					if m.Key != fmt.Sprintf("k%d", i) || m.Value.Integer != want {
						t.Fatalf("member %d is %s=%s, want k%d=%d",
							i, m.Key, showItem(m.Value), i, want)
					}
				}
			})
		}
	}
}

// TestParameterIndexIsNotSharedBetweenItems is the mistake the index makes possible: one
// map for the whole value would let a parameter of the first item satisfy a lookup for the
// second, and the second item's own parameter would then overwrite a position in a list it
// does not belong to.
func TestParameterIndexIsNotSharedBetweenItems(t *testing.T) {
	// Enough parameters on the first item to force its index into existence, then a
	// second item using the same keys.
	var b strings.Builder
	b.WriteString("first=1")
	for i := range indexThreshold + 2 {
		fmt.Fprintf(&b, ";p%d=%d", i, i)
	}
	b.WriteString(", second=2")
	for i := range indexThreshold + 2 {
		fmt.Fprintf(&b, ";p%d=%d", i, 100+i)
	}

	d, err := ParseDictionary(b.String())
	wantNoErr(t, err)
	first, _ := d.Get("first")
	second, _ := d.Get("second")
	if len(first.Params) != indexThreshold+2 || len(second.Params) != indexThreshold+2 {
		t.Fatalf("parameter counts are %d and %d, want %d each",
			len(first.Params), len(second.Params), indexThreshold+2)
	}
	for i := range indexThreshold + 2 {
		key := fmt.Sprintf("p%d", i)
		if v, _ := first.Params.Get(key); v.Integer != int64(i) {
			t.Fatalf("first item's %s is %s, want %d", key, showItem(v), i)
		}
		if v, _ := second.Params.Get(key); v.Integer != int64(100+i) {
			t.Fatalf("second item's %s is %s, want %d", key, showItem(v), 100+i)
		}
	}
}

// TestManyMembersIsNotQuadratic is the reason the index exists. The input is peer-supplied
// and its length is bounded only by a frame or a header field, so the work per octet has
// to stay flat.
//
// The measurement is a ratio and not a time, because a wall-clock threshold on a shared
// build machine is a flaky test. Sixteen times the members is sixteen times the work for a
// linear parser and 256 times for a quadratic one, so a factor well inside that range
// separates them without depending on how fast the machine is — and the best of three
// attempts is taken, so that one unlucky pause cannot fail a parser that is linear.
func TestManyMembersIsNotQuadratic(t *testing.T) {
	if testing.Short() {
		t.Skip("timing comparison")
	}
	build := func(n int) string {
		var b strings.Builder
		for i := range n {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, "k%d=1", i)
		}
		return b.String()
	}
	small, large := build(512), build(512*16)

	// Both sizes are parsed the same number of times, so the comparison is between two
	// totals of the same shape.
	const rounds = 20
	took := func(in string) time.Duration {
		start := time.Now()
		for range rounds {
			if _, err := ParseDictionary(in); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		}
		return time.Since(start)
	}
	// A warm round first, so that neither total pays for the first allocation of the
	// buffers the parser grows into.
	took(small)
	took(large)

	best := 0.0
	for attempt := range 3 {
		one, sixteen := took(small), took(large)
		if one <= 0 {
			t.Skip("clock resolution too coarse to compare")
		}
		ratio := float64(sixteen) / float64(one)
		if attempt == 0 || ratio < best {
			best = ratio
		}
	}
	if best > 64 {
		t.Fatalf("sixteen times the members took %.1f times as long, which is quadratic", best)
	}
}

// TestParseNeverPanicsOnAnyTruncationOrSubstitution is the adversarial sweep.
//
// It takes a set of values that exercise every branch, and from each one derives every
// prefix and every single-octet substitution over all 256 values at every position. That
// is a few hundred thousand field values, almost all of them malformed, and the assertions
// are the ones that have to hold for every input a peer can send: the parser returns rather
// than panics, a failure is a *SyntaxError whose offset is inside the value and whose
// message is one of the closed set, and a success is a Dictionary whose structure is one
// the grammar can produce.
//
// The last of those is what makes this more than a crash test. A parser can survive fuzzing
// while quietly returning a member with no key, an item of no kind, or an Inner List nested
// inside another — and each of those would be a lie told to a caller that trusted the type.
func TestParseNeverPanicsOnAnyTruncationOrSubstitution(t *testing.T) {
	bases := []string{
		`u=3, i`,
		`en="Applepie", da=:w4ZibGV0w6ZydGU=:`,
		`a=(1 2), b=3, c=4;aa=bb, d=(5 6);valid`,
		`a=1.5;p="x\\y", b=@-1, c=%"%c3%bc", d=?0, e=*tok:x/y`,
		`a=(), b=(1;p 2);q, c=:aGk=:`,
		`k=-999999999999.999, l=999999999999999`,
	}
	parses := 0
	for _, base := range bases {
		for cut := range len(base) + 1 {
			checkOne(t, base[:cut])
			parses++
		}
		for pos := range len(base) {
			for b := range 256 {
				// Spliced as an octet and not as a rune: a rune above 0x7f would
				// encode as two octets and change the length as well as the value,
				// which is a different mutation from the one being made here.
				mutated := base[:pos] + string([]byte{byte(b)}) + base[pos+1:]
				checkOne(t, mutated)
				parses++
			}
		}
	}
	if parses < 10000 {
		t.Fatalf("only %d values swept, which is not a sweep", parses)
	}
	t.Logf("%d field values parsed", parses)
}

// checkOne parses one value and asserts everything that must hold for every input.
func checkOne(t *testing.T, in string) {
	t.Helper()

	d, err := ParseDictionary(in)
	if err != nil {
		if d != nil {
			t.Fatalf("ParseDictionary(%q) returned %s alongside %v", in, show(d), err)
		}
		se, ok := err.(*SyntaxError)
		if !ok {
			t.Fatalf("ParseDictionary(%q) failed with %T (%v), want *SyntaxError", in, err, err)
		}
		if se.At < 0 || se.At > len(in) {
			t.Fatalf("ParseDictionary(%q) failed at offset %d, outside 0..%d", in, se.At, len(in))
		}
		if !messages[se.Msg] {
			t.Fatalf("ParseDictionary(%q) failed with %q, which is not in the closed set", in, se.Msg)
		}
		return
	}

	seen := make(map[string]bool, len(d))
	for _, m := range d {
		if seen[m.Key] {
			t.Fatalf("ParseDictionary(%q) = %s, with %q twice", in, show(d), m.Key)
		}
		seen[m.Key] = true
		checkKey(t, in, m.Key)
		checkValue(t, in, m.Value, true)
	}
}

func checkValue(t *testing.T, in string, it Item, listsAllowed bool) {
	t.Helper()

	switch it.Kind {
	case KindNone:
		t.Fatalf("ParseDictionary(%q) produced a value of no kind", in)
	case KindInnerList:
		if !listsAllowed {
			t.Fatalf("ParseDictionary(%q) produced an inner list where only a bare item fits", in)
		}
		if it.List == nil {
			t.Fatalf("ParseDictionary(%q) produced an inner list with a nil list", in)
		}
		for _, m := range it.List {
			checkValue(t, in, m, false)
		}
	default:
		if it.List != nil {
			t.Fatalf("ParseDictionary(%q) produced a %s carrying a list", in, it.Kind)
		}
	}

	seen := make(map[string]bool, len(it.Params))
	for _, pr := range it.Params {
		if seen[pr.Key] {
			t.Fatalf("ParseDictionary(%q) produced %q twice among one item's parameters", in, pr.Key)
		}
		seen[pr.Key] = true
		checkKey(t, in, pr.Key)
		checkValue(t, in, pr.Value, false)
	}
}

// checkKey asserts a key is one §4.2.3.3 of RFC 9651 could have produced. A key comes back
// as a slice of the input, so a parser that mislaid an index would return something that
// is not a key at all, and every caller that used it as a map key would carry the mistake.
func checkKey(t *testing.T, in, key string) {
	t.Helper()

	if key == "" {
		t.Fatalf("ParseDictionary(%q) produced an empty key", in)
	}
	if c := key[0]; !isLCAlpha(c) && c != '*' {
		t.Fatalf("ParseDictionary(%q) produced key %q, which begins with %q", in, key, string(c))
	}
	for i := 1; i < len(key); i++ {
		c := key[i]
		if !isLCAlpha(c) && !isDigit(c) && c != '_' && c != '-' && c != '.' && c != '*' {
			t.Fatalf("ParseDictionary(%q) produced key %q, which holds %q", in, key, string(c))
		}
	}
}

// FuzzParseDictionary hands the same assertions to the fuzzer, which finds the inputs a
// written table does not think of.
//
// The seeds are the values from the sweep plus the shapes that are only one octet away
// from a different meaning, since those are where a fuzzer's mutations pay off.
func FuzzParseDictionary(f *testing.F) {
	for _, seed := range []string{
		``,
		` `,
		`u=3, i`,
		`u=3;p=1, i;q`,
		`a=(1 2);p, b="x\"y", c=:aGk=:, d=%"%c3%bc", e=@-1, f=?0, g=1.5, h=*t:x/y`,
		`a=(), b=(()), c=(1,2), d=(1 2`,
		`a=1.2.3, b=-, c=@1.5, d=?2, e=%"%C3", f=:a:`,
		`a=1,`,
		`,`,
		`;`,
		`=`,
		`a`,
		`*=1`,
		`a=1, a=2, a=3`,
		strings.Repeat("a", 100) + "=1",
		`a="` + strings.Repeat(`\\`, 50) + `"`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in string) {
		checkOne(t, in)
	})
}
