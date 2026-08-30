package priority

import (
	"errors"
	"math"
	"strings"
	"testing"

	"zerodeps/zdh/internal/sfv"
)

// mustParse is for the inputs a test asserts nothing about the parsing of.
func mustParse(t *testing.T, field string) Params {
	t.Helper()
	p, err := Parse(field)
	if err != nil {
		t.Fatalf("Parse(%q): %v", field, err)
	}
	return p
}

// TestTheConstantsAreTheDocumentsNumbers pins the two numbers §4.1 of RFC 9218 gives,
// because nothing else in this file can. Every other test reads DefaultUrgency rather
// than 3, which is the right way to write them — a table that hard-coded the default
// would have to be edited if this package ever renamed it — and the consequence is that
// the constant's own value is asserted nowhere else. A DefaultUrgency of 0 would make
// every unprioritized request the most urgent thing on the connection, and the whole
// suite would stay green.
//
// §4.1 of RFC 9218: "between 0 and 7 inclusive, in descending order of priority"
func TestTheConstantsAreTheDocumentsNumbers(t *testing.T) {
	if DefaultUrgency != 3 {
		t.Errorf("DefaultUrgency = %d, want 3", DefaultUrgency)
	}
	if MaxUrgency != 7 {
		t.Errorf("MaxUrgency = %d, want 7", MaxUrgency)
	}
	// And the two have to be consistent with each other, because Urgency() returns the
	// default for an absent parameter and its callers index a table of MaxUrgency+1
	// entries with the result.
	if DefaultUrgency < 0 || DefaultUrgency > MaxUrgency {
		t.Errorf("DefaultUrgency %d is outside 0..%d, so Urgency() can return a value that "+
			"WithUrgency would panic on", DefaultUrgency, MaxUrgency)
	}
}

// TestParseDefaults is the shape of the field values that say nothing. Each of these has
// to arrive as the zero Params — not as urgency 3 with the parameter marked present —
// because §8 of RFC 9218 gives those two different answers when a response merges over
// them.
func TestParseDefaults(t *testing.T) {
	for _, field := range []string{
		"",
		"   ",
		"unknown",
		"x=1",
		"visible=?1, safe",
		// A key of "*" is legal in a Dictionary and is not a priority parameter.
		"*=1",
		// Registered later, perhaps, but not by this document.
		"urgency=0, incremental=?1",
	} {
		p := mustParse(t, field)
		if p != (Params{}) {
			t.Errorf("Parse(%q) = %+v, want the zero Params", field, p)
		}
		if p.Urgency() != DefaultUrgency {
			t.Errorf("Parse(%q).Urgency() = %d, want %d", field, p.Urgency(), DefaultUrgency)
		}
		if p.Incremental() {
			t.Errorf("Parse(%q).Incremental() = true, want false", field)
		}
		if p.HasUrgency() || p.HasIncremental() {
			t.Errorf("Parse(%q) reports a parameter present that was not sent", field)
		}
	}
}

func TestParseValid(t *testing.T) {
	tests := []struct {
		field       string
		urgency     int
		hasUrgency  bool
		incremental bool
		hasIncr     bool
	}{
		{field: "u=0", urgency: 0, hasUrgency: true},
		{field: "u=1", urgency: 1, hasUrgency: true},
		{field: "u=3", urgency: 3, hasUrgency: true},
		{field: "u=7", urgency: MaxUrgency, hasUrgency: true},
		// A bare key is Boolean true (§4.2.2 of RFC 9651), so "i" and "i=?1" are one
		// signal spelled two ways.
		{field: "i", urgency: DefaultUrgency, incremental: true, hasIncr: true},
		{field: "i=?1", urgency: DefaultUrgency, incremental: true, hasIncr: true},
		{field: "i=?0", urgency: DefaultUrgency, incremental: false, hasIncr: true},
		{
			field: "u=5, i", urgency: 5, hasUrgency: true,
			incremental: true, hasIncr: true,
		},
		{
			// Order is not significance. §3.2 of RFC 9651 keeps it, and §4 of RFC 9218
			// gives it no meaning.
			field: "i, u=5", urgency: 5, hasUrgency: true,
			incremental: true, hasIncr: true,
		},
		{
			// No optional whitespace at all is legal.
			field: "u=5,i", urgency: 5, hasUrgency: true,
			incremental: true, hasIncr: true,
		},
		{
			// And so is a great deal of it, on the side §4.2.2 of RFC 9651 permits it.
			field: "u=5,\t  i", urgency: 5, hasUrgency: true,
			incremental: true, hasIncr: true,
		},
		{
			// Parameters on a member are not priority parameters, and nothing in RFC 9218
			// says a member may not carry them. The value is an Integer in range, so the
			// urgency is 2 and the parameter attached to it is somebody else's business.
			field: "u=2;q=0.5", urgency: 2, hasUrgency: true,
		},
		{
			field: "i;why=\"because\"", urgency: DefaultUrgency,
			incremental: true, hasIncr: true,
		},
		{
			// The parameters this document defines, buried in ones it does not.
			field:   "a=1, u=0, b=(1 2), i, c=:AAEC:, d=@1659578233, e=%\"h\"",
			urgency: 0, hasUrgency: true, incremental: true, hasIncr: true,
		},
		{
			// "-0" is a legal Integer and is zero, which is in range. Worth pinning: a
			// parser that rejected the minus sign for an unsigned parameter would refuse
			// a signal that is inside the range the specification gives.
			field: "u=-0", urgency: 0, hasUrgency: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			p := mustParse(t, tt.field)
			if p.Urgency() != tt.urgency {
				t.Errorf("Urgency() = %d, want %d", p.Urgency(), tt.urgency)
			}
			if p.HasUrgency() != tt.hasUrgency {
				t.Errorf("HasUrgency() = %v, want %v", p.HasUrgency(), tt.hasUrgency)
			}
			if p.Incremental() != tt.incremental {
				t.Errorf("Incremental() = %v, want %v", p.Incremental(), tt.incremental)
			}
			if p.HasIncremental() != tt.hasIncr {
				t.Errorf("HasIncremental() = %v, want %v", p.HasIncremental(), tt.hasIncr)
			}
		})
	}
}

// TestParseIgnoresOutOfRangeUrgency is one of the three things §4 of RFC 9218 requires to
// be ignored, and the one where ignoring differs from the obvious alternative: the
// parameter is dropped, not clamped. "u=9" schedules at 3, not at 7.
//
// Clamping would be worse than wrong. A client that asked for the lowest precedence and got
// the default would be competing with the requests it meant to yield to, and nothing in the
// protocol would tell it so.
func TestParseIgnoresOutOfRangeUrgency(t *testing.T) {
	for _, field := range []string{
		"u=8",
		"u=9",
		"u=-1",
		"u=100",
		"u=999999999999999",  // fifteen digits, the most §3.3.1 of RFC 9651 allows
		"u=-999999999999999", // and the same going the other way
	} {
		p := mustParse(t, field)
		if p != (Params{}) {
			t.Errorf("Parse(%q) = %+v, want the parameter ignored", field, p)
		}
		if p.Urgency() != DefaultUrgency {
			t.Errorf("Parse(%q).Urgency() = %d, want the default %d — an out-of-range value "+
				"was clamped rather than ignored", field, p.Urgency(), DefaultUrgency)
		}
	}
}

// TestParseIgnoresUnexpectedTypes is the second of §4 of RFC 9218's three rules. Every one
// of these carries a value that means the right thing to a human and is the wrong type.
func TestParseIgnoresUnexpectedTypes(t *testing.T) {
	for _, field := range []string{
		"u=3.0",       // Decimal, numerically the default and still not an Integer
		"u=\"3\"",     // String
		"u=three",     // Token
		"u=?1",        // Boolean
		"u",           // and a bare key, which is Boolean true
		"u=(1)",       // Inner List
		"u=(0 1 2)",   // and a longer one
		"u=()",        // and an empty one
		"u=:AAEC:",    // Byte Sequence
		"u=@0",        // Date
		"u=%\"3\"",    // Display String
		"i=1",         // Integer, and the spelling a JSON habit produces
		"i=0",         // which makes this the one that would silently mean true
		"i=1.0",       // Decimal
		"i=\"true\"",  // String
		"i=true",      // Token
		"i=:AQ==:",    // Byte Sequence
		"i=@0",        // Date
		"i=%\"true\"", // Display String
		"i=(?1)",      // Inner List
	} {
		p := mustParse(t, field)
		if p != (Params{}) {
			t.Errorf("Parse(%q) = %+v, want the parameter ignored for its type", field, p)
		}
	}
}

// TestParseIgnoresOneBadParameterAndKeepsTheOther makes sure ignoring is per parameter.
// A field value carrying one usable signal and one unusable one has to arrive with the
// usable one intact — that is what "ignored" means, and a parser that abandoned the whole
// Dictionary at the first unusable member would be treating a MUST-ignore as a parse
// failure.
func TestParseIgnoresOneBadParameterAndKeepsTheOther(t *testing.T) {
	tests := []struct {
		field string
		want  Params
	}{
		{"u=8, i", Params{}.WithIncremental(true)},
		{"u=3.5, i=?0", Params{}.WithIncremental(false)},
		{"i=1, u=0", Params{}.WithUrgency(0)},
		{"u=0, i=maybe", Params{}.WithUrgency(0)},
		{"u=(1 2), i=(?1)", Params{}},
	}
	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			if got := mustParse(t, tt.field); got != tt.want {
				t.Errorf("Parse(%q) = %+v, want %+v", tt.field, got, tt.want)
			}
		})
	}
}

// TestParseResolvesDuplicatesBeforeIgnoring is the interaction between two rules that are
// in different documents, and it goes the way that surprises people: §4.2.2 of RFC 9651
// keeps the last member with a given key and discards the earlier ones while parsing, so
// §4 of RFC 9218's ignore rule is applied to the survivor. An illegal duplicate therefore
// erases a legal earlier one.
//
// It has to work that way round. The alternative — keeping the last member that happens to
// be usable — would have a client's "u=0, u=99" schedule at urgency 0, which is a value the
// client's last word withdrew.
func TestParseResolvesDuplicatesBeforeIgnoring(t *testing.T) {
	tests := []struct {
		field string
		want  Params
	}{
		{"u=0, u=7", Params{}.WithUrgency(7)},
		{"u=7, u=0", Params{}.WithUrgency(0)},
		{"i, i=?0", Params{}.WithIncremental(false)},
		{"i=?0, i", Params{}.WithIncremental(true)},
		{"u=1, u=2, u=3", Params{}.WithUrgency(3)},
		// The out-of-range last word wins by being last, and is then ignored, leaving
		// nothing behind.
		{"u=0, u=99", Params{}},
		{"i, i=1", Params{}},
		// And the same in reverse: the unusable member is discarded as a duplicate before
		// anything looks at its type.
		{"u=99, u=0", Params{}.WithUrgency(0)},
		{"i=1, i", Params{}.WithIncremental(true)},
	}
	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			if got := mustParse(t, tt.field); got != tt.want {
				t.Errorf("Parse(%q) = %+v, want %+v", tt.field, got, tt.want)
			}
		})
	}
}

// TestParseSyntaxErrors is the fourth case, and the only one that is not an ignore: a
// Dictionary that does not parse. §7 of RFC 9218 makes it a MAY, this server declines it,
// and what that costs is that these inputs are indistinguishable from an absent field —
// so the guarantee that matters is that the Params returned alongside the error is usable.
func TestParseSyntaxErrors(t *testing.T) {
	for _, field := range []string{
		"u=",       // a member with an "=" and no value
		"=1",       // a value with no key
		"U=1",      // §4.2.3.3 of RFC 9651 admits no capital in a key
		"1=u",      // nor a leading digit
		"u=1,",     // a trailing comma
		"u=1, ,i",  // an empty member
		"u=1 i",    // a missing comma
		"u=1;",     // a parameter with no key
		"u=\"3",    // an unterminated String
		"u=:AAE",   // an unterminated Byte Sequence
		"u=:!!!!:", // and one that is not base64
		"u=?2",     // a Boolean that is neither
		"u=@1.5",   // a Date that is not whole seconds
		"u=9999999999999999",
		"u=1\x00",   // a control character
		"u=1\r\n i", // a folded field value, which is not this parser's to unfold
		"u=é",       // and a value outside ASCII
	} {
		p, err := Parse(field)
		var syn *sfv.SyntaxError
		if !errors.As(err, &syn) {
			t.Errorf("Parse(%q) error = %v, want a *sfv.SyntaxError", field, err)
		}
		if p != (Params{}) {
			t.Errorf("Parse(%q) = %+v with an error, want the zero Params so that a caller "+
				"which declines the MAY in §7 of RFC 9218 has the defaults to schedule with",
				field, p)
		}
		if p.Urgency() != DefaultUrgency || p.Incremental() {
			t.Errorf("Parse(%q) resolved to urgency %d, incremental %v after a syntax error",
				field, p.Urgency(), p.Incremental())
		}
	}
}

// TestParseLongFieldValue is the resource question. The field value arrives from a peer at
// up to the maximum frame size, and nothing in this package bounds it — so what is asserted
// is that a large one is parsed rather than that it is refused, and that the two members
// that matter are still found at the end of it.
func TestParseLongFieldValue(t *testing.T) {
	var b strings.Builder
	b.WriteString("u=0")
	for i := range 20000 {
		b.WriteString(", k")
		b.WriteString(string(rune('a' + i%26)))
		b.WriteString("=1")
	}
	b.WriteString(", i")

	p := mustParse(t, b.String())
	want := Params{}.WithUrgency(0).WithIncremental(true)
	if p != want {
		t.Errorf("Parse of a %d-octet field value = %+v, want %+v", b.Len(), p, want)
	}
}

// TestParseDeeplyNestedIsRefusedRatherThanRecursed pins that a hostile field value cannot
// drive this into unbounded work. §3.1.1 of RFC 9651 makes an Inner List's members bare
// items, so the grammar nests exactly one level and a pile of opening parentheses is a
// syntax error rather than a stack.
func TestParseDeeplyNestedIsRefusedRatherThanRecursed(t *testing.T) {
	field := "u=" + strings.Repeat("(", 100000)
	if _, err := Parse(field); err == nil {
		t.Fatal("Parse accepted 100000 nested inner lists")
	}
}

func TestUrgencyAndIncrementalResolveIndependently(t *testing.T) {
	// Present-but-default is not the same value as absent, and the resolved answers are
	// the same. Both halves are load-bearing: the first for Merge, the second for the
	// scheduler.
	absent := Params{}
	explicit := Params{}.WithUrgency(DefaultUrgency)
	if absent == explicit {
		t.Error("an absent urgency compares equal to an explicit one at the same value")
	}
	if absent.Urgency() != explicit.Urgency() {
		t.Errorf("absent resolves to %d and explicit to %d; they must schedule alike",
			absent.Urgency(), explicit.Urgency())
	}

	explicitFalse := Params{}.WithIncremental(false)
	if absent == explicitFalse {
		t.Error("an absent incremental compares equal to an explicit false")
	}
	if absent.Incremental() != explicitFalse.Incremental() {
		t.Error("absent and explicit false resolve differently")
	}
}

func TestWithUrgency(t *testing.T) {
	for u := 0; u <= MaxUrgency; u++ {
		p := Params{}.WithUrgency(u)
		if !p.HasUrgency() || p.Urgency() != u {
			t.Errorf("WithUrgency(%d) = %+v, want it present at %d", u, p, u)
		}
		if p.HasIncremental() {
			t.Errorf("WithUrgency(%d) invented an incremental parameter", u)
		}
	}
	// It replaces rather than accumulating.
	if got := (Params{}).WithUrgency(1).WithUrgency(6); got.Urgency() != 6 {
		t.Errorf("WithUrgency(1).WithUrgency(6).Urgency() = %d, want 6", got.Urgency())
	}
	// And it does not touch the receiver, which is the whole point of the value semantics:
	// a Params handed to two goroutines cannot be changed by either.
	base := Params{}.WithUrgency(2)
	_ = base.WithUrgency(5)
	if base.Urgency() != 2 {
		t.Errorf("WithUrgency mutated its receiver: %d, want 2", base.Urgency())
	}
}

// TestWithUrgencyPanicsOutsideTheRange is the invariant Urgency() rests on. Nothing a peer
// sends can reach this, because Parse ignores an out-of-range value; only this server's own
// arithmetic can, and a schedule built on urgency 9 would index past the end of a table.
func TestWithUrgencyPanicsOutsideTheRange(t *testing.T) {
	for _, u := range []int{-1, MaxUrgency + 1, 100, math.MinInt, math.MaxInt} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("WithUrgency(%d) returned instead of panicking", u)
				}
			}()
			_ = Params{}.WithUrgency(u)
		}()
	}
}

func TestWithIncremental(t *testing.T) {
	for _, i := range []bool{true, false} {
		p := Params{}.WithIncremental(i)
		if !p.HasIncremental() || p.Incremental() != i {
			t.Errorf("WithIncremental(%v) = %+v, want it present at %v", i, p, i)
		}
		if p.HasUrgency() {
			t.Errorf("WithIncremental(%v) invented an urgency parameter", i)
		}
	}
	base := Params{}.WithIncremental(true)
	_ = base.WithIncremental(false)
	if !base.Incremental() {
		t.Error("WithIncremental mutated its receiver")
	}
}

// TestMerge is §8 of RFC 9218, including the example the section gives.
func TestMerge(t *testing.T) {
	tests := []struct {
		name string
		base Params
		over Params
		want Params
	}{
		{
			// §8 of RFC 9218's own example: a request of u=5, i under a response of u=1
			// keeps the client's incremental, because the response did not mention it.
			name: "the section's example",
			base: Params{}.WithUrgency(5).WithIncremental(true),
			over: Params{}.WithUrgency(1),
			want: Params{}.WithUrgency(1).WithIncremental(true),
		},
		{
			name: "nothing over something changes nothing",
			base: Params{}.WithUrgency(5).WithIncremental(true),
			over: Params{},
			want: Params{}.WithUrgency(5).WithIncremental(true),
		},
		{
			name: "something over nothing is that something",
			base: Params{},
			over: Params{}.WithUrgency(0),
			want: Params{}.WithUrgency(0),
		},
		{
			name: "nothing over nothing is nothing, not the defaults made explicit",
			base: Params{},
			over: Params{},
			want: Params{},
		},
		{
			// An explicit false in the response overrides the client's true. This is why
			// absence and false have to be different values: if the response's silence
			// about the incremental parameter were stored as false, every response would
			// do this.
			name: "an explicit false overrides a true",
			base: Params{}.WithIncremental(true),
			over: Params{}.WithIncremental(false),
			want: Params{}.WithIncremental(false),
		},
		{
			name: "both parameters replaced at once",
			base: Params{}.WithUrgency(7).WithIncremental(false),
			over: Params{}.WithUrgency(0).WithIncremental(true),
			want: Params{}.WithUrgency(0).WithIncremental(true),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base, over := tt.base, tt.over
			if got := base.Merge(over); got != tt.want {
				t.Errorf("Merge\n got %+v\nwant %+v", got, tt.want)
			}
			// Neither operand is touched. The value semantics make that free, and the test
			// is here because a later Merge taking a pointer receiver to avoid a copy would
			// break it silently — a response's signal would leak into the request's.
			if base != tt.base || over != tt.over {
				t.Errorf("Merge changed an operand: base %+v want %+v, over %+v want %+v",
					base, tt.base, over, tt.over)
			}
		})
	}
}

// TestMergeIsNotHowAFrameApplies pins the distinction the Merge comment makes, because it
// is the one an implementation gets wrong for free: the two operations have the same
// operands and different results, and the wrong one only shows up as a response that keeps
// an incremental flag its client withdrew.
//
// §7 of RFC 9218: "A PRIORITY_UPDATE frame communicates a complete set of all priority
// parameters in the Priority Field Value field.  Omitting a priority parameter is a signal
// to use its default value."
func TestMergeIsNotHowAFrameApplies(t *testing.T) {
	fromHeaderField := mustParse(t, "u=5, i")
	fromFrame := mustParse(t, "u=1")

	if got := fromFrame; got.Incremental() {
		t.Errorf("a frame of %q resolves incremental to true; applying it is an assignment, "+
			"and it named no incremental parameter", "u=1")
	}
	if got := fromHeaderField.Merge(fromFrame); !got.Incremental() {
		t.Error("Merge dropped the incremental parameter the response did not mention")
	}
	if fromHeaderField.Merge(fromFrame) == fromFrame {
		t.Error("Merge and assignment produced the same Params, so this test proves nothing " +
			"and one of the two is wrong")
	}
}

func TestField(t *testing.T) {
	tests := []struct {
		params Params
		want   string
	}{
		{Params{}, ""},
		{Params{}.WithUrgency(0), "u=0"},
		{Params{}.WithUrgency(3), "u=3"},
		{Params{}.WithUrgency(MaxUrgency), "u=7"},
		{Params{}.WithIncremental(true), "i"},
		{Params{}.WithIncremental(false), "i=?0"},
		{Params{}.WithUrgency(5).WithIncremental(true), "u=5, i"},
		{Params{}.WithUrgency(0).WithIncremental(false), "u=0, i=?0"},
	}
	for _, tt := range tests {
		if got := tt.params.Field(); got != tt.want {
			t.Errorf("%+v.Field() = %q, want %q", tt.params, got, tt.want)
		}
	}
}

// TestFieldRoundTrip is Field against Parse. It is the check that keeps the two in step:
// Field is what this server would put in a Priority response header field, and a value it
// wrote that its own parser read differently would be a bug visible only to the next hop.
func TestFieldRoundTrip(t *testing.T) {
	var all []Params
	for _, u := range []int{0, 1, 2, 3, 4, 5, 6, 7} {
		for _, p := range []Params{{}, Params{}.WithUrgency(u)} {
			all = append(all, p,
				p.WithIncremental(true),
				p.WithIncremental(false))
		}
	}
	for _, want := range all {
		field := want.Field()
		got, err := Parse(field)
		if err != nil {
			t.Errorf("Field() produced %q, which does not parse: %v", field, err)
			continue
		}
		if got != want {
			t.Errorf("round trip through %q\n got %+v\nwant %+v", field, got, want)
		}
	}
}

// TestFieldIsNotTheInputSpelling records what the round trip does not promise. Parse keeps
// the value and not the octets, so these three differ from what went in — deliberately, and
// a test that asserted the opposite would be asserting that this package stores peer text.
func TestFieldIsNotTheInputSpelling(t *testing.T) {
	tests := []struct{ in, want string }{
		{"i=?1", "i"},
		{"u=5,i", "u=5, i"},
		{"u=0, u=7", "u=7"},
		{"u=3;q=1", "u=3"},
		{"a=1, u=1, b=2", "u=1"},
		{"u=8, i", "i"},
	}
	for _, tt := range tests {
		if got := mustParse(t, tt.in).Field(); got != tt.want {
			t.Errorf("Parse(%q).Field() = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// FuzzParse asserts the three properties every field value has to leave behind, whatever
// it is: the urgency is in range so that it can index a table, an error means the zero
// Params so that a caller which ignores the error still schedules at the defaults, and no
// input parses to something this package cannot write back out.
func FuzzParse(f *testing.F) {
	for _, seed := range []string{
		"", "u=3", "i", "u=5, i", "i, u=0", "u=?1", "u=8", "u=-0", "i=?0", "i=1",
		"u=3;q=0.5", "a=1, u=2, b=(1 2)", "u=", "U=1", "u=:AAEC:", "u=%\"3\"",
		"u=9999999999999999", "\x00", "u=1\r\n i", strings.Repeat("u=1, ", 200),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, field string) {
		p, err := Parse(field)

		if u := p.Urgency(); u < 0 || u > MaxUrgency {
			t.Fatalf("Parse(%q).Urgency() = %d, outside 0..%d", field, u, MaxUrgency)
		}
		if err != nil {
			if p != (Params{}) {
				t.Fatalf("Parse(%q) = %+v with error %v, want the zero Params", field, p, err)
			}
			return
		}

		again, err := Parse(p.Field())
		if err != nil {
			t.Fatalf("Parse(%q) = %+v, whose Field() %q does not parse: %v",
				field, p, p.Field(), err)
		}
		if again != p {
			t.Fatalf("Parse(%q) = %+v, but reparsing its Field() %q gives %+v",
				field, p, p.Field(), again)
		}
	})
}
