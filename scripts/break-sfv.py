"""Deliberately break internal/sfv, one guard at a time, and report which tests notice.

Each entry below removes exactly one guard and names the tests that must fail as a
result. See breakage.py for the harness and for what the five outcomes mean.

Two files, and they hold two halves of the same parser. sfv.go is the value model — the
Kind names, the accessors that answer whether a key was found — and its breaks are the ones
that read a Params or a Dictionary the wrong way. parse.go is the algorithm of §4.2 of RFC
9651, and its breaks are the guards that separate one octet's meaning from the next: the
comma that ends a member, the colon that closes a byte sequence, the length that stops an
integer overflowing an int64. The anchors below are counted across both files, because a
single parser has one key space and one grammar, and a break that matched an accessor in
one file and a comment in the other would be ambiguous in fact.

The negative table, TestParseDictionaryRejects, is the primary detector, and it is stronger
than a table that only asserted failure: every row pins the offset as well as the message,
so a guard that fails for the wrong reason at the wrong place is a hole and not a pass. It
carries most of the campaign because most of these guards are refusals, and a refusal that
stops refusing is what it was written to see. The positive tables catch the other half — a
guard that keeps refusing but resolves a value wrongly, where the input parses and the
answer is quietly wrong.

Two guards have no break, and both absences are deliberate.

  * The trailing SP-and-leftover check that §4.2's step 7 calls for. It is not in
    ParseDictionary at all — see the doc comment there — because a Dictionary cannot leave
    anything over: the loop ends each member by discarding OWS and then either returning on
    empty or requiring a comma, so there is no code path that reaches step 7 with input
    left. There is no guard to remove.

  * The opening parenthesis that innerList consumes without checking. itemOrInnerList is
    the only caller and it dispatches on that octet, so the check §4.2.1.2 opens with cannot
    fail here. Removing the p.i++ that stands in its place would desynchronise the cursor by
    one on every inner list, which TestParseInnerListStructure catches — but that is a break
    of the cursor, not of a guard, and it is covered by the innerList break below that does
    the same thing legibly.

Run from the repository root. Restores the files on the way out, including on error.
"""

import breakage

SRC = [
    "internal/sfv/sfv.go",
    "internal/sfv/parse.go",
]
PKG = "./internal/sfv/"

# (name, old, new, tests that must fail)
BREAKS = [
    # --- sfv.go: the value model --------------------------------------------
    (
        "the zero Kind is an Integer, so an unparsed member reads as an integer of zero",
        """	KindNone Kind = iota
	KindInteger""",
        """	KindInteger Kind = iota
	KindNone""",
        ["TestKindStringNamesEveryKind", "TestGetReadsMembersAndParameters"],
    ),
    (
        "a Kind name is off by one, so every kind past it is misnamed",
        """	"none",
	"integer",""",
        """	"none",""",
        ["TestKindStringNamesEveryKind"],
    ),
    (
        "String out of range does not say the kind is unknown, so a bad Kind reads as empty",
        """	return fmt.Sprintf("unknown kind(%d)", uint8(k))""",
        """	return fmt.Sprintf("kind(%d)", uint8(k))""",
        ["TestKindStringNamesEveryKind"],
    ),
    (
        "Params.Get answers found for a key it never held, so a missing parameter is a value",
        """func (ps Params) Get(key string) (Item, bool) {
	for _, p := range ps {
		if p.Key == key {
			return p.Value, true
		}
	}
	return Item{}, false
}""",
        """func (ps Params) Get(key string) (Item, bool) {
	for _, p := range ps {
		if p.Key == key {
			return p.Value, true
		}
	}
	return Item{}, true
}""",
        ["TestGetReadsMembersAndParameters"],
    ),
    (
        "Dictionary.Get reports found for every key, so an absent member reads as a value",
        """func (d Dictionary) Get(key string) (Item, bool) {
	for _, m := range d {
		if m.Key == key {
			return m.Value, true
		}
	}
	return Item{}, false
}""",
        """func (d Dictionary) Get(key string) (Item, bool) {
	for _, m := range d {
		if m.Key == key {
			return m.Value, true
		}
	}
	return Item{}, true
}""",
        ["TestGetReadsMembersAndParameters", "TestParseDictionaryEmptyValueHasNoMembers"],
    ),

    # --- parse.go: the top-level Dictionary loop ----------------------------
    (
        "the leading discard is OWS, so a value that begins with a tab is accepted",
        """	p := &parser{s: value}
	p.skipSP()
	return p.dictionary()""",
        """	p := &parser{s: value}
	p.skipOWS()
	return p.dictionary()""",
        ["TestParseDictionaryLeadingTabIsNotWhitespaceHere"],
    ),
    (
        "an omitted value is Boolean false, so a bare member reads as absent-false not true",
        """			value = Item{Kind: KindBoolean, Boolean: true}
			if value.Params, err = p.params(); err != nil {""",
        """			value = Item{Kind: KindBoolean, Boolean: false}
			if value.Params, err = p.params(); err != nil {""",
        ["TestParseDictionaryOmittedValueIsBooleanTrue", "TestParseDictionaryFromTheExamplesInTheSpecifications"],
    ),
    (
        "a member without a comma after it is accepted, so two members run together",
        """		if p.peek() != ',' {
			return nil, p.errf("a comma between dictionary members")
		}""",
        """		if false && p.peek() != ',' {
			return nil, p.errf("a comma between dictionary members")
		}""",
        ["TestParseDictionaryRejects"],
    ),
    (
        "a trailing comma is accepted, so a truncated value parses as a shorter one",
        """		if p.empty() {
			// The whole value fails on a trailing comma. §4.2.2 of RFC 9651 spells""",
        """		if false && p.empty() {
			// The whole value fails on a trailing comma. §4.2.2 of RFC 9651 spells""",
        ["TestParseDictionaryRejects"],
    ),

    # --- setKeyed: last occurrence wins, in the first one's place -----------
    (
        "a repeated key appends, so the later value lands at the end instead of in place",
        """	for i := range list {
		if list[i].key() == e.key() {
			list[i] = e
			return list
		}
	}
	list = append(list, e)""",
        """	for i := range list {
		if list[i].key() == e.key() {
			return append(list, e)
		}
	}
	list = append(list, e)""",
        ["TestParseDictionaryLastOccurrenceOfAKeyWinsAndKeepsItsPlace", "TestKeyIndexAgreesWithTheScanItReplaces"],
    ),
    (
        "the indexed path appends a duplicate, so a long value keeps both occurrences",
        """	if *at != nil {
		if i, ok := (*at)[e.key()]; ok {
			list[i] = e
			return list
		}""",
        """	if *at != nil {
		if _, ok := (*at)[e.key()]; ok {
			return append(list, e)
		}""",
        ["TestKeyIndexAgreesWithTheScanItReplaces"],
    ),
    (
        "the parameter index is not reset, so one item's parameter answers the next item's key",
        """	p.paramAt = nil

	var ps Params""",
        """	var ps Params""",
        ["TestParameterIndexIsNotSharedBetweenItems"],
    ),

    # --- key: §4.2.3.3 of RFC 9651 ------------------------------------------
    (
        "a key may begin with any letter, so an upper-case key is a member not a failure",
        """	if c := p.peek(); !isLCAlpha(c) && c != '*' {
		return "", p.errf("a key beginning with a lower-case letter or an asterisk")
	}""",
        """	if c := p.peek(); !isAlpha(c) && c != '*' {
		return "", p.errf("a key beginning with a lower-case letter or an asterisk")
	}""",
        ["TestParseDictionaryRejects"],
    ),

    # --- bareItem: the total dispatch ---------------------------------------
    (
        "the bare item dispatch has a default that succeeds, so any octet begins a token",
        """	default:
		return Item{}, p.errf("a value of one of the eight item types")
	}
}""",
        """	default:
		return p.token()
	}
}""",
        ["TestParseDictionaryRejects"],
    ),

    # --- number: the length rules that keep values inside an int64 ----------
    (
        "an integer of any length is accepted, so sixteen digits is no longer refused",
        """	if point < 0 {
		if len(run) > maxIntegerDigits {
			p.i = at
			return Item{}, p.errf("an integer of at most fifteen digits")
		}""",
        """	if point < 0 {
		if false {
			p.i = at
			return Item{}, p.errf("an integer of at most fifteen digits")
		}""",
        ["TestParseDictionaryRejects"],
    ),
    (
        "a minus sign with no digit is a number, so a bare minus parses as zero",
        """		p.i++
		if p.empty() {
			return Item{}, p.errf("digits after the minus sign")
		}
		sign = -1""",
        """		p.i++
		if false {
			return Item{}, p.errf("digits after the minus sign")
		}
		sign = -1""",
        ["TestParseDictionaryRejects"],
    ),
    (
        "a decimal with no fractional digit is accepted, so '1.' parses",
        """	if len(frac) == 0 {
		p.i = at
		return Item{}, p.errf("a decimal with a digit after the point")
	}""",
        """	if false {
		p.i = at
		return Item{}, p.errf("a decimal with a digit after the point")
	}""",
        ["TestParseDictionaryRejects"],
    ),
    (
        "a decimal's fraction is unbounded, so four digits after the point is accepted",
        """	if len(frac) > maxDecimalFractionDigits {
		p.i = at
		return Item{}, p.errf("a decimal with at most three digits after the point")
	}""",
        """	if false {
		p.i = at
		return Item{}, p.errf("a decimal with at most three digits after the point")
	}""",
        ["TestParseDictionaryRejects"],
    ),
    (
        "a decimal's whole part is unbounded, so thirteen digits before the point is accepted",
        """	if len(whole) > maxDecimalIntegerDigits {
		p.i = at
		return Item{}, p.errf("a decimal with at most twelve digits before the point")
	}""",
        """	if false {
		p.i = at
		return Item{}, p.errf("a decimal with at most twelve digits before the point")
	}""",
        ["TestParseDictionaryRejects"],
    ),
    (
        "a second point does not end the number, so '1.2.3' is one decimal",
        """		if c == '.' && point < 0 {
			point = p.i
			p.i++
			continue
		}""",
        """		if c == '.' {
			point = p.i
			p.i++
			continue
		}""",
        ["TestParseDictionaryRejects"],
    ),
    (
        "the fraction is not scaled, so 1.5 and 1.50 are different numbers",
        """	scale := int64(thousand)
	for range len(frac) {
		scale /= 10
	}""",
        """	scale := int64(1)""",
        ["TestParseDecimalIsExactInThousandths"],
    ),

    # --- text: §4.2.5 of RFC 9651 -------------------------------------------
    (
        "any escape passes through, so a backslash-n is two characters not a failure",
        """			esc := p.s[p.i]
			if esc != '"' && esc != '\\\\' {
				return Item{}, p.errf("a quotation mark or a backslash after the backslash")
			}""",
        """			esc := p.s[p.i]
			if false {
				return Item{}, p.errf("a quotation mark or a backslash after the backslash")
			}""",
        ["TestParseDictionaryRejects"],
    ),
    (
        "a control octet inside a string is accepted, so a tab parses",
        """		case c < 0x20 || c >= 0x7f:
			// §4.2.5 of RFC 9651 fails on any octet outside VCHAR and SP. A control""",
        """		case false:
			// §4.2.5 of RFC 9651 fails on any octet outside VCHAR and SP. A control""",
        ["TestParseDictionaryRejects"],
    ),
    (
        "the string escapes the closing quote, so an escaped quote does not end the string",
        """		case c == '"':
			p.i++
			// An empty builder means no escape has been seen, because the branch above""",
        """		case c == '"' && b.Len() < 0:
			p.i++
			// An empty builder means no escape has been seen, because the branch above""",
        ["TestParseStringUnescapes"],
    ),

    # --- byteSequence: §4.2.7 of RFC 9651 -----------------------------------
    (
        "an unterminated byte sequence is accepted, so a missing closing colon parses",
        """	end := strings.IndexByte(p.s[p.i:], ':')
	if end < 0 {
		p.i = at
		return Item{}, p.errf("a closing colon on the byte sequence")
	}""",
        """	end := strings.IndexByte(p.s[p.i:], ':')
	if end < -1 {
		p.i = at
		return Item{}, p.errf("a closing colon on the byte sequence")
	}
	if end < 0 {
		end = len(p.s) - p.i
	}""",
        ["TestParseDictionaryRejects"],
    ),
    (
        "the alphabet is not checked, so a character outside base64 reaches the decoder",
        """	for i := range len(content) {
		if c := content[i]; !isAlpha(c) && !isDigit(c) && c != '+' && c != '/' && c != '=' {
			p.i = at
			return Item{}, p.errf("base64 content in the base64 alphabet")
		}
	}""",
        """	for i := range len(content) {
		if c := content[i]; false {
			_ = c
			p.i = at
			return Item{}, p.errf("base64 content in the base64 alphabet")
		}
	}""",
        ["TestParseDictionaryRejects"],
    ),

    # --- boolean: §4.2.8 of RFC 9651 ----------------------------------------
    (
        "a boolean is true for anything but zero, so '?2' is true instead of a failure",
        """	default:
		return Item{}, p.errf("a zero or a one after the question mark")
	}
}""",
        """	default:
		p.i++
		return Item{Kind: KindBoolean, Boolean: true}, nil
	}
}""",
        ["TestParseDictionaryRejects"],
    ),
    (
        "a question mark is true, so '?1' and '?0' are the same value",
        """	case '1':
		p.i++
		return Item{Kind: KindBoolean, Boolean: true}, nil
	case '0':
		p.i++
		return Item{Kind: KindBoolean, Boolean: false}, nil""",
        """	case '1':
		p.i++
		return Item{Kind: KindBoolean, Boolean: true}, nil
	case '0':
		p.i++
		return Item{Kind: KindBoolean, Boolean: true}, nil""",
        ["TestParseBooleanIsOnlyZeroOrOne", "TestParseDictionaryFromTheExamplesInTheSpecifications"],
    ),

    # --- date: §4.2.9 of RFC 9651 -------------------------------------------
    (
        "a date accepts a decimal, so '@1.5' is a date of fractional seconds",
        """	if n.Kind != KindInteger {
		p.i = at
		return Item{}, p.errf("whole seconds in the date")
	}""",
        """	if false {
		p.i = at
		return Item{}, p.errf("whole seconds in the date")
	}""",
        ["TestParseDictionaryRejects"],
    ),

    # --- displayString: §4.2.10 of RFC 9651 ---------------------------------
    (
        "a display string needs no opening quote, so '%x' begins one",
        """	if !strings.HasPrefix(p.s[p.i:], `%"`) {
		return Item{}, p.errf("a quotation mark after the percent sign")
	}""",
        """	if false {
		return Item{}, p.errf("a quotation mark after the percent sign")
	}""",
        ["TestParseDictionaryRejects"],
    ),
    (
        "a display string escape accepts upper case, so '%C3' decodes",
        """	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	default:
		return -1
	}
}""",
        """	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	default:
		return -1
	}
}""",
        ["TestParseDictionaryRejects"],
    ),
    (
        "display string content is not checked for UTF-8, so a lone 0xff octet decodes",
        """			if !utf8.ValidString(b.String()) {
				p.i = at
				return Item{}, p.errf("display string content that decodes as UTF-8")
			}""",
        """			if !utf8.ValidString(b.String()) && false {
				p.i = at
				return Item{}, p.errf("display string content that decodes as UTF-8")
			}""",
        ["TestParseDictionaryRejects"],
    ),

    # --- innerList and params: structure ------------------------------------
    (
        "an inner list needs no separator, so two items with no space between them parse",
        """		if c := p.peek(); !p.empty() && c != ' ' && c != ')' {
			return Item{}, p.errf("a space between inner list items, or a closing parenthesis")
		}""",
        """		if c := p.peek(); !p.empty() && c != ' ' && c != ')' && false {
			_ = c
			return Item{}, p.errf("a space between inner list items, or a closing parenthesis")
		}""",
        ["TestParseDictionaryRejects"],
    ),
    (
        "an unterminated inner list is accepted, so a missing parenthesis is not a failure",
        """	}
	return Item{}, p.errf("a closing parenthesis")
}""",
        """	}
	return Item{Kind: KindInnerList, List: list}, nil
}""",
        ["TestParseDictionaryRejects"],
    ),
    (
        "a parameter's value may be an inner list, so ';p=(1 2)' parses",
        """		value := Item{Kind: KindBoolean, Boolean: true}
		if p.peek() == '=' {
			p.i++
			if value, err = p.bareItem(); err != nil {
				return nil, err
			}
		}""",
        """		value := Item{Kind: KindBoolean, Boolean: true}
		if p.peek() == '=' {
			p.i++
			if value, err = p.itemOrInnerList(); err != nil {
				return nil, err
			}
		}""",
        ["TestParseDictionaryRejects"],
    ),

    # --- token: §4.2.6 of RFC 9651 ------------------------------------------
    (
        "a token is lower-cased, so a token no longer arrives as it was sent",
        """	return Item{Kind: KindToken, Text: p.s[start:p.i]}, nil
}

// byteSequence""",
        """	return Item{Kind: KindToken, Text: strings.ToLower(p.s[start:p.i])}, nil
}

// byteSequence""",
        ["TestParseTokenKeepsCaseAndPunctuation"],
    ),
]

breakage.main(SRC, PKG, BREAKS)
