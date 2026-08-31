"""Deliberately break internal/priority, one guard at a time, and report which tests
notice.

Each entry below removes exactly one guard and names the tests that must fail as a
result. See breakage.py for the harness and for what the five outcomes mean.

Two files, and they are two different kinds of risk. priority.go is a value type whose
whole subject is a distinction that costs nothing to lose: a parameter the peer sent and a
parameter that resolved to the same number are different Params, and §8 of RFC 9218 is the
only place the difference shows. So most of the breaks here collapse presence into value or
value into presence — the mutations that leave every scheduling decision correct and turn a
response's silence into an override. pending.go is a map a peer fills, and its breaks are
the ones that either lose a buffered priority or keep it forever.

One break needed a test that did not exist. Nothing in priority_test.go asserted that
DefaultUrgency is 3, because every table in the file reads the constant rather than the
number — which is the right way to write those tables and means the constant itself was
pinned nowhere. DefaultUrgency = 0 would make every unprioritized request the most urgent
thing on the connection and leave the whole suite green. It is now
TestTheConstantsAreTheDocumentsNumbers, and it is the sole detection for that break, which
is exactly the shape of hole a campaign is for.

One break named a test that cannot see it, which is worth recording because it looks like
a hole and is not. WithIncremental ignoring its argument was reported unnoticed while
TestMerge was named alongside the two tests that do catch it: every operand and every
expectation in TestMerge's table is built by WithUrgency and WithIncremental, so a
constructor that returned the wrong value returns it on both sides of the comparison and
the table stays green. That is the right way to write a test of Merge — it asserts what
Merge does relative to the constructors, and the constructors are pinned absolutely by
TestWithIncremental and TestField, where the value is read back through the accessors and
written out as a field value. So the test list lost TestMerge rather than the table
gaining a case; a break is only signed off by a test whose assertions can reach it.

Four guards have no break, and all four absences are deliberate.

  * Prune's unsigned comparison. Doing it in an int32 is the classic mistake and it cannot
    be observed here: §7.1 of RFC 9218 makes a PRIORITY_UPDATE naming a server-initiated
    stream a connection error, so the caller never buffers one, and §5.1.1 of RFC 9113 caps
    what it does buffer at 2^31-1. Every identifier in the map and every below it is
    compared against are positive in either type. The break would be a no-op on every
    reachable input. TestPendingHoldsEveryLegalIdentifier walks the top of the space
    anyway.

  * The order Field writes its two members in. §4 of RFC 9218 names the urgency first and
    gives order no meaning, so a Dictionary with the members the other way round is the
    same field value and swapping them is not a defect. TestField pins the spelling as
    documentation of what this server emits, not as a rule, and a break there would be
    asserting a preference.

  * The absence of a mutex on Pending. One connection's read loop owns one of these and
    nothing else touches it, which is the same ownership the rest of the per-connection
    state has. There is no lock to remove.

  * Merge's value receiver. The mutation worth testing — a pointer receiver taken to avoid
    copying a four-field struct, which would let a response's signal leak back into the
    request's Params — cannot be written as one edit, because the receiver, the return
    type and every call site move together. TestMerge asserts both operands are unchanged
    after every case in its table, which is the check that would catch it.

Run from the repository root. Restores the files on the way out, including on error.
"""

import breakage

SRC = [
    "internal/priority/priority.go",
    "internal/priority/pending.go",
]
PKG = "./internal/priority/"

# (name, old, new, tests that must fail)
BREAKS = [
    # --- the numbers the document gives ---------------------------------------
    (
        "the default urgency is 0, so every unprioritized request is the most urgent",
        """	DefaultUrgency = 3""",
        """	DefaultUrgency = 0""",
        ["TestTheConstantsAreTheDocumentsNumbers"],
    ),
    (
        "the urgency range stops one short, so §4.1 of RFC 9218's least urgent is ignored",
        """	MaxUrgency = 7""",
        """	MaxUrgency = 6""",
        [
            "TestTheConstantsAreTheDocumentsNumbers",
            "TestParseValid",
            "TestField",
        ],
    ),
    (
        "the urgency range is one too wide, so an out-of-range signal is accepted",
        """	MaxUrgency = 7""",
        """	MaxUrgency = 8""",
        [
            "TestTheConstantsAreTheDocumentsNumbers",
            "TestParseIgnoresOutOfRangeUrgency",
            "TestField",
        ],
    ),
    (
        "the urgency key is spelled out, so the parameter §4.1 of RFC 9218 defines is unknown",
        """	keyUrgency     = "u\"""",
        """	keyUrgency     = "urgency\"""",
        ["TestParseValid", "TestParseDefaults", "TestField"],
    ),
    (
        "the incremental key is spelled out, so §4.2 of RFC 9218's parameter is unknown",
        """	keyIncremental = "i\"""",
        """	keyIncremental = "incremental\"""",
        ["TestParseValid", "TestParseDefaults", "TestField"],
    ),
    # --- Urgency and Incremental: resolving absence ---------------------------
    (
        "Urgency returns the stored zero for an absent parameter instead of the default",
        """	if !p.hasUrgency {
		return DefaultUrgency
	}
	return int(p.urgency)""",
        """	return int(p.urgency)""",
        [
            "TestParseDefaults",
            "TestParseIgnoresOutOfRangeUrgency",
            "TestUrgencyAndIncrementalResolveIndependently",
        ],
    ),
    (
        "Urgency resolves the parameter that was sent and returns the sent one's default",
        """	if !p.hasUrgency {""",
        """	if p.hasUrgency {""",
        ["TestParseValid", "TestParseDefaults", "TestWithUrgency"],
    ),
    (
        "Incremental answers whether the parameter was sent, so i=?0 is incremental",
        """func (p Params) Incremental() bool { return p.incremental }""",
        """func (p Params) Incremental() bool { return p.hasIncremental }""",
        [
            "TestParseValid",
            "TestWithIncremental",
            "TestUrgencyAndIncrementalResolveIndependently",
        ],
    ),
    (
        "HasUrgency is computed from the value, so an explicit u=3 reads as absent",
        """func (p Params) HasUrgency() bool { return p.hasUrgency }""",
        """func (p Params) HasUrgency() bool { return p.urgency != DefaultUrgency }""",
        ["TestParseDefaults", "TestParseValid", "TestWithUrgency"],
    ),
    (
        "HasIncremental is the value, so an explicit i=?0 reads as absent",
        """func (p Params) HasIncremental() bool { return p.hasIncremental }""",
        """func (p Params) HasIncremental() bool { return p.incremental }""",
        ["TestParseValid", "TestWithIncremental"],
    ),
    # --- WithUrgency and WithIncremental: the invariant ----------------------
    (
        "WithUrgency accepts a negative urgency, which becomes 255 in a uint8",
        """	if u < 0 || u > MaxUrgency {""",
        """	if u > MaxUrgency {""",
        ["TestWithUrgencyPanicsOutsideTheRange"],
    ),
    (
        "WithUrgency's bound is off by one, so urgency 8 indexes past the last band",
        """	if u < 0 || u > MaxUrgency {""",
        """	if u < 0 || u > MaxUrgency+1 {""",
        ["TestWithUrgencyPanicsOutsideTheRange"],
    ),
    (
        "WithUrgency stores the value without marking the parameter present",
        """	p.urgency, p.hasUrgency = uint8(u), true""",
        """	p.urgency, p.hasUrgency = uint8(u), p.hasUrgency""",
        ["TestWithUrgency", "TestField"],
    ),
    (
        "WithIncremental marks the parameter present only when it is true",
        """	p.incremental, p.hasIncremental = i, true""",
        """	p.incremental, p.hasIncremental = i, i""",
        ["TestWithIncremental", "TestField"],
    ),
    (
        "WithIncremental ignores its argument, so a response cannot withdraw an i",
        """	p.incremental, p.hasIncremental = i, true""",
        """	p.incremental, p.hasIncremental = true, true""",
        ["TestWithIncremental", "TestField"],
    ),
    # --- Merge: §8 of RFC 9218 ----------------------------------------------
    (
        "Merge takes the urgency whether or not the response sent one",
        """	if over.hasUrgency {
		p.urgency, p.hasUrgency = over.urgency, true
	}""",
        """	p.urgency, p.hasUrgency = over.urgency, true""",
        ["TestMerge"],
    ),
    (
        "Merge takes the incremental whether or not the response sent one",
        """	if over.hasIncremental {
		p.incremental, p.hasIncremental = over.incremental, true
	}""",
        """	p.incremental, p.hasIncremental = over.incremental, true""",
        ["TestMerge", "TestMergeIsNotHowAFrameApplies"],
    ),
    (
        "Merge merges the urgency the wrong way round, into the response's own copy",
        """		p.urgency, p.hasUrgency = over.urgency, true""",
        """		over.urgency, over.hasUrgency = p.urgency, true""",
        ["TestMerge"],
    ),
    (
        "Merge writes the response's presence as the incremental value",
        """		p.incremental, p.hasIncremental = over.incremental, true""",
        """		p.incremental, p.hasIncremental = over.hasIncremental, true""",
        ["TestMerge"],
    ),
    (
        "Merge is an assignment, which is what §7 of RFC 9218 wants and §8 does not",
        """	if over.hasIncremental {
		p.incremental, p.hasIncremental = over.incremental, true
	}
	return p""",
        """	if over.hasIncremental {
		p.incremental, p.hasIncremental = over.incremental, true
	}
	return over""",
        ["TestMerge", "TestMergeIsNotHowAFrameApplies"],
    ),
    # --- Field: what this server puts on the wire ---------------------------
    (
        "Field writes the urgency when its value is not zero rather than when it was sent",
        """	if p.hasUrgency {""",
        """	if p.urgency != 0 {""",
        ["TestField", "TestFieldRoundTrip"],
    ),
    (
        "Field writes the incremental when it is true rather than when it was sent",
        """	if p.hasIncremental {""",
        """	if p.incremental {""",
        ["TestField", "TestFieldRoundTrip"],
    ),
    (
        "Field writes the urgency as a raw octet instead of a digit",
        """		b.WriteByte('0' + p.urgency)""",
        """		b.WriteByte(p.urgency)""",
        ["TestField", "TestFieldRoundTrip"],
    ),
    (
        "Field omits the separator, so two parameters are one unparseable member",
        """		if b.Len() > 0 {
			b.WriteString(", ")
		}
		b.WriteString(keyIncremental)""",
        """		b.WriteString(keyIncremental)""",
        ["TestField", "TestFieldRoundTrip"],
    ),
    (
        "Field spells the incremental out when it is true instead of when it is false",
        """		if !p.incremental {""",
        """		if p.incremental {""",
        ["TestField", "TestFieldRoundTrip"],
    ),
    (
        "Field spells a false incremental as the Boolean it is not",
        """			b.WriteString("=?0")""",
        """			b.WriteString("=?1")""",
        ["TestField", "TestFieldRoundTrip"],
    ),
    # --- Parse: the error, and the four ignore rules of §4 of RFC 9218 ------
    (
        "Parse swallows the syntax error, so §7 of RFC 9218's MAY cannot be taken",
        """		return Params{}, err""",
        """		return Params{}, nil""",
        [
            "TestParseSyntaxErrors",
            "TestParseDeeplyNestedIsRefusedRatherThanRecursed",
        ],
    ),
    (
        "a syntax error resolves to the default made explicit rather than to absence",
        """		return Params{}, err""",
        """		return Params{}.WithUrgency(DefaultUrgency), err""",
        ["TestParseSyntaxErrors"],
    ),
    (
        "the urgency is read whatever its type, so a Decimal or an Inner List is urgency 0",
        """		it.Kind == sfv.KindInteger && it.Integer >= 0 && it.Integer <= MaxUrgency {""",
        """		it.Integer >= 0 && it.Integer <= MaxUrgency {""",
        [
            "TestParseIgnoresUnexpectedTypes",
            "TestParseIgnoresOneBadParameterAndKeepsTheOther",
        ],
    ),
    (
        "a negative urgency is kept, and becomes 255 on the way into the uint8",
        """		it.Kind == sfv.KindInteger && it.Integer >= 0 && it.Integer <= MaxUrgency {""",
        """		it.Kind == sfv.KindInteger && it.Integer <= MaxUrgency {""",
        ["TestParseIgnoresOutOfRangeUrgency"],
    ),
    (
        "an urgency above §4.1 of RFC 9218's range is kept instead of ignored",
        """		it.Kind == sfv.KindInteger && it.Integer >= 0 && it.Integer <= MaxUrgency {""",
        """		it.Kind == sfv.KindInteger && it.Integer >= 0 {""",
        [
            "TestParseIgnoresOutOfRangeUrgency",
            "TestParseResolvesDuplicatesBeforeIgnoring",
            "TestFieldIsNotTheInputSpelling",
        ],
    ),
    (
        "the upper bound is exclusive, so the one urgency §4.1 of RFC 9218 reserves is lost",
        """		it.Kind == sfv.KindInteger && it.Integer >= 0 && it.Integer <= MaxUrgency {""",
        """		it.Kind == sfv.KindInteger && it.Integer >= 0 && it.Integer < MaxUrgency {""",
        ["TestParseValid", "TestParseResolvesDuplicatesBeforeIgnoring"],
    ),
    (
        "the urgency is read from the incremental's key",
        """	if it, ok := d.Get(keyUrgency); ok &&""",
        """	if it, ok := d.Get(keyIncremental); ok &&""",
        ["TestParseValid", "TestParseIgnoresOneBadParameterAndKeepsTheOther"],
    ),
    (
        "the urgency is marked present and stored as the default rather than as sent",
        """		p.urgency, p.hasUrgency = uint8(it.Integer), true""",
        """		p.urgency, p.hasUrgency = DefaultUrgency, true""",
        ["TestParseValid", "TestParseResolvesDuplicatesBeforeIgnoring"],
    ),
    (
        "the incremental is read whatever its type, so i=1 is a signal of false",
        """	if it, ok := d.Get(keyIncremental); ok && it.Kind == sfv.KindBoolean {""",
        """	if it, ok := d.Get(keyIncremental); ok {""",
        [
            "TestParseIgnoresUnexpectedTypes",
            "TestParseResolvesDuplicatesBeforeIgnoring",
            "TestParseIgnoresOneBadParameterAndKeepsTheOther",
        ],
    ),
    (
        "the incremental's value is discarded and stored as true, so i=?0 is incremental",
        """		p.incremental, p.hasIncremental = it.Boolean, true""",
        """		p.incremental, p.hasIncremental = true, true""",
        ["TestParseValid", "TestParseResolvesDuplicatesBeforeIgnoring"],
    ),
    (
        "the incremental is present only when it is true, so i=?0 arrives as absent",
        """		p.incremental, p.hasIncremental = it.Boolean, true""",
        """		p.incremental, p.hasIncremental = it.Boolean, it.Boolean""",
        ["TestParseValid", "TestParseIgnoresOneBadParameterAndKeepsTheOther"],
    ),
    (
        "Parse discards everything it read on the way out",
        """	return p, nil""",
        """	return Params{}, nil""",
        [
            "TestParseValid",
            "TestParseResolvesDuplicatesBeforeIgnoring",
            "TestFieldIsNotTheInputSpelling",
        ],
    ),
    # --- Pending.Put: the bound of one entry per stream ----------------------
    (
        "Put does not create the map, so the first PRIORITY_UPDATE of a connection panics",
        """	if p.of == nil {
		p.of = make(map[uint32]Params)
	}
	p.of[id] = params""",
        """	p.of[id] = params""",
        ["TestPendingZeroValueIsUsable", "TestPendingPutTake"],
    ),
    (
        "Put keeps the first frame rather than the most recent §7 of RFC 9218 asks for",
        """	p.of[id] = params""",
        """	if _, ok := p.of[id]; !ok {
		p.of[id] = params
	}""",
        [
            "TestPendingPutReplaces",
            "TestPendingPutReplacesWithSomethingSmaller",
        ],
    ),
    # --- Pending.Take: applying, and forgetting ------------------------------
    (
        "Take does not forget, so every stream a client prioritizes leaves an entry behind",
        """	if ok {
		delete(p.of, id)
	}
	return params, ok""",
        """	return params, ok""",
        [
            "TestPendingTakeForgets",
            "TestPendingLen",
            "TestPendingHoldsEveryLegalIdentifier",
        ],
    ),
    (
        "Take reports a buffered priority for every stream, including the zero Params",
        """	return params, ok""",
        """	return params, true""",
        ["TestPendingZeroValueIsUsable", "TestPendingTakeForgets", "TestPendingLen"],
    ),
    (
        "Take creates the map it is only reading, so a connection with no signal allocates",
        """func (p *Pending) Take(id uint32) (Params, bool) {
	params, ok := p.of[id]""",
        """func (p *Pending) Take(id uint32) (Params, bool) {
	if p.of == nil {
		p.of = make(map[uint32]Params)
	}
	params, ok := p.of[id]""",
        ["TestPendingZeroValueIsUsable"],
    ),
    # --- Pending.Held and Len: the left-hand side of §7.1 of RFC 9218 -------
    (
        "Held answers true for a stream nobody prioritized",
        """	_, ok := p.of[id]
	return ok
}""",
        """	return true
}""",
        [
            "TestPendingZeroValueIsUsable",
            "TestPendingHeldIsNotTake",
            "TestPruneBoundary",
        ],
    ),
    (
        "Held consumes the entry it reports on, so asking twice is a different answer",
        """	_, ok := p.of[id]""",
        """	_, ok := p.Take(id)""",
        ["TestPendingPutTake", "TestPendingHeldIsNotTake", "TestPruneBoundary"],
    ),
    (
        "Len reports an empty buffer, so §7.1 of RFC 9218's limit counts only active streams",
        """func (p *Pending) Len() int { return len(p.of) }""",
        """func (p *Pending) Len() int { return 0 }""",
        [
            "TestPendingZeroValueIsUsable",
            "TestPendingLen",
            "TestPendingUnderTheWorstClient",
        ],
    ),
    # --- Pending.Prune: §5.1.1 of RFC 9113's close --------------------------
    (
        "Prune's boundary is inclusive, so the opening stream's own priority is thrown away",
        """		if id < below {""",
        """		if id <= below {""",
        [
            "TestPruneBoundary",
            "TestPruneEdges",
            "TestPruneThenTakeAndTakeThenPrune",
        ],
    ),
    (
        "Prune closes the streams above rather than the ones §5.1.1 of RFC 9113 closed",
        """		if id < below {""",
        """		if id > below {""",
        ["TestPruneBoundary", "TestPruneEdges", "TestPendingUnderTheWorstClient"],
    ),
    (
        "Prune counts the dead entries and keeps them",
        """			delete(p.of, id)
			n++""",
        """			n++""",
        ["TestPruneBoundary", "TestPruneEdges", "TestPendingUnderTheWorstClient"],
    ),
    (
        "Prune forgets the entries and reports nothing, so the caller's count never falls",
        """			n++
		}
	}
	return n""",
        """		}
	}
	return n""",
        [
            "TestPruneBoundary",
            "TestPruneEdges",
            "TestPruneThenTakeAndTakeThenPrune",
            "TestPendingUnderTheWorstClient",
        ],
    ),
    (
        "Prune returns what is left rather than what it forgot",
        """	return n""",
        """	return len(p.of)""",
        ["TestPruneBoundary", "TestPruneEdges"],
    ),
]

breakage.main(SRC, PKG, BREAKS)
