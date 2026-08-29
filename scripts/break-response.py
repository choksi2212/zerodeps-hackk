"""Deliberately break internal/response, one guard at a time, and report which tests
notice.

Three files, one package: encoder.go turns a field list into frames, fields.go decides
whether the field list may be sent at all, and writer.go is one stream's response — the
order §8.1 puts those frames in, and the flow-control credit the body is sent against.
Each entry below removes exactly one guard from one of them and names the tests that must
fail as a result. See breakage.py for the harness, for how a break finds the file it
belongs to, and for what the five outcomes mean.

Two of these are index panics rather than wrong answers — an empty field name and an
empty field value, each indexed by the check sitting immediately after the length guard
that was removed — and both are still reported as fires rather than as crashes. That was
not the prediction. The panic happens inside a subtest, so the framework prints the
parent's --- FAIL banner before the process dies and the harness sees a test that named
itself, which says something about breakage.py's taxonomy worth writing down: `crash` is
what a panic *outside* a subtest looks like, and a table-driven suite turns most of them
into ordinary failures for nothing.

The writer.go section found two guards with no test at all, which is the outcome this
whole exercise is for. Both header and trailer sections are latched as sent *before* the
enqueue that sends them and regardless of what it returns, because writeSection can fail
with a HEADERS frame already on the queue and its CONTINUATION frames not — and a handler
that took the error as permission to try again would put a second field block behind the
first one's fragments, which §8.1 makes a connection error for every stream on the
connection. Nothing asserted it. Writing the break is what asked the question; the two
tests named ...ThatFailedHalfwayIsNotRetried are the answer, and they were written after
this file and observed failing here before they were believed.

Every test named below was checked against what it actually asserts rather than against
what its name suggests, which is not a distinction worth drawing until it bites: the
ordering test's blocks are 2*maxFrame+1 octets and so already span three frames, which
makes a break clearing END_HEADERS on the HEADERS frame invisible to it. Naming it there
would have reported a hole in a guard that is tested.

Two guards here are deliberately not broken, because no textual edit isolates them. The
`strings` import is used in exactly one expression, so a break that removes the informational
test removes the import's only use and the outcome is `build` — a hole in the report that
says nothing about the guard. Both are broken by substitution instead, which keeps the
import and still gets the answer wrong.

Run from the repository root. Restores all three files on the way out, including on error.
"""

import breakage

SRC = [
    "internal/response/encoder.go",
    "internal/response/fields.go",
    "internal/response/writer.go",
]
PKG = "./internal/response/"

# (name, old, new, tests that must fail)
BREAKS = [
    # ---------------------------------------------------------------- construction
    (
        "NewEncoder: no nil codec check, so the connection's first response panics instead",
        """	if codec == nil {
		panic("response: NewEncoder requires a header codec")
	}
""",
        "",
        ["TestNewEncoderRefusesToBeBuiltWithoutItsTwoHalves"],
    ),
    (
        "NewEncoder: no nil transport check, so the connection's first response panics instead",
        """	if t == nil {
		panic("response: NewEncoder requires a transport")
	}
""",
        "",
        ["TestNewEncoderRefusesToBeBuiltWithoutItsTwoHalves"],
    ),
    (
        "WriteHeaders: no stream check, so a header section is built for the connection",
        """	if id == 0 {
		panic("response: WriteHeaders requires a stream identifier")
	}
""",
        "",
        ["TestAHeaderBlockOnTheConnectionPanics"],
    ),
    (
        "WriteTrailers: no stream check, so a trailer section is built for the connection",
        """	if id == 0 {
		panic("response: WriteTrailers requires a stream identifier")
	}
""",
        "",
        ["TestAHeaderBlockOnTheConnectionPanics"],
    ),

    # ------------------------------------------------- which rules each entry point uses
    (
        "WriteHeaders: no validation, so a malformed field list reaches the codec",
        """	if err := checkSection(sectionHeader, fields); err != nil {
		return err
	}
	return e.writeSection(id, fields, endStream)""",
        """	return e.writeSection(id, fields, endStream)""",
        ["TestAMalformedFieldListIsRefusedWithoutBeingEncoded"],
    ),
    (
        "WriteHeaders: held to the trailer rules, so a response may not carry a status",
        """	if err := checkSection(sectionHeader, fields); err != nil {
		return err
	}
	return e.writeSection(id, fields, endStream)""",
        """	if err := checkSection(sectionTrailer, fields); err != nil {
		return err
	}
	return e.writeSection(id, fields, endStream)""",
        ["TestABodylessResponseIsOneHeadersFrameThatEndsTheStream"],
    ),
    (
        "WriteTrailers: no validation, so a pseudo-header field reaches a trailer section",
        """	if err := checkSection(sectionTrailer, fields); err != nil {
		return err
	}
	return e.writeSection(id, fields, true)""",
        """	return e.writeSection(id, fields, true)""",
        [
            "TestATrailerSectionRefusesEveryPseudoHeaderField",
            "TestATrailerSectionIsHeldToTheFieldRules",
        ],
    ),
    (
        "WriteTrailers: held to the header rules, so a trailer section must carry a status",
        """	if err := checkSection(sectionTrailer, fields); err != nil {
		return err
	}
	return e.writeSection(id, fields, true)""",
        """	if err := checkSection(sectionHeader, fields); err != nil {
		return err
	}
	return e.writeSection(id, fields, true)""",
        [
            "TestATrailerSectionNeedsNoStatus",
            "TestATrailerSectionRefusesEveryPseudoHeaderField",
        ],
    ),

    # ------------------------------------------------------------ END_STREAM on a burst
    (
        "WriteTrailers: END_STREAM not forced, so a stream is left open after its trailers",
        """	return e.writeSection(id, fields, true)""",
        """	return e.writeSection(id, fields, false)""",
        ["TestATrailerSectionAlwaysEndsTheStream"],
    ),
    (
        "WriteHeaders: END_STREAM forced, so a response with a body is closed before it",
        """	return e.writeSection(id, fields, endStream)""",
        """	return e.writeSection(id, fields, true)""",
        ["TestAResponseWithABodyLeavesEndStreamClear"],
    ),
    (
        "HEADERS: END_STREAM dropped, so a bodyless response never ends its stream",
        """		EndStream:  endStream,""",
        """		EndStream:  false,""",
        [
            "TestABodylessResponseIsOneHeadersFrameThatEndsTheStream",
            "TestATrailerSectionAlwaysEndsTheStream",
        ],
    ),

    # ------------------------------------------------------- the lock over both halves
    (
        "writeSection: the lock released before the enqueue, so two blocks interleave",
        """	e.mu.Lock()
	defer e.mu.Unlock()

	// Before Encode, not after. Encode mutates the dynamic table, and a list refused
	// afterwards would have already changed the encoding context that every later
	// response on the connection depends on — so the refusal would corrupt the
	// connection it was trying to protect.
	if err := e.checkListSize(fields); err != nil {
		return err
	}

	block := e.codec.Encode(fields)

	max := e.splitAt()""",
        """	e.mu.Lock()
	if err := e.checkListSize(fields); err != nil {
		e.mu.Unlock()
		return err
	}
	block := e.codec.Encode(fields)
	max := e.splitAt()
	e.mu.Unlock()""",
        ["TestNoSecondBlockIsEncodedWhileTheFirstIsStillBeingEnqueued"],
    ),

    # ------------------------------------------------------------ END_HEADERS and §6.10
    (
        "HEADERS: END_HEADERS always set, so a split block claims to be complete",
        """		EndHeaders: n == len(block),""",
        """		EndHeaders: true,""",
        [
            "TestABlockIsSplitAtThePeersFrameSizeCap",
            "TestBlocksReachTheWireInTheOrderTheyWereEncoded",
        ],
    ),
    (
        "HEADERS: END_HEADERS never set, so a single-frame block is never finished",
        """		EndHeaders: n == len(block),""",
        """		EndHeaders: false,""",
        [
            "TestABodylessResponseIsOneHeadersFrameThatEndsTheStream",
            "TestABlockIsSplitAtThePeersFrameSizeCap",
        ],
    ),
    (
        "CONTINUATION: END_HEADERS always set, so a block of three frames ends after two",
        """			EndHeaders: n == len(rest),""",
        """			EndHeaders: true,""",
        [
            "TestABlockIsSplitAtThePeersFrameSizeCap",
            "TestBlocksReachTheWireInTheOrderTheyWereEncoded",
        ],
    ),
    (
        "CONTINUATION: END_HEADERS never set, so no split block is ever finished",
        """			EndHeaders: n == len(rest),""",
        """			EndHeaders: false,""",
        [
            "TestABlockIsSplitAtThePeersFrameSizeCap",
            "TestBlocksReachTheWireInTheOrderTheyWereEncoded",
        ],
    ),

    # ------------------------------------------------------------------------ the split
    (
        "writeSection: the first fragment uncapped, so one frame carries the whole block",
        """	n := min(len(block), max)""",
        """	n := len(block)""",
        ["TestABlockIsSplitAtThePeersFrameSizeCap"],
    ),
    (
        "writeSection: later fragments uncapped, so one CONTINUATION carries the remainder",
        """		n = min(len(rest), max)""",
        """		n = len(rest)""",
        ["TestABlockIsSplitAtThePeersFrameSizeCap"],
    ),
    (
        "writeSection: an empty block treated as no response at all",
        """	n := min(len(block), max)
	if err := e.t.Enqueue(frame.HeadersFrame{""",
        """	if len(block) == 0 {
		return nil
	}
	n := min(len(block), max)
	if err := e.t.Enqueue(frame.HeadersFrame{""",
        ["TestAnEmptyBlockStillProducesOneHeadersFrame"],
    ),
    (
        "splitAt: the peer's cap trusted below the floor, so a zero splits into nothing",
        """	max := int(e.t.MaxFrameSize())
	if max < frame.DefaultMaxFrameSize {
		return frame.DefaultMaxFrameSize
	}
	return max""",
        """	return int(e.t.MaxFrameSize())""",
        ["TestACapBelowTheProtocolFloorIsFlooredRatherThanObeyed"],
    ),
    (
        "splitAt: the cap re-read per frame, so one burst is split against two numbers",
        """		n = min(len(rest), max)""",
        """		n = min(len(rest), e.splitAt())""",
        ["TestTheFrameSizeCapIsReadOnceForTheWholeBurst"],
    ),

    # ---------------------------------------------------- the fragments the frames carry
    (
        "HEADERS: the fragment aliases the codec's buffer instead of copying it",
        """		Fragment:   fragment(block[:n]),""",
        """		Fragment:   block[:n],""",
        ["TestEveryFragmentIsACopyRatherThanAViewOfTheCodecsBuffer"],
    ),
    (
        "CONTINUATION: the fragment aliases the codec's buffer instead of copying it",
        """			Fragment:   fragment(rest[:n]),""",
        """			Fragment:   rest[:n],""",
        ["TestEveryFragmentIsACopyRatherThanAViewOfTheCodecsBuffer"],
    ),

    # --------------------------------------------------------------- a refused enqueue
    (
        "writeSection: a refused HEADERS ignored, so a dead connection reports success",
        """	if err := e.t.Enqueue(frame.HeadersFrame{
		StreamID:   id,
		EndStream:  endStream,
		EndHeaders: n == len(block),
		Fragment:   fragment(block[:n]),
	}); err != nil {
		return err
	}""",
        """	e.t.Enqueue(frame.HeadersFrame{
		StreamID:   id,
		EndStream:  endStream,
		EndHeaders: n == len(block),
		Fragment:   fragment(block[:n]),
	})""",
        ["TestARefusedHeadersFrameIsReported"],
    ),
    (
        "writeSection: a refused CONTINUATION ignored, so a half-sent block reports success",
        """		if err := e.t.Enqueue(frame.ContinuationFrame{
			StreamID:   id,
			EndHeaders: n == len(rest),
			Fragment:   fragment(rest[:n]),
		}); err != nil {
			// The HEADERS frame is already queued, and this stream's header block
			// therefore ends without END_HEADERS. That is not a stream this server
			// can rescue: §6.10 forbids sending anything else until the block is
			// finished, and the reason a frame was refused is that the write half
			// has stopped, so nothing further will be sent on this connection at
			// all. Reporting it is the whole of the remedy.
			return err
		}""",
        """		e.t.Enqueue(frame.ContinuationFrame{
			StreamID:   id,
			EndHeaders: n == len(rest),
			Fragment:   fragment(rest[:n]),
		})""",
        ["TestARefusedContinuationIsReportedWithTheHeadersAlreadyQueued"],
    ),

    # --------------------------------------------------- the peer's two header settings
    (
        "SetMaxDynamicTableSize: the setting dropped instead of reaching the codec",
        """func (e *Encoder) SetMaxDynamicTableSize(n int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.codec.SetMaxDynamicTableSize(n)
}""",
        """func (e *Encoder) SetMaxDynamicTableSize(n int) {
	_ = n
}""",
        ["TestSetMaxDynamicTableSizeReachesTheCodec"],
    ),
    (
        "SetMaxHeaderListSize: the setting dropped, so the peer's limit is never applied",
        """func (e *Encoder) SetMaxHeaderListSize(n uint32) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.maxList = int64(n)
}""",
        """func (e *Encoder) SetMaxHeaderListSize(n uint32) {
	_ = n
}""",
        [
            "TestAnAdvertisedHeaderListLimitOfZeroIsNotTheSameAsNoLimit",
            "TestTheHeaderListSizeIsCountedTheWaySettingsDefinesIt",
        ],
    ),

    # -------------------------------------------------------- §6.5.2's list accounting
    (
        "fieldOverhead: the 32 octets a field costs not charged, so a list measures short",
        """const fieldOverhead = 32""",
        """const fieldOverhead = 0""",
        ["TestTheHeaderListSizeIsCountedTheWaySettingsDefinesIt"],
    ),
    (
        "checkListSize: values not counted, so a list of long values measures short",
        """		size += int64(len(f.Name)) + int64(len(f.Value)) + fieldOverhead""",
        """		size += int64(len(f.Name)) + fieldOverhead""",
        ["TestTheHeaderListSizeIsCountedTheWaySettingsDefinesIt"],
    ),
    (
        "checkListSize: the boundary excluded, so a list exactly at the limit is refused",
        """	if size > e.maxList {""",
        """	if size >= e.maxList {""",
        ["TestTheHeaderListSizeIsCountedTheWaySettingsDefinesIt"],
    ),
    (
        "checkListSize: the encoded block measured instead of the list",
        """	if err := e.checkListSize(fields); err != nil {
		return err
	}

	block := e.codec.Encode(fields)""",
        """	block := e.codec.Encode(fields)
	if e.maxList != noHeaderListLimit && int64(len(block)) > e.maxList {
		return fmt.Errorf("%w: %d octets, limit %d", ErrHeaderListTooLarge, len(block), e.maxList)
	}""",
        [
            "TestTheHeaderListLimitIsNotMeasuredOnTheEncodedBlock",
            "TestTheHeaderListSizeIsCountedTheWaySettingsDefinesIt",
        ],
    ),
    (
        "checkListSize: run after the encode, so a refusal moves the dynamic table on",
        """	if err := e.checkListSize(fields); err != nil {
		return err
	}

	block := e.codec.Encode(fields)""",
        """	block := e.codec.Encode(fields)

	if err := e.checkListSize(fields); err != nil {
		return err
	}""",
        ["TestTheHeaderListSizeIsCountedTheWaySettingsDefinesIt"],
    ),
    (
        "checkListSize: no unadvertised case, so the sentinel becomes a limit of nothing",
        """	if e.maxList == noHeaderListLimit {
		return nil
	}
""",
        "",
        [
            "TestNoAdvertisedHeaderListLimitAllowsAnySize",
            "TestABodylessResponseIsOneHeadersFrameThatEndsTheStream",
        ],
    ),
    (
        "noHeaderListLimit: zero as the sentinel, so a peer advertising 0 gets no limit",
        """const noHeaderListLimit = -1""",
        """const noHeaderListLimit = 0""",
        ["TestAnAdvertisedHeaderListLimitOfZeroIsNotTheSameAsNoLimit"],
    ),
    (
        "ErrHeaderListTooLarge: not wrapped, so a caller cannot tell it from a bug",
        """		return fmt.Errorf("%w: %d fields totalling %d octets, limit %d",""",
        """		return fmt.Errorf("%v: %d fields totalling %d octets, limit %d",""",
        [
            "TestTheHeaderListSizeIsCountedTheWaySettingsDefinesIt",
            "TestAnAdvertisedHeaderListLimitOfZeroIsNotTheSameAsNoLimit",
        ],
    ),
    (
        "checkListSize: the refused list quoted, so a header section reaches the log",
        """		return fmt.Errorf("%w: %d fields totalling %d octets, limit %d",
			ErrHeaderListTooLarge, len(fields), size, e.maxList)""",
        """		return fmt.Errorf("%w: %v totalling %d octets, limit %d",
			ErrHeaderListTooLarge, fields, size, e.maxList)""",
        ["TestNoFieldNameOrValueReachesTheHeaderListSizeError"],
    ),

    # ------------------------------------------------- fields.go: §8.3's section rules
    (
        "checkSection: field lines not checked, so §8.2 is not applied at all",
        """		if err := checkFieldLine(f); err != nil {
			return err
		}

""",
        "",
        ["TestEveryRuleAResponseFieldListIsHeldTo"],
    ),
    (
        "checkSection: regular fields not checked, so §8.2.2's ban is not applied",
        """			regular = true
			if err := checkRegular(f); err != nil {
				return err
			}
			continue""",
        """			regular = true
			continue""",
        ["TestEveryRuleAResponseFieldListIsHeldTo"],
    ),
    (
        "checkSection: no ordering rule, so a pseudo-header field may follow a regular one",
        """		if regular {
			return malformedf("the pseudo-header field %q after a regular field line (RFC 9113 §8.3)", f.Name)
		}""",
        """		_ = regular""",
        ["TestEveryRuleAResponseFieldListIsHeldTo"],
    ),
    (
        "checkSection: the list walked back to front, so the last fault is the one reported",
        """	for _, f := range fields {
		if err := checkFieldLine(f); err != nil {""",
        """	for i := len(fields) - 1; i >= 0; i-- {
		f := fields[i]
		if err := checkFieldLine(f); err != nil {""",
        [
            "TestTheFirstBrokenFieldIsTheOneReported",
            "TestEveryRuleAResponseFieldListIsHeldTo",
        ],
    ),
    (
        "checkSection: no trailer rule, so a trailer section may carry a status",
        """		if kind == sectionTrailer {
			// §8.3: "Pseudo-header fields MUST NOT appear in a trailer section." The
			// reason is §8.1's: a trailer section arrives after the response has been
			// acted on, so a ":status" in one would be a second answer to a question
			// already answered.
			return malformedf("the pseudo-header field %q in a trailer section (RFC 9113 §8.3)", f.Name)
		}
""",
        "",
        [
            "TestATrailerSectionRefusesEveryPseudoHeaderField",
            "TestEveryRuleAResponseFieldListIsHeldTo",
        ],
    ),
    (
        "checkSection: the pseudo-header set left open, so a request's pseudo-fields pass",
        """		if f.Name != pseudoStatus {
			return malformedf("the undefined pseudo-header field %q; a response defines only %q (RFC 9113 §8.3.2)",
				f.Name, pseudoStatus)
		}
""",
        "",
        ["TestEveryRuleAResponseFieldListIsHeldTo"],
    ),
    (
        "checkSection: no repeat check, so two statuses carrying the same code both pass",
        """		if status {
			// §8.3: a pseudo-header field may appear once. Checked by presence rather
			// than by comparing values, so that two ":status" fields carrying the same
			// code are still refused — a receiver is entitled to take either, and two
			// receivers taking different ones is the response half of smuggling.
			return malformedf("a repeated %q pseudo-header field (RFC 9113 §8.3)", pseudoStatus)
		}
""",
        "",
        ["TestEveryRuleAResponseFieldListIsHeldTo"],
    ),
    (
        "checkSection: the status value not checked, so any three octets will do",
        """		if err := checkStatus(f.Value); err != nil {
			return err
		}
""",
        "",
        ["TestEveryRuleAResponseFieldListIsHeldTo"],
    ),
    (
        "checkSection: no required status, so a response goes out with no status at all",
        """	if kind == sectionHeader && !status {
		// §8.3.2: ":status" is the one pseudo-header field a response must include.
		// Reported by name rather than as "a missing pseudo-header field", because
		// this is the failure a handler that built its field list by hand will hit and
		// the name is the fix.
		return malformedf("no %q pseudo-header field (RFC 9113 §8.3.2)", pseudoStatus)
	}
""",
        "",
        ["TestEveryRuleAResponseFieldListIsHeldTo"],
    ),
    (
        "checkSection: the two sections swapped, so each is held to the other's rules",
        """	if kind == sectionHeader && !status {""",
        """	if kind == sectionTrailer && !status {""",
        ["TestEveryRuleAResponseFieldListIsHeldTo"],
    ),

    # -------------------------------------------- fields.go: §8.2's field-line octets
    (
        "checkFieldLine: no empty-name check, so the pseudo-header test indexes nothing",
        """	if f.Name == "" {
		// A field name is a token (§5.1 of RFC 9110) and a token is at least one
		// character. This is the part of that definition an octet check cannot state.
		return malformedf("a field line with an empty name (RFC 9110 §5.1)")
	}
""",
        "",
        ["TestEveryRuleAResponseFieldListIsHeldTo"],
    ),
    (
        "checkFieldLine: the leading colon not exempted, so every pseudo-field is refused",
        """	name := f.Name
	if name[0] == ':' {
		name = name[1:]
	}""",
        """	name := f.Name""",
        ["TestEveryRuleAResponseFieldListIsHeldTo"],
    ),
    (
        "checkFieldLine: no case check, so a capitalised field name goes out as it is",
        """		case c >= 'A' && c <= 'Z':
			// §8.2: "Field names MUST be converted to lowercase when constructing an
			// HTTP/2 message." Reported separately from the octet range it belongs to,
			// because it is the one a handler hits by accident — "Content-Type" is
			// what every other HTTP API in the world spells it — and "not lowercase"
			// is the answer its author needs.
			return malformedf("field name %q is not lowercase (RFC 9113 §8.2)", f.Name)
""",
        "",
        ["TestEveryRuleAResponseFieldListIsHeldTo"],
    ),
    (
        "checkFieldLine: the name octet range open at both ends, so SP and DEL pass",
        """		case c <= 0x20, c >= 0x7f:""",
        """		case c < 0x20, c > 0x7f:""",
        ["TestEveryRuleAResponseFieldListIsHeldTo"],
    ),
    (
        "checkFieldLine: no colon check, so a name may carry the HTTP/1.1 delimiter",
        """		case c == ':':
			return malformedf("field name %q contains a colon (RFC 9113 §8.2.1)", f.Name)
""",
        "",
        ["TestEveryRuleAResponseFieldListIsHeldTo"],
    ),
    (
        "checkFieldLine: CR allowed in a value, which is half of a response split",
        """		case 0x00, 0x0a, 0x0d:""",
        """		case 0x00, 0x0a:""",
        ["TestEveryRuleAResponseFieldListIsHeldTo"],
    ),
    (
        "checkFieldLine: LF allowed in a value, which is the other half",
        """		case 0x00, 0x0a, 0x0d:""",
        """		case 0x00, 0x0d:""",
        ["TestEveryRuleAResponseFieldListIsHeldTo"],
    ),
    (
        "checkFieldLine: NUL allowed in a value",
        """		case 0x00, 0x0a, 0x0d:""",
        """		case 0x0a, 0x0d:""",
        ["TestEveryRuleAResponseFieldListIsHeldTo"],
    ),
    (
        "checkFieldLine: no length guard, so an empty value indexes its first octet",
        """	if len(f.Value) > 0 {""",
        """	if true {""",
        ["TestEveryRuleAResponseFieldListIsHeldTo"],
    ),
    (
        "checkFieldLine: no leading-whitespace check on a value",
        """		if c := f.Value[0]; c == ' ' || c == '\\t' {
			return malformedf("the value of field %q starts with whitespace (RFC 9113 §8.2.1)", f.Name)
		}
""",
        "",
        ["TestEveryRuleAResponseFieldListIsHeldTo"],
    ),
    (
        "checkFieldLine: no trailing-whitespace check on a value",
        """		if c := f.Value[len(f.Value)-1]; c == ' ' || c == '\\t' {
			return malformedf("the value of field %q ends with whitespace (RFC 9113 §8.2.1)", f.Name)
		}
""",
        "",
        ["TestEveryRuleAResponseFieldListIsHeldTo"],
    ),
    (
        "checkFieldLine: HTAB not whitespace at the front of a value",
        """		if c := f.Value[0]; c == ' ' || c == '\\t' {""",
        """		if c := f.Value[0]; c == ' ' {""",
        ["TestEveryRuleAResponseFieldListIsHeldTo"],
    ),
    (
        "checkFieldLine: HTAB not whitespace at the end of a value",
        """		if c := f.Value[len(f.Value)-1]; c == ' ' || c == '\\t' {""",
        """		if c := f.Value[len(f.Value)-1]; c == ' ' {""",
        ["TestEveryRuleAResponseFieldListIsHeldTo"],
    ),

    # ------------------------------------- fields.go: §8.2.2's connection-specific set
    (
        "checkRegular: connection allowed in a response",
        """	case "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade", "te":""",
        """	case "proxy-connection", "keep-alive", "transfer-encoding", "upgrade", "te":""",
        ["TestEveryRuleAResponseFieldListIsHeldTo"],
    ),
    (
        "checkRegular: proxy-connection allowed in a response",
        """	case "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade", "te":""",
        """	case "connection", "keep-alive", "transfer-encoding", "upgrade", "te":""",
        ["TestEveryRuleAResponseFieldListIsHeldTo"],
    ),
    (
        "checkRegular: keep-alive allowed in a response",
        """	case "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade", "te":""",
        """	case "connection", "proxy-connection", "transfer-encoding", "upgrade", "te":""",
        ["TestEveryRuleAResponseFieldListIsHeldTo"],
    ),
    (
        "checkRegular: transfer-encoding allowed, so a response can arrange a smuggle",
        """	case "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade", "te":""",
        """	case "connection", "proxy-connection", "keep-alive", "upgrade", "te":""",
        ["TestEveryRuleAResponseFieldListIsHeldTo"],
    ),
    (
        "checkRegular: upgrade allowed in a response",
        """	case "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade", "te":""",
        """	case "connection", "proxy-connection", "keep-alive", "transfer-encoding", "te":""",
        ["TestEveryRuleAResponseFieldListIsHeldTo"],
    ),
    (
        "checkRegular: TE allowed, as §8.2.2's request-only exception would have it",
        """	case "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade", "te":""",
        """	case "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade":""",
        ["TestEveryRuleAResponseFieldListIsHeldTo"],
    ),
    (
        "checkRegular: Trailer banned too, so a trailer section cannot be announced",
        """	case "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade", "te":""",
        """	case "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade", "te", "trailer":""",
        ["TestEveryRuleAResponseFieldListIsHeldTo"],
    ),

    # ------------------------------------------ fields.go: §8.3.2's three-digit status
    (
        "checkStatus: the length only floored, so a four-digit status passes",
        """	if len(v) != 3 {""",
        """	if len(v) < 3 {""",
        ["TestEveryRuleAResponseFieldListIsHeldTo"],
    ),
    (
        "checkStatus: no length check at all, so an empty status indexes nothing",
        """	if len(v) != 3 {
		return malformedf("a %q of %d octets, want three digits (RFC 9113 §8.3.2)", pseudoStatus, len(v))
	}
""",
        "",
        ["TestEveryRuleAResponseFieldListIsHeldTo"],
    ),
    (
        "checkStatus: the length checked after the digits, so a status line misdiagnoses",
        """	if len(v) != 3 {
		return malformedf("a %q of %d octets, want three digits (RFC 9113 §8.3.2)", pseudoStatus, len(v))
	}
	for i := 0; i < len(v); i++ {
		if c := v[i]; c < '0' || c > '9' {
			return malformedf("a %q containing the octet 0x%02x, want three digits (RFC 9113 §8.3.2)",
				pseudoStatus, c)
		}
	}""",
        """	for i := 0; i < len(v); i++ {
		if c := v[i]; c < '0' || c > '9' {
			return malformedf("a %q containing the octet 0x%02x, want three digits (RFC 9113 §8.3.2)",
				pseudoStatus, c)
		}
	}
	if len(v) != 3 {
		return malformedf("a %q of %d octets, want three digits (RFC 9113 §8.3.2)", pseudoStatus, len(v))
	}""",
        ["TestEveryRuleAResponseFieldListIsHeldTo"],
    ),
    (
        "checkStatus: the digits not checked, so a status may carry letters",
        """	for i := 0; i < len(v); i++ {
		if c := v[i]; c < '0' || c > '9' {
			return malformedf("a %q containing the octet 0x%02x, want three digits (RFC 9113 §8.3.2)",
				pseudoStatus, c)
		}
	}
""",
        "",
        ["TestEveryRuleAResponseFieldListIsHeldTo"],
    ),
    (
        "checkStatus: no class check, so a 0xx or a 9xx goes out",
        """	if c := v[0]; c < '1' || c > '5' {
		return malformedf("a %q of class %cxx; RFC 9110 §15 defines 1xx through 5xx", pseudoStatus, c)
	}
""",
        "",
        ["TestEveryRuleAResponseFieldListIsHeldTo"],
    ),
    (
        "checkStatus: the class range open below, so a 0xx goes out",
        """	if c := v[0]; c < '1' || c > '5' {""",
        """	if c := v[0]; c < '0' || c > '5' {""",
        ["TestEveryRuleAResponseFieldListIsHeldTo"],
    ),
    (
        "checkStatus: the class range open above, so a 6xx goes out",
        """	if c := v[0]; c < '1' || c > '5' {""",
        """	if c := v[0]; c < '1' || c > '6' {""",
        ["TestEveryRuleAResponseFieldListIsHeldTo"],
    ),
    (
        "checkStatus: the class range short below, so no informational response can be sent",
        """	if c := v[0]; c < '1' || c > '5' {""",
        """	if c := v[0]; c < '2' || c > '5' {""",
        ["TestEveryStatusClassTheProtocolDefinesIsAccepted"],
    ),
    (
        "checkStatus: the class range short above, so a server error cannot be reported",
        """	if c := v[0]; c < '1' || c > '5' {""",
        """	if c := v[0]; c < '1' || c > '4' {""",
        ["TestEveryStatusClassTheProtocolDefinesIsAccepted"],
    ),

    # -------------------------------------- fields.go: what a message is allowed to say
    (
        "malformedf: the sentinel not wrapped, so a caller cannot classify the failure",
        """	return fmt.Errorf("%w: "+format, append([]any{ErrMalformedResponse}, args...)...)""",
        """	return fmt.Errorf("%v: "+format, append([]any{ErrMalformedResponse}, args...)...)""",
        [
            "TestEveryRuleAResponseFieldListIsHeldTo",
            "TestAMalformedFieldListIsRefusedWithoutBeingEncoded",
            "TestATrailerSectionIsHeldToTheFieldRules",
        ],
    ),
    (
        "checkFieldLine: the refused value quoted, so a Set-Cookie reaches the log",
        """			return malformedf("the value of field %q contains the octet 0x%02x (RFC 9113 §8.2.1)", f.Name, c)""",
        """			return malformedf("the value of field %q (%q) contains the octet 0x%02x (RFC 9113 §8.2.1)",
				f.Name, f.Value, c)""",
        [
            "TestNoFieldValueEverReachesAnErrorMessage",
            "TestEveryRuleAResponseFieldListIsHeldTo",
        ],
    ),
    (
        "checkFieldLine: the whitespace-padded value quoted, so a signed URL reaches the log",
        """			return malformedf("the value of field %q starts with whitespace (RFC 9113 §8.2.1)", f.Name)""",
        """			return malformedf("the value of field %q (%q) starts with whitespace (RFC 9113 §8.2.1)",
				f.Name, f.Value)""",
        [
            "TestNoFieldValueEverReachesAnErrorMessage",
            "TestEveryRuleAResponseFieldListIsHeldTo",
        ],
    ),
    (
        "checkStatus: the rejected value quoted, so whatever was in it reaches the log",
        """		return malformedf("a %q of %d octets, want three digits (RFC 9113 §8.3.2)", pseudoStatus, len(v))""",
        """		return malformedf("a %q of %q, want three digits (RFC 9113 §8.3.2)", pseudoStatus, v)""",
        [
            "TestNoFieldValueEverReachesAnErrorMessage",
            "TestEveryRuleAResponseFieldListIsHeldTo",
        ],
    ),
    (
        "checkFieldLine: the indexing hint read, so a message depends on h2.Field.Sensitive",
        """			return malformedf("the value of field %q contains the octet 0x%02x (RFC 9113 §8.2.1)", f.Name, c)""",
        """			return malformedf("the value of field %q (sensitive=%v) contains the octet 0x%02x (RFC 9113 §8.2.1)",
				f.Name, f.Sensitive, c)""",
        [
            "TestASensitiveFieldIsRefusedTheSameWayAsAnyOther",
            "TestEveryRuleAResponseFieldListIsHeldTo",
        ],
    ),

    # ------------------------------------ writer.go: the three parts NewWriter needs
    (
        "NewWriter: no nil encoder check, so a handler's first write panics instead",
        """	if enc == nil {
		panic("response: NewWriter requires an encoder")
	}
""",
        "",
        ["TestNewWriterRefusesToBeBuiltWithoutItsThreeParts"],
    ),
    (
        "NewWriter: no nil credit check, so a handler's first body write panics instead",
        """	if credit == nil {
		panic("response: NewWriter requires a source of flow-control credit")
	}
""",
        "",
        ["TestNewWriterRefusesToBeBuiltWithoutItsThreeParts"],
    ),
    (
        "NewWriter: no stream check, so a whole response is written for the connection",
        """	if id == 0 {
		panic("response: NewWriter requires a stream identifier")
	}
""",
        "",
        ["TestNewWriterRefusesToBeBuiltWithoutItsThreeParts"],
    ),

    # ----------------------------------------------- writer.go: the order §8.1 fixes
    (
        "writeHeader: a header section after END_STREAM, reported as the wrong mistake",
        """	case w.closed:
		return ErrDone
	case w.wroteHeader:
		return ErrHeaderWritten
	}
""",
        """	case w.wroteHeader:
		return ErrHeaderWritten
	}
""",
        ["TestNothingFollowsTheFrameThatEndedTheStream"],
    ),
    (
        "writeHeader: a second final header section allowed",
        """	case w.wroteHeader:
		return ErrHeaderWritten
	}
""",
        """	}
""",
        [
            "TestASecondHeaderSectionIsRefused",
            "TestAnInterimResponseDoesNotBecomeTheHeaderSection",
            "TestAHeaderSectionThatFailedHalfwayIsNotRetried",
        ],
    ),
    (
        "Write: a body after END_STREAM",
        """	case w.closed:
		return 0, ErrDone
	case !w.wroteHeader:
		return 0, ErrNoHeader
	}
""",
        """	case !w.wroteHeader:
		return 0, ErrNoHeader
	}
""",
        ["TestNothingFollowsTheFrameThatEndedTheStream"],
    ),
    (
        "Write: a body before any header section",
        """	case !w.wroteHeader:
		return 0, ErrNoHeader
	}
""",
        """	}
""",
        [
            "TestNothingMayBeWrittenBeforeAHeaderSection",
            "TestAnInterimResponseDoesNotBecomeTheHeaderSection",
        ],
    ),
    (
        "Close: not idempotent, so a teardown path ends an ended stream again",
        """	if w.closed {
		return nil
	}
""",
        "",
        [
            "TestNothingFollowsTheFrameThatEndedTheStream",
            "TestABodylessHeaderSectionNeedsNoClose",
            "TestATrailerSectionEndsTheStreamAfterTheBody",
        ],
    ),
    (
        "Close: an empty response ended for a handler that never wrote one",
        """	if !w.wroteHeader {
		return ErrNoHeader
	}
	w.closed = true
""",
        """	w.closed = true
""",
        ["TestNothingMayBeWrittenBeforeAHeaderSection"],
    ),
    (
        "Trailers: a trailer section after END_STREAM",
        """	case w.closed:
		return ErrDone
	case !w.wroteHeader:
		return ErrNoHeader
	}
""",
        """	case !w.wroteHeader:
		return ErrNoHeader
	}
""",
        [
            "TestNothingFollowsTheFrameThatEndedTheStream",
            "TestATrailerSectionThatFailedHalfwayIsNotRetried",
        ],
    ),
    (
        "Trailers: a trailer section before any header section",
        """	case !w.wroteHeader:
		return ErrNoHeader
	}
""",
        """	}
""",
        ["TestNothingMayBeWrittenBeforeAHeaderSection"],
    ),

    # -------------------------------------------- writer.go: the interim response
    (
        "writeHeader: an interim response latched, so the final one is refused",
        """	w.wroteHeader = !interim""",
        """	w.wroteHeader = true""",
        ["TestAnInterimResponseDoesNotBecomeTheHeaderSection"],
    ),
    (
        "writeHeader: no header section ever latched, so no body is ever legal",
        """	w.wroteHeader = !interim""",
        """	w.wroteHeader = false""",
        [
            "TestABodyIsSplitAtThePeersFrameSizeCap",
            "TestASecondHeaderSectionIsRefused",
            "TestATrailerSectionNeedsNoBody",
        ],
    ),
    (
        "writeHeader: every header section ends the stream, so no response has a body",
        """	w.closed = endStream""",
        """	w.closed = true""",
        [
            "TestABodyIsSplitAtThePeersFrameSizeCap",
            "TestAnInterimResponseDoesNotBecomeTheHeaderSection",
        ],
    ),
    (
        "writeHeader: END_STREAM on the burst not recorded, so the response stays open",
        """	w.closed = endStream""",
        """	w.closed = false""",
        [
            "TestNothingFollowsTheFrameThatEndedTheStream",
            "TestABodylessHeaderSectionNeedsNoClose",
        ],
    ),
    (
        "writeHeader: no 1xx-with-END_STREAM refusal, so a malformed response is sent",
        """	interim := informational(fields)
	if endStream && interim {
		return ErrInformationalEnd
	}
""",
        """	interim := informational(fields)
""",
        [
            "TestAnInterimResponseCannotEndTheStream",
            "TestWhichStatusCodesAreInformational",
        ],
    ),
    (
        "writeHeader: every interim response refused, not only one ending the stream",
        """	if endStream && interim {""",
        """	if interim {""",
        ["TestAnInterimResponseDoesNotBecomeTheHeaderSection"],
    ),
    (
        "writeHeader: the field list validated after the informational test, not before",
        """	if err := checkSection(sectionHeader, fields); err != nil {
		return err
	}

	interim := informational(fields)
	if endStream && interim {
		return ErrInformationalEnd
	}
""",
        """	interim := informational(fields)
	if endStream && interim {
		return ErrInformationalEnd
	}

	if err := checkSection(sectionHeader, fields); err != nil {
		return err
	}
""",
        ["TestAMalformedFieldListIsReportedBeforeTheInformationalRule"],
    ),
    (
        "informational: only 100 counted, so 101 and 103 may end a stream",
        """			return strings.HasPrefix(f.Value, "1")""",
        """			return strings.HasPrefix(f.Value, "100")""",
        ["TestWhichStatusCodesAreInformational"],
    ),
    (
        "informational: the wrong end of the status code read",
        """			return strings.HasPrefix(f.Value, "1")""",
        """			return strings.HasSuffix(f.Value, "1")""",
        [
            "TestWhichStatusCodesAreInformational",
            "TestAnInterimResponseCannotEndTheStream",
            "TestAnInterimResponseDoesNotBecomeTheHeaderSection",
        ],
    ),

    # ----------------------------- writer.go: latched before the enqueue, not after
    (
        "writeHeader: the response latched only if the burst was accepted whole",
        """	w.wroteHeader = !interim
	w.closed = endStream

	return w.enc.writeSection(w.id, fields, endStream)""",
        """	if err := w.enc.writeSection(w.id, fields, endStream); err != nil {
		return err
	}
	w.wroteHeader = !interim
	w.closed = endStream
	return nil""",
        ["TestAHeaderSectionThatFailedHalfwayIsNotRetried"],
    ),
    (
        "Trailers: the stream closed only if the burst was accepted whole",
        """	if err := checkSection(sectionTrailer, fields); err != nil {
		return err
	}
	w.closed = true

	return w.enc.writeSection(w.id, fields, true)""",
        """	if err := checkSection(sectionTrailer, fields); err != nil {
		return err
	}
	if err := w.enc.writeSection(w.id, fields, true); err != nil {
		return err
	}
	w.closed = true
	return nil""",
        ["TestATrailerSectionThatFailedHalfwayIsNotRetried"],
    ),
    (
        "Trailers: the stream closed before the field list is validated",
        """	if err := checkSection(sectionTrailer, fields); err != nil {
		return err
	}
	w.closed = true
""",
        """	w.closed = true
	if err := checkSection(sectionTrailer, fields); err != nil {
		return err
	}
""",
        ["TestARefusedTrailerSectionLeavesTheStreamOpen"],
    ),
    (
        "Close: the stream closed only if the empty frame was accepted",
        """	return w.enc.enqueue(frame.DataFrame{StreamID: w.id, EndStream: true})""",
        """	if err := w.enc.enqueue(frame.DataFrame{StreamID: w.id, EndStream: true}); err != nil {
		w.closed = false
		return err
	}
	return nil""",
        ["TestARefusedCloseStillEndsTheResponse"],
    ),

    # -------------------------------------- writer.go: the body's two separate limits
    (
        "Write: no frame-size cap, so one Write is one DATA frame of any size",
        """min(len(p), w.enc.splitAt())""",
        """len(p)""",
        [
            "TestABodyIsSplitAtThePeersFrameSizeCap",
            "TestTheFrameSizeCapIsReadForEveryDataFrame",
            "TestOnlyTheContentIsReservedAndTheFrameHeaderIsNot",
        ],
    ),
    (
        "Write: the cap read once for the whole body instead of once per frame",
        """	sent := 0
	for len(p) > 0 {
		n, err := w.credit.Reserve(w.id, min(len(p), w.enc.splitAt()))""",
        """	sent, size := 0, w.enc.splitAt()
	for len(p) > 0 {
		n, err := w.credit.Reserve(w.id, min(len(p), size))""",
        ["TestTheFrameSizeCapIsReadForEveryDataFrame"],
    ),
    (
        "Write: the caller's slice aliased into a frame the writer goroutine owns",
        """			Data:     bytes.Clone(p[:n]),""",
        """			Data:     bytes.NewBuffer(p[:n]).Bytes(),""",
        ["TestTheContentIsCopiedRatherThanAliased"],
    ),
    (
        "Write: the loop entered unconditionally, so an empty body reserves nothing",
        """	for len(p) > 0 {""",
        """	for first := true; first || len(p) > 0; first = false {""",
        ["TestAnEmptyWriteSendsNothingAndReservesNothing"],
    ),
    (
        "Write: a failed reservation reported as though its octets had been sent",
        """		if err != nil {
			// Short and honest. The octets already enqueued are on their way and the
			// caller is entitled to know how many; the ones Reserve was asked for are
			// not coming, on this stream, ever — see Credit.Reserve.
			return sent, err
		}
""",
        """		if err != nil {
			return sent + len(p), err
		}
""",
        ["TestAFailedReservationIsReportedWithTheOctetsAlreadySent"],
    ),
    (
        "Write: a refused DATA frame reported as a short write with no error",
        """		}); err != nil {
			return sent, err
		}
""",
        """		}); err != nil {
			return sent, nil
		}
""",
        ["TestARefusedDataFrameIsReportedWithTheOctetsAlreadySent"],
    ),

    # ------------------------------------------- writer.go: ending the stream
    (
        "Close: the empty END_STREAM frame reserved for, against §6.9.1's exemption",
        """	return w.enc.enqueue(frame.DataFrame{StreamID: w.id, EndStream: true})""",
        """	if _, err := w.credit.Reserve(w.id, 1); err != nil {
		return err
	}
	return w.enc.enqueue(frame.DataFrame{StreamID: w.id, EndStream: true})""",
        ["TestCloseSendsAnEmptyDataFrameAndReservesNothing"],
    ),
    (
        "Close: the frame sent without END_STREAM, so it says nothing at all",
        """	return w.enc.enqueue(frame.DataFrame{StreamID: w.id, EndStream: true})""",
        """	return w.enc.enqueue(frame.DataFrame{StreamID: w.id})""",
        [
            "TestCloseSendsAnEmptyDataFrameAndReservesNothing",
            "TestCloseFollowsTheBodyItEnds",
        ],
    ),
    (
        "Trailers: the trailer block sent without END_STREAM",
        """	return w.enc.writeSection(w.id, fields, true)""",
        """	return w.enc.writeSection(w.id, fields, false)""",
        [
            "TestATrailerSectionEndsTheStreamAfterTheBody",
            "TestATrailerSectionNeedsNoBody",
        ],
    ),
    (
        "Trailers: the field list held to §8.3's header rules, so :status is allowed",
        """	if err := checkSection(sectionTrailer, fields); err != nil {
		return err
	}
	w.closed = true
""",
        """	if err := checkSection(sectionHeader, fields); err != nil {
		return err
	}
	w.closed = true
""",
        [
            "TestARefusedTrailerSectionLeavesTheStreamOpen",
            "TestATrailerSectionEndsTheStreamAfterTheBody",
        ],
    ),

    # --------------------------- writer.go: where the Encoder's lock is and is not held
    (
        "enqueue: a DATA frame outside the lock, so it lands inside a header burst",
        """func (e *Encoder) enqueue(f frame.Frame) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.t.Enqueue(f)
}""",
        """func (e *Encoder) enqueue(f frame.Frame) error {
	return e.t.Enqueue(f)
}""",
        ["TestNoHeaderSectionIsEncodedWhileADataFrameIsBeingEnqueued"],
    ),
    (
        "Write: the reservation taken inside the lock, so one slow reader stalls them all",
        """		n, err := w.credit.Reserve(w.id, min(len(p), w.enc.splitAt()))""",
        """		w.enc.mu.Lock()
		n, err := w.credit.Reserve(w.id, min(len(p), w.enc.splitAt()))
		w.enc.mu.Unlock()""",
        ["TestAnotherStreamsHeaderSectionGoesOutWhileOneWaitsForCredit"],
    ),
]

breakage.main(SRC, PKG, BREAKS)
