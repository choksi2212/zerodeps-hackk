package frame

import (
	"fmt"
	"testing"
)

// implementedFrameTypes is the hand-written list of every frame type this package
// implements: the wire value and the name, taken from RFC 9113 §11.2 and RFC 9218
// §7.1 rather than derived from the constants or from either table in types.go.
//
// It is the independent authority the tables are checked against. Two tables that
// agree with each other can still both be wrong, and the only thing that cannot be
// is the specification — so the value, the name, the name table, the parser table
// and known are all compared against this list and not against one another.
var implementedFrameTypes = []struct {
	typ  FrameType
	want uint8
	name string
}{
	{TypeData, 0x0, "DATA"},
	{TypeHeaders, 0x1, "HEADERS"},
	{TypePriority, 0x2, "PRIORITY"},
	{TypeRSTStream, 0x3, "RST_STREAM"},
	{TypeSettings, 0x4, "SETTINGS"},
	{TypePushPromise, 0x5, "PUSH_PROMISE"},
	{TypePing, 0x6, "PING"},
	{TypeGoAway, 0x7, "GOAWAY"},
	{TypeWindowUpdate, 0x8, "WINDOW_UPDATE"},
	{TypeContinuation, 0x9, "CONTINUATION"},
	{TypePriorityUpdate, 0x10, "PRIORITY_UPDATE"},
}

// frameTypeSet is implementedFrameTypes as a lookup, for the exhaustive walks.
func frameTypeSet() map[FrameType]bool {
	set := make(map[FrameType]bool, len(implementedFrameTypes))
	for _, tt := range implementedFrameTypes {
		set[tt.typ] = true
	}
	return set
}

func TestFrameTypeWireValues(t *testing.T) {
	// Asserted against the literal values in RFC 9113 §11.2 and RFC 9218 §7.1
	// rather than derived from iota. A wrong constant here makes the server send a
	// well-formed frame of the wrong kind, which surfaces as a conformance failure
	// a long way from the mistake.
	for _, tt := range implementedFrameTypes {
		if got := uint8(tt.typ); got != tt.want {
			t.Errorf("%s = 0x%x, want 0x%x", tt.name, got, tt.want)
		}
		if got := tt.typ.String(); got != tt.name {
			t.Errorf("FrameType(0x%x).String() = %q, want %q", uint8(tt.typ), got, tt.name)
		}
		if !tt.typ.known() {
			t.Errorf("%s.known() = false, want true", tt.name)
		}
	}
	if int(maxDefinedType) != 0x10 {
		t.Errorf("maxDefinedType = 0x%x, want 0x10 (PRIORITY_UPDATE, the highest type "+
			"this package implements)", uint8(maxDefinedType))
	}
}

// TestFrameTypeTablesAgree holds the name table and the parser table to the same
// shape.
//
// They have to have it. String is what a log line and an error message call, and
// known is what decides whether ReadFrame calls parsers[t] — so a type with a name
// and no parser would be reported as a frame this package handles and then index a
// nil function, and a type with a parser and no name would be parsed and then
// logged as unknown. Since PRIORITY_UPDATE opened a hole in the middle of both
// tables, neither shape can be checked by its length alone.
func TestFrameTypeTablesAgree(t *testing.T) {
	if got, want := len(parsers), int(maxDefinedType)+1; got != want {
		t.Fatalf("parsers has %d entries, want %d: the table must stop at the highest "+
			"type it implements, with no unassigned tail", got, want)
	}
	if got, want := len(frameTypeNames), int(maxDefinedType)+1; got != want {
		t.Fatalf("frameTypeNames has %d entries, want %d", got, want)
	}

	implemented := frameTypeSet()
	for v := range len(parsers) {
		typ := FrameType(v)
		named := frameTypeNames[v] != ""
		parseable := parsers[v] != nil
		switch {
		case named != parseable:
			t.Errorf("FrameType(0x%x): named = %v but parseable = %v; a type must have "+
				"both or neither", v, named, parseable)
		case named != implemented[typ]:
			t.Errorf("FrameType(0x%x): the tables say implemented = %v, the specification "+
				"says %v", v, named, implemented[typ])
		}
	}
}

func TestFrameTypeUnknown(t *testing.T) {
	// RFC 9113 §4.1 requires a type this package does not implement to be
	// discarded, not rejected, so the type must survive being named and must
	// report itself as unknown. Every value of the 8-bit field is exercised
	// because String is called from log lines on the hostile-input path — and
	// because the unimplemented values are no longer a tail: 0xa through 0xf sit
	// between CONTINUATION and PRIORITY_UPDATE, index inside both tables, and are
	// exactly the values a range check would get wrong.
	implemented := frameTypeSet()
	for v := range 256 {
		typ := FrameType(v)
		got := typ.String()
		if got == "" {
			t.Fatalf("FrameType(0x%x).String() is empty", v)
		}
		if typ.known() != implemented[typ] {
			t.Errorf("FrameType(0x%x).known() = %v, want %v", v, typ.known(), implemented[typ])
		}
		if !implemented[typ] {
			want := fmt.Sprintf("UNKNOWN_FRAME_TYPE(0x%x)", v)
			if got != want {
				t.Errorf("FrameType(0x%x).String() = %q, want %q", v, got, want)
			}
		}
	}
}

func TestFlagWireValues(t *testing.T) {
	tests := []struct {
		flag Flags
		want uint8
		name string
	}{
		{FlagEndStream, 0x1, "END_STREAM"},
		{FlagAck, 0x1, "ACK"},
		{FlagEndHeaders, 0x4, "END_HEADERS"},
		{FlagPadded, 0x8, "PADDED"},
		{FlagPriority, 0x20, "PRIORITY"},
	}
	for _, tt := range tests {
		if got := uint8(tt.flag); got != tt.want {
			t.Errorf("%s = 0x%x, want 0x%x", tt.name, got, tt.want)
		}
	}
	// END_STREAM and ACK are deliberately the same bit: 0x1 means END_STREAM on
	// DATA and HEADERS, and ACK on SETTINGS and PING. This is the reason frame
	// structs expose named booleans instead of a raw Flags field.
	if FlagEndStream != FlagAck {
		t.Error("FlagEndStream and FlagAck must be the same bit, 0x1")
	}
}

func TestFlagsHas(t *testing.T) {
	fl := FlagEndStream | FlagPadded
	if !fl.has(FlagEndStream) {
		t.Error("has(END_STREAM) = false on END_STREAM|PADDED")
	}
	if !fl.has(FlagPadded) {
		t.Error("has(PADDED) = false on END_STREAM|PADDED")
	}
	if fl.has(FlagEndHeaders) {
		t.Error("has(END_HEADERS) = true on END_STREAM|PADDED")
	}
	if fl.has(FlagPriority) {
		t.Error("has(PRIORITY) = true on END_STREAM|PADDED")
	}
	// has reports whether *every* bit is set, so a combination that is only
	// partly present is not "had". A parser that got this wrong would accept a
	// HEADERS frame as padded when only END_STREAM was set.
	if fl.has(FlagEndStream | FlagEndHeaders) {
		t.Error("has(END_STREAM|END_HEADERS) = true when END_HEADERS is absent")
	}
	if !fl.has(FlagEndStream | FlagPadded) {
		t.Error("has(END_STREAM|PADDED) = false when both are set")
	}
	if !Flags(0).has(0) {
		t.Error("Flags(0).has(0) = false; the empty set is always present")
	}
}

func TestFlagsSet(t *testing.T) {
	var fl Flags
	fl = fl.set(FlagEndStream, true)
	fl = fl.set(FlagPadded, false)
	fl = fl.set(FlagEndHeaders, true)
	if want := FlagEndStream | FlagEndHeaders; fl != want {
		t.Errorf("flags = 0x%02x, want 0x%02x", uint8(fl), uint8(want))
	}
	// set never clears: it is only ever used to build wire flags from named
	// booleans, all of which start from zero.
	if got := fl.set(FlagEndStream, false); got != fl {
		t.Errorf("set(END_STREAM, false) cleared a set bit: 0x%02x", uint8(got))
	}
	if got := fl.set(FlagEndHeaders, true); got != fl {
		t.Errorf("set of an already-set bit changed the value: 0x%02x", uint8(got))
	}
}

// implementedSettings is the hand-written list of every SETTINGS identifier this
// server implements, from RFC 9113 §11.3 and RFC 9218 §2.1. It plays the same part
// for settingNames that implementedFrameTypes plays for the frame tables.
var implementedSettings = []struct {
	id   SettingID
	want uint16
	name string
}{
	{SettingHeaderTableSize, 0x1, "SETTINGS_HEADER_TABLE_SIZE"},
	{SettingEnablePush, 0x2, "SETTINGS_ENABLE_PUSH"},
	{SettingMaxConcurrentStreams, 0x3, "SETTINGS_MAX_CONCURRENT_STREAMS"},
	{SettingInitialWindowSize, 0x4, "SETTINGS_INITIAL_WINDOW_SIZE"},
	{SettingMaxFrameSize, 0x5, "SETTINGS_MAX_FRAME_SIZE"},
	{SettingMaxHeaderListSize, 0x6, "SETTINGS_MAX_HEADER_LIST_SIZE"},
	{SettingNoRFC7540Priorities, 0x9, "SETTINGS_NO_RFC7540_PRIORITIES"},
}

func settingIDSet() map[SettingID]bool {
	set := make(map[SettingID]bool, len(implementedSettings))
	for _, tt := range implementedSettings {
		set[tt.id] = true
	}
	return set
}

func TestSettingIDWireValues(t *testing.T) {
	for _, tt := range implementedSettings {
		if got := uint16(tt.id); got != tt.want {
			t.Errorf("%s = 0x%x, want 0x%x", tt.name, got, tt.want)
		}
		if got := tt.id.String(); got != tt.name {
			t.Errorf("SettingID(0x%x).String() = %q, want %q", uint16(tt.id), got, tt.name)
		}
		if !tt.id.known() {
			t.Errorf("%s.known() = false, want true", tt.name)
		}
	}
	if got, want := len(settingNames), int(SettingNoRFC7540Priorities)+1; got != want {
		t.Errorf("settingNames has %d entries, want %d: the table must stop at the highest "+
			"identifier it names", got, want)
	}
}

func TestSettingIDUnknown(t *testing.T) {
	// Identifier 0x0 is not assigned to anything, and 0x7 and 0x8 belong to
	// extensions this server does not implement, so none of the three may be
	// reported as known even though all three index inside settingNames. RFC 9113
	// §6.5.2 requires an identifier we do not implement to be ignored, and
	// ignoring the wrong one means silently dropping a setting the peer expects us
	// to honour.
	for _, id := range []SettingID{0x0, 0x7, 0x8} {
		if id.known() {
			t.Errorf("SettingID(0x%x).known() = true, want false", uint16(id))
		}
		want := fmt.Sprintf("UNKNOWN_SETTING(0x%x)", uint16(id))
		if got := id.String(); got != want {
			t.Errorf("SettingID(0x%x).String() = %q, want %q", uint16(id), got, want)
		}
	}
	// Exhaustive over the 16-bit field: String is called on hostile input and
	// must never panic or return an empty label.
	implemented := settingIDSet()
	for v := range 1 << 16 {
		id := SettingID(v)
		if id.String() == "" {
			t.Fatalf("SettingID(0x%x).String() is empty", v)
		}
		if id.known() != implemented[id] {
			t.Fatalf("SettingID(0x%x).known() = %v, want %v", v, id.known(), implemented[id])
		}
	}
}

func TestProtocolConstants(t *testing.T) {
	// Every one of these is a number a hostile peer will probe the boundary of,
	// so each is asserted against the decimal value in RFC 9113 rather than the
	// shift expression that produced it.
	tests := []struct {
		got  int
		want int
		name string
	}{
		{HeaderLen, 9, "HeaderLen"},
		{MaxLength, 16777215, "MaxLength"},
		{DefaultMaxFrameSize, 16384, "DefaultMaxFrameSize"},
		{DefaultInitialWindowSize, 65535, "DefaultInitialWindowSize"},
		{MaxWindowSize, 2147483647, "MaxWindowSize"},
		{DefaultHeaderTableSize, 4096, "DefaultHeaderTableSize"},
		{streamIDMask, 2147483647, "streamIDMask"},
		{priorityLen, 5, "priorityLen"},
		{priorityUpdateFixedLen, 4, "priorityUpdateFixedLen"},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s = %d, want %d", tt.name, tt.got, tt.want)
		}
	}
	// DefaultMaxFrameSize is both the initial value and the minimum a peer may
	// advertise, and MaxLength is the ceiling, so the legal SETTINGS_MAX_FRAME_SIZE
	// range is exactly [DefaultMaxFrameSize, MaxLength] (§6.5.2).
	if DefaultMaxFrameSize > MaxLength {
		t.Error("the minimum legal max frame size exceeds the 24-bit length field")
	}
}
