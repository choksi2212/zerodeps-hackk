// Package frame reads and writes HTTP/2 frames on a byte stream, per RFC 9113
// §4 and §6.
//
// The package is deliberately narrow. It validates everything that can be
// decided from a single frame plus the reader's own header-block continuity
// state: lengths, flags, stream-id legality, payload structure, and field
// ranges. It does not know about streams, flow-control windows or HTTP
// semantics, so rules that need that state — a RST_STREAM on an idle stream, a
// WINDOW_UPDATE overflowing a window — are enforced by the layers that own it.
//
// Errors are h2.ConnError or h2.StreamError, never bare strings, because the
// caller's correct response differs completely between the two.
package frame

import (
	"fmt"

	"zerodeps/zdh/internal/h2"
)

// FrameType is the 8-bit frame type field (RFC 9113 §11.2).
type FrameType uint8

// The frame types this server implements: the ten of RFC 9113 §11.2, and the one
// RFC 9218 registers. A type this package does not implement must be discarded
// silently rather than rejected, which is handled in Reader.ReadFrame.
const (
	TypeData         FrameType = 0x0
	TypeHeaders      FrameType = 0x1
	TypePriority     FrameType = 0x2
	TypeRSTStream    FrameType = 0x3
	TypeSettings     FrameType = 0x4
	TypePushPromise  FrameType = 0x5
	TypePing         FrameType = 0x6
	TypeGoAway       FrameType = 0x7
	TypeWindowUpdate FrameType = 0x8
	TypeContinuation FrameType = 0x9

	// TypePriorityUpdate is PRIORITY_UPDATE (RFC 9218 §7.1), the frame that
	// carries an extensible-priorities signal. It is not in RFC 9113's own
	// registry, and the eight-bit space between it and CONTINUATION holds types
	// this server does not implement — so this is where the assigned range stops
	// being a range, and why the two tables below are indexed rather than
	// listed.
	TypePriorityUpdate FrameType = 0x10

	// maxDefinedType is the highest type this package implements. Anything above
	// it is unknown and must be discarded — and so is anything inside the hole
	// beneath it, which is why known does not compare against this.
	maxDefinedType = TypePriorityUpdate
)

// frameTypeNames is indexed by frame type, so the unimplemented types in the
// middle read as the empty string. That is the sentinel String and known both
// test: a keyed literal cannot drift out of step with the constants above the way
// a positional one could, where inserting a type would silently rename every type
// after it.
var frameTypeNames = [...]string{
	TypeData:           "DATA",
	TypeHeaders:        "HEADERS",
	TypePriority:       "PRIORITY",
	TypeRSTStream:      "RST_STREAM",
	TypeSettings:       "SETTINGS",
	TypePushPromise:    "PUSH_PROMISE",
	TypePing:           "PING",
	TypeGoAway:         "GOAWAY",
	TypeWindowUpdate:   "WINDOW_UPDATE",
	TypeContinuation:   "CONTINUATION",
	TypePriorityUpdate: "PRIORITY_UPDATE",
}

func (t FrameType) String() string {
	if int(t) < len(frameTypeNames) && frameTypeNames[t] != "" {
		return frameTypeNames[t]
	}
	return fmt.Sprintf("UNKNOWN_FRAME_TYPE(0x%x)", uint8(t))
}

// known reports whether this package has a parser for the type.
//
// It asks the parser table rather than comparing against maxDefinedType, because
// the range has a hole in it: 0xa through 0xf index inside the table and are not
// implemented, and a range check would call a nil function for them. Asking the
// table makes "known" and "parseable" the same question by construction, and
// TestFrameTypeTablesAgree holds the name table to the same shape.
func (t FrameType) known() bool { return int(t) < len(parsers) && parsers[t] != nil }

// Flags is the 8-bit flags field. The meaning of a bit depends on the frame
// type, and the same bit means different things in different frames: 0x1 is
// END_STREAM on DATA and HEADERS but ACK on SETTINGS and PING.
//
// Frame structs in this package expose named booleans instead of raw flag bits
// so that a nonsensical combination — END_STREAM on a SETTINGS frame — cannot
// be expressed at all.
type Flags uint8

const (
	// FlagEndStream is 0x1 on DATA and HEADERS.
	FlagEndStream Flags = 0x1
	// FlagAck is 0x1 on SETTINGS and PING. Same bit as FlagEndStream.
	FlagAck Flags = 0x1
	// FlagEndHeaders is 0x4 on HEADERS, PUSH_PROMISE and CONTINUATION.
	FlagEndHeaders Flags = 0x4
	// FlagPadded is 0x8 on DATA, HEADERS and PUSH_PROMISE.
	FlagPadded Flags = 0x8
	// FlagPriority is 0x20 on HEADERS.
	FlagPriority Flags = 0x20
)

// has reports whether every bit in f is set.
func (fl Flags) has(f Flags) bool { return fl&f == f }

// set returns fl with f set when cond holds.
func (fl Flags) set(f Flags, cond bool) Flags {
	if cond {
		return fl | f
	}
	return fl
}

// SettingID is a 16-bit SETTINGS parameter identifier (RFC 9113 §11.3).
type SettingID uint16

const (
	SettingHeaderTableSize      SettingID = 0x1
	SettingEnablePush           SettingID = 0x2
	SettingMaxConcurrentStreams SettingID = 0x3
	SettingInitialWindowSize    SettingID = 0x4
	SettingMaxFrameSize         SettingID = 0x5
	SettingMaxHeaderListSize    SettingID = 0x6

	// SettingNoRFC7540Priorities is SETTINGS_NO_RFC7540_PRIORITIES (RFC 9218
	// §2.1): the parameter by which an endpoint says it is not using the
	// priority scheme RFC 9113 §5.3 deprecated. The identifiers between it and
	// SETTINGS_MAX_HEADER_LIST_SIZE belong to extensions this server does not
	// implement, and an identifier it does not implement must be ignored rather
	// than rejected — so the gap is a gap in the name table, not an error.
	SettingNoRFC7540Priorities SettingID = 0x9
)

// settingNames is indexed by identifier, and an identifier this server does not
// implement — including 0x0, which is not assigned to anything — reads as the
// empty string. String and known both test for it, so neither has a special case
// for zero and neither can be fooled by the hole in the middle.
var settingNames = [...]string{
	SettingHeaderTableSize:      "SETTINGS_HEADER_TABLE_SIZE",
	SettingEnablePush:           "SETTINGS_ENABLE_PUSH",
	SettingMaxConcurrentStreams: "SETTINGS_MAX_CONCURRENT_STREAMS",
	SettingInitialWindowSize:    "SETTINGS_INITIAL_WINDOW_SIZE",
	SettingMaxFrameSize:         "SETTINGS_MAX_FRAME_SIZE",
	SettingMaxHeaderListSize:    "SETTINGS_MAX_HEADER_LIST_SIZE",
	SettingNoRFC7540Priorities:  "SETTINGS_NO_RFC7540_PRIORITIES",
}

func (id SettingID) String() string {
	if int(id) < len(settingNames) && settingNames[id] != "" {
		return settingNames[id]
	}
	return fmt.Sprintf("UNKNOWN_SETTING(0x%x)", uint16(id))
}

// known reports whether this server implements the identifier. One it does not
// must be ignored rather than rejected (RFC 9113 §6.5.2), so this is used when
// applying settings, not when parsing them.
func (id SettingID) known() bool {
	return int(id) < len(settingNames) && settingNames[id] != ""
}

// Protocol constants from RFC 9113 §6.5.2 and §11.3.
const (
	// HeaderLen is the fixed size of the frame header in octets (§4.1).
	HeaderLen = 9

	// MaxLength is the largest value the 24-bit length field can hold, and so
	// the ceiling on SETTINGS_MAX_FRAME_SIZE.
	MaxLength = 1<<24 - 1

	// DefaultMaxFrameSize is the initial SETTINGS_MAX_FRAME_SIZE, and also its
	// minimum legal value: a peer may not advertise less.
	DefaultMaxFrameSize = 1 << 14 // 16384

	// DefaultInitialWindowSize is the initial flow-control window for the
	// connection and for every new stream.
	DefaultInitialWindowSize = 1<<16 - 1 // 65535

	// MaxWindowSize is the largest legal flow-control window. Exceeding it is a
	// FLOW_CONTROL_ERROR.
	MaxWindowSize = 1<<31 - 1

	// DefaultHeaderTableSize is the initial SETTINGS_HEADER_TABLE_SIZE.
	DefaultHeaderTableSize = 4096

	// streamIDMask clears the reserved bit of a 32-bit stream identifier
	// field. The reserved bit must be ignored on receive and sent as zero
	// (§4.1); masking it is how "ignore" is implemented.
	streamIDMask = 1<<31 - 1

	// priorityLen is the size of the priority block: one exclusive bit plus a
	// 31-bit stream dependency, plus a one-octet weight (§6.3).
	priorityLen = 5
)

// Frame is one HTTP/2 frame.
//
// The set of implementations is closed: appendPayload is unexported, so no type
// outside this package can satisfy the interface. A reader can therefore switch
// on the concrete types and know the switch is exhaustive.
//
// The accessor is Stream rather than StreamID because the frame structs carry an
// exported StreamID field, and Go does not allow a field and a method to share a
// name. The field keeps the name from RFC 9113 §4.1, since that is what someone
// writing a frame literal will look for.
//
// Frames that are only ever sent on the connection — SETTINGS, PING, GOAWAY —
// have no StreamID field at all and return 0 here. A SETTINGS frame on a stream
// is not a mistake to be caught later; it cannot be constructed.
type Frame interface {
	// Type is the frame's wire type.
	Type() FrameType
	// Flags is the frame's wire flags, derived from the frame's own fields.
	Flags() Flags
	// Stream is the stream this frame belongs to; 0 means the connection.
	Stream() uint32
	// PayloadLen is the wire length of the payload, excluding the 9-octet
	// header.
	PayloadLen() uint32
	// appendPayload appends the wire payload to dst and returns the extended
	// slice.
	appendPayload(dst []byte) []byte
}

// connErrf builds a connection error: the caller sends GOAWAY and closes the
// connection (RFC 9113 §5.4.1).
//
// Every error message in this package names the RFC section that mandates it,
// so that a conformance failure can be traced back to the rule in one step.
func connErrf(code h2.ErrCode, format string, args ...any) error {
	return h2.ConnErrorf(code, format, args...)
}

// streamErrf builds a stream error: the caller sends RST_STREAM on that stream
// and keeps the connection serving (RFC 9113 §5.4.2).
func streamErrf(id uint32, code h2.ErrCode, format string, args ...any) error {
	return h2.StreamErrorf(id, code, format, args...)
}
