package response

import (
	"errors"
	"strings"
	"testing"

	"zerodeps/zdh/internal/h2"
)

// field is a shorthand for a regular field line, to keep the tables below readable.
func field(name, value string) h2.Field { return h2.Field{Name: name, Value: value} }

// TestEveryRuleAResponseFieldListIsHeldTo is §8.2 and §8.3, one row per rule.
//
// want is a substring of the message, and the substring is always the RFC citation
// plus whatever distinguishes the rule from the others citing the same section. That
// is deliberate: a table asserting only "some error" cannot tell a rule that fired
// from a different rule that fired instead, and these rules overlap enough that a
// list refused for the wrong reason is a real outcome. An empty want means the list
// must be accepted.
func TestEveryRuleAResponseFieldListIsHeldTo(t *testing.T) {
	const (
		header  = sectionHeader
		trailer = sectionTrailer
	)
	for _, tc := range []struct {
		name   string
		kind   section
		fields []h2.Field
		want   string
	}{
		// --- §8.3.2: the one pseudo-header field a response has ---
		{"a header section with only a status", header, []h2.Field{status("200")}, ""},
		{"a header section with no status", header, []h2.Field{field("server", "zdh")},
			`no ":status" pseudo-header field (RFC 9113 §8.3.2)`},
		{"an empty header section", header, nil,
			`no ":status" pseudo-header field (RFC 9113 §8.3.2)`},
		{"a repeated status", header, []h2.Field{status("200"), status("200")},
			`a repeated ":status" pseudo-header field (RFC 9113 §8.3)`},
		{"a request pseudo-header field", header, []h2.Field{status("200"), field(":path", "/")},
			`undefined pseudo-header field ":path"`},
		{"an invented pseudo-header field", header, []h2.Field{status("200"), field(":zdh", "1")},
			`undefined pseudo-header field ":zdh"`},
		{"a bare colon as a name", header, []h2.Field{status("200"), field(":", "1")},
			`undefined pseudo-header field ":"`},

		// --- §8.3: ordering, and the trailer section ---
		{"a status after a regular field", header, []h2.Field{field("server", "zdh"), status("200")},
			`after a regular field line (RFC 9113 §8.3)`},
		{"a status before its regular fields", header, []h2.Field{status("200"), field("server", "zdh")}, ""},
		{"a trailer section", trailer, []h2.Field{field("x-checksum", "beef")}, ""},
		{"an empty trailer section", trailer, nil, ""},
		{"a status in a trailer section", trailer, []h2.Field{status("200")},
			`the pseudo-header field ":status" in a trailer section (RFC 9113 §8.3)`},
		{"a request pseudo-header field in a trailer section", trailer, []h2.Field{field(":method", "GET")},
			`the pseudo-header field ":method" in a trailer section (RFC 9113 §8.3)`},

		// --- §8.2: field names ---
		{"an empty name", header, []h2.Field{status("200"), field("", "v")},
			`a field line with an empty name (RFC 9110 §5.1)`},
		{"a capitalised name", header, []h2.Field{status("200"), field("Server", "zdh")},
			`field name "Server" is not lowercase (RFC 9113 §8.2)`},
		{"a fully uppercase name", header, []h2.Field{status("200"), field("ETAG", "\"x\"")},
			`is not lowercase (RFC 9113 §8.2)`},
		{"a capitalised connection-specific name", header, []h2.Field{status("200"), field("Connection", "close")},
			// Caught as a case error rather than as §8.2.2's ban, which is why the ban
			// list below needs no case folding: nothing reaches it that is not already
			// lowercase.
			`is not lowercase (RFC 9113 §8.2)`},
		{"a space in a name", header, []h2.Field{status("200"), field("x note", "v")},
			`field name "x note" contains the octet 0x20`},
		{"a tab in a name", header, []h2.Field{status("200"), field("x\tnote", "v")},
			`contains the octet 0x09`},
		{"a CR in a name", header, []h2.Field{status("200"), field("x\rnote", "v")},
			`contains the octet 0x0d`},
		{"a NUL in a name", header, []h2.Field{status("200"), field("x\x00note", "v")},
			`contains the octet 0x00`},
		{"a DEL in a name", header, []h2.Field{status("200"), field("x\x7fnote", "v")},
			`contains the octet 0x7f`},
		{"a high octet in a name", header, []h2.Field{status("200"), field("x\xffnote", "v")},
			`contains the octet 0xff`},
		{"a colon inside a name", header, []h2.Field{status("200"), field("x:note", "v")},
			`field name "x:note" contains a colon (RFC 9113 §8.2.1)`},
		{"a trailing colon on a name", header, []h2.Field{status("200"), field("note:", "v")},
			`contains a colon (RFC 9113 §8.2.1)`},
		{"a double colon on a pseudo-header field", header, []h2.Field{field("::status", "200")},
			// §8.2.1's exception is for names that start "with a single colon", so this
			// is not a pseudo-header field and falls under the ban like any other name.
			`field name "::status" contains a colon (RFC 9113 §8.2.1)`},
		{"the punctuation a token may contain", header,
			[]h2.Field{status("200"), field("x-a_b.c~d!#$%&'*+^`|9", "v")}, ""},

		// --- §8.2.1: field values ---
		{"a NUL in a value", header, []h2.Field{status("200"), field("x-note", "a\x00b")},
			`the value of field "x-note" contains the octet 0x00 (RFC 9113 §8.2.1)`},
		{"an LF in a value", header, []h2.Field{status("200"), field("x-note", "a\nb")},
			`contains the octet 0x0a (RFC 9113 §8.2.1)`},
		{"a CR in a value", header, []h2.Field{status("200"), field("x-note", "a\rb")},
			`contains the octet 0x0d (RFC 9113 §8.2.1)`},
		{"a CRLF injection in a value", header,
			[]h2.Field{status("200"), field("location", "/a\r\nx-injected: 1")},
			`contains the octet 0x0d (RFC 9113 §8.2.1)`},
		{"a leading space in a value", header, []h2.Field{status("200"), field("x-note", " v")},
			`the value of field "x-note" starts with whitespace (RFC 9113 §8.2.1)`},
		{"a leading tab in a value", header, []h2.Field{status("200"), field("x-note", "\tv")},
			`starts with whitespace (RFC 9113 §8.2.1)`},
		{"a trailing space in a value", header, []h2.Field{status("200"), field("x-note", "v ")},
			`the value of field "x-note" ends with whitespace (RFC 9113 §8.2.1)`},
		{"a trailing tab in a value", header, []h2.Field{status("200"), field("x-note", "v\t")},
			`ends with whitespace (RFC 9113 §8.2.1)`},
		{"a value of one space", header, []h2.Field{status("200"), field("x-note", " ")},
			// Both ends at once. The leading check is the one that fires, and either
			// answer would be true — what matters is that a value with no non-whitespace
			// octet in it is not mistaken for an empty one.
			`starts with whitespace (RFC 9113 §8.2.1)`},
		{"an empty value", header, []h2.Field{status("200"), field("x-note", "")},
			// Legal: §8.2.1's rule is about the first and last octet of a value, and an
			// empty value has neither. This is the row that keeps the length guard in
			// front of those two index expressions.
			""},
		{"internal whitespace in a value", header,
			[]h2.Field{status("200"), field("x-note", "a b\tc")}, ""},
		{"a DEL in a value", header, []h2.Field{status("200"), field("x-note", "a\x7fb")},
			// Accepted, deliberately. §8.2.1's MUST list for values is NUL, LF, CR and
			// the whitespace rule, and this validator implements that list rather than
			// RFC 9110 §5.5's stricter field-vchar grammar — the same list
			// internal/request holds a peer to, where being stricter than the RFC would
			// mean rejecting traffic the RFC allows.
			""},
		{"a high octet in a value", header, []h2.Field{status("200"), field("x-note", "caf\xc3\xa9")}, ""},

		// --- §8.2.2: connection-specific fields ---
		{"connection", header, []h2.Field{status("200"), field("connection", "close")},
			`the connection-specific header field "connection" (RFC 9113 §8.2.2)`},
		{"proxy-connection", header, []h2.Field{status("200"), field("proxy-connection", "close")},
			`"proxy-connection" (RFC 9113 §8.2.2)`},
		{"keep-alive", header, []h2.Field{status("200"), field("keep-alive", "timeout=5")},
			`"keep-alive" (RFC 9113 §8.2.2)`},
		{"transfer-encoding", header, []h2.Field{status("200"), field("transfer-encoding", "chunked")},
			`"transfer-encoding" (RFC 9113 §8.2.2)`},
		{"upgrade", header, []h2.Field{status("200"), field("upgrade", "websocket")},
			`"upgrade" (RFC 9113 §8.2.2)`},
		{"te", header, []h2.Field{status("200"), field("te", "trailers")},
			// The one that differs from the request side. §8.2.2's exception reads "TE
			// MAY be present in an HTTP/2 request", so a response carrying TE — even
			// with the value "trailers", which is the only value that exception allows —
			// is not covered by it.
			`the connection-specific header field "te" (RFC 9113 §8.2.2)`},
		{"a connection-specific field in a trailer section", trailer,
			[]h2.Field{field("transfer-encoding", "chunked")},
			`"transfer-encoding" (RFC 9113 §8.2.2)`},
		{"trailer", header, []h2.Field{status("200"), field("trailer", "grpc-status")},
			// Legal, and it is the field a response actually uses to announce a trailer
			// section (§6.6.2 of RFC 9110). Banning it along with the hop-by-hop fields
			// would make trailers unannounceable.
			""},
		{"names that only look connection-specific", header, []h2.Field{
			status("200"),
			field("tea", "earl grey"),
			field("connection-id", "7"),
			field("keep-alive-hint", "5"),
			field("content-encoding", "gzip"),
		}, ""},

		// --- §8.3.2 and RFC 9110 §15: the status code ---
		{"a two-digit status", header, []h2.Field{status("20")},
			`a ":status" of 2 octets, want three digits (RFC 9113 §8.3.2)`},
		{"a four-digit status", header, []h2.Field{status("2000")},
			`a ":status" of 4 octets, want three digits (RFC 9113 §8.3.2)`},
		{"an empty status", header, []h2.Field{status("")},
			`a ":status" of 0 octets, want three digits (RFC 9113 §8.3.2)`},
		{"an HTTP/1.1 status line", header, []h2.Field{status("200 OK")},
			// The mistake a handler makes, and the reason the length is checked before
			// the digits: "6 octets" says what is wrong with it, where "contains the
			// octet 0x20" would send its author looking for a whitespace rule.
			`a ":status" of 6 octets, want three digits (RFC 9113 §8.3.2)`},
		{"a status with a letter in it", header, []h2.Field{status("2x0")},
			`a ":status" containing the octet 0x78, want three digits (RFC 9113 §8.3.2)`},
		{"a status with a space in it", header, []h2.Field{status("2 0")},
			`containing the octet 0x20, want three digits`},
		{"a status of class 0", header, []h2.Field{status("099")},
			`a ":status" of class 0xx; RFC 9110 §15 defines 1xx through 5xx`},
		{"a status of class 6", header, []h2.Field{status("600")},
			`a ":status" of class 6xx; RFC 9110 §15 defines 1xx through 5xx`},
		{"a status of class 9", header, []h2.Field{status("999")},
			`of class 9xx; RFC 9110 §15 defines 1xx through 5xx`},

		// --- a response a handler would actually build ---
		{"a full header section", header, []h2.Field{
			status("200"),
			field("content-type", "text/html; charset=utf-8"),
			field("content-length", "1274"),
			field("date", "Sat, 29 Aug 2026 12:00:00 GMT"),
			field("etag", `W/"1a2b3c"`),
			field("cache-control", "max-age=0, must-revalidate"),
			field("set-cookie", "s=abc; Path=/; HttpOnly; SameSite=Lax"),
			field("strict-transport-security", "max-age=31536000"),
			field("trailer", "server-timing"),
			field("vary", ""),
		}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkSection(tc.kind, tc.fields)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("checkSection: %v, want it accepted", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("checkSection accepted the list, want a %v mentioning %q",
					ErrMalformedResponse, tc.want)
			}
			if !errors.Is(err, ErrMalformedResponse) {
				t.Errorf("checkSection: %v, want it to wrap %v", err, ErrMalformedResponse)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("checkSection: %v\nwant a message containing %q", err, tc.want)
			}
		})
	}
}

func TestEveryStatusClassTheProtocolDefinesIsAccepted(t *testing.T) {
	// The boundaries of the class check, from both ends of each class. A guard written
	// as a range is a guard that can be written one off in two directions, and the
	// cost of getting it wrong is a server that cannot send a 100 or a 599.
	for _, code := range []string{
		"100", "101", "199",
		"200", "204", "299",
		"300", "304", "399",
		"400", "404", "499",
		"500", "503", "599",
	} {
		t.Run(code, func(t *testing.T) {
			if err := checkSection(sectionHeader, []h2.Field{status(code)}); err != nil {
				t.Errorf("checkSection with a status of %s: %v", code, err)
			}
		})
	}
}

func TestNoFieldValueEverReachesAnErrorMessage(t *testing.T) {
	// A response's field values are the secrets on a connection: a Set-Cookie, a
	// signed URL, an authorization challenge, a token a handler has just minted. The
	// errors from this package end up in a server log, which is a place with different
	// readers and a longer life than the response was meant to have.
	//
	// So no message here interpolates a value, and this is the test that keeps it that
	// way. Every row is a list that is refused *because of* its value, which is exactly
	// where a message would be tempted to quote one to be helpful.
	const secret = "s3cr3t-bearer-token"

	for _, tc := range []struct {
		name   string
		kind   section
		fields []h2.Field
	}{
		{"a CRLF in a value", sectionHeader,
			[]h2.Field{status("200"), field("set-cookie", secret+"\r\nx-injected: 1")}},
		{"a NUL in a value", sectionHeader,
			[]h2.Field{status("200"), field("authorization", secret+"\x00")}},
		{"leading whitespace in a value", sectionHeader,
			[]h2.Field{status("200"), field("location", " https://example.test/?sig="+secret)}},
		{"trailing whitespace in a value", sectionHeader,
			[]h2.Field{status("200"), field("www-authenticate", "Bearer realm="+secret+" ")}},
		{"a connection-specific field carrying one", sectionHeader,
			[]h2.Field{status("200"), field("connection", secret)}},
		{"a value in a trailer section", sectionTrailer,
			[]h2.Field{field("x-signature", secret+"\n")}},
		{"a bad status carrying one", sectionHeader, []h2.Field{status(secret)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkSection(tc.kind, tc.fields)
			if err == nil {
				t.Fatalf("checkSection accepted the list, want it refused")
			}
			if strings.Contains(err.Error(), secret) {
				t.Errorf("the error quotes a field value: %v", err)
			}
		})
	}
}

func TestNoFieldNameOrValueReachesTheHeaderListSizeError(t *testing.T) {
	// The same rule for the other refusal this package can produce. A list too large
	// to send is a whole header section, so a message that named its fields would put
	// the entire section in a log line — every cookie and every token in it.
	const secret = "s3cr3t-bearer-token"

	enc, _, _ := newEncoder()
	enc.SetMaxHeaderListSize(1)

	err := enc.WriteHeaders(1, []h2.Field{status("200"), field("set-cookie", secret)}, true)
	if !errors.Is(err, ErrHeaderListTooLarge) {
		t.Fatalf("WriteHeaders: %v, want %v", err, ErrHeaderListTooLarge)
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "set-cookie") {
		t.Errorf("the error quotes the field list: %v", err)
	}
}

func TestASensitiveFieldIsRefusedTheSameWayAsAnyOther(t *testing.T) {
	// h2.Field.Sensitive is a hint to the HPACK encoder about indexing (§7.1.3 of RFC
	// 7541), not a validity flag. Nothing in this validator reads it, which is what
	// makes the no-values rule hold by construction rather than by remembering to
	// check: there is no path on which a value is quoted, so there is no path on which
	// a sensitive one is.
	sensitive := h2.Field{Name: "set-cookie", Value: "s=abc\r\nx: y", Sensitive: true}
	plain := h2.Field{Name: "set-cookie", Value: "s=abc\r\nx: y"}

	got := checkSection(sectionHeader, []h2.Field{status("200"), sensitive})
	want := checkSection(sectionHeader, []h2.Field{status("200"), plain})
	if got == nil || want == nil {
		t.Fatalf("checkSection accepted a CRLF in a value: sensitive=%v plain=%v", got, want)
	}
	if got.Error() != want.Error() {
		t.Errorf("a sensitive field is reported as %v, a plain one as %v; want the same", got, want)
	}
}

func TestTheFirstBrokenFieldIsTheOneReported(t *testing.T) {
	// checkSection returns on the first failure rather than collecting them, and the
	// list is walked in order. Both halves matter: a caller gets one actionable
	// diagnosis, and it is about the earliest field, which is the one a handler
	// building a list top to bottom will recognise.
	err := checkSection(sectionHeader, []h2.Field{
		status("200"),
		field("x-first", "a\rb"),
		field("X-Second", "b"),
		field("connection", "close"),
	})
	if err == nil {
		t.Fatalf("checkSection accepted a list with three broken fields")
	}
	if got := err.Error(); !strings.Contains(got, "x-first") {
		t.Errorf("checkSection reported %v, want the first broken field", err)
	}
}
