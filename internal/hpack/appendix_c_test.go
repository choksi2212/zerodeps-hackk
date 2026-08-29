package hpack

import (
	"encoding/hex"
	"testing"

	"zerodeps/zdh/internal/h2"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func assertFields(t *testing.T, got []h2.Field, want []h2.Field) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d fields, want %d\ngot:  %+v\nwant: %+v", len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("field %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

// C.1 — integer representation examples.

func TestAppendixC1Integers(t *testing.T) {
	cases := []struct {
		prefix uint8
		value  uint64
		hex    string
	}{
		{5, 10, "0a"},
		{5, 1337, "1f9a0a"},
		{8, 42, "2a"},
	}
	for _, c := range cases {
		enc := appendInt(nil, 0, c.prefix, c.value)
		if hex.EncodeToString(enc) != c.hex {
			t.Errorf("appendInt(%d, %d) = %x, want %s", c.prefix, c.value, enc, c.hex)
		}
		got, n, err := decodeInt(mustHex(t, c.hex), c.prefix)
		if err != nil {
			t.Fatalf("decodeInt(%s): %v", c.hex, err)
		}
		if got != c.value || n != len(enc) {
			t.Errorf("decodeInt(%s) = %d, %d bytes; want %d, %d bytes", c.hex, got, n, c.value, len(enc))
		}
	}
}

// C.2 — header field representation examples, independent of each other
// (each decoded with a fresh codec).

func TestAppendixC2Literals(t *testing.T) {
	cases := []struct {
		name string
		hex  string
		want h2.Field
	}{
		{"with indexing", "400a637573746f6d2d6b65790d637573746f6d2d686561646572",
			h2.Field{Name: "custom-key", Value: "custom-header"}},
		{"without indexing", "040c2f73616d706c652f70617468",
			h2.Field{Name: ":path", Value: "/sample/path"}},
		{"never indexed", "100870617373776f726406736563726574",
			h2.Field{Name: "password", Value: "secret", Sensitive: true}},
		{"indexed", "82",
			h2.Field{Name: ":method", Value: "GET"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			codec := New()
			got, err := codec.Decode(mustHex(t, c.hex))
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			assertFields(t, got, []h2.Field{c.want})
		})
	}
}

// C.3 — request sequence without Huffman coding. This and C.5 are the two
// vectors that matter most: they walk the dynamic table across several
// requests, so they are the strongest evidence the table's FIFO order and
// +32 accounting are both right.

func TestAppendixC3RequestsWithoutHuffman(t *testing.T) {
	codec := New()

	// Request 1
	got, err := codec.Decode(mustHex(t, "828684410f7777772e6578616d706c652e636f6d"))
	if err != nil {
		t.Fatalf("request 1: %v", err)
	}
	assertFields(t, got, []h2.Field{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "http"},
		{Name: ":path", Value: "/"},
		{Name: ":authority", Value: "www.example.com"},
	})
	if len(codec.dyn.entries) != 1 || codec.dyn.size != 57 {
		t.Fatalf("after request 1: %d entries, size %d; want 1 entry, size 57",
			len(codec.dyn.entries), codec.dyn.size)
	}

	// Request 2
	got, err = codec.Decode(mustHex(t, "828684be58086e6f2d6361636865"))
	if err != nil {
		t.Fatalf("request 2: %v", err)
	}
	assertFields(t, got, []h2.Field{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "http"},
		{Name: ":path", Value: "/"},
		{Name: ":authority", Value: "www.example.com"},
		{Name: "cache-control", Value: "no-cache"},
	})
	if len(codec.dyn.entries) != 2 || codec.dyn.size != 110 {
		t.Fatalf("after request 2: %d entries, size %d; want 2 entries, size 110",
			len(codec.dyn.entries), codec.dyn.size)
	}
	if codec.dyn.entries[0] != (h2.Field{Name: "cache-control", Value: "no-cache"}) {
		t.Fatalf("most recent entry = %+v, want cache-control: no-cache", codec.dyn.entries[0])
	}

	// Request 3
	got, err = codec.Decode(mustHex(t, "828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565"))
	if err != nil {
		t.Fatalf("request 3: %v", err)
	}
	assertFields(t, got, []h2.Field{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/index.html"},
		{Name: ":authority", Value: "www.example.com"},
		{Name: "custom-key", Value: "custom-value"},
	})
	if len(codec.dyn.entries) != 3 || codec.dyn.size != 164 {
		t.Fatalf("after request 3: %d entries, size %d; want 3 entries, size 164",
			len(codec.dyn.entries), codec.dyn.size)
	}
}

// C.4 — the same three requests, Huffman-coded. Decoding must produce the
// identical header lists as C.3.

func TestAppendixC4RequestsWithHuffman(t *testing.T) {
	codec := New()

	blocks := []string{
		"828684418cf1e3c2e5f23a6ba0ab90f4ff",
		"828684be5886a8eb10649cbf",
		"828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf",
	}
	want := [][]h2.Field{
		{
			{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "http"},
			{Name: ":path", Value: "/"}, {Name: ":authority", Value: "www.example.com"},
		},
		{
			{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "http"},
			{Name: ":path", Value: "/"}, {Name: ":authority", Value: "www.example.com"},
			{Name: "cache-control", Value: "no-cache"},
		},
		{
			{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"},
			{Name: ":path", Value: "/index.html"}, {Name: ":authority", Value: "www.example.com"},
			{Name: "custom-key", Value: "custom-value"},
		},
	}
	for i, block := range blocks {
		got, err := codec.Decode(mustHex(t, block))
		if err != nil {
			t.Fatalf("request %d: %v", i+1, err)
		}
		assertFields(t, got, want[i])
	}
	if len(codec.dyn.entries) != 3 || codec.dyn.size != 164 {
		t.Fatalf("final table: %d entries, size %d; want 3, 164", len(codec.dyn.entries), codec.dyn.size)
	}
}

// C.5 — response sequence without Huffman coding, SETTINGS_HEADER_TABLE_SIZE
// = 256, which forces eviction. This is the vector that most exercises the
// dynamic table: eviction order and the +32 accounting both have to be
// exactly right for the table sizes below to match the RFC.

func TestAppendixC5ResponsesWithoutHuffman(t *testing.T) {
	codec := New()
	codec.SetMaxDynamicTableSize(256)

	// Response 1
	got, err := codec.Decode(mustHex(t,
		"4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d"))
	if err != nil {
		t.Fatalf("response 1: %v", err)
	}
	assertFields(t, got, []h2.Field{
		{Name: ":status", Value: "302"},
		{Name: "cache-control", Value: "private"},
		{Name: "date", Value: "Mon, 21 Oct 2013 20:13:21 GMT"},
		{Name: "location", Value: "https://www.example.com"},
	})
	if len(codec.dyn.entries) != 4 || codec.dyn.size != 222 {
		t.Fatalf("after response 1: %d entries, size %d; want 4, 222", len(codec.dyn.entries), codec.dyn.size)
	}

	// Response 2 — evicts :status: 302
	got, err = codec.Decode(mustHex(t, "4803333037c1c0bf"))
	if err != nil {
		t.Fatalf("response 2: %v", err)
	}
	assertFields(t, got, []h2.Field{
		{Name: ":status", Value: "307"},
		{Name: "cache-control", Value: "private"},
		{Name: "date", Value: "Mon, 21 Oct 2013 20:13:21 GMT"},
		{Name: "location", Value: "https://www.example.com"},
	})
	if len(codec.dyn.entries) != 4 || codec.dyn.size != 222 {
		t.Fatalf("after response 2: %d entries, size %d; want 4, 222", len(codec.dyn.entries), codec.dyn.size)
	}
	if codec.dyn.entries[0] != (h2.Field{Name: ":status", Value: "307"}) {
		t.Fatalf("most recent entry = %+v, want :status: 307", codec.dyn.entries[0])
	}

	// Response 3 — evicts cache-control, date(21), location, :status:307
	got, err = codec.Decode(mustHex(t,
		"88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d54c05a04677a69707738666f6f3d4153444a4b48514b425a584f5157454f50495541585157454f49553b206d61782d6167653d333630303b2076657273696f6e3d31"))
	if err != nil {
		t.Fatalf("response 3: %v", err)
	}
	assertFields(t, got, []h2.Field{
		{Name: ":status", Value: "200"},
		{Name: "cache-control", Value: "private"},
		{Name: "date", Value: "Mon, 21 Oct 2013 20:13:22 GMT"},
		{Name: "location", Value: "https://www.example.com"},
		{Name: "content-encoding", Value: "gzip"},
		{Name: "set-cookie", Value: "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"},
	})
	if len(codec.dyn.entries) != 3 || codec.dyn.size != 215 {
		t.Fatalf("after response 3: %d entries, size %d; want 3, 215", len(codec.dyn.entries), codec.dyn.size)
	}
	wantFinal := []h2.Field{
		{Name: "set-cookie", Value: "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"},
		{Name: "content-encoding", Value: "gzip"},
		{Name: "date", Value: "Mon, 21 Oct 2013 20:13:22 GMT"},
	}
	assertFields(t, codec.dyn.entries, wantFinal)
}

// C.6 — same three responses as C.5, Huffman-coded. The eviction mechanism
// uses the length of the *decoded* literal, so the same evictions occur.

func TestAppendixC6ResponsesWithHuffman(t *testing.T) {
	codec := New()
	codec.SetMaxDynamicTableSize(256)

	blocks := []string{
		"488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3",
		"4883640effc1c0bf",
		"88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007",
	}
	want := [][]h2.Field{
		{
			{Name: ":status", Value: "302"}, {Name: "cache-control", Value: "private"},
			{Name: "date", Value: "Mon, 21 Oct 2013 20:13:21 GMT"},
			{Name: "location", Value: "https://www.example.com"},
		},
		{
			{Name: ":status", Value: "307"}, {Name: "cache-control", Value: "private"},
			{Name: "date", Value: "Mon, 21 Oct 2013 20:13:21 GMT"},
			{Name: "location", Value: "https://www.example.com"},
		},
		{
			{Name: ":status", Value: "200"}, {Name: "cache-control", Value: "private"},
			{Name: "date", Value: "Mon, 21 Oct 2013 20:13:22 GMT"},
			{Name: "location", Value: "https://www.example.com"},
			{Name: "content-encoding", Value: "gzip"},
			{Name: "set-cookie", Value: "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"},
		},
	}
	for i, block := range blocks {
		got, err := codec.Decode(mustHex(t, block))
		if err != nil {
			t.Fatalf("response %d: %v", i+1, err)
		}
		assertFields(t, got, want[i])
	}
	if len(codec.dyn.entries) != 3 || codec.dyn.size != 215 {
		t.Fatalf("final table: %d entries, size %d; want 3, 215", len(codec.dyn.entries), codec.dyn.size)
	}
}
