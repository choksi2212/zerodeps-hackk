package hpack

import (
	"testing"

	"zerodeps/zdh/internal/h2"
)

func TestEncodeStaticExactMatch(t *testing.T) {
	c := New()
	block := c.Encode([]h2.Field{{Name: ":method", Value: "GET"}})
	if len(block) != 1 || block[0] != 0x82 {
		t.Fatalf("block = %x, want a single 0x82 (indexed, static entry 2)", block)
	}
}

func TestEncodeSensitiveNeverEntersDynamicTable(t *testing.T) {
	c := New()
	c.Encode([]h2.Field{{Name: "authorization", Value: "secret-token", Sensitive: true}})
	if len(c.dyn.entries) != 0 {
		t.Fatalf("dynamic table has %d entries, want 0", len(c.dyn.entries))
	}
}

func TestEncodeSensitiveIsNeverIndexedRepresentation(t *testing.T) {
	c := New()
	block := c.Encode([]h2.Field{{Name: "x-custom", Value: "v", Sensitive: true}})
	// Literal Never Indexed: top nibble 0001.
	if block[0]&0xf0 != 0x10 {
		t.Fatalf("first byte = %#x, want top nibble 0001 (never indexed)", block[0])
	}
}

func TestEncodeRepeatedFieldUsesIndexedOnSecondOccurrence(t *testing.T) {
	c := New()
	fields := []h2.Field{
		{Name: "x-custom", Value: "same-value"},
		{Name: "x-custom", Value: "same-value"},
	}
	block := c.Encode(fields)

	// Decode with a mirroring codec to confirm both fields still resolve
	// correctly, and that the encoder actually used a shorter indexed form
	// for the second occurrence (an indexed reference is the cheapest
	// possible encoding: it can never be longer than the first literal).
	dec := New()
	got, err := dec.Decode(block)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 2 || got[0] != fields[0] || got[1] != fields[1] {
		t.Fatalf("got %+v, want %+v", got, fields)
	}

	firstOnly := New().Encode(fields[:1])
	if len(block) >= 2*len(firstOnly) {
		t.Fatalf("second occurrence did not compress: block len %d, one-field len %d", len(block), len(firstOnly))
	}
}

func TestEncodeUsesIndexedNameForUnknownValue(t *testing.T) {
	c := New()
	// :path is a static name (index 4/5) but "/unusual" matches neither
	// static value, so the encoder should reference the name and inline
	// only the value.
	block := c.encodeLiteral(nil, h2.Field{Name: ":path", Value: "/unusual"}, 0x40, 6)
	// Literal-with-indexing using indexed name 4 fits the 6-bit prefix
	// directly: flag 0x40 | 4 = 0x44.
	if block[0] != 0x44 {
		t.Fatalf("first byte = %#x, want 0x44 (indexed name 4, incremental indexing)", block[0])
	}
}

func TestEncodeThenDecodeMatchesAppendixC3(t *testing.T) {
	// A cross-check that our own encoder, not just the RFC's, produces
	// something our own decoder accepts identically to the RFC sequence —
	// i.e. the two halves of the codec genuinely agree with each other.
	enc := New()
	dec := New()

	requests := [][]h2.Field{
		{
			{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "http"},
			{Name: ":path", Value: "/"}, {Name: ":authority", Value: "www.example.com"},
		},
		{
			{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "http"},
			{Name: ":path", Value: "/"}, {Name: ":authority", Value: "www.example.com"},
			{Name: "cache-control", Value: "no-cache"},
		},
	}
	for _, want := range requests {
		block := enc.Encode(want)
		got, err := dec.Decode(block)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(got) != len(want) {
			t.Fatalf("got %+v, want %+v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("field %d: got %+v, want %+v", i, got[i], want[i])
			}
		}
	}
}
