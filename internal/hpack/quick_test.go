package hpack

import (
	"testing"
	"testing/quick"

	"zerodeps/zdh/internal/h2"
)

// TestRoundTripProperty checks, for random field lists, that decoding what
// was just encoded reproduces it exactly. testing/quick is the stdlib
// answer to a property-based test library: it generates the random inputs
// and shrinks nothing, but for a round-trip property that's all this needs.
//
// Both ends start with an empty dynamic table and process the same list in
// the same order, exactly as two directions of a real connection would, so
// any indexed references the encoder emits resolve to the same entries on
// the decoding side.
func TestRoundTripProperty(t *testing.T) {
	prop := func(fields []h2.Field) bool {
		enc := New()
		block := enc.Encode(fields)

		dec := New()
		got, err := dec.Decode(block)
		if err != nil {
			t.Logf("decode error for %+v: %v", fields, err)
			return false
		}
		if len(got) != len(fields) {
			return false
		}
		for i := range fields {
			if got[i] != fields[i] {
				return false
			}
		}
		return true
	}

	cfg := &quick.Config{MaxCount: 2000}
	if err := quick.Check(prop, cfg); err != nil {
		t.Fatal(err)
	}
}
