package hpack

import (
	"encoding/hex"
	"testing"
)

// FuzzHPACKDecode is the robustness proof for the decoder: on arbitrary
// bytes straight off a hostile network, Decode must either return fields or
// a COMPRESSION_ERROR. It must never panic, never loop forever, and never
// allocate unboundedly. The seed corpus is the RFC 7541 Appendix C blocks
// (known-good) plus a handful of the malformed shapes from the adversarial
// tests (known-bad), so the fuzzer starts already near the interesting
// edges instead of discovering them from nothing.
func FuzzHPACKDecode(f *testing.F) {
	seeds := []string{
		// RFC 7541 Appendix C — known good.
		"828684410f7777772e6578616d706c652e636f6d",
		"828684be58086e6f2d6361636865",
		"828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565",
		"828684418cf1e3c2e5f23a6ba0ab90f4ff",
		"828684be5886a8eb10649cbf",
		"828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf",
		"4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d",
		"4803333037c1c0bf",
		"488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3",
		"400a637573746f6d2d6b65790d637573746f6d2d686561646572",
		"040c2f73616d706c652f70617468",
		"100870617373776f726406736563726574",
		"82",
		// Known-bad shapes from the adversarial tests.
		"80",                                    // indexed, index 0
		"ff9f4e",                                // huge index, continuation bytes
		"40",                                    // literal-with-indexing, truncated
		"4000",                                  // literal name, no string data
		"1f8080808080808080",                    // non-terminating integer
		"64" + hex.EncodeToString([]byte("ab")), // string length exceeds block
	}
	for _, s := range seeds {
		b, err := hex.DecodeString(s)
		if err != nil {
			f.Fatalf("bad seed hex %q: %v", s, err)
		}
		f.Add(b)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		codec := New()
		fields, err := codec.Decode(data)
		if err != nil {
			if fields != nil {
				t.Fatalf("Decode returned both an error and %d fields; errors must be all-or-nothing", len(fields))
			}
			return
		}
		// A successful decode must not have grown the dynamic table past
		// its own configured max — otherwise the accounting itself is
		// broken, independent of whether this particular input errors.
		if codec.dyn.size > codec.dyn.max {
			t.Fatalf("dynamic table size %d exceeds max %d after a successful decode", codec.dyn.size, codec.dyn.max)
		}
	})
}
