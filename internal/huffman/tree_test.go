package huffman

import "testing"

// TestTableIsPrefixFree is the mechanical self-check the plan calls for: a
// mistyped entry in table.go almost always breaks the prefix-free property
// long before it would show up as a subtly wrong test vector, so this test
// exists to catch a transcription error in milliseconds instead of during a
// debugging session against RFC 7541 Appendix C.
func TestTableIsPrefixFree(t *testing.T) {
	all := make([]struct {
		sym  int
		code uint32
		len  uint8
	}, 257)
	for s := 0; s < 256; s++ {
		all[s] = struct {
			sym  int
			code uint32
			len  uint8
		}{s, codes[s], codeLens[s]}
	}
	all[256] = struct {
		sym  int
		code uint32
		len  uint8
	}{EOS, codes[EOS], codeLens[EOS]}

	for i := range all {
		if all[i].len == 0 || all[i].len > 30 {
			t.Errorf("symbol %d: implausible code length %d", all[i].sym, all[i].len)
		}
		for j := range all {
			if i == j {
				continue
			}
			a, b := all[i], all[j]
			if a.len > b.len {
				continue // only check each ordered pair once, shorter-as-prefix-of-longer
			}
			// Is a's code a prefix of b's code?
			shift := b.len - a.len
			if a.code == b.code>>shift {
				t.Errorf("symbol %d's code (len %d) is a prefix of symbol %d's code (len %d)",
					a.sym, a.len, b.sym, b.len)
			}
		}
	}
}

func TestTableHas257Leaves(t *testing.T) {
	count := countLeaves(root)
	if count != 257 {
		t.Errorf("decode tree has %d leaves, want 257", count)
	}
}

func countLeaves(n *node) int {
	if n == nil {
		return 0
	}
	if n.isLeaf {
		return 1
	}
	return countLeaves(n.children[0]) + countLeaves(n.children[1])
}

func TestEOSIsThirtyOnes(t *testing.T) {
	if codeLens[EOS] != 30 {
		t.Fatalf("EOS length = %d, want 30", codeLens[EOS])
	}
	if codes[EOS] != 0x3fffffff {
		t.Fatalf("EOS code = %#x, want 0x3fffffff", codes[EOS])
	}
}
