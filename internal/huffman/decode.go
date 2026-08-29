package huffman

import "errors"

var (
	// ErrEOSSymbol is returned when the bitstream decodes to the EOS
	// symbol itself. RFC 7541 §5.2: EOS "MUST NOT" appear as a decoded
	// symbol; it exists only as the source of padding bits.
	ErrEOSSymbol = errors.New("huffman: EOS decoded as a symbol")

	// ErrPadding is returned when the bits left over at the end of the
	// stream are not a valid pad: RFC 7541 §5.2 requires the padding be
	// at most 7 bits, and be the most-significant bits of the EOS code
	// (which, being all ones, means the padding bits must all be 1).
	ErrPadding = errors.New("huffman: invalid padding")
)

// node is one state in the decode trie. A leaf has children == [nil, nil]
// and sym holding the decoded symbol (0..256, 256 == EOS).
type node struct {
	children [2]*node
	sym      int
	isLeaf   bool
}

var root = buildTree()

func buildTree() *node {
	r := &node{sym: -1}
	insert := func(sym int, code uint32, length uint8) {
		n := r
		for i := int(length) - 1; i >= 0; i-- {
			bit := (code >> uint(i)) & 1
			if n.children[bit] == nil {
				n.children[bit] = &node{sym: -1}
			}
			n = n.children[bit]
		}
		n.isLeaf = true
		n.sym = sym
	}
	for s := 0; s < 256; s++ {
		insert(s, codes[s], codeLens[s])
	}
	insert(EOS, codes[EOS], codeLens[EOS])
	return r
}

// Decode expands a Huffman-coded byte string (RFC 7541 §5.2) and appends
// the result to dst. It never allocates more than roughly 8/5 of len(src)
// bytes, since the shortest Huffman code is 5 bits, so a hostile caller
// cannot use it to turn a small input into an unbounded allocation.
func Decode(dst []byte, src []byte) ([]byte, error) {
	n := root
	depth := 0
	allOnes := true

	for _, b := range src {
		for i := 7; i >= 0; i-- {
			bit := (b >> uint(i)) & 1
			n = n.children[bit]
			if n == nil {
				return dst, ErrPadding
			}
			depth++
			if bit == 0 {
				allOnes = false
			}
			if n.isLeaf {
				if n.sym == EOS {
					return dst, ErrEOSSymbol
				}
				dst = append(dst, byte(n.sym))
				n = root
				depth = 0
				allOnes = true
			}
		}
	}

	if n != root {
		if depth > 7 {
			return dst, ErrPadding
		}
		if !allOnes {
			return dst, ErrPadding
		}
	}

	return dst, nil
}
