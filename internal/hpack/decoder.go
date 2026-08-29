package hpack

import "zerodeps/zdh/internal/h2"

// Decode expands one complete header block (RFC 7541 §6), dispatching each
// instruction on the leading bits of its first byte:
//
//	1xxxxxxx  Indexed Header Field                (§6.1, 7-bit prefix)
//	01xxxxxx  Literal with Incremental Indexing    (§6.2.1, 6-bit prefix)
//	001xxxxx  Dynamic Table Size Update            (§6.3, 5-bit prefix)
//	0001xxxx  Literal Never Indexed                (§6.2.3, 4-bit prefix)
//	0000xxxx  Literal without Indexing             (§6.2.2, 4-bit prefix)
//
// These five prefixes exhaustively and exclusively partition all 256 byte
// values, so the switch below never needs a fallback branch for a bit
// pattern it did not expect.
//
// Every error path returns ErrCompression (wrapped). There is no partial
// result on error: once decoding fails, the dynamic table's state is
// unknown, and returning fields decoded so far would let the caller use a
// header list whose later entries never happened.
func (c *Codec) Decode(block []byte) ([]h2.Field, error) {
	var fields []h2.Field
	pos := 0
	sawHeaderField := false

	for pos < len(block) {
		b := block[pos]
		switch {
		case b&0x80 != 0: // Indexed Header Field
			idx, n, err := decodeInt(block[pos:], 7)
			if err != nil {
				return nil, err
			}
			f, err := c.lookupIndexed(idx)
			if err != nil {
				return nil, err
			}
			pos += n
			fields = append(fields, f)
			sawHeaderField = true

		case b&0xc0 == 0x40: // Literal with Incremental Indexing
			f, n, err := c.decodeLiteral(block[pos:], 6)
			if err != nil {
				return nil, err
			}
			pos += n
			c.dyn.add(f)
			fields = append(fields, f)
			sawHeaderField = true

		case b&0xe0 == 0x20: // Dynamic Table Size Update
			if sawHeaderField {
				return nil, wrap("dynamic table size update after a header field")
			}
			size, n, err := decodeInt(block[pos:], 5)
			if err != nil {
				return nil, err
			}
			if err := c.dyn.setMax(int(size)); err != nil {
				return nil, err
			}
			pos += n

		case b&0xf0 == 0x10: // Literal Never Indexed
			f, n, err := c.decodeLiteral(block[pos:], 4)
			if err != nil {
				return nil, err
			}
			pos += n
			f.Sensitive = true
			fields = append(fields, f)
			sawHeaderField = true

		default: // 0000xxxx: Literal without Indexing
			f, n, err := c.decodeLiteral(block[pos:], 4)
			if err != nil {
				return nil, err
			}
			pos += n
			fields = append(fields, f)
			sawHeaderField = true
		}
	}

	return fields, nil
}

// decodeLiteral decodes the common shape shared by all three literal
// representations (§6.2.1, §6.2.2, §6.2.3): a name — either an index into
// the combined static+dynamic space or an inline string — followed always
// by an inline string value. It does not touch the dynamic table; the
// caller decides whether to index the result.
func (c *Codec) decodeLiteral(src []byte, prefixBits uint8) (h2.Field, int, error) {
	nameIdx, n, err := decodeInt(src, prefixBits)
	if err != nil {
		return h2.Field{}, 0, err
	}
	pos := n

	var name string
	if nameIdx == 0 {
		s, m, err := decodeString(src[pos:])
		if err != nil {
			return h2.Field{}, 0, err
		}
		name = s
		pos += m
	} else {
		f, err := c.lookupIndexed(nameIdx)
		if err != nil {
			return h2.Field{}, 0, err
		}
		name = f.Name
	}

	value, m, err := decodeString(src[pos:])
	if err != nil {
		return h2.Field{}, 0, err
	}
	pos += m

	return h2.Field{Name: name, Value: value}, pos, nil
}

// lookupIndexed resolves a 1-based index in the combined address space
// (RFC 7541 §2.3.3): 1..61 is the static table, 62.. is the dynamic table,
// most-recently-added first. Index 0 is explicitly invalid.
func (c *Codec) lookupIndexed(idx uint64) (h2.Field, error) {
	if idx == 0 {
		return h2.Field{}, wrap("indexed header field: index 0 is invalid")
	}
	if idx <= uint64(len(staticTable)) {
		return staticTable[idx-1], nil
	}
	f, ok := c.dyn.get(int(idx) - len(staticTable))
	if !ok {
		return h2.Field{}, wrap("indexed header field: index out of range")
	}
	return f, nil
}
