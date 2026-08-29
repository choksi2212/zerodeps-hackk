package hpack

import "zerodeps/zdh/internal/h2"

// Encode compresses fields into one header block fragment (RFC 7541 §6).
// It never fails: every field, however unusual, has a valid literal
// encoding, so Encode has no error return (matching the h2.HeaderCodec
// contract).
//
// The encoding choice per field, cheapest first:
//
//  1. Sensitive fields are always Literal Never Indexed (§6.2.3) — never
//     added to the dynamic table, so a compression oracle across requests
//     cannot recover them by observing encoded sizes.
//  2. An exact (name, value) match in the static or dynamic table is one
//     Indexed Header Field (§6.1).
//  3. Otherwise, Literal with Incremental Indexing (§6.2.1), using an
//     indexed name when the name alone is already in a table, and adding
//     the field to the dynamic table so a repeat is cheap next time.
//
// This is not the most compact encoder possible — it does not weigh
// whether a value is likely to repeat before indexing it — but it is
// correct, and correctness is what a decoder on the other end depends on.
func (c *Codec) Encode(fields []h2.Field) []byte {
	var dst []byte
	for _, f := range fields {
		if f.Sensitive {
			dst = c.encodeLiteral(dst, f, 0x10, 4)
			continue
		}
		if idx, ok := c.findExact(f.Name, f.Value); ok {
			dst = appendInt(dst, 0x80, 7, idx)
			continue
		}
		dst = c.encodeLiteral(dst, f, 0x40, 6)
		c.dyn.add(f)
	}
	return dst
}

// encodeLiteral appends one of the three literal representations, which
// all share the same shape: a name (indexed, or inline if not found in
// either table) followed by an inline value. flag carries the
// representation's leading bits and prefixBits its prefix width.
func (c *Codec) encodeLiteral(dst []byte, f h2.Field, flag byte, prefixBits uint8) []byte {
	if nameIdx, ok := c.findName(f.Name); ok {
		dst = appendInt(dst, flag, prefixBits, nameIdx)
	} else {
		dst = appendInt(dst, flag, prefixBits, 0)
		dst = appendString(dst, f.Name)
	}
	return appendString(dst, f.Value)
}

// findExact returns the combined-space index (RFC 7541 §2.3.3) of an entry
// whose name and value both match, searching the static table then the
// dynamic table.
func (c *Codec) findExact(name, value string) (idx uint64, found bool) {
	for i, f := range staticTable {
		if f.Name == name && f.Value == value {
			return uint64(i + 1), true
		}
	}
	if off, exact := c.dyn.find(name, value); exact {
		return uint64(len(staticTable) + off), true
	}
	return 0, false
}

// findName returns the combined-space index of an entry whose name matches,
// regardless of value, searching the static table then the dynamic table.
func (c *Codec) findName(name string) (idx uint64, found bool) {
	if i, ok := staticNameIndex[name]; ok {
		return uint64(i), true
	}
	if off := c.dyn.findName(name); off > 0 {
		return uint64(len(staticTable) + off), true
	}
	return 0, false
}
