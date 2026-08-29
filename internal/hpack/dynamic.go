package hpack

import "zerodeps/zdh/internal/h2"

// defaultDynamicTableSize is the SETTINGS_HEADER_TABLE_SIZE default
// (RFC 9113 §6.5.2), used until SetMaxDynamicTableSize says otherwise.
const defaultDynamicTableSize = 4096

// entrySize is RFC 7541 §4.1's accounting formula: the name and value
// octets plus a fixed 32-byte overhead per entry, modeling the cost of the
// structure holding it. Forgetting the 32 makes every eviction decision
// wrong, so it is the one number in this file worth re-reading twice.
func entrySize(f h2.Field) int {
	return len(f.Name) + len(f.Value) + 32
}

// dynamicTable is the per-connection, per-direction FIFO of RFC 7541 §2.3.2.
// entries[0] is the most recently added entry (wire index 62); entries[i]
// is wire index 62+i. It is not safe for concurrent use — see the
// single-threaded-per-connection contract on Codec.
type dynamicTable struct {
	entries []h2.Field
	size    int // sum of entrySize(e) for e in entries — the accounted size
	max     int // current effective limit; always <= ceiling
	ceiling int // the SETTINGS-derived hard limit (SetMaxDynamicTableSize)
}

func newDynamicTable() *dynamicTable {
	return &dynamicTable{
		max:     defaultDynamicTableSize,
		ceiling: defaultDynamicTableSize,
	}
}

// setCeiling applies a new SETTINGS-derived maximum (RFC 7541 §4.3). If the
// current effective max is now above the new ceiling, it is clamped down
// immediately, evicting as needed.
func (dt *dynamicTable) setCeiling(n int) {
	dt.ceiling = n
	if dt.max > n {
		dt.max = n
		dt.evictToFit()
	}
}

// setMax applies an in-band Dynamic Table Size Update (RFC 7541 §6.3). It
// is an error for n to exceed the SETTINGS-derived ceiling — that would let
// a peer grant itself more table than the connection agreed to.
func (dt *dynamicTable) setMax(n int) error {
	if n > dt.ceiling {
		return wrap("dynamic table size update exceeds the SETTINGS maximum")
	}
	dt.max = n
	dt.evictToFit()
	return nil
}

func (dt *dynamicTable) evictToFit() {
	for dt.size > dt.max && len(dt.entries) > 0 {
		last := len(dt.entries) - 1
		dt.size -= entrySize(dt.entries[last])
		dt.entries = dt.entries[:last]
	}
}

// add inserts f at the front of the table (RFC 7541 §4.4), evicting from
// the back until it fits. An entry whose own size exceeds the table's
// current max empties the table entirely and is not inserted — this is
// legal per §4.4, not an error.
func (dt *dynamicTable) add(f h2.Field) {
	esize := entrySize(f)
	if esize > dt.max {
		dt.entries = dt.entries[:0]
		dt.size = 0
		return
	}
	for dt.size+esize > dt.max && len(dt.entries) > 0 {
		last := len(dt.entries) - 1
		dt.size -= entrySize(dt.entries[last])
		dt.entries = dt.entries[:last]
	}
	grown := make([]h2.Field, len(dt.entries)+1)
	grown[0] = f
	copy(grown[1:], dt.entries)
	dt.entries = grown
	dt.size += esize
}

// get looks up a 1-based offset into the dynamic part of the address space
// (offset 1 is wire index 62, the most recently added entry).
func (dt *dynamicTable) get(offset int) (h2.Field, bool) {
	if offset < 1 || offset > len(dt.entries) {
		return h2.Field{}, false
	}
	return dt.entries[offset-1], true
}

// find looks for f.Name (and, if present, f.Value) among the dynamic
// entries. It returns the 1-based offset of the best match: an exact
// name+value match if one exists, otherwise the first name-only match.
// exact reports which kind was found.
func (dt *dynamicTable) find(name, value string) (offset int, exact bool) {
	nameOffset := 0
	for i, e := range dt.entries {
		if e.Name != name {
			continue
		}
		if e.Value == value {
			return i + 1, true
		}
		if nameOffset == 0 {
			nameOffset = i + 1
		}
	}
	return nameOffset, false
}

// findName returns the 1-based offset of the first entry with a matching
// name, or 0 if none exists.
func (dt *dynamicTable) findName(name string) (offset int) {
	for i, e := range dt.entries {
		if e.Name == name {
			return i + 1
		}
	}
	return 0
}
