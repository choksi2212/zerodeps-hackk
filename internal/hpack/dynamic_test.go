package hpack

import (
	"testing"

	"zerodeps/zdh/internal/h2"
)

func TestDynamicTableEntrySizeIncludesOverhead(t *testing.T) {
	f := h2.Field{Name: "ab", Value: "cde"} // 2 + 3 + 32 = 37
	if got := entrySize(f); got != 37 {
		t.Fatalf("entrySize = %d, want 37", got)
	}
}

func TestDynamicTableEvictionOrder(t *testing.T) {
	dt := newDynamicTable()
	dt.setCeiling(100) // room for roughly two ~37-byte entries, not three

	dt.add(h2.Field{Name: "a", Value: "1"}) // size 34
	dt.add(h2.Field{Name: "b", Value: "2"}) // size 34, total 68
	dt.add(h2.Field{Name: "c", Value: "3"}) // size 34, total 102 -> evicts "a"

	if len(dt.entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(dt.entries))
	}
	if dt.entries[0].Name != "c" || dt.entries[1].Name != "b" {
		t.Fatalf("eviction order wrong: got %+v", dt.entries)
	}
	if dt.size != 68 {
		t.Fatalf("size = %d, want 68", dt.size)
	}
}

func TestDynamicTableOversizedEntryEmptiesTable(t *testing.T) {
	dt := newDynamicTable()
	dt.setCeiling(50)
	dt.add(h2.Field{Name: "a", Value: "1"}) // 34, fits

	huge := h2.Field{Name: "this-name-is-long-enough", Value: "and-so-is-this-value-here"}
	if entrySize(huge) <= dt.max {
		t.Fatalf("test setup: entry not actually oversized")
	}
	dt.add(huge)

	if len(dt.entries) != 0 || dt.size != 0 {
		t.Fatalf("table not emptied: %d entries, size %d", len(dt.entries), dt.size)
	}
}

func TestDynamicTableIndexOutOfRange(t *testing.T) {
	dt := newDynamicTable()
	if _, ok := dt.get(1); ok {
		t.Fatal("get(1) on an empty table should fail")
	}
	if _, ok := dt.get(0); ok {
		t.Fatal("get(0) is not a valid offset")
	}
}

func TestDynamicTableSizeUpdateExceedsCeiling(t *testing.T) {
	dt := newDynamicTable()
	dt.setCeiling(100)
	if err := dt.setMax(101); err == nil {
		t.Fatal("setMax above the ceiling should fail")
	}
	if err := dt.setMax(100); err != nil {
		t.Fatalf("setMax at the ceiling should succeed: %v", err)
	}
}

func TestDynamicTableSizeUpdateToZeroThenBackUp(t *testing.T) {
	dt := newDynamicTable()
	dt.setCeiling(4096)
	dt.add(h2.Field{Name: "a", Value: "1"})
	if len(dt.entries) != 1 {
		t.Fatal("setup: expected one entry")
	}

	if err := dt.setMax(0); err != nil {
		t.Fatalf("setMax(0): %v", err)
	}
	if len(dt.entries) != 0 || dt.size != 0 {
		t.Fatalf("setMax(0) should evict everything: %d entries, size %d", len(dt.entries), dt.size)
	}

	if err := dt.setMax(4096); err != nil {
		t.Fatalf("setMax back up: %v", err)
	}
	dt.add(h2.Field{Name: "b", Value: "2"})
	if len(dt.entries) != 1 {
		t.Fatal("table should work normally again after raising max back up")
	}
}

func TestDynamicTableSetCeilingClampsCurrentMax(t *testing.T) {
	dt := newDynamicTable()
	dt.setCeiling(4096)
	dt.add(h2.Field{Name: "a-long-enough-name", Value: "a-long-enough-value-too"})
	if len(dt.entries) == 0 {
		t.Fatal("setup: expected an entry")
	}
	sizeBefore := dt.size

	dt.setCeiling(10) // below the entry's own size: must evict
	if dt.size > 10 {
		t.Fatalf("size %d exceeds the new ceiling of 10", dt.size)
	}
	if dt.size == sizeBefore {
		t.Fatal("setCeiling did not evict to fit the smaller ceiling")
	}
}
