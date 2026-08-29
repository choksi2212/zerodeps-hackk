package hpack

import (
	"errors"
	"testing"
)

func TestDecodeIndexZeroIsInvalid(t *testing.T) {
	codec := New()
	_, err := codec.Decode([]byte{0x80}) // indexed, index 0
	if !errors.Is(err, ErrCompression) {
		t.Fatalf("err = %v, want ErrCompression", err)
	}
}

func TestDecodeIndexPastEndIsInvalid(t *testing.T) {
	codec := New()
	// 0xff = 1111111, 7-bit prefix all-ones -> continuation; encode a huge
	// index that is neither in the static table nor in an empty dynamic
	// table.
	block := appendInt(nil, 0x80, 7, 9999)
	_, err := codec.Decode(block)
	if !errors.Is(err, ErrCompression) {
		t.Fatalf("err = %v, want ErrCompression", err)
	}
}

func TestDecodeSizeUpdateAfterHeaderFieldIsInvalid(t *testing.T) {
	codec := New()
	block := []byte{0x82}                                  // Indexed :method: GET
	block = append(block, appendInt(nil, 0x20, 5, 100)...) // size update after a field
	_, err := codec.Decode(block)
	if !errors.Is(err, ErrCompression) {
		t.Fatalf("err = %v, want ErrCompression", err)
	}
}

func TestDecodeSizeUpdateBeforeHeaderFieldIsValid(t *testing.T) {
	codec := New()
	block := appendInt(nil, 0x20, 5, 100) // size update first
	block = append(block, 0x82)           // then Indexed :method: GET
	got, err := codec.Decode(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].Name != ":method" {
		t.Fatalf("got %+v", got)
	}
	if codec.dyn.max != 100 {
		t.Fatalf("dyn.max = %d, want 100", codec.dyn.max)
	}
}

func TestDecodeTruncatedBlockMidInstruction(t *testing.T) {
	cases := [][]byte{
		{0x40},             // literal-with-indexing: name index byte present, nothing else
		{0x40, 0x00},       // name index=0 (literal name follows), no string
		{0x00, 0x00, 0x05}, // literal-without-indexing, value claims len 5, absent
	}
	for _, c := range cases {
		codec := New()
		_, err := codec.Decode(c)
		if !errors.Is(err, ErrCompression) {
			t.Fatalf("block %x: err = %v, want ErrCompression", c, err)
		}
	}
}

func TestDecodeEmptyBlockIsValid(t *testing.T) {
	codec := New()
	got, err := codec.Decode(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %+v, want empty", got)
	}
}

func TestDecodeLiteralNeverIndexedNotAddedToTable(t *testing.T) {
	codec := New()
	block := append([]byte{0x10}, appendString(nil, "password")...)
	block = appendString(block, "secret")
	got, err := codec.Decode(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || !got[0].Sensitive {
		t.Fatalf("got %+v, want one sensitive field", got)
	}
	if len(codec.dyn.entries) != 0 {
		t.Fatal("literal never-indexed must not enter the dynamic table")
	}
}

func TestDecodeLiteralWithoutIndexingNotAddedToTable(t *testing.T) {
	codec := New()
	block := append([]byte{0x04}, appendString(nil, "/sample/path")...)
	got, err := codec.Decode(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].Name != ":path" {
		t.Fatalf("got %+v", got)
	}
	if len(codec.dyn.entries) != 0 {
		t.Fatal("literal without indexing must not enter the dynamic table")
	}
}
