package hpack

import (
	"errors"
	"testing"
)

func TestDecodeIntRoundTrip(t *testing.T) {
	values := []uint64{0, 1, 30, 31, 32, 127, 128, 1337, 4096, 1 << 20, maxIntValue}
	for _, n := range []uint8{4, 5, 6, 7, 8} {
		for _, v := range values {
			enc := appendInt(nil, 0, n, v)
			got, consumed, err := decodeInt(enc, n)
			if err != nil {
				t.Fatalf("prefix %d value %d: decode error: %v", n, v, err)
			}
			if got != v {
				t.Fatalf("prefix %d value %d: got %d", n, v, got)
			}
			if consumed != len(enc) {
				t.Fatalf("prefix %d value %d: consumed %d, want %d", n, v, consumed, len(enc))
			}
		}
	}
}

// A non-terminating integer: every continuation byte has the high bit set
// and it never stops. This must fail fast, not loop or overflow.
func TestDecodeIntNeverTerminates(t *testing.T) {
	src := make([]byte, 64)
	src[0] = 0x1f // 5-bit prefix, all set -> continuation follows
	for i := 1; i < len(src); i++ {
		src[i] = 0xff // continuation bit always set
	}
	_, _, err := decodeInt(src, 5)
	if !errors.Is(err, ErrCompression) {
		t.Fatalf("err = %v, want ErrCompression", err)
	}
}

func TestDecodeIntOverflows(t *testing.T) {
	// 5-bit prefix all-ones, then continuation bytes whose value pushes
	// well past maxIntValue.
	src := []byte{0x1f, 0xff, 0xff, 0xff, 0xff, 0x7f}
	_, _, err := decodeInt(src, 5)
	if !errors.Is(err, ErrCompression) {
		t.Fatalf("err = %v, want ErrCompression", err)
	}
}

func TestDecodeIntTruncated(t *testing.T) {
	cases := [][]byte{
		{},           // no prefix byte at all
		{0x1f},       // prefix says "continues", nothing follows
		{0x1f, 0xff}, // continuation bit still set, stream ends
	}
	for _, c := range cases {
		_, _, err := decodeInt(c, 5)
		if !errors.Is(err, ErrCompression) {
			t.Fatalf("decodeInt(%x): err = %v, want ErrCompression", c, err)
		}
	}
}

func TestDecodeStringLengthExceedsBlock(t *testing.T) {
	// Length byte claims 100 literal bytes; only 2 are actually present.
	src := append([]byte{0x64}, []byte("ab")...)
	_, _, err := decodeString(src)
	if !errors.Is(err, ErrCompression) {
		t.Fatalf("err = %v, want ErrCompression", err)
	}
}

func TestDecodeStringDoesNotAllocateBeforeValidating(t *testing.T) {
	// A 2-byte block claiming a length near the uint64 space: decodeInt
	// itself rejects it (exceeds maxIntValue) long before any allocation.
	src := []byte{0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	_, _, err := decodeString(src)
	if !errors.Is(err, ErrCompression) {
		t.Fatalf("err = %v, want ErrCompression", err)
	}
}

func TestDecodeStringHuffmanInvalidPadding(t *testing.T) {
	// Huffman flag set (0x80), length 1, one byte of data whose low bits
	// are an invalid pad (not all-ones) after the shortest valid symbol.
	src := []byte{0x81, 0x18} // H=1, len=1; data 0x18 = 00011 000 ('a' + bad pad)
	_, _, err := decodeString(src)
	if !errors.Is(err, ErrCompression) {
		t.Fatalf("err = %v, want ErrCompression", err)
	}
}

func TestAppendStringRoundTrip(t *testing.T) {
	cases := []string{"", "a", "www.example.com", "gzip, deflate", "!!!!!!!!!!"}
	for _, c := range cases {
		enc := appendString(nil, c)
		got, n, err := decodeString(enc)
		if err != nil {
			t.Fatalf("%q: %v", c, err)
		}
		if got != c || n != len(enc) {
			t.Fatalf("%q: got %q, consumed %d, want consumed %d", c, got, n, len(enc))
		}
	}
}
