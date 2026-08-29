package huffman

import (
	"bytes"
	"testing"
)

func TestRoundTripEveryByte(t *testing.T) {
	for b := 0; b < 256; b++ {
		in := []byte{byte(b)}
		enc := Encode(nil, in)
		dec, err := Decode(nil, enc)
		if err != nil {
			t.Fatalf("byte %d: decode error: %v", b, err)
		}
		if !bytes.Equal(dec, in) {
			t.Fatalf("byte %d: round-trip = %v, want %v", b, dec, in)
		}
	}
}

func TestRoundTripSequences(t *testing.T) {
	cases := []string{
		"",
		"a",
		"www.example.com",
		"custom-key",
		"custom-header",
		"Mon, 21 Oct 2013 20:13:21 GMT",
		"https://www.example.com",
		"foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1",
		string(allBytes()),
	}
	for _, c := range cases {
		enc := Encode(nil, []byte(c))
		dec, err := Decode(nil, enc)
		if err != nil {
			t.Fatalf("%q: decode error: %v", c, err)
		}
		if string(dec) != c {
			t.Fatalf("round-trip mismatch: got %q, want %q", dec, c)
		}
	}
}

func allBytes() []byte {
	b := make([]byte, 256)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func TestDecodeRejectsEOSAsSymbol(t *testing.T) {
	// The EOS code itself, byte-aligned: 30 ones then 2 padding ones to
	// reach a byte boundary. A correct decoder must reject this before
	// treating the padding as valid, because the bits decode fully to EOS.
	enc := []byte{}
	var acc uint64 = uint64(codes[EOS])
	nbits := uint(codeLens[EOS])
	// left-align into a byte stream
	for nbits > 0 {
		if nbits >= 8 {
			nbits -= 8
			enc = append(enc, byte(acc>>nbits))
		} else {
			enc = append(enc, byte(acc<<(8-nbits)))
			nbits = 0
		}
	}
	_, err := Decode(nil, enc)
	if err != ErrEOSSymbol {
		t.Fatalf("decode of raw EOS bits: err = %v, want ErrEOSSymbol", err)
	}
}

func TestDecodeRejectsPaddingLongerThan7Bits(t *testing.T) {
	// 'a' is 5 bits (00011). Followed by a full extra byte of 1s, the
	// leftover after 'a' is 8+ pad bits, more than the 7-bit maximum.
	enc := []byte{0x1f, 0xff} // 00011 111 | 11111111 -> 11 leftover bits, all ones
	_, err := Decode(nil, enc)
	if err != ErrPadding {
		t.Fatalf("err = %v, want ErrPadding", err)
	}
}

func TestDecodeRejectsPaddingNotAllOnes(t *testing.T) {
	// 'a' (00011, 5 bits) followed by 3 zero bits as pad: invalid, must be
	// the high bits of EOS (all ones).
	enc := []byte{0x18} // 00011 000
	_, err := Decode(nil, enc)
	if err != ErrPadding {
		t.Fatalf("err = %v, want ErrPadding", err)
	}
}

func TestDecodeAcceptsShortValidPadding(t *testing.T) {
	// 'a' (00011, 5 bits) followed by 3 one bits as pad: valid.
	enc := []byte{0x1f} // 00011 111
	dec, err := Decode(nil, enc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(dec) != "a" {
		t.Fatalf("decoded %q, want %q", dec, "a")
	}
}

func TestEncodedLenMatchesEncode(t *testing.T) {
	cases := []string{"", "a", "www.example.com", "0123456789"}
	for _, c := range cases {
		want := len(Encode(nil, []byte(c)))
		got := EncodedLen([]byte(c))
		if got != want {
			t.Errorf("%q: EncodedLen = %d, want %d", c, got, want)
		}
	}
}
