package hpack

import (
	"errors"

	"zerodeps/zdh/internal/huffman"
)

// ErrCompression is returned by every decode-time failure in this package.
// RFC 7541 has no notion of a recoverable HPACK error: once a header block
// fails to decode, the dynamic table's state is unknown, and every
// subsequent block on the connection would decode against a table the peer
// does not share. The caller (internal/server) maps this straight to a
// connection-level COMPRESSION_ERROR.
var ErrCompression = errors.New("hpack: COMPRESSION_ERROR")

// wrap turns a reason into an error that still satisfies errors.Is(err,
// ErrCompression), so callers can test for the category without caring
// about the specific message.
func wrap(reason string) error {
	return &compressionError{reason}
}

type compressionError struct{ reason string }

func (e *compressionError) Error() string { return "hpack: COMPRESSION_ERROR: " + e.reason }
func (e *compressionError) Unwrap() error { return ErrCompression }

// maxContinuationBytes bounds how many continuation octets a prefix integer
// (RFC 7541 §5.1) may spend. A hostile peer can set the continuation bit on
// every byte and never terminate; five continuation bytes is already enough
// to encode any value up to maxIntValue, so anything longer is malformed by
// construction, not merely large.
const maxContinuationBytes = 5

// maxIntValue bounds the value a decoded integer may reach. It is well
// above any real header size or table size, so it never rejects legitimate
// input; its purpose is purely to give the non-terminating / overflowing
// integer case (§5.1) a hard, cheap stop instead of an unbounded loop.
const maxIntValue = 1 << 32

// appendInt appends i (RFC 7541 §5.1), using an n-bit prefix. flags carries
// any bits above the prefix (already shifted into position; the low n bits
// of flags must be zero) and is OR-ed into the first byte.
func appendInt(dst []byte, flags byte, n uint8, i uint64) []byte {
	max := uint64(1)<<n - 1
	if i < max {
		return append(dst, flags|byte(i))
	}
	dst = append(dst, flags|byte(max))
	i -= max
	for i >= 128 {
		dst = append(dst, byte(i&0x7f)|0x80)
		i >>= 7
	}
	return append(dst, byte(i))
}

// decodeInt decodes a prefix integer (RFC 7541 §5.1) from the low n bits of
// src[0] plus any continuation bytes. It returns the value and the number
// of bytes consumed (always >= 1).
func decodeInt(src []byte, n uint8) (value uint64, consumed int, err error) {
	if len(src) == 0 {
		return 0, 0, wrap("truncated integer: no prefix byte")
	}
	max := uint64(1)<<n - 1
	v := uint64(src[0]) & max
	if v < max {
		return v, 1, nil
	}

	value = max
	shift := uint(0)
	i := 1
	for {
		if i-1 >= maxContinuationBytes {
			return 0, 0, wrap("integer continuation exceeds the allowed length")
		}
		if i >= len(src) {
			return 0, 0, wrap("truncated integer: continuation byte missing")
		}
		b := src[i]
		value += uint64(b&0x7f) << shift
		if value > maxIntValue {
			return 0, 0, wrap("integer overflows the allowed range")
		}
		shift += 7
		i++
		if b&0x80 == 0 {
			return value, i, nil
		}
	}
}

// maxStringLen is a belt-and-braces cap on a decoded string's length, on
// top of the check that a claimed length cannot exceed the bytes actually
// remaining in the block. It exists so a corrupted or adversarial length
// nowhere near the block size still fails fast and legibly.
const maxStringLen = 1 << 24 // 16 MiB; far above any real header value

// appendString appends s as an HPACK string literal (RFC 7541 §5.2),
// Huffman-coding it when doing so is strictly shorter than the literal
// bytes.
func appendString(dst []byte, s string) []byte {
	raw := []byte(s)
	hlen := huffman.EncodedLen(raw)
	if hlen < len(raw) {
		dst = appendInt(dst, 0x80, 7, uint64(hlen))
		return huffman.Encode(dst, raw)
	}
	dst = appendInt(dst, 0x00, 7, uint64(len(raw)))
	return append(dst, raw...)
}

// decodeString decodes an HPACK string literal (RFC 7541 §5.2) from the
// start of src, returning the decoded value and the number of bytes of src
// consumed (header byte plus data).
func decodeString(src []byte) (value string, consumed int, err error) {
	if len(src) == 0 {
		return "", 0, wrap("truncated string: no length byte")
	}
	huffmanCoded := src[0]&0x80 != 0
	length, n, err := decodeInt(src, 7)
	if err != nil {
		return "", 0, err
	}
	if length > maxStringLen {
		return "", 0, wrap("string length exceeds the maximum allowed")
	}
	if length > uint64(len(src)-n) {
		return "", 0, wrap("string length exceeds the remaining block")
	}
	data := src[n : n+int(length)]
	total := n + int(length)

	if !huffmanCoded {
		return string(data), total, nil
	}

	decoded, err := huffman.Decode(nil, data)
	if err != nil {
		return "", 0, wrap("huffman: " + err.Error())
	}
	return string(decoded), total, nil
}
