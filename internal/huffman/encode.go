package huffman

// EncodedLen returns the number of bytes Encode(data) would produce,
// without doing the encoding. The HPACK string encoder (RFC 7541 §5.2)
// needs this to decide whether Huffman coding is actually shorter than the
// literal bytes before committing to it.
func EncodedLen(data []byte) int {
	bits := 0
	for _, b := range data {
		bits += int(codeLens[b])
	}
	return (bits + 7) / 8
}

// Encode appends the Huffman encoding of data (RFC 7541 §5.2) to dst and
// returns the extended slice. The final partial byte, if any, is padded
// with the most-significant bits of the EOS code (all ones), as required.
func Encode(dst []byte, data []byte) []byte {
	var acc uint64
	nbits := uint(0)

	for _, b := range data {
		code := uint64(codes[b])
		clen := uint(codeLens[b])
		acc = (acc << clen) | code
		nbits += clen
		for nbits >= 8 {
			nbits -= 8
			dst = append(dst, byte(acc>>nbits))
		}
	}

	if nbits > 0 {
		// Pad with the high-order (all-one) bits of the EOS code.
		acc = (acc << (8 - nbits)) | (uint64(0xff) >> nbits)
		dst = append(dst, byte(acc))
	}

	return dst
}
