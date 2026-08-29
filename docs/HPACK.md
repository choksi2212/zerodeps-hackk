# HPACK — implementation notes and correctness evidence

`internal/hpack` and `internal/huffman` implement RFC 7541 (HPACK: Header
Compression for HTTP/2) from scratch: no `golang.org/x/net/http2/hpack`, no
vendored code. This document is the reviewer's shortcut to trusting it
without re-deriving it.

## RFC 7541 Appendix C → the test that proves it

Appendix C is a complete, published, byte-exact worked example suite. Every
row below is pass/fail against the spec itself — the strongest correctness
evidence available, because it doesn't depend on trusting this codebase at
all.

| Vector | Exercises | Test function | testdata |
|---|---|---|---|
| C.1 | Integer representation (5-bit and 8-bit prefixes, multi-octet continuation) | `TestAppendixC1Integers` | `testdata/hpack/c1_integers.txt` |
| C.2 | All four literal representations independently | `TestAppendixC2Literals` | `testdata/hpack/c2_literals.txt` |
| C.3 | Request sequence, no Huffman — dynamic table evolution across 3 requests | `TestAppendixC3RequestsWithoutHuffman` | `testdata/hpack/c3_without_huffman.txt` |
| C.4 | Same 3 requests, Huffman-coded | `TestAppendixC4RequestsWithHuffman` | `testdata/hpack/c4_with_huffman.txt` |
| C.5 | Response sequence, no Huffman, `SETTINGS_HEADER_TABLE_SIZE=256` — **exercises eviction** | `TestAppendixC5ResponsesWithoutHuffman` | `testdata/hpack/c5_without_huffman.txt` |
| C.6 | Same 3 responses, Huffman-coded, same evictions | `TestAppendixC6ResponsesWithHuffman` | `testdata/hpack/c6_with_huffman.txt` |

C.5 matters most: it's the only vector that exercises eviction, so it's the
one that actually tests the `+32` accounting and the FIFO order together —
both C.3 and C.4 only ever grow the table. Every test above asserts not
just the decoded header list but the dynamic table's exact entry count and
accounted size after each step, taken directly from the RFC text.

The hex in every `testdata/hpack/*.txt` file was extracted **programmatically**
from the RFC's own hex dumps (concatenating the dump lines and stripping the
ASCII sidebar and whitespace with a script), never transcribed by eye — the
one part of this codec where a manual transcription error would be both easy
to make and hard to notice.

## The dynamic table

RFC 7541 §4.1: an entry's accounted size is `len(name) + len(value) + 32`.
The `32` is a fixed per-entry overhead constant, not derived from anything —
forgetting it is *the* classic HPACK bug, because it makes every eviction
decision fire at the wrong table occupancy. `internal/hpack/dynamic.go`'s
`entrySize` is the one function in this codebase worth reading before
touching eviction logic.

Addressing (RFC 7541 §2.3.3): index 1–61 is the static table (fixed,
`internal/hpack/static.go`); index 62 onward is the dynamic table, most
recently inserted entry first. `dynamicTable.entries[0]` is always wire
index 62.

Two distinct "max size" concepts, both in `internal/hpack/dynamic.go`:

- **`ceiling`** — set by `Codec.SetMaxDynamicTableSize` (the `h2.HeaderCodec`
  method), driven by a peer's `SETTINGS_HEADER_TABLE_SIZE`. Hard limit.
- **`max`** — the table's *current* effective limit, always `<= ceiling`.
  Movable within `[0, ceiling]` by an in-band Dynamic Table Size Update
  instruction (RFC 7541 §6.3) during `Decode`. An in-band request above
  `ceiling` is a `COMPRESSION_ERROR` (§4.2) — a peer cannot grant itself
  more table than the connection agreed to via SETTINGS.

An entry whose own size exceeds `max` empties the table and is **not**
inserted — this is legal per §4.4, not an error.

## The single-threaded-per-connection contract

`Codec` (`internal/hpack/codec.go`) is explicitly **not** safe for
concurrent use, and no mutex is added to make it one. This is deliberate,
not an oversight:

The dynamic table is connection-scoped and *order-dependent*. A mutex would
serialize access correctly but would not guarantee the two goroutines call
`Decode` in the order the bytes actually arrived on the wire — and a decode
in the wrong order desynchronizes the table from what the peer's encoder
believes it holds, silently corrupting every subsequent header block on
that connection. The fix is not "add a lock," it's "call this from one
goroutine, in arrival order." `internal/server` decodes on the single
reader goroutine and encodes on the single writer goroutine, per
`README.md`'s concurrency model.

## Every `COMPRESSION_ERROR` trigger

All decode-time failures return an error satisfying
`errors.Is(err, hpack.ErrCompression)`. There is no partial/recoverable
HPACK error: once decoding fails, the dynamic table's state is unknown, so
`Decode` never returns fields alongside an error. The server
(`internal/server`) maps this straight to a connection-level
`COMPRESSION_ERROR` and a `GOAWAY`.

| Trigger | RFC | Where | Test |
|---|---|---|---|
| Integer continuation exceeds 5 bytes (non-terminating integer) | §5.1 | `primitives.go: decodeInt` | `TestDecodeIntNeverTerminates` |
| Integer value exceeds `maxIntValue` (overflow) | §5.1 | `primitives.go: decodeInt` | `TestDecodeIntOverflows` |
| Truncated integer (prefix or continuation byte missing) | §5.1 | `primitives.go: decodeInt` | `TestDecodeIntTruncated` |
| String length exceeds the remaining block bytes | §5.2 | `primitives.go: decodeString` | `TestDecodeStringLengthExceedsBlock` |
| String length exceeds `maxStringLen` (16 MiB sanity cap) | §5.2 | `primitives.go: decodeString` | `TestDecodeStringDoesNotAllocateBeforeValidating` |
| Huffman-coded string: EOS decoded as a real symbol | §5.2 | `huffman/decode.go` | `TestDecodeRejectsEOSAsSymbol` |
| Huffman-coded string: padding longer than 7 bits | §5.2 | `huffman/decode.go` | `TestDecodeRejectsPaddingLongerThan7Bits` |
| Huffman-coded string: padding bits not all-ones | §5.2 | `huffman/decode.go` | `TestDecodeRejectsPaddingNotAllOnes` |
| Indexed Header Field with index 0 | §6.1 | `decoder.go: lookupIndexed` | `TestDecodeIndexZeroIsInvalid` |
| Index (static+dynamic) past the end of both tables | §2.3.3 | `decoder.go: lookupIndexed` | `TestDecodeIndexPastEndIsInvalid` |
| Dynamic Table Size Update after a header field in the same block | §4.2 | `decoder.go: Decode` | `TestDecodeSizeUpdateAfterHeaderFieldIsInvalid` |
| Dynamic Table Size Update above the SETTINGS ceiling | §4.2 | `dynamic.go: setMax` | `TestDynamicTableSizeUpdateExceedsCeiling` |
| Block truncated mid-instruction | §6 | `decoder.go: Decode` (via the primitives above) | `TestDecodeTruncatedBlockMidInstruction` |

`FuzzHPACKDecode` (`internal/hpack/fuzz_test.go`) is the standing proof that
this list is complete in practice, not just on paper: on arbitrary bytes,
`Decode` returns either fields or one of the errors above — never a panic,
never unbounded allocation, never an infinite loop.

## Encoding choices

`Codec.Encode` is correct, not maximally compact — see `STDLIB.md`'s
"honestly slower" section for the specific trade-off and why. The one rule
that is never relaxed: `Field.Sensitive` always encodes as Literal Never
Indexed (§6.2.3) and is never added to the dynamic table, so a compression
oracle across requests cannot recover it by observing encoded sizes.
