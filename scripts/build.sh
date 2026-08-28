#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# scripts/build.sh — the reproducible build.
#
#   bash scripts/build.sh            build bin/zdh
#   bash scripts/build.sh --verify   build it twice and compare SHA-256
#
# Every flag below is load-bearing:
#
#   CGO_ENABLED=0     no C toolchain in the graph, so the binary is static and
#                     the build does not depend on which gcc happens to be
#                     installed
#   -trimpath         strips absolute source paths, which otherwise embed the
#                     builder's home directory into the binary
#   -buildvcs=false   stops Go stamping git commit and dirty state into the
#                     binary. This is the flag everyone forgets: without it two
#                     builds of identical source at different commits differ.
#   -ldflags -s -w    drop the symbol table and DWARF
#   -ldflags -buildid= clears the build ID, the last non-deterministic field
# ---------------------------------------------------------------------------
set -euo pipefail

cd "$(dirname "$0")/.."

OUT=bin/zdh
FLAGS=(-trimpath -buildvcs=false "-ldflags=-s -w -buildid=")

build() { CGO_ENABLED=0 go build "${FLAGS[@]}" -o "$1" ./cmd/zdh; }

sha() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d' ' -f1
	else
		shasum -a 256 "$1" | cut -d' ' -f1
	fi
}

mkdir -p bin

if [ "${1:-}" = "--verify" ]; then
	build bin/.repro-a
	build bin/.repro-b
	A="$(sha bin/.repro-a)"
	B="$(sha bin/.repro-b)"
	printf 'build 1: %s\nbuild 2: %s\n' "$A" "$B"
	rm -f bin/.repro-a bin/.repro-b
	if [ "$A" != "$B" ]; then
		printf '\n\033[31mNOT REPRODUCIBLE\033[0m two builds of the same source differ.\n' >&2
		exit 1
	fi
	printf '\n\033[32mREPRODUCIBLE\033[0m identical SHA-256 from two independent builds.\n'
	printf 'toolchain: %s\n' "$(go version)"
	exit 0
fi

build "$OUT"
printf '%s\n' "$OUT"
sha "$OUT"
