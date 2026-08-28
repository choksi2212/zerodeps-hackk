#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# scripts/deps-proof.sh — regenerate deps-proof.txt.
#
# Emits the evidence for the zero-dependency claim, verbatim, so that a judge
# can re-run this script and diff the output against the committed file.
#
# The strongest single artifact here is `go version -m bin/zdh`: it reads the
# dependency list out of the compiled binary. A manifest can omit vendored
# code; the binary cannot.
#
# Usage: bash scripts/deps-proof.sh > deps-proof.txt
# ---------------------------------------------------------------------------
set -euo pipefail

cd "$(dirname "$0")/.."

BIN=bin/zdh

say() { printf '\n----- %s -----\n' "$1"; }

printf 'zdh — zero-dependency proof\n'
printf 'Regenerate with: bash scripts/deps-proof.sh > deps-proof.txt\n'

say '$ go version'
go version

say '$ cat go.mod'
cat go.mod

say '$ ls go.sum'
if [ -f go.sum ]; then
	printf 'go.sum EXISTS — the zero-dependency claim is broken.\n'
	exit 1
fi
printf 'go.sum: does not exist (this absence is the proof)\n'

say '$ ls vendor'
if [ -d vendor ]; then
	printf 'vendor/ EXISTS — vendoring is banned by the rules.\n'
	exit 1
fi
printf 'vendor/: does not exist\n'

say '$ go list -m all'
go list -m all

say '$ go list -deps ./... | grep -v "^zerodeps/" | wc -l   (standard-library packages reached)'
go list -deps ./... | grep -v '^zerodeps/' | wc -l

say '$ go list -deps -f "{{if not .Standard}}{{.ImportPath}}{{end}}" ./...   (non-standard packages)'
go list -deps -f '{{if not .Standard}}{{.ImportPath}}{{end}}' ./...
printf '(every line above is one of our own packages; anything else would be an external dependency)\n'

say '$ go list -deps ./... | grep -E "^net/http(/|$)"   (net/http occurrences)'
if go list -deps ./... | grep -E '^net/http(/|$)'; then
	printf 'net/http IS PRESENT — the entry is defeated.\n'
	exit 1
fi
printf 'net/http: 0 occurrences\n'

say '$ go list -deps ./... | grep "\." (dependency paths containing a dot)'
go list -deps ./... | grep '\.' || printf '(none)\n'
cat <<'NOTE'

Note on the paths above, if any are listed. Importing crypto/tls legitimately
reaches a handful of paths under vendor/golang.org/x/crypto, vendor/golang.org/
x/net and crypto/internal/entropy. Those are the standard library's own
internal copies, shipped inside GOROOT as part of the Go distribution itself.
They are in no manifest, cannot be removed or substituted, and `go list`
reports .Standard = true for every one of them — see the non-standard listing
above, which is the authoritative check. This project has no module
dependencies at all.
NOTE

say "$ go version -m $BIN   (dependencies read out of the compiled binary)"
if [ ! -f "$BIN" ]; then
	printf 'binary not built yet; run: bash scripts/build.sh\n'
	exit 1
fi
go version -m "$BIN"

say "$ go version -m $BIN | grep -c '^\\s*dep\\s'   (dependency records in the binary)"
if go version -m "$BIN" | grep -qE '^[[:space:]]+dep[[:space:]]'; then
	printf 'the binary records dependencies — investigate immediately.\n'
	exit 1
fi
printf '0\n'

printf '\n----- conclusion -----\n'
printf 'No go.sum, no vendor directory, no require directive, no non-standard\n'
printf 'import, and no dependency record in the compiled binary.\n'
