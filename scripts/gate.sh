#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# scripts/gate.sh — the build gate for zdh.
#
# Ten ordered checks. Nothing is committed while any of them is red.
#
# Checks 6, 7 and 8 are the ones that matter to this project: they turn the
# zero-dependency claim into something the build enforces instead of something
# the README asserts. Check 6 is deliberately hostile to us — Go's standard
# library already contains an HTTP/2 implementation in net/http, and importing
# it would quietly defeat the entire entry.
#
# Check 9 is the odd one out: it grades the comments rather than the code, by
# checking every RFC 9113 quotation in the tree against RFC 9113. It needs
# Python and a copy of the RFC, and skips rather than fails when either is
# absent, so a checkout without them still gets a green gate.
#
# Runs in Git Bash on Windows and in any POSIX shell on Linux. Uses only the
# Go toolchain and no third-party tool of any kind.
#
# Usage: bash scripts/gate.sh
# Exit:  0 = GATE GREEN, 1 = a check failed (the failing check says why)
# ---------------------------------------------------------------------------
set -euo pipefail

cd "$(dirname "$0")/.."

step() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
ok() { printf '   ok: %s\n' "$1"; }
die() {
	printf '\n\033[31mGATE RED\033[0m  %s\n' "$1" >&2
	exit 1
}

step "1/10 gofmt -l . — every file formatted"
unformatted="$(gofmt -l .)"
if [ -n "$unformatted" ]; then
	printf '%s\n' "$unformatted"
	die "the files listed above are not gofmt-clean. Fix with: gofmt -w ."
fi
ok "every .go file is gofmt-clean"

step "2/10 go vet ./... — no suspicious constructs"
go vet ./...
ok "go vet is silent"

step "3/10 go build ./... — everything compiles"
go build ./...
ok "all packages build"

step "4/10 go test ./... — tests pass"
go test ./...
ok "tests pass"

step "5/10 go test -race ./... — no data races"
go test -race ./...
ok "race detector is clean"

step "6/10 net/http must NOT be in the dependency graph"
deps="$(go list -deps ./...)"
if printf '%s\n' "$deps" | grep -Eq '^net/http(/|$)'; then
	printf '%s\n' "$deps" | grep -E '^net/http(/|$)'
	die "net/http is in the dependency graph. Go's net/http already speaks
          HTTP/2, so importing it (including net/http/httptest in a test) makes
          this project a wrapper around the very thing it exists to replace.
          Find the import and remove it."
fi
ok "net/http is absent — this is the whole point of the project"

step "7/10 every dependency must be the standard library or this module"
# The authoritative check. Instead of pattern-matching import paths, ask the Go
# tool itself whether each package is part of the standard library. Anything it
# does not certify as standard, other than our own packages, is an external
# dependency.
#
# This matters because a naive `grep golang.org` over `go list -deps` output
# gives a FALSE POSITIVE: importing crypto/tls legitimately pulls in nine paths
# that contain dots, eight of them under vendor/golang.org/x/crypto and
# vendor/golang.org/x/net. Those are the standard library's own internal copies,
# shipped inside GOROOT as part of the Go distribution. They appear in no
# manifest, cannot be removed, and `go list` reports .Standard = true for every
# one of them. They are not module dependencies, and this project has none.
foreign="$(go list -deps -f '{{if not .Standard}}{{.ImportPath}}{{end}}' ./... |
	grep -v '^zerodeps/zdh' || true)"
if [ -n "$foreign" ]; then
	printf '%s\n' "$foreign"
	die "the packages above are outside the standard library and outside this
          module. That is an external dependency."
fi
# Belt and braces for the one module the rules name explicitly. Anchored, so
# the legitimate vendor/golang.org/... GOROOT paths described above do not match.
if printf '%s\n' "$deps" | grep -Eq '^golang\.org/'; then
	printf '%s\n' "$deps" | grep -E '^golang\.org/'
	die "a golang.org/x package is imported directly. golang.org/x is a separate
          module, not the standard library, and the rules name
          golang.org/x/net/http2 by name."
fi
ok "the Go tool certifies every dependency as standard library"

step "8/10 the module manifest is empty and nothing is vendored"
if [ -f go.sum ]; then
	die "go.sum exists. A populated go.sum is the most visible zero-dependency
          failure there is, and its absence is the proof. Delete it and find the
          'go get' that created it."
fi
if [ -d vendor ]; then
	die "a vendor/ directory exists. Vendoring is banned by the rules — a copied
          dependency is still a dependency."
fi
if grep -Eq '^[[:space:]]*(require|replace|exclude|toolchain)' go.mod; then
	grep -nE '^[[:space:]]*(require|replace|exclude|toolchain)' go.mod
	die "go.mod must stay three lines: module, blank, go. The directives above do
          not belong in a zero-dependency module. A 'toolchain' line in
          particular gets added silently by the Go tool — delete it and pin the
          version in README prose instead."
fi
ok "go.mod is $(grep -c . go.mod) non-blank lines; no go.sum, no vendor/"

step "9/10 every RFC 9113 quotation must be the RFC's own words"
# The comments here argue from the specification and quote it, and six of those
# quotations turned out to be RFC 7540's text under RFC 9113's numbers, or
# sentences that appear in neither. See scripts/quotes.py, which explains what it
# tolerates and why.
#
# Skipped, loudly, when Python or the RFC is missing. This check grades prose, it
# is the only step that needs anything outside the Go toolchain, and a
# contributor without the RFC beside their checkout should not be stopped from
# committing code — so it says it was skipped rather than passing quietly.
#
# Each candidate is run, not merely found on PATH. On Windows, `python3` is an
# App Execution Alias that exists whether or not Python is installed: it is on
# PATH, `command -v` finds it, and running it prints "Python was not found" to
# stdout and fails. A gate that trusted the lookup would report a misquotation in
# every comment in the tree, on a machine with a perfectly good `python`.
py=""
for candidate in python3 python; do
	if "$candidate" -c "" >/dev/null 2>&1; then
		py="$candidate"
		break
	fi
done
if [ -z "$py" ]; then
	printf '   skipped: no python on PATH, so the quotations were not checked\n'
else
	quotes="$("$py" scripts/quotes.py)" || die "$quotes
          Fix the comment so it matches the RFC, or drop the quotation marks and
          paraphrase instead. See scripts/quotes.py for what counts as verbatim."
	printf '%s\n' "$quotes" | sed 's/^/   /'
fi

step "10/10 result"
printf '\n\033[32mGATE GREEN\033[0m  zero dependencies, no net/http, formatted, vetted, tested, race-clean.\n'
