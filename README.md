# zdh

`zdh` is an HTTP/2 server written against the Go standard library only. **It does not import `net/http`.** Go's standard library already contains an HTTP/2 implementation; this project deliberately does not use it. Frames are read and written directly on a `net.Conn` per RFC 9113, and header compression is a from-scratch HPACK implementation per RFC 7541. The full dependency graph is `net`, `crypto/tls`, `bufio`, `encoding/binary`, and the rest of the standard library — verify with `go list -deps ./...`. The build enforces this: `scripts/gate.sh` fails if `net/http` ever appears in the dependency graph.

Built for the **Zero Dependency Hackathon 2026**, Track C (Web & Network), in the 72 hours from 2026-08-28 18:00 UTC.

## Status

This section is kept honest as the build proceeds; nothing is claimed here before it works.

| Layer | State |
|---|---|
| Build gate, zero-dependency guards, reproducible build | working |
| Shared `internal/h2` contract | frozen |
| Frame layer (RFC 9113 §4, §6) | working — all 10 frame types, 478 tests, 4 fuzz targets |
| Connection timeouts and peer bounds (`internal/limits`) | working — six timeouts, 48 tests; the reset bucket is not yet wired to a connection |
| Connection lifecycle, SETTINGS, PING, GOAWAY | working — 67 tests, and 56 guards each observed failing |
| Accept loop, connection bound, graceful shutdown | working — 25 tests, and 34 guards each observed failing |
| Streams and flow control (§5) | not started |
| HPACK (RFC 7541) | in progress, separate author |
| Request semantics (§8), static file handler | not started |
| TLS + ALPN, browser demo | not started |
| h2spec conformance score | not yet run |

## Zero dependencies — check it in thirty seconds

```bash
cat go.mod            # three lines: module, blank, go directive
ls go.sum             # does not exist
go list -m all        # one line: this module
```

The strongest check does not trust any manifest — it reads the dependency records out of the compiled binary:

```bash
go version -m bin/zdh | grep -c dep    # 0
./bin/zdh -version                     # ...dependencies: 0
```

`zdh -version` reports its own dependency count from its embedded build info, so the claim is verifiable from the artifact you run rather than from a file we wrote. The full evidence, regenerable with `bash scripts/deps-proof.sh`, is committed as [`deps-proof.txt`](deps-proof.txt).

### The guards, and proof that they fire

`scripts/gate.sh` runs nine ordered checks and fails the build on any of them:

1. `gofmt -l .` prints nothing
2. `go vet ./...` is silent
3. `go build ./...`
4. `go test ./...`
5. `go test -race ./...`
6. `net/http` is not in the dependency graph
7. every dependency is certified `.Standard` by the Go tool itself, and nothing imports `golang.org/x`
8. no `go.sum`, no `vendor/`, no `require`/`replace`/`exclude`/`toolchain` directive
9. `GATE GREEN`

Each guard was deliberately tripped at bootstrap and observed to fail at the expected step: a used `net/http` import failed check 6, an empty `go.sum` failed check 8, a `require` line failed check 8, and a `vendor/` directory failed check 8. A guard nobody has seen fire is not a guard.

One honest note about check 7, because a casual `grep golang.org` over the dependency graph is misleading here. Importing `crypto/tls` reaches nine paths that contain dots — eight under `vendor/golang.org/x/crypto` and `vendor/golang.org/x/net`, plus `crypto/internal/entropy`. Those are the standard library's own internal copies, shipped inside `GOROOT` as part of the Go distribution. They appear in no manifest, cannot be removed or substituted, and `go list` reports `.Standard = true` for every one of them. So the gate asks the Go tool whether a package is standard rather than pattern-matching its path, and the authoritative listing of non-standard packages contains only this module's own packages.

### And proof that the tests fire

The same argument applies one level up: a test that has never been seen failing is a test nobody has checked. A green suite proves the code passes the tests; it says nothing about whether the tests would notice if the code stopped being correct.

So every security bound, deadline and protocol rule in this server has a *break* recorded against it — a one-line edit that removes exactly that guard, together with the tests that must fail as a result:

```bash
python scripts/break-conn.py     # 43 breaks, all 43 caught
python scripts/break-server.py   # 34 breaks, all 34 caught
python scripts/break-writer.py   # 13 breaks, all 13 caught
```

Each campaign edits one file in place, runs each expected test in a process of its own, and restores the file on the way out — including on error, so a campaign that left the tree modified could not be mistaken for one that found a bug. A break that fires nothing is reported as a hole, and a hole is either a missing test or a guard whose justification was wrong. Both are worth knowing before a judge finds them.

Three of the ninety are the reason the campaigns are run rather than read. Recomputing the SETTINGS-acknowledgement deadline on each read passes the silent-peer test and still lets a peer hold a connection open for ever. Taking the connection slot after `Accept` instead of before it leaves a server that honours its bound and still spends a descriptor and a handshake per refused peer. Dropping the backoff reset after a successful accept leaves a server that recovers from a rough patch on paper and carries a one-second pause before every connection for the rest of the week. None of the three is visible in a green suite.

Four breaks are detected as a panic rather than as a named failure, and the harness reports those separately rather than rounding them up: a missing `sync.Once` announces itself as `close of closed channel`, and there is nothing better to expect. Two guards in `internal/server/server.go` have no break at all, because both cover interleavings a test cannot schedule; `scripts/break-server.py` names them and says why.

## Build

```bash
bash scripts/gate.sh          # or: make gate
bash scripts/build.sh         # or: make build   -> bin/zdh
bash scripts/build.sh --verify # two builds, identical SHA-256
```

The reproducible build is:

```bash
CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o bin/zdh ./cmd/zdh
```

`-buildvcs=false` is the flag that is usually missing: without it Go stamps the git commit and working-tree state into the binary, and two builds of identical source at different commits differ. Toolchain is pinned to **go1.26.7** on both authors' machines with `GOTOOLCHAIN=local`, because the compiler version is baked into the binary. `go.mod` declares `go 1.24` so that any Go 1.24 or newer toolchain can build the project.

The `Makefile` only delegates to `scripts/*.sh`. Git Bash on Windows ships no `make`, so the authors run the scripts directly while a judge on Linux can run `make gate`; both execute the same code, so there is no second implementation to drift.

## Why not `net/http`

Using it would answer the question the project is asking. `net/http` has spoken HTTP/2 since Go 1.6, so importing it would make this a wrapper around the implementation it exists to replace, and the hackathon's own rules name `golang.org/x/net/http2` as banned. Refusing `net/http` is a self-imposed constraint stricter than the rules require, and it is enforced mechanically rather than by intention: check 6 above.

## Authors

Two-person entry, split so that neither author's files overlap the other's.

- **Manas Choksi** ([@choksi2212](https://github.com/choksi2212)) — framing, connection lifecycle, streams, flow control, request semantics, TLS/ALPN, hardening, build and conformance tooling.
- **Mihir** — HPACK (RFC 7541): integer and string primitives, Huffman coding, static and dynamic tables, and the attack harness.

The split is visible in `git log`: development happened on the `manas` and `mihir` branches, which merge here at completion.

## License

MIT — see [LICENSE](LICENSE).
