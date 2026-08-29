# zdh

`zdh` is an HTTP/2 server written against the Go standard library only. **It does not import `net/http`.** Go's standard library already contains an HTTP/2 implementation; this project deliberately does not use it. Frames are read and written directly on a `net.Conn` per RFC 9113, and header compression is a from-scratch HPACK implementation per RFC 7541. The full dependency graph is `net`, `crypto/tls`, `bufio`, `encoding/binary`, and the rest of the standard library — verify with `go list -deps ./...`. The build enforces this: `scripts/gate.sh` fails if `net/http` ever appears in the dependency graph.

Built for the **Zero Dependency Hackathon 2026**, Track C (Web & Network), in the 72 hours from 2026-08-28 18:00 UTC.

## Status

This section is kept honest as the build proceeds; nothing is claimed here before it works.

| Layer | State |
|---|---|
| Build gate, zero-dependency guards, reproducible build | working |
| Shared `internal/h2` contract | frozen |
| Frame layer (RFC 9113 §4, §6) | working — all 10 frame types, 198 tests, 5 fuzz targets |
| Connection timeouts and peer bounds (`internal/limits`) | working — six timeouts, 36 tests; the reset bucket is not yet wired to a connection |
| Connection lifecycle, SETTINGS, PING, GOAWAY | working — 75 tests, and 65 guards each observed failing |
| Accept loop, connection bound, graceful shutdown | working — 28 tests, and 38 guards each observed failing |
| Streams and flow control (§5) | working — 151 tests, and 223 guards each observed failing; both halves of flow control are wired to the stream table, and none of it is reachable from `cmd/zdh` |
| HPACK (RFC 7541) | in progress, separate author |
| Request semantics (RFC 9113 §8) | working — 70 tests, and 132 guards each observed failing |
| Response header encoding (§8.3, §6.10, §6.5.2) | working — 30 tests, and 80 guards each observed failing; the per-stream body writer and the static file handler are not started |
| Self-signed certificate generation (`internal/certgen`) | working — 46 tests, and 39 guards each observed failing |
| TLS 1.2/1.3, ALPN, RFC 9113 §9.2 cipher policy | working — 24 tests, and 31 guards each observed failing |
| Browser demo | not started |
| h2spec conformance score | not yet run |

Every count above is a top-level test function, which is what `go test -list '.*' ./...` prints: a table-driven test counts once rather than once per case, so the number is one command away from being checked rather than one convention away from being argued about.

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
python scripts/break-conn.py     # 51 breaks, all 51 caught
python scripts/break-server.py   # 38 breaks, all 38 caught
python scripts/break-tls.py      # 31 breaks, all 31 caught
python scripts/break-writer.py   # 14 breaks, all 14 caught
python scripts/break-certgen.py  # 39 breaks, all 39 caught
python scripts/break-flow.py     # 39 breaks, all 39 caught
python scripts/break-sender.py   # 53 breaks, all 53 caught
python scripts/break-stream.py   # 16 breaks, all 16 caught
python scripts/break-table.py    # 115 breaks, all 115 caught
python scripts/break-request.py  # 70 breaks, all 70 caught
python scripts/break-fields.py   # 62 breaks, all 62 caught
python scripts/break-response.py # 80 breaks, all 80 caught
```

Each campaign covers one Go package — usually one file, and for `internal/response` two — removes one guard at a time in place, runs each expected test in a process of its own, and restores every file on the way out, including on error, so a campaign that left the tree modified could not be mistaken for one that found a bug. A break that fires nothing is reported as a hole, and a hole is either a missing test or a guard whose justification was wrong. Both are worth knowing before a judge finds them.

The harness checks each campaign before it runs any of it, and refuses with a distinct exit status — 2 for a malformed campaign, 1 for holes — because the two need different readers. An anchor that matches no line removes nothing, so every test it named comes back green, and a typo in the campaign then reads as a suite full of holes. The preflight's four checks have all been observed refusing a deliberately malformed campaign, and observed leaving the target file byte-identical while doing it. `break-table.py`'s own first run was refused the same way, on an anchor that matched twice: a one-tab line is a substring of the two-tab version of itself, and the check counts substrings rather than lines because that is what the replacement will do.

The second refusal was the more valuable one, because nobody was looking for it. `break-conn.py` held a break anchored on `handleSettings`'s loop body, and that loop had since grown an error check — the connection began routing `SETTINGS_INITIAL_WINDOW_SIZE` to the stream layer, which gave `applySetting` an error to return. The anchor matched nothing, so the campaign was refused with exit 2 and nothing ran. Without the check it would have removed nothing, reported its test as green, and read as coverage of a rule it was no longer touching. Asking why then turned up the real gap behind it: the three routing behaviours added in that same commit had no breaks at all. This campaign is 51 rather than 45 because of what one stale anchor led to.

Three of the six hundred and eight are the reason the campaigns are run rather than read. Recomputing the SETTINGS-acknowledgement deadline on each read passes the silent-peer test and still lets a peer hold a connection open for ever. Taking the connection slot after `Accept` instead of before it leaves a server that honours its bound and still spends a descriptor and a handshake per refused peer. Dropping the backoff reset after a successful accept leaves a server that recovers from a rough patch on paper and carries a one-second pause before every connection for the rest of the week. None of the three is visible in a green suite.

`break-table.py` is the largest of the twelve at 115 breaks, and two of them are why the stream table is worth that many. Returning a refused stream's verdict *before* its header block is decoded leaves a server that is correct for every request a client sends until one of them is refused — and from that moment the HPACK dynamic table is one insertion behind the peer's, so every later request on the connection decodes into header fields nobody sent. §5.1 requires the compression state to be updated for a stream that is closed or refused, and that break is the demonstration of why. Moving the connection-window debit in `data` below the stream lookup is the same shape: flow control that is exactly right for every frame it accepts and silently wrong for every frame it refuses, after which the two ends disagree about the connection's credit by the size of whatever was dropped, permanently. Neither break produces a symptom anywhere near its cause.

Four of `internal/stream`'s tests exist because a break was worked out that nothing would have noticed — worked out while the campaign was being written, which is early enough that the run itself came back clean. Nothing observed that a *refused* stream still spends its identifier, though the code claims it in as many words. Nothing pinned which of §5.1 and §8.1 answers a trailer section that breaks both. Every trailer test sent END_HEADERS on the first frame, so the trailer path's own call into the reassembler could complete a block early and no test would see it. And §6.9.1's accounting rule was pinned for a DATA frame on a closed stream but not for one after END_STREAM, which left the whole state check free to move above the debit. A fifth test was weak rather than missing: the CONTINUATION-on-the-wrong-stream test only ever sent a *higher* identifier than the open block's, so `!=` could become `>` and fire nothing. It now runs both directions.

`break-stream.py` produced the third kind of hole on its first run, and it was in the campaign rather than in the code or the tests. The break that stops `recvEnd` from closing a stream this server has already finished sending on was expected to fail `TestAnEmptyDataFrameWithEndStreamClosesAnExhaustedStream` — but that test never sends END_STREAM of its own, so its stream is never in half-closed (local), which is the only state that break changes. Three other tests caught it. A name in a campaign's list is a claim about a specific test, and the harness holds it to that claim rather than settling for the break being caught by something.

`break-sender.py` is the first campaign against code that is shared between goroutines, and that changes what a break looks like. Everywhere else a removed guard makes a test report a wrong value; a third of these make a test report nothing at all. A writer parked on a condition variable nobody broadcasts to does not fail, it waits — and `go test`'s own timeout names the package, dumps every goroutine in it, and says nothing about which broadcast went missing. The harness scores that as `hang` and counts it as a hole, which is right: a break whose only symptom is a hang is a break nobody has diagnosed. So every wait in `sender_test.go` is bounded by a five-second deadline that says what it was waiting for, and each wake-up break fires a named test in five seconds instead of stalling one for sixty. That bound exists because of this campaign.

Four of its fifty-three came back as holes over two runs, and all four were the tests rather than the code — three of them the same mistake twice over. `Sender.waiting` is the count the tests wait on, and it deliberately does not drop between a broadcast and the woken writer re-acquiring the lock, so **no test can tell a parked writer from a waking one**. A writer already on its way back to the lock returns without needing the broadcast the break removed, so any test that let something else wake a writer before the event under test was scoring the runtime's scheduling rather than the guard. The two tests that drive eight writers in a loop have that shape by construction — their writers collect credit, or their own retirement, on re-entry — so they are no longer named on any break that removes a broadcast; what they are for is the arithmetic under contention. The deterministic tests each now park several writers with nothing at all reaching them in between, which is also what makes `Signal` fire rather than fire four times in five: Go's `sync.Cond` wakes waiters in the order they parked, so the test parks the one writer that can use what arrives last, behind three that cannot.

The fourth was a break whose premise turned out to be impossible, which is worth more than the break would have been. Reserve checks whether the connection has ended *before* it looks at the windows, so that a writer woken by both at once returns the reason rather than credit it cannot spend, and the test for it closed the connection and then granted the credit. It was asserting nothing: all three crediting methods return early once the connection has ended, so credit offered after `Close` is dropped rather than applied, and the stream window the break consulted was still empty. The arrangement that actually separates the two checks is a writer parked with credit on its stream window and none on the connection — the state where consulting the windows first finds something and still cannot use it.

The seam that campaign is about paid for itself the next time `break-table.py` ran. Thirteen of its breaks were refused outright by preflight, because the send half of flow control had moved out of the stream table and behind the `Sender`: ten were re-anchored to the one-line delegation that replaced the arithmetic and still name the same tests, and three had lost their subject rather than moved it — the connection send window's construction, the size a new stream's send window opens at, and whether the peer's `SETTINGS_INITIAL_WINDOW_SIZE` survives an empty table are all `break-sender.py`'s now, because that is where the code they were about now lives. Three took their place, and they are the ones the seam makes possible: a table that ignores the `Sender` it was handed and makes its own, a table that makes none at all, and a stream that leaves the table without its send window going with it. That last one fails a test that parks a goroutine in `Reserve` and resets the stream underneath it — the whole reason the send windows are not reachable from a `Stream`.

One break could not be re-anchored at all, and that is the return on the refactor rather than a gap in it. `data` debits the window we grant the peer, and the break that used to catch the wrong direction swapped `s.recv` for `s.send` — two fields of the same type, with the same methods, one line apart. A `Stream` no longer has a `send` field, so that edit is now a compile error instead of a mistake something has to notice; the same is true of the `SendWindow` accessor beside `RecvWindow`, which was broken against it and is gone with it. Both breaks were replaced with the nearest slip still expressible — debiting the connection's window twice, and an accessor that answers with a window that is not the stream's — and a typo that the compiler refuses is worth more than a break that catches it.

`break-request.py` and `break-fields.py` cover `internal/request` between them, and four of that package's tests were written or strengthened by designing them, before either script was run. §8.3.1's required-set check turned out to be untestable as written: removing it left the value checks below refusing the zero value, so `:path` still appeared in the reason and the assertion passed — it now asserts the words *no `:path`*, which only the required-set check produces. A tchar set narrowed to letters would have fired nothing, because every method in the suite was letters-only, so the unrecognised-method test now sends `M-SEARCH` and `BREW2`. The `+`, `-` and `.` half of §3.1's scheme grammar had no test at all, because the only non-HTTP scheme anywhere was `ftp`; it now sends `coap+tcp`, `view-source` and `z39.50r`. And the test that holds a stand-in `Host` to the authority rules found a bug in the code rather than a hole in itself: a `Host` carrying a userinfo was refused with a message blaming `:authority`, for a request that had no `:authority` at all. The checks are shared because the rules are shared, so the field name is now passed in and the message names whichever field actually carried the fault. A fifth test came out of the run: the same TE folding is enforced in a trailer section and in a header section by the same function, and only the header-section test sent `TrAiLeRs`.

Two of `break-fields.py`'s breaks came back as holes on their first run and neither was one. Go treats a variable that is only assigned as unused, so `return int64(n), nil` cannot be broken to `return 0, nil` and `if regular {` cannot be broken to `if false {`: the package stops compiling, and a break that does not compile fails every test it names for a reason that has nothing to do with the guard. The harness reports that as `build` rather than folding it into `pass`, which is what made both diagnosable in one reading — and the fix belongs in the campaign, which now discards the value explicitly. Any break that removes the last read of something has this shape.

`break-response.py` is the first campaign whose defects were all found before it ran, by reading what each named test asserts instead of trusting what it is called. Three of the eighty named a test that would not have failed. Clearing END_HEADERS on the HEADERS frame was pinned to the test that proves header blocks reach the wire unsplit by other streams, per §6.10 — but that test's blocks are 2·16384+1 octets and already span three frames, so END_HEADERS on the first of them is false to begin with and the break changes nothing that test looks at; it now names the two tests whose single-frame blocks do fire. A break called *the encoded block measured instead of the list* only moved the §6.5.2 check below the encode, which is a different mistake with a different symptom, so it became two: one that genuinely compares the compressed length against the peer's limit, and one honestly named for the reordering. And the missing length check in front of a `:status` value had no break at all. A hole that is the campaign's own fault reads as a weak suite, which is the one failure this apparatus cannot afford, so a break is now checked against the assertion it is supposed to trip rather than against the name above it.

Two of the eighty are index panics — an empty field name and an empty field value, each indexed by the check sitting just after the length guard the break removes — and both were expected as `crash` and came back as `fire`. The panic happens inside a subtest, so the framework prints the parent's `--- FAIL` banner before the process dies and the harness sees a test that named itself. `crash` is what a panic *outside* a subtest looks like; a table-driven suite converts most of them into ordinary failures for nothing. The harness also grew a second source file for this campaign, and the anchor check got stricter rather than looser as a result: the match is counted across every file in the package instead of within one, so an anchor occurring once in each of two files — unambiguous per file, ambiguous in fact — is refused now. `break-writer.py` was re-run against the generalised harness before `internal/response` had a single break written, so that the change and the campaign that motivated it were not first tested together.

Two more results are measurements rather than catches, and both stay in the scripts because the reasoning is what a reader would otherwise reconstruct wrongly. `beginTrailers` records END_STREAM on a trailer block and nothing can observe it, because the trailer path ends the stream unconditionally — which it may, since a trailer section without END_STREAM is already a stream error by the time it gets there. And `admit`'s self-dependency check reads the PRIORITY flag before the dependency it guards, which cannot matter: `internal/frame` leaves the dependency at zero when the flag is absent and rejects a dependency on stream 0 outright, so the two forms agree for every frame that can reach the check. Both are kept for what they say to a reader, not for what they guard.

Two of `break-certgen.py`'s findings were holes on the first run, and both were in the tests rather than in the code — which is the outcome the campaigns exist to produce. Dropping `serialNumber`'s error return changed nothing observable through the public API, because a dead entropy source fails the key generation too and both failures wrap the same underlying error; the guard is now tested by calling the unexported function directly. Dropping `cert.Leaf = leaf` also changed nothing, because `crypto/tls` has set `Leaf` itself in `X509KeyPair` since Go 1.23 — the comment in the code claiming otherwise was simply wrong. It sets it only while the `x509keypairleaf` GODEBUG is on, and that is off for any module declaring `go 1.22` or older, so the test now switches it off and asserts against this package instead of against the standard library.

Four of `break-certgen.py`'s breaks make a related point about what a passing handshake proves. Removing `ExtKeyUsage`, `IsCA`, `KeyUsageCertSign` or `BasicConstraintsValid` leaves every TLS handshake test in that package passing, because `crypto/x509` short-circuits verification when the leaf is itself in the client's root pool — `if opts.Roots.contains(c) { candidateChains = [][]*Certificate{{c}} }` — and a chain of one is never handed to `CheckSignatureFrom`. Those fields matter to a trust store verifying the certificate as the root it was imported as, so they are held by explicit field assertions and by a self-signature check, and by nothing else.

Two of `break-tls.py`'s findings were holes on the first run, and they turned out to be one mistake wearing two disguises: an assertion satisfied by something other than the thing it was written to check. Changing `ALPNProtocol` from `"h2"` to `"h2c"` left the end-to-end negotiation test passing, because that test dialled with `clientTLSConfig(t, ALPNProtocol)` — both ends read the same constant, so they agreed on `"h2c"` and negotiated it happily while every real client in the world would have stopped connecting. Discarding the error from `Handshake` left a refusal test passing, because it asserted that the log mentioned `"TLS handshake"` — which is also a substring of `"the client completed a TLS handshake without negotiating ALPN"`, so the connection failing one line further down logged prose that happened to contain the phrase. Both end-to-end tests now dial with the literal `"h2"`, and both refusal tests assert on `"TLS handshake: "` with the colon, which appears only in this package's own wrap of a handshake error.

A word on what the ALPN check is for, since `crypto/tls` looks as though it should make one unnecessary. It does not. Go's `negotiateALPN` treats a client offering only `http/1.1` against a server offering only `h2` as a case to let through rather than to reject: the handshake **completes**, with `ConnectionState().NegotiatedProtocol` set to the empty string (Go issue 46310, kept that way for clients predating ALPN). So `crypto/tls` does not keep HTTP/1.1 clients off an h2-only port — this server's own check does, and there is a test named for exactly that case. A client offering something neither side shares, such as `spdy/3`, does get the `no_application_protocol` alert from `crypto/tls` itself; the gap is specifically `http/1.1`.

Two results in that campaign are measurements rather than catches, and both are written into the scripts because the reasoning is what a reader would otherwise have to reconstruct. Clearing the handshake deadline once the handshake succeeds fires no end-to-end test, because every deadline here is re-armed before it is used — the read loop arms one before each `ReadFrame`, the writer arms one before each `Flush`, and `crypto/tls`'s own `Close` arms a five-second write deadline of its own — so the clearing is defence in depth against a future path that forgets, not a live guard. And deleting `runConn`'s handshake step altogether leaves a well-behaved client served correctly, because `tls.NewListener` returns a `*tls.Conn` that handshakes lazily on its first read and negotiates `h2` from the server's own `NextProtos` unaided. What the eager handshake buys is the two things a lazy one cannot: refusing a client that negotiated no protocol *before* a SETTINGS frame has been written to it, and timing the handshake on `Timeouts.TLSHandshake` instead of on the preface clock. Both of those fail when the step is removed. The happy path was named on that break in the belief that it would fail too — it was wrong, and the note records the belief as well as the correction, because the same reasoning would otherwise come back as "the eager handshake buys nothing, so move it into `Serve`".

Six breaks are detected as a panic rather than as a named failure, and the harness reports those separately rather than rounding them up to a pass: a missing `sync.Once` announces itself as `close of closed channel`, and a guard whose entire job is to name a nil argument announces itself as a nil dereference. For those there is nothing better to expect, but a panicking binary has not reported through the suite, so it is not signed off as one that did.

Six guards have no break at all, and each is named in the campaign that would otherwise have covered it rather than quietly left out. Two in `internal/server/server.go` cover interleavings a test cannot schedule. Two are in `conn.discard`, the teardown for a connection that never became one: removing its `c.w.Close()` deadlocks the very next line rather than failing a test — and a deadlock, which this harness reports as a hang and counts as a hole, is not a detection — while dropping the wait itself is unobservable, because `discard` runs before `Serve` and therefore before anything has been queued, so the writer's goroutine returns whether or not anyone waits for it. Two in `internal/certgen/certgen.go`: the private key's `0o600` mode, whose test skips on Windows where the ACL rather than the mode governs, and a `Close` that fails after a successful write, which needs a fault injector this project has no business growing.

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
