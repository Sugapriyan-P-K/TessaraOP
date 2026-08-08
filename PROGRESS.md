# TessaraOP — Progress & Handoff

Single source of truth for where this project stands and what to do next.
Written so a fresh session, or any engineer, can pick it up with zero prior
context.

**Last verified:** `go build ./...` clean, `go vet ./...` clean, **316 tests pass
under `-race`**, working tree clean.

---

## 1. What this project is

A multi-tenant ABAC / Zero-Trust **policy validation and decision engine** in Go,
built to be plugged into an existing policy flow rather than to replace one.

Two claims, and the evidence for each:

- **Fast**: microsecond decisions against large corpora, by sharding
  (tenant + scope) plus per-attribute indexing plus a verified decision cache.
  Evidence: layered benchmarks that attribute each effect separately.
- **Correct**: the indexed fast path is differentially tested against a naive
  linear-scan oracle on every run, under all three combining algorithms.

No external dependencies. No `go.sum`. Go 1.26.5.

---

## 2. Current state

### Layout

```
internal/
├── model/     types, operator semantics, condition trees, both combining tiers
├── attr/      117-attribute L3/L4/L7 registry with type + operator validation
├── bitset/    hybrid sparse/dense integer sets
├── matcher/   CIDR trie, domain trie, prefix/suffix tables, interval, numeric set
├── index/     sub-indexes over flattened rules, two intersection strategies
├── engine/    sharding, algorithm selection, decision cache
├── naive/     linear-scan oracle
├── indexed/   single-shard indexed evaluator (benchmark control)
├── bundle/    declarative JSON format + linter
├── ingest/    L3/L4/L7 adapters over stdlib parsers
├── genutil/   corpus generator with multi-rule policies and boolean trees
└── benchmark/ layered benchmarks
pkg/tessaraop/            public SDK: PDP, atomic reload, metrics, RequestBuilder
pkg/tessaraop/pdpserver/  HTTP PDP: native, forward-auth, OPA-shaped
cmd/tessaraop/            CLI: -demo -attrs -lint -export -interactive, bench
cmd/tessaraopd/           server binary: SIGHUP reload, graceful shutdown
examples/starter-bundle.json
```

~8,400 lines of source, ~6,200 of tests, 42 Go files.

### Data model

```
Policy (ID, TenantID, Scope, Priority, RuleAlgorithm)
  └─ Rule (ID, Effect, Priority, Obligations)
        └─ When: ConditionExpr — And / Or / Not / leaf Condition
```

**28 operators** across four families. String: `eq ne in nin contains ncontains
prefix nprefix suffix nsuffix regex nregex dnssuffix ndnssuffix`. Numeric:
`range nrange gt gte lt lte num_eq num_ne num_in num_nin`. Network:
`cidr ncidr`. Presence: `exists nexists`.

**Two-tier combining.** Tier 1 resolves a policy's matching rules under its own
`RuleAlgorithm` into one `Verdict`; tier 2 resolves policy verdicts under the
shard `Algorithm`. Both drive the same `Accumulator`, so the oracle and the fast
path cannot diverge.

**The AND-spine is the indexing boundary.** Only leaves reachable from a rule's
root through exclusively `And` nodes may build a filter. Leaves under `Or` or
`Not` contribute nothing and fall through to validation. This is the one subtle
correctness rule in the codebase — `DOCUMENTATION.md` §9.

### Request flow

```
Request
  ├─ decision cache (verified on hit, striped, order-independent hash)
  ├─ global shard → tenant-wide shard → (tenant, scope) shard
  └─ per shard: attribute filters → intersect → two-tier combination
```

Intersection has **two strategies**, chosen by seed size vs `n/32`: per-element
filtering (cost tracks survivors) and word-parallel bitmap AND (cost tracks
`n/64`). A test forces both paths on the same input and asserts identical output,
because only one runs per request.

---

## 3. Measured results

AMD Ryzen 5 5600H, 12 threads, Go 1.26.5. Sizes in **policies**; the indexed
universe is **rules**, about 2x that. 27% of generated rules carry an `OR` or
`NOT` the index cannot prune on.

| Corpus | Naive sharded | Engine | Speedup |
|---|---:|---:|---:|
| 10,000 | 10.1 µs | **3.2 µs** | 3.2x |
| 100,000 | 212 µs | **4.1 µs** | **51x** |
| 1,000,000 | 2.07 ms | not re-measured | — |

Zero allocations per request in steady state.

Unsharded (index in isolation): 10k — naive 108 µs vs indexed **25.9 µs**;
100k — naive 99 µs vs indexed 206 µs.

**Not re-measured after the rule restructure**, and therefore omitted rather than
carried forward: the 1M sharded row, cache hit latency, multi-core throughput,
whale-shard tail latency, and index build time and memory. Reproduce with
`go test ./internal/benchmark/ -run XXX_NONE -bench . -benchmem`. **This is the
highest-value loose end** — see §6.

---

## 4. What was done in the last two sessions

Two local commits. **Nothing has been pushed** — see §5.

### `8a55e9f` — Policy → Rule → ConditionExpr, plus the full L3/L4/L7 catalog

Restructured from flat `[]Condition` to rules holding boolean trees. Operators
14 → 28. Added `internal/attr`. Reworked the index so the atomic unit is a rule,
with positions in policy order so ascending candidates group contiguously by
policy. Two-tier evaluation in engine, naive and indexed. genutil rewritten to
emit multi-rule policies with real `Or`/`Not` trees and L3/L4/L7 attributes.
Tests 120 → 197.

Fixed a latent under-inclusiveness bug: `ne` indexed every value as rejected
while `Condition.Matches` consults only `Values[0]`, so a rule that genuinely
matched could be filtered out.

Deleted the stale root `main.go`, a pre-rebuild leftover that no longer compiled.

### `d1fd047` — the GTM integration surfaces

`internal/bundle` (JSON format + 28-check linter), `pkg/tessaraop` (SDK with
atomic hot reload and metrics), `internal/ingest` (stdlib-only L3/L4/L7
adapters), `pkg/tessaraop/pdpserver` + `cmd/tessaraopd` (four endpoint shapes),
CLI `-lint` / `-export`, `examples/starter-bundle.json`. Tests 197 → 316.

Also fixed the **word-parallel intersection gap**: a 200k-rule flat shard cost
5.04 ms and 10.6 KB per request — 25x slower than a linear scan. Now 206 µs and
20 B.

Two live bugs found by the new tests:

1. `tls.version_num` encoded SSLv3 as `30`, above TLS 1.3's `13`, so a `>= 12`
   version floor **accepted SSLv3** — the exact protocol such a rule exists to
   reject. Now SSLv3 is `3`, unknown is `0`.
2. The forward-auth handler applied the transport peer address *after* resolving
   forwarded headers, so behind a proxy the proxy's own address overwrote the real
   client's and a client blocklist never fired.

---

## 5. Environment constraints (read before assuming anything)

**Local commits only.** The user has stated explicitly that pushing is not
possible and that changes stay local. Do not attempt `git push`.

**Go toolchain**: installed this session via
`winget install GoLang.Go` (1.26.5) at `C:\Program Files\Go\bin`. It may not be
on `PATH` in a fresh shell; prefix if needed.

**`-race` on Windows needs a 64-bit gcc.** A 32-bit MinGW at `C:\MinGW\bin` is on
`PATH` and fails with *"64-bit mode not compiled in"*. A working 64-bit toolchain
was installed to:

```
C:\Users\sugap\AppData\Local\Microsoft\WinGet\Packages\
  BrechtSanders.WinLibs.POSIX.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\mingw64\bin
```

Put that ahead of `C:\MinGW\bin` on `PATH` to run `go test -race`.

**PowerShell gotchas that cost time here:**

- `go test ... -bench=.` silently loses the flag through the tool's argument
  handling. Pass args as an array: `& go @('test','./p','-bench','.')`.
- The `--%` stop-parsing token swallows a following `>` redirect.
- `Get-Content` / `Set-Content` round-tripping a UTF-8 file without a BOM mangles
  non-ASCII (em-dashes became `â€”`). Use
  `[System.IO.File]::ReadAllText/WriteAllText` with
  `New-Object System.Text.UTF8Encoding($false)`.
- `>` redirection writes a BOM. The bundle loader now skips a leading BOM, but
  prefer `WriteAllText` for generated files.

---

## 6. What to do next, in priority order

### 1. Re-measure the full benchmark matrix

The single most valuable loose end, because the README and `DOCUMENTATION.md`
currently say "not re-measured" for five figures. Needed:

```bash
go test ./internal/benchmark/ -run XXX_NONE -bench . -benchmem -benchtime=1s
```

That covers `BenchmarkEngine` at 1M, `EngineCached`, `EngineParallel`,
`WorstCaseShard` and `IndexBuild`. The 1M cases take minutes to build a corpus, so
run it detached. Then update the tables in `README.md` §Measured results and
`DOCUMENTATION.md` §19, and delete the "not re-measured" notes.

Expect **build memory to have grown** — the rule count is roughly 2x the policy
count now.

### The five-phase roadmap

`COMPARISON.md` establishes where TessaraOP sits against Cedar, OPA, OpenFGA and
Casbin, and which authorization models are actually supported. These phases are
ordered by the gap each closes, not by size.

| Phase | Work | Gap closed |
|---|---|---|
| **1** | Role/group hierarchy with transitive closure, resolved at ingest | RBAC hierarchy (High) — `subject.role` is flat today |
| **2** | `Explain` — non-short-circuiting, built on `internal/naive`, differentially tested against `Evaluate`, with attribute redaction | Cedar + OPA parity; unblocks every POC |
| **3** | The 4 missing XACML algorithms + obligation union semantics | Procurement conformance; removes the non-canonical-attribution caveat |
| **4** | ReBAC **resolver interface** + OpenFGA / SpiceDB adapters | The Critical gap, without becoming stateful |
| **5** | BDD/MTBDD compilation → subsumption, conflict, reachability | Cedar's differentiator |

Phases 1 and 4 both feed the same design: resolve facts *outside* the engine and
hand them in as attributes. Neither touches `internal/index`, `internal/model` or
the hot path, which is why neither risks the performance or correctness properties
already established. `COMPARISON.md` §4 has the reasoning.

### 2. Tuple space search

The identified answer to the one remaining performance limitation: a large *flat*
shard, where the index still trails a short-circuiting scan by 2.1x at 100k
policies. Group rules by *which attributes they constrain*, then hash the
request's values per group. This sidesteps the non-participant inflation that
makes the smallest available seed a large fraction of the shard.

The word-parallel path already reduced this from 25x to 2.1x, so this is an
optimization rather than a rescue — it sits below the five phases above.

### 3. Importers from existing policy formats

Started and then deprioritized in favour of `COMPARISON.md`.
`internal/importer/importer.go` exists and is **untracked and unwired** — it holds
the shared `Fidelity`/`Note`/`Report`/`Options` types, glob→operator translation,
and the widening guard. Nothing imports it. Either finish it or delete it; do not
leave it half-wired.

The design decision worth keeping if it is resumed: **an import must fail by
default if any construct would widen access.** Dropping a constraint from a
*grant* silently broadens it and the bundle still lints clean; dropping a grant
causes a visible outage someone fixes. The two failure directions are not
symmetric, so the default must not be either.

Per-format assessment:

- **AWS IAM** — closest semantic fit. `IfExists` → `Or(Not(exists), cond)` and
  `Null` → `exists`/`nexists` translate *exactly*. Widens on `${aws:...}`
  variables, `ForAllValues:`/`ForAnyValue:`, unknown condition keys.
- **Kubernetes NetworkPolicy** — maps well onto L3/L4, but **its implicit
  default-deny for selected pods must be materialized as an explicit catch-all
  DENY**, or the import is dramatically more permissive than the source. Label
  selectors need live cluster state.
- **Envoy RBAC** — best structural fit; `and_rules`/`or_rules`/`not_rule` map 1:1
  onto `And`/`Or`/`Not`. `action: ALLOW` needs the same catch-all materialization.
- **OPA/Rego** — only a recognizable subset can be translated, and a partial
  translator invites silent widening on what it does not understand. The
  OPA-compatible *endpoint* is the better migration story.
- **Cedar** — closest in spirit; `when`/`unless` map onto `And`/`Not`.

### 4. Incremental index updates

Adding a policy rebuilds its shard. Sharding already bounds the blast radius;
per-shard rebuild on write is the next increment. Matters once tenants edit
policies live, which is after Phase 2.

### 5. Smaller items

- Build-time memory: sub-index construction can stream rather than buffer.
- `cmd/tessaraopd` has no tests of its own; the server package is well covered but
  the flag wiring and SIGHUP path are not.
- The linter's hostname heuristic for `suffix` is deliberately loose; it may want
  a real public-suffix check if false positives annoy anyone.

---

## 7. Things not to re-litigate

Decisions already made deliberately, with the reasoning recorded in
`DOCUMENTATION.md`. Changing any of them is fine, but do it knowingly.

- **JSON, not YAML** — keeps dependencies at zero. §15.
- **The engine consumes named, pre-parsed attributes** and never decodes packets
  or HTTP bytes. §16.
- **Token signature verification is the caller's job.** §16.
- **`suffix` and `dnssuffix` are separate operators.** §3.
- **Unregistered attribute names are a linter warning, not an error**, by default.
  §15.
- **An empty policy set is an error, not a deny-everything posture.** §14.
- **`/v1/authz` never returns 5xx**, because those proxies fail open. §17.
- **`X-Forwarded-For` is ignored unless a trusted-hop count is given.** §16.
- **Cookie values require an allowlist.** §16.
- **Only the AND-spine is indexable.** §9.

Two further decisions recorded in `COMPARISON.md` rather than `DOCUMENTATION.md`:

- **ReBAC is integrated, not built.** A Zanzibar-style tuple store requires a
  database, which turns TessaraOP from a stateless drop-in component into a
  stateful service and loses the zero-dependency property. Hierarchy closure (one
  relation, transitive, no storage) is built natively in Phase 1; general
  relationship graphs are consumed through a resolver interface with adapters, so
  a native implementation later is a drop-in rather than a rewrite.
  `COMPARISON.md` §7.1.
- **No Casbin-style configurable effect expressions.** Deny-overrides can
  short-circuit only because it is order-independent, and the index yields
  candidates in arbitrary order. An arbitrary effect expression would force either
  sorting every candidate set — forfeiting short-circuiting — or letting
  enumeration order leak into decisions. Implement the remaining *standard* XACML
  algorithms instead. `COMPARISON.md` §3.2.

---

## 8. How to verify any of this yourself

```bash
cd D:\tessaraop
go build ./...
go vet ./...
go test ./... -race                  # 316 tests (needs 64-bit gcc, see §5)

go run ./cmd/tessaraop -demo         # policy walkthrough, incl. the two-tier case
go run ./cmd/tessaraop -attrs        # the 117-attribute registry
go run ./cmd/tessaraop -lint examples/starter-bundle.json
go run ./cmd/tessaraop -n 100000 -tenants 1000 -requests 6
go run ./cmd/tessaraopd -bundle examples/starter-bundle.json -addr :8181
```

Then, against the running server:

```bash
curl localhost:8181/readyz
curl -X POST localhost:8181/v1/decision -H 'content-type: application/json' \
  -d '{"tenant":"acme","attributes":{"subject.role":"admin"}}'
curl -i localhost:8181/v1/authz -H 'X-Tessaraop-Tenant: acme' -H 'X-Tessaraop-Role: viewer'
curl -X POST localhost:8181/v1/data/tessaraop -H 'content-type: application/json' \
  -d '{"input":{"tenant":"acme","scope":"network","transport.dest_port":22}}'
curl localhost:8181/metrics
```

All of the above was run and verified in-session.
