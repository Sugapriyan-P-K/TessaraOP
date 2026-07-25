# TessaraOP — Technical Documentation

Complete reference for the engine: what exists, how each part works, why it was
built that way, what it measures, and what it deliberately does not do.

**Status summary**

| | |
|---|---|
| Packages | 8 (+1 CLI) |
| Source | ~2,700 lines |
| Tests | ~2,400 lines, 120 tests, passing under `-race` |
| External dependencies | **none** — no `go.sum` |
| Go version | built and tested on 1.24.7 |

---

## Table of contents

1. [What is and is not implemented](#1-what-is-and-is-not-implemented)
2. [Data model](#2-data-model)
3. [Evaluation semantics](#3-evaluation-semantics)
4. [Architecture and request flow](#4-architecture-and-request-flow)
5. [Package reference](#5-package-reference)
6. [The candidate-set algorithm](#6-the-candidate-set-algorithm)
7. [Index structures](#7-index-structures)
8. [Sharding](#8-sharding)
9. [Decision cache](#9-decision-cache)
10. [Concurrency](#10-concurrency)
11. [Correctness strategy](#11-correctness-strategy)
12. [Performance](#12-performance)
13. [Limitations](#13-limitations)
14. [Roadmap](#14-roadmap)

---

## 1. What is and is not implemented

Stated plainly, because two items are commonly assumed to be present.

### Implemented

| Capability | Where |
|---|---|
| 14 operators across 4 families | `internal/model` |
| Deny-overrides / permit-overrides / first-applicable | `internal/model` |
| Obligations on decisions | `internal/model` |
| Hybrid sparse/dense integer sets | `internal/bitset` |
| CIDR radix trie | `internal/matcher/cidr.go` |
| DNS suffix trie (label-aligned) | `internal/matcher/domain.go` |
| Path prefix table | `internal/matcher/prefix.go` |
| Numeric interval table | `internal/matcher/interval.go` |
| Per-attribute sub-indexes + intersection | `internal/index` |
| Two-level sharding (tenant, scope) + global shard | `internal/engine` |
| Verified decision cache | `internal/engine/cache.go` |
| Linear-scan oracle | `internal/naive` |
| Multi-tenant corpus generator | `internal/genutil` |
| Layered benchmarks | `internal/benchmark` |
| CLI (demo / bench / interactive) | `cmd/tessaraop` |

### Not implemented

| Item | Status |
|---|---|
| **MTBDD / BDD / decision diagrams** | **Not started.** Zero lines. Appears only as a roadmap entry. |
| **RoaringBitmap** | **Not used.** No external dependency. See below. |
| Tuple space search | Not started — the highest-value next step |
| Incremental index updates | Not started — adding a policy rebuilds its shard |
| Policy conflict / redundancy detection | Not started (would fall out of MTBDD) |
| Policy DSL, parser, storage, network API | Out of scope — this is an evaluation core |

#### On MTBDD

Nothing exists. The idea is to compile each policy's boolean condition
structure into a shared multi-terminal binary decision diagram, so evaluation
becomes a single root-to-leaf walk whose depth is the number of *distinct
attributes* rather than the number of policies. Its appeal is not only speed:
because a BDD is canonical, two policies that are logically equivalent compile
to the same node, which gives conflict and redundancy detection as a byproduct.

Why it was not built: it is the largest single piece of work on the roadmap,
and it is not what the measurements point at. The remaining structural cost
(§13) is the non-participant term on a large flat scope, which tuple space
search addresses far more cheaply.

#### On RoaringBitmap

Not used, and no external dependency exists anywhere in the project.

`internal/bitset` implements a hybrid representation that borrows Roaring's
central idea — choose the storage form from the cardinality — without being
Roaring:

| | RoaringBitmap | `internal/bitset` |
|---|---|---|
| Partitioning | 16-bit chunks, one container each | single set, one representation |
| Sparse form | `[]uint16` array container | sorted `[]uint32` |
| Dense form | `[]uint64` bitmap container | `[]uint64` bitmap |
| Run-length form | run containers | none |
| Dependency | external | none |

The problem Roaring was originally meant to solve here — a dense bitset making
every operation cost `O(N/64)` regardless of survivors — is solved. Real
Roaring would still win where policy IDs cluster into dense regions separated
by sparse gaps, since per-chunk containers adapt locally while this adapts
globally.

---

## 2. Data model

`internal/model/model.go`

### Policy

```go
type Policy struct {
    ID          string
    TenantID    string     // shard key, part 1
    Scope       string     // shard key, part 2 ("" = tenant-wide)
    Effect      Effect     // ALLOW | DENY
    Priority    int        // used by FirstApplicable only
    Conditions  []Condition // implicitly AND-ed
    Obligations []string   // e.g. require_mfa, audit_log
}
```

A policy with zero conditions matches everything — that is how catch-all
grants and backstop denies are expressed.

### Request

```go
type Request struct {
    TenantID   string
    Scope      string
    Attributes map[string]string      // strings: role, action, domain, path
    Numeric    map[string]float64     // risk_score, time.hour
    IPs        map[string]netip.Addr  // source_ip
}
```

Values are split by type so the hot path never parses or casts. `netip.Addr`
is comparable and allocation-free, unlike `net.IP`.

### Operators

Fourteen operators in four families. The family determines the index structure,
which is the whole reason the split matters.

**Set family** — reads `Attributes`

| Operator | Meaning |
|---|---|
| `eq` | equals `Values[0]` |
| `ne` | not equal to `Values[0]` |
| `in` | member of `Values` |
| `nin` | not a member of `Values` |
| `exists` | attribute is present |
| `nexists` | attribute is absent |

**Numeric family** — reads `Numeric`

| Operator | Meaning |
|---|---|
| `range` | `Min <= v <= Max` |
| `gt` | `v > Min` |
| `lt` | `v < Max` |

**Network family** — reads `IPs`

| Operator | Meaning |
|---|---|
| `cidr` | address inside any prefix in `Prefixes` |
| `ncidr` | address outside every prefix |

**Name family** — reads `Attributes`

| Operator | Meaning |
|---|---|
| `dnssuffix` | host equals, or is under, any domain in `Values` |
| `prefix` | path byte-starts-with any string in `Values` |

### Absent attributes fail closed

Every operator except `nexists` returns false when the attribute is missing —
**including the negations**. `subject.role != admin` does *not* pass for a
request carrying no role at all.

This is the safe reading and it is not the only possible one; XACML would call
the missing case *indeterminate*. Fail-closed was chosen because the
alternative lets a caller acquire access by *omitting* a field, which is the
easier mistake to exploit. The index mirrors this exactly (§6), or the fast
path and the oracle would disagree.

Tested by `TestCondition_AbsentAttributeFailsClosed`, which asserts the
property across all twelve applicable operators.

---

## 3. Evaluation semantics

### Combining algorithms

| Algorithm | Rule | Order-independent | Can short-circuit |
|---|---|---|---|
| `deny-overrides` *(default)* | any deny wins, else any allow, else deny | **yes** | yes, on first deny |
| `permit-overrides` | any allow wins, else any deny, else deny | yes | no |
| `first-applicable` | highest `Priority`, ties by lowest ID | no | no |

Default-deny throughout: no match at all means denied.

### Why deny-overrides is the default

The security argument is familiar — it fails safe, and adding a deny can only
reduce access. The engineering argument is what actually shaped the codebase:

> **Deny-overrides is order-independent, and that is what makes indexing
> sound.** The index yields candidates in whatever order the underlying sets
> enumerate — an implementation detail of bitset iteration. Under an
> order-sensitive algorithm that arbitrary order would leak into the decision.

`first-applicable` *is* order-sensitive, which is why it must examine every
candidate and sort by priority. It costs more, and that cost is a direct
consequence of the semantics, not an implementation weakness.

Asserted by `TestDenyOverrides_IsOrderIndependent`, which evaluates the same
policies in two different orders and requires the same decision.

### MatchedPolicyID is a justification, not a canonical answer

Under the overrides algorithms, several policies can match with the winning
effect. Those algorithms say nothing about which to credit, and the engine
reports whichever it reached before short-circuiting.

Scanning the rest to pick a canonical winner would forfeit short-circuiting and
change no decision, so it does not. **`first-applicable` is the exception** —
it must see everything anyway, and its priority-then-ID ordering makes the
reported policy fully deterministic. Use it where audit trails need stable
attribution.

This shaped the test suite: the differential tests verify that the credited
policy is in scope, genuinely matches, and carries the winning effect — rather
than asserting equality with the oracle's equally arbitrary pick.

### The Accumulator

Both evaluators drive the same `model.Accumulator`, so combining semantics
cannot drift between the slow path and the fast one.

```go
acc := model.NewAccumulator(alg)
for each candidate policy p {
    if p.Matches(req) {
        acc.Consider(&p)
        if acc.CanShortCircuit() { break }
    }
}
acc.SetScanned(n)
decision := acc.Resolve()
```

---

## 4. Architecture and request flow

```
Request{tenant, scope, attributes, numeric, ips}
   │
   ├─► Decision cache ─── hit? ──► return (≈1.1 µs, key fully verified)
   │                                     
   ├─► Global shard        platform denies: blocklists, kill switches
   │      └─ short-circuit on deny under deny-overrides
   ├─► Tenant-wide shard   rules spanning the whole customer
   └─► (tenant, scope) shard
          │
          ├─ 1. collect one filter per attribute sub-index
          ├─ 2. order filters cheapest-first (insertion sort)
          ├─ 3. seed the candidate list from the most selective filter
          ├─ 4. filter that list in place against the rest
          └─ 5. run Policy.Matches on survivors
   │
   └─► Decision{allowed, effect, matchedID, obligations, scanned}
```

Global is evaluated first because it is both the smallest shard and the most
likely to end evaluation immediately.

---

## 5. Package reference

| Package | Src | Test | Responsibility |
|---|---:|---:|---|
| `model` | 453 | 285 | Types, operator semantics, combining algorithms |
| `bitset` | 279 | 240 | Hybrid sparse/dense integer sets |
| `matcher` | 566 | 358 | CIDR trie, DNS trie, prefix table, interval table |
| `index` | 573 | 352 | Per-attribute sub-indexes, candidate intersection |
| `engine` | 417 | 443 | Sharding, algorithm selection, decision cache |
| `naive` | 50 | 133 | Linear-scan oracle |
| `indexed` | 45 | 115 | Single-shard evaluator (benchmark control) |
| `genutil` | 329 | 146 | Synthetic multi-tenant corpus generator |
| `benchmark` | — | 263 | Layered benchmarks |

Dependency direction is strictly downward — `model` imports nothing internal;
`engine` sits at the top.

```
engine ──► index ──► matcher ──► bitset
   │         │                     ▲
   └─────────┴──────► model ───────┘
```

### Why `indexed` exists alongside `engine`

`indexed` applies indexing *without* sharding. It is the benchmark control:
comparing naive→indexed isolates what the index alone buys, and indexed→engine
isolates what partitioning buys. Keeping the two effects separable is what
allows §12 to attribute the speedup honestly rather than reporting one blended
number — and it is what surfaced the finding that indexing alone is a *loss*.

---

## 6. The candidate-set algorithm

The core of the system. `internal/index/index.go`.

### Per-sub-index pass sets

Each attribute contributes one or more sub-indexes, one per operator family
present on it. For a request value `v`, sub-index `S` yields the policies that
pass it:

```
pass_S(v) = notParticipating_S ∪ accepted_S(v)
```

**The `notParticipating` term is the correctness keystone.** A policy that
places no condition of kind `S` on that attribute must never be filtered out by
`S`. Get it wrong and the engine returns confidently wrong answers rather than
merely slow ones — there is no crash to catch it.

A policy survives only if it passes *every* sub-index it participates in, so
the candidate set is the intersection across all of them.

### Negation collapses to something cheaper

For negated operators (`ne`, `nin`, `ncidr`), the accepted set is
`participating \ rejected`. Substituting:

```
pass_S(v) = notParticipating ∪ (participating \ rejected)
          = ALL \ rejected_S(v)
```

Because `notParticipating ∪ participating = ALL`. So **a negation needs no
complement at query time** — it is simply "reject these, pass everything else."
That makes negations cheap post-filters rather than per-request set
differences.

### The intersection: two strategies, chosen per request

v1 AND-ed dense bitsets pairwise, so every step cost `O(N/64)` no matter how
few candidates survived. At a million policies that dominated everything and
the speedup collapsed to 1.1x.

Replacing that with per-element filtering fixed the small-shard case but
created a new one: on a large shard the seed is a sizeable fraction of the
shard, and probing each element against every filter became the dominant cost
(168 µs on a 22k-policy shard).

Neither strategy dominates, so the engine costs both and picks:

```
per-element   ≈ seed × filters          cost tracks the seed
word-parallel ≈ 2 × filters × words     cost is independent of the seed
```

Equating them puts the crossover at a seed of about **`n/32`**. Below it the
seed is small enough that probing wins and the accumulator's fixed per-word
cost would be wasted; above it the seed is dense enough that word parallelism
pays for itself. Measured effect on the 1M whale shard: **168 µs → 7.9 µs.**

Both paths are pinned together by `TestIntersectStrategies_Agree`, which runs
each directly over the same randomized corpora and requires identical output —
otherwise a divergence would surface only on inputs that happen to cross the
threshold.

#### Per-element path

```go
// 1. Order filters cheapest-first.
//    Insertion sort, not sort.Slice: the list is short and near-sorted,
//    and sort.Slice's closure escapes to the heap on every request.
insertionSortByEstimate(filters)

// 2. Seed from the most selective *enumerable* filter.
//    Negative filters can only reject, never enumerate, so they are
//    never seeds. With no positive filter, the seed is the whole shard.
cands = filters[best].pass.AppendMembers(cands[:0])

// 3. Filter in place. The list only ever shrinks.
for each remaining filter f {
    w := 0
    for _, c := range cands {
        if f.allows(c) { cands[w] = c; w++ }
    }
    cands = cands[:w]
    if len(cands) == 0 { break }
}
```

Cost tracks the surviving candidate count rather than the corpus size.

#### Word-parallel path

```go
w := sc.words(s.n)
clearWords(sc.acc)
filters[best].pass.OrInto(sc.acc)      // seed the accumulator

for each remaining filter f {
    clearWords(sc.tmp)
    if f.kind == filterNegative {
        f.reject.OrInto(sc.tmp)
        for k := range acc { acc[k] &^= tmp[k] }   // reject
    } else {
        f.pass.OrInto(sc.tmp)
        for k := range acc { acc[k] &= tmp[k] }    // intersect
    }
}
cands = bitset.AppendWordMembers(cands[:0], sc.acc)
```

Intersects 64 policies per operation. The lazy `MatchSet` union is folded into
a scratch word buffer once per filter rather than probed once per candidate.
Both buffers live in `Scratch` and are reused, so this path allocates nothing
in steady state.

Padding bits above `n` in the final word are never set, because only real
members are ever OR-ed in — `TestIntersectWords_HandlesPartialFinalWord` pins
that for shard sizes that are not multiples of 64, since a stray padding bit
would enumerate a policy index that does not exist.

**Every filter is applied — there is no early bail below some candidate
count.** An earlier revision skipped filtering under 16 candidates on the
theory that bookkeeping outweighed the benefit. That was wrong twice over: a
filter pass over *k* candidates is *k* `Contains` probes, cheaper than letting
those *k* policies run their full condition lists in validation; and bailing
made pruning depend on the arbitrary order filters happened to sit in, which
made behaviour untestable. Removing it simplified the code and improved
pruning.

### Absent-attribute pruning

If a request omits an attribute entirely, policies requiring it cannot match,
so the index prunes them rather than deferring to validation. This is pure
selectivity gain and it is why `requiresPresent` / `allowsAbsent` exist.

---

## 7. Index structures

`internal/matcher`

### MatchSet — lazy union in a fixed array

Nested matches produce unions: an address inside `10.0.0.0/8` *and*
`10.4.0.0/16` matches both prefixes' policy sets. Eagerly OR-ing them would
allocate per filter per request.

`MatchSet` holds up to 8 constituent sets in a **fixed array** (spilling to a
slice past that) and evaluates the union lazily via `Contains`. Only the single
most selective MatchSet is ever materialized. Moving from a slice to a fixed
array removed the last hot-path allocations — 27 allocs/op → **0**.

`EstimatedCardinality` sums member cardinalities, an *upper bound* since sets
may overlap. That is fine: it only orders intersections, so a poor estimate
costs a little speed and never correctness.

### CIDRIndex — binary radix trie

Walks address bits, collecting the policy set at **every terminal node passed
through** — because an address in `10.0.0.0/8` is also in `10.4.0.0/16`, and
every enclosing prefix matches, not just the longest.

Walk depth is bounded by address width (32 or 128), independent of how many
blocks the corpus holds. Addresses are canonicalized with `Unmap()` so
`10.0.0.0/8` and `::ffff:10.0.0.0/104` land in the same trie. Prefixes are
`Masked()` on insert, so `10.4.2.7/8` normalizes to `10.0.0.0/8` instead of
landing in the wrong subtree.

Address buffers are stack-resident `[16]byte` arrays passed by pointer — an
earlier version used `addr.As4()[:]`, whose slice-of-local escapes to the heap
on every lookup.

### DomainIndex — reversed-label trie

Labels are walked right to left: `api.admin.acme.com` visits
`com → acme → admin → api`, collecting a set at every terminal.

**This structure enforces label alignment for free, which is a security
property, not a convenience.** `strings.HasSuffix("evilacme.com", "acme.com")`
is *true* — a naive suffix check hands a lookalike domain the authorization
scoped to the real one. That is a real and frequently exploited bypass. The
trie walks `com → evilacme` and never reaches the `acme` node. `model.MatchDNSSuffix`
applies the same label-boundary rule so the index and validation agree.

Label iteration uses index arithmetic over string slices, which share backing
memory — no allocation, no `strings.Split`.

Hosts are expected pre-lowercased by the ingest layer, as any gateway does;
the hot path does not allocate to case-fold.

### PrefixIndex — distinct-length probe table

Records which prefix *lengths* actually occur, then probes only those. Real
corpora reuse a handful of path roots (`/api`, `/api/v2`, `/api/v2/admin`), so
a lookup is a few map probes rather than one per character.

Semantics deliberately match `model.OpPrefix` exactly — a raw byte prefix, so
`/api/v2/admin` *does* match `/api/v2/adminfoo`. An index stricter than
validation would wrongly drop matching policies. (A segment-aligned prefix
would be the safer *policy* semantic; changing it would require changing both
sides together.)

### IntervalIndex — distinct-range table

Groups policies by *distinct* range rather than building a per-value or
per-bucket structure, because of what real corpora look like: a million
policies referencing time-of-day windows still use only a handful of distinct
windows (business hours, after hours, maintenance), and risk-score conditions
collapse onto a few bands.

Ranges are sorted by lower bound, so a lookup binary-searches the cut where
`min <= v` and scans that prefix testing `max >= v`. `gt`/`lt` arrive as ranges
with an infinite end and need no special case.

Past `MaxDistinctIntervals` (4096) the index sets `Degraded` and reports
nothing, and the caller falls back to treating every participant as a
candidate — conservative, still correct, just less selective.

---

## 8. Sharding

**This is what buys the microseconds.** Not the indexing.

Two levels plus a global shard:

```
global shard            evaluated for every request (blocklists, kill switches)
tenant-wide shard       Scope == "" — spans the whole customer
(tenant, scope) shard   the request's own scope
```

Tenant alone is not a fine enough partition. Corpora are heavily skewed — one
whale customer and a long tail — and a single large customer can hold a
six-figure policy count that no amount of indexing makes fast. Production
systems partition the same way: Zanzibar by namespace, IAM by principal and
resource, Envoy RBAC per listener.

Measured effect on the largest tenant at 1M policies:

| | In scope | Latency |
|---|---:|---:|
| Tenant sharding only | 102,220 | 1.80 ms |
| + scope sharding | 21,935 | **168 µs** |

`Request.InScope(p)` is the single definition of reachability, used by both the
oracle and the engine — otherwise the differential tests would silently compare
different policy sets.

---

## 9. Decision cache

`internal/engine/cache.go`. Optional, off by default (`CacheSize: 0`), because
benchmarks should measure the index rather than traffic locality.

Striped, direct-mapped: 64 stripes each with an `RWMutex`, power-of-two slots
selected by mask.

**Every hit is verified by comparing the full request against the stored key,
never by trusting the hash.** This matters more than in an ordinary cache: a
hash collision in an authorization path would silently hand one subject another
subject's decision. The hash only picks a slot; the comparison decides the hit.

Requests are hashed **order-independently** — per-entry hashes are summed
rather than chained — because Go randomizes map iteration order, so a chained
hash would put the same logical request in different slots on different calls
and the cache would never hit.

Stored keys are **owned copies**, not aliases. Callers routinely reuse request
maps; retaining a reference would let a later mutation corrupt the stored key.
`TestCache_DoesNotAliasCallerMaps` covers exactly this.

Replacement is direct-mapped overwrite rather than LRU, keeping lookups to one
striped read lock with no list bookkeeping on the hot path.

---

## 10. Concurrency

One engine serves many request goroutines safely:

- **Shards are immutable** after construction — no locking on the read path
- **Scratch buffers come from a `sync.Pool`**, one per goroutine, which is what
  keeps the steady state allocation-free
- **The cache stripes its locks** across 64 mutexes

Measured: 2.0 µs/op across 4 cores ≈ **513k req/s**, versus 4.9 µs
single-threaded — near-linear scaling.

`TestConcurrentEvaluation` runs 8 goroutines × 5 passes × 400 requests against
one engine and compares every decision to the serial answer. The whole suite
passes under `-race`.

Note: `indexed.Evaluator` is **not** concurrency-safe — it owns a single
scratch buffer. It is a benchmark control, not a serving path.

---

## 11. Correctness strategy

The engine is far too intricate to trust by inspection. Correctness rests on
four things instead.

### 1. Shared semantics

Both evaluators route every match through `Condition.Matches` and resolve
through the same `Accumulator`. The fast path has no second copy of the rules
to drift from.

### 2. The index is a pre-filter only

It may be over-inclusive but never under-inclusive, and survivors always face
the real match logic. **A bug in an index costs performance, not correctness.**

This is asserted directly rather than assumed:
`TestCandidates_NeverExcludesAMatchingPolicy` drives 200 randomized corpora ×
20 requests spanning every operator family, and for each request checks every
policy that genuinely matches also appears in the candidate set.

### 3. Differential testing

Randomized corpora through both evaluators under all three algorithms. Where
the credited policy is not canonically defined (§3), the test verifies it names
a policy that is in scope, actually matches, and carries the winning effect —
rather than asserting a determinism the semantics do not provide.

### 4. Adversarial and concurrent cases

Missing attributes, unknown tenants, empty requests, lookalike domains, plus
8-goroutine concurrent evaluation under `-race`.

### Security-specific tests

| Property | Test |
|---|---|
| Lookalike domains cannot inherit a grant | `TestDomain_RejectsUnalignedSuffix` |
| Cache never serves across requests | `TestCache_NeverServesAcrossDifferentRequests` (3,000 requests through an 8-entry cache to force collisions) |
| Cache does not alias caller maps | `TestCache_DoesNotAliasCallerMaps` |
| Absent attributes fail closed | `TestCondition_AbsentAttributeFailsClosed` |
| Conditionless policies survive indexing | `TestCandidates_PolicyWithNoConditionOnAttributeSurvives` |
| Tenant isolation | `TestSharding_TenantIsolation` |
| Scope isolation within a tenant | `TestScoping_IsolatesWithinATenant` |

---

## 12. Performance

Intel Xeon @ 2.10 GHz, 4 cores, Go 1.24. Corpus spread over tenants with 1/rank
skew, 8 scopes per tenant, 50 global policies, all four operator families.

### Multi-tenant corpus — linear scan vs engine

| Corpus | Naive | Engine | Speedup | Validated | Alloc |
|---|---:|---:|---:|---:|---:|
| 10,000 | 38.5 µs | 5.7 µs | 7x | 13 | 0 B |
| 100,000 | 378 µs | 5.4 µs | 70x | 13 | 0 B |
| 1,000,000 | 4.03 ms | **5.1 µs** | **798x** | 0 | 0 B |

Engine latency is flat as the corpus grows 100x — per-request cost tracks the
shard, not the corpus. Out of a million policies, a handful reach validation.

### Layers, at 1M policies

| Configuration | Latency | Throughput |
|---|---:|---:|
| Single-threaded | 5.1 µs | 197k req/s |
| 4 cores | 2.0 µs/op | **513k req/s** |
| + decision cache (hit) | 1.1–1.5 µs | ~800k req/s |

### Index build (one-time)

| Corpus | Build | Memory |
|---|---:|---:|
| 10,000 | 36 ms | 23 MB |
| 100,000 | 381 ms | 208 MB |
| 1,000,000 | 8.3 s | 1.9 GB |

### Optimization history

Each step measured, not assumed:

| Change | Effect |
|---|---|
| Dense bitset → hybrid sparse/dense | removed the `O(N/64)` floor |
| Tenant → tenant+scope sharding | whale shard 1.80 ms → 168 µs |
| Filters ordered cheapest-first | candidate list collapses sooner |
| Removed the early-bail threshold | better pruning, simpler, more testable |
| `sort.Slice` → insertion sort | removed a per-request closure allocation |
| MatchSet slice → fixed array | 27 allocs/op → **0** |
| Eager → lazy sub-index builders | build allocs 55.8M → 26.4M, 11.6 s → 8.3 s |
| Added word-parallel intersection path | whale shard 168 µs → **7.9 µs**; flat 100k 2.66 ms → 50 µs |

---

## 13. Limitations

Measured, not theoretical. Stating them is the point.

### 1. On a large flat scope, a short-circuiting scan still wins

Under deny-overrides a linear scan stops at the first matching deny. With ~20%
deny policies one turns up after **about 375 policies regardless of corpus
size** (measured directly). So on a flat, unsharded corpus naive never does
O(N) work:

| Flat corpus | Naive | Indexed (no sharding) |
|---|---:|---:|
| 10,000 | 19.2 µs | **7.7 µs** |
| 100,000 | 17.8 µs | 50 µs |

Word-parallel intersection turned this from a ~150x loss into a win at 10k and
a 2.8x loss at 100k. The residual gap is structural: the index must touch every
word of the shard (100k policies = 1,563 words × ~10 filters), while the scan it
replaces stops after a few hundred policies.

In the multi-tenant table, naive's cost is instead dominated by walking the
corpus to *skip* out-of-scope policies — exactly the work sharding eliminates.

> The conclusion the data supports is not "indexing is fast." It is:
> **sharding buys the microseconds; indexing keeps a shard's cost proportional
> to its survivors.** Neither is sufficient alone.

Tuple space search removes the remaining gap by eliminating the
non-participant term entirely.

### 2. The tail is now close to the average

| Corpus | Worst-case shard | In scope | Validated |
|---|---:|---:|---:|
| 10,000 | 5.5 µs | 499 | 4 |
| 100,000 | 5.4 µs | 2,937 | 17 |
| 1,000,000 | 7.9 µs | 21,935 | 4 |

7.9 µs is 1.6x the average request, down from 34x before the word-parallel
path. This is no longer the dominant concern it was.

### 3. Build cost

1.9 GB and 8.3 s at a million policies is heavy for a structure that is
read-only afterwards. Sub-index construction buffers where it could stream.
This is now the largest outstanding weakness.

### 4. No incremental updates

Adding or removing one policy rebuilds its entire shard. Sharding bounds the
blast radius — a rebuild touches one scope, not the corpus — but this is not
yet a live-update system.

## 14. Roadmap

Ordered by measured value, not novelty.

### 1. Tuple space search — highest value

Group policies by *which attributes they constrain* (the signature/mask), then
hash the request's values for each group. A lookup becomes one hash probe per
signature, returning an exact small set.

There is no `notParticipating` term because every policy in a group constrains
exactly the same attributes, which is the remaining structural cost on a large
flat scope. It is what Open vSwitch uses for megaflow classification.

### 2. Build-time memory

Now the largest outstanding weakness at 1.9 GB / 8.3 s per million policies.
Stream sub-index construction rather than buffering.

### 3. Incremental index updates

Per-shard rebuild on write is the natural increment, since sharding already
bounds the work. Copy-on-write shard swap would keep readers lock-free.

### 4. MTBDD compilation

Compile boolean policy structure into a shared decision diagram. Evaluation
becomes a root-to-leaf walk with depth proportional to distinct attributes
rather than policy count. Canonicity yields conflict and redundancy detection
free. Largest piece of work here, and not what the measurements currently point
at.

### 5. Real RoaringBitmap

Worth revisiting if policy IDs cluster into dense regions separated by sparse
gaps, where per-chunk containers adapt locally in a way this global hybrid
cannot.

---

## Appendix: running

```bash
go build ./...
go test ./... -race                  # 118 tests
go test ./internal/benchmark/... -bench=. -benchtime=1s -benchmem
```

```bash
go run ./cmd/tessaraop -demo                                  # every operator, 8 scenarios
go run ./cmd/tessaraop -n 1000000 -tenants 10000 -requests 10 # scale test
go run ./cmd/tessaraop -n 1000000 -cache 8192 -alg first-applicable
go run ./cmd/tessaraop -n 100000 -interactive                 # type your own requests
```

Interactive request syntax:

```
tenant=tenant-0000 scope=billing subject.role=admin action=read \
  resource.domain=api.tenant-0000.example.com resource.path=/api/v2/x \
  subject.risk_score=10 network.source_ip=10.0.0.5
```
