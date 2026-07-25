# TessaraOP

A multi-tenant ABAC / Zero-Trust policy decision engine built to answer
authorization questions against millions of policies in microseconds.

A request — *this admin, from 10.4.2.7, with risk score 12, calling
`/api/v2/admin/users` on `api.admin.acme.com` at 14:30* — is checked against a
policy corpus two ways: by linear scan, and by the engine. The engine is
verified against the scan on every test run, so the speed claims and the
correctness claims rest on the same evidence.

## What a policy looks like

```
Policy: acme-prod-admin-console
  Tenant:   acme          Scope: identity        Priority: 100
  Effect:   ALLOW
  Conditions (all AND-ed):
    subject.role          IN     [admin, security-admin]
    subject.risk_score    RANGE  [0, 30]
    subject.mfa_verified  ==     true
    network.source_ip     CIDR   10.0.0.0/8
    network.source_ip     !CIDR  203.0.113.0/24
    resource.domain       SUFFIX admin.acme.com
    resource.path         PREFIX /api/v2/admin
    time.hour             RANGE  [9, 17]
    geo.country           IN     [US, CA]
  Obligations: require_mfa, audit_log
```

Fourteen operators across four families, each needing a different index
structure — a hash map cannot answer "is 10.4.2.7 inside 10.0.0.0/8".

| Family | Operators | Index structure |
|---|---|---|
| Set | `eq` `ne` `in` `nin` `exists` `nexists` | hash map |
| Numeric | `range` `gt` `lt` | distinct-range table, binary searched |
| Network | `cidr` `ncidr` | binary radix trie over address bits |
| Name | `dnssuffix` `prefix` | reversed-label trie / prefix table |

Decisions carry **obligations** (`require_mfa`, `audit_log`, `step_up_auth`) so
a policy can grant conditionally rather than only allow or deny.

## Deny-overrides, and why that choice is structural

The default is **deny-overrides with default-deny**: any matching deny wins,
otherwise any matching allow, otherwise denied. `permit-overrides` and
`first-applicable` are also implemented and selectable per engine.

The security argument for deny-overrides is the familiar one — it fails safe,
and adding a deny can only ever reduce access. The engineering argument is the
one that actually shaped this codebase:

> Deny-overrides is **order-independent**, and that is what makes indexing
> sound. The index yields candidates in whatever order the underlying sets
> enumerate. If the algorithm were order-sensitive, that arbitrary order would
> leak into the decision. `first-applicable` is order-sensitive, so it pays for
> a priority ordering pass and cannot short-circuit.

One consequence is worth stating plainly: when several policies match with the
winning effect, deny-overrides does not define *which* to credit, and the
engine reports whichever it reached before stopping. `MatchedPolicyID` is
therefore *a* justification, not a canonical one. Audit trails needing stable
attribution should use `first-applicable`, which is fully deterministic
(priority, then policy ID).

## Architecture

```
Request
  │
  ├─ decision cache ──────────────► hit: ~1.1 µs, verified by full key compare
  │
  ├─ global shard      (platform denies: blocklists, kill switches)
  ├─ tenant-wide shard (customer-wide rules)
  └─ (tenant, scope) shard
        │
        ├─ per-attribute filters ─── hash / radix trie / label trie / range table
        ├─ order cheapest-first, seed from the most selective
        ├─ filter the candidate list in place, shrinking as it goes
        └─ exact validation on survivors ── model.Policy.Matches
```

```
internal/
├── model/      types, operator semantics, combining algorithms
├── naive/      linear-scan oracle
├── bitset/     hybrid sparse/dense integer sets
├── matcher/    CIDR trie, domain trie, prefix table, interval table
├── index/      per-attribute sub-indexes and the intersection
├── engine/     sharding, algorithm selection, decision cache
├── genutil/    synthetic multi-tenant corpus generator
└── benchmark/  layered benchmarks
```

## Results

Intel Xeon @ 2.10 GHz, 4 cores, Go 1.24. Corpus: policies spread over tenants
with a 1/rank skew (one whale, long tail), 8 scopes per tenant, 50 global
policies, all four operator families in use.

**Multi-tenant corpus — linear scan vs. engine**

| Corpus | Naive | Engine | Speedup | Validated | Alloc |
|---|---:|---:|---:|---:|---:|
| 10,000 | 38.5 µs | 6.4 µs | **6x** | 9 | 0 B |
| 100,000 | 378 µs | 5.6 µs | **67x** | 0 | 0 B |
| 1,000,000 | 4.03 ms | 4.9 µs | **816x** | 22 | 0 B |

Engine latency is flat as the corpus grows 100x, because per-request cost
tracks the shard, not the corpus. Out of a million policies, 22 reach exact
validation.

**Layers, at 1M policies**

| Configuration | Latency | Throughput |
|---|---:|---:|
| Engine, single-threaded | 4.9 µs | 204k req/s |
| Engine, 4 cores | 2.0 µs/op | **513k req/s** |
| Engine + decision cache (hit) | 1.1–1.5 µs | ~800k req/s |

The steady-state hot path performs **zero allocations**: scratch buffers are
pooled per goroutine, and the lazy set union lives in a fixed array rather than
a slice.

**Index build (one-time)**

| Corpus | Build | Memory |
|---|---:|---:|
| 10,000 | 36 ms | 23 MB |
| 100,000 | 381 ms | 208 MB |
| 1,000,000 | 8.3 s | 1.9 GB |

### Where this does not win

Two honest results, both measured rather than assumed.

**The naive baseline is not really O(N), and that flatters the headline
number.** Under deny-overrides a linear scan stops at the first matching deny.
With ~20% deny policies, a match turns up after about 375 policies regardless
of corpus size. So on a *flat* corpus, naive never does O(N) work:

| Flat corpus | Naive | Indexed (no sharding) |
|---|---:|---:|
| 10,000 | 19.2 µs | 256 µs |
| 100,000 | 17.6 µs | 2.66 ms |

**Indexing alone is a 100x loss here.** The reason is structural: a filter
must pass every policy that places no condition on the attribute, so the
smallest available seed set is still a large fraction of the shard. Building
that seed costs O(shard), while the scan it replaces stops after a few hundred
policies. In the multi-tenant table above, naive's cost is dominated by
walking the corpus to skip out-of-scope policies — which is exactly the work
sharding eliminates.

The conclusion the data supports is not "indexing is fast". It is:

> **Sharding is what buys the microseconds; indexing is what keeps a shard's
> cost proportional to its survivors.** Neither is sufficient alone, and on a
> single flat scope this index design is worse than a linear scan.

**The whale shard is still the tail.** Scoping cuts the largest tenant's
working set from 102,220 to 21,935 policies, and its latency from 1.80 ms to
168 µs — but that is 34x the average request.

| Corpus | Worst-case shard | In scope | Validated |
|---|---:|---:|---:|
| 10,000 | 9.9 µs | 499 | 2 |
| 100,000 | 24.2 µs | 2,937 | 15 |
| 1,000,000 | 168 µs | 21,935 | 92 |

A scope holding tens of thousands of policies is where this design runs out,
and the fix is a different structure rather than a tuning pass — see next
steps.

## Correctness

The engine is far too intricate to trust by inspection: sharding, four index
families, negation handling, lazy set unions, a cache, and three combining
algorithms. Correctness rests on four things instead.

1. **Shared semantics.** Both evaluators route every match through
   `Condition.Matches` and resolve through the same `Accumulator`. The fast
   path has no second copy of the rules to drift from.

2. **The index is a pre-filter only.** It may be over-inclusive but never
   under-inclusive, and survivors always face the real match logic. A bug in
   an index costs performance, not correctness — a property asserted directly
   by a randomized test that checks no genuinely matching policy is ever
   excluded, across every operator family.

3. **Differential testing.** Randomized corpora run through both evaluators
   under all three algorithms, asserting the same decision. Where the credited
   policy is not canonically defined, the test verifies it names a policy that
   is in scope, actually matches, and carries the winning effect — rather than
   asserting a false determinism.

4. **Adversarial and concurrent cases.** Missing attributes, unknown tenants,
   empty requests, lookalike domains; plus eight goroutines against one engine
   under `-race`.

Two security properties have dedicated tests:

- **DNS label alignment.** `strings.HasSuffix("evilacme.com", "acme.com")` is
  true, so a naive suffix check hands a lookalike domain the authorization
  scoped to the real one. Both the trie and the validation path match on label
  boundaries.
- **Cache hits are verified, never assumed.** Every hit compares the full
  request against the stored key. A hash collision serving one subject another
  subject's decision would be an authorization bug, so the hash only selects a
  slot. A test drives 3,000 distinct requests through an 8-entry cache to force
  collisions.

Absent attributes **fail closed**: every operator except `nexists` rejects a
request that lacks the attribute, negations included. `role != admin` does not
quietly pass for a request carrying no role.

## Running

```bash
go build ./...
go test ./... -race
go test ./internal/benchmark/... -bench=. -benchtime=1s -benchmem
```

```bash
# Walk a hand-written policy set covering every operator
go run ./cmd/tessaraop -demo

# One million policies over ten thousand tenants
go run ./cmd/tessaraop -n 1000000 -tenants 10000 -requests 10

# With the decision cache, under first-applicable
go run ./cmd/tessaraop -n 1000000 -cache 8192 -alg first-applicable

# Type requests and watch both evaluators
go run ./cmd/tessaraop -n 100000 -interactive
```

## Design notes

- **Hybrid sparse/dense sets.** A purely dense bitset makes every operation
  O(N/64) regardless of how few elements survive. Sets here carry a sorted
  `[]uint32` when sparse and a bitmap when dense, so intersection cost tracks
  the candidate count.

- **Negation needs no complement.** For a negated operator,
  `notParticipating ∪ (participating \ rejected)` is just the universe minus
  the rejected set — so negations are cheap post-filters, not set differences
  computed per request.

- **Lazy set union in a fixed array.** Nested CIDR prefixes and DNS suffixes
  produce multi-set unions. Materializing them would allocate per filter per
  request; a lazy union in an 8-element array removed the last of the hot-path
  allocations.

- **Lazily built sub-indexes.** An attribute almost always uses one operator
  family, so building all twelve structures per attribute wasted most of them.
  Deferring construction cut build allocations from 55.8M to 26.4M.

- **Realistic corpus generation.** Shared vocabularies rather than unique
  per-policy values (unique values would give every hash bucket one member and
  flatter the index), and skewed tenant sizes rather than uniform, so the whale
  case cannot hide.

## Next steps

1. **Tuple space search** — group policies by which attributes they constrain,
   then hash the request's values for each group. This sidesteps the
   non-participant inflation that makes the flat and whale-shard cases slow,
   and is the direct answer to the two limitations above.
2. **Incremental index updates** — adding a policy currently rebuilds its
   shard. Sharding already bounds the blast radius; per-shard rebuild on write
   is the next increment.
3. **Build-time memory** — 1.9 GB at a million policies is heavy for a
   structure that is read-only afterwards; sub-index construction can stream
   rather than buffer.
4. **BDD/MTBDD compilation** — would also yield policy conflict and
   redundancy detection as a byproduct.
