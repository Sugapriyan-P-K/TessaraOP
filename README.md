# TessaraOP

A high-throughput ABAC (attribute-based access control) policy evaluation
engine proving that per-attribute field indexing with bitset intersection
beats naive linear policy scanning — and that the performance gap grows
with policy-set size.

This mirrors what specialized hardware (TCAM) does for router ACLs and
firewall rules — multi-dimensional predicate matching against many rules
simultaneously — reimplemented in software for ABAC/IAM/Zero Trust-style
access policies.

## How it works

A request like *"can this engineering-department subject read a
high-sensitivity resource at 2pm?"* gets checked against a policy set
two ways:

- **Naive evaluator**: linear scan every policy, check if all conditions
  match, apply deny-overrides/default-deny. O(N) per request.
- **Indexed evaluator**: look up per-attribute bitsets, AND them together
  to narrow to a small candidate set, then run the *exact same* match
  logic only on survivors.

The benchmark harness proves the indexed version is faster and gets the
identical answer every time (proven via differential testing, not assumed).

## Architecture

```
Request → [Field Index Lookup] → [Bitset AND] → [Exact validation on survivors] → Decision
           (hash map per attr)    (word-packed     (same logic naive uses)
                                   intersect)
```

### Package layout

```
internal/
├── model/      Policy, Condition, Request, Decision, shared eval semantics
├── naive/      O(N) linear-scan baseline evaluator
├── bitset/     Dense word-packed bitset (Set/Test/And/Or/Xor/Ones)
├── index/      Per-attribute field indexes built from a policy set
├── indexed/    Index lookup + bitset AND + final validation evaluator
├── genutil/    Synthetic policy/request generator for benchmarking
└── benchmark/  go test -bench harness
```

## Benchmark results

| Scale | Naive (ns/op) | Indexed (ns/op) | Speedup | Candidates | % of total |
|-------|-------------:|----------------:|--------:|-----------:|-----------:|
| 1,000 | 30,316 | 5,152 | **5.9x** | 102 | 10.2% |
| 10,000 | 346,532 | 51,430 | **6.7x** | 985 | 9.9% |
| 100,000 | 5,277,846 | 1,005,390 | **5.3x** | 10,219 | 10.2% |

Index build (one-time, at construction): 129µs / 1.6ms / 22ms.

### Honest read of these numbers

The candidate-set reduction is a consistent ~10x at every scale — the index
does its job. But the end-to-end speedup (5.3–6.7x) is smaller and doesn't
scale linearly with the candidate reduction. Root cause: the dense bitset
is `O(N/64)` words, so every AND/OR and the final bit-enumeration (`Ones()`)
costs time proportional to total N, not candidate-set size — regardless of
how small the surviving set is.

This is the direct, measurable cost of choosing a dense bitset over a
compressed one (RoaringBitmap). A compressed bitmap that's sparse in
practice would make the AND operations proportional to actual set
cardinality, pushing end-to-end speedup closer to the raw ~10x candidate
reduction. This is real signal from profiling, not a modeling assumption.

## Correctness guarantees

1. **Shared evaluation semantics.** Both evaluators call the same
   `Policy.Matches()` / `Condition.Matches()` methods and the same
   `ResolveDecision()` function in `internal/model`. Semantics cannot
   silently drift between the two paths.

2. **Index is a pre-filter only.** The index stage can only be conservative
   (over-inclusive), never wrongly exclude a matching policy. A bug in the
   index costs performance, not correctness, because the final validation
   pass always re-runs ground-truth matching.

3. **Differential testing.** `TestDifferential_MatchesNaive` runs 50
   randomized policy sets × 20 requests each (1,000 comparisons) asserting
   the indexed and naive evaluators produce identical decisions.

4. **The no-condition property.** A policy with no condition on attribute A
   must NOT be excluded by A's index. Implemented via
   `noCondition = universe.Xor(hasCondition)` (complement within known
   universe). Tested explicitly in
   `TestCandidates_PolicyWithNoConditionAlwaysSurvives`.

## Evaluation semantics

- **Deny-overrides, default-deny**: an explicit Deny match always wins
  regardless of scan order; no match at all = denied.
- Conditions within a policy are implicitly AND-ed.
- A policy with zero conditions matches everything (catch-all).
- Range conditions (`OpRange`) are NOT indexed in v1 — only checked in the
  final validation pass. This is intentional scope.

## Running

```bash
go build ./...
go test ./... -v                                                    # 32 tests
go test ./internal/benchmark/... -bench=. -benchtime=2s -benchmem   # benchmarks
```

## Design decisions

- **Dense bitset over RoaringBitmap**: a custom `[]uint64` bitset avoids
  external dependencies while proving the core thesis. Swapping in
  RoaringBitmap is the most concrete next optimization — the benchmark
  data already shows exactly why (dense bitset O(N/64) overhead is the
  bottleneck, not the candidate-set reduction).

- **Shared vocabulary in synthetic data**: the generator uses 10
  departments × 4 sensitivity tiers × 5 actions (not random unique
  strings) because real IAM rule sets have many policies sharing the same
  attribute values.

- **EvaluateIndices over slice copy**: the indexed evaluator iterates by
  position index into the original policy slice rather than copying matched
  policies into a new slice — a measured allocation fix (eliminates
  per-request slice allocation scaling with candidate count).

## Explicitly out of scope (v1)

- Range/interval indexing (segment tree for time-of-day conditions)
- BDD/MTBDD evaluation stage
- Tuple space search
- Incremental index updates
- Compressed bitmaps (RoaringBitmap)
