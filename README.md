# TessaraOP

A high-throughput ABAC (attribute-based access control) policy evaluation
engine, built to prove that structured field-indexing + roaring-bitmap
intersection beats naive linear policy evaluation at scale.

## Status: v1 in progress

- [x] Core data model (`internal/model`)
- [x] Naive linear-scan baseline evaluator (`internal/naive`) — correctness-tested
- [ ] Field indexes (hash map / radix trie per attribute)
- [ ] Roaring bitmap intersection across matched fields
- [ ] Final exact-match validation pass on the candidate set
- [ ] Benchmark harness: naive vs. indexed at 1k / 10k / 100k policies

## Why this exists

General-purpose databases and policy engines like OPA re-evaluate policy
logic per request without a real index over the rule set — cost grows
linearly with policy count. TessaraOP applies the same technique real
databases use internally for multi-predicate filtering (per-column index +
bitmap merge), but embedded directly in the authorization hot path: no
network round trip, no query planner overhead, just in-memory index lookups
and bitmap AND-intersection.

## Data model

- `Policy`: an ID, an `Effect` (Allow/Deny), and a list of AND-ed `Condition`s.
- `Condition`: an attribute name, an operator (`eq`, `in`, `range`), and
  values/bounds to match against.
- `Request`: string attributes (department, role, resource path, etc.) and
  numeric attributes (time-of-day, risk score) for range conditions.
- Evaluation semantics: **deny-overrides, default-deny** — any matching Deny
  policy wins regardless of scan order; no match at all means deny.

## Scope (v1)

In scope: hash map / trie field indexes, roaring bitmap candidate-set
intersection, exact-match validation pass, naive-vs-indexed benchmark
harness at 1k/10k/100k policies.

Explicitly out of scope for v1 (future work): decision trees (HiCuts/
HyperCuts) for range-heavy rule sets, BDD/MTBDD evaluation stage, tuple
space search.

## Running tests

```
go test ./... -v
```
