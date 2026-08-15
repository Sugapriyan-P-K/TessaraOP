# TessaraOP — Technical Documentation

Complete reference for the engine: what exists, how each part works, why it was
built that way, what it measures, and what it deliberately does not do.

**Status summary**

| | |
|---|---|
| Packages | 11 internal, 2 public, 2 binaries |
| Source | ~8,400 lines |
| Tests | ~6,200 lines, 316 tests, passing under `-race` |
| External dependencies | **none** — no `go.sum` |
| Go version | built and tested on 1.26.5 |
| Registered attributes | 118 across L3 / L4 / L7 |
| Operators | 31 across 4 families, combinable with AND / OR / NOT |
| Combining algorithms | 6 of the 8 XACML 3.0 set, at two tiers |

---

## Table of contents

1. [What is and is not implemented](#1-what-is-and-is-not-implemented)
2. [Data model](#2-data-model)
3. [Evaluation semantics](#3-evaluation-semantics)
4. [The two-tier combination](#4-the-two-tier-combination)
5. [The attribute registry](#5-the-attribute-registry)
6. [Architecture and request flow](#6-architecture-and-request-flow)
7. [Package reference](#7-package-reference)
8. [The candidate-set algorithm](#8-the-candidate-set-algorithm)
9. [The AND-spine: the indexing boundary](#9-the-and-spine-the-indexing-boundary)
10. [Index structures](#10-index-structures)
11. [Two intersection strategies](#11-two-intersection-strategies)
12. [Sharding](#12-sharding)
13. [Decision cache](#13-decision-cache)
14. [Concurrency and hot reload](#14-concurrency-and-hot-reload)
15. [The bundle format and linter](#15-the-bundle-format-and-linter)
16. [Ingestion](#16-ingestion)
17. [The PDP server](#17-the-pdp-server)
18. [Correctness strategy](#18-correctness-strategy)
19. [Performance](#19-performance)
20. [Limitations](#20-limitations)
21. [Roadmap](#21-roadmap)

---

## 1. What is and is not implemented

Stated plainly, because several items are commonly assumed to be present.

### Implemented

| Capability | Where |
|---|---|
| 31 operators across 4 families | `internal/model` |
| AND / OR / NOT condition trees | `internal/model/expr.go` |
| `Policy → []Rule → ConditionExpr` structure | `internal/model/policy.go` |
| Two-tier combining (rules within a policy, policies within a shard) | `internal/model`, `internal/index` |
| Deny-overrides / permit-overrides / first-applicable, at both tiers | `internal/model` |
| Obligations on decisions, attributed to the rule that fired | `internal/model` |
| 118-attribute L3/L4/L7 registry with type and operator validation | `internal/attr` |
| Role / group / resource hierarchies with transitive closure | `internal/hierarchy` |
| Decision explanation, per condition | `internal/explain` |
| ReBAC resolver interface + in-memory implementation | `internal/relation` |
| Structured decision audit log | `pkg/tessaraop/audit` |
| Hybrid sparse/dense integer sets | `internal/bitset` |
| CIDR radix trie | `internal/matcher/cidr.go` |
| DNS suffix trie (label-aligned) | `internal/matcher/domain.go` |
| Path prefix table | `internal/matcher/prefix.go` |
| Byte suffix table | `internal/matcher/suffix.go` |
| Numeric interval table | `internal/matcher/interval.go` |
| Numeric discrete-set hash | `internal/matcher/numset.go` |
| Per-attribute sub-indexes over flattened rules | `internal/index` |
| Two intersection strategies with a size heuristic | `internal/index` |
| Two-level sharding (tenant, scope) + global shard | `internal/engine` |
| Verified decision cache | `internal/engine/cache.go` |
| Linear-scan oracle | `internal/naive` |
| Declarative JSON bundle format | `internal/bundle` |
| Policy linter (28 checks) | `internal/bundle/lint.go` |
| L3/L4/L7 ingestion adapters over stdlib parsers | `internal/ingest` |
| Public SDK with atomic hot reload and metrics | `pkg/tessaraop` |
| HTTP PDP: native, forward-auth, OPA-shaped | `pkg/tessaraop/pdpserver` |
| Prometheus metrics, health/readiness, token-guarded reload | `pkg/tessaraop/pdpserver` |
| Multi-tenant corpus generator with boolean trees | `internal/genutil` |
| Layered benchmarks | `internal/benchmark` |
| CLI: demo, registry, lint, export, bench, interactive | `cmd/tessaraop` |
| Server binary with SIGHUP reload and graceful shutdown | `cmd/tessaraopd` |

### Not implemented

| Absent | Note |
|---|---|
| MTBDD / BDD decision diagrams | Zero lines. Roadmap only. |
| Tuple space search | The identified next optimization for the flat-shard case. |
| RoaringBitmap | Not used. `internal/bitset` borrows the "pick representation by cardinality" idea without being Roaring. |
| Incremental index updates | Adding a policy rebuilds its shard. Reload is whole-corpus and atomic. |
| Importers from other policy formats | AWS IAM, Kubernetes NetworkPolicy, Envoy RBAC, Cedar, Rego. The bundle format is the migration target; no translator exists. |
| gRPC | The HTTP forward-auth shape covers the same proxies without a protobuf dependency. |
| YAML authoring | JSON only, to keep dependencies at zero. Convert at build time. |
| Raw packet or HTTP byte parsing | Deliberate. See §16. |
| Token signature verification | Deliberate. The caller supplies a verdict. See §16. |

---

## 2. Data model

Three levels:

```go
type Policy struct {
    ID, TenantID, Scope string
    Priority            int        // orders policies at the outer tier
    RuleAlgorithm       Algorithm  // combines this policy's rules
    Rules               []Rule
}

type Rule struct {
    ID          string
    Effect      Effect     // ALLOW | DENY
    Priority    int        // orders rules at the inner tier
    When        *ConditionExpr
    Obligations []string
}

type ConditionExpr struct {
    Kind ExprKind          // Leaf | And | Or | Not
    Cond Condition         // when Leaf
    Sub  []*ConditionExpr  // children of And/Or/Not
}

type Condition struct {
    Attribute string
    Operator  Operator
    Values    []string        // string family
    Min, Max  float64         // numeric bounds and scalar comparand
    Numbers   []float64       // numeric set family
    Prefixes  []netip.Prefix  // network family
    re        []*regexp.Regexp // compiled by Prepare
}
```

### Why rules exist

v1 held a flat `[]Condition` that was implicitly AND-ed. Two things it could not
express, both of them ordinary:

**Disjunction.** *"(role is admin OR role is security-admin) AND NOT department is
contractor"* had to be expanded into a cross product of AND-only policies. That
multiplies the corpus, and it makes the result unreviewable — a human auditor can
no longer see the intent.

**A scoped exception.** *"deny deleting critical resources, except with an approved
break-glass ticket"* required two policies. The exception then lived at shard
scope, where it could override an unrelated policy's deny. Rules keep it inside
the policy that owns it, resolved by that policy's own algorithm.

### Why a tree rather than nesting flags

A tagged union would need a discriminator and per-kind payloads. A single struct
with a `Kind` and a child slice keeps construction readable (`And(Or(a, b),
Not(c))`) and serialization symmetric. The cost is that `Not` with the wrong child
count is representable; it fails closed (reports no match) and the linter rejects
it.

### Empty-combinator conventions

- `And()` with no children **matches everything** — the catch-all rule, the
  default-deny backstop at the bottom of a policy.
- `Or()` with no children **matches nothing**, so an empty disjunction cannot
  silently grant access. The linter treats it as an error, since it makes a rule
  dead.
- A `nil` `When` matches everything, same as `And()`.

---

## 3. Evaluation semantics

### Operators

Four families, each reading a different map on the request, because each needs a
different index structure — a hash map cannot answer *"is 10.4.2.7 inside
10.0.0.0/8"*.

| Family | Reads | Operators |
|---|---|---|
| String | `Request.Attributes` | `eq ne in nin contains ncontains prefix nprefix suffix nsuffix regex nregex dnssuffix ndnssuffix` |
| Numeric | `Request.Numeric` | `range nrange gt gte lt lte num_eq num_ne num_in num_nin` |
| Network | `Request.IPs` | `cidr ncidr` |
| Presence | any of the three | `exists nexists` |

`Operator.Family()` is the single source of truth for which map an operator reads;
a test asserts every operator in `AllOperators` has one, since an operator with no
family reads nothing and can never match.

### Fail-closed on absent attributes

Every operator except `nexists` rejects a request that lacks the attribute —
**including the negations**. `role != admin` does not quietly pass for a request
carrying no role; `source_ip NOT IN 203.0.113.0/24` requires `source_ip` to be
present *and* outside the block.

This is the property that makes the linter necessary rather than nice to have. A
condition that can never match produces no error at runtime; it is
indistinguishable from a rule the author meant to be narrow. §15 covers what the
linter catches as a result.

### NaN satisfies nothing

Every IEEE comparison against NaN is false, so a negated numeric operator would
return true for it by default — turning a malformed or unparsed measurement into a
match. `Condition.matchNumeric` rejects NaN before dispatching, so
`dest_port != 22` does not fire on a port that failed to parse.

### `suffix` vs `dnssuffix`

Two separate operators, deliberately.

- `suffix` is a raw byte test. `".php"` matches `"shell.php"`. This is what file
  extension filtering needs.
- `dnssuffix` is **label-aligned**. `"acme.com"` matches `"api.acme.com"` but not
  `"evilacme.com"`.

`strings.HasSuffix("evilacme.com", "acme.com")` is true, so conflating them hands
a lookalike domain the authorization scoped to the real one. That is a live and
frequently exploited bypass class. Both the trie and the validation path match on
label boundaries, and the linter warns when a `suffix` condition's value looks
like a hostname.

### Regular expressions

RE2 via `regexp`, so there is no catastrophic backtracking. Patterns are compiled
by `Prepare`, which `index.BuildShard` calls, so evaluation never compiles. A
condition that was never prepared falls back to a process-wide `sync.Map` compile
cache — correct, just a map lookup per evaluation instead of none. That fallback
exists so a hand-built policy from the SDK still evaluates correctly.

The linter rejects an uncompilable pattern; the cache fallback treats one as
matching nothing, which keeps evaluation deterministic rather than panicking.

### Short-circuiting inside a tree

`And` stops at the first false child, `Or` at the first true one. Nothing about
the index constrains child order, so authors control cost by putting cheap
conditions first — a regex behind an equality check runs only when the equality
passed.

---

## 4. The two-tier combination

```
Tier 1 (inside a Policy)
    matching Rules ──[Policy.RuleAlgorithm]──► one Verdict per Policy

Tier 2 (across Policies in a shard)
    Policy Verdicts ──[shard Algorithm]──► final Decision
```

Both tiers drive the same `Accumulator` over the same exported `Verdict` type, so
the combining semantics cannot drift between them, and the naive oracle and the
indexed engine reach the identical answer by calling the same code.

### The algorithms

| Algorithm | Rule | Order-independent | Short-circuits |
|---|---|---|---|
| `deny-overrides` (default) | Any matching DENY wins, else any ALLOW | Yes | Yes, on the first DENY |
| `permit-overrides` | Any matching ALLOW wins, else any DENY | Yes | No |
| `first-applicable` | Highest priority wins; ties by policy ID then rule ID | No | No |

Order-independence is what makes indexing sound. The index yields candidates in
whatever order the underlying sets enumerate, and if the algorithm were
order-sensitive that arbitrary order would leak into the decision.
`first-applicable` is order-sensitive, so it must see every candidate and cannot
short-circuit.

### Which priority orders which tier

`Rule.Priority` orders rules inside a policy. `Policy.Priority` orders policies
against each other. The inner tier emits a verdict carrying the rule's priority;
`outerVerdict` rewrites it to the policy's before it reaches the outer tier.

Getting this wrong would let a high-priority rule inside a low-priority policy
outrank a policy that should have won —
`TestFirstApplicable_OuterTierUsesPolicyPriority` pins it.

### One comparator, both tiers

`outranks` compares `(Priority desc, PolicyID asc, RuleID asc)`. Within a policy
every candidate shares a `PolicyID`, so it reduces to rule ID; across policies the
IDs are distinct, so rule ID is never reached. One function, no second subtly
different comparator.

### Attribution

The matched rule ID is threaded through the accumulator from the moment the rule
matched. The tempting alternative — resolve the effect first, then scan for "some
rule with the winning effect" — misattributes two same-effect rules in one policy,
putting the wrong rule in an audit trail.
`TestPolicy_AttributesTheRuleThatActuallyFired` guards it.

### The non-canonical-attribution caveat

Under the overrides algorithms, several rules can match with the winning effect and
the algorithm says nothing about which to credit. The engine reports whichever it
reached first and stops, because scanning the remainder to pick a canonical winner
would forfeit short-circuiting for no change in the decision.

**Obligations travel with the credited rule**, so they can differ between two
correct implementations too. This is a real consequence of the model, not a defect:
use `first-applicable` where audit attribution or a guaranteed obligation set
matters. `cmd/tessaraop -demo` demonstrates it live.

---

## 5. The attribute registry

`internal/attr` holds 118 named attributes, each with a declared type
(`string` / `numeric` / `ip`), a layer, documentation, and the operators valid on
it.

Making the contract **data rather than convention** buys three things:

1. **Load-time rejection.** A policy comparing a numeric attribute with a string
   operator is rejected by the linter instead of failing closed at runtime, where
   it looks exactly like a rule that simply never fires.
2. **An onboarding checklist.** A customer is handed the list of attributes to
   supply (`tessaraop -attrs`, or `GET /v1/attributes`) rather than reading the
   evaluator.
3. **Documentation that cannot drift**, since the linter and the CLI both read the
   same table.

### Namespaces

`network.*` (L3) · `transport.*` (L4) · `conn.*` · `geo.*` `threat.*` `iface.*` ·
`http.*` (L7) · `payload.*` · `tls.*` · `subject.*` `token.*` `session.*` `api.*`
`bot.*` · `resource.*` `action` `time.*` `graphql.*` `ws.*`

Four are open-ended, because their key space belongs to the customer's traffic
rather than to this registry: `http.header.*`, `http.query.*`, `http.cookie.*`,
`subject.claim.*`. `Lookup` resolves exact names first, then namespaces by longest
prefix.

### Attributes registered twice, on purpose

Several protocol fields appear as both a string and a number, because policies ask
two different questions of them.

`tls.version` is a string for exact-set membership (*"reject SSLv3, TLS1.0,
TLS1.1"*). `tls.version_num` is numeric for a floor (*"require at least 1.2"*).
Expressing the floor as a string set means editing every policy when a new version
ships. The same reasoning applies to `network.protocol` / `network.protocol_name`.

**The numeric scale must be monotonic in protocol age**, and this was a real bug.
Encoding SSLv3 as its version number, 30, places it *above* TLS 1.3's 13 — so
`tls.version_num >= 12` would accept SSLv3, precisely the protocol the rule exists
to reject. SSLv3 is `3`; an unrecognized version is `0`, which fails every floor a
policy can express.

### Boolean attributes are strings

`subject.mfa_verified`, `token.valid`, `tls.client_cert_verified` and similar carry
`"true"` / `"false"` as strings, so set membership, negation and existence work on
them uniformly with everything else rather than needing a fourth typed map and a
fifth operator family.

### Multi-valued attributes are comma-joined

`subject.groups`, `token.scopes`, `transport.tcp_flags`, `network.ip_options` and
similar join their values with commas. Match with `contains`. This keeps the
request shape flat — three maps, no nesting — which is what lets the hot path read
a value with a single map lookup and no allocation.

---

## 6. Architecture and request flow

```
Request
  │
  ├─ decision cache ──────────────► hit: verified by full key compare
  │
  ├─ global shard      (platform denies: blocklists, kill switches)
  ├─ tenant-wide shard (customer-wide rules)
  └─ (tenant, scope) shard
        │
        ├─ universe = the shard's flattened rules, in policy order
        ├─ per-attribute filters ── hash / CIDR trie / DNS trie /
        │                            prefix / suffix / interval / numeric hash
        ├─ order filters cheapest-first
        ├─ intersect, by one of two strategies (§11)
        └─ two-tier combination on survivors (§4)
```

Global first, because it is the smallest shard and the most likely to end
evaluation outright under deny-overrides — paying for it up front is usually
cheaper than reaching it last.

---

## 7. Package reference

| Package | Responsibility |
|---|---|
| `internal/model` | Types, operator semantics, condition trees, `Accumulator`, both combining tiers. The ground truth every evaluator routes through. |
| `internal/attr` | The attribute registry: names, types, layers, valid operators. |
| `internal/bitset` | Hybrid sparse/dense integer sets. `OrWords` bridges to the word-parallel path. |
| `internal/matcher` | The per-attribute structures a hash map cannot replace: CIDR radix trie, reversed-label DNS trie, prefix and suffix length tables, distinct-interval table, numeric hash. Plus `MatchSet`, a lazy union in a fixed array. |
| `internal/index` | Builds the sub-indexes over flattened rules, derives the candidate set, and runs the two-tier walk. |
| `internal/engine` | Sharding, algorithm selection, scratch pooling, the decision cache. |
| `internal/naive` | The linear-scan oracle. Obviously correct rather than fast. |
| `internal/bundle` | The declarative JSON format, its round trip, and the linter. |
| `internal/ingest` | Builds a request from real traffic using stdlib parsers only. |
| `internal/genutil` | Synthetic corpora and request streams with realistic shape. |
| `internal/benchmark` | Layered benchmarks, so each optimization is attributable. |
| `pkg/tessaraop` | The public SDK: the only package an integration imports. |
| `pkg/tessaraop/pdpserver` | Four HTTP endpoint shapes plus operational endpoints. |
| `cmd/tessaraop` | CLI: demo, registry, lint, export, bench, interactive. |
| `cmd/tessaraopd` | The server binary. |

`internal/indexed` is a fourth evaluator: indexing with no sharding. It exists as
the **control** in the benchmarks — comparing naive to indexed isolates what the
index alone buys, and comparing indexed to the sharded engine isolates what
partitioning buys on top. Keeping the two effects separable is what lets the
results table attribute the speedup honestly instead of reporting one blended
number.

---

## 8. The candidate-set algorithm

### The pass function

Each attribute contributes one or more sub-indexes, one per operator family
present on it. For a request value `v`, a sub-index `S` yields the rules that pass
it:

```
pass_S(v) = notParticipating_S ∪ accepted_S(v)
```

**The `notParticipating` term is the correctness keystone.** A rule that places no
condition of kind `S` on the attribute must never be filtered out by `S`. Get that
wrong and the engine returns confidently wrong answers rather than merely slow
ones.

### Negations need no complement

For a negated operator,
`notParticipating ∪ (participating \ rejected)` is just the whole universe minus
the rejected set. So a negation is a cheap post-filter — "reject these, pass
everything else" — not a set difference computed per request.

### Absent attributes prune

If a request omits an attribute entirely, only rules that tolerate its absence can
match, so `allowsAbsent` (the complement of `requiresPresent`) becomes the filter.
On real corpora this prunes a great deal, and it is the **only** filter the
non-indexable operators contribute.

### What is not indexable

Substring and regular-expression matching have no structure a pre-filter can
exploit. Neither do negated affix operators or negated ranges. Those contribute
`requiresPresent` and nothing else, then resolve exactly during validation.

That group is an explicit `case` in `indexCondition` rather than a `default`,
because a new operator added to `internal/model` with no entry would silently
become unindexed — still correct, but silently costing a great deal of
performance, and silence is the wrong outcome there.

### Complements are computed lazily

A complement over an unused family is the whole shard: the largest set built and
never consulted. So `posNot`, `cidrNot`, `domainNot`, `prefixNot`, `suffixNot`,
`intervalNot` and `numsetNot` are computed only when that family actually
participates.

### A latent under-inclusiveness bug, fixed

`Condition.Matches` for `eq` and `ne` consults `Values[0]` alone. The index used
to add **every** value to the posting list. For `eq` that is merely
over-inclusive, but for `ne` it makes the filter reject a rule that actually
matches — the one error class that produces wrong decisions rather than slow ones.
Both now index `Values[0]` only, and the linter turns extra values into an error
so the discrepancy cannot arise from the author's side either.

---

## 9. The AND-spine: the indexing boundary

This is the one subtle correctness rule introduced by condition trees.

Only leaves reachable from the root by following **exclusively `And` nodes** may
build an index filter. Call that the AND-spine.

```
And                     ← spine
├── Cond(a)             ← indexable
├── And                 ← still spine
│   └── Cond(b)         ← indexable
├── Or                  ← breaks the spine
│   ├── Cond(c)         ← NOT indexable
│   └── Cond(d)         ← NOT indexable
└── Not                 ← breaks the spine
    └── Cond(e)         ← NOT indexable
```

**Why.** A leaf under an `Or` is not logically necessary for the tree to match —
its sibling may satisfy the disjunction. A leaf under a `Not` is required to be
*false* rather than true. Indexing either would let the pre-filter exclude a rule
that genuinely matches.

Leaves off the spine contribute no filter and fall through to exact validation:
over-inclusive, never under-inclusive, consistent with every other index here. A
rule whose root is an `Or` therefore gets no index help at all and is validated on
every request reaching its shard.

`ANDSpineLeaves` stops at `Or` and `Not` rather than trying to be clever.
`Not(Not(x))` is equivalent to `x` and could in principle be descended into, but
soundness is worth more than the last few percent of selectivity.

Tested from both sides: `TestANDSpineLeaves_ExcludesOrAndNot` in `model`, and
`TestCandidates_OffSpineConditionIsNotIndexed` /
`TestCandidates_NegatedSubtreeIsNotIndexed` in `index`. The randomized invariant
generates `Or`/`Not` trees so the never-under-inclusive property is exercised
against them, and `TestCandidates_SpineStillPrunesAroundOffSpineNodes` confirms
that adding an `Or` does not disable indexing for the rest of a rule.

---

## 10. Index structures

The indexed unit is a **rule**, not a policy. A policy's index entry would be the
union of what all its rules ask for — near-useless as a filter. So the universe is
the shard's flattened rule list, and a candidate position names a rule.

Positions are assigned in **policy order**, which matters: candidates come back
ascending, so all surviving rules of one policy form a contiguous run and the
two-tier walk groups them without a map and without allocating.
`ruleRef` is `{policy, rule int32}` — 8 bytes rather than 16, halving the mapping
table and the cache lines the run-detection walk touches.

| Structure | Answers | Shape |
|---|---|---|
| Hash map (`posValues` / `negValues`) | "which rules require `role == admin`" | `map[string]*bitset.Set` |
| `CIDRIndex` | "which rules have a prefix containing 10.4.2.7" | Binary radix trie over address bits |
| `DomainIndex` | "which rules accept `api.admin.acme.com`" | Trie over **reversed labels** |
| `PrefixIndex` | "which rules have a path prefix of `/api/v2/x`" | Distinct prefix lengths, probed by slicing |
| `SuffixIndex` | "which rules have a byte suffix of `shell.php`" | Distinct suffix lengths, sliced from the right |
| `IntervalIndex` | "which rules have a range covering 14.5" | Distinct ranges sorted by min, binary searched |
| `NumSetIndex` | "which rules accept exactly 443" | `map[float64]*bitset.Set` |

### Why a reversed-label trie for domains

Walking `api.admin.acme.com` right-to-left visits `com → acme → admin → api`,
collecting a rule set at every terminal passed. That enforces label alignment for
free: `evilacme.com` walks `com → evilacme` and never reaches the `acme` node.

### Why length tables rather than character tries for affixes

Real policy sets reuse a small number of path roots (`/api`, `/api/v2`,
`/api/v2/admin`) and file extensions. Recording the **distinct lengths** that occur
and probing only those costs a handful of map lookups instead of one per character.
Substring slicing in Go shares the backing array, so the probes do not allocate.

`SuffixIndex` slices from the right rather than reversing the string, because
reversing would allocate on every lookup — unacceptable on a path that is otherwise
allocation-free.

### Why distinct intervals rather than buckets

A million policies referencing time-of-day windows still use only a handful of
distinct windows (business hours, after hours, maintenance). Risk-score conditions
collapse onto a few bands. So the number of distinct ranges stays small as the
corpus grows, and a query is a binary search plus a short scan. Past
`MaxDistinctIntervals` (4096) the index reports `Degraded` and every participant
stays a candidate — conservative, still correct, just less selective.

### Why a separate numeric hash rather than degenerate intervals

`IntervalIndex` can serve `num_in` by inserting `[v, v]` per value, and for a
handful of values it would. It fails at the shape that motivates the operator:
`dest_port IN {…}` over a couple of hundred ports turns every value into its own
distinct interval, burns through `MaxDistinctIntervals`, and drops the whole
attribute into degraded mode. Discrete membership wants a hash map — O(1), no cap,
no binary search.

Float64 keys are exact here, which is correct for the domain: ports, protocol
numbers, status codes, ICMP types are all small integers, exactly representable,
and compared with `==` by `Condition.Matches`. Negative zero is normalized so `-0`
and `+0` share a bucket, matching `==`. NaN is dropped on insert.

### Hybrid sparse/dense sets

v1 used a purely dense `[]uint64`. At 1M policies every AND touched N/64 words and
every enumeration walked the whole universe, so cost scaled with the corpus rather
than the survivors, and end-to-end speedup collapsed to ~1.1x even though the
index was still cutting candidates 10x.

A `Set` now carries whichever representation fits its cardinality: a sorted
`[]uint32` below `n/32`, a bitmap above. `Compact` chooses once at build time.

### Lazy set union in a fixed array

Nested CIDR prefixes, nested DNS suffixes and covering ranges all produce
multi-set unions. `MatchSet` keeps up to 8 constituent sets in a **fixed array**
and evaluates the union lazily — `Contains` probes each. Materializing the union
would allocate per filter per request, and a slice rather than an array would too;
that was the bulk of the engine's remaining allocation traffic.

### Lazily built sub-indexes

An attribute almost always carries one operator family — roles are equality, source
addresses are CIDR, risk scores are ranges. Eagerly allocating every builder and
matcher per attribute meant the overwhelming majority were built, sized to the
shard, and thrown away empty. With a corpus partitioned into tens of thousands of
shards that dominated both build time and peak memory.

---

## 11. Two intersection strategies

### Per-element filtering

Materialize the single most selective posting list, then filter that list in place
against the remaining filters. Cost tracks the **surviving candidate count**, not
the corpus size, and the list only ever shrinks.

Every filter is applied rather than bailing out below some candidate count: a
filter pass over `k` candidates is `k` `Contains` probes, which is cheaper than
letting those `k` rules reach exact validation and run their full condition trees.
Stopping early would trade a cheap probe for expensive validation, and make pruning
depend on the arbitrary order filters happen to sit in.

### Where it collapses

On a large **flat** shard — one tenant, no scoping — the seed is drawn from a
filter whose non-participant complement is itself enormous. The engine materializes
tens of thousands of ints and probes each against every filter.

Measured on a 200k-rule flat shard: **5.04 ms per request and 10.6 KB of
allocation**, against 200 µs for a plain linear scan. The index was 25x slower than
the baseline it exists to beat.

### Word-parallel bitmap AND

Above a seed size of `n / 32`, the intersection runs as a bitmap AND over words
instead:

```
acc ← words(seed filter)
for each remaining filter f:
    tmp ← words(f)
    acc &= tmp        (or acc &^= tmp for a negative filter)
    if acc is all zero: stop
enumerate acc
```

Cost becomes `O(filters × n/64)` with no allocation and no per-candidate probe.
Both word buffers live in `Scratch` and are reused across requests.

Result: flat 100k went **5.04 ms → 206 µs** and **10.6 KB → 20 B**; flat 10k went
438 µs → 25.9 µs, which now beats naive 4.2x rather than trailing it.

### The threshold

Per-element cost is roughly `seed × filters` membership probes; word-parallel is
`filters × n/64` word operations. They cross near `n/64`. The divisor is **32**
rather than 64 to bias toward per-element filtering, which has the better constant
factor and does not touch a word per 64 rules that survived nothing.

### Why both paths are pinned together by a test

The strategies are chosen by a size heuristic, so on any given request only one of
them runs. A divergence between them would stay invisible until a corpus grew past
the threshold and the answers quietly changed — the worst possible failure mode for
an authorization engine.

`TestIntersectStrategies_Agree` forces each path on the same randomized input and
asserts identical candidate sets. `TestIntersectStrategies_BothAscending` pins the
ordering the two-tier walk depends on.
`TestIntersectWordParallel_HandlesPaddingBits` covers universes that are not a
multiple of 64, where a stray bit above `n` would enumerate a rule position that
does not exist.

### `bitset.OrWords`, and why not expose the array

The word-parallel path needs word access. Exposing the backing array would let a
caller mutate a set that shards share across every request, and a sparse set has no
backing array to expose. Both representations can write themselves *into* a
caller-owned buffer, and the buffer is what gets AND-ed.

---

## 12. Sharding

```
(tenant, scope) → Shard
tenant          → tenant-wide Shard
__global__      → global Shard
```

Sharding, not indexing, is what puts microsecond evaluation in reach. Ten million
rules over ten thousand tenants is roughly a thousand rules per request — that
ratio, not any bit-twiddling, is the headline.

**Scope exists because tenant alone is not a fine enough partition.** Real corpora
are heavily skewed: a single large customer can hold a six-figure rule count that
no amount of indexing makes fast on its own. Production systems partition the same
way — Zanzibar by namespace, IAM by principal and resource, Envoy RBAC per
listener.

A policy with an empty `Scope` applies across its whole tenant and lands in the
tenant-wide shard. A request reaches exactly three shards: global, tenant-wide, and
its own scope.

`Engine.InScope(tenant, scope)` reports how many **rules** a request can reach.
That is the number that governs per-request cost, and the one to watch as a
customer's shard grows. `PDP.ReachableRules` exposes it through the SDK.

---

## 13. Decision cache

Striped, direct-mapped, and **verified on every hit**.

```go
h    := hashRequest(req)
s    := &c.stripes[h % 64]
slot := (h >> 6) & c.mask
```

Three decisions worth naming:

**Hits are verified by full key compare, never trusted on hash alone.** A hash
collision in an authorization path would silently hand one subject another
subject's decision. So the hash only selects a slot and the comparison decides the
hit. `TestCache_NeverServesAcrossDifferentRequests` drives 3,000 distinct requests
through an 8-entry cache to force heavy collision pressure.

**Requests are hashed order-independently.** Go randomizes map iteration order, so
per-entry hashes are summed rather than chained — otherwise the same logical
request would land in different slots on different calls and the cache would never
hit.

**Stored keys are owned copies.** Callers routinely reuse request maps; retaining a
reference would let a later mutation corrupt the stored key and start serving wrong
decisions. `TestCache_DoesNotAliasCallerMaps` covers it.

Replacement is direct-mapped overwrite rather than LRU, which keeps lookups to a
single striped read lock with no list bookkeeping on the hot path.

`+0` and `-0` hash identically, matching `==`.

---

## 14. Concurrency and hot reload

An `Engine` is safe for concurrent use: shards are immutable after construction,
per-goroutine scratch comes from a `sync.Pool`, and the cache stripes its locks.

A `PDP` adds atomic reload. The engine sits behind an `atomic.Pointer`, so:

- A request in flight sees **one complete policy set**, never a mixture.
- `Reload` serializes on a mutex so two callers cannot interleave building and
  swapping. `Evaluate` never takes that mutex.
- A **failed** load leaves the previous set installed. A bad policy deploy degrades
  to stale rules, never to an engine that denies everything.
- `Generation` counts installed sets — the value to expose in a readiness probe or
  compare across a fleet to confirm a rollout landed.

`Reload` copies the caller's slice contents, because the engine retains policies by
reference and a caller appending to their slice afterwards would otherwise mutate a
live policy set.

An empty policy set is an **error**, not an accepted deny-everything posture. The
two are indistinguishable at the call site and the consequences differ wildly: an
empty set denies every request, which as a silent outcome of a mis-pathed file is
an outage. Callers who genuinely want deny-everything say so with an explicit
catch-all DENY policy.

Metrics are maintained with atomic adds on the evaluation path. That costs a few
nanoseconds against a multi-microsecond evaluation — a trade worth making, because
an authorization component nobody can observe is one nobody will trust in
production.

---

## 15. The bundle format and linter

### The format

JSON, because the zero-dependency property is deliberate and the standard library
ships a JSON codec and no YAML codec. A condition node is exactly one of `"all"`,
`"any"`, `"not"`, or a leaf carrying `"attr"` and `"op"` — a shape chosen to stay
readable to a human reviewer.

A node with **no** form and a node with **several** are both invalid. The second
matters: resolving ambiguity by precedence would let the reader and the engine
disagree about what a rule means.

### Two encoding traps, handled

**`omitempty` destroys the catch-all.** An empty `"all"` means match-everything —
the catch-all rule. With `omitempty` it serializes to `{}` and reloads as a node
with no form at all, which the linter then rejects. Without `omitempty`, every leaf
sprouts `"all": null`. So `Node.MarshalJSON` selects the form explicitly and writes
an empty combinator as `[]`.

**Unknown fields are rejected.** `"polices"` instead of `"policies"` would
otherwise load as an empty bundle that denies every request — an outage presented
as a successful load.

**A UTF-8 BOM is skipped.** JSON's grammar has no place for one, so `encoding/json`
reports `invalid character 'ï'`, which tells a policy author nothing. Windows
editors and shell redirections emit a BOM by default, so a first bundle can easily
arrive with one.

### Why the linter is not optional

This engine fails closed by design. A condition comparing a string attribute with a
numeric operator does not error — it simply never fires, which is
indistinguishable from a rule the author meant to be narrow. **Load time is the
only place that can be caught.** The linter is what makes the fail-closed posture
safe rather than treacherous.

What it reports, among others:

| Finding | Severity | Why |
|---|---|---|
| Operator/type mismatch against the registry | Error | The condition can never match |
| `eq`/`ne` given several values | Error | Only `Values[0]` is read; the rule is narrower than it looks |
| Empty `"any"` | Error | Matches nothing, so the rule is dead |
| Uncompilable regex | Error | |
| Inverted range (`min > max`) | Error | Can never match |
| Missing operands for an operator | Error | |
| Invalid CIDR | Error | |
| Duplicate policy or rule ID | Error | IDs appear in decisions and audit trails |
| Tree deeper than 16, or over 64 conditions | Error | An unbounded tree is a DoS vector against every request reaching the shard |
| Policy with no rules | Error | Can never produce a verdict |
| Rule priorities set under an algorithm that ignores them | Warning | Reads as ordering the rules when it does nothing |
| `suffix` on something shaped like a hostname | Warning | Would accept the lookalike domain |
| Unregistered attribute name | Warning | See below |
| Catch-all rule (no `when`) | Warning | Matches every request in scope |
| Single-branch `"any"` | Warning | Costs the index for nothing |
| Non-canonical CIDR (bits below the mask) | Warning | |
| Operands the operator ignores | Warning | An author who wrote them believes they do something |

**Unregistered attributes are a warning, not an error, by default.** The registry
covers the protocol and identity surface, but customers legitimately carry their own
attributes — an internal risk signal, a bespoke resource label — and refusing those
at load time would force every integration to fork the registry. The warning still
fires, so a typo in a registry name is visible rather than silent.
`StrictAttributes` promotes it once the vocabulary settles.

One warning was deliberately narrowed during development: an empty string among
several values is often correct (a NULL TCP scan genuinely presents no flags, so
`tcp_flags in ["fin,syn", "", "fin,psh,urg"]` is how the three classic
invalid-flag scans are expressed), so only a *sole* empty value warns.

### Summarize

`Bundle.Summarize` reports policy, rule and condition counts plus **how much of
the bundle the index can prune on** — the AND-spine share. A policy set written
mostly as disjunctions is correct but slow, and that is worth knowing before it
ships rather than after a latency alert. `tessaraop -lint` prints it.

A test pins the serialized-form spine count against the model's own extraction, so
the two implementations of that rule cannot drift.

---

## 16. Ingestion

`internal/ingest` builds a `model.Request` from real traffic. Everything delegates
to code that already has to be right: `net/http` for requests, `net/netip` for
addresses, `crypto/tls` for handshake state, `mime` for media types.

**Why that boundary is deliberate.** Parser-differential bugs are one of the most
productive sources of authorization bypasses: when the component making the
decision parses a request differently from the component serving it, an attacker
crafts input the two disagree about. A hand-rolled TCP/IP or HTTP decoder inside an
authorization hot path is exactly that shape of mistake.

### The three enforced security properties

**1. `X-Forwarded-For` requires an explicit trusted-hop count, and defaults to
ignoring the header.** The header is attacker-controlled on its left, so taking the
leftmost entry — the common implementation — lets a client claim any source address
and walk through a CIDR allowlist. With `trustedHops = n`, the `(n+1)`-th entry
from the right is the last one your own infrastructure wrote; everything left of it
is discarded. When fewer hops arrive than configured, the leftmost value is recorded
as `http.header.x-forwarded-for-claimed` rather than promoted to the verified
source address.

**2. Credentials never become attributes.** `Authorization`,
`Proxy-Authorization`, `Cookie` and `Set-Cookie` are excluded, and cookie values are
populated only for names an integrator allowlists via `WithCookies`. Attributes flow
into the decision cache, into logs, and into whatever an integration does with a
`Request` afterwards; a bearer token or session cookie copied into that path is a
credential leak waiting for a debug log line. No policy needs the secret — the
parsed results (`token.valid`, `token.scopes`, `api.key_id`,
`http.authorization_scheme`) carry everything a rule can use.

**3. The clock is a parameter.** `AtTime(t)` rather than reading `time.Now`
internally, so replaying an audited request yields the same answer.

### Normalizations that matter for correctness

The host is lowercased and port-stripped, so a `dnssuffix` condition on
`admin.acme.com` matches `Admin.Acme.com:8443`. Without it the rule would silently
not apply.

Both the cleaned path and the raw path are exposed. Comparing them is how a policy
detects traversal and encoding tricks — a single normalized value would hide it, and
only the raw value would make every ordinary rule fragile.

### What it deliberately does not do

No I/O, no DNS lookup, no threat-intelligence enrichment, and no body reading
unless explicitly asked. Geo-IP, IP reputation, ASN, session validity and token
verification all need a store or a network call, so they arrive through
`Set`/`SetNum` rather than being inferred.

Layer 3 and 4 header fields beyond what a `net.Conn` exposes — TTL, TCP flags,
fragmentation, DSCP — are not reachable from Go's socket abstraction at all. They
come from whatever dataplane sits in front of the application, through the same
seam. **An adapter that fabricated a TTL would be worse than one that omits it**,
because a policy on a fabricated attribute reads as enforced when it is not.

Token signature verification is the caller's job. Doing it here would require key
material, key rotation, clock policy and an audience list, all of which belong to
the integration — and a token library that quietly accepted `alg=none` inside an
authorization engine would be a critical vulnerability. `TokenInfo` carries a
verdict the caller already reached.

Body inspection takes `[]byte`, not a reader: consuming `http.Request.Body` inside
an authorization check would leave the handler with nothing to read. It is bounded,
because an unbounded read in an authorization path is a memory-exhaustion vector
reachable by anyone who can send a request.

---

## 17. The PDP server

Four endpoint shapes over the same policy set, because an authorization engine only
gets adopted if it speaks the protocol the customer's proxy already speaks. Asking
a platform team to write a new sidecar is how a pilot stalls.

| Endpoint | Shape |
|---|---|
| `POST /v1/decision` | Native JSON: full request in, full decision out |
| `ANY /v1/authz` | Forward-auth: status code is the answer |
| `POST /v1/data/tessaraop` | OPA data API envelope |
| `GET /v1/attributes` | The registry as JSON |
| `GET /healthz` `/readyz` `/metrics` `/v1/info` | Operations |
| `POST /v1/reload` | Atomic reload, token-guarded |

### `/v1/authz` is the breadth play

Envoy's ext_authz HTTP service, NGINX `auth_request`, Traefik ForwardAuth, HAProxy,
Istio's ext_authz and Caddy's `forward_auth` all work identically: forward the
original request's headers to a URL and act on the status code. One handler covers
all of them, with no protobuf dependency and no per-proxy adapter.

**It never returns 5xx.** Every one of those proxies treats a 5xx as a failure of
the authorizer rather than a denial, and most are configured to **fail open** on
it. Returning 500 on a malformed request would therefore be the one response that
could grant access by accident. Anything this handler cannot understand is a 403
with the reason in a header. `TestForwardAuth_NeverReturns5xx` drives deliberately
awkward requests to prove it.

Obligations come back in `X-Tessaraop-Obligations`, which those proxies can copy
onto the upstream request — that is how a `require_mfa` reaches the application
that has to enforce it.

### Why the OPA shape earns its place

A team already calling OPA has the client code, the retry behaviour and the
dashboards. Matching the request and response envelope turns migration into a URL
change.

Flat input is accepted, because that is what an existing OPA policy's `input` looks
like. Each key is typed **from the registry rather than from its JSON type**: a
port arriving as `"443"` from one client and `443` from another must reach the same
numeric map, or the same policy behaves differently per caller. An unregistered key
falls back to its JSON type and says so in `warnings`.

### Operational details

`readyz` is separate from `healthz` because they answer different questions and
drive different orchestrator behaviour: a process that is alive but holds no policy
denies every request, so it must be pulled from the load balancer rather than
restarted.

Metrics are emitted in Prometheus text format **by hand**, keeping the
zero-dependency property. The format is stable and simple enough that this is a
better trade than a dependency in a request path.
`tessaraop_rules_validated_total / tessaraop_evaluations_total` is the index's
live selectivity.

A failed reload returns 422 and says explicitly that the previous policy set
remains in effect — an operator seeing a failed reload needs to know whether the
service is now denying everything or still serving the old rules.

`/v1/reload` is the only mutating endpoint and the only one worth protecting, since
reload changes what every subsequent request is authorized against. The token is
compared in constant time. Leaving it unset logs a warning at startup, as does
leaving `TrustedProxyHops` at 0.

### One bug worth recording

The handler originally applied the transport peer address *after* resolving
forwarded headers, so behind a proxy the proxy's own address overwrote the real
client's and a blocklist on the client never fired. Peer first, trusted headers
last.

---

## 18. Correctness strategy

The engine is too intricate to trust by inspection. Correctness rests on five
things.

**1. Shared semantics.** Both evaluators route every match through
`Condition.Matches` / `ConditionExpr.Matches` and resolve through the same
`Accumulator`, driving both tiers via `model.ConsiderPolicy`. The fast path has no
second copy of the rules to drift from.

**2. The index is a pre-filter only.** Over-inclusive but never under-inclusive,
and survivors always face the real match logic. A bug in an index costs
performance, not correctness — asserted directly by
`TestCandidates_NeverExcludesAMatchingRule` across 200 randomized corpora × 20
requests, spanning every operator family and every tree shape.

**3. Differential testing.** Randomized corpora through both evaluators under all
three algorithms. Where the credited rule is not canonically defined, the test
verifies it names a rule that is in scope, actually matches, and carries the
winning effect — rather than asserting a false determinism.
`TestDifferential_MultiRuleAndTreeHeavyCorpus` raises rules-per-policy to 8,
because a grouping error in the contiguous-run walk only surfaces when policies
hold several candidate rules at once.

**4. Both intersection strategies pinned together.** See §11.

**5. Adversarial and concurrent cases.** Missing attributes, values in the wrong
typed map, unknown tenants, empty requests, lookalike domains, reload under
concurrent evaluation, 8 goroutines against one engine — all under `-race`.

### Security properties with dedicated tests

- **DNS label alignment** — `TestCondition_SuffixIsNotLabelAligned`,
  `TestDomain_RejectsUnalignedSuffix`
- **Verified cache hits** — `TestCache_NeverServesAcrossDifferentRequests`
- **`X-Forwarded-For` spoofing** — `TestFromForwardedHeaders_HopCounting`,
  `TestFromForwardedHeaders_ClaimedAddressIsNotTrusted`
- **No credential becomes an attribute** —
  `TestFromHTTPRequest_SkipsCredentialHeaders`,
  `TestWithCookies_AllowlistIsRequired`
- **Fail-open proxies cannot be tricked** — `TestForwardAuth_NeverReturns5xx`
- **Bad deploys do not cause outages** —
  `TestReload_FailureKeepsThePreviousPolicySet`
- **NaN cannot satisfy a negation** — `TestCondition_NaNSatisfiesNothing`
- **TLS version floors are monotonic** —
  `TestTLSVersionNumbering_SortsSSLv3Lowest`

### Two live bugs found by these tests

Recorded because they are the evidence the strategy works, not decoration.

1. **`tls.version_num` encoded SSLv3 as 30**, above TLS 1.3's 13, so a `>= 12`
   version floor accepted SSLv3 — exactly the protocol such a rule exists to
   reject.
2. **The forward-auth handler overwrote the resolved client address** with the
   transport peer, so behind a proxy a client blocklist never fired.

---

## 19. Performance

AMD Ryzen 5 5600H, 12 threads, Go 1.26.5. Corpora from `internal/genutil`: skewed
tenant sizes, ~2 rules per policy, 27% of rules carrying an `OR` or `NOT`.

Sizes are in **policies**; the indexed universe is **rules**, about 2x that.

### Sharded

| Corpus | Naive | Engine | Speedup | Rules validated | Alloc |
|---|---:|---:|---:|---:|---:|
| 10,000 | 10.1 µs | **3.2 µs** | 3.2x | 2 | 0 B |
| 100,000 | 212 µs | **4.1 µs** | **51x** | 30 | 0 B |
| 1,000,000 | 2.07 ms | not re-measured | — | — | — |

### Unsharded — the index in isolation

| Corpus | Naive | Indexed | Ratio |
|---|---:|---:|---:|
| 10,000 | 108 µs | **25.9 µs** | 4.2x faster |
| 100,000 | 99 µs | 206 µs | 2.1x slower |

### The word-parallel fix, measured

| Flat corpus | Before | After |
|---|---:|---:|
| 10,000 | 438 µs, 138 B/op | **25.9 µs, 3 B/op** |
| 100,000 | 5.04 ms, 10,646 B/op | **206 µs, 20 B/op** |

**Not re-measured after the rule restructure:** the 1M sharded row, cache hit
latency, multi-core throughput, worst-case (whale) shard latency, and index build
time and memory. Earlier figures for those were taken on different hardware and
before rules existed, so they are omitted rather than carried forward as if
current.

The benchmarks are layered so each effect is attributable rather than blended:

```
BenchmarkNaiveFlat      linear scan, unsharded
BenchmarkIndexedFlat    indexing, unsharded          → isolates indexing
BenchmarkNaiveSharded   linear scan, multi-tenant
BenchmarkEngine         indexing + sharding          → isolates sharding
BenchmarkEngineCached   + decision cache
BenchmarkEngineParallel throughput across cores
BenchmarkWorstCaseShard tail latency on the whale tenant
BenchmarkIndexBuild     one-time construction
```

The `"validated"` metric counts **rules**, not policies: a rule is the atomic
indexed unit, so it is the number that tracks per-request cost.

---

## 20. Limitations

**1. On a large flat scope, a short-circuiting linear scan can still win.** Naive
is not truly O(N) — under deny-overrides it stops at the first matching deny, and
~20% of generated rules are denies. The index must touch every word of the shard's
bitmap before it knows what survived. The answer is scoping, not more index; the
sharded numbers are the same corpus with `scope` set. This case was 25x worse
before the word-parallel path.

**2. Expressiveness costs pruning, by construction.** Only AND-spine conditions can
be indexed (§9). A rule rooted at `Or` gets no index help at all. Over-inclusive,
never under-inclusive, and paid only by the rules that use it.

**3. Obligation attribution under the overrides algorithms is not canonical**
(§4). Use `first-applicable` where it matters.

**4. Parts of the rule catalog are not derivable in-process** (§16). Populated
explicitly rather than fabricated.

**5. Adding a policy rebuilds its shard.** Reload is whole-corpus and atomic —
right for bundle-based deployment, wrong for high-frequency single-policy writes.

**6. Build-time memory has not been re-measured** since the rule restructure, and
the rule count is roughly 2x the policy count, so it is expected to have grown.

**7. Regex and substring conditions are never indexed.** A WAF-style corpus that is
mostly signatures gets pruning only from attribute presence.

---

## 21. Roadmap

1. **Tuple space search** — group rules by which attributes they constrain, then
   hash the request's values per group. This sidesteps the non-participant
   inflation behind limitation 1, and is the direct answer to the flat-shard case.
2. **Incremental index updates** — sharding already bounds the blast radius;
   per-shard rebuild on write is the next increment.
3. **Importers** — AWS IAM, Kubernetes NetworkPolicy, Envoy RBAC, Cedar. The
   bundle format and linter are the target; each source format is its own
   semantics problem and needs its own fidelity statement about what does and does
   not translate.
4. **Re-measure the full benchmark matrix** at 1M policies, including cache,
   parallel throughput, whale-shard tail, and build cost.
5. **Build-time memory** — sub-index construction can stream rather than buffer.
6. **BDD/MTBDD compilation** — would also yield policy conflict and redundancy
   detection as a byproduct.
7. **Obligation union semantics** — an option to collect obligations from every
   matching same-effect rule rather than only the credited one, which would remove
   limitation 3 at the cost of short-circuiting.
