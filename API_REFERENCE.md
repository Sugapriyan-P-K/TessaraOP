# TessaraOP — API Reference

Every type and function in the project, grouped by package, with its source
doc comment. Exported API first, then unexported helpers.

This file is generated from the source. The canonical view is `go doc`:

```bash
go doc -all ./internal/engine
go doc ./internal/model Policy
```

---

## Contents

- [`model`](#package-model) — Core types, operator semantics, combining algorithms. Imports nothing internal.
- [`bitset`](#package-bitset) — Hybrid sparse/dense integer sets.
- [`matcher`](#package-matcher) — Per-attribute index structures: CIDR trie, DNS suffix trie, prefix table, interval table.
- [`index`](#package-index) — Per-attribute sub-indexes and candidate-set intersection.
- [`engine`](#package-engine) — Sharding, algorithm selection, decision cache. The top-level decision point.
- [`naive`](#package-naive) — Linear-scan oracle used by differential tests and benchmarks.
- [`indexed`](#package-indexed) — Single-shard indexed evaluator; the benchmark control.
- [`genutil`](#package-genutil) — Synthetic multi-tenant corpus generator.
- [`main`](#package-main) — Command-line interface.

---

## Package `model`

Core types, operator semantics, combining algorithms. Imports nothing internal.

```go
import "github.com/suga/tessaraop/internal/model"
```

<details><summary>Index</summary>

- type `Effect`
- type `Operator`
- type `Condition`
- type `Policy`
- type `Request`
- type `Decision`
- type `Evaluator`
- type `Algorithm`
- type `Accumulator`
- func (c Condition) `Matches`
- func `MatchDNSSuffix`
- func (p Policy) `Matches`
- func (r Request) `InScope`
- func (d Decision) `String`
- func `NewAccumulator`
- func (a *Accumulator) `Consider`
- func (a *Accumulator) `CanShortCircuit`
- func (a *Accumulator) `SetScanned`
- func (a *Accumulator) `Resolve`
- func `Evaluate`
- func `EvaluateIndices`

</details>

### Types

#### `Effect`

```go
type Effect string
```
<sub>`model.go`</sub>

Effect is the outcome a policy grants if all its conditions match.

#### `Operator`

```go
type Operator string
```
<sub>`model.go`</sub>

Operator is the comparison a Condition applies to a request attribute.

Operators fall into three families, which matters because each family
needs a different index structure:

Set family    (eq, ne, in, nin, exists, nexists) -> hash map index
Numeric family(range, gt, lt)                    -> interval segment index
Network family(cidr, ncidr)                      -> radix trie index
Name family   (dnssuffix, prefix)                -> label/prefix trie index

#### `Condition`

```go
type Condition struct
```
<sub>`model.go`</sub>

Condition is a single predicate within a policy.

Absent-attribute semantics (fail closed): a condition whose attribute is
not present on the request does NOT match — including negations. So
`source_ip NOT IN 203.0.113.0/24` requires source_ip to be present AND
outside the block. OpNotExists is the sole operator that matches on
absence, by definition. The index layer mirrors this exactly.

#### `Policy`

```go
type Policy struct
```
<sub>`model.go`</sub>

Policy is a single rule: if every condition matches, Effect applies.

TenantID and Scope together form the shard key, and that pairing is what
makes a multi-million policy corpus tractable: the working set per request
is one shard, not the corpus.

Scope subdivides a tenant, typically by resource type or application. It
exists because tenant alone is not a fine enough partition — real corpora
are heavily skewed, and a single large customer can hold a six-figure policy
count that no amount of indexing makes fast on its own. Production systems
partition the same way: Zanzibar by namespace, IAM by principal and
resource, Envoy RBAC per listener. A policy with an empty Scope applies
across its whole tenant.

#### `Request`

```go
type Request struct
```
<sub>`model.go`</sub>

Request is a single access check. Attributes are split by type so the hot
path never parses or casts: string attributes, numeric attributes and IP
attributes each land in the map their operators read directly.

#### `Decision`

```go
type Decision struct
```
<sub>`model.go`</sub>

Decision is the result of evaluating a request against a policy set.

PoliciesScanned is the core instrumentation metric: it counts policies that
reached exact validation. Naive always scans the whole in-scope set; the
indexed engine should scan a small fraction.

MatchedPolicyID names *a* policy that matched and carries the winning
effect, not necessarily a canonical one. Under DenyOverrides and
PermitOverrides several policies can match with the same effect, and the
algorithms say nothing about which of them to credit — so the engine reports
whichever it reached first and stops, since scanning the remainder to pick a
canonical winner would forfeit short-circuiting for no change in the
decision. FirstApplicable is the exception: it must examine every candidate
anyway, and its priority-then-ID ordering makes the reported policy fully
deterministic. Audit trails that need a stable attribution should use
FirstApplicable.

#### `Evaluator`

```go
type Evaluator interface
```
<sub>`model.go`</sub>

Evaluator is implemented by every evaluation strategy. Benchmarks and the
differential test depend only on this interface.

#### `Algorithm`

```go
type Algorithm string
```
<sub>`model.go`</sub>

Algorithm selects how multiple matching policies combine into one decision.

#### `Accumulator`

```go
type Accumulator struct
```
<sub>`model.go`</sub>

Accumulator collects matching policies during a scan and resolves them into
a Decision under the chosen Algorithm. Both the naive and indexed evaluators
drive this same type, so combining semantics cannot drift between them.

### Functions and methods

**Methods on `Condition`**

```go
func (c Condition) Matches(req Request) bool
```
<sub>`model.go`</sub>

Matches evaluates this single condition against a request. This is the
ground truth for the entire engine: the naive evaluator calls it directly,
and the indexed evaluator calls it in its final validation pass. The index
is only ever a pre-filter over this function, never a replacement for it.

```go
func MatchDNSSuffix(host, suffix string) bool
```
<sub>`model.go`</sub>

MatchDNSSuffix reports whether host equals suffix or is a subdomain of it.
Matching is label-aligned, so "evilexample.com" does NOT match "example.com"
— a plain strings.HasSuffix here would be a real security bug.

```go
func NewAccumulator(alg Algorithm) *Accumulator
```
<sub>`model.go`</sub>

NewAccumulator returns an accumulator for the given algorithm, defaulting to
DenyOverrides when alg is empty.

```go
func Evaluate(policies []Policy, req Request, alg Algorithm) Decision
```
<sub>`model.go`</sub>

Evaluate scans every policy in the slice. This is the reference
implementation used by the naive evaluator and by differential tests.

```go
func EvaluateIndices(policies []Policy, positions []int, req Request, alg Algorithm) Decision
```
<sub>`model.go`</sub>

EvaluateIndices validates only the candidate positions the index produced,
indexing into the original slice rather than copying policies into a new
one. The copy version allocated proportionally to candidate-set size and
showed up directly in benchmark allocs/op.

**Methods on `Policy`**

```go
func (p Policy) Matches(req Request) bool
```
<sub>`model.go`</sub>

Matches reports whether every condition matches. An empty condition list
matches everything (catch-all), which is how default-deny backstops and
blanket grants are expressed.

**Methods on `Request`**

```go
func (r Request) InScope(p *Policy) bool
```
<sub>`model.go`</sub>

InScope reports whether a policy is reachable by this request: it must
belong to the global tenant, or to the request's tenant at either
tenant-wide scope or the request's own scope.

**Methods on `Decision`**

```go
func (d Decision) String() string
```
<sub>`model.go`</sub>

String renders a decision for logs and test failures.

**Methods on `Accumulator`**

```go
func (a *Accumulator) Consider(p *Policy)
```
<sub>`model.go`</sub>

Consider feeds one policy that has already been confirmed to match.

```go
func (a *Accumulator) CanShortCircuit() bool
```
<sub>`model.go`</sub>

CanShortCircuit reports whether the outcome is already decided, so the
caller may stop scanning. Only DenyOverrides can short-circuit (on the
first Deny) — the others must see every candidate.

```go
func (a *Accumulator) SetScanned(n int) { a.scanned = n }
```
<sub>`model.go`</sub>

SetScanned records how many policies reached exact validation.

```go
func (a *Accumulator) Resolve() Decision
```
<sub>`model.go`</sub>

Resolve produces the final decision under the configured algorithm.

---

## Package `bitset`

Hybrid sparse/dense integer sets.

```go
import "github.com/suga/tessaraop/internal/bitset"
```

<details><summary>Index</summary>

- type `Set`
- type `Builder`
- func `New`
- func `NewDense`
- func `Full`
- func (s *Set) `Universe`
- func (s *Set) `Cardinality`
- func (s *Set) `IsSparse`
- func (s *Set) `Add`
- func (s *Set) `Contains`
- func (s *Set) `Compact`
- func (s *Set) `AppendMembers`
- func (s *Set) `Members`
- func (s *Set) `OrInto`
- func `Words`
- func `AppendWordMembers`
- func `CountWords`
- func (s *Set) `Or`
- func (s *Set) `And`
- func (s *Set) `AndNot`
- func (s *Set) `Complement`
- func `NewBuilder`
- func (b *Builder) `Add`
- func (b *Builder) `Build`
- func `FromSorted`
- func `FromUnsorted`

</details>

### Types

#### `Set`

```go
type Set struct
```
<sub>`bitset.go`</sub>

Set is an immutable-after-Compact set of non-negative ints below Universe.

#### `Builder`

```go
type Builder struct
```
<sub>`bitset.go`</sub>

Builder accumulates members efficiently when the final cardinality is not
known in advance, deferring the representation choice to Build.

### Functions and methods

```go
func New(n int) *Set
```
<sub>`bitset.go`</sub>

New returns an empty set over [0, n).

```go
func NewDense(n int) *Set
```
<sub>`bitset.go`</sub>

NewDense returns an empty dense set over [0, n). Used by builders that will
set many bits and compact afterwards.

```go
func Full(n int) *Set
```
<sub>`bitset.go`</sub>

Full returns the set containing every element of [0, n).

```go
func Words(n int) int { return (n + 63) / 64 }
```
<sub>`bitset.go`</sub>

Words returns the number of 64-bit words needed to cover n elements.

```go
func AppendWordMembers(dst []int, words []uint64) []int
```
<sub>`bitset.go`</sub>

AppendWordMembers appends the set bits of words to dst in ascending order.

```go
func CountWords(words []uint64) int
```
<sub>`bitset.go`</sub>

CountWords returns the population count of a raw word slice.

```go
func NewBuilder(n int) *Builder { return &Builder{n: n, dst: NewDense(n)} }
```
<sub>`bitset.go`</sub>

NewBuilder returns a Builder accumulating members over the universe [0, n).
It starts dense because construction sets bits in arbitrary order; Build
picks the final representation once the cardinality is known.

```go
func FromSorted(members []uint32, n int) *Set
```
<sub>`bitset.go`</sub>

FromSorted wraps an already-sorted, duplicate-free slice as a sparse set
without copying. The caller must not mutate the slice afterwards.

```go
func FromUnsorted(members []uint32, n int) *Set
```
<sub>`bitset.go`</sub>

FromUnsorted sorts and dedupes members into a sparse set.

**Methods on `Set`**

```go
func (s *Set) Universe() int { return s.n }
```
<sub>`bitset.go`</sub>

Universe returns the size of the domain this set is defined over.

```go
func (s *Set) Cardinality() int { return s.card }
```
<sub>`bitset.go`</sub>

Cardinality returns the number of members.

```go
func (s *Set) IsSparse() bool { return s.dense == nil }
```
<sub>`bitset.go`</sub>

IsSparse reports which representation is in use (exposed for tests and for
the benchmark harness's reporting).

```go
func (s *Set) Add(i int)
```
<sub>`bitset.go`</sub>

Add inserts i. Only valid on dense sets during construction; call Compact
when the build is finished.

```go
func (s *Set) Contains(i int) bool
```
<sub>`bitset.go`</sub>

Contains reports membership: O(1) on dense sets, O(log k) on sparse ones.
This is the hot-path primitive — the engine's intersection filter calls it
once per surviving candidate per attribute.

```go
func (s *Set) Compact() *Set
```
<sub>`bitset.go`</sub>

Compact converts to whichever representation is smaller for the current
cardinality. Called once at the end of index construction.

```go
func (s *Set) AppendMembers(dst []int) []int
```
<sub>`bitset.go`</sub>

AppendMembers appends every member in ascending order to dst and returns
the extended slice. Passing a reusable buffer keeps the hot path
allocation-free across requests.

```go
func (s *Set) Members() []int { return s.AppendMembers(make([]int, 0, s.card)) }
```
<sub>`bitset.go`</sub>

Members returns a freshly allocated slice of all members. Convenience for
tests; the hot path uses AppendMembers with a reused buffer.

```go
func (s *Set) OrInto(dst []uint64)
```
<sub>`bitset.go`</sub>

OrInto ORs this set's members into a raw word slice, which the caller sizes
to the universe. It is the primitive behind the engine's word-parallel
intersection path: folding sets into a reusable accumulator lets the
intersection proceed 64 policies at a time instead of one at a time.

Dense sets fold with a word-wise OR; sparse sets set their members
individually, which is still proportional to cardinality rather than to the
universe.

```go
func (s *Set) Or(other *Set) *Set
```
<sub>`bitset.go`</sub>

Or returns the union. Used at build time to fold multiple value postings
into one set (e.g. an `in [a,b,c]` condition).

```go
func (s *Set) And(other *Set) *Set
```
<sub>`bitset.go`</sub>

And returns the intersection. Build-time helper; the request hot path uses
the filter-in-place approach in the index layer instead.

```go
func (s *Set) AndNot(other *Set) *Set
```
<sub>`bitset.go`</sub>

AndNot returns the difference s \ other. This is how negated conditions
(ne, nin, ncidr) build their candidate sets: start from the universe of
policies carrying the condition, remove the ones the request value hits.

```go
func (s *Set) Complement() *Set { return Full(s.n).AndNot(s) }
```
<sub>`bitset.go`</sub>

Complement returns [0, n) \ s.

**Methods on `Builder`**

```go
func (b *Builder) Add(i int) { b.dst.Add(i) }
```
<sub>`bitset.go`</sub>

Add records i as a member. Adding the same value twice is harmless.

```go
func (b *Builder) Build() *Set { return b.dst.Compact() }
```
<sub>`bitset.go`</sub>

Build finalizes the set, compacting to the sparse representation when that
is the smaller of the two. The Builder must not be used afterwards.

### Unexported helpers

```go
func sparseLimit(n int) int
```
<sub>`bitset.go`</sub>

sparseLimit reports the cardinality below which the sparse representation
is the smaller of the two. A sparse entry costs 4 bytes; the dense bitmap
costs n/8 bytes total, so sparse wins below n/32. The floor keeps small
universes from flapping between representations.

**Methods on `Set`**

```go
func (s *Set) writeInto(dst *Set)
```
<sub>`bitset.go`</sub>

writeInto ORs this set's members into dst's dense word slice. Build-time
helper for Or; dst must already be dense and cover this set's universe.

```go
func (s *Set) recount()
```
<sub>`bitset.go`</sub>

recount recomputes cardinality from the dense words. Needed after words are
written directly rather than through Add, which maintains the count itself.

---

## Package `matcher`

Per-attribute index structures: CIDR trie, DNS suffix trie, prefix table, interval table.

```go
import "github.com/suga/tessaraop/internal/matcher"
```

<details><summary>Index</summary>

- type `CIDRIndex`
- type `DomainIndex`
- type `IntervalIndex`
- type `MatchSet`
- type `PrefixIndex`
- func `NewCIDRIndex`
- func (c *CIDRIndex) `Insert`
- func (c *CIDRIndex) `Freeze`
- func (c *CIDRIndex) `Lookup`
- func `NewDomainIndex`
- func (d *DomainIndex) `Insert`
- func (d *DomainIndex) `Freeze`
- func (d *DomainIndex) `Lookup`
- func `NewIntervalIndex`
- func (x *IntervalIndex) `Insert`
- func (x *IntervalIndex) `Degraded`
- func (x *IntervalIndex) `Freeze`
- func (x *IntervalIndex) `Lookup`
- func `Single`
- func (m MatchSet) `Union`
- func (m *MatchSet) `Contains`
- func (m *MatchSet) `OrInto`
- func (m *MatchSet) `EstimatedCardinality`
- func (m *MatchSet) `IsEmpty`
- func (m *MatchSet) `AppendMembers`
- func `NewPrefixIndex`
- func (x *PrefixIndex) `Insert`
- func (x *PrefixIndex) `Freeze`
- func (x *PrefixIndex) `Lookup`

</details>

### Types

#### `CIDRIndex`

```go
type CIDRIndex struct
```
<sub>`cidr.go`</sub>

CIDRIndex answers "which policies have a CIDR condition whose block
contains this address" via a binary radix trie over address bits.

A query walks at most 32 (IPv4) or 128 (IPv6) levels and collects the
policy set at every terminal node it passes through, because an address
inside 10.0.0.0/8 is also inside 10.4.0.0/16 — every enclosing prefix
matches, not just the longest. Walk cost is bounded by address width and is
independent of how many blocks the corpus holds, which is the point versus
testing every prefix in turn.

Addresses are canonicalized with Unmap, so 10.0.0.0/8 and ::ffff:10.0.0.0/104
land in the same trie and a query for either form finds both. A genuine
IPv6 prefix written to deliberately cover IPv4-mapped space is not modeled;
real policy corpora do not mix the families that way.

#### `DomainIndex`

```go
type DomainIndex struct
```
<sub>`domain.go`</sub>

DomainIndex answers "which policies have a DNS-suffix condition that
accepts this host" via a trie over reversed labels.

Labels are walked right to left, so api.admin.acme.com visits
com -> acme -> admin -> api and collects a policy set at every terminal it
passes. That structure enforces label alignment for free: evilacme.com
walks com -> evilacme and never reaches the acme node, so it cannot match a
policy scoped to acme.com. A plain strings.HasSuffix check would match it —
that is a real and frequently exploited authorization bypass, so the index
and the validation path in model.MatchDNSSuffix both align on labels.

Hosts are expected already lowercased by the ingest layer, as any gateway
or proxy normalizes them; the hot path does not allocate to case-fold.

#### `IntervalIndex`

```go
type IntervalIndex struct
```
<sub>`interval.go`</sub>

IntervalIndex answers "which policies have a numeric condition whose range
covers this value".

It groups policies by *distinct* range rather than building a per-value or
per-bucket structure. That choice comes from what real policy corpora look
like: a million policies referencing time-of-day windows still only use a
handful of distinct windows (business hours, after hours, maintenance
windows), and risk-score conditions collapse onto a few bands. So the
number of distinct ranges stays small even as the corpus grows, and a query
is a binary search plus a short scan over ranges whose lower bound is below
the query value.

Ranges are stored half-inclusive-agnostic: OpGreaterThan and OpLessThan
arrive as ranges with an infinite end, which sort and compare correctly
against ±Inf without special cases.

#### `MatchSet`

```go
type MatchSet struct
```
<sub>`matchset.go`</sub>

MatchSet is the union of zero or more precomputed sets, evaluated lazily.

Two things keep this off the heap. The union is lazy, so a CIDR lookup
matching several nested prefixes never OR-s them into a new set — the engine
materializes only the single most selective MatchSet and probes the rest with
Contains. And the members live in a fixed array rather than a slice, because
a slice would allocate once per filter per request, which measured as the
bulk of the engine's allocation traffic.

#### `PrefixIndex`

```go
type PrefixIndex struct
```
<sub>`prefix.go`</sub>

PrefixIndex answers "which policies have a prefix condition satisfied by
this path".

Rather than a character trie, it records the distinct prefix lengths that
actually occur in the corpus and probes only those. A path is checked
against however many distinct lengths exist — typically a handful, since
real policy sets reuse a small number of path roots (/api, /api/v2,
/api/v2/admin) — instead of one probe per character. Substring slicing in
Go shares the backing array, so the probes do not allocate.

Semantics match model.OpPrefix exactly: a raw byte-prefix test, so
/api/v2/admin does match /api/v2/adminfoo. That is deliberately the same
rule the validation pass applies, since an index that disagreed with
validation in the stricter direction would wrongly drop matching policies.

### Unexported types

#### `cidrTrie`

```go
type cidrTrie struct
```
<sub>`cidr.go`</sub>

cidrTrie is a binary radix trie over address bits, held in one flat slice.
Nodes reference children by index rather than pointer, which keeps the trie
in contiguous memory and its nodes small.

#### `cidrNode`

```go
type cidrNode struct
```
<sub>`cidr.go`</sub>

cidrNode is one bit position. builder accumulates during construction and
is replaced by set at Freeze; a node with a non-nil set terminates at least
one prefix.

#### `domainNode`

```go
type domainNode struct
```
<sub>`domain.go`</sub>

domainNode is one DNS label in the reversed-label trie. A non-nil set marks
a label path that some policy registered as a suffix.

#### `intervalEntry`

```go
type intervalEntry struct
```
<sub>`interval.go`</sub>

intervalEntry is one distinct numeric range and every policy that uses it.
Entries are kept sorted by min so Lookup can binary-search the candidates.

### Functions and methods

```go
func NewCIDRIndex() *CIDRIndex
```
<sub>`cidr.go`</sub>

NewCIDRIndex returns an empty index ready for Insert.

```go
func NewDomainIndex(universe int) *DomainIndex
```
<sub>`domain.go`</sub>

NewDomainIndex returns an empty index over a shard of `universe` policies.

```go
func NewIntervalIndex(universe int) *IntervalIndex
```
<sub>`interval.go`</sub>

NewIntervalIndex returns an empty index over a shard of `universe` policies.

```go
func Single(s *bitset.Set) MatchSet
```
<sub>`matchset.go`</sub>

Single wraps one set.

```go
func NewPrefixIndex(universe int) *PrefixIndex
```
<sub>`prefix.go`</sub>

NewPrefixIndex returns an empty index over a shard of `universe` policies.

**Methods on `CIDRIndex`**

```go
func (c *CIDRIndex) Insert(p netip.Prefix, policyIdx, universe int)
```
<sub>`cidr.go`</sub>

Insert records that the policy at policyIdx carries a condition accepting
prefix. universe is the policy count of the shard being indexed.

```go
func (c *CIDRIndex) Freeze()
```
<sub>`cidr.go`</sub>

Freeze finalizes every terminal set. Call once after all Inserts.

```go
func (c *CIDRIndex) Lookup(addr netip.Addr, base MatchSet) MatchSet
```
<sub>`cidr.go`</sub>

Lookup unions into base the policy set of every prefix containing addr.
The address buffer stays on the stack, so lookups do not allocate.

**Methods on `DomainIndex`**

```go
func (d *DomainIndex) Insert(suffix string, policyIdx int)
```
<sub>`domain.go`</sub>

Insert records that the policy at policyIdx accepts `suffix` and anything
under it.

```go
func (d *DomainIndex) Freeze() { freezeDomain(d.root) }
```
<sub>`domain.go`</sub>

Freeze finalizes every terminal set. Call once after all Inserts.

```go
func (d *DomainIndex) Lookup(host string, base MatchSet) MatchSet
```
<sub>`domain.go`</sub>

Lookup unions into base the policy set of every suffix that accepts host.

**Methods on `IntervalIndex`**

```go
func (x *IntervalIndex) Insert(min, max float64, policyIdx int)
```
<sub>`interval.go`</sub>

Insert records that the policy at policyIdx accepts values in [min, max].
Use math.Inf for open ends.

```go
func (x *IntervalIndex) Degraded() bool { return x.degraded }
```
<sub>`interval.go`</sub>

Degraded reports whether the index gave up on selectivity. The engine must
then fall back to the attribute's has-condition set.

```go
func (x *IntervalIndex) Freeze()
```
<sub>`interval.go`</sub>

Freeze sorts and finalizes the entries. Call once after all Inserts.

```go
func (x *IntervalIndex) Lookup(v float64, base MatchSet) MatchSet
```
<sub>`interval.go`</sub>

Lookup unions into base the policy set of every range covering v.

**Methods on `MatchSet`**

```go
func (m MatchSet) Union(s *bitset.Set) MatchSet
```
<sub>`matchset.go`</sub>

Union adds another set to the lazy union.

```go
func (m *MatchSet) Contains(i int) bool
```
<sub>`matchset.go`</sub>

Contains reports whether any constituent set holds i.

```go
func (m *MatchSet) OrInto(dst []uint64)
```
<sub>`matchset.go`</sub>

OrInto folds every constituent set into a raw word accumulator. Used by the
engine's word-parallel intersection path, where the lazy union has to be
made concrete once per filter rather than probed per candidate.

```go
func (m *MatchSet) EstimatedCardinality() int { return m.est }
```
<sub>`matchset.go`</sub>

EstimatedCardinality is the sum of member cardinalities: an upper bound on
the true union size, since the sets may overlap. The engine uses it only to
order intersections cheapest-first, so an upper bound is fine — a bad
estimate costs a little speed, never correctness.

```go
func (m *MatchSet) IsEmpty() bool { return m.count() == 0 || m.est == 0 }
```
<sub>`matchset.go`</sub>

IsEmpty reports whether the union holds nothing.

```go
func (m *MatchSet) AppendMembers(dst []int) []int
```
<sub>`matchset.go`</sub>

AppendMembers appends the deduplicated union to dst. The engine calls this
exactly once per request, on the most selective MatchSet only.

**Methods on `PrefixIndex`**

```go
func (x *PrefixIndex) Insert(p string, policyIdx int)
```
<sub>`prefix.go`</sub>

Insert records that the policy at policyIdx accepts paths starting with p.

```go
func (x *PrefixIndex) Freeze()
```
<sub>`prefix.go`</sub>

Freeze finalizes every prefix set. Call once after all Inserts.

```go
func (x *PrefixIndex) Lookup(path string, base MatchSet) MatchSet
```
<sub>`prefix.go`</sub>

Lookup unions into base the policy set of every recorded prefix of path.

### Unexported helpers

```go
func newCIDRTrie() cidrTrie
```
<sub>`cidr.go`</sub>

newCIDRTrie returns a trie holding only its root, whose children are marked
absent with -1 rather than 0, since 0 is the root's own index.

```go
func freezeDomain(n *domainNode)
```
<sub>`domain.go`</sub>

freezeDomain converts every node's builder into a finished set, depth first.

```go
func forEachLabelRTL(name string, fn func(label string))
```
<sub>`domain.go`</sub>

forEachLabelRTL yields the dot-separated labels of name from right to left.
The callback receives substrings of name, which share its backing array, so
iteration does not allocate.

**Methods on `cidrTrie`**

```go
func (t *cidrTrie) insert(addr *[16]byte, bits, policyIdx, universe int)
```
<sub>`cidr.go`</sub>

insert walks the first `bits` address bits, creating nodes as needed, and
records policyIdx at the terminal. The address is passed by pointer to a
caller-owned array so it stays on the stack.

```go
func (t *cidrTrie) freeze()
```
<sub>`cidr.go`</sub>

freeze converts every terminal's builder into a finished set.

```go
func (t *cidrTrie) lookup(addr *[16]byte, width int, out MatchSet) MatchSet
```
<sub>`cidr.go`</sub>

lookup walks the address bits from the root, unioning the policy set of
every terminal it passes. Collecting all of them, not just the deepest, is
what makes enclosing prefixes match: an address in 10.4.0.0/16 is also in
10.0.0.0/8, and both blocks' policies are candidates.

**Methods on `MatchSet`**

```go
func (m *MatchSet) count() int { return m.n + len(m.overflow) }
```
<sub>`matchset.go`</sub>

count reports the total number of constituent sets.

```go
func (m *MatchSet) at(k int) *bitset.Set
```
<sub>`matchset.go`</sub>

at returns the k'th constituent set.

**Methods on `PrefixIndex`**

```go
func (x *PrefixIndex) insertLength(l int)
```
<sub>`prefix.go`</sub>

insertLength records a distinct prefix length, keeping the slice sorted so
Lookup can stop probing once the lengths exceed the query path.

---

## Package `index`

Per-attribute sub-indexes and candidate-set intersection.

```go
import "github.com/suga/tessaraop/internal/index"
```

<details><summary>Index</summary>

- type `Shard`
- type `Scratch`
- func `BuildShard`
- func (s *Shard) `Size`
- func `NewScratch`
- func (s *Shard) `Candidates`

</details>

### Types

#### `Shard`

```go
type Shard struct
```
<sub>`index.go`</sub>

Shard indexes one tenant's policies. Requests are evaluated against their
own tenant's shard plus the global shard, never the whole corpus.

#### `Scratch`

```go
type Scratch struct
```
<sub>`index.go`</sub>

Scratch holds the reusable buffers one evaluation goroutine needs. Reusing
it across requests is what keeps the steady-state hot path free of
allocation; each goroutine must own its own.

### Unexported types

#### `attrIndex`

```go
type attrIndex struct
```
<sub>`index.go`</sub>

attrIndex holds every sub-index built for a single attribute.

#### `attrBuilder`

```go
type attrBuilder struct
```
<sub>`index.go`</sub>

attrBuilder accumulates one attribute's sub-indexes during construction.

Every sub-structure is created on first use rather than up front. An
attribute almost always carries a single operator family — roles are
equality, source addresses are CIDR, risk scores are ranges — so eagerly
allocating all twelve builders and five matcher indexes per attribute meant
the overwhelming majority were built, sized to the shard, and thrown away
empty. With a corpus partitioned into tens of thousands of shards that
dominated both build time and peak memory.

#### `filterKind`

```go
type filterKind uint8
```
<sub>`index.go`</sub>

filterKind distinguishes filters that can enumerate their members from
those that can only reject.

#### `filter`

```go
type filter struct
```
<sub>`index.go`</sub>

filter is one attribute sub-index's verdict for a specific request value.

Positive filters carry the set of policies that pass and can enumerate it,
so one of them seeds the candidate list. Negative filters carry only the
set they reject and pass everything else, which is why a negated operator
never needs a complement computed at query time.

est orders filters cheapest-first; it is an upper bound, and a poor estimate
costs speed rather than correctness.

### Functions and methods

```go
func BuildShard(policies []model.Policy) *Shard
```
<sub>`index.go`</sub>

BuildShard indexes a slice of policies. The slice is retained by reference;
callers must not mutate it afterwards.

```go
func NewScratch() *Scratch
```
<sub>`index.go`</sub>

NewScratch returns a scratch buffer sized for the expected candidate count.

**Methods on `Shard`**

```go
func (s *Shard) Size() int { return s.n }
```
<sub>`index.go`</sub>

Size reports how many policies this shard holds.

```go
func (s *Shard) Candidates(req model.Request, sc *Scratch) []int
```
<sub>`index.go`</sub>

Candidates returns the policy positions in this shard that survive index
filtering. The returned slice aliases sc and is valid only until the next
call with the same Scratch.

### Unexported helpers

```go
func newAttrBuilder(n int) *attrBuilder { return &attrBuilder{n: n} }
```
<sub>`index.go`</sub>

newAttrBuilder returns a builder for one attribute over a shard of n
policies. No sub-structure is allocated until a condition needs it.

```go
func buildOrEmpty(b *bitset.Builder, n int) *bitset.Set
```
<sub>`index.go`</sub>

build finalizes a builder that may never have been created, yielding an
empty set of the right universe rather than nil.

```go
func freezeValues(in map[string]*bitset.Builder) map[string]*bitset.Set
```
<sub>`index.go`</sub>

freezeValues finalizes every posting list in a value map, returning nil for
an unused family so callers can skip it cheaply.

```go
func clearWords(w []uint64)
```
<sub>`index.go`</sub>

clearWords zeroes a word buffer. Go compiles this loop to a memclr.

```go
func inclusiveLower(v float64) float64 { return v }
```
<sub>`index.go`</sub>

Strict inequalities (gt, lt) are indexed as inclusive ranges. That is
deliberately one hair over-inclusive at the boundary value, which a
pre-filter is always allowed to be — validation applies the exact strict
comparison and drops the boundary case.

```go
func inclusiveUpper(v float64) float64 { return v }
```
<sub>`index.go`</sub>

inclusiveUpper is the counterpart for a strict upper bound.

**Methods on `attrBuilder`**

```go
func (b *attrBuilder) bs(dst **bitset.Builder) *bitset.Builder
```
<sub>`index.go`</sub>

bs returns the builder at *dst, creating it on first use.

```go
func (b *attrBuilder) valueBuilder(m *map[string]*bitset.Builder, v string) *bitset.Builder
```
<sub>`index.go`</sub>

valueBuilder returns the posting-list builder for value v in map m,
creating both the map and the builder on first use.

```go
func (b *attrBuilder) cidrIndex(dst **matcher.CIDRIndex) *matcher.CIDRIndex
```
<sub>`index.go`</sub>

cidrIndex returns the CIDR trie at *dst, creating it on first use. Takes a
pointer-to-pointer so the same helper serves both the positive and negated
tries.

```go
func (b *attrBuilder) domainIndex() *matcher.DomainIndex
```
<sub>`index.go`</sub>

domainIndex returns the DNS suffix trie, creating it on first use.

```go
func (b *attrBuilder) prefixIndex() *matcher.PrefixIndex
```
<sub>`index.go`</sub>

prefixIndex returns the path prefix table, creating it on first use.

```go
func (b *attrBuilder) intervalIndex() *matcher.IntervalIndex
```
<sub>`index.go`</sub>

intervalIndex returns the numeric range table, creating it on first use.

**Methods on `filter`**

```go
func (f filter) allows(i int) bool
```
<sub>`index.go`</sub>

allows reports whether policy i survives this filter. It is the innermost
predicate of the per-element intersection path, called once per surviving
candidate per filter.

A negative filter passes everything it does not explicitly reject, which is
what makes negated operators cheap: no complement is ever materialized.

**Methods on `Scratch`**

```go
func (sc *Scratch) words(n int) int
```
<sub>`index.go`</sub>

words ensures both word buffers cover n elements and returns their length.

**Methods on `Shard`**

```go
func (s *Shard) intersectElements(sc *Scratch, best int) []int
```
<sub>`index.go`</sub>

intersectElements materializes the seed and filters it in place. Cost tracks
the surviving candidate count, so it wins whenever the seed is already small.

Every filter is applied rather than bailing out below some candidate count.
A filter pass over k candidates is k Contains probes, cheaper than letting
those k policies reach Policy.Matches and run their full condition lists — so
stopping early would trade a cheap probe for expensive validation, and would
make pruning depend on the arbitrary order filters happen to sit in.

```go
func (s *Shard) intersectWords(sc *Scratch, best int) []int
```
<sub>`index.go`</sub>

intersectWords folds every filter into a word accumulator, intersecting 64
policies per operation, then enumerates what survives. Cost is proportional
to the shard's word count rather than to the seed, which is what makes it the
better choice on large dense seeds.

```go
func (s *Shard) collectFilters(name string, ai *attrIndex, req model.Request, sc *Scratch)
```
<sub>`index.go`</sub>

collectFilters appends every filter attribute `name` contributes for req.

```go
func (s *Shard) attributePresent(name string, req model.Request) bool
```
<sub>`index.go`</sub>

attributePresent reports whether the request carries this attribute in any
of its three typed maps. Absence lets the index prune every policy that
requires the attribute, rather than deferring them to validation.

---

## Package `engine`

Sharding, algorithm selection, decision cache. The top-level decision point.

```go
import "github.com/suga/tessaraop/internal/engine"
```

<details><summary>Index</summary>

- type `Cache`
- type `Engine`
- type `Config`
- func `NewCache`
- func (c *Cache) `Get`
- func (c *Cache) `Put`
- func `New`
- func (e *Engine) `TotalPolicies`
- func (e *Engine) `TenantCount`
- func (e *Engine) `ShardCount`
- func (e *Engine) `InScope`
- func (e *Engine) `Evaluate`

</details>

### Types

#### `Cache`

```go
type Cache struct
```
<sub>`cache.go`</sub>

Cache is a striped, direct-mapped decision cache.

Every hit is verified by comparing the full request against the stored key,
never by trusting the hash alone. That matters more here than in an ordinary
cache: a hash collision in an authorization path would silently hand one
subject another subject's decision, so the hash is used only to pick a slot
and the comparison decides the hit. Replacement is direct-mapped overwrite
rather than LRU, which keeps lookups to a single striped read lock with no
list bookkeeping on the hot path.

Requests are hashed order-independently, since Go map iteration order is
randomized and the same logical request must always land in the same slot.

#### `Engine`

```go
type Engine struct
```
<sub>`engine.go`</sub>

Engine evaluates requests against a sharded, indexed policy corpus.
It is safe for concurrent use: shards are immutable after construction,
per-goroutine scratch comes from a pool, and the cache is internally striped.

#### `Config`

```go
type Config struct
```
<sub>`engine.go`</sub>

Config controls engine construction.

### Unexported types

#### `stripe`

```go
type stripe struct
```
<sub>`cache.go`</sub>

stripe is one lock-partitioned region of the cache. Striping keeps
concurrent readers off a single mutex without per-entry locking.

#### `cacheEntry`

```go
type cacheEntry struct
```
<sub>`cache.go`</sub>

cacheEntry is one direct-mapped slot: the stored request key and the
decision it produced. valid distinguishes an empty slot from a zero key.

#### `cachedRequest`

```go
type cachedRequest struct
```
<sub>`cache.go`</sub>

cachedRequest is an owned copy of a request's identifying fields. The
engine must not alias caller maps, which callers are free to mutate or
reuse after Evaluate returns.

#### `shardKey`

```go
type shardKey struct
```
<sub>`engine.go`</sub>

shardKey identifies a scoped shard. Tenant and scope are kept as separate
fields rather than a joined string so lookups never allocate.

### Functions and methods

```go
func NewCache(size int) *Cache
```
<sub>`cache.go`</sub>

NewCache returns a cache holding approximately size entries.

```go
func New(policies []model.Policy, cfg Config) *Engine
```
<sub>`engine.go`</sub>

New builds an engine over the given policies, partitioning them into shards
by TenantID. Policies in model.GlobalTenant form the global shard evaluated
for every request.

**Methods on `Cache`**

```go
func (c *Cache) Get(req model.Request) (model.Decision, bool)
```
<sub>`cache.go`</sub>

Get returns a cached decision for req, if one is present and verified.

```go
func (c *Cache) Put(req model.Request, d model.Decision)
```
<sub>`cache.go`</sub>

Put stores a decision, overwriting whatever occupied the slot.

**Methods on `Engine`**

```go
func (e *Engine) TotalPolicies() int { return e.total }
```
<sub>`engine.go`</sub>

TotalPolicies reports the corpus size across every shard.

```go
func (e *Engine) TenantCount() int { return e.tenants }
```
<sub>`engine.go`</sub>

TenantCount reports how many distinct tenants hold policies.

```go
func (e *Engine) ShardCount() int
```
<sub>`engine.go`</sub>

ShardCount reports how many shards the corpus partitions into.

```go
func (e *Engine) InScope(tenantID, scope string) int
```
<sub>`engine.go`</sub>

InScope reports how many policies a request can reach: the global shard,
its tenant-wide shard, and its own scope's shard. This is the number that
governs per-request cost, as opposed to the corpus total.

```go
func (e *Engine) Evaluate(req model.Request) model.Decision
```
<sub>`engine.go`</sub>

Evaluate renders a decision for req.

### Unexported helpers

**Methods on `cachedRequest`**

```go
func (k cachedRequest) matches(req model.Request) bool
```
<sub>`cache.go`</sub>

matches reports exact equality with req.

```go
func hashRequest(req model.Request) uint64
```
<sub>`cache.go`</sub>

hashRequest computes an order-independent 64-bit hash. Per-entry hashes are
summed rather than chained, so Go's randomized map iteration order cannot
change the result for a given logical request.

```go
func fnv64(h uint64, s string) uint64
```
<sub>`cache.go`</sub>

fnv64 folds a string into an FNV-1a accumulator. Chosen over hash/fnv so the
hot path neither allocates a hasher nor crosses an interface boundary.

```go
func fnv64Uint(h, v uint64) uint64
```
<sub>`cache.go`</sub>

fnv64Uint folds the eight bytes of v into an FNV-1a accumulator.

```go
func mix(h uint64) uint64
```
<sub>`cache.go`</sub>

mix is a finalizer that spreads entropy across all bits, so both the stripe
selection (low bits) and the slot selection (higher bits) are well
distributed from one hash value.

```go
func floatBits(f float64) uint64
```
<sub>`cache.go`</sub>

floatBits returns the bit pattern to hash for a float attribute.

```go
func evalShard(s *index.Shard, req model.Request, acc *model.Accumulator, sc *index.Scratch) int
```
<sub>`engine.go`</sub>

evalShard narrows the shard to candidates and validates them, feeding
matches into the shared accumulator. It returns how many policies reached
validation, which is the metric proving the index is doing work.

---

## Package `naive`

Linear-scan oracle used by differential tests and benchmarks.

```go
import "github.com/suga/tessaraop/internal/naive"
```

<details><summary>Index</summary>

- type `Evaluator`
- func `New`
- func `NewWith`
- func (e *Evaluator) `Evaluate`

</details>

### Types

#### `Evaluator`

```go
type Evaluator struct
```
<sub>`naive.go`</sub>

Evaluator scans the full policy slice on every call.

### Functions and methods

```go
func New(policies []model.Policy) *Evaluator
```
<sub>`naive.go`</sub>

New constructs a naive evaluator using deny-overrides.

```go
func NewWith(policies []model.Policy, alg model.Algorithm) *Evaluator
```
<sub>`naive.go`</sub>

NewWith constructs a naive evaluator using the given combining algorithm.

**Methods on `Evaluator`**

```go
func (e *Evaluator) Evaluate(req model.Request) model.Decision
```
<sub>`naive.go`</sub>

Evaluate scans every policy. It applies the same tenant scoping the sharded
engine does — a request only reaches its own tenant's policies plus the
global ones — so the two are comparable on identical inputs.

---

## Package `indexed`

Single-shard indexed evaluator; the benchmark control.

```go
import "github.com/suga/tessaraop/internal/indexed"
```

<details><summary>Index</summary>

- type `Evaluator`
- func `New`
- func `NewWith`
- func (e *Evaluator) `Evaluate`

</details>

### Types

#### `Evaluator`

```go
type Evaluator struct
```
<sub>`indexed.go`</sub>

Evaluator indexes one flat policy set with no tenant partitioning.

### Functions and methods

```go
func New(policies []model.Policy) *Evaluator
```
<sub>`indexed.go`</sub>

New builds an indexed evaluator over the policies using deny-overrides.

```go
func NewWith(policies []model.Policy, alg model.Algorithm) *Evaluator
```
<sub>`indexed.go`</sub>

NewWith builds an indexed evaluator with an explicit combining algorithm.

**Methods on `Evaluator`**

```go
func (e *Evaluator) Evaluate(req model.Request) model.Decision
```
<sub>`indexed.go`</sub>

Evaluate narrows the policy set via the index, then applies exact match
logic to the survivors.

Not safe for concurrent use: the scratch buffer is owned by this evaluator.
The sharded engine pools scratch per goroutine and is the concurrent path.

---

## Package `genutil`

Synthetic multi-tenant corpus generator.

```go
import "github.com/suga/tessaraop/internal/genutil"
```

<details><summary>Index</summary>

- type `Corpus`
- type `Options`
- func `Generate`
- func (c *Corpus) `GenerateRequest`
- func (c *Corpus) `GenerateRequestFor`

</details>

### Types

#### `Corpus`

```go
type Corpus struct
```
<sub>`genutil.go`</sub>

Corpus is a generated policy set plus the tenants and scopes it spans.

#### `Options`

```go
type Options struct
```
<sub>`genutil.go`</sub>

Options controls corpus generation.

### Functions and methods

```go
func Generate(opt Options, rng *rand.Rand) *Corpus
```
<sub>`genutil.go`</sub>

Generate builds a corpus. Tenant sizes follow a skewed distribution: tenant
0 is the whale, and size falls off from there, so benchmarks exercise both
the common small shard and the pathological large one.

**Methods on `Corpus`**

```go
func (c *Corpus) GenerateRequest(rng *rand.Rand) model.Request
```
<sub>`genutil.go`</sub>

GenerateRequest produces a request against a random tenant in the corpus.

```go
func (c *Corpus) GenerateRequestFor(tenant string, rng *rand.Rand) model.Request
```
<sub>`genutil.go`</sub>

GenerateRequestFor produces a request against a named tenant, for
benchmarking a specific shard size.

### Unexported helpers

```go
func globalPolicy(i int, rng *rand.Rand) model.Policy
```
<sub>`genutil.go`</sub>

globalPolicy produces a platform-level rule: IP blocklists, geo blocks and
blanket kill switches. These are deliberately cheap to match and heavily
deny-weighted, since that is what platform policy looks like in practice.

```go
func tenantPolicy(tenant string, i int, rng *rand.Rand) model.Policy
```
<sub>`genutil.go`</sub>

tenantPolicy produces a customer-level rule spanning the full operator
surface: set membership, negation, numeric ranges, CIDR, DNS suffix and
path prefix.

```go
func randomAddr(rng *rand.Rand) netip.Addr
```
<sub>`genutil.go`</sub>

randomAddr returns an address weighted toward corporate space, with a
minority from public and blocklisted ranges — roughly the mix a corporate
gateway sees.

**Methods on `Corpus`**

```go
func (c *Corpus) requestFor(tenant string, rng *rand.Rand) model.Request
```
<sub>`genutil.go`</sub>

requestFor builds one request against a named tenant, picking a random scope
and drawing every attribute from the same vocabularies the policies use — so
generated requests actually stand a chance of matching.

---

## Package `main`

Command-line interface.

### Unexported helpers

```go
func main()
```
<sub>`main.go`</sub>

main parses flags and dispatches to one of the three modes.

```go
func printCorpusSummary(c *genutil.Corpus, eng *engine.Engine, build time.Duration)
```
<sub>`main.go`</sub>

printCorpusSummary reports the shape of the generated corpus: shard sizes,
operator mix, and the worst-case in-scope count. That last number is the one
that governs per-request cost, as opposed to the corpus total.

```go
func runBench(eng *engine.Engine, c *genutil.Corpus, rng *rand.Rand,
```
<sub>`main.go`</sub>

runBench evaluates a stream of requests through the engine and, unless
disabled, the naive oracle alongside it — so the timing table doubles as a
correctness check.

```go
func runInteractive(eng *engine.Engine, c *genutil.Corpus)
```
<sub>`main.go`</sub>

runInteractive reads key=value requests from stdin and reports each decision
with both evaluators' timings and the matched policy.

```go
func parseRequest(line string) model.Request
```
<sub>`main.go`</sub>

parseRequest turns a key=value line into a Request, routing each key to the
typed map its operators read: IPs by name, numerics by name, strings
otherwise.

```go
func runDemo()
```
<sub>`main.go`</sub>

runDemo walks a hand-written policy set covering every operator family and
evaluates scenarios against it, including a global deny overriding a tenant
grant and a lookalike-domain bypass attempt.

```go
func describe(c model.Condition) string
```
<sub>`main.go`</sub>

describe renders a condition in readable form for the demo listing.

```go
func truncate(s string, n int) string
```
<sub>`main.go`</sub>

truncate shortens s to n runes-worth of bytes for table alignment.

```go
func comma(n int) string
```
<sub>`main.go`</sub>

comma formats an integer with thousands separators.

---

<sub>37 types, 132 functions.</sub>