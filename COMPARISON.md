# TessaraOP — Competitive Position & Authorization Models

How Cedar, OPA, OpenFGA and Casbin actually work, which evaluation models exist,
which authorization models TessaraOP supports today, and what it would take to
support the rest.

---

## 1. Scope and non-scope

**This is an engineering document, not marketing copy.** It states TessaraOP's
gaps as plainly as its strengths, because it exists to support roadmap decisions,
and a comparison that flattered the project would be useless for that. An
external-facing subset can be lifted from it; the honesty must survive the edit.

**What this document does not contain:**

- **No competitor performance numbers.** None were measured here. Every
  comparison below is architectural. Claiming a throughput advantage over Cedar
  or OPA without running both on the same corpus would be exactly the kind of
  unfounded assertion §8 forbids.
- **No claim of feature parity.** §5 is a gap table, and the gaps are real.
- **No stable version pinning.** These projects move. The architectural shapes
  described here are durable; specific syntax, flag names and feature sets should
  be re-verified against current upstream documentation before being quoted
  externally.

Every claim about TessaraOP itself is checkable against this repository, and §8
lists the commands used to verify them.

---

## 2. How each system works

### 2.1 AWS Cedar

**Language / model shape.** A fixed `(principal, action, resource)` triple with
`when` / `unless` guards.

```
permit(principal in Group::"admins", action == Action::"view", resource in Album::"vacation")
when    { resource.owner == principal }
unless  { context.ip.isInRange(ip("192.0.2.0/24")) };
```

**Evaluation model.** `forbid` always beats `permit`. Default deny.
**Not configurable — deliberately.** A fixed algorithm is a precondition for the
analysis story below, since a policy set whose combining rule can vary is much
harder to reason about mechanically.

**Scale approach.** Cedar evaluates the policy set it is handed, essentially
linearly. There is no index. *Slicing* — fetching only the policies and entities
relevant to a request — is the caller's responsibility, handled at the service
layer in Amazon Verified Permissions rather than in the engine.

**The actual moat: analyzability.** The language is intentionally restricted — no
loops, no recursion, no unbounded arithmetic — so every policy provably
terminates. That buys SMT-solver analysis: *is policy A redundant given B? can
these two ever both apply? is this policy unreachable?* The semantics are backed
by a formal specification with machine-checked proofs. This, plus AWS
distribution, is what Cedar is defended by.

**RBAC and ReBAC** come from a transitive entity hierarchy: `in` walks a DAG of
entities supplied with the request, so groups, folders and org trees all work.

---

### 2.2 Open Policy Agent (OPA)

**Language / model shape.** Rego — Datalog-derived, with comprehensions,
negation-as-failure and partial evaluation. A policy returns arbitrary JSON, not
a decision.

**Evaluation model: there is none built in.** This surprises people, and it is the
most important thing to understand about OPA. The conventional idiom is

```rego
default allow := false
allow if { ... }
```

or the deny-set form (`deny contains msg if {...}` plus `allow if count(deny) == 0`).
**Deny-overrides in OPA is a coding convention, not an engine guarantee.** Every
organization writes its own conflict resolution, and nothing validates that it is
consistent across policies.

**Scale approach.** Policies compile to an intermediate representation executed by
a virtual machine, with an optimizing build mode. Partial evaluation specializes a
policy against known input ahead of time. It does have **rule indexing** — a trie
over rule-head arguments and equality expressions in rule bodies, used to skip
rules that cannot match. That is the closest existing analogue to
`internal/index`, though it operates within modules and over a narrower set of
patterns than the seven index families here.

**The actual moat: ecosystem, not engine.** Bundle distribution API, decision
logs, status API, discovery, evaluation tracing, Gatekeeper for Kubernetes,
conftest, and integrations across Envoy, Terraform and Kubernetes. Replacing the
evaluator is tractable; replacing that surface is not.

---

### 2.3 OpenFGA — and the Zanzibar lineage (SpiceDB, Ory Keto)

**Language / model shape.** Relationship tuples plus a type model.

```
user:anne | viewer | document:budget

type document
  relations
    define owner:  [user]
    define editor: [user] or owner
    define viewer: [user] or editor
```

**Evaluation model.** Graph traversal via userset rewrites. `Check(user, relation,
object)` expands the relation definition and walks tuples.

**There is no deny primitive.** The algebra is union / intersection / exclusion
(`or`, `and`, `but not`) over relation sets. This is **a different decision model,
not a variant of permit/forbid with override precedence** — which matters when
comparing, because "does OpenFGA do deny-overrides?" is a category error rather
than a feature question.

ABAC arrived later as *Conditions*: expressions attached to tuples.

**Scale approach and hard problems.** Fan-out, traversal depth, and consistency.
Zanzibar's zookies exist to give snapshot consistency across a distributed tuple
store; OpenFGA exposes consistency options. Cache invalidation on tuple writes is
the persistent difficulty.

**The actual moat.** Being the practical open implementation of a well-known
design for the relationship problem, with the storage and consistency engineering
that implies.

---

### 2.4 Casbin

The most directly relevant system for TessaraOP's design questions, because it is
the one that makes the combining algorithm **configuration**.

**Language / model shape.** A model file plus a policy store.

```ini
[request_definition]  r = sub, obj, act
[policy_definition]   p = sub, obj, act, eft
[role_definition]     g = _, _
[matchers]            m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
```

**Evaluation model — configurable effect expressions:**

```ini
e = some(where (p.eft == allow))                                  # allow-overrides
e = !some(where (p.eft == deny))                                  # deny-overrides
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))  # allow-and-deny
e = priority(p.eft) || deny                                       # first match by priority
```

**Scale approach.** Matchers are expression strings interpreted per policy line.
Indexes and caches have been added over time, but per-line interpretation is the
structural ceiling.

**The actual moat.** Ubiquity and portability — implementations across many
languages, trivial to adopt, and flexible enough to model most schemes. Its
weakness is exactly the axis TessaraOP is strong on.

---

## 3. Evaluation models — the XACML lineage

TessaraOP's three combining algorithms are not ad hoc: they are **XACML 3.0
standard combining algorithms**. Naming the lineage is worth doing, and it also
makes clear what is missing.

| XACML 3.0 algorithm | Semantics | TessaraOP | Order-independent? |
|---|---|---|---|
| deny-overrides | Any DENY wins | **Yes** | Yes |
| permit-overrides | Any PERMIT wins | **Yes** | Yes |
| first-applicable | First applicable (priority/order) wins | **Yes** | No |
| deny-unless-permit | Default deny, no indeterminate state | No | Yes |
| permit-unless-deny | Default permit | No | Yes |
| only-one-applicable | Error if more than one applies | No | Yes |
| ordered-deny-overrides | deny-overrides in document order | No | No |
| ordered-permit-overrides | permit-overrides in document order | No | No |

Where the field sits:

| System | Combining model | Configurable |
|---|---|---|
| Cedar | forbid-overrides, default deny | No, by design |
| OPA | None — the author writes it | N/A |
| OpenFGA | Union / intersection / exclusion; no deny | No |
| Casbin | Effect expression in the model file | Yes |
| **TessaraOP** | 3 XACML algorithms, **at two tiers** | Yes — per policy *and* per shard |

### 3.1 The two-tier combination is genuinely differentiated

No system above lets a **policy resolve its own rules by one algorithm while the
shard resolves policies by another**. TessaraOP does
(`DOCUMENTATION.md` §4), and the consequence is concrete.

The worked example is in `cmd/tessaraop -demo`: a broad deny with its own narrow
exception, both inside one policy resolved by `first-applicable`, sitting in a
shard resolved by `deny-overrides`.

```
acme-break-glass  (RuleAlgorithm: first-applicable)
  deny-critical-delete           priority 10
  except-approved-break-glass    priority 100   ← wins inside this policy
```

The exception beats its own policy's broad deny **without becoming visible to any
other policy in the shard** — an unrelated policy's DENY still overrides the whole
thing. Verified by `TestTwoTier_ExceptionDoesNotLeakAcrossPolicies`.

- **Cedar cannot express this.** `forbid` always wins, so the exception is
  unreachable.
- **OPA can, but only as hand-written logic** the author must get right and
  nothing validates.
- **Casbin cannot.** One effect expression applies globally.

### 3.2 Why Casbin-style effect expressions will not be supported

This is a deliberate closed door, and the reason is structural rather than
preference.

Deny-overrides can **short-circuit** precisely because it is order-independent,
and the index yields candidates in whatever order the underlying sets enumerate
(`DOCUMENTATION.md` §4, §8). A user-supplied effect expression cannot be assumed
order-independent. Supporting one would force a choice between:

1. sorting every candidate set before resolving — forfeiting short-circuiting and
   a meaningful share of the performance the project exists for; or
2. letting arbitrary enumeration order leak into decisions — which is a
   correctness defect, not a trade-off.

**"Our combining algorithms are order-independent, which is what makes indexing
sound" is a stronger technical position than "configurable like Casbin."** The
right response to the flexibility gap is to implement the remaining *standard*
algorithms (§7 Phase 3), not to accept arbitrary expressions.

---

## 4. ACL / RBAC / ABAC / ReBAC

### 4.1 The reframe

**These are not four engines.** They are four ways of deriving facts about a
(subject, resource) pair. The combining logic is orthogonal to all of them — you
can run deny-overrides over ACLs, over roles, over attributes or over
relationships.

| Model | The primitive | What it mechanically requires |
|---|---|---|
| **ACL** | `(subject, resource, action)` triples | A **tuple index** — millions of *entries*, not millions of rules |
| **RBAC** | subject → roles → permissions | **Transitive closure** over a role hierarchy |
| **ABAC** | attribute predicates | ← **what TessaraOP already is** |
| **ReBAC** | subject → relationship graph → resource | **Graph traversal** with cycle handling and depth limits |

ACL deserves a note: TessaraOP *can* express an ACL today (a policy per resource
with `subject.id in [...]`), but at scale that is the wrong storage shape. A
million ACL entries want a tuple index, not a million rules, each with a shard and
an index entry.

### 4.2 Two designs for the models TessaraOP lacks

**Design A — pre-materialize at the ingest boundary.** Expand roles and
relationships into request attributes *before* evaluation:

```
subject.roles      = "admin,editor,viewer"    (transitively closed)
subject.relations  = "owner,viewer"           (for the named resource)
resource.ancestors = "folder:eng,org:acme"
```

Existing operators (`contains`, `in`) then work unchanged, the index still
applies, and **the hot path needs no changes at all.**

**Design B — relationship operators that resolve mid-evaluation.** New operators
(`rel_has`, `in_group`) consulting a graph store during evaluation.

### 4.3 Decision: A as primary, B only as a cost-labelled escape hatch

The reason to record is not that A is faster, though it is. It is that **A is a
coherent extension of a principle already committed to.** `internal/ingest`
already establishes that the engine consumes named, pre-parsed attributes and
performs no I/O (`DOCUMENTATION.md` §16) — precisely so that parser-differential
and latency concerns live outside the decision path. Role and relationship
expansion is that same pattern applied to a new source of facts.

Design B would put I/O inside evaluation, destroying both the microsecond claim
and the zero-allocation property, and such operators are not indexable in any case.

**A's limits, stated honestly:**

- It serves **`Check`-shaped** questions — *"can Anne view document 123?"* —
  because relations are expanded for one named resource.
- It does **not** serve `ListObjects` — *"which documents can Anne view?"* — which
  is a reverse-index query over the relationship graph, not a predicate
  evaluation.
- It degrades on deep or high-fan-out graphs, where the expansion itself becomes
  the cost.

---

## 5. Where TessaraOP stands

### 5.1 Strengths

Each is checkable in this repository.

| Strength | Evidence |
|---|---|
| **Scale at the decision point.** Sharding + seven index families + verified cache; 4.1 µs against 100k policies with zero allocations | `README.md` §Measured results, `internal/index` |
| **Two-tier combining.** Uniquely expressive for scoped exceptions | `DOCUMENTATION.md` §4 |
| **Multi-tenancy as a first-class primitive**, not a bolt-on | `internal/engine`, shard key is `(tenant, scope)` |
| **The attribute registry** — a partial analogue of Cedar's schema, catching the fail-closed bug class at load time | `internal/attr`, `internal/bundle/lint.go` |
| **Differential testing against a naive oracle**, under every algorithm | `internal/engine/engine_test.go` |
| **Zero dependencies** — a smaller supply-chain surface than any system above | no `go.sum` |

### 5.2 Gaps

This table is the spine of the document.

**Closed since this assessment was first written** — phases 1 to 4 of §7 shipped:

| Was | Now |
|---|---|
| No ReBAC / entity hierarchy (**Critical**) | Resolver interface + in-memory implementation with object containment and group expansion; adapters are the integrator's to write (§7.1) |
| No RBAC role hierarchy (**High**) | `internal/hierarchy`: transitive closure, cycle detection, resolved at ingest |
| No explain / decision trace (**High**) | `PDP.Explain`, `POST /v1/explain`, CLI; differentially tested against `Evaluate` |
| No decision-log sink (Medium) | `pkg/tessaraop/audit`: structured, generation-tagged, allowlisted values, non-blocking |
| 4 of 8 XACML algorithms missing (Low) | 6 of 8; the `ordered-` variants are deliberately excluded |

Closing the role-hierarchy gap surfaced a real bug class in the process:
expanding a closure into a comma-joined attribute and matching it with `contains`
is a substring test, so a principal holding only `readwrite` satisfies
`contains "read"`. The `has_any` / `has_all` / `has_none` operators compare whole
elements, and the linter now rejects `contains` on any registered set attribute.

**Remaining gaps:**

| Gap | Severity | Who has it |
|---|---|---|
| No policy analysis (subsumption, conflict, reachability) | Medium | Cedar |
| No delta bundles or discovery API | Medium | OPA |
| No entity type schema | Medium | Cedar |
| No `ListObjects` over relationships | Medium | OpenFGA, SpiceDB |
| No importers from other policy formats | Medium | — |

`ListObjects` — *"which documents can Anne view"* — is a reverse query over the
relationship graph rather than a predicate evaluation, and is explicitly out of
scope for the resolver design: ask your ReBAC store directly.

---

## 6. What is winnable

| Competitor | Verdict |
|---|---|
| **Casbin** | **Winnable now.** Faster, better tested, better documented. Their per-line matcher interpretation is the structural ceiling; the model-file flexibility is real but is not what large deployments are blocked on. |
| **OPA** | **Hard on their turf, winnable on yours.** The moat is ecosystem, not engine. Competing as a *general policy language* is not realistic. Competing on *multi-tenant decision throughput* is. The OPA-compatible endpoint in `pkg/tessaraop/pdpserver` already turns migration into a URL change — that is the wedge. |
| **Cedar** | **Needs the analysis story.** Their differentiator is analyzability plus AWS distribution. Phase 5 (BDD compilation) is the direct answer. TessaraOP already beats Cedar on combining expressiveness (§3.1) and on scale. |
| **OpenFGA / SpiceDB** | **Different problem — complementary, not competing.** They answer *"who is related to what."* TessaraOP answers *"does this request satisfy these predicates."* A realistic enterprise architecture uses both. |

### The defensible positioning

> **The policy decision point that stays in microseconds at multi-tenant scale,
> speaks every proxy protocol, and validates policy before it ships** — consuming
> identity from your IdP and relationships from your ReBAC store rather than
> reimplementing either.

Claiming to replace all five invites evaluation on each competitor's strongest
axis instead of TessaraOP's own.

---

## 7. Roadmap implications

| Phase | Work | Gap closed | Status |
|---|---|---|---|
| **1** | Role/group hierarchy with transitive closure, resolved at ingest | RBAC hierarchy (High) | **Done** |
| **2** | `Explain` — non-short-circuiting, built on the naive path, differentially tested against `Evaluate`, with attribute redaction | Cedar + OPA parity; unblocks every POC | **Done** |
| **3** | The missing XACML algorithms + obligation union semantics | Procurement conformance; removes the non-canonical-attribution caveat | **Done** (6 of 8) |
| **4** | ReBAC **resolver interface** + adapters | Critical gap, without becoming stateful | **Interface done**; adapters not written |
| **5** | BDD/MTBDD compilation → subsumption, conflict, reachability | Cedar's moat | Not started |
| **6** | Importers from other policy formats | Migration | Not started |

Phase 4 shipped the interface, the in-memory implementation, composition
(chaining, timeouts, TTL caching) and the adapter contract. **OpenFGA and SpiceDB
adapters are not included**, and that is deliberate rather than an oversight: both
need a live server to verify against, and shipping unexercised network code as a
"supported adapter" is exactly the kind of claim §8 forbids. The contract is
documented in `internal/relation` and an adapter is one method.

### 7.1 The ReBAC decision, recorded

Because it will be questioned again:

> **Integrate rather than build.**
>
> The decisive factor is not difficulty, it is **persistence**. A Zanzibar-style
> tuple store requires a database — durability, migrations, replication, snapshot
> consistency semantics. That turns TessaraOP from a stateless drop-in compute
> component into a **stateful service**, with a different operational burden,
> different failure modes, a different sales motion, and the loss of the
> zero-dependency property the moment a driver is added. It would also mean
> competing on OpenFGA's strongest axis while the actual differentiator —
> index-and-shard predicate evaluation — stagnated for months.
>
> **Split the problem instead.** A role/group **hierarchy closure** is a
> degenerate ReBAC: one relation, transitive, no tuple store, no persistence. It
> covers a large share of real-world need (`user → group → group → resource`) and
> is built natively in Phase 1.
>
> **General relationship graphs are consumed through a native resolver
> interface**, with adapters for OpenFGA and SpiceDB. Defining the interface
> natively — rather than coupling to one vendor — means a native implementation
> later is a drop-in third implementation rather than a rewrite. That hedge costs
> almost nothing now and preserves the option.

### 7.2 What Phase 1 and 4 share

Both feed **Design A** (§4.2): they resolve facts outside the engine and hand them
in as attributes. Neither touches `internal/index`, `internal/model` or the hot
path. That is why they can be built independently and why neither risks the
performance or correctness properties already established.

---

## 8. Claims discipline

What may and may not be asserted about TessaraOP, publicly or in a sales
conversation.

**Do not claim:**

- **Any competitor performance figure.** None were measured. Not "faster than
  OPA", not "faster than Cedar" — there is no benchmark behind either statement.
- **Full XACML conformance.** The accurate phrasing is *"implements six of the
  eight standard XACML 3.0 combining algorithms — every order-independent one."*
  The `ordered-` variants are excluded by design, not pending.
- **A ReBAC store.** TessaraOP *consumes* relationships through a resolver; it
  does not store tuples, and it cannot answer `ListObjects`. The honest phrasing
  is "integrates with your ReBAC store", never "replaces it".
- **Shipped OpenFGA or SpiceDB adapters.** The interface and contract exist; the
  adapters do not, because they cannot be verified without a live server.
- **Policy analysis.** No subsumption, conflict or reachability detection.
- The five performance figures marked *not re-measured* in `README.md` and
  `DOCUMENTATION.md` §19 — the 1M sharded row, cache-hit latency, multi-core
  throughput, whale-shard tail latency, and index build cost. The
  pre-restructure values were taken on different hardware before rules existed.

**Do state, because they are true and verified:**

- 4.1 µs against 100k policies, sharded, zero allocations per request.
- All tests passing under `-race`, including a differential against a naive
  oracle across every combining algorithm.
- Zero external dependencies.
- 118 registered attributes, 31 operators, 6 combining algorithms at two tiers.
- ACL, RBAC (with hierarchy), ABAC and ReBAC (via a resolver) are all
  expressible.
- **The flat-shard limitation.** At 100k policies in a single unsharded shard the
  index is ~2.1x *slower* than a short-circuiting linear scan. This is already
  disclosed in `README.md` and `DOCUMENTATION.md` §20 and **must not quietly
  disappear from a comparison document.** It is also the honest lead-in to the
  scoping argument, which is the actual answer.

### Verifying the claims in this document

```bash
go run ./cmd/tessaraop -attrs | head -1        # attribute count
grep -c 'Operator = "' internal/model/model.go # operator count
grep 'var AllAlgorithms' internal/model/policy.go
go test ./... -race                            # test count

# The gaps, confirmed by absence:
grep -riE "role.*hierarch|transitive" internal/ pkg/ --include=*.go
grep -riE "func .*Explain|Explanation" internal/ pkg/ --include=*.go
grep -riE "entity|relationship|tuple" internal/ pkg/ --include=*.go
```

These commands exist because the prose has drifted twice. An early draft claimed
118 attributes when the registry held 117; a later change added one and the docs
still said 117. Both were caught by running the command rather than trusting the
text, which is the point of keeping this section — the counts move whenever the
registry does, so they must be checked, not remembered.
