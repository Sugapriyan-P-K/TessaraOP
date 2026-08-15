# TessaraOP

A multi-tenant ABAC / Zero-Trust **policy validation and decision engine** in Go.

The thesis: answer authorization questions against millions of rules in
microseconds — not by brute-force scanning, but by sharding (tenant + scope),
per-attribute indexing (hash maps, radix tries, interval and affix tables), and a
verified decision cache.

It is built to be **dropped into an existing policy flow** rather than to replace
one. A customer keeps their proxy, their identity provider and their policy review
process; TessaraOP becomes the thing that answers *"is this allowed?"*.

**No external dependencies.** No `go.sum`. Standard library only, deliberately —
an authorization component sitting in a request path is a supply-chain surface,
and every dependency widens it.

---

## What a policy looks like

A policy holds rules; a rule holds a boolean tree over conditions.

```
Policy   — the unit of tenancy, sharding and distribution
  └─ Rule    — carries the Effect and the Obligations
       └─ When: AND / OR / NOT tree over Conditions
```

```json
{
  "version": 1,
  "policies": [{
    "id": "acme-admin-console",
    "tenant": "acme",
    "scope": "identity",
    "rules": [{
      "id": "grant-admin-console",
      "effect": "ALLOW",
      "obligations": ["require_mfa", "audit_log"],
      "when": {
        "all": [
          {"any": [
            {"attr": "subject.role", "op": "eq", "values": ["admin"]},
            {"attr": "subject.role", "op": "eq", "values": ["security-admin"]}
          ]},
          {"not": {"attr": "subject.groups", "op": "contains", "values": ["contractor"]}},
          {"attr": "subject.risk_score",  "op": "range",     "min": 0, "max": 30},
          {"attr": "network.source_ip",   "op": "cidr",      "prefixes": ["10.0.0.0/8"]},
          {"attr": "resource.domain",     "op": "dnssuffix", "values": ["admin.acme.com"]},
          {"attr": "transport.dest_port", "op": "num_in",    "numbers": [443, 8443]}
        ]
      }
    }]
  }]
}
```

```go
pdp, diags, err := tessaraop.OpenBundle("policies.json", tessaraop.Config{CacheSize: 8192})
if err != nil {
    log.Fatalf("policy bundle rejected:\n%s", tessaraop.FormatDiagnostics(diags))
}

req := tessaraop.NewRequest("acme", "identity").
    Str(tessaraop.AttrSubjectRole, "admin").
    Num(tessaraop.AttrRiskScore, 12).
    IPString(tessaraop.AttrSourceIP, "10.1.2.3").
    Build()

d := pdp.Evaluate(req)
// d.Allowed, d.Effect, d.MatchedRuleID, d.Obligations
```

The two-level shape is not decoration. A flat `[]Condition` cannot express
*"(role is admin OR role is security-admin) AND NOT department is contractor"*
without expanding it into a cross product of AND-only policies, which multiplies
the corpus and makes the result unreviewable. And a broad deny with its own narrow
exception had to be split across two policies, leaking the exception to every
other policy in the shard. Rules fix both.

---

## Measured results

AMD Ryzen 5 5600H, 12 threads, Go 1.26.5. Corpora from `internal/genutil`:
skewed tenant sizes (one whale, long tail), ~2 rules per policy, and **27% of
rules carrying an `OR` or `NOT` that the index cannot prune on** — deliberately,
so the numbers are honest about the cost of expressiveness.

Corpus sizes are stated in **policies**; the indexed universe is **rules**, about
2x that.

### Sharded — the way you would actually deploy it

| Corpus (policies) | Naive scan | TessaraOP | Speedup | Rules validated | Alloc |
|---|---:|---:|---:|---:|---:|
| 10,000 | 10.1 µs | **3.2 µs** | 3.2x | 2 | 0 B |
| 100,000 | 212 µs | **4.1 µs** | **51x** | 30 | 0 B |
| 1,000,000 | 2.07 ms | not re-measured | — | — | — |

Latency is flat as the corpus grows 10x, because per-request cost tracks the
shard, not the corpus. Zero allocations per request in steady state.

### Unsharded — indexing in isolation

Flattening the corpus onto one tenant removes sharding from the comparison, so
these rows measure the index alone.

| Corpus (policies) | Naive scan | Indexed | Ratio |
|---|---:|---:|---:|
| 10,000 | 108 µs | **25.9 µs** | 4.2x faster |
| 100,000 | 99 µs | 206 µs | **2.1x slower** |

That second row is not a typo. §Limitations explains it rather than burying it.

> **Not re-measured after the rule restructure:** the 1M sharded row, decision
> cache hit latency, multi-core throughput, worst-case (whale) shard latency, and
> index build time and memory. Earlier figures for those were taken on different
> hardware and before rules existed, so they are omitted rather than carried
> forward as if current. Reproduce with
> `go test ./internal/benchmark/ -run XXX_NONE -bench . -benchmem`.

---

## Limitations, stated plainly

**1. On a large flat scope, a short-circuiting linear scan can still win.**

Naive is not truly O(N): under deny-overrides it stops at the first matching deny,
and roughly 20% of generated rules are denies, so on a large corpus it often stops
almost immediately. The index has no such luck — it must touch every word of the
shard's bitmap before it knows what survived. At 10k policies in one flat shard
the index wins 4.2x; at 100k it trails by 2.1x.

The fix is not more index; it is **scoping**. The sharded rows above are the same
corpus with `scope` set, and there the engine is 51x ahead. If you have one large
tenant, partition it by resource family or application. `tessaraop -lint` reports
how much of a bundle the index can prune on, and `PDP.ReachableRules` reports how
large a given shard actually is.

This case used to be far worse. Before the word-parallel intersection path, a
200k-rule flat shard cost **5.04 ms and 10.6 KB of allocation per request** — 25x
slower than the baseline it exists to beat. It is now 206 µs and 20 B.

**2. Expressiveness costs pruning, by construction.**

Only conditions on a rule's **AND-spine** — reachable from the root through
exclusively `And` nodes — can build an index filter. A condition under an `Or` is
not logically necessary for the rule to match, and one under a `Not` is required to
be *false*; indexing either would let the pre-filter drop a rule that genuinely
matches, which is the one failure mode that turns a fast engine into a wrong one.

So off-spine conditions contribute no filter and are resolved by full validation.
A rule rooted at `Or` gets no index help at all. This is over-inclusive, never
under-inclusive, and the cost is paid only by the rules that use it.

**3. Obligation attribution under the overrides algorithms is not canonical.**

When several rules match with the winning effect, `deny-overrides` and
`permit-overrides` do not specify which to credit — so the reported rule, and the
obligations that travel with it, depend on which one the evaluator reached first.
Two correct implementations can differ. Use `first-applicable` where audit
attribution or a guaranteed obligation set matters; it orders candidates
deterministically by priority then ID.

**4. Parts of the rule catalog are not derivable inside the process.**

TTL, TCP flags, fragmentation and DSCP are not reachable through Go's socket
abstraction; geo-IP, ASN, IP reputation and session validity need a store or a
network call. `internal/ingest` populates what the standard library can actually
see and leaves the rest to an explicit `Set`, rather than fabricating values — a
policy written against a fabricated attribute reads as enforced when it is not.

**5. Adding a policy rebuilds its shard.** Incremental index updates are not
implemented. Reload is whole-corpus and atomic, which is the right shape for
bundle-based deployment but not for high-frequency single-policy writes.

---

## Integrating

Four surfaces, because an engine only gets adopted if it speaks the protocol the
customer's stack already speaks.

### 1. Embedded Go SDK — `pkg/tessaraop`

The only package to import; everything under `internal/` is free to change.

```go
pdp, _, _ := tessaraop.OpenBundle("policies.json", tessaraop.Config{CacheSize: 8192})
pdp.Evaluate(req)          // safe for any number of goroutines
pdp.LoadBundleFile(path)   // atomic swap; a failed load keeps the old set
pdp.Metrics()              // evaluations, allow/deny, cache hits, rules validated
pdp.Info()                 // generation, policies, rules, tenants, shards
```

`Reload` swaps the whole policy set behind an atomic pointer: a request in flight
sees one complete set, never a mixture. A **failed** load leaves the previous set
installed — a bad policy deploy degrades to stale rules, never to an engine that
denies everything.

### 2. Declarative bundles + linter

Policies are files: reviewed, diffed, and shipped through the same pipeline as the
rest of your configuration.

```bash
tessaraop -lint policies.json          # non-zero exit if it has errors
tessaraop -export > starter-bundle.json
```

The linter matters more here than in most systems, because this engine fails
closed: a condition comparing a string attribute with a numeric operator does not
error, it simply never fires — indistinguishable from a rule meant to be narrow.
Load time is the only place to catch it. It also flags `eq` given several values
(only the first is read), an empty `any` (a dead rule), uncompilable regexes,
inverted ranges, rule priorities set under an algorithm that ignores them, and a
byte-`suffix` condition on something shaped like a hostname — which would accept
the lookalike domain.

Unregistered attribute names are a **warning**, not an error: customers
legitimately carry their own vocabulary, and forcing a registry fork would block
every integration. `-strict-attributes` promotes them once the vocabulary settles.

### 3. HTTP decision point — `cmd/tessaraopd`

```bash
tessaraopd -bundle policies.json -addr :8181 -trusted-proxy-hops 1
```

| Endpoint | For |
|---|---|
| `POST /v1/decision` | Native JSON: full request in, full decision out |
| `POST /v1/explain` | **Why** a decision came out as it did, per condition |
| `ANY /v1/authz` | **Envoy ext_authz (HTTP), NGINX `auth_request`, Traefik ForwardAuth, HAProxy, Istio, Caddy `forward_auth`** — one handler, no protobuf |
| `POST /v1/data/tessaraop` | OPA-shaped envelope, so migrating an existing OPA client is a URL change |
| `GET /v1/attributes` | The attribute registry, as onboarding documentation |
| `GET /metrics` | Prometheus text format (emitted by hand — still zero dependencies) |
| `GET /healthz` `/readyz` | Liveness and readiness, distinguished |
| `POST /v1/reload` | Atomic reload, token-guarded; also `SIGHUP` |

`/v1/authz` never returns 5xx. Every proxy in that family treats a 5xx as a
failure of the authorizer rather than a denial, and most are configured to **fail
open** on it — so a 500 would be the one response that could grant access by
accident. Anything unparsable is a 403 with the reason in a header.

`readyz` is separate from `healthz` because they drive different orchestrator
behaviour: a live process holding no policy denies every request, so it must be
pulled from the load balancer, not restarted.

### 4. Explain — answering "why was this denied?"

The question every onboarding runs into. Without an answer, each one becomes a
support ticket where somebody reads the bundle by hand.

```go
ex := pdp.Explain(req, tessaraop.DefaultExplainOptions())
fmt.Println(ex.Summary)
for _, a := range ex.UnmatchedAttributes() {
    fmt.Printf("%s failed %d times (%d because it was never supplied)\n",
        a.Attribute, a.Failures, a.Absent)
}
```

```
DENIED by default: 4 policies were in scope and 8 rules evaluated, but none matched
action           failed 3 times (3 because it was never supplied)
subject.role     failed 3 times (0 because it was never supplied)
```

That distinction is the whole value: `action` is an **integration bug** — nobody
is sending it — while `subject.role` is the **policy working as intended**.

It is a deliberately slower second path. `Evaluate` is allocation-free and runs
in microseconds; threading a trace through it would cost that on every request to
serve the rare one where somebody is asking a question. So `Explain` bypasses the
index, evaluates every in-scope rule, and short-circuits nowhere — an author wants
every failing condition, not the first one checked. A differential test asserts
it agrees with `Evaluate` across all six algorithms, because an explanation that
contradicts the decision would be believed.

Attribute values are **redacted by default**, since a trace usually travels
somewhere less trusted than the evaluator.

### 5. Static analysis — defects testing cannot find

Everything above answers *"what does this policy set do for this request"*.
Analysis answers *"what does it do for every request"*: can this rule ever fire,
is it already covered by another, can these two contradict. Those quantify over
infinitely many requests, so no number of passing tests settles them.

```bash
tessaraop -lint policies.json   # lint + analysis in one pass
```

```
Analysis (11 rules across 4 shards, 25 atoms, 502 BDD nodes)
  info: conflict: acme-break-glass/deny-critical-delete vs .../except-approved-break-glass:
        can both match the same request with opposite effects (DENY and ALLOW)
        (example: [action eq "delete"  resource.sensitivity in "critical"
                   subject.role eq "security-admin"])
```

| Finding | Meaning |
|---|---|
| `unreachable` | Conditions contradict — the rule can never fire. Always a bug. |
| `shadowed` | Another rule with the same effect already covers everything this matches. |
| `duplicate` | Identical conditions and effect. |
| `conflict` | Opposite effects that can both match. Legitimate under deny-overrides, but should be deliberate. |
| `always-matches` | Matches every request in its shard. |

Conditions compile to a **reduced ordered binary decision diagram**, so
"unreachable" is a comparison against the false terminal rather than a search.
The hard part is not the BDD but the *theory*: treating each predicate as an
independent boolean would call `role=="admin" ∧ role=="viewer"` satisfiable and
flag every mutually exclusive pair as a conflict. So atoms carry derived
implications and exclusions — interval arithmetic for numerics, prefix
containment for CIDR, and for anything with a finite domain, evaluating it
directly through the engine's own matcher, which decides even regex and
`contains` pairs exactly.

**The incompleteness is biased safely.** When nothing can be derived, atoms are
treated as independent — so the analyser may report a conflict that cannot really
occur, but it will never call a live rule unreachable or a needed rule redundant.
False alarms, never false reassurance.

### 6. Roles, groups and relationships

Hierarchies are resolved *outside* the engine and handed in as attributes, so the
index still prunes and the hot path is untouched.

```go
roles, _ := tessaraop.HierarchyFromMap(map[string][]string{
    "admin":  {"editor"},
    "editor": {"viewer"},
})
// A principal holding "admin" arrives carrying subject.roles = "admin,editor,viewer"
req := ingest.New("acme", "identity").
    WithRoleHierarchy(roles).
    FromSubject(&ingest.SubjectInfo{Role: "admin"}).
    Build()
```

**ReBAC is consumed, not stored.** A `RelationResolver` answers "what is this
subject to this object", and the answer materializes into `subject.relations`.
Building a native tuple store would mean adding a database and turning a
stateless component into a stateful service — `COMPARISON.md` §7.1 has the
reasoning.

Two implementations ship: an in-memory one with object-containment and group
expansion, and **`pkg/tessaraop/openfga`**, which is verified against a real
OpenFGA server rather than a mock — including the tuple-to-userset rewrite that
lets a folder viewer reach the documents inside it.

```go
resolver := openfga.New(openfga.Config{
    Endpoint: "http://localhost:8080", StoreID: storeID,
    Relations: []string{"owner", "editor", "viewer"},
})
tessaraop.ResolveRelations(ctx, resolver, &req, "user:anne", "document:budget")
// req now carries subject.relations = "editor,owner,viewer"
```

Still stdlib-only: the adapter speaks OpenFGA's Check API over `net/http` rather
than pulling in its SDK, which would have been the first external dependency in
the module and in the package closest to the request path.

### 7. Decision audit — `pkg/tessaraop/audit`

Structured records with the policy generation attached, so a decision can be tied
back to exactly what was installed six months later. **Attribute values are not
logged unless allowlisted** — audit logs are retained for years and shipped
outside the trust boundary of the service that wrote them. Writes go through a
bounded buffer: if the sink stalls, records drop and the drop is counted, because
a decision that cannot be logged must still be *made*.

### 8. Ingestion adapters — `internal/ingest`

Builds a request from `*http.Request`, `net.Conn`, `*tls.ConnectionState` and your
own token/subject verdicts, using only standard-library parsers. Parser-differential
bugs are one of the most productive sources of authorization bypasses — when the
component deciding parses differently from the component serving, an attacker
crafts input they disagree about — so `net/http`, `net/netip`, `crypto/tls` and
`mime` do the parsing and this package only maps their output onto registry names.

```go
req := ingest.New("acme", "identity").
    FromHTTPRequest(r).
    FromForwardedHeaders(r, trustedHops).
    FromTLS(r.TLS).
    FromSubject(subject).
    AtTime(time.Now()).
    Build()
```

Three security properties are enforced rather than merely documented:

- **`FromForwardedHeaders` requires an explicit trusted-hop count** and defaults
  to ignoring `X-Forwarded-For` entirely. The header is attacker-controlled on its
  left; taking the leftmost entry — the common implementation — lets any client
  claim a corporate source address and walk through a CIDR allowlist.
- **Credentials never become attributes.** `Authorization`, `Proxy-Authorization`
  and `Cookie` are excluded, and cookie values are populated only for names you
  allowlist. Attributes reach the decision cache and audit records; a session
  cookie copied into that path is a credential leak waiting for a debug log line.
- **The clock is a parameter**, so an audited request replays to the same decision.

---

## What a policy can match on

118 registered attributes across the full Layer 3 / 4 / 7 surface, each with a
declared type and the operators valid on it. Run `tessaraop -attrs` for the
complete list, or `GET /v1/attributes` for JSON.

| Namespace | Covers |
|---|---|
| `network.*` | L3: source/dest address, IP version, protocol, TTL, options, fragmentation, DSCP/ToS |
| `transport.*` | L4: ports, TCP flags, sequence, window, ICMP type/code |
| `conn.*` | Connection state, rate, concurrency, PPS, BPS, idle time |
| `geo.*` `threat.*` `iface.*` | Country/continent/city, IP reputation, proxy/Tor, ASN, interfaces |
| `http.*` | Method, path (cleaned **and** raw), query, host, version, headers, cookies, content type/length, status |
| `payload.*` | Body, file name/extension, magic bytes, declared vs detected MIME, schema validity, DLP hits, entropy |
| `tls.*` | Version (string **and** numeric), cipher suite, SNI, ALPN, client-certificate metadata, JA3 |
| `subject.*` `token.*` `session.*` | Principal, roles, groups, MFA, risk, JWT claims, session state |
| `resource.*` `action` `time.*` | Object identity and sensitivity, operation, clock |

Four namespaces are open-ended, because their keys belong to your traffic:
`http.header.*`, `http.query.*`, `http.cookie.*`, `subject.claim.*`.

**31 operators.** String: `eq ne in nin contains ncontains prefix nprefix suffix
nsuffix regex nregex dnssuffix ndnssuffix`. Sets: `has_any has_all has_none`.
Numeric: `range nrange gt gte lt lte num_eq num_ne num_in num_nin`. Network:
`cidr ncidr`. Presence: `exists nexists`. Combined with `AND` / `OR` / `NOT`.

Four deliberate distinctions:

- **`has_any` vs `contains`** on a multi-valued attribute. `contains` is a
  substring test, so a principal holding only `readwrite` satisfies
  `subject.roles contains "read"` — a privilege escalation. The `has_*` operators
  split on the delimiter and compare whole elements. The linter rejects
  `contains` on any attribute the registry documents as a set.

- **`suffix` vs `dnssuffix`.** `suffix` is a raw byte test, for file extensions.
  `dnssuffix` is label-aligned, because accepting `evilacme.com` for `acme.com` is
  a live authorization bypass.
- **Version fields are registered twice**, string and numeric, so a floor
  ("at least TLS 1.2") is one comparison rather than an enumerated set needing an
  edit every release. On that numeric scale SSLv3 is `3`, not `30` — otherwise it
  would sort *above* TLS 1.3 and satisfy a `>= 12` floor. (That was a real bug,
  caught by a test during development.)
- **NaN satisfies nothing**, including negated comparisons. Every IEEE comparison
  against NaN is false, so `num_ne` would otherwise turn a malformed measurement
  into a match.

---

## Architecture

```
Request
  ├─ decision cache (verified on hit, striped, order-independent hash)
  ├─ global shard (platform-wide denies)
  ├─ tenant-wide shard
  └─ (tenant, scope) shard
        ├─ universe = flattened rules, in policy order
        ├─ per-attribute filters: hash map / CIDR trie / DNS trie /
        │     prefix table / suffix table / interval table / numeric hash
        ├─ filters ordered cheapest-first
        ├─ two intersection strategies, chosen by seed size vs n/32:
        │     · per-element filtering    (small seeds — cost tracks survivors)
        │     · word-parallel bitmap AND (large seeds — cost tracks n/64)
        └─ two-tier combination on survivors:
              tier 1: rules within a policy, by its RuleAlgorithm
              tier 2: policy verdicts within the shard, by the shard Algorithm
```

```
internal/
├── model/     types, operator semantics, condition trees, combining algorithms
├── attr/      the attribute registry: names, types, valid operators
├── naive/     linear-scan oracle
├── bitset/    hybrid sparse/dense integer sets
├── matcher/   CIDR trie, domain trie, prefix/suffix tables, interval, numeric set
├── index/     per-attribute sub-indexes and both intersection strategies
├── engine/    sharding, algorithm selection, decision cache
├── bundle/    declarative JSON format and the linter
├── ingest/    L3/L4/L7 adapters over stdlib parsers
├── genutil/   synthetic multi-tenant corpus generator
└── benchmark/ layered benchmarks
pkg/tessaraop/            public SDK
pkg/tessaraop/pdpserver/  HTTP decision point
cmd/tessaraop/            CLI: demo, registry, lint, export, bench, interactive
cmd/tessaraopd/           the server binary
```

The indexed unit is a **rule**, not a policy: a policy's index entry would be the
union of what all its rules ask for, which is useless as a filter. Positions are
assigned in policy order, so ascending candidate positions form one contiguous run
per policy and the two-tier walk groups them with no map and no allocation.

Six combining algorithms, used at both tiers — the order-independent subset of
XACML 3.0's eight. `deny-overrides` (default, the only one that short-circuits),
`permit-overrides`, `first-applicable`, `deny-unless-permit`,
`permit-unless-deny` and `only-one-applicable`. The `ordered-` variants are
deliberately absent: they resolve ties by document order, and the index yields
candidates in arbitrary order, so honouring them would forfeit short-circuiting.

Deny-overrides being **order-independent** is what makes indexing sound: the index
yields candidates in whatever order the underlying sets enumerate, and that
arbitrary order must not leak into the decision.

---

## Correctness

The engine is too intricate to trust by inspection: sharding, seven index
families, negation handling, lazy set unions, two intersection strategies, a
cache, and two tiers of combining logic. Correctness rests on five things.

1. **Shared semantics.** Both evaluators route every match through
   `Condition.Matches` and resolve through the same `Accumulator`. The fast path
   has no second copy of the rules to drift from.
2. **The index is a pre-filter only** — over-inclusive but never under-inclusive,
   and survivors always face the real match logic. A bug in an index costs
   performance, not correctness, and a randomized test asserts that directly.
3. **Differential testing** against the naive oracle, under all three algorithms,
   over randomized corpora spanning every operator family and tree shape.
4. **Both intersection strategies are pinned together.** Only one runs per
   request, so a divergence would stay invisible until a corpus crossed the size
   threshold and answers quietly changed.
5. **Adversarial and concurrent cases**: missing attributes, wrong typed maps,
   unknown tenants, empty requests, lookalike domains, reload under concurrent
   evaluation — all under `-race`.

**316 tests, all passing under `-race`.** The ones worth knowing about:

| Test | Guards |
|---|---|
| `TestCandidates_NeverExcludesAMatchingRule` | 200 randomized corpora × 20 requests: the index is never under-inclusive |
| `TestIntersectStrategies_Agree` | The two intersection paths cannot silently diverge |
| `TestANDSpineLeaves_ExcludesOrAndNot` | The indexing boundary, from both the model and index sides |
| `TestDifferential_EngineMatchesNaive` | Engine vs. the auditable oracle across every algorithm |
| `TestPolicy_AttributesTheRuleThatActuallyFired` | Two same-effect rules in one policy are not misattributed |
| `TestCondition_NaNSatisfiesNothing` | A malformed measurement cannot satisfy a negated comparison |
| `TestCondition_SuffixIsNotLabelAligned` | The `evilacme.com` / `acme.com` bypass class |
| `TestCache_NeverServesAcrossDifferentRequests` | 3,000 requests through an 8-entry cache to force collisions |
| `TestFromForwardedHeaders_HopCounting` | The `X-Forwarded-For` spoofing class |
| `TestFromHTTPRequest_SkipsCredentialHeaders` | No credential becomes an attribute |
| `TestForwardAuth_NeverReturns5xx` | A malformed request cannot make a fail-open proxy grant access |
| `TestReload_FailureKeepsThePreviousPolicySet` | A bad policy deploy degrades to stale rules, not an outage |

Absent attributes **fail closed**: every operator except `nexists` rejects a
request that lacks the attribute, negations included. `role != admin` does not
quietly pass for a request carrying no role.

Two live bugs were found by these tests during development and are recorded in the
git history: the SSLv3 numeric encoding satisfying a TLS 1.2 floor, and the
forward-auth handler letting a proxy's own address overwrite the real client's.

---

## Running

```bash
go build ./...
go vet ./...
go test ./... -race                  # 316 tests
go test ./internal/benchmark/ -run XXX_NONE -bench . -benchmem

go run ./cmd/tessaraop -demo         # hand-written policy walkthrough
go run ./cmd/tessaraop -attrs        # the attribute registry
go run ./cmd/tessaraop -lint examples/starter-bundle.json
go run ./cmd/tessaraop -n 1000000 -tenants 10000 -requests 10
go run ./cmd/tessaraop -n 100000 -interactive

go run ./cmd/tessaraopd -bundle examples/starter-bundle.json -addr :8181
```

`-race` on Windows needs a **64-bit** gcc on `PATH`
(`winget install BrechtSanders.WinLibs.POSIX.UCRT`); a 32-bit MinGW fails with
"64-bit mode not compiled in".

---

## Documentation

| File | Purpose |
|---|---|
| `README.md` | This file: what it is, results, honest limitations, how to integrate |
| `DOCUMENTATION.md` | Full architecture, algorithms, and the reasoning behind each choice |
| `COMPARISON.md` | How Cedar / OPA / OpenFGA / Casbin work, which authorization models are supported, and what may and may not be claimed |
| `API_REFERENCE.md` | Every exported type and function |
| `PROGRESS.md` | Current state and what is next |
| `rules_for_policy.md` | The source catalog of telemetry points the operator surface covers |
| `examples/starter-bundle.json` | A working bundle: identity, L3/L4 perimeter and L7 rules |

## Not implemented

Named explicitly so the roadmap is not confused with the codebase:

- **MTBDD/BDD decision diagrams** — zero lines
- **Tuple space search** — the identified next optimization for the flat-shard case
- **RoaringBitmap** — not used; `internal/bitset` borrows the "pick representation
  by cardinality" idea without being Roaring
- **Incremental index updates** — adding a policy rebuilds its shard
- **Importers from other formats** (AWS IAM, Kubernetes NetworkPolicy, Envoy RBAC,
  Cedar, Rego) — the bundle format and linter are the migration target, but no
  translator is written
- **gRPC** — the HTTP forward-auth shape covers the same proxies without a
  protobuf dependency
- **YAML authoring** — JSON only, to keep the dependency count at zero; convert at
  build time if you prefer YAML
