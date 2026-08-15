# TessaraOP - API Reference

Generated from source doc comments with `go doc -all`. Do not edit by hand;
regenerate after changing any exported declaration.

Go go1.26.5 | 2026-08-15

## Packages

- [`pkg/tessaraop`](#pkg-tessaraop) - The public SDK. The only package an integration imports.
- [`pkg/tessaraop/pdpserver`](#pkg-tessaraop-pdpserver) - HTTP decision point: native, explain, forward-auth and OPA-shaped endpoints.
- [`pkg/tessaraop/audit`](#pkg-tessaraop-audit) - Structured decision audit records.
- [`internal/model`](#internal-model) - Core types, operator semantics, condition trees, both combining tiers.
- [`internal/attr`](#internal-attr) - The L3/L4/L7 attribute registry.
- [`internal/explain`](#internal-explain) - Per-condition answers to why a decision came out as it did.
- [`internal/hierarchy`](#internal-hierarchy) - Role, group and resource membership DAGs with transitive closure.
- [`internal/relation`](#internal-relation) - ReBAC resolver interface and in-memory implementation.
- [`internal/bundle`](#internal-bundle) - The declarative JSON policy format and its linter.
- [`internal/ingest`](#internal-ingest) - Builds requests from real traffic using stdlib parsers only.
- [`internal/engine`](#internal-engine) - Sharding, algorithm selection, decision cache.
- [`internal/index`](#internal-index) - Per-attribute sub-indexes and both intersection strategies.
- [`internal/matcher`](#internal-matcher) - CIDR trie, domain trie, prefix/suffix tables, interval and numeric-set indexes.
- [`internal/bitset`](#internal-bitset) - Hybrid sparse/dense integer sets.
- [`internal/naive`](#internal-naive) - The linear-scan oracle.
- [`internal/indexed`](#internal-indexed) - Single-shard indexed evaluator; the benchmark control.
- [`internal/genutil`](#internal-genutil) - Synthetic multi-tenant corpus generator.

---

## pkg/tessaraop

The public SDK. The only package an integration imports.

```go
package tessaraop // import "github.com/suga/tessaraop/pkg/tessaraop"

Package tessaraop is the public API of the TessaraOP policy decision engine.

It is the only package an integration should import. Everything under internal/
is free to change shape between releases; the names here are the contract.

# The shortest useful program

    pdp, diags, err := tessaraop.OpenBundle("policies.json", tessaraop.Config{
        CacheSize: 8192,
    })
    if err != nil {
        log.Fatalf("policy bundle rejected: %v", tessaraop.FormatDiagnostics(diags))
    }

    req := tessaraop.NewRequest("acme", "identity").
        Str(tessaraop.AttrSubjectRole, "admin").
        Num(tessaraop.AttrRiskScore, 12).
        IPString(tessaraop.AttrSourceIP, "10.1.2.3").
        Build()

    if d := pdp.Evaluate(req); !d.Allowed {
        http.Error(w, "forbidden", http.StatusForbidden)
        return
    }

# What this type guarantees

A PDP is safe for concurrent use by any number of goroutines, and Reload swaps
the whole policy set atomically: a request in flight either sees the old set
entirely or the new one entirely, never a mixture. That is what makes it safe to
ship policy on a different cadence from the binary.

# Fail-closed is the default everywhere

A request that omits an attribute does not match conditions on it — including
negated ones. A policy set that fails to load leaves the previous set in
place rather than emptying it. A malformed condition tree denies. If you want
a different posture, express it as an explicit catch-all ALLOW rule at low
priority, so it is visible in the bundle rather than implied by the engine.

CONSTANTS

const (
	Allow = model.Allow
	Deny  = model.Deny

	DenyOverrides   = model.DenyOverrides
	PermitOverrides = model.PermitOverrides
	FirstApplicable = model.FirstApplicable

	// DenyUnlessPermit and OnlyOneApplicable complete the order-independent
	// XACML 3.0 set. OnlyOneApplicable is the genuinely distinct one: it detects
	// ambiguity rather than resolving it, denying when several units apply.
	DenyUnlessPermit  = model.DenyUnlessPermit
	OnlyOneApplicable = model.OnlyOneApplicable

	// PermitUnlessDeny grants by default: a request matching nothing is ALLOWED.
	// That inverts the fail-closed posture the rest of this engine holds to.
	// Confine it to a shard whose contents are exhaustively known.
	PermitUnlessDeny = model.PermitUnlessDeny

	// GlobalTenant holds platform-wide policies evaluated for every request,
	// whatever tenant it names: blocklists, kill switches, baseline denies.
	GlobalTenant = model.GlobalTenant
	// TenantWideScope is the scope of policies applying across a whole tenant.
	TenantWideScope = model.TenantWideScope
)
    Effects and combining algorithms.

const (
	OpEquals       = model.OpEquals
	OpNotEquals    = model.OpNotEquals
	OpIn           = model.OpIn
	OpNotIn        = model.OpNotIn
	OpContains     = model.OpContains
	OpNotContains  = model.OpNotContains
	OpPrefix       = model.OpPrefix
	OpNotPrefix    = model.OpNotPrefix
	OpSuffix       = model.OpSuffix
	OpNotSuffix    = model.OpNotSuffix
	OpRegex        = model.OpRegex
	OpNotRegex     = model.OpNotRegex
	OpDNSSuffix    = model.OpDNSSuffix
	OpNotDNSSuffix = model.OpNotDNSSuffix
	OpExists       = model.OpExists
	OpNotExists    = model.OpNotExists
	OpRange        = model.OpRange
	OpNotRange     = model.OpNotRange
	OpGreaterThan  = model.OpGreaterThan
	OpGreaterEq    = model.OpGreaterEq
	OpLessThan     = model.OpLessThan
	OpLessEq       = model.OpLessEq
	OpNumEquals    = model.OpNumEquals
	OpNumNotEq     = model.OpNumNotEq
	OpNumIn        = model.OpNumIn
	OpNumNotIn     = model.OpNumNotIn
	OpCIDR         = model.OpCIDR
	OpNotCIDR      = model.OpNotCIDR

	// Multi-valued set operators. Use these — never OpContains — on an attribute
	// the registry documents as a comma-delimited set (subject.roles,
	// subject.groups, token.scopes, resource.ancestors, transport.tcp_flags).
	// OpContains is a substring test, so a principal holding only "readwrite"
	// would satisfy `contains "read"`.
	OpHasAny  = model.OpHasAny
	OpHasAll  = model.OpHasAll
	OpHasNone = model.OpHasNone
)
    Operators. See the package documentation of the registry (or the -attrs
    output of cmd/tessaraop) for which apply to which attribute.

const (
	AttrSourceIP     = attr.SourceIP
	AttrDestIP       = attr.DestIP
	AttrDestPort     = attr.DestPort
	AttrSourcePort   = attr.SourcePort
	AttrTCPFlags     = attr.TCPFlags
	AttrConnState    = attr.ConnState
	AttrGeoCountry   = attr.GeoCountry
	AttrThreatRep    = attr.ThreatRep
	AttrProxyType    = attr.ProxyType
	AttrHTTPMethod   = attr.HTTPMethod
	AttrHTTPPath     = attr.HTTPPath
	AttrHTTPHost     = attr.HTTPHost
	AttrHTTPQuery    = attr.HTTPQuery
	AttrUserAgent    = attr.UserAgent
	AttrContentType  = attr.ContentType
	AttrContentLen   = attr.ContentLen
	AttrHTTPStatus   = attr.HTTPStatus
	AttrFileExt      = attr.FileExt
	AttrTLSVersion   = attr.TLSVersion
	AttrTLSVersionNo = attr.TLSVersionNo
	AttrSNI          = attr.SNI
	AttrSubjectID    = attr.SubjectID
	AttrSubjectRole  = attr.SubjectRole
	AttrMFAVerified  = attr.MFAVerified
	AttrRiskScore    = attr.RiskScore
	AttrTokenValid   = attr.TokenValid
	AttrTokenScopes  = attr.TokenScopes
	AttrResourceType = attr.ResourceType
	AttrResourcePath = attr.ResourcePath
	AttrSensitivity  = attr.Sensitivity
	AttrAction       = attr.Action
	AttrTimeHour     = attr.TimeHour
)
    Well-known attribute names. The registry holds many more; these are the
    ones integrations touch most. Using a constant makes a typo a compile error
    rather than a rule that silently never matches.

const AttrSubjectRelations = relation.SubjectRelations
    AttrSubjectRelations is where ResolveRelations puts its answer. Match it
    with OpHasAny / OpHasAll / OpHasNone.


VARIABLES

var (
	// Cond wraps one condition as a leaf.
	Cond = model.Cond
	// And returns the conjunction. And() with no arguments matches everything.
	And = model.And
	// Or returns the disjunction. Or() with no arguments matches nothing.
	Or = model.Or
	// Not negates.
	Not = model.Not
	// AllOf is the flat conjunction of conditions, the common case.
	AllOf = model.AllOf
	// AnyOf is the flat disjunction of conditions.
	AnyOf = model.AnyOf
	// NewRule builds a rule.
	NewRule = model.NewRule
	// SimplePolicy builds a one-rule policy from an AND-ed condition list.
	SimplePolicy = model.SimplePolicy
)
    Condition-tree builders.

var ErrHierarchyCycle = hierarchy.ErrCycle
    ErrHierarchyCycle is reported when a membership graph is not acyclic.
    A cycle is always an authoring mistake, and tolerating one would make a
    principal's effective roles depend on traversal order.

var ErrNoPolicies = errors.New("tessaraop: policy set is empty")
    ErrNoPolicies is returned when a load would leave the PDP with nothing.

    It is an error rather than an empty accept-nothing set because the two are
    indistinguishable at the call site and the consequences differ wildly:
    an empty set denies every request, which as a silent outcome of a mis-pathed
    file is an outage. Callers that genuinely want a deny-everything posture
    should say so with an explicit catch-all DENY policy.


FUNCTIONS

func Claim(name string) string
    Claim returns the attribute name for a token claim.

func Cookie(name string) string
    Cookie returns the attribute name for a cookie.

func ExportBundle(policies []Policy, w io.Writer) error
    ExportBundle serializes policies to the declarative format. Useful to
    migrate a hand-coded integration onto files, and to snapshot what a running
    PDP holds.

func FormatDiagnostics(diags []Diagnostic) string
    FormatDiagnostics renders diagnostics one per line, errors first, for a log
    line or a CI annotation.

func HasErrors(diags []Diagnostic) bool
    HasErrors reports whether any diagnostic blocks loading.

func Header(name string) string
    Header returns the attribute name for an HTTP request header.

func NewStaticRelations(tuples ...RelationTuple) *relation.Static
    NewStaticRelations returns an in-memory relationship resolver.

    It is not a substitute for a real ReBAC store — no persistence,
    no consistency model, no reverse index — but it covers tests, local
    development, and deployments whose relationship set is genuinely small and
    static.

func OpenBundle(path string, cfg Config) (*PDP, []Diagnostic, error)
    OpenBundle builds a PDP from a bundle file in one call.

func QueryParam(name string) string
    QueryParam returns the attribute name for a URL query parameter.

func ReadBundle(r io.Reader, cfg Config) (*PDP, []Diagnostic, error)
    ReadBundle builds a PDP from a bundle read from r.

func ResolveRelations(ctx context.Context, r RelationResolver, req *Request, subject, object string) error
    ResolveRelations resolves the subject's relations to the object and writes
    them into the request, ready for evaluation.

    Call it while assembling a request, never on a hot loop: a resolver may
    perform I/O. Wrap a remote one in RelationTimeout.


TYPES

type Algorithm = model.Algorithm
    Algorithm selects how matching units combine.

type Attribute = attr.Attribute
    Attribute is a registry entry.

func Attributes() []Attribute
    Attributes returns every registered attribute, so an integration can
    generate its own onboarding documentation or offer authoring completions.

func LookupAttribute(name string) (Attribute, bool)
    LookupAttribute resolves a name, matching open-ended namespaces by prefix.

type Bundle = bundle.Bundle
    Bundle is the declarative policy format.

type Condition = model.Condition
    Condition is a single predicate over one attribute.

type Config struct {
	// Algorithm combines matching policies across a shard. Empty means
	// DenyOverrides, which is the only order-independent choice and the only one
	// that can short-circuit.
	//
	// Choose FirstApplicable when audit attribution must be deterministic: the
	// overrides algorithms do not specify which of several same-effect matches to
	// credit, so the reported rule and its obligations can differ between two
	// correct implementations.
	Algorithm Algorithm

	// CacheSize is the number of decision cache entries. Zero disables it.
	//
	// Every hit is verified against the full stored request rather than trusted
	// on hash alone, so a collision cannot serve one subject another's decision.
	// Real authorization traffic repeats heavily, so this is usually the single
	// largest win available.
	CacheSize int

	// UnionObligations collects obligations from every matching rule carrying the
	// winning effect, rather than only from the one credited.
	//
	// It removes the caveat on Algorithm above — that obligations depend on which
	// of several equally-valid matches was reached first — and it is what XACML
	// specifies. The cost is short-circuiting: the engine must see every
	// candidate, so deny-overrides can no longer stop at the first deny. Enable
	// it where a dropped require_mfa would be a security incident; leave it off
	// where throughput dominates.
	UnionObligations bool

	// Lint tunes validation of bundles loaded through this PDP.
	Lint LintOptions
}
    Config controls a PDP.

type Decision = model.Decision
    Decision is the engine's answer.

type Diagnostic = bundle.Diagnostic
    Diagnostic is one linter finding.

func Errors(diags []Diagnostic) []Diagnostic
    Errors returns only the blocking diagnostics, for a caller that wants to
    count or report them separately from warnings.

func LintBundle(r io.Reader, opt LintOptions) ([]Diagnostic, error)
    LintBundle validates a bundle without installing it. Use it in CI: a policy
    change should fail the pipeline, not the request path.

func LintBundleFile(path string, opt LintOptions) ([]Diagnostic, error)
    LintBundleFile is LintBundle from a path.

func ValidatePolicies(policies []Policy, opt LintOptions) []Diagnostic
    ValidatePolicies runs the same checks over programmatically built policies,
    so an SDK caller gets the linter too rather than only bundle authors.

type Effect = model.Effect
    Effect is ALLOW or DENY.

type ExplainOptions = explain.Options
    ExplainOptions controls how much an explanation reveals.

func DefaultExplainOptions() ExplainOptions
    DefaultExplainOptions redacts observed attribute values, includes rules that
    did not match, and omits policies the request could not reach.

type Explanation = explain.Explanation
    Explanation is the full account of why a decision came out as it did.

type Expr = model.ConditionExpr
    Expr is a boolean tree over conditions.

type Hierarchy = hierarchy.Graph
    Hierarchy is a membership DAG: role inheritance, nested groups, or resource
    containment.

    It is resolved *outside* the engine. A principal holding "admin" in a graph
    where admin inherits editor inherits viewer arrives carrying subject.roles
    = "admin,editor,viewer", and an ordinary indexed operator (OpHasAny) answers
    the question. The engine gains no new concept, the index still prunes,
    and the evaluation path is untouched — the same division of labour that
    keeps parsing and I/O outside the hot path.

func HierarchyFromMap(m map[string][]string) (*Hierarchy, error)
    HierarchyFromMap builds and freezes a graph from a child -> parents mapping,
    which is the shape a configuration file naturally carries. It reports an
    error if the graph contains a cycle.

        roles, err := tessaraop.HierarchyFromMap(map[string][]string{
            "admin":  {"editor"},
            "editor": {"viewer"},
        })

func NewHierarchy() *Hierarchy
    NewHierarchy returns an empty, unfrozen membership graph. Call Add to record
    that a child is subsumed by its parents, then Freeze.

type Info struct {
	Generation      uint64 `json:"generation"`
	Policies        int    `json:"policies"`
	Rules           int    `json:"rules"`
	Tenants         int    `json:"tenants"`
	Shards          int    `json:"shards"`
	Algorithm       string `json:"algorithm"`
	CacheEnabled    bool   `json:"cache_enabled"`
	CacheSizeHint   int    `json:"cache_size_hint,omitempty"`
	RulesInUniverse int    `json:"rules_in_universe"`
}
    Info describes the installed policy set.

type LintOptions = bundle.LintOptions
    LintOptions tunes bundle validation.

type Metrics struct {
	Evaluations atomic.Uint64
	Allowed     atomic.Uint64
	Denied      atomic.Uint64
	CacheHits   atomic.Uint64
	RulesTested atomic.Uint64
	Reloads     atomic.Uint64
}
    Metrics are cumulative counters, safe to read at any time.

    They are maintained with atomic adds on the evaluation path. That costs a
    few nanoseconds against a multi-microsecond evaluation, which is a trade
    worth making: an authorization component nobody can observe is one nobody
    will trust in production.

type MetricsSnapshot struct {
	Evaluations uint64 `json:"evaluations"`
	Allowed     uint64 `json:"allowed"`
	Denied      uint64 `json:"denied"`
	CacheHits   uint64 `json:"cache_hits"`
	RulesTested uint64 `json:"rules_tested"`
	Reloads     uint64 `json:"reloads"`
}
    MetricsSnapshot is a point-in-time copy of the counters.

type Operator = model.Operator
    Operator is a comparison.

type PDP struct {
	// Has unexported fields.
}

func New(policies []Policy, cfg Config) (*PDP, error)
    New builds a PDP over policies held in memory.

func (p *PDP) Allowed(req Request) bool
    Allowed is Evaluate reduced to a boolean, for call sites that do not act on
    obligations. Prefer Evaluate: dropping the obligations silently discards
    requirements like require_mfa that a policy author expected to be enforced.

func (p *PDP) Evaluate(req Request) Decision
    Evaluate renders a decision. Safe for concurrent use.

func (p *PDP) Explain(req Request, opt ExplainOptions) *Explanation
    Explain reports why the request produced the decision it did: which policies
    were in scope, which rules were evaluated, and for each condition whether
    the attribute was present and whether it matched.

    It is a deliberately slower second path. Evaluate is allocation-free and
    runs in microseconds; threading a trace through it would cost that for
    every request in order to serve the rare one where somebody is asking a
    question. So Explain bypasses the index, evaluates every in-scope rule,
    and short-circuits nowhere — an author wants every failing condition,
    not the first one checked.

    Do not call it on the hot path. Call it from a support tool, a CLI, or an
    endpoint a human hits.

    The returned Decision is computed on the same inputs as Evaluate and is
    asserted to agree with it; an explanation that contradicted the decision
    would be worse than none, because it would be believed.

func (p *PDP) Generation() uint64
    Generation counts how many policy sets have been installed. It changes on
    every successful Reload, which makes it the value to expose in a readiness
    probe or compare across a fleet to confirm a rollout landed.

func (p *PDP) Info() Info
    Info reports what is currently installed.

func (p *PDP) LoadBundle(r io.Reader) ([]Diagnostic, error)
    LoadBundle validates and installs a bundle read from r.

    Diagnostics are returned whether or not the load succeeded, so warnings on
    a good bundle still reach the caller's log. On error the previous policy set
    is untouched.

func (p *PDP) LoadBundleFile(path string) ([]Diagnostic, error)
    LoadBundleFile is LoadBundle from a path.

func (p *PDP) Metrics() MetricsSnapshot
    Metrics returns a snapshot of the counters.

func (p *PDP) Policies() []Policy
    Policies returns the installed policy set. The slice is owned by the PDP and
    must not be modified; copy it if you need to.

func (p *PDP) ReachableRules(tenantID, scope string) int
    ReachableRules reports how many rules a request to this tenant and scope can
    reach. It is the number that governs per-request cost, and the one to watch
    when a customer's shard grows.

func (p *PDP) Reload(policies []Policy) error
    Reload replaces the policy set atomically.

    Requests in flight complete against whichever set they started on. If
    building the new set fails, the existing one stays in place — a bad deploy
    degrades to stale policy, never to no policy.

type Policy = model.Policy
    Policy is a tenanted collection of rules.

type RelationResolver = relation.Resolver
    RelationResolver answers what relations a subject holds to an object.

    Relationships are *consumed*, not stored: TessaraOP does not implement a
    Zanzibar-style tuple store, because that would require a database and turn
    a stateless drop-in component into a stateful service. Instead a resolver is
    called once per request, before evaluation, and the answer is materialized
    into subject.relations where an indexed operator (OpHasAny) matches it.

    Implement this against OpenFGA, SpiceDB or your own service. See package
    relation for the adapter contract and for the in-memory implementation used
    in tests and small deployments.

func RelationCache(r RelationResolver, ttl time.Duration) RelationResolver
    RelationCache memoizes resolutions for a bounded time. A cached relationship
    is a stale authorization decision, so the TTL is required and there is no
    invalidation hook — if your relationships must take effect immediately,
    cache them where the writes are instead.

func RelationTimeout(r RelationResolver, d time.Duration) RelationResolver
    RelationTimeout bounds how long a resolver may take. A remote relationship
    store sits in the request path, so an unbounded call there is an
    availability risk for everything behind it.

type RelationTuple = relation.Tuple
    RelationTuple is one relationship fact.

type Request = model.Request
    Request is one access check: a tenant, a scope, and typed attributes.

type RequestBuilder struct {
	// Has unexported fields.
}
    RequestBuilder assembles a Request with the right typed map per attribute.

    Putting a value in the wrong map is the most common integration mistake
    and the hardest to notice: a port supplied as a string is invisible to
    every numeric operator, so the rule guarding it silently never fires.
    The builder's per-type methods make the choice explicit, and Validate
    cross-checks it against the registry.

func NewRequest(tenantID, scope string) *RequestBuilder
    NewRequest starts a builder for a tenant and scope. An empty scope means the
    request reaches only the tenant-wide and global shards.

func (b *RequestBuilder) Bool(name string, value bool) *RequestBuilder
    Bool sets a string attribute to "true" or "false". Boolean-valued attributes
    in the registry are strings, so that set membership and negation work on
    them uniformly with everything else.

func (b *RequestBuilder) Build() Request
    Build returns the request. Empty maps are dropped so the decision cache
    hashes the same logical request identically however it was built.

func (b *RequestBuilder) Err() error
    Err reports parse failures accumulated during building, and any attribute
    supplied in a map the registry does not declare for it. Checking it is
    optional but strongly advised during integration: it turns the silent
    wrong-map mistake into a visible one.

func (b *RequestBuilder) IP(name string, addr netip.Addr) *RequestBuilder
    IP sets an IP attribute.

func (b *RequestBuilder) IPString(name, value string) *RequestBuilder
    IPString parses and sets an IP attribute, recording a builder error if the
    value does not parse. An unparsable address is dropped rather than guessed
    at: substituting a zero address would make a CIDR condition match a block it
    should not.

func (b *RequestBuilder) Int(name string, value int) *RequestBuilder
    Int sets a numeric attribute from an int.

func (b *RequestBuilder) Num(name string, value float64) *RequestBuilder
    Num sets a numeric attribute.

func (b *RequestBuilder) Str(name, value string) *RequestBuilder
    Str sets a string attribute. An empty name is ignored; an empty value is
    kept, since "present but empty" is distinguishable from absent and policies
    rely on that distinction.

func (b *RequestBuilder) Strs(name string, values ...string) *RequestBuilder
    Strs joins values with commas, which is the convention the registry
    documents for multi-valued string attributes such as subject.groups and
    token.scopes. Match them with the contains operator.

type Rule = model.Rule
    Rule carries an effect and the condition tree that triggers it.

```

---

## pkg/tessaraop/pdpserver

HTTP decision point: native, explain, forward-auth and OPA-shaped endpoints.

```go
package pdpserver // import "github.com/suga/tessaraop/pkg/tessaraop/pdpserver"

Package pdpserver exposes a PDP over HTTP so stacks that are not Go can use it.

# Why several endpoint shapes rather than one

An authorization engine only gets adopted if it speaks the protocol the
customer's proxy already speaks. Asking a platform team to write a new sidecar
is how a pilot stalls. So this serves four shapes over the same policy set:

    POST /v1/decision          native JSON: full request in, full decision out
    ANY  /v1/authz             forward-auth: 200 or 403, headers describe the request
    POST /v1/data/tessaraop    OPA-compatible: {"input": …} -> {"result": …}
    GET  /v1/attributes        the registry, as onboarding documentation

/v1/authz is the important one for breadth. Envoy's ext_authz HTTP service,
NGINX auth_request, Traefik ForwardAuth, HAProxy, Istio's ext_authz and Caddy's
forward_auth all work the same way: forward the original request's headers to a
URL and act on the status code. One handler covers all of them, with no protobuf
dependency and no per-proxy adapter.

The OPA-shaped endpoint exists because a team already calling OPA has the client
code, the retry behaviour and the dashboards; matching the request and response
envelope turns migration into a URL change.

# Operational endpoints

    GET  /healthz    process is up
    GET  /readyz     a policy set is installed; 503 before the first load
    GET  /metrics    Prometheus text format
    POST /v1/reload  re-read the bundle from disk, atomically
    GET  /v1/info    what is installed right now

Metrics are emitted in Prometheus' text exposition format by hand rather than
through a client library, keeping the zero-dependency property. The format is
stable and simple enough that this is a better trade than a dependency in a
request path.

CONSTANTS

const (
	// HeaderTenant and HeaderScope override what the request would otherwise
	// infer. A proxy typically sets them per listener or per route.
	HeaderTenant = "X-Tessaraop-Tenant"
	HeaderScope  = "X-Tessaraop-Scope"

	// HeaderSubject and friends carry the authenticated principal, which the
	// proxy or an upstream auth filter has already established.
	HeaderSubject     = "X-Tessaraop-Subject"
	HeaderSubjectRole = "X-Tessaraop-Role"
	HeaderGroups      = "X-Tessaraop-Groups"
	HeaderMFA         = "X-Tessaraop-Mfa"
	HeaderRiskScore   = "X-Tessaraop-Risk-Score"

	// HeaderAction and HeaderResource override the defaults derived from the
	// HTTP method and path.
	HeaderAction      = "X-Tessaraop-Action"
	HeaderResource    = "X-Tessaraop-Resource"
	HeaderSensitivity = "X-Tessaraop-Sensitivity"

	// Response headers. Envoy, Traefik and NGINX can all copy selected response
	// headers onto the upstream request, which is how obligations reach the
	// application that has to enforce them.
	HeaderDecision    = "X-Tessaraop-Decision"
	HeaderPolicy      = "X-Tessaraop-Policy"
	HeaderRule        = "X-Tessaraop-Rule"
	HeaderObligations = "X-Tessaraop-Obligations"
	HeaderGeneration  = "X-Tessaraop-Generation"
)
    Forward-auth request and response headers.

    These are read from and written to the proxy's own header plumbing, which is
    the only channel available in that protocol shape. The names are namespaced
    so they cannot collide with a customer's headers.

const DefaultMaxBodyBytes = 1 << 20
    DefaultMaxBodyBytes bounds request decoding.


VARIABLES

var ErrNoPDP = errors.New("pdpserver: Config.PDP is required")
    ErrNoPDP is returned when Config.PDP is nil.


TYPES

type Config struct {
	// PDP is the decision point to serve. Required.
	PDP *tessaraop.PDP

	// BundlePath, when set, is what POST /v1/reload re-reads.
	BundlePath string

	// DefaultTenant is used when a request names no tenant. Empty means a
	// request without a tenant reaches only global policies.
	DefaultTenant string

	// TrustedProxyHops is how many proxies you operate in front of this server,
	// counted from the right of X-Forwarded-For.
	//
	// It defaults to 0, meaning the header is ignored and the transport-level
	// peer address is used. That default is the safe one: X-Forwarded-For is
	// attacker-controlled on its left, so trusting its first entry lets any
	// client claim any source address and walk through a CIDR allowlist. Set it
	// to the actual number of hops you control, never higher.
	TrustedProxyHops int

	// MaxBodyBytes caps a decode. Zero means DefaultMaxBodyBytes.
	MaxBodyBytes int64

	// Now supplies the clock, for tests and for replaying audited requests.
	Now func() time.Time

	// OnDecision, if set, is called after every decision. Use it for audit
	// logging. It runs on the request goroutine, so it must not block.
	OnDecision func(req tessaraop.Request, d tessaraop.Decision)

	// AllowExplainRevealValues permits /v1/explain to echo observed attribute
	// values instead of redacting them.
	//
	// Off by default. A trace shows what the request actually carried, which is
	// what makes it useful and also what makes it sensitive — and this endpoint
	// is reachable by anyone who can reach the PDP. Enable it for a local or
	// staging deployment; naming individual attributes in reveal_attributes is
	// the better answer in production, since that is an explicit and auditable
	// choice rather than a blanket one.
	AllowExplainRevealValues bool

	// ReloadToken, when set, is required in the X-Tessaraop-Token header on
	// /v1/reload.
	//
	// Reload changes what every subsequent request is authorized against, so it
	// is the one mutating endpoint here and the one worth protecting. Leaving it
	// empty is only appropriate when the listener is not reachable from outside
	// the pod; the server logs a warning at construction either way.
	ReloadToken string
}
    Config controls a Server.

type DecisionRequest struct {
	Tenant string `json:"tenant"`
	Scope  string `json:"scope"`

	Attributes map[string]string  `json:"attributes,omitempty"`
	Numeric    map[string]float64 `json:"numeric,omitempty"`
	IPs        map[string]string  `json:"ips,omitempty"`
}
    DecisionRequest is the native request envelope.

    Attributes are split by type on the wire exactly as they are in memory,
    rather than being inferred from JSON types. Inference would be ambiguous in
    the way that matters: a port arriving as "443" and one arriving as 443 would
    land in different maps, and the string one is invisible to every numeric
    operator — a rule that silently never fires. Making the caller choose the
    map makes the mistake impossible to express.

type DecisionResponse struct {
	Allowed     bool     `json:"allowed"`
	Effect      string   `json:"effect"`
	PolicyID    string   `json:"policy_id,omitempty"`
	RuleID      string   `json:"rule_id,omitempty"`
	Obligations []string `json:"obligations,omitempty"`

	RulesScanned    int  `json:"rules_scanned"`
	PoliciesScanned int  `json:"policies_scanned"`
	CacheHit        bool `json:"cache_hit"`

	// Generation identifies the policy set that produced this answer, so an
	// audit record can be tied back to what was installed at the time.
	Generation uint64 `json:"generation"`

	// Warnings reports attributes the registry declares under a different type
	// than the one they arrived in. Advisory, not fatal: unregistered names are a
	// customer's own vocabulary and must keep working.
	Warnings []string `json:"warnings,omitempty"`
}
    DecisionResponse is the native response envelope.

type ExplainRequest struct {
	DecisionRequest

	// RevealValues turns off redaction of observed attribute values.
	//
	// It is refused unless the server was started with
	// Config.AllowExplainRevealValues, because a trace echoes what the request
	// carried and this endpoint is reachable by whoever can reach the PDP. The
	// ingest layer works hard to keep credentials out of attributes; an
	// explanation must not undo that.
	RevealValues bool `json:"reveal_values,omitempty"`

	// RevealAttributes names individual attributes whose values may be shown
	// even while the rest stay redacted. Always permitted: naming an attribute
	// is an explicit, auditable choice, unlike revealing everything.
	RevealAttributes []string `json:"reveal_attributes,omitempty"`

	// IncludeOutOfScope reports policies the request could not reach, which is
	// what you want when the surprise is that a policy did *not* apply.
	IncludeOutOfScope bool `json:"include_out_of_scope,omitempty"`

	// MaxPolicies caps the trace size. Zero uses the default.
	MaxPolicies int `json:"max_policies,omitempty"`
}
    ExplainRequest is a decision request plus the knobs that control how much
    the trace reveals.

type Server struct {
	// Has unexported fields.
}
    Server is an http.Handler serving a PDP.

func New(cfg Config) (*Server, []string, error)
    New builds a server. It returns a warning string when the configuration is
    usable but has a footgun worth surfacing in a startup log.

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request)

```

---

## pkg/tessaraop/audit

Structured decision audit records.

```go
package audit // import "github.com/suga/tessaraop/pkg/tessaraop/audit"

Package audit records decisions for compliance, incident review and debugging.

# Why this is not just a log line

An authorization decision is a compliance artifact. "Who was allowed to do what,
when, and under which policy" is the question an auditor asks, and answering it
six months later requires that the record be structured, complete, and tied to
the exact policy set that produced it. A printf in a handler does not survive
that conversation.

So a Record carries the decision, the rule credited, the generation of the
policy set that was installed at the time, and a bounded, redacted view of the
request.

# Two things this refuses to do

**It does not log attribute values by default.** A request carries whatever the
integration put in it, and package ingest works hard to keep credentials out of
attributes — an audit sink that echoed them wholesale would undo that at the
worst possible place, since audit logs are retained for years and shipped to
third-party systems. Attribute *names* are recorded; values only for attributes
explicitly allowlisted.

**It does not block the request path.** Writes go through a bounded buffer and
a background goroutine. If the sink cannot keep up the buffer fills and records
are dropped, with the drop counted — because an authorization decision that
cannot be logged must still be *made*. Blocking a decision on a slow log shipper
turns an observability problem into an availability one.

That last choice has a consequence worth stating plainly: this sink is
lossy under pressure. If your compliance regime requires that no decision go
unrecorded, you need a durable queue, and this is the wrong component.

CONSTANTS

const DefaultBuffer = 4096
    DefaultBuffer bounds the queue.


TYPES

type JSONLines struct {
	// Has unexported fields.
}
    JSONLines writes one JSON object per line, which is what every log shipper
    already understands.

func NewJSONLines(w io.Writer) *JSONLines
    NewJSONLines returns a sink writing newline-delimited JSON to w.

func (j *JSONLines) Write(r Record) error
    Write implements Sink.

type Logger struct {
	// Has unexported fields.
}
    Logger turns decisions into records and hands them to a Sink without
    blocking the caller.

func New(sink Sink, opt Options) (*Logger, []string)
    New starts a logger. Close it to flush.

    It returns warnings for configurations that are legal but worth seeing in a
    startup log, in the same spirit as pdpserver.New.

func (l *Logger) Close(ctx context.Context) error
    Close stops the logger and waits for queued records to be written.

    It is safe to call more than once. Records submitted after Close are dropped
    silently rather than panicking on a closed channel, because shutdown races
    with in-flight requests by nature.

func (l *Logger) Record(req tessaraop.Request, d tessaraop.Decision)
    Record queues a decision. It never blocks.

    This is the signature pdpserver.Config.OnDecision expects, so wiring it up
    is one line.

func (l *Logger) RecordAt(req tessaraop.Request, d tessaraop.Decision, generation uint64)
    RecordAt is Record with the policy generation, which the caller knows and
    the decision does not carry.

func (l *Logger) Stats() Stats
    Stats returns a snapshot.

type Options struct {
	// RecordValues names attributes whose values may be written. Everything else
	// is recorded by name only.
	//
	// The allowlist is the whole design. Audit logs are retained for years and
	// shipped to systems outside the trust boundary of the service that produced
	// them, so "record everything and redact later" is not a posture that
	// survives contact with a real incident.
	RecordValues map[string]bool

	// RecordAllValues writes every attribute value. Intended for a local debug
	// session; it is a deliberate footgun and Logger warns when it is set.
	RecordAllValues bool

	// Buffer is how many records may be queued before writes are dropped. Zero
	// means DefaultBuffer.
	Buffer int

	// SampleAllowed records only every Nth allowed decision. Denials are always
	// recorded in full, because they are what an investigation starts from and
	// they are far rarer.
	//
	// Zero or one records everything.
	SampleAllowed int

	// Now supplies the clock, for tests.
	Now func() time.Time

	// OnError is called when the sink returns an error. It must not block. A nil
	// OnError discards the error, which is the right default: an audit write
	// failing must not take down the decision path.
	OnError func(error)
}
    Options configures a Logger.

type Record struct {
	Time time.Time `json:"time"`

	TenantID string `json:"tenant_id,omitempty"`
	Scope    string `json:"scope,omitempty"`

	Allowed     bool     `json:"allowed"`
	Effect      string   `json:"effect"`
	PolicyID    string   `json:"policy_id,omitempty"`
	RuleID      string   `json:"rule_id,omitempty"`
	Obligations []string `json:"obligations,omitempty"`

	// Generation identifies the policy set that produced this decision, so a
	// record can be tied back to exactly what was installed at the time. Without
	// it a six-month-old audit record cannot be reproduced.
	Generation uint64 `json:"generation"`

	// CacheHit reports that the decision was served from cache. Worth recording:
	// a cached decision was computed against the generation stored with the
	// cache entry, not necessarily the current one.
	CacheHit bool `json:"cache_hit,omitempty"`

	RulesScanned int `json:"rules_scanned,omitempty"`

	// Attributes names what the request carried. Values appear only for
	// allowlisted attributes; see Options.RecordValues.
	Attributes map[string]string `json:"attributes,omitempty"`
	// AttributeNames lists the attributes present but not recorded by value,
	// so an investigator knows what was available without seeing it.
	AttributeNames []string `json:"attribute_names,omitempty"`
}
    Record is one audited decision.

type Sink interface {
	Write(Record) error
}
    Sink consumes audit records. Implementations must be safe for concurrent
    use.

type SinkFunc func(Record) error
    SinkFunc adapts a function to Sink.

func (f SinkFunc) Write(r Record) error
    Write implements Sink.

type Stats struct {
	Seen    uint64 `json:"seen"`
	Written uint64 `json:"written"`
	Dropped uint64 `json:"dropped"`
	Failed  uint64 `json:"failed"`
}
    Stats reports what the logger has done. Dropped is the number worth alerting
    on: it means the sink could not keep up and decisions went unrecorded.

```

---

## internal/model

Core types, operator semantics, condition trees, both combining tiers.

```go
package model // import "github.com/suga/tessaraop/internal/model"

Package model defines the core ABAC/Zero-Trust data types shared by every
evaluator implementation. Every matching decision in the system routes through
Condition.Matches / ConditionExpr.Matches here, so the indexed fast path and the
naive reference oracle can never disagree on semantics.

The shape is three levels deep:

    Policy  — the unit of tenancy, sharding and distribution
      └─ Rule    — the unit that carries an Effect and Obligations
           └─ When: ConditionExpr — an AND/OR/NOT tree over Conditions

A Policy holds many Rules; a Rule holds one boolean expression over many
Conditions. That is the structure real security policy takes — one document
("production database access") containing several rules, each granting or
denying under its own compound predicate.

CONSTANTS

const GlobalTenant = "__global__"
    GlobalTenant holds platform-wide policies evaluated for every request
    regardless of the request's own tenant (blocklists, kill switches).

const SetDelimiter = ','
    SetDelimiter separates elements of a multi-valued string attribute. The
    registry documents this convention for every attribute that carries a set.

const TenantWideScope = ""
    TenantWideScope is the scope of policies applying across an entire tenant,
    evaluated alongside whichever scope a request names.


VARIABLES

var AllAlgorithms = []Algorithm{
	DenyOverrides, PermitOverrides, FirstApplicable,
	DenyUnlessPermit, PermitUnlessDeny, OnlyOneApplicable,
}
    AllAlgorithms lists every combining algorithm, for the linter and docs.

    The XACML "ordered-" variants are deliberately absent. They resolve ties
    by document order, and this engine's index yields candidates in whatever
    order the underlying sets enumerate — so honouring document order would
    mean sorting every candidate set and forfeiting the short-circuiting that
    order-independence buys. FirstApplicable covers the same intent with an
    explicit Priority, which is order-independent and therefore sound here.

var AllOperators = []Operator{
	OpEquals, OpNotEquals, OpIn, OpNotIn,
	OpContains, OpNotContains, OpPrefix, OpNotPrefix,
	OpSuffix, OpNotSuffix, OpRegex, OpNotRegex,
	OpDNSSuffix, OpNotDNSSuffix,
	OpHasAny, OpHasAll, OpHasNone,
	OpExists, OpNotExists,
	OpRange, OpNotRange, OpGreaterThan, OpGreaterEq,
	OpLessThan, OpLessEq, OpNumEquals, OpNumNotEq,
	OpNumIn, OpNumNotIn,
	OpCIDR, OpNotCIDR,
}
    AllOperators lists every operator the engine implements, in catalog order.
    The linter and the generated documentation both read it, so a new operator
    added to the const block above must be added here too.


FUNCTIONS

func ConsiderPolicy(p *Policy, req Request, positions []int, acc *Accumulator) int
    ConsiderPolicy resolves one policy's inner tier and feeds the result to an
    outer-tier accumulator. It is the seam the indexed engine drives, so the
    index layer never reimplements tier-one combination.

    positions names the rule indices the index selected as candidates.
    It returns how many rules reached exact validation.

func ForEachSetMember(value string, fn func(string) bool)
    ForEachSetMember calls fn for each element of a delimited multi-valued
    attribute, stopping early if fn returns false.

    It takes a callback rather than returning a slice because it runs on the
    evaluation path: splitting into a []string would allocate once per condition
    per request, and the whole hot path is otherwise allocation-free. Substrings
    share the value's backing array, so this allocates nothing.

    Surrounding whitespace is trimmed and empty elements are skipped, so "admin,
    editor" and "admin,editor" mean the same thing and a trailing comma is
    harmless.

func MatchDNSSuffix(host, suffix string) bool
    MatchDNSSuffix reports whether host equals suffix or is a subdomain of it.
    Matching is label-aligned, so "evilexample.com" does NOT match "example.com"
    — a plain strings.HasSuffix here would be a real security bug.


TYPES

type Accumulator struct {
	Algorithm Algorithm

	// UnionObligations collects obligations from every matching verdict carrying
	// the winning effect, rather than only from the one credited.
	//
	// It removes the attribution caveat that otherwise makes obligations depend
	// on which of several equally-valid matches the evaluator reached first, and
	// it is what XACML actually specifies. The cost is that it forfeits
	// short-circuiting: the accumulator must see every candidate to collect from
	// them, so DenyOverrides can no longer stop at the first Deny. Off by
	// default for that reason.
	UnionObligations bool

	// Has unexported fields.
}
    Accumulator collects matching verdicts during a scan and resolves them under
    the chosen Algorithm. Both tiers and both evaluators drive this same type,
    so combining semantics cannot drift between them.

    The zero value is usable after Reset, which is what lets the inner tier keep
    one on the stack per policy instead of allocating per request.

func NewAccumulator(alg Algorithm) *Accumulator
    NewAccumulator returns an accumulator for the given algorithm. Empty means
    DenyOverrides.

func (a *Accumulator) CanShortCircuit() bool
    CanShortCircuit reports whether the outcome is already decided, so the
    caller may stop scanning. Only DenyOverrides can short-circuit (on the first
    Deny) — the others must see every candidate.

func (a *Accumulator) Consider(v Verdict)
    Consider feeds one verdict that has already been confirmed to apply.

func (a *Accumulator) Reset(alg Algorithm)
    Reset clears the accumulator for reuse under alg. Empty alg means
    DenyOverrides. Reset preserves UnionObligations, so the inner tier inherits
    the outer tier's obligation semantics rather than silently diverging from
    it.

func (a *Accumulator) Resolve() Decision
    Resolve produces the final decision under the configured algorithm.

func (a *Accumulator) SetScanned(policies, rules int)
    SetScanned records how much reached exact validation.

func (a *Accumulator) Winner() (Verdict, bool)
    Winner returns the verdict the algorithm selects, and whether anything
    matched. The inner tier uses this directly to produce the policy's verdict.

type Algorithm string
    Algorithm selects how multiple matching units combine into one outcome.
    The same three algorithms serve both tiers: rules within a policy, and
    policies within a shard.

const (
	// DenyOverrides: any matching Deny wins; else any matching Allow wins;
	// else no match.
	//
	// This is the default and the only order-independent algorithm here, which
	// is exactly what makes indexing sound — the index yields candidates in
	// arbitrary order, and the result must not depend on that order. Every
	// other algorithm below requires an explicit ordering pass.
	DenyOverrides Algorithm = "deny-overrides"

	// PermitOverrides: any matching Allow wins; else any matching Deny; else no
	// match. Also order-independent. Used for opt-in grant models.
	PermitOverrides Algorithm = "permit-overrides"

	// FirstApplicable: the matching unit with the highest Priority wins, ties
	// broken by policy ID then rule ID for determinism. Order-dependent, so the
	// engine must see every candidate — strictly more expensive than
	// DenyOverrides. Needed for exception rules ("deny all except X").
	FirstApplicable Algorithm = "first-applicable"

	// DenyUnlessPermit: any matching Allow wins; everything else denies.
	//
	// It differs from PermitOverrides only in attribution. With no Allow but a
	// matching Deny, PermitOverrides credits that Deny while this credits
	// nothing, because XACML defines this algorithm as never producing an
	// Indeterminate or NotApplicable result — it always resolves to Permit or
	// Deny. The enforceable outcome is identical. Provided for conformance and
	// for policy sets migrated from an XACML engine.
	DenyUnlessPermit Algorithm = "deny-unless-permit"

	// PermitUnlessDeny: any matching Deny wins; everything else permits.
	//
	// This is the one algorithm here that grants by default. A request matching
	// nothing at all is ALLOWED, which inverts the fail-closed posture the rest
	// of this engine is built on. It exists because XACML defines it and some
	// migrated policy sets depend on it; it should be confined to a shard whose
	// contents are exhaustively known, never used as a corpus-wide default.
	PermitUnlessDeny Algorithm = "permit-unless-deny"

	// OnlyOneApplicable: exactly one unit may apply. If several do, the result is
	// Indeterminate, which this engine resolves as a deny.
	//
	// Unlike the algorithms above this one is genuinely distinct: it detects
	// ambiguity rather than resolving it. Use it where overlapping policies
	// indicate a configuration error that should fail loudly — a routing table
	// where two rules claim the same traffic, say — rather than being silently
	// arbitrated.
	OnlyOneApplicable Algorithm = "only-one-applicable"
)
type Condition struct {
	Attribute string
	Operator  Operator

	Values   []string       // string family
	Min, Max float64        // numeric family: range bounds and scalar comparand
	Numbers  []float64      // numeric set family (num_in, num_nin)
	Prefixes []netip.Prefix // network family

	// Has unexported fields.
}
    Condition is a single predicate over one request attribute.

    Absent-attribute semantics (fail closed): a condition whose attribute
    is not present on the request does NOT match — including negations.
    So `source_ip NOT IN 203.0.113.0/24` requires source_ip to be present AND
    outside the block. OpNotExists is the sole operator that matches on absence,
    by definition. The index layer mirrors this exactly.

func (c *Condition) Matches(req Request) bool
    Matches evaluates this single condition against a request. This is the
    ground truth for the entire engine: the naive evaluator reaches it through
    the condition tree, and the indexed evaluator reaches it in its final
    validation pass. The index is only ever a pre-filter over this function,
    never a replacement for it.

func (c *Condition) Prepare() error
    Prepare compiles this condition's regular expressions so evaluation needs no
    cache lookup. It is idempotent and reports the first pattern that fails to
    compile.

type ConditionError struct {
	Attribute string
	Operator  Operator
	Err       error
}
    ConditionError reports a condition that cannot be compiled or validated.

func (e *ConditionError) Error() string

func (e *ConditionError) Unwrap() error

type ConditionExpr struct {
	Kind ExprKind

	// Cond is the predicate when Kind is ExprLeaf.
	Cond Condition

	// Sub holds the children of And, Or and Not. Not has exactly one.
	Sub []*ConditionExpr
}
    ConditionExpr is a boolean expression over Conditions: the predicate a Rule
    fires on.

    v1 held a flat `[]Condition` that was implicitly AND-ed. That cannot express
    the shape most real security policy takes — "(role is admin OR role is
    security-admin) AND NOT department is contractor" — and forcing authors to
    expand it into a cross product of AND-only rules multiplies the corpus and
    makes the resulting policies unreviewable. So the predicate is a tree.

    The zero value is not meaningful; build trees with Cond, And, Or and Not.
    A nil *ConditionExpr matches everything, which is how a catch-all rule
    (default-deny backstop, blanket grant) is expressed.

func AllOf(conds ...Condition) *ConditionExpr
    AllOf is a convenience for the common flat case: every condition AND-ed.
    It is the direct translation of the pre-Rule `[]Condition` shape.

func And(sub ...*ConditionExpr) *ConditionExpr
    And returns the conjunction of its arguments. And() with no arguments
    matches everything, mirroring the empty-conjunction convention: a rule with
    nothing to check applies unconditionally.

func AnyOf(conds ...Condition) *ConditionExpr
    AnyOf is a convenience for a flat disjunction of conditions.

func Cond(c Condition) *ConditionExpr
    Cond wraps a single condition as a leaf node.

func Not(e *ConditionExpr) *ConditionExpr
    Not returns the negation of e.

func Or(sub ...*ConditionExpr) *ConditionExpr
    Or returns the disjunction of its arguments. Or() with no arguments matches
    nothing, so an empty disjunction cannot silently grant access.

func (e *ConditionExpr) ANDSpineLeaves(dst []Condition) []Condition
    ANDSpineLeaves appends every condition that is logically necessary for the
    whole tree to match, and returns the extended slice.

    This is the indexing boundary, and it is the one correctness rule in this
    package that is easy to get wrong. Only leaves reachable from the root by
    following *exclusively* And nodes qualify — call that the AND-spine. A leaf
    under an Or is not necessary (its sibling may satisfy the disjunction),
    and a leaf under a Not is required to be false rather than true. Indexing
    on either would let the pre-filter exclude a rule that actually matches,
    which is the one failure mode that turns a fast engine into a wrong one.

    Leaves off the spine simply contribute no filter and fall through to exact
    validation: over-inclusive, never under-inclusive, consistent with every
    other index in this codebase. A rule whose root is an Or therefore gets no
    index help at all and is validated on every request that reaches its shard —
    the cost of expressiveness, paid only by the rules that use it.

func (e *ConditionExpr) CountLeaves() int
    CountLeaves reports how many conditions the tree holds.

func (e *ConditionExpr) Depth() int
    Depth reports the height of the tree. The linter caps it, because an
    unbounded tree submitted by a tenant is a denial-of-service vector against
    every request that reaches its shard.

func (e *ConditionExpr) Matches(req Request) bool
    Matches evaluates the tree against a request. A nil expression matches.

    Evaluation short-circuits: And stops at the first false child, Or at the
    first true one. Since the index orders nothing about child order, authors
    control cost by putting cheap conditions first — a regex behind an equality
    check runs only when the equality passed.

func (e *ConditionExpr) Prepare() error
    Prepare compiles every regular expression in the tree, reporting the first
    failure. Callers that build policies programmatically should run it once at
    load time; index.BuildShard and the naive evaluator both do so on their own
    inputs, so evaluation never pays for compilation.

func (e *ConditionExpr) Walk(fn func(*ConditionExpr) error) error
    Walk calls fn for every node in the tree, parents before children. It stops
    and returns the first error fn reports.

type Decision struct {
	Allowed         bool
	Effect          Effect
	MatchedPolicyID string
	MatchedRuleID   string
	Obligations     []string
	PoliciesScanned int
	RulesScanned    int
	CacheHit        bool
}
    Decision is the result of evaluating a request against a policy set.

    RulesScanned and PoliciesScanned are the core instrumentation metrics: they
    count what reached exact validation. Naive always validates every in-scope
    rule; the indexed engine should reach a small fraction.

    MatchedPolicyID and MatchedRuleID name *a* rule that matched and carries
    the winning effect, not necessarily a canonical one. Under DenyOverrides
    and PermitOverrides several rules can match with the same effect,
    and the algorithms say nothing about which to credit — so the engine reports
    whichever it reached first and stops, since scanning the remainder to pick
    a canonical winner would forfeit short-circuiting for no change in the
    decision. FirstApplicable is the exception: it must examine every candidate
    anyway, and its priority-then-ID ordering makes the reported rule fully
    deterministic. Audit trails needing stable attribution should use it.

func Evaluate(policies []Policy, req Request, alg Algorithm) Decision
    Evaluate scans every policy in the slice, applying both tiers. This is the
    reference implementation used by the naive evaluator and by differential
    tests. It applies no tenant scoping — callers that need it filter first.

func EvaluatePolicyPositions(policies []Policy, positions []int, req Request, alg Algorithm) Decision
    EvaluatePolicyPositions validates only the policies at the given positions,
    indexing into the original slice rather than copying them into a new one.
    The copy version allocated proportionally to candidate-set size and showed
    up directly in benchmark allocs/op.

func EvaluateUnion(policies []Policy, req Request, alg Algorithm, unionObligations bool) Decision
    EvaluateUnion is Evaluate with explicit obligation union semantics.
    The naive evaluator and the indexed engine both route through this, so a
    differential test can exercise union mode on both sides.

func (d Decision) String() string

type Effect string
    Effect is the outcome a rule grants if its condition tree matches.

const (
	Allow Effect = "ALLOW"
	Deny  Effect = "DENY"
)
type Evaluator interface {
	Evaluate(req Request) Decision
}
    Evaluator is implemented by every evaluation strategy. Benchmarks and the
    differential test depend only on this interface.

type ExprKind uint8
    ExprKind tags a node in a condition tree.

const (
	ExprLeaf ExprKind = iota
	ExprAnd
	ExprOr
	ExprNot
)
func (k ExprKind) String() string

type Family uint8
    Family classifies an operator by which Request map it reads.

const (
	FamilyString Family = iota
	FamilyNumeric
	FamilyNetwork
	FamilyPresence
	FamilyUnknown
)
type Operator string
    Operator is the comparison a Condition applies to a request attribute.

    Operators fall into families, which matters because each family needs a
    different index structure and reads a different map on the Request:

        String   -> Request.Attributes — hash map, prefix table, suffix table, label trie
        Numeric  -> Request.Numeric    — interval table, numeric hash map
        Network  -> Request.IPs        — binary radix trie over address bits
        Presence -> any of the three   — plain participation bitsets

    Some operators are deliberately not indexable: substring and regular
    expression matching have no structure a pre-filter can exploit. Those still
    narrow the candidate set through attribute presence, then resolve in the
    exact validation pass. That is the same over-inclusive-never-under-inclusive
    contract every other index here honours.

const (
	OpEquals      Operator = "eq"        // Attributes[Attr] == Values[0]
	OpNotEquals   Operator = "ne"        // Attributes[Attr] != Values[0]
	OpIn          Operator = "in"        // Attributes[Attr] ∈ Values
	OpNotIn       Operator = "nin"       // Attributes[Attr] ∉ Values
	OpContains    Operator = "contains"  // any of Values is a substring
	OpNotContains Operator = "ncontains" // no Value is a substring
	OpPrefix      Operator = "prefix"    // starts with any of Values (byte-wise)
	OpNotPrefix   Operator = "nprefix"   // starts with none of Values
	OpSuffix      Operator = "suffix"    // ends with any of Values (byte-wise)
	OpNotSuffix   Operator = "nsuffix"   // ends with none of Values
	OpRegex       Operator = "regex"     // matches any pattern in Values
	OpNotRegex    Operator = "nregex"    // matches no pattern in Values

	// OpDNSSuffix is label-aligned, unlike OpSuffix. Use it for every host,
	// domain and SNI comparison: OpSuffix would accept evilacme.com for
	// acme.com, which is a live authorization-bypass class.
	OpDNSSuffix    Operator = "dnssuffix"  // host is, or is under, any domain in Values
	OpNotDNSSuffix Operator = "ndnssuffix" // host is under none of Values

	// -- Multi-valued set family --
	//
	// These read an attribute whose value is a comma-delimited *set* — the
	// convention the registry documents for subject.roles, subject.groups,
	// token.scopes and transport.tcp_flags — and test membership of whole
	// elements.
	//
	// They exist because OpContains is wrong for this and wrong in the dangerous
	// direction. A principal holding only "readwrite" satisfies
	// `subject.roles contains "read"`, because that is a substring test. For a
	// role check that is a privilege escalation. These operators split on the
	// delimiter and compare complete elements, so "read" matches "read" and
	// never "readwrite".
	OpHasAny  Operator = "has_any"  // the set shares at least one element with Values
	OpHasAll  Operator = "has_all"  // the set contains every element of Values
	OpHasNone Operator = "has_none" // the set shares no element with Values

	OpExists    Operator = "exists"  // the attribute is present
	OpNotExists Operator = "nexists" // the attribute is absent

	OpRange       Operator = "range"   // Min <= v <= Max
	OpNotRange    Operator = "nrange"  // v < Min or v > Max
	OpGreaterThan Operator = "gt"      // v > Min
	OpGreaterEq   Operator = "gte"     // v >= Min
	OpLessThan    Operator = "lt"      // v < Max
	OpLessEq      Operator = "lte"     // v <= Max
	OpNumEquals   Operator = "num_eq"  // v == Min
	OpNumNotEq    Operator = "num_ne"  // v != Min
	OpNumIn       Operator = "num_in"  // v ∈ Numbers
	OpNumNotIn    Operator = "num_nin" // v ∉ Numbers

	OpCIDR    Operator = "cidr"  // IPs[Attr] ∈ any prefix in Prefixes
	OpNotCIDR Operator = "ncidr" // IPs[Attr] ∉ every prefix in Prefixes
)
func (op Operator) Family() Family
    Family reports which Request map this operator reads. The attribute registry
    uses it to reject a policy that applies a numeric comparison to a string
    attribute — a mistake that would otherwise fail closed at runtime and look
    like a policy that simply never matches.

func (op Operator) Negated() bool
    Negated reports whether the operator succeeds on absence of a match rather
    than presence of one. The index layer needs this because a negated operator
    can only ever reject candidates, never enumerate them.

type Policy struct {
	ID       string
	TenantID string
	Scope    string

	// Priority orders this policy against others under FirstApplicable at the
	// cross-policy tier. Rule.Priority orders rules within this policy.
	Priority int

	// RuleAlgorithm combines this policy's matching rules into one verdict.
	// Empty means DenyOverrides.
	RuleAlgorithm Algorithm

	Rules []Rule
}
    Policy is a named collection of Rules sharing a tenant, a scope and a
    rule-combining algorithm.

    TenantID and Scope together form the shard key, and that pairing is what
    makes a multi-million policy corpus tractable: the working set per request
    is one shard, not the corpus.

    Scope subdivides a tenant, typically by resource type or application.
    It exists because tenant alone is not a fine enough partition — real corpora
    are heavily skewed, and a single large customer can hold a six-figure
    policy count that no amount of indexing makes fast on its own. Production
    systems partition the same way: Zanzibar by namespace, IAM by principal
    and resource, Envoy RBAC per listener. A policy with an empty Scope applies
    across its whole tenant.

func SimplePolicy(id, tenantID, scope string, effect Effect, priority int, conds []Condition, obligations ...string) Policy
    SimplePolicy builds a single-rule policy from a flat AND-ed condition list.

    It exists because that shape covers most real policies and all of the
    pre-Rule corpus, and asking every caller to spell out a one-element Rules
    slice wrapping an AllOf tree obscures what the policy says. Onboarding
    integrations and tests use it heavily.

func (p *Policy) Prepare() error
    Prepare compiles every regular expression in every rule, reporting the first
    failure. Index construction calls it, so evaluation never compiles.

func (p *Policy) Resolve(req Request) (Verdict, bool, int)
    Resolve applies every rule in this policy and combines the matches under
    the policy's RuleAlgorithm. This is tier one of the two-tier evaluation:
    it turns a policy into at most one Verdict.

    It reports the verdict, whether any rule matched at all, and how many rules
    reached exact validation.

func (p *Policy) ResolveAt(req Request, positions []int) (Verdict, bool, int)
    ResolveAt is Resolve restricted to the rule positions the index produced.
    Positions outside the rule slice are ignored rather than panicking, so an
    index that has drifted from its policies degrades to under-selective instead
    of crashing the decision path.

func (p *Policy) ResolveAtUnion(req Request, positions []int, unionObligations bool) (Verdict, bool, int)
    ResolveAtUnion is ResolveAt with explicit obligation union semantics.

func (p *Policy) ResolveUnion(req Request, unionObligations bool) (Verdict, bool, int)
    ResolveUnion is Resolve with explicit control over obligation union
    semantics, so the inner tier applies the same rule the outer one was
    configured with.

func (p *Policy) RuleCount() int
    RuleCount reports how many rules this policy holds. The index universe is
    the sum of this across a shard, since a rule — not a policy — is the atomic
    indexed unit.

type Request struct {
	TenantID   string
	Scope      string
	Attributes map[string]string
	Numeric    map[string]float64
	IPs        map[string]netip.Addr
}
    Request is a single access check. Attributes are split by type so the hot
    path never parses or casts: string attributes, numeric attributes and IP
    attributes each land in the map their operators read directly.

    The engine consumes named, already-parsed attributes and never decodes raw
    packets or raw HTTP bytes itself. Package ingest builds a Request from a
    net.Conn, an *http.Request or a *tls.ConnectionState using the standard
    library's audited parsers — a hand-rolled TCP/IP or HTTP decoder inside an
    authorization hot path is exactly where parser-differential bypasses live.

func (r Request) Has(name string) bool
    Has reports whether the request carries the named attribute in any of its
    three typed maps.

func (r Request) InScope(p *Policy) bool
    InScope reports whether a policy is reachable by this request:
    it must belong to the global tenant, or to the request's tenant at either
    tenant-wide scope or the request's own scope.

type Rule struct {
	ID       string
	Effect   Effect
	Priority int // higher wins under FirstApplicable; ignored by the overrides algorithms

	When *ConditionExpr

	Obligations []string // e.g. require_mfa, audit_log — carried into the Decision
}
    Rule is the unit that carries an Effect: if When matches, Effect applies and
    Obligations attach to the decision.

    A nil When matches everything, which is how a catch-all rule is expressed —
    the default-deny backstop at the bottom of a policy, or a blanket grant.

func NewRule(id string, effect Effect, when *ConditionExpr, obligations ...string) Rule
    NewRule is a convenience constructor for the common case.

type Verdict struct {
	PolicyID    string
	RuleID      string
	Effect      Effect
	Priority    int
	Obligations []string
}
    Verdict is one resolved outcome, produced by either tier. The inner tier
    emits a Verdict per matching rule; the outer tier emits one per matching
    policy. Carrying both IDs is what makes attribution correct: the rule
    that actually fired is threaded through from the moment it matched, never
    reconstructed afterwards by scanning for some rule with the winning effect —
    two same-effect rules in one policy would otherwise be misattributed.

```

---

## internal/attr

The L3/L4/L7 attribute registry.

```go
package attr // import "github.com/suga/tessaraop/internal/attr"

Package attr is the canonical registry of attributes a request can carry.

The engine evaluates named, already-typed attributes; it never decodes raw
packets or raw HTTP bytes. This package is the contract between the two halves
of that split: an ingestion adapter promises to populate these names with these
types, and a policy author promises to reference only these names. Package
ingest implements the adapter side using the standard library's audited parsers.

Having the contract be data rather than convention buys three things a product
needs. A policy that compares a numeric attribute with a string operator is
rejected at load time instead of failing closed at runtime and looking like
a rule that simply never fires. A customer onboarding against TessaraOP can
be handed the list of attributes to supply rather than reading the evaluator.
And the operator surface for each attribute is documented in one place that
cannot drift from the code, since the linter reads it.

# Naming

Names are dotted and namespaced by protocol layer or by subject area:

    network.*    layer 3, IP header
    transport.*  layer 4, TCP/UDP/ICMP header
    conn.*       connection state and volumetric counters
    geo.*        geographic resolution of an address
    threat.*     threat-intelligence enrichment
    iface.*      ingress and egress interface
    http.*       layer 7, HTTP request and response structure
    payload.*    decoded body content and signature results
    tls.*        TLS handshake and client certificate metadata
    subject.*    the authenticated principal
    token.*      bearer token / JWT claim validation results
    session.*    server-side session state
    api.*        API key presence and identity
    bot.*        bot-detection and challenge outcome
    graphql.*    GraphQL operation shape
    ws.*         WebSocket upgrade attempts
    resource.*   the object being acted on
    action       the operation requested
    time.*       evaluation-time clock attributes

Four namespaces are open-ended, because their key space belongs to the
customer's traffic rather than to this registry: http.header.*, http.query.*,
http.cookie.* and subject.claim.*.

CONSTANTS

const (
	SourceIP     = "network.source_ip"
	DestIP       = "network.dest_ip"
	IPProtocol   = "network.protocol"
	SourcePort   = "transport.source_port"
	DestPort     = "transport.dest_port"
	TCPFlags     = "transport.tcp_flags"
	ConnState    = "conn.state"
	GeoCountry   = "geo.country"
	ThreatRep    = "threat.ip_reputation"
	ProxyType    = "threat.proxy_type"
	ASN          = "threat.asn"
	HTTPMethod   = "http.method"
	HTTPPath     = "http.path"
	HTTPHost     = "http.host"
	HTTPQuery    = "http.query"
	UserAgent    = "http.user_agent"
	ContentType  = "http.content_type"
	ContentLen   = "http.content_length"
	HTTPStatus   = "http.status"
	HTTPVersion  = "http.version"
	PayloadBody  = "payload.body"
	FileExt      = "payload.file_ext"
	TLSVersion   = "tls.version"
	TLSVersionNo = "tls.version_num"
	CipherSuite  = "tls.cipher_suite"
	SNI          = "tls.sni"
	SubjectID    = "subject.id"
	SubjectRole  = "subject.role"
	MFAVerified  = "subject.mfa_verified"
	RiskScore    = "subject.risk_score"
	TokenValid   = "token.valid"
	TokenScopes  = "token.scopes"
	ResourceType = "resource.type"
	ResourcePath = "resource.path"
	Sensitivity  = "resource.sensitivity"
	Action       = "action"
	TimeHour     = "time.hour"

	// HeaderPrefix and friends build names in the open-ended namespaces.
	HeaderPrefix = "http.header."
	QueryPrefix  = "http.query."
	CookiePrefix = "http.cookie."
	ClaimPrefix  = "subject.claim."
)
    Well-known attribute names, so Go callers get a compile-time check rather
    than discovering a typo as a rule that silently never matches. The registry
    covers far more names than this; these are the ones integrations touch most.


VARIABLES

var Catalog = []Attribute{

	ip("network.source_ip", LayerNetwork, "Address originating the packet."),
	ip("network.dest_ip", LayerNetwork, "Address receiving the packet."),
	n("network.ip_version", LayerNetwork, "4 or 6."),
	n("network.protocol", LayerNetwork, "IP protocol number: 1 ICMP, 2 IGMP, 6 TCP, 17 UDP, 47 GRE, 50 ESP."),
	s("network.protocol_name", LayerNetwork, "Lowercased protocol name, for set membership instead of numbers."),
	n("network.ttl", LayerNetwork, "TTL / hop limit. Low or unusual values indicate traceroute and OS fingerprinting."),
	s("network.ip_options", LayerNetwork, "Comma-joined IP option names present, e.g. lsrr,ssrr,rr. Empty when none."),
	s("network.fragment_flags", LayerNetwork, "Comma-joined fragmentation flags set: df, mf."),
	n("network.fragment_offset", LayerNetwork, "Fragment offset in 8-byte units. Non-zero on a non-first fragment."),
	n("network.dscp", LayerNetwork, "DSCP code point, 0-63."),
	n("network.tos", LayerNetwork, "Legacy ToS byte."),

	n("transport.source_port", LayerTransport, "Originating port, typically ephemeral."),
	n("transport.dest_port", LayerTransport, "Target service port."),
	s("transport.tcp_flags", LayerTransport, "Comma-joined flags set, ascending: ack,cwr,ece,fin,psh,rst,syn,urg."),
	n("transport.tcp_seq", LayerTransport, "TCP sequence number."),
	n("transport.tcp_window", LayerTransport, "TCP receive window size."),
	n("transport.icmp_type", LayerTransport, "ICMP type, e.g. 8 echo request, 3 destination unreachable."),
	n("transport.icmp_code", LayerTransport, "ICMP code within the type."),

	s("conn.state", LayerConn, "Firewall state table verdict: new, established, related, invalid."),
	n("conn.rate_per_sec", LayerConn, "New connections per second from this source."),
	n("conn.concurrent", LayerConn, "Currently open connections from this source."),
	n("conn.packets_per_sec", LayerConn, "Packets per second on this flow or source."),
	n("conn.bytes_per_sec", LayerConn, "Bytes per second on this flow or source."),
	n("conn.idle_seconds", LayerConn, "Seconds this connection has been idle."),
	n("conn.duration_seconds", LayerConn, "Seconds since the connection opened."),

	s("geo.country", LayerInfra, "ISO 3166-1 alpha-2 country code, uppercase."),
	s("geo.continent", LayerInfra, "Two-letter continent code."),
	s("geo.city", LayerInfra, "Resolved city name."),
	n("threat.ip_reputation", LayerInfra, "Reputation score, 0 clean to 100 known-malicious."),
	s("threat.proxy_type", LayerInfra, "Anonymizer classification: none, tor, vpn, proxy, hosting, relay."),
	n("threat.asn", LayerInfra, "Autonomous system number of the source address."),
	s("threat.as_org", LayerInfra, "Autonomous system organisation name."),
	s("threat.categories", LayerInfra, "Comma-joined feed categories, e.g. botnet,scanner,spam."),
	s("iface.inbound", LayerInfra, "Ingress interface, e.g. eth0, wan1, vlan10."),
	s("iface.outbound", LayerInfra, "Egress interface."),

	s("http.method", LayerHTTP, "Uppercase verb: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, TRACE, CONNECT."),
	s("http.path", LayerHTTP, "Decoded request path, no query string. Normalize before populating."),
	s("http.raw_path", LayerHTTP, "Path exactly as received, before normalization. Compare the two to detect traversal."),
	s("http.query", LayerHTTP, "Raw query string, without the leading question mark."),
	s("http.host", LayerHTTP, "Host header, lowercased, port stripped."),
	s("http.version", LayerHTTP, "Protocol version string: HTTP/1.0, HTTP/1.1, HTTP/2, HTTP/3."),
	s("http.user_agent", LayerHTTP, "User-Agent header verbatim."),
	s("http.referer", LayerHTTP, "Referer header verbatim."),
	s("http.content_type", LayerHTTP, "Content-Type media type, parameters stripped and lowercased."),
	n("http.content_length", LayerHTTP, "Declared or observed body length in bytes."),
	s("http.authorization_scheme", LayerHTTP, "Lowercased auth scheme: bearer, basic, negotiate."),
	s("http.multipart_boundary", LayerHTTP, "Multipart boundary token, for structural inspection of uploads."),
	n("http.status", LayerHTTP, "Downstream response status. Response-phase rules only."),
	n("http.header_count", LayerHTTP, "Number of headers received."),
	n("http.uri_length", LayerHTTP, "Length of the full request URI in bytes."),
	dyn("http.header.", KindString, LayerHTTP, "Any request header by lowercased name, e.g. http.header.x-forwarded-for."),
	dyn("http.query.", KindString, LayerHTTP, "Any query parameter by name, e.g. http.query.id. First value wins."),
	dyn("http.cookie.", KindString, LayerHTTP, "A cookie by name, e.g. http.cookie.locale. The ingest adapter populates only cookies an integrator allowlists, since cookie values are frequently credentials."),

	s("payload.body", LayerPayload, "Decoded body, for regex and DLP scanning. Populate only when inspection is enabled."),
	s("payload.file_name", LayerPayload, "Uploaded file name as declared."),
	s("payload.file_ext", LayerPayload, "Lowercased extension including the dot, e.g. .exe, .php."),
	s("payload.file_magic", LayerPayload, "Leading body bytes as lowercase hex, for true-type detection."),
	s("payload.declared_mime", LayerPayload, "MIME type the client claimed."),
	s("payload.detected_mime", LayerPayload, "MIME type sniffed from content. Disagreement with declared_mime is the signal."),
	s("payload.schema_valid", LayerPayload, "\"true\" or \"false\": JSON/XML body validated against the endpoint schema."),
	s("payload.schema_errors", LayerPayload, "Comma-joined schema violation names."),
	n("payload.dlp_matches", LayerPayload, "Count of DLP pattern hits in the inspected content."),
	s("payload.dlp_categories", LayerPayload, "Comma-joined DLP categories hit, e.g. pan,ssn,api_key."),
	n("payload.entropy", LayerPayload, "Shannon entropy of the body, for packed or encrypted payload detection."),

	s("tls.version", LayerTLS, "Negotiated version string: SSLv3, TLS1.0, TLS1.1, TLS1.2, TLS1.3."),
	n("tls.version_num", LayerTLS, "Negotiated version on a monotonic scale: SSLv3 -> 3, TLS 1.0-1.3 -> 10, 11, 12, 13, unknown -> 0. Ordered by age so a floor like >=12 rejects everything older."),
	s("tls.cipher_suite", LayerTLS, "IANA cipher suite name, e.g. TLS_AES_128_GCM_SHA256."),
	s("tls.sni", LayerTLS, "Server Name Indication from the handshake, lowercased."),
	s("tls.alpn", LayerTLS, "Negotiated ALPN protocol, e.g. h2, http/1.1."),
	s("tls.client_cert_cn", LayerTLS, "Client certificate subject common name."),
	s("tls.client_cert_issuer", LayerTLS, "Client certificate issuer distinguished name."),
	s("tls.client_cert_serial", LayerTLS, "Client certificate serial number."),
	s("tls.client_cert_verified", LayerTLS, "\"true\" or \"false\": chain verified against the trusted CA set."),
	s("tls.client_cert_revoked", LayerTLS, "\"true\", \"false\" or \"unknown\" from CRL/OCSP."),
	n("tls.client_cert_expires_in_days", LayerTLS, "Days until the client certificate expires; negative when already expired."),
	s("tls.ja3", LayerTLS, "JA3 client hello fingerprint, for stack identification."),

	s("subject.id", LayerIdentity, "Stable principal identifier."),
	s("subject.type", LayerIdentity, "Principal class: user, service, device."),
	s("subject.role", LayerIdentity, "Primary role."),
	s("subject.roles", LayerIdentity, "Comma-joined roles. Carries the transitive closure when a role hierarchy is configured, so it is a superset of subject.role. Match with has_any / has_all / has_none, never contains."),
	s("subject.department", LayerIdentity, "Organisational unit."),
	s("subject.groups", LayerIdentity, "Comma-joined group memberships, transitively closed when a group hierarchy is configured. Match with has_any / has_all / has_none, never contains."),
	s("subject.mfa_verified", LayerIdentity, "\"true\" or \"false\"."),
	s("subject.device_managed", LayerIdentity, "\"true\" or \"false\": device is enrolled and compliant."),
	n("subject.risk_score", LayerIdentity, "Continuous risk assessment, 0 to 100."),
	n("subject.auth_age_seconds", LayerIdentity, "Seconds since the principal last authenticated."),
	s("token.valid", LayerIdentity, "\"true\" or \"false\": signature, expiry and audience all checked."),
	s("token.signature_valid", LayerIdentity, "\"true\" or \"false\": cryptographic signature alone."),
	s("token.algorithm", LayerIdentity, "JWS algorithm from the header, e.g. RS256. Reject \"none\"."),
	s("token.issuer", LayerIdentity, "iss claim."),
	s("token.subject", LayerIdentity, "sub claim."),
	s("token.audience", LayerIdentity, "Comma-joined aud claim."),
	s("token.scopes", LayerIdentity, "Comma-joined scope or scp claim."),
	n("token.expires_in_seconds", LayerIdentity, "Seconds until exp; negative when already expired."),
	dyn("subject.claim.", KindString, LayerIdentity, "Any additional token claim by name, e.g. subject.claim.tenant."),
	s("session.id", LayerIdentity, "Server-side session identifier."),
	s("session.valid", LayerIdentity, "\"true\" or \"false\": session found and active in the backing store."),
	n("session.age_seconds", LayerIdentity, "Seconds since the session was created."),
	s("api.key_present", LayerIdentity, "\"true\" or \"false\"."),
	s("api.key_id", LayerIdentity, "Identifier of the presented API key. Never the key itself."),
	s("bot.challenge_passed", LayerIdentity, "\"true\" or \"false\": CAPTCHA or silent browser challenge cleared."),
	n("bot.score", LayerIdentity, "Automation likelihood, 0 human to 100 bot."),

	s("resource.id", LayerResource, "Identifier of the object acted on."),
	s("resource.type", LayerResource, "Object class, e.g. document, bucket, endpoint."),
	s("resource.domain", LayerResource, "Fully qualified host of the resource. Use dnssuffix, never suffix."),
	s("resource.path", LayerResource, "Hierarchical path of the resource."),
	s("resource.sensitivity", LayerResource, "Classification: low, medium, high, critical."),
	s("resource.owner", LayerResource, "Principal owning the resource, for relationship checks."),
	s("resource.ancestors", LayerResource, "Comma-joined containment ancestors of the resource, closest first, including the resource itself. Match with has_any so a policy scoped to a folder or project covers everything beneath it."),
	s("action", LayerResource, "Operation requested, e.g. read, write, delete, admin."),
	n("graphql.depth", LayerResource, "Maximum nesting depth of the incoming query."),
	n("graphql.complexity", LayerResource, "Computed cost score of the incoming query."),
	s("graphql.operation", LayerResource, "Named GraphQL operation."),
	s("ws.upgrade_requested", LayerResource, "\"true\" or \"false\": the request asks to become a WebSocket."),
	s("ws.protocol", LayerResource, "Requested WebSocket subprotocol."),
	n("time.hour", LayerResource, "Hour of day in the evaluating zone, 0 to 24 with a fractional part."),
	n("time.day_of_week", LayerResource, "0 Sunday through 6 Saturday."),
	n("time.unix", LayerResource, "Evaluation timestamp in Unix seconds."),
}
    Catalog is every registered attribute, in layer order.

    Several protocol fields are registered twice under different types, because
    policies ask two different questions of them. tls.version is a string for
    exact-set membership ("reject SSLv3, TLS1.0, TLS1.1") while tls.version_num
    is numeric for a floor ("require at least 1.2") — expressing the floor as
    a string set means editing every policy when a new version ships. The same
    reasoning applies to network.protocol / protocol_name.


FUNCTIONS

func Claim(name string) string
    Claim returns the attribute name for a token claim.

func Cookie(name string) string
    Cookie returns the attribute name for a cookie.

func Header(name string) string
    Header returns the attribute name for an HTTP request header. The name is
    lowercased, matching what the ingest adapter populates.

func Names() []string
    Names returns every non-dynamic attribute name, sorted.

func QueryParam(name string) string
    QueryParam returns the attribute name for a query parameter.


TYPES

type Attribute struct {
	Name  string
	Kind  Kind
	Layer Layer
	Doc   string

	// Dynamic marks an open-ended namespace rather than a single attribute.
	// Name then ends in a dot and matches any attribute under it.
	Dynamic bool
}
    Attribute is one registry entry.

func ByLayer(l Layer) []Attribute
    ByLayer returns every attribute in a layer, in catalog order.

func Lookup(name string) (Attribute, bool)
    Lookup resolves an attribute name, matching exact entries first and then
    open-ended namespaces by prefix.

func (a Attribute) Accepts(op model.Operator) bool
    Accepts reports whether an operator can be applied to this attribute's type.
    Presence operators apply to every kind; the rest must match the family.

func (a Attribute) Operators() []model.Operator
    Operators lists every operator valid on this attribute, for documentation
    and for authoring tools that offer completions.

type Kind uint8
    Kind is the value type an attribute carries, and therefore which map on
    model.Request holds it.

const (
	KindString  Kind = iota // model.Request.Attributes
	KindNumeric             // model.Request.Numeric
	KindIP                  // model.Request.IPs
)
func KindFor(name string) (Kind, bool)
    KindFor reports the registered type of an attribute.

func (k Kind) String() string

type Layer uint8
    Layer groups attributes for documentation and for the onboarding checklist
    an integrator works through.

const (
	LayerNetwork   Layer = iota // L3
	LayerTransport              // L4
	LayerConn                   // connection state, rate and volume
	LayerInfra                  // geo, threat intel, interfaces
	LayerHTTP                   // L7 structure
	LayerPayload                // decoded content
	LayerTLS                    // handshake and certificates
	LayerIdentity               // principal, token, session
	LayerResource               // resource, action, time
)
func (l Layer) String() string

```

---

## internal/explain

Per-condition answers to why a decision came out as it did.

```go
package explain // import "github.com/suga/tessaraop/internal/explain"

Package explain answers "why?" about a decision.

# Why this is a separate path, not a flag on Evaluate

Evaluate is allocation-free and measured in microseconds. Threading a trace
through it would wreck both properties for every request, in order to serve
the rare one where somebody is asking a question. So Explain is a deliberately
slower second path that trades speed for detail.

That choice falls out well, because the index actively works against
explanation. A rule pruned by the pre-filter never reached validation, so there
is no natural place to record why it did not match — the filter only knows the
rule was excluded, not which condition would have failed. Explain therefore
bypasses the index entirely and evaluates every in-scope rule directly, which is
what package naive already does.

# Two things that must be true

First, **the explanation must agree with the decision it explains.** An
explanation that contradicts Evaluate is worse than none, because it will be
believed. Explain returns the decision it computed, and a differential test
asserts it matches Evaluate on the same input.

Second, **tracing must not short-circuit.** And stops at the first false child
and Or at the first true one, which is right for evaluation and wrong for
explanation: an author wants every failing condition, not just the one that
happened to be checked first. So the traversal here evaluates every node.

# Attribute values in traces

A trace shows what the request actually carried, which is what makes it useful
and also what makes it sensitive. Package ingest works hard to keep credentials
out of attributes; an explanation must not undo that by echoing values into a
log or an API response. Options.Redact controls it, and the default redacts.

CONSTANTS

const DefaultMaxPolicies = 200
    DefaultMaxPolicies bounds a trace.

const Redacted = "<redacted>"
    Redacted is what a hidden attribute value is replaced with.


TYPES

type AttributeCount struct {
	Attribute string `json:"attribute"`
	Failures  int    `json:"failures"`
	// Absent counts the failures caused by the request not carrying the
	// attribute at all, as opposed to carrying a value that did not satisfy the
	// condition. A high Absent count is an integration bug, not a policy one.
	Absent int `json:"absent"`
}
    AttributeCount is how often one attribute defeated a condition.

type Explanation struct {
	// Decision is what the engine concluded. It is computed by this package on
	// the same inputs, and a differential test asserts it matches Evaluate.
	Decision model.Decision `json:"decision"`

	// Algorithm is the shard-level combining algorithm applied.
	Algorithm string `json:"algorithm"`

	// Summary is a one-line human answer to "why?".
	Summary string `json:"summary"`

	// Policies are the traces, in corpus order.
	Policies []PolicyTrace `json:"policies"`

	// Truncated reports that MaxPolicies cut the trace short.
	Truncated bool `json:"truncated,omitempty"`

	// Counts, which hold even when the trace was truncated.
	PoliciesInScope int `json:"policies_in_scope"`
	RulesEvaluated  int `json:"rules_evaluated"`
	RulesMatched    int `json:"rules_matched"`
}
    Explanation is the full account of one decision.

func Explain(policies []model.Policy, req model.Request, alg model.Algorithm, opt Options) *Explanation
    Explain evaluates the policies against the request and reports why the
    result came out as it did.

    Policies are the full corpus; scoping is applied here exactly as the engine
    applies it, so an out-of-scope policy is reported as such rather than
    silently omitted.

func (ex *Explanation) UnmatchedAttributes() []AttributeCount
    UnmatchedAttributes reports the attributes that most often defeated a rule,
    most frequent first.

    This is the aggregate view an integrator wants during onboarding: a policy
    set that denies everything usually does so because one attribute is never
    being supplied, and that shows up here immediately rather than by reading
    traces one at a time.

type LeafTrace struct {
	Attribute string `json:"attribute"`
	Operator  string `json:"operator"`
	Matched   bool   `json:"matched"`

	// Present reports whether the request carried the attribute at all. This is
	// the single most useful field in a trace: the engine fails closed on absent
	// attributes, so "not present" explains far more denials than a value
	// mismatch does.
	Present bool `json:"present"`

	// Actual is what the request carried, redacted unless allowed.
	Actual string `json:"actual,omitempty"`
	// Expected is what the condition wanted. Never redacted — it comes from the
	// policy, which the reader is entitled to see.
	Expected string `json:"expected,omitempty"`

	// Why is the reason in words.
	Why string `json:"why"`

	// Indexable reports whether this condition sits on the rule's AND-spine and
	// can therefore contribute an index filter. Conditions under an Or or a Not
	// cannot, which is a performance property worth surfacing to a policy author
	// who is wondering why their shard is slow.
	Indexable bool `json:"indexable"`
}
    LeafTrace is one condition's evaluation against the request.

type NodeTrace struct {
	Kind    string       `json:"kind"` // leaf, and, or, not
	Matched bool         `json:"matched"`
	Leaf    *LeafTrace   `json:"leaf,omitempty"`
	Sub     []*NodeTrace `json:"sub,omitempty"`
}
    NodeTrace is one node of an evaluated condition tree.

type Options struct {
	// Redact replaces observed attribute values with a placeholder. On by
	// default via DefaultOptions, because an explanation is usually going
	// somewhere less trusted than the evaluator: a log, an API response, a
	// support ticket.
	//
	// Turning it off is reasonable for a local CLI session against a test
	// corpus, and rarely reasonable in production.
	Redact bool

	// RedactExcept names attributes whose values are safe to show even when
	// Redact is on — a role, an action, a country. Without it a redacted trace
	// is often too vague to act on.
	RedactExcept map[string]bool

	// IncludeNonMatching includes rules that did not match. On by default: "why
	// was I denied" is usually answered by a rule that *nearly* matched, and
	// omitting non-matching rules omits the answer.
	IncludeNonMatching bool

	// IncludeOutOfScope includes policies the request could not reach at all.
	// Off by default — on a large corpus that is most of it — but useful when
	// the surprise is that a policy did *not* apply.
	IncludeOutOfScope bool

	// MaxPolicies caps how many policies appear in the trace. Zero means
	// DefaultMaxPolicies. A trace over a whale shard would otherwise be
	// unreadable and expensive to serialize.
	MaxPolicies int
}
    Options controls how much an explanation reveals and how much work it does.

func DefaultOptions() Options
    DefaultOptions is the safe starting point: redacted, non-matching rules
    included, out-of-scope policies omitted.

type PolicyTrace struct {
	PolicyID string `json:"policy_id"`
	TenantID string `json:"tenant_id,omitempty"`
	Scope    string `json:"scope,omitempty"`
	Priority int    `json:"priority,omitempty"`

	// InScope reports whether the request could reach this policy at all.
	InScope bool `json:"in_scope"`
	// OutOfScopeReason explains a false InScope in words.
	OutOfScopeReason string `json:"out_of_scope_reason,omitempty"`

	// RuleAlgorithm combines this policy's own rules.
	RuleAlgorithm string `json:"rule_algorithm,omitempty"`

	Rules []RuleTrace `json:"rules,omitempty"`

	// Matched reports whether any rule matched, and Verdict is what the policy
	// resolved to if so.
	Matched bool         `json:"matched"`
	Verdict *VerdictInfo `json:"verdict,omitempty"`

	// Decisive marks the policy that produced the final decision.
	Decisive bool `json:"decisive,omitempty"`
}
    PolicyTrace is one policy's contribution.

type RuleTrace struct {
	RuleID   string `json:"rule_id"`
	Effect   string `json:"effect"`
	Priority int    `json:"priority,omitempty"`
	Matched  bool   `json:"matched"`

	// Why summarizes, in one line, what decided this rule.
	Why string `json:"why"`

	// Condition is the evaluated condition tree. Nil for a catch-all rule.
	Condition *NodeTrace `json:"condition,omitempty"`
}
    RuleTrace is one rule's evaluation.

type VerdictInfo struct {
	RuleID      string   `json:"rule_id"`
	Effect      string   `json:"effect"`
	Obligations []string `json:"obligations,omitempty"`
}
    VerdictInfo is a policy's resolved outcome.

```

---

## internal/hierarchy

Role, group and resource membership DAGs with transitive closure.

```go
package hierarchy // import "github.com/suga/tessaraop/internal/hierarchy"

Package hierarchy resolves transitive membership over a directed acyclic graph:
role inheritance, group nesting, and resource containment.

# Why this is not part of the engine

It would be natural to add a "role inherits" operator that walked a graph
during evaluation. That is the wrong place for it, for the same reason package
ingest does no I/O: the evaluation path is allocation-free and measured in
microseconds, and a traversal inside it would be neither.

So the closure is computed here, once, and handed to the engine as an ordinary
attribute. A principal with role "admin" arrives carrying subject.roles =
"admin,editor,viewer", and an existing indexed operator (has_any) answers the
question. The engine needs no new concept, the index still prunes, and the hot
path is untouched.

# Why it is a DAG and not a tree

Real role models are not trees. "on-call engineer" inherits from both "engineer"
and "incident responder"; a resource belongs to a folder and a project. Multiple
parents are the normal case, so this is a DAG, and the closure of a node is the
union over all its ancestors.

# Immutable after Freeze

Freeze detects cycles and precomputes every closure, so a request-time lookup
is one map read. That mirrors how index shards work: pay at build time, read at
request time. A Graph must not be mutated after Freeze, and Add reports an error
if it is.

VARIABLES

var ErrCycle = errors.New("hierarchy: cycle")
    ErrCycle is returned by Freeze when the graph is not acyclic.


FUNCTIONS

func Join(elems []string) string
    Join renders elements in the delimited form the engine's set operators read.


TYPES

type Graph struct {
	// Has unexported fields.
}
    Graph is a membership DAG: each node names its immediate parents.

    "Parent" means "is subsumed by". If admin inherits editor's permissions,
    admin is the child and editor is the parent, and the closure of admin
    contains editor. Getting this direction backwards is the easiest mistake to
    make here, so the tests state it explicitly.

func FromMap(m map[string][]string) (*Graph, error)
    FromMap builds and freezes a graph from a child -> parents mapping, which is
    the shape a bundle or a configuration file naturally carries.

func New() *Graph
    New returns an empty, unfrozen graph.

func (g *Graph) Add(child string, parents ...string) *Graph
    Add records that child is subsumed by each of parents. It may be called
    repeatedly for the same child; parents accumulate.

    Adding after Freeze is a programming error rather than a runtime condition,
    so it panics: a graph that changed under a running engine would silently
    produce closures inconsistent with the ones already computed.

func (g *Graph) Closure(node string) []string
    Closure returns the node together with all of its transitive parents,
    sorted.

    An unknown node yields just itself. That is deliberate: a principal carrying
    a role the graph has never heard of should still match policies naming that
    role exactly, rather than vanishing. The alternative — dropping it — would
    silently narrow access on a typo in the graph rather than in the policy.

    The returned slice is shared and must not be modified.

func (g *Graph) ClosureOf(nodes ...string) []string
    ClosureOf returns the union of the closures of several nodes, sorted and
    deduplicated.

func (g *Graph) Expand(value string) string
    Expand returns the closure of a delimited multi-valued attribute value,
    in the same delimited form. This is the shape the engine consumes: pass the
    result straight to a subject.roles or subject.groups attribute and match it
    with has_any / has_all / has_none.

func (g *Graph) Freeze() error
    Freeze validates the graph and precomputes every node's closure.

    A cycle is an error rather than something to tolerate. Left in,
    it would make closure computation non-terminating; "handled" by cutting the
    traversal, it would make the closure depend on which node you started from,
    so two principals with the same roles could get different answers.
    Neither is acceptable in an authorization path, and a cycle in a role model
    is always an authoring mistake.

func (g *Graph) Frozen() bool
    Frozen reports whether Freeze has run successfully.

func (g *Graph) Nodes() []string
    Nodes returns every node, sorted.

func (g *Graph) Parents(node string) []string
    Parents returns a node's immediate parents, sorted. The returned slice is a
    copy and is safe to modify.

func (g *Graph) Roots() []string
    Roots returns nodes with no parents — the top of the hierarchy. Useful for
    rendering a role model and for spotting an accidentally orphaned role.

func (g *Graph) Size() int
    Size reports how many distinct nodes the graph holds.

func (g *Graph) Subsumes(node, ancestor string) bool
    Subsumes reports whether node inherits from ancestor, directly or
    transitively. A node subsumes itself.

```

---

## internal/relation

ReBAC resolver interface and in-memory implementation.

```go
package relation // import "github.com/suga/tessaraop/internal/relation"

Package relation resolves what a subject is to an object, so relationship-based
policy can be expressed without the engine growing a graph database.

# The decision this package encodes

ReBAC — "Anne can view this document because she is in the group that owns
the parent folder" — is the largest functional gap against Cedar and OpenFGA.
There were two ways to close it, and COMPARISON.md §7.1 records why this one was
chosen.

Building a Zanzibar-style tuple store natively would mean adding a database:
durability, migrations, replication, snapshot consistency. That turns TessaraOP
from a stateless drop-in compute component into a stateful service, with a
different operational burden and the loss of the zero-dependency property the
moment a driver is added. It would also mean competing on OpenFGA's strongest
axis while the actual differentiator stagnated.

So relationships are *consumed*, not stored. A Resolver answers "what is this
subject to this object", the answer is materialized into an ordinary attribute
before evaluation, and an indexed operator (has_any) matches it. The engine
gains no new concept and the evaluation path is untouched — the same division of
labour that keeps parsing and I/O outside the hot path.

# Why the interface is defined here rather than importing a client

Defining it natively means TessaraOP is not coupled to any one store. An adapter
for OpenFGA, SpiceDB or an in-house service is an implementation of one method,
and a native tuple store later would be a drop-in third implementation rather
than a rewrite. That hedge costs almost nothing now and preserves the option.

# What this handles, and what it does not

This serves Check-shaped questions: "what is Anne to document:123", asked about
one named object. That is what an authorization decision needs.

It does not serve ListObjects — "which documents can Anne view" — which is a
reverse query over the relationship graph and a genuinely different problem.
If you need it, ask your ReBAC store directly; this package is not a substitute
for one.

CONSTANTS

const SubjectRelations = "subject.relations"
    SubjectRelations is the attribute Materialize's output belongs in. Match it
    with has_any / has_all / has_none.


VARIABLES

var ErrResolverTimeout = errors.New("relation: resolver timed out")
    ErrResolverTimeout is returned when a resolver exceeds its deadline.


FUNCTIONS

func Apply(ctx context.Context, r Resolver, req *model.Request, subject, object string) error
    Apply resolves the subject's relations to the object and writes them into a
    request's attribute map, ready for evaluation.

    It is a convenience over Materialize for callers assembling a request by
    hand rather than through package ingest.

func Materialize(ctx context.Context, r Resolver, subject, object string) (string, error)
    Materialize resolves the relations and renders them in the delimited form
    the engine's set operators read.

    This is the whole integration surface: call it while building a request, put
    the result in subject.relations, and write policy against `subject.relations
    has_any ["owner", "editor"]`.


TYPES

type Cache struct {
	// Has unexported fields.
}
    Cache memoizes resolutions for a bounded time.

    Relationship data changes, and a cached answer is a stale authorization
    decision — so the TTL is required rather than optional, and there is no
    invalidation hook. If your relationships change in ways that must take
    effect immediately, do not cache them here; cache them where the writes are,
    so an invalidation can accompany them.

func NewCache(inner Resolver, ttl time.Duration) *Cache
    NewCache wraps a resolver with a time-bounded cache.

func (c *Cache) Len() int
    Len reports how many entries are held, expired or not.

func (c *Cache) Relations(ctx context.Context, subject, object string) ([]string, error)
    Relations implements Resolver.

type Chain []Resolver
    Chain queries several resolvers and unions their answers.

    The common shape is a Static holding locally-known relationships in front of
    a remote store, so an outage in the remote one degrades to the local subset
    rather than to no relationships at all.

func (c Chain) Relations(ctx context.Context, subject, object string) ([]string, error)
    Relations implements Resolver. An error from any member fails the whole
    chain: silently returning a partial relation set would narrow access without
    saying so, which in an authorization path is an outage disguised as a
    decision.

type Resolver interface {
	// Relations returns the relation names the subject holds to the object, in
	// any order. An empty result is not an error: it means no relationship,
	// which is a perfectly ordinary answer.
	Relations(ctx context.Context, subject, object string) ([]string, error)
}
    Resolver answers what relations a subject holds to an object.

    Implementations are called once per request, before evaluation, from
    whatever goroutine is assembling the request — never from the evaluation
    path. They may block and may perform I/O; the context carries the caller's
    deadline.

    An implementation must be safe for concurrent use.

func WithTimeout(r Resolver, d time.Duration) Resolver
    WithTimeout bounds how long a resolver may take.

    A remote relationship store sits in the request path, so an unbounded call
    there is an availability risk for everything behind it. This does not decide
    what to do on timeout — that is a policy question, and the caller answers
    it by choosing whether to fail the request or to proceed with no relations,
    which fails closed at the engine.

type ResolverFunc func(ctx context.Context, subject, object string) ([]string, error)
    ResolverFunc adapts a function to the Resolver interface.

func (f ResolverFunc) Relations(ctx context.Context, subject, object string) ([]string, error)
    Relations implements Resolver.

type Static struct {
	// Has unexported fields.
}
    Static is an in-memory Resolver over a fixed set of tuples.

    It is not a substitute for a real ReBAC store — there is no persistence,
    no consistency model, and no reverse index. It exists for three things
    a product needs anyway: tests, local development, and deployments whose
    relationship set is genuinely small and static (a handful of service
    accounts and owners), where running a separate store would be absurd.

    Two expansions are applied, and together they cover most of what a real
    ReBAC model is asked for:

      - **Object containment.** With a resource hierarchy, a relation held on a
        folder is also held on everything inside it. This is what makes "Anne
        can view the doc because she can view its folder" work.
      - **Subject groups.** With a group hierarchy, a relation held by a group
        is also held by its members, transitively.

    What it deliberately does not implement is Zanzibar's full userset rewrite
    algebra — computed usersets, tuple-to-userset indirection. Those need a real
    engine, and pretending otherwise would be the dishonest half-implementation
    this package's documentation warns against.

func NewStatic() *Static
    NewStatic returns an empty in-memory resolver.

func (s *Static) Add(tuples ...Tuple) *Static
    Add records a relationship. Safe to call concurrently with reads.

func (s *Static) Relations(_ context.Context, subject, object string) ([]string, error)
    Relations implements Resolver.

func (s *Static) Size() int
    Size reports how many (subject, object) pairs hold at least one relation.

func (s *Static) WithGroupHierarchy(g *hierarchy.Graph) *Static
    WithGroupHierarchy makes a relation held by a group also hold for its
    members, transitively. The graph must be frozen, and its edges run member ->
    group.

func (s *Static) WithObjectHierarchy(g *hierarchy.Graph) *Static
    WithObjectHierarchy makes a relation held on a container also hold on
    everything it contains. The graph must be frozen.

type Tuple struct {
	Subject  string
	Relation string
	Object   string
}
    Tuple is one relationship fact: subject holds relation on object.

```

---

## internal/bundle

The declarative JSON policy format and its linter.

```go
package bundle // import "github.com/suga/tessaraop/internal/bundle"

Package bundle is the declarative, on-the-wire policy format.

Customers do not author Go structs. They author files, review them, diff them,
and ship them through the same pipeline as the rest of their configuration.
So the engine needs a serialized form that is stable, reviewable, and validated
before it ever reaches a decision path — this package is that form plus its
linter.

# Why JSON and not YAML

The engine has no external dependencies, and that is a deliberate property:
an authorization component sitting in a request path is a supply-chain surface,
and every dependency widens it. Go's standard library ships a JSON codec and no
YAML codec, so JSON is what this reads. Teams that prefer YAML for authoring can
convert at build time; the format below is a direct structural match either way.

# Shape

    {
      "version": 1,
      "policies": [{
        "id": "acme-admin-console",
        "tenant": "acme",
        "scope": "identity",
        "priority": 100,
        "rule_algorithm": "first-applicable",
        "rules": [{
          "id": "grant-admin",
          "effect": "ALLOW",
          "priority": 100,
          "obligations": ["require_mfa"],
          "when": {
            "all": [
              {"any": [
                {"attr": "subject.role", "op": "eq", "values": ["admin"]},
                {"attr": "subject.role", "op": "eq", "values": ["security-admin"]}
              ]},
              {"not": {"attr": "subject.groups", "op": "has_any", "values": ["contractor"]}},
              {"attr": "subject.risk_score", "op": "range", "min": 0, "max": 30},
              {"attr": "network.source_ip", "op": "cidr", "prefixes": ["10.0.0.0/8"]}
            ]
          }
        }]
      }]
    }

A condition node is exactly one of "all", "any", "not", or a leaf carrying
"attr" and "op". Nesting is unrestricted up to the linter's depth cap.

CONSTANTS

const (
	DefaultMaxDepth             = 16
	DefaultMaxConditionsPerRule = 64
	DefaultMaxRegexLength       = 512
)
    Linter defaults.

const FormatVersion = 1
    FormatVersion is the bundle schema version this package reads and writes.
    A bundle omitting the field is assumed to be version 1.


VARIABLES

var ErrInvalidBundle = errors.New("bundle: validation failed")
    ErrInvalidBundle is returned by Compile when the bundle holds errors.


FUNCTIONS

func HasErrors(diags []Diagnostic) bool
    HasErrors reports whether any diagnostic blocks loading.


TYPES

type Bundle struct {
	Version  int      `json:"version"`
	Policies []Policy `json:"policies"`

	// Metadata is free-form and carried through untouched. Deployment pipelines
	// use it for provenance: the commit that produced the bundle, who approved
	// it, when it was built.
	Metadata map[string]string `json:"metadata,omitempty"`
}
    Bundle is a complete, self-contained policy set.

func FromPolicies(policies []model.Policy) *Bundle
    FromPolicies converts engine policies back to a bundle. Round-tripping
    matters for two reasons: it lets the CLI emit a starter bundle from the
    built-in demo set, and it gives the linter's tests a way to assert that
    compiling loses nothing.

func Read(r io.Reader) (*Bundle, error)
    Read parses a bundle from r without validating it. Use Lint, or Compile,
    to find problems; Read only reports malformed JSON.

    Unknown fields are rejected. A typo'd key would otherwise be silently
    ignored, and "polices" instead of "policies" yields an empty bundle that
    denies every request — an outage presented as a successful load.

func ReadFile(path string) (*Bundle, error)
    ReadFile parses a bundle from a path.

func (b *Bundle) Compile(opt LintOptions) ([]model.Policy, []Diagnostic, error)
    Compile validates a bundle and converts it to engine policies.

    It refuses to produce policies when any diagnostic is an error, and that
    refusal is the point: a bundle with an unparsable regex or a numeric
    operator on a string attribute would otherwise load cleanly and fail closed
    at runtime, which looks exactly like a rule the author wrote wrong on
    purpose. Warnings do not block, and are returned so a deployment pipeline
    can surface them.

func (b *Bundle) Lint(opt LintOptions) []Diagnostic
    Lint validates a bundle and returns every finding, errors and warnings
    together, in bundle order.

    The linter exists because of a specific failure mode this engine has
    by design: absent attributes and unsatisfiable conditions fail closed.
    A rule comparing a string attribute with a numeric operator does not error
    — it simply never matches, which is indistinguishable from a rule the author
    meant to be narrow. Catching that at load time is the only place it can be
    caught.

func (b *Bundle) Summarize() Stats
    Summarize walks the bundle and reports what it contains, including how much
    of it the index will actually be able to prune on. That last number is the
    one an operator wants before shipping a bundle: a policy set written mostly
    as disjunctions will be correct but will not be fast.

func (b *Bundle) Write(w io.Writer) error
    Write serializes a bundle as indented JSON.

type Diagnostic struct {
	Severity Severity
	Path     string // e.g. policies[2].rules[0].when.all[1]
	Message  string
}
    Diagnostic is one finding, located by a path into the bundle.

func Errors(diags []Diagnostic) []Diagnostic
    Errors returns only the blocking diagnostics.

func (d Diagnostic) String() string

type LintOptions struct {
	// StrictAttributes makes an unregistered attribute name an error rather than
	// a warning.
	//
	// It defaults off, and that is deliberate. The registry covers the protocol
	// and identity surface, but customers legitimately carry their own
	// attributes — an internal risk signal, a bespoke resource label — and
	// refusing those at load time would force every integration to fork the
	// registry. The warning still fires, so a typo in a registry name is visible
	// rather than silent. Turn this on once the vocabulary is settled.
	StrictAttributes bool

	// MaxDepth caps condition-tree height. Zero means DefaultMaxDepth.
	//
	// An unbounded tree submitted by a tenant is a denial-of-service vector
	// against every request that reaches its shard: evaluation is linear in tree
	// size and the index cannot prune inside a disjunction.
	MaxDepth int

	// MaxConditionsPerRule caps leaves in one rule. Zero means
	// DefaultMaxConditionsPerRule.
	MaxConditionsPerRule int

	// MaxRegexLength caps a single pattern's source length. Zero means
	// DefaultMaxRegexLength. Go's regexp is RE2 and has no catastrophic
	// backtracking, so this is a cost bound rather than a safety one.
	MaxRegexLength int

	// AllowEmptyRuleSet permits a policy with no rules. Off by default: such a
	// policy can never produce a verdict, so it is almost always an editing
	// mistake rather than an intent.
	AllowEmptyRuleSet bool
}
    LintOptions tunes what the linter enforces.

    The defaults are what a customer's first bundle should be held to. The knobs
    exist because two things vary legitimately between deployments: whether the
    customer has extended the attribute vocabulary beyond the built-in registry,
    and how large a tree their authoring tool emits.

type Node struct {
	All []*Node `json:"all,omitempty"`
	Any []*Node `json:"any,omitempty"`
	Not *Node   `json:"not,omitempty"`

	// Leaf fields.
	Attr string `json:"attr,omitempty"`
	Op   string `json:"op,omitempty"`

	Values   []string  `json:"values,omitempty"`
	Min      *float64  `json:"min,omitempty"`
	Max      *float64  `json:"max,omitempty"`
	Numbers  []float64 `json:"numbers,omitempty"`
	Prefixes []string  `json:"prefixes,omitempty"`
}
    Node is one node of a condition tree: a boolean combinator or a leaf.

    It is a single struct with a discriminating shape rather than a tagged
    union, because that is what makes the JSON readable to a human reviewer.
    The cost is custom marshalling and a validity check that exactly one form
    is populated, which the linter reports as a diagnostic rather than a parse
    failure — a malformed node should tell the author which rule is wrong,
    not abort the file.

func (n *Node) Kind() NodeKind
    Kind classifies the node. A node with no form and a node with several are
    both invalid: the first says nothing, and the second would let the reader
    and the engine disagree about what the rule means.

func (n *Node) MarshalJSON() ([]byte, error)
    MarshalJSON writes exactly the one form this node takes.

    The struct tags alone cannot do this. With `omitempty`, an empty "all"
    — which means "match everything", the catch-all rule — serializes to {}
    and reloads as a node with no form at all, which the linter then rejects.
    Without `omitempty`, every leaf sprouts "all": null. So the form is selected
    here and an empty combinator is written as an explicit [].

type NodeKind uint8
    Kind reports which form this node takes, and whether it is unambiguous.

const (
	NodeInvalid NodeKind = iota // zero, or more than one, form populated
	NodeAll
	NodeAny
	NodeNot
	NodeLeaf
)
func (k NodeKind) String() string

type Policy struct {
	ID       string `json:"id"`
	Tenant   string `json:"tenant,omitempty"`
	Scope    string `json:"scope,omitempty"`
	Priority int    `json:"priority,omitempty"`

	// RuleAlgorithm combines this policy's matching rules. Empty means
	// deny-overrides.
	RuleAlgorithm string `json:"rule_algorithm,omitempty"`

	Rules []Rule `json:"rules"`

	Description string `json:"description,omitempty"`
}
    Policy is the serialized form of model.Policy.

type Rule struct {
	ID          string   `json:"id"`
	Effect      string   `json:"effect"`
	Priority    int      `json:"priority,omitempty"`
	When        *Node    `json:"when,omitempty"`
	Obligations []string `json:"obligations,omitempty"`
	Description string   `json:"description,omitempty"`
}
    Rule is the serialized form of model.Rule.

type Severity uint8
    Severity ranks a diagnostic.

const (
	// Warning: the bundle will load and behave as written, but the author
	// probably did not mean it.
	Warning Severity = iota
	// Error: the bundle is rejected. Loading it would produce a policy set that
	// silently never matches, or that the engine cannot evaluate at all.
	Error
)
func (s Severity) String() string

type Stats struct {
	Policies       int
	Rules          int
	Conditions     int
	IndexableConds int
	RulesWithOrNot int
	Tenants        int
	Attributes     []string
	Operators      map[string]int
}
    Stats summarizes a bundle for a deployment log or an onboarding report.

```

---

## internal/ingest

Builds requests from real traffic using stdlib parsers only.

```go
package ingest // import "github.com/suga/tessaraop/internal/ingest"

Package ingest builds a model.Request from real traffic.

# Why this is a separate package, and why it uses only the standard library

The policy core evaluates named, already-typed attributes. It does not decode
packets or HTTP bytes, and that boundary is deliberate rather than incidental.
Parser-differential bugs are one of the most productive sources of authorization
bypasses in real systems: when the component making the decision parses a
request differently from the component serving it, an attacker crafts input
the two disagree about. A hand-rolled TCP/IP or HTTP decoder sitting inside an
authorization hot path is exactly that shape of mistake.

So everything here delegates to code that already has to be right: net/http
for requests, net/netip for addresses, crypto/tls for handshake state, mime for
media types. This package's whole job is mapping their output onto the names
in the attribute registry, and normalizing it the way policy authors expect —
lowercased hosts, port-stripped, media-type parameters removed.

# What it does not do

It performs no I/O, no DNS lookup, no threat-intelligence enrichment,
and no body reading unless explicitly asked. Geo-IP, IP reputation, ASN,
session validity and token verification all require a store or a network call,
so they arrive through Enrich rather than being inferred here. Layer 3 and 4
header fields beyond what a net.Conn exposes — TTL, TCP flags, fragmentation,
DSCP — are not reachable from Go's socket abstraction at all; they come from
whatever dataplane sits in front of the application, via the same Enrich seam.

That split is honest about where the data comes from. An adapter that fabricated
a TTL would be worse than one that omits it, because a policy on a fabricated
attribute reads as enforced when it is not.

CONSTANTS

const DefaultBodyLimit = 64 << 10
    DefaultBodyLimit bounds payload inspection. Bodies are only read when a
    caller explicitly asks, and even then a bound is required: an unbounded read
    in an authorization path is a memory-exhaustion vector reachable by anyone
    who can send a request.


FUNCTIONS

func HTTPRequest(tenantID, scope string, r *http.Request, subject *SubjectInfo,
	trustedHops int, now time.Time) model.Request
    HTTPRequest is the common case in one call: an HTTP request plus its
    authenticated principal, at a given time.

    trustedHops is passed through to FromForwardedHeaders; pass 0 unless
    you operate proxies in front of this service, and read that method's
    documentation before passing anything else.


TYPES

type Builder struct {
	// Has unexported fields.
}
    Builder accumulates attributes and produces a model.Request.

    Every From* method is additive and may be chained in any order; later calls
    overwrite earlier values for the same attribute. A nil argument is a no-op,
    so a caller need not branch on whether TLS was negotiated or a token was
    present.

func New(tenantID, scope string) *Builder
    New starts a builder for a tenant and scope.

    Scope is the second half of the shard key and the single most effective
    lever on per-request cost. Pick something stable and reasonably narrow
    — a resource family, an application, a listener — not something
    request-specific.

func (b *Builder) Action(action string) *Builder
    Action names the operation requested.

func (b *Builder) AtTime(t time.Time) *Builder
    AtTime populates the time.* namespace.

    The clock is passed in rather than read here so that a decision is
    reproducible: replaying an audited request must yield the same answer, which
    it cannot if the engine consults the wall clock itself. time.hour carries a
    fractional part so a window like [9, 17.5] means what it looks like.

func (b *Builder) Build() model.Request
    Build returns the assembled request. Empty maps are dropped so the decision
    cache hashes the same logical request identically however it was assembled.

func (b *Builder) FromAddrPort(src netip.AddrPort) *Builder
    FromAddrPort sets the source address and port from a parsed pair.

func (b *Builder) FromBody(body []byte) *Builder
    FromBody records an already-read body for regex, DLP and magic-number
    matching.

    It takes bytes rather than a reader, because consuming an http.Request.Body
    inside an authorization check would leave the handler with nothing to read.
    Callers that need body inspection should tee the body once at the edge
    and pass the buffer both here and downstream. Content is truncated to the
    builder's body limit.

func (b *Builder) FromConn(c net.Conn) *Builder
    FromConn populates what a net.Conn actually exposes: the peer and local
    address and port, and the transport protocol.

    It does not populate TTL, TCP flags, window size, fragmentation or DSCP.
    Go's net.Conn does not surface them, and inventing values would make
    policies on those attributes look enforced while matching nothing.
    Supply them through Set/SetNum from whatever dataplane can actually see the
    headers.

func (b *Builder) FromFileName(name string) *Builder
    FromFileName populates the payload.* attributes derivable from a name alone.

func (b *Builder) FromForwardedHeaders(r *http.Request, trustedHops int) *Builder
    FromForwardedHeaders resolves the client address from proxy headers.

    trustedHops is the number of proxies you operate, counted from the right.
    This argument has no safe default, which is why it is required:
    X-Forwarded-For is attacker-controlled on its left, so taking the leftmost
    entry — the common mistake — lets a client claim any source address it
    likes and walk straight through a CIDR allowlist. With trustedHops = n, the
    (n+1)-th entry from the right is the last one your own infrastructure wrote,
    and everything left of it is discarded.

    Pass 0 when nothing is in front of you; the header is then ignored entirely
    and the transport-level address stands.

func (b *Builder) FromHTTPRequest(r *http.Request) *Builder
    FromHTTPRequest populates the http.* namespace from a parsed request.

    The request is not modified and the body is not read; call FromBody for
    that.

    Two normalizations matter for policy correctness. The host is lowercased
    and port-stripped, so a dnssuffix condition on "admin.acme.com" matches
    "Admin.Acme.com:8443". And both the cleaned path and the raw path are
    exposed: comparing them is how a policy detects traversal and encoding
    tricks, which a single normalized value would hide.

func (b *Builder) FromResource(resourceType, id, resourcePath, sensitivity string) *Builder
    FromResource names what is being acted on.

func (b *Builder) FromResponse(statusCode int, header http.Header) *Builder
    FromResponse populates the response-phase attributes, for policies that act
    on what a downstream server returned.

func (b *Builder) FromSubject(s *SubjectInfo) *Builder
    FromSubject populates the subject.* namespace.

func (b *Builder) FromTLS(cs *tls.ConnectionState) *Builder
    FromTLS populates the tls.* namespace from a completed handshake.

func (b *Builder) FromToken(t *TokenInfo) *Builder
    FromToken populates the token.* namespace and any extra claims.

func (b *Builder) Set(name, value string) *Builder
    Set stores a string attribute directly, for values this package cannot
    derive.

func (b *Builder) SetBool(name string, value bool) *Builder
    SetBool stores a string attribute as "true" or "false".

func (b *Builder) SetIP(name string, addr netip.Addr) *Builder
    SetIP stores an IP attribute directly.

func (b *Builder) SetNum(name string, value float64) *Builder
    SetNum stores a numeric attribute directly.

func (b *Builder) WithBodyLimit(n int64) *Builder
    WithBodyLimit changes how much body FromBody will read.

func (b *Builder) WithCookies(names ...string) *Builder
    WithCookies allowlists the cookie names whose values may become attributes.

    No cookie is populated unless named here, and that default is the point.
    A session cookie is a credential; copying every cookie into the attribute
    map would put it in the decision cache, in whatever an integration logs,
    and in any audit record — the same leak this package refuses for the raw
    Cookie header, arriving through a different door.

    So the caller names the cookies their policies actually reference. Those are
    almost never the secret ones: a locale, a feature flag, a consent marker.
    If a policy genuinely needs to test a session cookie, prefer resolving
    it upstream and passing the result through FromSubject or session.valid,
    so the engine sees a verdict rather than the credential.

func (b *Builder) WithGroupHierarchy(g *hierarchy.Graph) *Builder
    WithGroupHierarchy does the same for nested group membership.

func (b *Builder) WithResourceHierarchy(g *hierarchy.Graph) *Builder
    WithResourceHierarchy expands a resource into its containment ancestors,
    so a policy scoped to a folder or project matches everything beneath it.

func (b *Builder) WithRoleHierarchy(g *hierarchy.Graph) *Builder
    WithRoleHierarchy expands a principal's roles into their transitive closure.

    A subject holding "admin" in a graph where admin inherits editor inherits
    viewer arrives at the engine carrying subject.roles = "admin,editor,viewer",
    so a policy written against `subject.roles has_any ["viewer"]` matches
    without knowing the role model.

    The graph must be frozen; an unfrozen one is ignored rather than silently
    producing partial closures.

type SubjectInfo struct {
	ID            string
	Type          string
	Role          string
	Roles         []string
	Department    string
	Groups        []string
	MFAVerified   bool
	DeviceManaged bool
	RiskScore     float64
	AuthAge       time.Duration
}
    SubjectInfo is the authenticated principal, as resolved by the caller.

type TokenInfo struct {
	Valid           bool
	SignatureValid  bool
	Algorithm       string
	Issuer          string
	Subject         string
	Audience        []string
	Scopes          []string
	ExpiresIn       time.Duration
	AdditionalClaim map[string]string
}
    TokenInfo is the outcome of validating a bearer token, as decided by the
    caller's own verifier.

    This package deliberately does not verify signatures. Doing so requires
    key material, key rotation, clock policy and an audience list, all of which
    belong to the integration; a token library that quietly accepted alg=none
    inside an authorization engine would be a critical vulnerability. What
    arrives here is a verdict the caller already reached, mapped onto attributes
    so policies can require it.

```

---

## internal/engine

Sharding, algorithm selection, decision cache.

```go
package engine // import "github.com/suga/tessaraop/internal/engine"

Package engine is the top-level policy decision point.

It composes three ideas, in descending order of how much each contributes to the
latency target:

 1. Sharding. No request is ever evaluated against the whole corpus. A request
    carries a tenant, and only that tenant's shard plus the global shard are
    in scope. Ten million policies spread over ten thousand tenants means
    roughly a thousand policies per request — that ratio, not any bit-twiddling,
    is what puts microsecond evaluation in reach.

 2. Indexing. Within a shard, per-attribute indexes narrow those policies to a
    handful of candidates before any exact matching runs.

 3. Caching. Real authorization traffic repeats heavily: the same subject
    hitting the same resource over and over. A verified decision cache turns
    those into a hash lookup.

Global policies are evaluated first, because platform-wide denies (IP
blocklists, kill switches) are both the smallest set and the most likely to
terminate evaluation immediately under deny-overrides.

TYPES

type Cache struct {
	// Has unexported fields.
}
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

func NewCache(size int) *Cache
    NewCache returns a cache holding approximately size entries.

func (c *Cache) Get(req model.Request) (model.Decision, bool)
    Get returns a cached decision for req, if one is present and verified.

func (c *Cache) Put(req model.Request, d model.Decision)
    Put stores a decision, overwriting whatever occupied the slot.

type Config struct {
	// Algorithm selects how matching policies combine. Defaults to
	// DenyOverrides, the only order-independent choice and therefore the only
	// one that needs no sorting pass over index output.
	Algorithm model.Algorithm

	// CacheSize is the number of decision cache entries. Zero disables the
	// cache entirely, which is what the benchmarks use when measuring raw
	// index performance rather than traffic locality.
	CacheSize int

	// UnionObligations collects obligations from every matching rule carrying the
	// winning effect, rather than only from the one credited. It removes the
	// attribution caveat at the cost of short-circuiting — see
	// model.Accumulator.UnionObligations.
	UnionObligations bool
}
    Config controls engine construction.

type Engine struct {
	// Has unexported fields.
}
    Engine evaluates requests against a sharded, indexed policy corpus.
    It is safe for concurrent use: shards are immutable after construction,
    per-goroutine scratch comes from a pool, and the cache is internally
    striped.

func New(policies []model.Policy, cfg Config) *Engine
    New builds an engine over the given policies, partitioning them into shards
    by TenantID. Policies in model.GlobalTenant form the global shard evaluated
    for every request.

func (e *Engine) Evaluate(req model.Request) model.Decision
    Evaluate renders a decision for req.

func (e *Engine) InScope(tenantID, scope string) int
    InScope reports how many rules a request can reach: the global shard,
    its tenant-wide shard, and its own scope's shard. This is the number that
    governs per-request cost, as opposed to the corpus total.

func (e *Engine) ShardCount() int
    ShardCount reports how many shards the corpus partitions into.

func (e *Engine) TenantCount() int
    TenantCount reports how many distinct tenants hold policies.

func (e *Engine) TotalPolicies() int
    TotalPolicies reports the corpus size across every shard.

func (e *Engine) TotalRules() int
    TotalRules reports how many rules the corpus holds. This, not the policy
    count, is what the index universe is sized to and what per-shard cost
    tracks.

```

---

## internal/index

Per-attribute sub-indexes and both intersection strategies.

```go
package index // import "github.com/suga/tessaraop/internal/index"

Package index builds the per-attribute structures that turn a request into a
small candidate set, and performs the intersection that produces it.

# The indexed unit is a rule, not a policy

A policy holds many rules and each rule carries its own condition tree,
so indexing at policy granularity would mean a policy's index entry is the union
of what all its rules ask for — near-useless as a filter. The universe here
is therefore the shard's flattened rule list, and a candidate position names a
rule. Positions are assigned in policy order, which matters: candidate positions
come back ascending, so all surviving rules of one policy form a contiguous run
and the two-tier evaluation walks them without a map or an allocation.

# Only the AND-spine may be indexed

A rule's conditions are a boolean tree, and only the leaves reachable
from the root through exclusively And nodes are logically necessary for
the rule to match. Those are the only ones that may build a filter — see
model.ConditionExpr.ANDSpineLeaves for why indexing a leaf under an Or or a Not
would let the pre-filter drop a rule that actually matches. Leaves off the spine
contribute nothing and fall through to exact validation.

# How a candidate set is derived

Each attribute contributes one or more sub-indexes, one per operator family
present on it. For a request value v, a sub-index S yields the set of rules that
pass it:

    pass_S(v) = notParticipating_S ∪ accepted_S(v)

The notParticipating term is the correctness keystone. A rule that places no
condition of kind S on the attribute must never be filtered out by S — get that
wrong and the engine returns confidently wrong answers rather than merely slow
ones.

Negated operators (ne, nin, !cidr) collapse to something much cheaper. For them,
notParticipating ∪ (participating \ rejected) is just the whole universe minus
the rejected set, so a negation needs no complement at query time — it is simply
"reject these, pass everything else".

Substring and regular-expression operators are not indexable at all: there is
no structure a pre-filter can exploit. They still contribute the requirement
that their attribute be present, which on real corpora prunes a great deal,
and then resolve exactly during validation.

# How the intersection runs

v1 AND-ed dense bitsets pairwise, so every step cost O(N/64) no matter how few
candidates survived; at a million policies that dominated everything and the
speedup collapsed to 1.1x. Instead this package materializes only the single
most selective sub-index, then filters that list in place against the remaining
ones. Cost tracks the surviving candidate count rather than the corpus size,
and the list only ever shrinks.

TYPES

type Scratch struct {
	// Has unexported fields.
}
    Scratch holds the reusable buffers one evaluation goroutine needs.
    Reusing it across requests is what keeps the steady-state hot path free of
    allocation; each goroutine must own its own.

func NewScratch() *Scratch
    NewScratch returns a scratch buffer sized for the expected candidate count.

type Shard struct {
	Policies []model.Policy

	// Has unexported fields.
}
    Shard indexes one tenant's policies. Requests are evaluated against their
    own tenant's shard plus the global shard, never the whole corpus.

func BuildShard(policies []model.Policy) *Shard
    BuildShard indexes a slice of policies, flattening their rules into one
    indexed universe. The slice is retained by reference; callers must not
    mutate it afterwards.

    It also runs model.Policy.Prepare on every policy, so regular expressions
    are compiled once here rather than looked up per evaluation. A pattern
    that fails to compile is left to the cache fallback in Condition.Matches —
    BuildShard cannot return an error without every caller in the tree growing
    one, and package bundle's linter is where an unparsable pattern is meant to
    be caught.

func (s *Shard) Candidates(req model.Request, sc *Scratch) []int
    Candidates returns the rule positions in this shard that survive index
    filtering. The returned slice aliases sc and is valid only until the next
    call with the same Scratch. Positions are ascending, which the two-tier walk
    in Evaluate relies on to group rules by policy.

func (s *Shard) Evaluate(req model.Request, sc *Scratch, acc *model.Accumulator) (policies, rules int)
    Evaluate narrows the shard to candidate rules and runs the two-tier
    combination over them, feeding resolved policy verdicts into acc. It reports
    how many policies and how many rules reached exact validation.

    Candidate positions arrive ascending and refs are assigned in policy order,
    so every policy's surviving rules form one contiguous run. Walking runs
    rather than grouping through a map is what keeps this allocation-free:
    the per-policy rule list is gathered into a scratch buffer that is reused
    across policies and across requests.

func (s *Shard) PolicyCount() int
    PolicyCount reports how many policies this shard holds.

func (s *Shard) RuleRef(pos int) (policyIdx, ruleIdx int)
    RuleRef resolves an indexed position to its policy and rule indices.

func (s *Shard) Size() int
    Size reports how many rules this shard indexes.

```

---

## internal/matcher

CIDR trie, domain trie, prefix/suffix tables, interval and numeric-set indexes.

```go
package matcher // import "github.com/suga/tessaraop/internal/matcher"

Package matcher provides the per-attribute index structures the engine uses to
turn a request value into a candidate policy set.

A hash map answers "which policies require department == engineering".
It cannot answer "which policies have a CIDR block containing 10.4.2.7",
"which policies accept the host api.admin.acme.com", or "which policies have a
time window covering 14:30". Those need a radix trie, a reversed label trie,
and an interval structure respectively — that is what lives here.

Every matcher answers the same shape of question and returns a MatchSet.

CONSTANTS

const MaxDistinctIntervals = 4096
    MaxDistinctIntervals caps how many distinct numeric ranges an IntervalIndex
    will track before it gives up on being selective. Past the cap the index
    reports Degraded and the engine treats every policy carrying the condition
    as a candidate — conservative, still correct, just less selective.


VARIABLES

var Empty = MatchSet{}
    Empty is the MatchSet matching nothing — used when a request carries an
    attribute whose value no policy condition accepts.


TYPES

type CIDRIndex struct {
	// Has unexported fields.
}
    CIDRIndex answers "which policies have a CIDR condition whose block contains
    this address" via a binary radix trie over address bits.

    A query walks at most 32 (IPv4) or 128 (IPv6) levels and collects the policy
    set at every terminal node it passes through, because an address inside
    10.0.0.0/8 is also inside 10.4.0.0/16 — every enclosing prefix matches, not
    just the longest. Walk cost is bounded by address width and is independent
    of how many blocks the corpus holds, which is the point versus testing every
    prefix in turn.

    Addresses are canonicalized with Unmap, so 10.0.0.0/8 and
    ::ffff:10.0.0.0/104 land in the same trie and a query for either form finds
    both. A genuine IPv6 prefix written to deliberately cover IPv4-mapped space
    is not modeled; real policy corpora do not mix the families that way.

func NewCIDRIndex() *CIDRIndex
    NewCIDRIndex returns an empty index ready for Insert.

func (c *CIDRIndex) Freeze()
    Freeze finalizes every terminal set. Call once after all Inserts.

func (c *CIDRIndex) Insert(p netip.Prefix, policyIdx, universe int)
    Insert records that the policy at policyIdx carries a condition accepting
    prefix. universe is the policy count of the shard being indexed.

func (c *CIDRIndex) Lookup(addr netip.Addr, base MatchSet) MatchSet
    Lookup unions into base the policy set of every prefix containing addr.
    The address buffer stays on the stack, so lookups do not allocate.

type DomainIndex struct {
	// Has unexported fields.
}
    DomainIndex answers "which policies have a DNS-suffix condition that accepts
    this host" via a trie over reversed labels.

    Labels are walked right to left, so api.admin.acme.com visits com -> acme
    -> admin -> api and collects a policy set at every terminal it passes.
    That structure enforces label alignment for free: evilacme.com walks com
    -> evilacme and never reaches the acme node, so it cannot match a policy
    scoped to acme.com. A plain strings.HasSuffix check would match it — that is
    a real and frequently exploited authorization bypass, so the index and the
    validation path in model.MatchDNSSuffix both align on labels.

    Hosts are expected already lowercased by the ingest layer, as any gateway or
    proxy normalizes them; the hot path does not allocate to case-fold.

func NewDomainIndex(universe int) *DomainIndex
    NewDomainIndex returns an empty index over a shard of `universe` policies.

func (d *DomainIndex) Freeze()
    Freeze finalizes every terminal set. Call once after all Inserts.

func (d *DomainIndex) Insert(suffix string, policyIdx int)
    Insert records that the policy at policyIdx accepts `suffix` and anything
    under it.

func (d *DomainIndex) Lookup(host string, base MatchSet) MatchSet
    Lookup unions into base the policy set of every suffix that accepts host.

type IntervalIndex struct {
	// Has unexported fields.
}
    IntervalIndex answers "which policies have a numeric condition whose range
    covers this value".

    It groups policies by *distinct* range rather than building a per-value
    or per-bucket structure. That choice comes from what real policy corpora
    look like: a million policies referencing time-of-day windows still
    only use a handful of distinct windows (business hours, after hours,
    maintenance windows), and risk-score conditions collapse onto a few bands.
    So the number of distinct ranges stays small even as the corpus grows,
    and a query is a binary search plus a short scan over ranges whose lower
    bound is below the query value.

    Ranges are stored half-inclusive-agnostic: OpGreaterThan and OpLessThan
    arrive as ranges with an infinite end, which sort and compare correctly
    against ±Inf without special cases.

func NewIntervalIndex(universe int) *IntervalIndex
    NewIntervalIndex returns an empty index over a shard of `universe` policies.

func (x *IntervalIndex) Degraded() bool
    Degraded reports whether the index gave up on selectivity. The engine must
    then fall back to the attribute's has-condition set.

func (x *IntervalIndex) Freeze()
    Freeze sorts and finalizes the entries. Call once after all Inserts.

func (x *IntervalIndex) Insert(min, max float64, policyIdx int)
    Insert records that the policy at policyIdx accepts values in [min, max].
    Use math.Inf for open ends.

func (x *IntervalIndex) Lookup(v float64, base MatchSet) MatchSet
    Lookup unions into base the policy set of every range covering v.

type MatchSet struct {
	// Has unexported fields.
}
    MatchSet is the union of zero or more precomputed sets, evaluated lazily.

    Two things keep this off the heap. The union is lazy, so a CIDR lookup
    matching several nested prefixes never OR-s them into a new set — the engine
    materializes only the single most selective MatchSet and probes the rest
    with Contains. And the members live in a fixed array rather than a slice,
    because a slice would allocate once per filter per request, which measured
    as the bulk of the engine's allocation traffic.

func Single(s *bitset.Set) MatchSet
    Single wraps one set.

func (m *MatchSet) AppendMembers(dst []int) []int
    AppendMembers appends the deduplicated union to dst. The engine calls this
    exactly once per request, on the most selective MatchSet only.

func (m *MatchSet) Contains(i int) bool
    Contains reports whether any constituent set holds i.

func (m *MatchSet) EstimatedCardinality() int
    EstimatedCardinality is the sum of member cardinalities: an upper bound on
    the true union size, since the sets may overlap. The engine uses it only
    to order intersections cheapest-first, so an upper bound is fine — a bad
    estimate costs a little speed, never correctness.

func (m *MatchSet) IsEmpty() bool
    IsEmpty reports whether the union holds nothing.

func (m *MatchSet) OrWords(dst []uint64)
    OrWords writes the union into dst as a bitmap, accumulating rather than
    clearing. It is how the word-parallel intersection path consumes a filter:
    materializing the union as a member list first is precisely the cost that
    path exists to avoid on a large shard.

func (m MatchSet) Union(s *bitset.Set) MatchSet
    Union adds another set to the lazy union.

type NumSetIndex struct {
	// Has unexported fields.
}
    NumSetIndex answers "which rules accept this exact numeric value" for
    discrete numeric set membership (model.OpNumIn).

    IntervalIndex could serve this by inserting a degenerate [v, v] range per
    value, and for a handful of values it would. It stops working at the shape
    that actually motivates the operator: `dest_port IN {…}` over a couple
    of hundred ports turns every value into its own distinct interval, burns
    through MaxDistinctIntervals, and drops the whole attribute into degraded
    mode where every participating rule stays a candidate. Discrete membership
    wants a hash map — O(1), no cap, no binary search — so it gets one.

    Float64 keys are exact here rather than approximate, and that is correct
    for the intended domain: ports, protocol numbers, status codes, ICMP types.
    All are small integers, exactly representable, and compared with == by
    Condition.Matches. NaN is dropped on insert since no NaN comparison can
    succeed anyway.

func NewNumSetIndex(universe int) *NumSetIndex
    NewNumSetIndex returns an empty index over a shard of `universe` rules.

func (x *NumSetIndex) Freeze()
    Freeze finalizes every value set. Call once after all Inserts.

func (x *NumSetIndex) Insert(v float64, ruleIdx int)
    Insert records that the rule at ruleIdx accepts the value v.

func (x *NumSetIndex) Lookup(v float64, base MatchSet) MatchSet
    Lookup unions into base the rule set accepting v.

type PrefixIndex struct {
	// Has unexported fields.
}
    PrefixIndex answers "which policies have a prefix condition satisfied by
    this path".

    Rather than a character trie, it records the distinct prefix lengths that
    actually occur in the corpus and probes only those. A path is checked
    against however many distinct lengths exist — typically a handful,
    since real policy sets reuse a small number of path roots (/api, /api/v2,
    /api/v2/admin) — instead of one probe per character. Substring slicing in Go
    shares the backing array, so the probes do not allocate.

    Semantics match model.OpPrefix exactly: a raw byte-prefix test,
    so /api/v2/admin does match /api/v2/adminfoo. That is deliberately the
    same rule the validation pass applies, since an index that disagreed with
    validation in the stricter direction would wrongly drop matching policies.

func NewPrefixIndex(universe int) *PrefixIndex
    NewPrefixIndex returns an empty index over a shard of `universe` policies.

func (x *PrefixIndex) Freeze()
    Freeze finalizes every prefix set. Call once after all Inserts.

func (x *PrefixIndex) Insert(p string, policyIdx int)
    Insert records that the policy at policyIdx accepts paths starting with p.

func (x *PrefixIndex) Lookup(path string, base MatchSet) MatchSet
    Lookup unions into base the policy set of every recorded prefix of path.

type SuffixIndex struct {
	// Has unexported fields.
}
    SuffixIndex answers "which rules have a byte-suffix condition satisfied
    by this string". It is the mirror of PrefixIndex and shares its reasoning:
    record the distinct suffix lengths the corpus actually uses and probe only
    those, since real policy sets reuse a small number of endings.

    The obvious implementation — reverse the string and reuse PrefixIndex —
    allocates on every lookup, which is unacceptable on a hot path that is
    otherwise allocation-free. Slicing from the right instead shares the backing
    array exactly as prefix slicing does, so this stays free.

    Semantics match model.OpSuffix exactly: a raw byte test, so ".php"
    matches "shell.php" and also "x.notphp"'s ending only if the bytes align.
    File extension filtering is the main user, which is why OpSuffix exists
    separately from OpDNSSuffix — hostnames need label alignment, filenames do
    not.

func NewSuffixIndex(universe int) *SuffixIndex
    NewSuffixIndex returns an empty index over a shard of `universe` rules.

func (x *SuffixIndex) Freeze()
    Freeze finalizes every suffix set. Call once after all Inserts.

func (x *SuffixIndex) Insert(s string, ruleIdx int)
    Insert records that the rule at ruleIdx accepts strings ending with s.

func (x *SuffixIndex) Lookup(val string, base MatchSet) MatchSet
    Lookup unions into base the rule set of every recorded suffix of val.

```

---

## internal/bitset

Hybrid sparse/dense integer sets.

```go
package bitset // import "github.com/suga/tessaraop/internal/bitset"

Package bitset implements a hybrid sparse/dense integer set.

v1 of this project used a purely dense []uint64 bitset. Benchmarking at 1M
policies showed why that caps out: every AND touched N/64 words and every
enumeration walked the whole universe, so cost scaled with the corpus size
rather than with the number of surviving candidates. End-to-end speedup
collapsed to ~1.1x even though the index was still cutting candidates 10x.

A Set here carries whichever representation fits its cardinality:

    sparse: sorted []uint32 of members   — O(k) space, O(log k) membership
    dense:  []uint64 bitmap              — O(n/64) space, O(1) membership

The engine's hot path exploits this: it materializes the single most selective
posting list, then filters that list in place against the remaining sets using
Contains. Cost becomes proportional to the candidate set, not to the corpus —
which is the property v1 was missing.

FUNCTIONS

func WordCount(n int) int
    WordCount reports how many 64-bit words a bitmap over [0, n) needs.
    The index layer sizes its word-parallel scratch buffers with it.


TYPES

type Builder struct {
	// Has unexported fields.
}
    Builder accumulates members efficiently when the final cardinality is not
    known in advance, deferring the representation choice to Build.

func NewBuilder(n int) *Builder

func (b *Builder) Add(i int)

func (b *Builder) Build() *Set

type Set struct {
	// Has unexported fields.
}
    Set is an immutable-after-Compact set of non-negative ints below Universe.

func FromSorted(members []uint32, n int) *Set
    FromSorted wraps an already-sorted, duplicate-free slice as a sparse set
    without copying. The caller must not mutate the slice afterwards.

func FromUnsorted(members []uint32, n int) *Set
    FromUnsorted sorts and dedupes members into a sparse set.

func Full(n int) *Set
    Full returns the set containing every element of [0, n).

func New(n int) *Set
    New returns an empty set over [0, n).

func NewDense(n int) *Set
    NewDense returns an empty dense set over [0, n). Used by builders that will
    set many bits and compact afterwards.

func (s *Set) Add(i int)
    Add inserts i. Only valid on dense sets during construction; call Compact
    when the build is finished.

func (s *Set) And(other *Set) *Set
    And returns the intersection. Build-time helper; the request hot path uses
    the filter-in-place approach in the index layer instead.

func (s *Set) AndNot(other *Set) *Set
    AndNot returns the difference s \ other. This is how negated conditions (ne,
    nin, ncidr) build their candidate sets: start from the universe of policies
    carrying the condition, remove the ones the request value hits.

func (s *Set) AppendMembers(dst []int) []int
    AppendMembers appends every member in ascending order to dst and returns the
    extended slice. Passing a reusable buffer keeps the hot path allocation-free
    across requests.

func (s *Set) Cardinality() int
    Cardinality returns the number of members.

func (s *Set) Compact() *Set
    Compact converts to whichever representation is smaller for the current
    cardinality. Called once at the end of index construction.

func (s *Set) Complement() *Set
    Complement returns [0, n) \ s.

func (s *Set) Contains(i int) bool
    Contains reports membership: O(1) on dense sets, O(log k) on sparse ones.
    This is the hot-path primitive — the engine's intersection filter calls it
    once per surviving candidate per attribute.

func (s *Set) IsSparse() bool
    IsSparse reports which representation is in use (exposed for tests and for
    the benchmark harness's reporting).

func (s *Set) Members() []int
    Members returns a freshly allocated slice of all members. Convenience for
    tests; the hot path uses AppendMembers with a reused buffer.

func (s *Set) Or(other *Set) *Set
    Or returns the union. Used at build time to fold multiple value postings
    into one set (e.g. an `in [a,b,c]` condition).

func (s *Set) OrWords(dst []uint64)
    OrWords sets, in dst, every bit this set holds. dst must hold at least
    WordCount(s.Universe()) words and is not cleared first, so successive calls
    accumulate a union.

    This is the bridge to the word-parallel intersection path. It exists because
    the alternative — exposing the backing array — would let a caller mutate a
    set that shards share across every request, and because a sparse set has no
    backing array to expose. Both representations can write themselves into a
    caller-owned buffer, and the buffer is what gets AND-ed.

func (s *Set) Universe() int
    Universe returns the size of the domain this set is defined over.

```

---

## internal/naive

The linear-scan oracle.

```go
package naive // import "github.com/suga/tessaraop/internal/naive"

Package naive implements the baseline evaluator: a linear scan over every
in-scope policy for every request.

It exists to be obviously correct rather than fast. It is the oracle the
differential tests compare the indexed engine against, and the O(N) reference
the benchmarks measure against. Any change to evaluation semantics has to land
in package model, where both evaluators read it from, so the two can never drift
apart.

TYPES

type Evaluator struct {
	Policies  []model.Policy
	Algorithm model.Algorithm

	// UnionObligations mirrors the engine setting, so the oracle and the fast
	// path answer the same question when it is enabled.
	UnionObligations bool
}
    Evaluator scans the full policy slice on every call.

func New(policies []model.Policy) *Evaluator
    New constructs a naive evaluator using deny-overrides.

func NewWith(policies []model.Policy, alg model.Algorithm) *Evaluator
    NewWith constructs a naive evaluator using the given combining algorithm.

func (e *Evaluator) Evaluate(req model.Request) model.Decision
    Evaluate scans every policy, and within each policy every rule. It applies
    the same tenant scoping the sharded engine does — a request only reaches its
    own tenant's policies plus the global ones — so the two are comparable on
    identical inputs.

    Both tiers run here exactly as they do in the indexed engine, because
    both call into package model to do the combining: rules resolve under the
    policy's RuleAlgorithm, then policy verdicts resolve under this evaluator's
    Algorithm. Nothing about the ordering is reimplemented, which is what makes
    this a trustworthy oracle for the differential tests.

```

---

## internal/indexed

Single-shard indexed evaluator; the benchmark control.

```go
package indexed // import "github.com/suga/tessaraop/internal/indexed"

Package indexed is a single-shard indexed evaluator.

It applies indexing without sharding, which makes it the control in the
benchmarks: comparing naive to indexed isolates what the index alone buys, and
comparing indexed to the sharded engine isolates what partitioning buys on top.
Keeping the two effects separable is what lets the results table attribute the
speedup honestly instead of reporting one blended number.

TYPES

type Evaluator struct {
	Algorithm model.Algorithm

	// UnionObligations mirrors the engine setting.
	UnionObligations bool
	// Has unexported fields.
}
    Evaluator indexes one flat policy set with no tenant partitioning.

func New(policies []model.Policy) *Evaluator
    New builds an indexed evaluator over the policies using deny-overrides.

func NewWith(policies []model.Policy, alg model.Algorithm) *Evaluator
    NewWith builds an indexed evaluator with an explicit combining algorithm.

func (e *Evaluator) Evaluate(req model.Request) model.Decision
    Evaluate narrows the rule set via the index, then applies exact match logic
    to the survivors under both combining tiers.

    Not safe for concurrent use: the scratch buffer is owned by this evaluator.
    The sharded engine pools scratch per goroutine and is the concurrent path.

func (e *Evaluator) TotalRules() int
    TotalRules reports the size of the indexed universe.

```

---

## internal/genutil

Synthetic multi-tenant corpus generator.

```go
package genutil // import "github.com/suga/tessaraop/internal/genutil"

Package genutil generates synthetic policy corpora and request streams that
resemble production authorization workloads.

Four properties matter for the benchmarks to mean anything.

First, a shared vocabulary. Values are drawn from small realistic sets (roles,
departments, CIDR blocks, ports, path roots) rather than being unique per
policy. Unique values would give every hash bucket exactly one member and make
indexing look far better than it is; real IAM corpora have thousands of policies
referencing the same handful of roles and networks.

Second, realistic tenancy. Policies are distributed across tenants with a skewed
distribution rather than uniformly, because real platforms have a few enormous
customers and a long tail of small ones. A uniform split would hide the worst
case that actually matters — the request that lands on the biggest shard.

Third, multi-rule policies. A policy carrying one implicitly-AND-ed condition
list is the easy case for the index; a policy holding several rules that must be
combined under a rule-level algorithm is the real one. Generated policies hold
between one and RulesPerPolicy rules.

Fourth, and most important now that conditions form boolean trees: a realistic
share of rules must sit partly *off* the AND-spine. Only leaves reachable
through exclusively And nodes can be indexed, so a corpus of pure conjunctions
would report a speedup the engine does not actually deliver on expressive
policy. Roughly a quarter of generated rules place a condition under an Or and a
further sixth under a Not, both of which are invisible to the index and must be
resolved by full validation.

TYPES

type Corpus struct {
	Policies []model.Policy
	Tenants  []string
	Scopes   []string
}
    Corpus is a generated policy set plus the tenants and scopes it spans.

func Generate(opt Options, rng *rand.Rand) *Corpus
    Generate builds a corpus. Tenant sizes follow a skewed distribution:
    tenant 0 is the whale, and size falls off from there, so benchmarks exercise
    both the common small shard and the pathological large one.

func (c *Corpus) GenerateRequest(rng *rand.Rand) model.Request
    GenerateRequest produces a request against a random tenant in the corpus.

func (c *Corpus) GenerateRequestFor(tenant string, rng *rand.Rand) model.Request
    GenerateRequestFor produces a request against a named tenant, for
    benchmarking a specific shard size.

func (c *Corpus) RuleCount() int
    RuleCount reports the total rule count, which is the size of the indexed
    universe and the number the per-request cost actually tracks.

type Options struct {
	Policies int // total policies to generate
	Tenants  int // number of tenants to spread them across
	Global   int // platform-wide policies applying to every request

	// RulesPerPolicy caps how many rules a generated policy holds. Zero means
	// 3. Set it to 1 to reproduce the pre-Rule flat corpus for comparison.
	RulesPerPolicy int
}
    Options controls corpus generation.

```

---

