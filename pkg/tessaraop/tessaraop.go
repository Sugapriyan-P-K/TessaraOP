// Package tessaraop is the public API of the TessaraOP policy decision engine.
//
// It is the only package an integration should import. Everything under
// internal/ is free to change shape between releases; the names here are the
// contract.
//
// # The shortest useful program
//
//	pdp, diags, err := tessaraop.OpenBundle("policies.json", tessaraop.Config{
//	    CacheSize: 8192,
//	})
//	if err != nil {
//	    log.Fatalf("policy bundle rejected: %v", tessaraop.FormatDiagnostics(diags))
//	}
//
//	req := tessaraop.NewRequest("acme", "identity").
//	    Str(tessaraop.AttrSubjectRole, "admin").
//	    Num(tessaraop.AttrRiskScore, 12).
//	    IPString(tessaraop.AttrSourceIP, "10.1.2.3").
//	    Build()
//
//	if d := pdp.Evaluate(req); !d.Allowed {
//	    http.Error(w, "forbidden", http.StatusForbidden)
//	    return
//	}
//
// # What this type guarantees
//
// A PDP is safe for concurrent use by any number of goroutines, and Reload
// swaps the whole policy set atomically: a request in flight either sees the
// old set entirely or the new one entirely, never a mixture. That is what makes
// it safe to ship policy on a different cadence from the binary.
//
// # Fail-closed is the default everywhere
//
// A request that omits an attribute does not match conditions on it — including
// negated ones. A policy set that fails to load leaves the previous set in place
// rather than emptying it. A malformed condition tree denies. If you want a
// different posture, express it as an explicit catch-all ALLOW rule at low
// priority, so it is visible in the bundle rather than implied by the engine.
package tessaraop

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/suga/tessaraop/internal/attr"
	"github.com/suga/tessaraop/internal/bundle"
	"github.com/suga/tessaraop/internal/engine"
	"github.com/suga/tessaraop/internal/explain"
	"github.com/suga/tessaraop/internal/hierarchy"
	"github.com/suga/tessaraop/internal/model"
	"github.com/suga/tessaraop/internal/relation"
)

// Core types, re-exported as aliases so callers never import internal packages
// and never need a conversion at the boundary.
type (
	// Request is one access check: a tenant, a scope, and typed attributes.
	Request = model.Request
	// Decision is the engine's answer.
	Decision = model.Decision
	// Policy is a tenanted collection of rules.
	Policy = model.Policy
	// Rule carries an effect and the condition tree that triggers it.
	Rule = model.Rule
	// Condition is a single predicate over one attribute.
	Condition = model.Condition
	// Expr is a boolean tree over conditions.
	Expr = model.ConditionExpr
	// Effect is ALLOW or DENY.
	Effect = model.Effect
	// Operator is a comparison.
	Operator = model.Operator
	// Algorithm selects how matching units combine.
	Algorithm = model.Algorithm

	// Bundle is the declarative policy format.
	Bundle = bundle.Bundle
	// Diagnostic is one linter finding.
	Diagnostic = bundle.Diagnostic
	// LintOptions tunes bundle validation.
	LintOptions = bundle.LintOptions
	// Attribute is a registry entry.
	Attribute = attr.Attribute
)

// Effects and combining algorithms.
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

// Operators. See the package documentation of the registry (or the -attrs output
// of cmd/tessaraop) for which apply to which attribute.
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

// Condition-tree builders.
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

// Config controls a PDP.
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

// PDP is a policy decision point: an immutable indexed policy set behind an
// atomic pointer, plus the counters an operator needs to see it working.
// installed is one atomically-swappable policy set: the indexed engine that
// answers requests, plus the policies themselves, which Explain needs because it
// deliberately bypasses the index.
type installed struct {
	eng      *engine.Engine
	policies []Policy
}

type PDP struct {
	cfg Config

	current atomic.Pointer[installed]

	// reload serializes Reload so two concurrent callers cannot interleave
	// building and swapping. Evaluate never takes it.
	reload sync.Mutex

	generation atomic.Uint64
	metrics    Metrics
}

// Metrics are cumulative counters, safe to read at any time.
//
// They are maintained with atomic adds on the evaluation path. That costs a few
// nanoseconds against a multi-microsecond evaluation, which is a trade worth
// making: an authorization component nobody can observe is one nobody will trust
// in production.
type Metrics struct {
	Evaluations atomic.Uint64
	Allowed     atomic.Uint64
	Denied      atomic.Uint64
	CacheHits   atomic.Uint64
	RulesTested atomic.Uint64
	Reloads     atomic.Uint64
}

// MetricsSnapshot is a point-in-time copy of the counters.
type MetricsSnapshot struct {
	Evaluations uint64 `json:"evaluations"`
	Allowed     uint64 `json:"allowed"`
	Denied      uint64 `json:"denied"`
	CacheHits   uint64 `json:"cache_hits"`
	RulesTested uint64 `json:"rules_tested"`
	Reloads     uint64 `json:"reloads"`
}

// New builds a PDP over policies held in memory.
func New(policies []Policy, cfg Config) (*PDP, error) {
	p := &PDP{cfg: cfg}
	if err := p.Reload(policies); err != nil {
		return nil, err
	}
	return p, nil
}

// ErrNoPolicies is returned when a load would leave the PDP with nothing.
//
// It is an error rather than an empty accept-nothing set because the two are
// indistinguishable at the call site and the consequences differ wildly: an
// empty set denies every request, which as a silent outcome of a mis-pathed file
// is an outage. Callers that genuinely want a deny-everything posture should say
// so with an explicit catch-all DENY policy.
var ErrNoPolicies = errors.New("tessaraop: policy set is empty")

// Reload replaces the policy set atomically.
//
// Requests in flight complete against whichever set they started on. If building
// the new set fails, the existing one stays in place — a bad deploy degrades to
// stale policy, never to no policy.
func (p *PDP) Reload(policies []Policy) error {
	if len(policies) == 0 {
		return ErrNoPolicies
	}
	p.reload.Lock()
	defer p.reload.Unlock()

	// Copy the slice header's contents: the engine retains the policies by
	// reference, and a caller reusing or appending to their slice afterwards
	// would otherwise mutate a live policy set.
	owned := make([]Policy, len(policies))
	copy(owned, policies)

	next := engine.New(owned, engine.Config{
		Algorithm:        p.cfg.Algorithm,
		CacheSize:        p.cfg.CacheSize,
		UnionObligations: p.cfg.UnionObligations,
	})
	p.current.Store(&installed{eng: next, policies: owned})
	p.generation.Add(1)
	p.metrics.Reloads.Add(1)
	return nil
}

// LoadBundle validates and installs a bundle read from r.
//
// Diagnostics are returned whether or not the load succeeded, so warnings on a
// good bundle still reach the caller's log. On error the previous policy set is
// untouched.
func (p *PDP) LoadBundle(r io.Reader) ([]Diagnostic, error) {
	b, err := bundle.Read(r)
	if err != nil {
		return nil, err
	}
	policies, diags, err := b.Compile(p.cfg.Lint)
	if err != nil {
		return diags, err
	}
	return diags, p.Reload(policies)
}

// LoadBundleFile is LoadBundle from a path.
func (p *PDP) LoadBundleFile(path string) ([]Diagnostic, error) {
	b, err := bundle.ReadFile(path)
	if err != nil {
		return nil, err
	}
	policies, diags, err := b.Compile(p.cfg.Lint)
	if err != nil {
		return diags, err
	}
	return diags, p.Reload(policies)
}

// OpenBundle builds a PDP from a bundle file in one call.
func OpenBundle(path string, cfg Config) (*PDP, []Diagnostic, error) {
	b, err := bundle.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	return openBundle(b, cfg)
}

// ReadBundle builds a PDP from a bundle read from r.
func ReadBundle(r io.Reader, cfg Config) (*PDP, []Diagnostic, error) {
	b, err := bundle.Read(r)
	if err != nil {
		return nil, nil, err
	}
	return openBundle(b, cfg)
}

func openBundle(b *Bundle, cfg Config) (*PDP, []Diagnostic, error) {
	policies, diags, err := b.Compile(cfg.Lint)
	if err != nil {
		return nil, diags, err
	}
	pdp, err := New(policies, cfg)
	if err != nil {
		return nil, diags, err
	}
	return pdp, diags, nil
}

// Evaluate renders a decision. Safe for concurrent use.
func (p *PDP) Evaluate(req Request) Decision {
	cur := p.current.Load()
	if cur == nil {
		// Only reachable if a caller built a zero-value PDP directly instead of
		// through New. Fail closed rather than panic in a request path.
		return Decision{Allowed: false, Effect: Deny}
	}
	d := cur.eng.Evaluate(req)

	p.metrics.Evaluations.Add(1)
	p.metrics.RulesTested.Add(uint64(d.RulesScanned))
	if d.Allowed {
		p.metrics.Allowed.Add(1)
	} else {
		p.metrics.Denied.Add(1)
	}
	if d.CacheHit {
		p.metrics.CacheHits.Add(1)
	}
	return d
}

// Allowed is Evaluate reduced to a boolean, for call sites that do not act on
// obligations. Prefer Evaluate: dropping the obligations silently discards
// requirements like require_mfa that a policy author expected to be enforced.
func (p *PDP) Allowed(req Request) bool {
	return p.Evaluate(req).Allowed
}

// Generation counts how many policy sets have been installed. It changes on
// every successful Reload, which makes it the value to expose in a readiness
// probe or compare across a fleet to confirm a rollout landed.
func (p *PDP) Generation() uint64 { return p.generation.Load() }

// Metrics returns a snapshot of the counters.
func (p *PDP) Metrics() MetricsSnapshot {
	return MetricsSnapshot{
		Evaluations: p.metrics.Evaluations.Load(),
		Allowed:     p.metrics.Allowed.Load(),
		Denied:      p.metrics.Denied.Load(),
		CacheHits:   p.metrics.CacheHits.Load(),
		RulesTested: p.metrics.RulesTested.Load(),
		Reloads:     p.metrics.Reloads.Load(),
	}
}

// Info describes the installed policy set.
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

// Info reports what is currently installed.
func (p *PDP) Info() Info {
	cur := p.current.Load()
	if cur == nil {
		return Info{Generation: p.generation.Load()}
	}
	eng := cur.eng
	alg := p.cfg.Algorithm
	if alg == "" {
		alg = DenyOverrides
	}
	return Info{
		Generation:      p.generation.Load(),
		Policies:        eng.TotalPolicies(),
		Rules:           eng.TotalRules(),
		Tenants:         eng.TenantCount(),
		Shards:          eng.ShardCount(),
		Algorithm:       string(alg),
		CacheEnabled:    p.cfg.CacheSize > 0,
		CacheSizeHint:   p.cfg.CacheSize,
		RulesInUniverse: eng.TotalRules(),
	}
}

// ReachableRules reports how many rules a request to this tenant and scope can
// reach. It is the number that governs per-request cost, and the one to watch
// when a customer's shard grows.
func (p *PDP) ReachableRules(tenantID, scope string) int {
	cur := p.current.Load()
	if cur == nil {
		return 0
	}
	return cur.eng.InScope(tenantID, scope)
}

// --- Explain ----------------------------------------------------------------

// Explanation is the full account of why a decision came out as it did.
type Explanation = explain.Explanation

// ExplainOptions controls how much an explanation reveals.
type ExplainOptions = explain.Options

// DefaultExplainOptions redacts observed attribute values, includes rules that
// did not match, and omits policies the request could not reach.
func DefaultExplainOptions() ExplainOptions { return explain.DefaultOptions() }

// Explain reports why the request produced the decision it did: which policies
// were in scope, which rules were evaluated, and for each condition whether the
// attribute was present and whether it matched.
//
// It is a deliberately slower second path. Evaluate is allocation-free and runs
// in microseconds; threading a trace through it would cost that for every
// request in order to serve the rare one where somebody is asking a question. So
// Explain bypasses the index, evaluates every in-scope rule, and short-circuits
// nowhere — an author wants every failing condition, not the first one checked.
//
// Do not call it on the hot path. Call it from a support tool, a CLI, or an
// endpoint a human hits.
//
// The returned Decision is computed on the same inputs as Evaluate and is
// asserted to agree with it; an explanation that contradicted the decision would
// be worse than none, because it would be believed.
func (p *PDP) Explain(req Request, opt ExplainOptions) *Explanation {
	cur := p.current.Load()
	if cur == nil {
		return &Explanation{
			Decision: Decision{Allowed: false, Effect: Deny},
			Summary:  "DENIED: no policy set is installed",
		}
	}
	alg := p.cfg.Algorithm
	if alg == "" {
		alg = DenyOverrides
	}
	return explain.Explain(cur.policies, req, alg, opt)
}

// Policies returns the installed policy set. The slice is owned by the PDP and
// must not be modified; copy it if you need to.
func (p *PDP) Policies() []Policy {
	cur := p.current.Load()
	if cur == nil {
		return nil
	}
	return cur.policies
}

// --- Bundle helpers ---------------------------------------------------------

// LintBundle validates a bundle without installing it. Use it in CI: a policy
// change should fail the pipeline, not the request path.
func LintBundle(r io.Reader, opt LintOptions) ([]Diagnostic, error) {
	b, err := bundle.Read(r)
	if err != nil {
		return nil, err
	}
	return b.Lint(opt), nil
}

// LintBundleFile is LintBundle from a path.
func LintBundleFile(path string, opt LintOptions) ([]Diagnostic, error) {
	b, err := bundle.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return b.Lint(opt), nil
}

// ValidatePolicies runs the same checks over programmatically built policies, so
// an SDK caller gets the linter too rather than only bundle authors.
func ValidatePolicies(policies []Policy, opt LintOptions) []Diagnostic {
	return bundle.FromPolicies(policies).Lint(opt)
}

// ExportBundle serializes policies to the declarative format. Useful to migrate
// a hand-coded integration onto files, and to snapshot what a running PDP holds.
func ExportBundle(policies []Policy, w io.Writer) error {
	return bundle.FromPolicies(policies).Write(w)
}

// HasErrors reports whether any diagnostic blocks loading.
func HasErrors(diags []Diagnostic) bool { return bundle.HasErrors(diags) }

// Errors returns only the blocking diagnostics, for a caller that wants to count
// or report them separately from warnings.
func Errors(diags []Diagnostic) []Diagnostic { return bundle.Errors(diags) }

// FormatDiagnostics renders diagnostics one per line, errors first, for a log
// line or a CI annotation.
func FormatDiagnostics(diags []Diagnostic) string {
	if len(diags) == 0 {
		return "no findings"
	}
	var b strings.Builder
	for _, d := range bundle.Errors(diags) {
		fmt.Fprintf(&b, "%s\n", d)
	}
	for _, d := range diags {
		if d.Severity != bundle.Error {
			fmt.Fprintf(&b, "%s\n", d)
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

// --- Attribute registry ----------------------------------------------------

// Attributes returns every registered attribute, so an integration can generate
// its own onboarding documentation or offer authoring completions.
func Attributes() []Attribute { return attr.Catalog }

// LookupAttribute resolves a name, matching open-ended namespaces by prefix.
func LookupAttribute(name string) (Attribute, bool) { return attr.Lookup(name) }

// Well-known attribute names. The registry holds many more; these are the ones
// integrations touch most. Using a constant makes a typo a compile error rather
// than a rule that silently never matches.
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

// --- Role, group and resource hierarchies -----------------------------------

// Hierarchy is a membership DAG: role inheritance, nested groups, or resource
// containment.
//
// It is resolved *outside* the engine. A principal holding "admin" in a graph
// where admin inherits editor inherits viewer arrives carrying
// subject.roles = "admin,editor,viewer", and an ordinary indexed operator
// (OpHasAny) answers the question. The engine gains no new concept, the index
// still prunes, and the evaluation path is untouched — the same division of
// labour that keeps parsing and I/O outside the hot path.
type Hierarchy = hierarchy.Graph

// NewHierarchy returns an empty, unfrozen membership graph. Call Add to record
// that a child is subsumed by its parents, then Freeze.
func NewHierarchy() *Hierarchy { return hierarchy.New() }

// HierarchyFromMap builds and freezes a graph from a child -> parents mapping,
// which is the shape a configuration file naturally carries. It reports an error
// if the graph contains a cycle.
//
//	roles, err := tessaraop.HierarchyFromMap(map[string][]string{
//	    "admin":  {"editor"},
//	    "editor": {"viewer"},
//	})
func HierarchyFromMap(m map[string][]string) (*Hierarchy, error) {
	return hierarchy.FromMap(m)
}

// ErrHierarchyCycle is reported when a membership graph is not acyclic. A cycle
// is always an authoring mistake, and tolerating one would make a principal's
// effective roles depend on traversal order.
var ErrHierarchyCycle = hierarchy.ErrCycle

// --- Relationships (ReBAC) --------------------------------------------------

// RelationResolver answers what relations a subject holds to an object.
//
// Relationships are *consumed*, not stored: TessaraOP does not implement a
// Zanzibar-style tuple store, because that would require a database and turn a
// stateless drop-in component into a stateful service. Instead a resolver is
// called once per request, before evaluation, and the answer is materialized
// into subject.relations where an indexed operator (OpHasAny) matches it.
//
// Implement this against OpenFGA, SpiceDB or your own service. See package
// relation for the adapter contract and for the in-memory implementation used in
// tests and small deployments.
type RelationResolver = relation.Resolver

// RelationTuple is one relationship fact.
type RelationTuple = relation.Tuple

// AttrSubjectRelations is where ResolveRelations puts its answer. Match it with
// OpHasAny / OpHasAll / OpHasNone.
const AttrSubjectRelations = relation.SubjectRelations

// NewStaticRelations returns an in-memory relationship resolver.
//
// It is not a substitute for a real ReBAC store — no persistence, no consistency
// model, no reverse index — but it covers tests, local development, and
// deployments whose relationship set is genuinely small and static.
func NewStaticRelations(tuples ...RelationTuple) *relation.Static {
	return relation.NewStatic().Add(tuples...)
}

// ResolveRelations resolves the subject's relations to the object and writes them
// into the request, ready for evaluation.
//
// Call it while assembling a request, never on a hot loop: a resolver may perform
// I/O. Wrap a remote one in RelationTimeout.
func ResolveRelations(ctx context.Context, r RelationResolver, req *Request, subject, object string) error {
	return relation.Apply(ctx, r, req, subject, object)
}

// RelationTimeout bounds how long a resolver may take. A remote relationship
// store sits in the request path, so an unbounded call there is an availability
// risk for everything behind it.
func RelationTimeout(r RelationResolver, d time.Duration) RelationResolver {
	return relation.WithTimeout(r, d)
}

// RelationCache memoizes resolutions for a bounded time. A cached relationship is
// a stale authorization decision, so the TTL is required and there is no
// invalidation hook — if your relationships must take effect immediately, cache
// them where the writes are instead.
func RelationCache(r RelationResolver, ttl time.Duration) RelationResolver {
	return relation.NewCache(r, ttl)
}

// Header returns the attribute name for an HTTP request header.
func Header(name string) string { return attr.Header(name) }

// QueryParam returns the attribute name for a URL query parameter.
func QueryParam(name string) string { return attr.QueryParam(name) }

// Cookie returns the attribute name for a cookie.
func Cookie(name string) string { return attr.Cookie(name) }

// Claim returns the attribute name for a token claim.
func Claim(name string) string { return attr.Claim(name) }

// --- Request building ------------------------------------------------------

// RequestBuilder assembles a Request with the right typed map per attribute.
//
// Putting a value in the wrong map is the most common integration mistake and
// the hardest to notice: a port supplied as a string is invisible to every
// numeric operator, so the rule guarding it silently never fires. The builder's
// per-type methods make the choice explicit, and Validate cross-checks it
// against the registry.
type RequestBuilder struct {
	req  Request
	errs []string
}

// NewRequest starts a builder for a tenant and scope. An empty scope means the
// request reaches only the tenant-wide and global shards.
func NewRequest(tenantID, scope string) *RequestBuilder {
	return &RequestBuilder{req: Request{
		TenantID:   tenantID,
		Scope:      scope,
		Attributes: map[string]string{},
		Numeric:    map[string]float64{},
		IPs:        map[string]netip.Addr{},
	}}
}

// Str sets a string attribute. An empty name is ignored; an empty value is kept,
// since "present but empty" is distinguishable from absent and policies rely on
// that distinction.
func (b *RequestBuilder) Str(name, value string) *RequestBuilder {
	if name != "" {
		b.req.Attributes[name] = value
	}
	return b
}

// Bool sets a string attribute to "true" or "false". Boolean-valued attributes
// in the registry are strings, so that set membership and negation work on them
// uniformly with everything else.
func (b *RequestBuilder) Bool(name string, value bool) *RequestBuilder {
	if value {
		return b.Str(name, "true")
	}
	return b.Str(name, "false")
}

// Strs joins values with commas, which is the convention the registry documents
// for multi-valued string attributes such as subject.groups and token.scopes.
// Match them with the contains operator.
func (b *RequestBuilder) Strs(name string, values ...string) *RequestBuilder {
	return b.Str(name, strings.Join(values, ","))
}

// Num sets a numeric attribute.
func (b *RequestBuilder) Num(name string, value float64) *RequestBuilder {
	if name != "" {
		b.req.Numeric[name] = value
	}
	return b
}

// Int sets a numeric attribute from an int.
func (b *RequestBuilder) Int(name string, value int) *RequestBuilder {
	return b.Num(name, float64(value))
}

// IP sets an IP attribute.
func (b *RequestBuilder) IP(name string, addr netip.Addr) *RequestBuilder {
	if name != "" && addr.IsValid() {
		b.req.IPs[name] = addr
	}
	return b
}

// IPString parses and sets an IP attribute, recording a builder error if the
// value does not parse. An unparsable address is dropped rather than guessed at:
// substituting a zero address would make a CIDR condition match a block it
// should not.
func (b *RequestBuilder) IPString(name, value string) *RequestBuilder {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		// Strip a port if the caller passed host:port, which is what
		// net.Conn.RemoteAddr().String() yields.
		if ap, perr := netip.ParseAddrPort(value); perr == nil {
			return b.IP(name, ap.Addr())
		}
		b.errs = append(b.errs, fmt.Sprintf("%s: %q is not an IP address", name, value))
		return b
	}
	return b.IP(name, addr)
}

// Build returns the request. Empty maps are dropped so the decision cache hashes
// the same logical request identically however it was built.
func (b *RequestBuilder) Build() Request {
	r := b.req
	if len(r.Attributes) == 0 {
		r.Attributes = nil
	}
	if len(r.Numeric) == 0 {
		r.Numeric = nil
	}
	if len(r.IPs) == 0 {
		r.IPs = nil
	}
	return r
}

// Err reports parse failures accumulated during building, and any attribute
// supplied in a map the registry does not declare for it. Checking it is
// optional but strongly advised during integration: it turns the silent
// wrong-map mistake into a visible one.
func (b *RequestBuilder) Err() error {
	problems := append([]string(nil), b.errs...)

	check := func(name string, got attr.Kind) {
		a, ok := attr.Lookup(name)
		if !ok {
			return // unregistered names are the customer's own vocabulary
		}
		if a.Kind != got {
			problems = append(problems, fmt.Sprintf(
				"%s is registered as %s but was supplied as %s; no %s operator can read it",
				name, a.Kind, got, got))
		}
	}
	for name := range b.req.Attributes {
		check(name, attr.KindString)
	}
	for name := range b.req.Numeric {
		check(name, attr.KindNumeric)
	}
	for name := range b.req.IPs {
		check(name, attr.KindIP)
	}

	if len(problems) == 0 {
		return nil
	}
	return errors.New("tessaraop: request: " + strings.Join(problems, "; "))
}
