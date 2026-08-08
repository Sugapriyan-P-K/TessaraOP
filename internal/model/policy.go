package model

// GlobalTenant holds platform-wide policies evaluated for every request
// regardless of the request's own tenant (blocklists, kill switches).
const GlobalTenant = "__global__"

// TenantWideScope is the scope of policies applying across an entire tenant,
// evaluated alongside whichever scope a request names.
const TenantWideScope = ""

// Rule is the unit that carries an Effect: if When matches, Effect applies and
// Obligations attach to the decision.
//
// A nil When matches everything, which is how a catch-all rule is expressed —
// the default-deny backstop at the bottom of a policy, or a blanket grant.
type Rule struct {
	ID       string
	Effect   Effect
	Priority int // higher wins under FirstApplicable; ignored by the overrides algorithms

	When *ConditionExpr

	Obligations []string // e.g. require_mfa, audit_log — carried into the Decision
}

// NewRule is a convenience constructor for the common case.
func NewRule(id string, effect Effect, when *ConditionExpr, obligations ...string) Rule {
	return Rule{ID: id, Effect: effect, When: when, Obligations: obligations}
}

// Policy is a named collection of Rules sharing a tenant, a scope and a
// rule-combining algorithm.
//
// TenantID and Scope together form the shard key, and that pairing is what
// makes a multi-million policy corpus tractable: the working set per request is
// one shard, not the corpus.
//
// Scope subdivides a tenant, typically by resource type or application. It
// exists because tenant alone is not a fine enough partition — real corpora are
// heavily skewed, and a single large customer can hold a six-figure policy
// count that no amount of indexing makes fast on its own. Production systems
// partition the same way: Zanzibar by namespace, IAM by principal and resource,
// Envoy RBAC per listener. A policy with an empty Scope applies across its
// whole tenant.
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

// SimplePolicy builds a single-rule policy from a flat AND-ed condition list.
//
// It exists because that shape covers most real policies and all of the
// pre-Rule corpus, and asking every caller to spell out a one-element Rules
// slice wrapping an AllOf tree obscures what the policy says. Onboarding
// integrations and tests use it heavily.
func SimplePolicy(id, tenantID, scope string, effect Effect, priority int, conds []Condition, obligations ...string) Policy {
	return Policy{
		ID:       id,
		TenantID: tenantID,
		Scope:    scope,
		Priority: priority,
		Rules: []Rule{{
			ID:          id + "/r0",
			Effect:      effect,
			Priority:    priority,
			When:        AllOf(conds...),
			Obligations: obligations,
		}},
	}
}

// RuleCount reports how many rules this policy holds. The index universe is the
// sum of this across a shard, since a rule — not a policy — is the atomic
// indexed unit.
func (p *Policy) RuleCount() int { return len(p.Rules) }

// Prepare compiles every regular expression in every rule, reporting the first
// failure. Index construction calls it, so evaluation never compiles.
func (p *Policy) Prepare() error {
	for i := range p.Rules {
		if err := p.Rules[i].When.Prepare(); err != nil {
			return err
		}
	}
	return nil
}

// Resolve applies every rule in this policy and combines the matches under the
// policy's RuleAlgorithm. This is tier one of the two-tier evaluation: it turns
// a policy into at most one Verdict.
//
// It reports the verdict, whether any rule matched at all, and how many rules
// reached exact validation.
func (p *Policy) Resolve(req Request) (Verdict, bool, int) {
	return p.ResolveUnion(req, false)
}

// ResolveUnion is Resolve with explicit control over obligation union semantics,
// so the inner tier applies the same rule the outer one was configured with.
func (p *Policy) ResolveUnion(req Request, unionObligations bool) (Verdict, bool, int) {
	var acc Accumulator
	acc.UnionObligations = unionObligations
	acc.Reset(p.RuleAlgorithm)
	scanned := 0
	for i := range p.Rules {
		scanned++
		if p.Rules[i].When.Matches(req) {
			acc.Consider(p.verdict(i))
			if acc.CanShortCircuit() {
				break
			}
		}
	}
	v, ok := acc.Winner()
	if ok {
		if union := acc.obligationsFor(v.Effect); union != nil {
			v.Obligations = union
		}
	}
	return v, ok, scanned
}

// ResolveAt is Resolve restricted to the rule positions the index produced.
// Positions outside the rule slice are ignored rather than panicking, so an
// index that has drifted from its policies degrades to under-selective instead
// of crashing the decision path.
func (p *Policy) ResolveAt(req Request, positions []int) (Verdict, bool, int) {
	return p.ResolveAtUnion(req, positions, false)
}

// ResolveAtUnion is ResolveAt with explicit obligation union semantics.
func (p *Policy) ResolveAtUnion(req Request, positions []int, unionObligations bool) (Verdict, bool, int) {
	var acc Accumulator
	acc.UnionObligations = unionObligations
	acc.Reset(p.RuleAlgorithm)
	scanned := 0
	for _, i := range positions {
		if i < 0 || i >= len(p.Rules) {
			continue
		}
		scanned++
		if p.Rules[i].When.Matches(req) {
			acc.Consider(p.verdict(i))
			if acc.CanShortCircuit() {
				break
			}
		}
	}
	v, ok := acc.Winner()
	if ok {
		if union := acc.obligationsFor(v.Effect); union != nil {
			v.Obligations = union
		}
	}
	return v, ok, scanned
}

// verdict builds the inner-tier verdict for rule i. Priority is the rule's,
// because the inner tier orders rules against each other.
func (p *Policy) verdict(i int) Verdict {
	r := &p.Rules[i]
	return Verdict{
		PolicyID:    p.ID,
		RuleID:      r.ID,
		Effect:      r.Effect,
		Priority:    r.Priority,
		Obligations: r.Obligations,
	}
}

// Algorithm selects how multiple matching units combine into one outcome. The
// same three algorithms serve both tiers: rules within a policy, and policies
// within a shard.
type Algorithm string

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

// AllAlgorithms lists every combining algorithm, for the linter and docs.
//
// The XACML "ordered-" variants are deliberately absent. They resolve ties by
// document order, and this engine's index yields candidates in whatever order
// the underlying sets enumerate — so honouring document order would mean sorting
// every candidate set and forfeiting the short-circuiting that order-independence
// buys. FirstApplicable covers the same intent with an explicit Priority, which
// is order-independent and therefore sound here.
var AllAlgorithms = []Algorithm{
	DenyOverrides, PermitOverrides, FirstApplicable,
	DenyUnlessPermit, PermitUnlessDeny, OnlyOneApplicable,
}

// Verdict is one resolved outcome, produced by either tier. The inner tier
// emits a Verdict per matching rule; the outer tier emits one per matching
// policy. Carrying both IDs is what makes attribution correct: the rule that
// actually fired is threaded through from the moment it matched, never
// reconstructed afterwards by scanning for some rule with the winning effect —
// two same-effect rules in one policy would otherwise be misattributed.
type Verdict struct {
	PolicyID    string
	RuleID      string
	Effect      Effect
	Priority    int
	Obligations []string
}

// Accumulator collects matching verdicts during a scan and resolves them under
// the chosen Algorithm. Both tiers and both evaluators drive this same type, so
// combining semantics cannot drift between them.
//
// The zero value is usable after Reset, which is what lets the inner tier keep
// one on the stack per policy instead of allocating per request.
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

	foundDeny bool
	deny      Verdict

	foundAllow bool
	allow      Verdict

	foundBest bool
	best      Verdict

	// applicable counts matching verdicts, for OnlyOneApplicable.
	applicable int

	// Collected per effect, since the winning effect is not known until Resolve.
	denyObligations  []string
	allowObligations []string

	policiesScanned int
	rulesScanned    int
}

// NewAccumulator returns an accumulator for the given algorithm. Empty means
// DenyOverrides.
func NewAccumulator(alg Algorithm) *Accumulator {
	a := &Accumulator{}
	a.Reset(alg)
	return a
}

// Reset clears the accumulator for reuse under alg. Empty alg means
// DenyOverrides.
// Reset preserves UnionObligations, so the inner tier inherits the outer tier's
// obligation semantics rather than silently diverging from it.
func (a *Accumulator) Reset(alg Algorithm) {
	if alg == "" {
		alg = DenyOverrides
	}
	union := a.UnionObligations
	*a = Accumulator{Algorithm: alg, UnionObligations: union}
}

// Consider feeds one verdict that has already been confirmed to apply.
func (a *Accumulator) Consider(v Verdict) {
	a.applicable++

	if a.UnionObligations && len(v.Obligations) > 0 {
		if v.Effect == Deny {
			a.denyObligations = appendMissing(a.denyObligations, v.Obligations)
		} else {
			a.allowObligations = appendMissing(a.allowObligations, v.Obligations)
		}
	}

	switch a.Algorithm {
	case FirstApplicable, OnlyOneApplicable:
		// OnlyOneApplicable shares the priority ordering so that when exactly one
		// verdict applies it is credited deterministically; the ambiguity check
		// happens in Winner.
		if !a.foundBest || outranks(v, a.best) {
			a.foundBest = true
			a.best = v
		}
	default:
		if v.Effect == Deny {
			if !a.foundDeny {
				a.foundDeny = true
				a.deny = v
			}
		} else {
			if !a.foundAllow {
				a.foundAllow = true
				a.allow = v
			}
		}
	}
}

// appendMissing adds any obligation not already present, preserving order. The
// lists are short — a handful of entries — so a linear scan beats a map.
func appendMissing(dst, src []string) []string {
	for _, s := range src {
		found := false
		for _, existing := range dst {
			if existing == s {
				found = true
				break
			}
		}
		if !found {
			dst = append(dst, s)
		}
	}
	return dst
}

// outranks reports whether a should beat b under FirstApplicable.
//
// The comparison is (Priority desc, PolicyID asc, RuleID asc). One function
// serves both tiers: within a policy every candidate shares a PolicyID so it
// reduces to rule ID, and across policies the IDs are distinct so rule ID is
// never reached. That avoids a second, subtly different comparator.
func outranks(a, b Verdict) bool {
	if a.Priority != b.Priority {
		return a.Priority > b.Priority
	}
	if a.PolicyID != b.PolicyID {
		return a.PolicyID < b.PolicyID
	}
	return a.RuleID < b.RuleID
}

// CanShortCircuit reports whether the outcome is already decided, so the caller
// may stop scanning. Only DenyOverrides can short-circuit (on the first Deny) —
// the others must see every candidate.
func (a *Accumulator) CanShortCircuit() bool {
	if a.UnionObligations {
		// Stopping early would miss obligations on candidates not yet seen, which
		// is the whole point of collecting them.
		return false
	}
	return a.Algorithm == DenyOverrides && a.foundDeny
}

// SetScanned records how much reached exact validation.
func (a *Accumulator) SetScanned(policies, rules int) {
	a.policiesScanned = policies
	a.rulesScanned = rules
}

// Winner returns the verdict the algorithm selects, and whether anything
// matched. The inner tier uses this directly to produce the policy's verdict.
func (a *Accumulator) Winner() (Verdict, bool) {
	switch a.Algorithm {
	case FirstApplicable:
		return a.best, a.foundBest

	case OnlyOneApplicable:
		// Several applicable units is Indeterminate. Reporting no winner resolves
		// it to a deny at the outer tier, which is the fail-closed reading — and
		// the point of choosing this algorithm is that the overlap is a
		// configuration error, so it must not be silently arbitrated.
		if a.applicable == 1 {
			return a.best, true
		}
		return Verdict{}, false

	case PermitOverrides, DenyUnlessPermit:
		if a.foundAllow {
			return a.allow, true
		}
		if a.Algorithm == DenyUnlessPermit {
			// Never credits a Deny: this algorithm resolves to Permit or Deny and
			// nothing else, so an unmatched Allow simply means Deny with no
			// attribution.
			return Verdict{}, false
		}
		if a.foundDeny {
			return a.deny, true
		}

	case PermitUnlessDeny:
		if a.foundDeny {
			return a.deny, true
		}
		return Verdict{}, false

	default: // DenyOverrides
		if a.foundDeny {
			return a.deny, true
		}
		if a.foundAllow {
			return a.allow, true
		}
	}
	return Verdict{}, false
}

// obligationsFor returns the collected obligations for an effect when union
// semantics are on, and nil otherwise.
func (a *Accumulator) obligationsFor(e Effect) []string {
	if !a.UnionObligations {
		return nil
	}
	if e == Deny {
		return a.denyObligations
	}
	return a.allowObligations
}

// Resolve produces the final decision under the configured algorithm.
func (a *Accumulator) Resolve() Decision {
	v, ok := a.Winner()
	if !ok {
		// Nothing was credited. Every algorithm but one resolves that to a deny.
		//
		// PermitUnlessDeny is the exception: it grants unless a Deny matched, so
		// an unmatched request is ALLOWED. That inverts the fail-closed posture
		// the rest of this engine holds to, which is why the algorithm's
		// documentation says to confine it to a shard whose contents are
		// exhaustively known.
		if a.Algorithm == PermitUnlessDeny {
			return Decision{
				Allowed:         true,
				Effect:          Allow,
				Obligations:     a.obligationsFor(Allow),
				PoliciesScanned: a.policiesScanned,
				RulesScanned:    a.rulesScanned,
			}
		}
		return Decision{
			Allowed:         false,
			Effect:          Deny,
			Obligations:     a.obligationsFor(Deny),
			PoliciesScanned: a.policiesScanned,
			RulesScanned:    a.rulesScanned,
		}
	}

	obligations := v.Obligations
	if union := a.obligationsFor(v.Effect); union != nil {
		obligations = union
	}
	return Decision{
		Allowed:         v.Effect == Allow,
		Effect:          v.Effect,
		MatchedPolicyID: v.PolicyID,
		MatchedRuleID:   v.RuleID,
		Obligations:     obligations,
		PoliciesScanned: a.policiesScanned,
		RulesScanned:    a.rulesScanned,
	}
}

// outerVerdict rewrites an inner-tier verdict for the cross-policy tier,
// substituting the policy's own priority. The outer tier orders policies
// against each other, so it must not inherit whatever priority the matching
// rule happened to carry.
func outerVerdict(p *Policy, v Verdict) Verdict {
	v.Priority = p.Priority
	return v
}

// Evaluate scans every policy in the slice, applying both tiers. This is the
// reference implementation used by the naive evaluator and by differential
// tests. It applies no tenant scoping — callers that need it filter first.
func Evaluate(policies []Policy, req Request, alg Algorithm) Decision {
	return EvaluateUnion(policies, req, alg, false)
}

// EvaluateUnion is Evaluate with explicit obligation union semantics. The naive
// evaluator and the indexed engine both route through this, so a differential
// test can exercise union mode on both sides.
func EvaluateUnion(policies []Policy, req Request, alg Algorithm, unionObligations bool) Decision {
	acc := NewAccumulator(alg)
	acc.UnionObligations = unionObligations
	rules := 0
	for i := range policies {
		rules += ConsiderPolicy(&policies[i], req, allRulePositions(&policies[i]), acc)
		if acc.CanShortCircuit() {
			break
		}
	}
	acc.SetScanned(len(policies), rules)
	return acc.Resolve()
}

// allRulePositions returns every rule index in p. Only the reference path uses
// it; the indexed path supplies the positions the index selected.
func allRulePositions(p *Policy) []int {
	out := make([]int, len(p.Rules))
	for i := range out {
		out[i] = i
	}
	return out
}

// EvaluatePolicyPositions validates only the policies at the given positions,
// indexing into the original slice rather than copying them into a new one. The
// copy version allocated proportionally to candidate-set size and showed up
// directly in benchmark allocs/op.
func EvaluatePolicyPositions(policies []Policy, positions []int, req Request, alg Algorithm) Decision {
	acc := NewAccumulator(alg)
	rules := 0
	for _, idx := range positions {
		v, ok, scanned := policies[idx].Resolve(req)
		rules += scanned
		if ok {
			acc.Consider(outerVerdict(&policies[idx], v))
			if acc.CanShortCircuit() {
				break
			}
		}
	}
	acc.SetScanned(len(positions), rules)
	return acc.Resolve()
}

// ConsiderPolicy resolves one policy's inner tier and feeds the result to an
// outer-tier accumulator. It is the seam the indexed engine drives, so the
// index layer never reimplements tier-one combination.
//
// positions names the rule indices the index selected as candidates. It returns
// how many rules reached exact validation.
func ConsiderPolicy(p *Policy, req Request, positions []int, acc *Accumulator) int {
	v, ok, scanned := p.ResolveAtUnion(req, positions, acc.UnionObligations)
	if ok {
		acc.Consider(outerVerdict(p, v))
	}
	return scanned
}
