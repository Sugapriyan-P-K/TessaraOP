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
	var acc Accumulator
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
	return v, ok, scanned
}

// ResolveAt is Resolve restricted to the rule positions the index produced.
// Positions outside the rule slice are ignored rather than panicking, so an
// index that has drifted from its policies degrades to under-selective instead
// of crashing the decision path.
func (p *Policy) ResolveAt(req Request, positions []int) (Verdict, bool, int) {
	var acc Accumulator
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
)

// AllAlgorithms lists every combining algorithm, for the linter and docs.
var AllAlgorithms = []Algorithm{DenyOverrides, PermitOverrides, FirstApplicable}

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

	foundDeny bool
	deny      Verdict

	foundAllow bool
	allow      Verdict

	foundBest bool
	best      Verdict

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
func (a *Accumulator) Reset(alg Algorithm) {
	if alg == "" {
		alg = DenyOverrides
	}
	*a = Accumulator{Algorithm: alg}
}

// Consider feeds one verdict that has already been confirmed to apply.
func (a *Accumulator) Consider(v Verdict) {
	switch a.Algorithm {
	case FirstApplicable:
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
	case PermitOverrides:
		if a.foundAllow {
			return a.allow, true
		}
		if a.foundDeny {
			return a.deny, true
		}
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

// Resolve produces the final decision under the configured algorithm.
func (a *Accumulator) Resolve() Decision {
	v, ok := a.Winner()
	if !ok {
		// Default deny: nothing matched at all.
		return Decision{
			Allowed:         false,
			Effect:          Deny,
			PoliciesScanned: a.policiesScanned,
			RulesScanned:    a.rulesScanned,
		}
	}
	return Decision{
		Allowed:         v.Effect == Allow,
		Effect:          v.Effect,
		MatchedPolicyID: v.PolicyID,
		MatchedRuleID:   v.RuleID,
		Obligations:     v.Obligations,
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
	acc := NewAccumulator(alg)
	rules := 0
	for i := range policies {
		v, ok, scanned := policies[i].Resolve(req)
		rules += scanned
		if ok {
			acc.Consider(outerVerdict(&policies[i], v))
			if acc.CanShortCircuit() {
				break
			}
		}
	}
	acc.SetScanned(len(policies), rules)
	return acc.Resolve()
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
	v, ok, scanned := p.ResolveAt(req, positions)
	if ok {
		acc.Consider(outerVerdict(p, v))
	}
	return scanned
}
