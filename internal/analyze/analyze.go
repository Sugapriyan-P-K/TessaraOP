// Package analyze finds policy defects that testing cannot: rules that can never
// fire, rules shadowed by others, and pairs that contradict each other.
//
// # What this buys, and why it needs a BDD
//
// Everything else in this repository answers "what does this policy set do for
// *this* request". Analysis answers "what does it do for *every* request" — is
// this rule reachable at all, is that one already covered, can these two ever
// both apply. Those are satisfiability questions over infinitely many requests,
// so no amount of testing settles them.
//
// A BDD settles them exactly. See bdd.go for the representation and atoms.go for
// the theory that makes the boolean abstraction faithful to what the operators
// actually mean.
//
// # Soundness direction
//
// The theory is deliberately incomplete: when nothing can be derived about two
// predicates it treats them as independent. That biases the results in one
// direction, and it is the right one.
//
//	Under-constrained ⇒ the analyser thinks more is possible than really is.
//	  - It may report a Conflict that cannot actually occur.        (noise)
//	  - It will not report Unreachable for a rule that can fire.    (safe)
//	  - It will not report Shadowed for a rule that is still needed. (safe)
//
// The failures it can produce are false alarms, never false reassurance, and
// never advice to delete a rule that is doing something. That asymmetry is what
// makes it safe to act on the output.
//
// # Cost
//
// This is an authoring and CI tool, not a request-path one. Rules are compared
// pairwise within a shard, so cost is quadratic in shard size, and the BDD has a
// hard node cap past which a rule is reported as too complex rather than
// analysed. Both bounds are configurable.
package analyze

import (
	"fmt"
	"sort"

	"github.com/suga/tessaraop/internal/model"
)

// Severity ranks a finding.
type Severity uint8

const (
	// Info: worth knowing, not necessarily wrong.
	Info Severity = iota
	// Warning: very likely an authoring mistake.
	Warning
	// Error: the rule cannot do anything, or two rules directly contradict.
	Error
)

func (s Severity) String() string {
	switch s {
	case Error:
		return "error"
	case Warning:
		return "warning"
	}
	return "info"
}

// Kind identifies what was found.
type Kind string

const (
	// Unreachable: the rule's conditions cannot all hold simultaneously, so it
	// can never fire. Always an authoring mistake.
	Unreachable Kind = "unreachable"

	// Shadowed: an earlier rule with the same effect already covers everything
	// this one matches, so this one never decides anything.
	Shadowed Kind = "shadowed"

	// Conflict: two rules with opposite effects can both match the same request.
	// Not necessarily wrong — that is what deny-overrides is for — but it should
	// be intentional.
	Conflict Kind = "conflict"

	// Duplicate: two rules with identical conditions and the same effect.
	Duplicate Kind = "duplicate"

	// AlwaysMatches: the rule matches every request reaching its shard.
	AlwaysMatches Kind = "always-matches"

	// TooComplex: the rule exceeded the analysis budget and was skipped. Reported
	// rather than silently omitted, so an operator knows the coverage is partial.
	TooComplex Kind = "too-complex"
)

// Finding is one result.
type Finding struct {
	Kind     Kind     `json:"kind"`
	Severity Severity `json:"-"`
	// SeverityText is the JSON form of Severity.
	SeverityText string `json:"severity"`

	PolicyID string `json:"policy_id"`
	RuleID   string `json:"rule_id"`

	// Related names the other rule, for findings about a pair.
	RelatedPolicyID string `json:"related_policy_id,omitempty"`
	RelatedRuleID   string `json:"related_rule_id,omitempty"`

	Message string `json:"message"`

	// Example is a concrete request shape demonstrating the finding, for the
	// kinds where one exists. A conflict nobody can reproduce gets ignored; one
	// with an example gets fixed.
	Example []string `json:"example,omitempty"`
}

func (f Finding) String() string {
	s := fmt.Sprintf("%s: %s: %s/%s", f.Severity, f.Kind, f.PolicyID, f.RuleID)
	if f.RelatedRuleID != "" {
		s += fmt.Sprintf(" vs %s/%s", f.RelatedPolicyID, f.RelatedRuleID)
	}
	s += ": " + f.Message
	if len(f.Example) > 0 {
		s += fmt.Sprintf(" (example: %v)", f.Example)
	}
	return s
}

// Options tunes an analysis.
type Options struct {
	// MaxNodes caps the BDD. Zero means DefaultMaxNodes.
	MaxNodes int

	// MaxRulesPerShard caps pairwise comparison. Zero means
	// DefaultMaxRulesPerShard.
	//
	// Comparison is quadratic, so a whale shard would otherwise dominate the run.
	// Past the cap, single-rule findings (unreachable, always-matches) are still
	// produced — they are linear — and pairwise ones are skipped with a
	// TooComplex finding so the gap is visible.
	MaxRulesPerShard int

	// IncludeConflicts reports rules with opposite effects that can both match.
	// On by default; turn it off when deny-overrides makes overlap the intended
	// design and the findings are pure noise.
	IncludeConflicts bool

	// CrossPolicy compares rules in different policies within the same shard, not
	// only rules within one policy. Off by default: across policies an overlap is
	// usually deliberate, and the volume is high.
	CrossPolicy bool
}

// Defaults.
const (
	DefaultMaxRulesPerShard = 400
)

// DefaultOptions reports unreachable rules, shadowing, duplicates and conflicts
// within each policy.
func DefaultOptions() Options {
	return Options{
		MaxNodes:         DefaultMaxNodes,
		MaxRulesPerShard: DefaultMaxRulesPerShard,
		IncludeConflicts: true,
	}
}

func (o Options) maxRules() int {
	if o.MaxRulesPerShard <= 0 {
		return DefaultMaxRulesPerShard
	}
	return o.MaxRulesPerShard
}

// Report is the result of analysing a policy set.
type Report struct {
	Findings []Finding `json:"findings"`

	PoliciesAnalysed int `json:"policies_analysed"`
	RulesAnalysed    int `json:"rules_analysed"`
	Shards           int `json:"shards"`

	// AtomsDerived and PairsCompared describe the work done, which is what to
	// look at when a run is slow.
	AtomsDerived  int `json:"atoms_derived"`
	PairsCompared int `json:"pairs_compared"`
	BDDNodes      int `json:"bdd_nodes"`
}

// HasErrors reports whether any finding is an error.
func (r *Report) HasErrors() bool {
	for _, f := range r.Findings {
		if f.Severity == Error {
			return true
		}
	}
	return false
}

// Errors returns only the error-severity findings.
func (r *Report) Errors() []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Severity == Error {
			out = append(out, f)
		}
	}
	return out
}

// compiled is one rule with its BDD.
type compiled struct {
	policyIdx int
	ruleIdx   int
	policyID  string
	ruleID    string
	effect    model.Effect
	node      nodeID
	failed    bool
}

// Analyze examines a policy set and reports defects.
//
// Rules are grouped by shard — (tenant, scope) — because that is the only set
// that can ever be evaluated together. Comparing rules across shards would report
// overlaps between policies that no single request can reach.
func Analyze(policies []model.Policy, opt Options) *Report {
	report := &Report{PoliciesAnalysed: len(policies)}

	shards := map[[2]string][]int{}
	for i := range policies {
		key := [2]string{policies[i].TenantID, policies[i].Scope}
		shards[key] = append(shards[key], i)
		report.RulesAnalysed += len(policies[i].Rules)
	}
	report.Shards = len(shards)

	// Deterministic shard order, so two runs over the same input report findings
	// in the same order.
	keys := make([][2]string, 0, len(shards))
	for k := range shards {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i][0] != keys[j][0] {
			return keys[i][0] < keys[j][0]
		}
		return keys[i][1] < keys[j][1]
	})

	for _, key := range keys {
		analyzeShard(policies, shards[key], opt, report)
	}

	sort.SliceStable(report.Findings, func(i, j int) bool {
		if report.Findings[i].Severity != report.Findings[j].Severity {
			return report.Findings[i].Severity > report.Findings[j].Severity
		}
		if report.Findings[i].PolicyID != report.Findings[j].PolicyID {
			return report.Findings[i].PolicyID < report.Findings[j].PolicyID
		}
		return report.Findings[i].RuleID < report.Findings[j].RuleID
	})
	return report
}

func analyzeShard(policies []model.Policy, indices []int, opt Options, report *Report) {
	b := newBDD(opt.MaxNodes)
	t := newTheory(b)

	add := func(f Finding) {
		f.SeverityText = f.Severity.String()
		report.Findings = append(report.Findings, f)
	}

	// Register every condition first so variables are grouped by attribute. This
	// is what keeps the constraint BDD small enough to build; see theory.prepare.
	var allConditions []model.Condition
	for _, pi := range indices {
		for ri := range policies[pi].Rules {
			_ = policies[pi].Rules[ri].When.Walk(func(e *model.ConditionExpr) error {
				if e.Kind == model.ExprLeaf {
					allConditions = append(allConditions, e.Cond)
				}
				return nil
			})
		}
	}
	t.prepare(allConditions)

	if t.degraded {
		add(Finding{
			Kind: TooComplex, Severity: Info,
			PolicyID: policies[indices[0]].ID,
			Message: "the constraint set for this shard exceeded the node budget, so " +
				"some relationships between conditions were not derived; unreachable " +
				"findings remain sound, but shadowing and duplicate coverage is partial " +
				"and conflicts may be over-reported",
		})
	}

	var rules []compiled
	for _, pi := range indices {
		p := &policies[pi]
		for ri := range p.Rules {
			r := &p.Rules[ri]
			node, err := t.compile(r.When)
			c := compiled{
				policyIdx: pi, ruleIdx: ri,
				policyID: p.ID, ruleID: r.ID,
				effect: r.Effect, node: node,
			}
			if err != nil {
				c.failed = true
				add(Finding{
					Kind: TooComplex, Severity: Info,
					PolicyID: p.ID, RuleID: r.ID,
					Message: "rule exceeded the analysis node budget and was skipped; " +
						"raise Options.MaxNodes to include it",
				})
			}
			rules = append(rules, c)
		}
	}

	// Single-rule findings. Linear, so always produced.
	for i := range rules {
		c := &rules[i]
		if c.failed {
			continue
		}

		sat, err := t.satisfiableUnderTheory(c.node)
		if err != nil {
			continue
		}
		if !sat {
			add(Finding{
				Kind: Unreachable, Severity: Error,
				PolicyID: c.policyID, RuleID: c.ruleID,
				Message: "conditions are mutually exclusive, so this rule can never " +
					"match any request",
			})
			continue
		}

		if b.tautology(c.node) {
			add(Finding{
				Kind: AlwaysMatches, Severity: Info,
				PolicyID: c.policyID, RuleID: c.ruleID,
				Message: fmt.Sprintf("matches every request reaching this shard and "+
					"always yields %s; intended only for a catch-all backstop", c.effect),
			})
		}
	}

	if len(rules) > opt.maxRules() {
		add(Finding{
			Kind: TooComplex, Severity: Info,
			PolicyID: policies[indices[0]].ID,
			Message: fmt.Sprintf("shard holds %d rules, above the pairwise limit of %d; "+
				"shadowing, duplicate and conflict analysis was skipped for it",
				len(rules), opt.maxRules()),
		})
		report.AtomsDerived += len(t.atoms)
		report.PairsCompared += t.pairsChecked
		report.BDDNodes += b.size()
		return
	}

	// Pairwise findings.
	for i := range rules {
		a := &rules[i]
		if a.failed {
			continue
		}
		for j := range rules {
			if i == j {
				continue
			}
			c := &rules[j]
			if c.failed {
				continue
			}
			if !opt.CrossPolicy && a.policyIdx != c.policyIdx {
				continue
			}

			// Both orderings are visited deliberately. Shadowing is directional —
			// "a adds nothing over c" is a different claim from the reverse — so
			// skipping half the pairs would report it only when the rules happened
			// to be declared in one particular order. The symmetric kinds
			// (duplicate, conflict) deduplicate themselves by rule position.
			if a.effect == c.effect {
				analyzeSameEffect(t, b, a, c, add)
				continue
			}
			if opt.IncludeConflicts {
				analyzeOppositeEffect(t, b, a, c, add)
			}
		}
	}

	report.AtomsDerived += len(t.atoms)
	report.PairsCompared += t.pairsChecked
	report.BDDNodes += b.size()
}

func analyzeSameEffect(t *theory, b *bdd, a, c *compiled, add func(Finding)) {
	// Identical conditions: canonicity makes this a comparison.
	if b.equivalent(a.node, c.node) {
		// Report once, from the later rule's perspective.
		if a.policyIdx > c.policyIdx || (a.policyIdx == c.policyIdx && a.ruleIdx > c.ruleIdx) {
			add(Finding{
				Kind: Duplicate, Severity: Warning,
				PolicyID: a.policyID, RuleID: a.ruleID,
				RelatedPolicyID: c.policyID, RelatedRuleID: c.ruleID,
				Message: fmt.Sprintf("identical conditions and the same effect (%s); "+
					"one of the two is redundant", a.effect),
			})
		}
		return
	}

	// a is shadowed when everything it matches, c already matches with the same
	// effect — so a never changes an outcome.
	implies, err := t.impliesUnderTheory(a.node, c.node)
	if err != nil || !implies {
		return
	}
	add(Finding{
		Kind: Shadowed, Severity: Warning,
		PolicyID: a.policyID, RuleID: a.ruleID,
		RelatedPolicyID: c.policyID, RelatedRuleID: c.ruleID,
		Message: fmt.Sprintf("every request this matches is already matched by %s "+
			"with the same effect (%s), so it never changes a decision",
			c.ruleID, a.effect),
	})
}

func analyzeOppositeEffect(t *theory, b *bdd, a, c *compiled, add func(Finding)) {
	// Only report a pair once.
	if a.policyIdx > c.policyIdx || (a.policyIdx == c.policyIdx && a.ruleIdx > c.ruleIdx) {
		return
	}

	both, err := b.and(a.node, c.node)
	if err != nil {
		return
	}
	withTheory, err := b.and(t.constraints, both)
	if err != nil {
		return
	}
	if !b.satisfiable(withTheory) {
		return // they can never both apply, so there is no conflict
	}

	add(Finding{
		Kind: Conflict, Severity: Info,
		PolicyID: a.policyID, RuleID: a.ruleID,
		RelatedPolicyID: c.policyID, RelatedRuleID: c.ruleID,
		Message: fmt.Sprintf("can both match the same request with opposite effects "+
			"(%s and %s); the combining algorithm decides, so make sure that is "+
			"intended", a.effect, c.effect),
		Example: t.describeSolution(b.anySolution(withTheory)),
	})
}
