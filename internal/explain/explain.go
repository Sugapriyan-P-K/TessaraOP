// Package explain answers "why?" about a decision.
//
// # Why this is a separate path, not a flag on Evaluate
//
// Evaluate is allocation-free and measured in microseconds. Threading a trace
// through it would wreck both properties for every request, in order to serve
// the rare one where somebody is asking a question. So Explain is a deliberately
// slower second path that trades speed for detail.
//
// That choice falls out well, because the index actively works against
// explanation. A rule pruned by the pre-filter never reached validation, so there
// is no natural place to record why it did not match — the filter only knows the
// rule was excluded, not which condition would have failed. Explain therefore
// bypasses the index entirely and evaluates every in-scope rule directly, which
// is what package naive already does.
//
// # Two things that must be true
//
// First, **the explanation must agree with the decision it explains.** An
// explanation that contradicts Evaluate is worse than none, because it will be
// believed. Explain returns the decision it computed, and a differential test
// asserts it matches Evaluate on the same input.
//
// Second, **tracing must not short-circuit.** And stops at the first false child
// and Or at the first true one, which is right for evaluation and wrong for
// explanation: an author wants every failing condition, not just the one that
// happened to be checked first. So the traversal here evaluates every node.
//
// # Attribute values in traces
//
// A trace shows what the request actually carried, which is what makes it
// useful and also what makes it sensitive. Package ingest works hard to keep
// credentials out of attributes; an explanation must not undo that by echoing
// values into a log or an API response. Options.Redact controls it, and the
// default redacts.
package explain

import (
	"fmt"
	"sort"
	"strings"

	"github.com/suga/tessaraop/internal/model"
)

// Options controls how much an explanation reveals and how much work it does.
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

// DefaultMaxPolicies bounds a trace.
const DefaultMaxPolicies = 200

// Redacted is what a hidden attribute value is replaced with.
const Redacted = "<redacted>"

// DefaultOptions is the safe starting point: redacted, non-matching rules
// included, out-of-scope policies omitted.
func DefaultOptions() Options {
	return Options{
		Redact:             true,
		IncludeNonMatching: true,
		MaxPolicies:        DefaultMaxPolicies,
	}
}

func (o Options) maxPolicies() int {
	if o.MaxPolicies <= 0 {
		return DefaultMaxPolicies
	}
	return o.MaxPolicies
}

func (o Options) reveal(attribute string) bool {
	return !o.Redact || o.RedactExcept[attribute]
}

// Explanation is the full account of one decision.
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

// PolicyTrace is one policy's contribution.
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

// VerdictInfo is a policy's resolved outcome.
type VerdictInfo struct {
	RuleID      string   `json:"rule_id"`
	Effect      string   `json:"effect"`
	Obligations []string `json:"obligations,omitempty"`
}

// RuleTrace is one rule's evaluation.
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

// NodeTrace is one node of an evaluated condition tree.
type NodeTrace struct {
	Kind    string       `json:"kind"` // leaf, and, or, not
	Matched bool         `json:"matched"`
	Leaf    *LeafTrace   `json:"leaf,omitempty"`
	Sub     []*NodeTrace `json:"sub,omitempty"`
}

// LeafTrace is one condition's evaluation against the request.
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

// Explain evaluates the policies against the request and reports why the result
// came out as it did.
//
// Policies are the full corpus; scoping is applied here exactly as the engine
// applies it, so an out-of-scope policy is reported as such rather than silently
// omitted.
func Explain(policies []model.Policy, req model.Request, alg model.Algorithm, opt Options) *Explanation {
	if alg == "" {
		alg = model.DenyOverrides
	}

	ex := &Explanation{Algorithm: string(alg)}
	acc := model.NewAccumulator(alg)

	// Evaluated in corpus order, with no short-circuiting anywhere: the
	// accumulator is fed every applicable verdict so the trace is complete even
	// when the decision was settled early.
	for i := range policies {
		p := &policies[i]

		if !req.InScope(p) {
			if opt.IncludeOutOfScope && len(ex.Policies) < opt.maxPolicies() {
				ex.Policies = append(ex.Policies, PolicyTrace{
					PolicyID: p.ID, TenantID: p.TenantID, Scope: p.Scope,
					Priority: p.Priority, InScope: false,
					OutOfScopeReason: scopeReason(p, req),
				})
			}
			continue
		}
		ex.PoliciesInScope++

		trace := explainPolicy(p, req, opt, ex)
		if trace.Matched {
			acc.Consider(model.Verdict{
				PolicyID: p.ID, RuleID: trace.Verdict.RuleID,
				Effect: model.Effect(trace.Verdict.Effect), Priority: p.Priority,
				Obligations: trace.Verdict.Obligations,
			})
		}

		if len(ex.Policies) < opt.maxPolicies() {
			if trace.Matched || opt.IncludeNonMatching {
				ex.Policies = append(ex.Policies, trace)
			}
		} else {
			ex.Truncated = true
		}
	}

	acc.SetScanned(ex.PoliciesInScope, ex.RulesEvaluated)
	ex.Decision = acc.Resolve()

	// Mark whichever policy the decision credits, so a reader can find it
	// without scanning.
	for i := range ex.Policies {
		if ex.Policies[i].PolicyID == ex.Decision.MatchedPolicyID && ex.Decision.MatchedPolicyID != "" {
			ex.Policies[i].Decisive = true
		}
	}
	ex.Summary = summarize(ex)
	return ex
}

// scopeReason states in words why a policy was unreachable.
func scopeReason(p *model.Policy, req model.Request) string {
	if p.TenantID != req.TenantID {
		return fmt.Sprintf("policy belongs to tenant %q, request is for %q",
			p.TenantID, req.TenantID)
	}
	return fmt.Sprintf("policy is scoped to %q, request is for scope %q",
		p.Scope, req.Scope)
}

func explainPolicy(p *model.Policy, req model.Request, opt Options, ex *Explanation) PolicyTrace {
	alg := p.RuleAlgorithm
	if alg == "" {
		alg = model.DenyOverrides
	}
	trace := PolicyTrace{
		PolicyID: p.ID, TenantID: p.TenantID, Scope: p.Scope,
		Priority: p.Priority, InScope: true, RuleAlgorithm: string(alg),
	}

	inner := model.NewAccumulator(alg)

	// Every rule is evaluated, including after the inner tier could have
	// short-circuited. A rule that would have been skipped is exactly the one an
	// author may be asking about.
	for ri := range p.Rules {
		r := &p.Rules[ri]
		ex.RulesEvaluated++

		node, matched := explainNode(r.When, req, opt, true)
		rt := RuleTrace{
			RuleID: r.ID, Effect: string(r.Effect), Priority: r.Priority,
			Matched: matched, Condition: node,
		}
		rt.Why = ruleWhy(r, node, matched)

		if matched {
			ex.RulesMatched++
			inner.Consider(model.Verdict{
				PolicyID: p.ID, RuleID: r.ID, Effect: r.Effect,
				Priority: r.Priority, Obligations: r.Obligations,
			})
		}
		if matched || opt.IncludeNonMatching {
			trace.Rules = append(trace.Rules, rt)
		}
	}

	if v, ok := inner.Winner(); ok {
		trace.Matched = true
		trace.Verdict = &VerdictInfo{
			RuleID: v.RuleID, Effect: string(v.Effect), Obligations: v.Obligations,
		}
	}
	return trace
}

// explainNode evaluates one node and records the result.
//
// onSpine tracks whether this node is still reachable from the root through
// exclusively And nodes, which is what determines whether its leaves can be
// indexed. Or and Not break the spine for everything beneath them.
func explainNode(e *model.ConditionExpr, req model.Request, opt Options, onSpine bool) (*NodeTrace, bool) {
	if e == nil {
		return nil, true // a catch-all rule matches
	}

	switch e.Kind {
	case model.ExprLeaf:
		leaf := explainLeaf(&e.Cond, req, opt, onSpine)
		return &NodeTrace{Kind: "leaf", Matched: leaf.Matched, Leaf: leaf}, leaf.Matched

	case model.ExprAnd:
		node := &NodeTrace{Kind: "and", Matched: true}
		for _, child := range e.Sub {
			// No short-circuit: every child is evaluated so the trace names
			// every failing condition, not just the first.
			sub, ok := explainNode(child, req, opt, onSpine)
			if sub != nil {
				node.Sub = append(node.Sub, sub)
			}
			if !ok {
				node.Matched = false
			}
		}
		return node, node.Matched

	case model.ExprOr:
		node := &NodeTrace{Kind: "or", Matched: false}
		if len(e.Sub) == 0 {
			// An empty disjunction matches nothing.
			return node, false
		}
		for _, child := range e.Sub {
			sub, ok := explainNode(child, req, opt, false)
			if sub != nil {
				node.Sub = append(node.Sub, sub)
			}
			if ok {
				node.Matched = true
			}
		}
		return node, node.Matched

	case model.ExprNot:
		node := &NodeTrace{Kind: "not"}
		if len(e.Sub) != 1 {
			// A malformed Not fails closed, matching the evaluator.
			return node, false
		}
		sub, ok := explainNode(e.Sub[0], req, opt, false)
		if sub != nil {
			node.Sub = append(node.Sub, sub)
		}
		node.Matched = !ok
		return node, node.Matched
	}
	return &NodeTrace{Kind: "invalid"}, false
}

func explainLeaf(c *model.Condition, req model.Request, opt Options, onSpine bool) *LeafTrace {
	present := req.Has(c.Attribute)
	matched := c.Matches(req)

	lt := &LeafTrace{
		Attribute: c.Attribute,
		Operator:  string(c.Operator),
		Matched:   matched,
		Present:   present,
		Expected:  describeExpected(c),
		Indexable: onSpine && indexable(c.Operator),
	}

	if present {
		lt.Actual = observedValue(c.Attribute, req, opt)
	}
	lt.Why = leafWhy(c, present, matched, lt.Actual, lt.Expected)
	return lt
}

// observedValue renders what the request carried, honouring redaction.
func observedValue(name string, req model.Request, opt Options) string {
	if !opt.reveal(name) {
		return Redacted
	}
	if v, ok := req.Attributes[name]; ok {
		return v
	}
	if v, ok := req.Numeric[name]; ok {
		return trimFloat(v)
	}
	if v, ok := req.IPs[name]; ok {
		return v.String()
	}
	return ""
}

// leafWhy states the reason in words. The absent-attribute case is called out
// specifically because it explains more denials than anything else: the engine
// fails closed, so a missing attribute silently defeats every operator except
// nexists — including the negations, which is the part that surprises people.
func leafWhy(c *model.Condition, present, matched bool, actual, expected string) string {
	if !present {
		if c.Operator == model.OpNotExists {
			return "attribute is absent, which is what this condition requires"
		}
		return fmt.Sprintf(
			"request carries no %q, and conditions on an absent attribute never match "+
				"— including negated ones", c.Attribute)
	}
	if matched {
		return fmt.Sprintf("%s is %s, which satisfies %s %s",
			c.Attribute, actual, c.Operator, expected)
	}
	return fmt.Sprintf("%s is %s, which does not satisfy %s %s",
		c.Attribute, actual, c.Operator, expected)
}

func ruleWhy(r *model.Rule, node *NodeTrace, matched bool) string {
	if r.When == nil {
		return "rule has no conditions, so it matches every request in scope"
	}
	if matched {
		return fmt.Sprintf("every condition held, so %s applies", r.Effect)
	}
	if failed := firstFailure(node); failed != nil {
		return failed.Why
	}
	return "conditions did not hold"
}

// firstFailure finds a leaf that explains a non-match, preferring an absent
// attribute since that is usually the real answer.
func firstFailure(node *NodeTrace) *LeafTrace {
	var absent, mismatch *LeafTrace
	var walk func(*NodeTrace)
	walk = func(n *NodeTrace) {
		if n == nil {
			return
		}
		if n.Leaf != nil && !n.Leaf.Matched {
			if !n.Leaf.Present && absent == nil {
				absent = n.Leaf
			} else if mismatch == nil {
				mismatch = n.Leaf
			}
		}
		for _, sub := range n.Sub {
			walk(sub)
		}
	}
	walk(node)
	if absent != nil {
		return absent
	}
	return mismatch
}

func describeExpected(c *model.Condition) string {
	switch c.Operator {
	case model.OpExists, model.OpNotExists:
		return ""
	case model.OpRange, model.OpNotRange:
		return fmt.Sprintf("[%s, %s]", trimFloat(c.Min), trimFloat(c.Max))
	case model.OpGreaterThan, model.OpGreaterEq, model.OpNumEquals, model.OpNumNotEq:
		return trimFloat(c.Min)
	case model.OpLessThan, model.OpLessEq:
		return trimFloat(c.Max)
	case model.OpNumIn, model.OpNumNotIn:
		parts := make([]string, len(c.Numbers))
		for i, v := range c.Numbers {
			parts[i] = trimFloat(v)
		}
		return "{" + strings.Join(parts, ", ") + "}"
	case model.OpCIDR, model.OpNotCIDR:
		parts := make([]string, len(c.Prefixes))
		for i, p := range c.Prefixes {
			parts[i] = p.String()
		}
		return strings.Join(parts, ", ")
	default:
		if len(c.Values) == 1 {
			return c.Values[0]
		}
		return "{" + strings.Join(c.Values, ", ") + "}"
	}
}

// indexable mirrors the index layer's operator classification, so a trace does
// not claim a filter the index would not actually build.
func indexable(op model.Operator) bool {
	switch op {
	case model.OpContains, model.OpNotContains,
		model.OpNotPrefix, model.OpNotSuffix,
		model.OpRegex, model.OpNotRegex,
		model.OpNotDNSSuffix,
		model.OpNotRange, model.OpNumNotEq, model.OpNumNotIn:
		return false
	}
	return true
}

func trimFloat(f float64) string {
	s := fmt.Sprintf("%.4f", f)
	s = strings.TrimRight(s, "0")
	return strings.TrimSuffix(s, ".")
}

// summarize produces the one-line answer.
func summarize(ex *Explanation) string {
	d := ex.Decision
	if d.MatchedPolicyID == "" {
		if d.Allowed {
			return fmt.Sprintf(
				"ALLOWED by default: nothing matched, and %s permits unless denied",
				ex.Algorithm)
		}
		if ex.PoliciesInScope == 0 {
			return "DENIED by default: no policy is in scope for this tenant and scope"
		}
		return fmt.Sprintf(
			"DENIED by default: %d policies were in scope and %d rules evaluated, but none matched",
			ex.PoliciesInScope, ex.RulesEvaluated)
	}
	verb := "DENIED"
	if d.Allowed {
		verb = "ALLOWED"
	}
	s := fmt.Sprintf("%s by rule %q in policy %q under %s",
		verb, d.MatchedRuleID, d.MatchedPolicyID, ex.Algorithm)
	if len(d.Obligations) > 0 {
		s += ", with obligations " + strings.Join(d.Obligations, ", ")
	}
	return s
}

// UnmatchedAttributes reports the attributes that most often defeated a rule,
// most frequent first.
//
// This is the aggregate view an integrator wants during onboarding: a policy set
// that denies everything usually does so because one attribute is never being
// supplied, and that shows up here immediately rather than by reading traces one
// at a time.
func (ex *Explanation) UnmatchedAttributes() []AttributeCount {
	counts := map[string]*AttributeCount{}
	for i := range ex.Policies {
		for j := range ex.Policies[i].Rules {
			walkLeaves(ex.Policies[i].Rules[j].Condition, func(l *LeafTrace) {
				if l.Matched {
					return
				}
				c, ok := counts[l.Attribute]
				if !ok {
					c = &AttributeCount{Attribute: l.Attribute}
					counts[l.Attribute] = c
				}
				c.Failures++
				if !l.Present {
					c.Absent++
				}
			})
		}
	}
	out := make([]AttributeCount, 0, len(counts))
	for _, c := range counts {
		out = append(out, *c)
	}
	// Total impact first, then absence, then name.
	//
	// Absence is the tiebreak rather than an afterthought because the two causes
	// are not equally actionable. A condition failing on a value mismatch is
	// usually the policy working as intended; one failing because the request
	// never carried the attribute is usually an integration bug, and that is what
	// somebody debugging an onboarding wants at the top of the list.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Failures != out[j].Failures {
			return out[i].Failures > out[j].Failures
		}
		if out[i].Absent != out[j].Absent {
			return out[i].Absent > out[j].Absent
		}
		return out[i].Attribute < out[j].Attribute
	})
	return out
}

// AttributeCount is how often one attribute defeated a condition.
type AttributeCount struct {
	Attribute string `json:"attribute"`
	Failures  int    `json:"failures"`
	// Absent counts the failures caused by the request not carrying the
	// attribute at all, as opposed to carrying a value that did not satisfy the
	// condition. A high Absent count is an integration bug, not a policy one.
	Absent int `json:"absent"`
}

func walkLeaves(n *NodeTrace, fn func(*LeafTrace)) {
	if n == nil {
		return
	}
	if n.Leaf != nil {
		fn(n.Leaf)
	}
	for _, sub := range n.Sub {
		walkLeaves(sub, fn)
	}
}
