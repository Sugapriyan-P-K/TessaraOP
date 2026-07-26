// Package naive implements the baseline evaluator: a linear scan over every
// in-scope policy for every request.
//
// It exists to be obviously correct rather than fast. It is the oracle the
// differential tests compare the indexed engine against, and the O(N)
// reference the benchmarks measure against. Any change to evaluation
// semantics has to land in package model, where both evaluators read it from,
// so the two can never drift apart.
package naive

import "github.com/suga/tessaraop/internal/model"

// Evaluator scans the full policy slice on every call.
type Evaluator struct {
	Policies  []model.Policy
	Algorithm model.Algorithm
}

// New constructs a naive evaluator using deny-overrides.
func New(policies []model.Policy) *Evaluator {
	return &Evaluator{Policies: policies, Algorithm: model.DenyOverrides}
}

// NewWith constructs a naive evaluator using the given combining algorithm.
func NewWith(policies []model.Policy, alg model.Algorithm) *Evaluator {
	return &Evaluator{Policies: policies, Algorithm: alg}
}

// Evaluate scans every policy, and within each policy every rule. It applies
// the same tenant scoping the sharded engine does — a request only reaches its
// own tenant's policies plus the global ones — so the two are comparable on
// identical inputs.
//
// Both tiers run here exactly as they do in the indexed engine, because both
// call into package model to do the combining: rules resolve under the policy's
// RuleAlgorithm, then policy verdicts resolve under this evaluator's Algorithm.
// Nothing about the ordering is reimplemented, which is what makes this a
// trustworthy oracle for the differential tests.
func (e *Evaluator) Evaluate(req model.Request) model.Decision {
	acc := model.NewAccumulator(e.Algorithm)
	policies, rules := 0, 0
	for i := range e.Policies {
		p := &e.Policies[i]
		if !req.InScope(p) {
			continue
		}
		policies++
		rules += model.ConsiderPolicy(p, req, allRules(p), acc)
		if acc.CanShortCircuit() {
			break
		}
	}
	acc.SetScanned(policies, rules)
	return acc.Resolve()
}

// allRules returns every rule position in p. The naive path is the oracle, not
// the fast path, so allocating the index list per policy is acceptable — being
// obviously correct matters more here than being cheap.
func allRules(p *model.Policy) []int {
	out := make([]int, len(p.Rules))
	for i := range out {
		out[i] = i
	}
	return out
}
