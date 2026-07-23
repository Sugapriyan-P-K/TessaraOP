// Package model defines the core ABAC data types shared by every evaluator
// implementation (naive linear scan, and later the indexed evaluator).
// Keeping this package evaluator-agnostic is what lets NaiveEvaluator and
// IndexedEvaluator both satisfy the same Evaluator interface later.
package model

import "fmt"

// Effect is the outcome a policy grants if its conditions match.
type Effect string

const (
	Allow Effect = "ALLOW"
	Deny  Effect = "DENY"
)

// Operator is the comparison a Condition applies to a request attribute.
// v1 intentionally supports only these three — range-based / wildcard
// matching (HiCuts/HyperCuts territory) is explicitly out of scope for v1.
type Operator string

const (
	OpEquals Operator = "eq"    // Attribute == Values[0]
	OpIn     Operator = "in"    // Attribute is a member of Values
	OpRange  Operator = "range" // Min <= NumericAttribute <= Max
)

// Condition is a single predicate within a policy, e.g.
// {Attribute: "resource.sensitivity", Operator: OpIn, Values: []string{"high","critical"}}
type Condition struct {
	Attribute string
	Operator  Operator
	Values    []string // used by OpEquals (len 1) and OpIn (len N)
	Min, Max  float64  // used by OpRange
}

// Matches evaluates this single condition against a request.
// All condition-matching logic lives here so both the naive evaluator
// and the future indexed evaluator's final validation pass share
// identical semantics — the indexed path must never disagree with this.
func (c Condition) Matches(req Request) bool {
	switch c.Operator {
	case OpEquals:
		val, ok := req.Attributes[c.Attribute]
		if !ok || len(c.Values) == 0 {
			return false
		}
		return val == c.Values[0]

	case OpIn:
		val, ok := req.Attributes[c.Attribute]
		if !ok {
			return false
		}
		for _, v := range c.Values {
			if val == v {
				return true
			}
		}
		return false

	case OpRange:
		val, ok := req.Numeric[c.Attribute]
		if !ok {
			return false
		}
		return val >= c.Min && val <= c.Max

	default:
		return false
	}
}

// Policy is a single ABAC rule: if all Conditions match, Effect applies.
// Conditions are implicitly AND-ed together.
type Policy struct {
	ID         string
	Effect     Effect
	Conditions []Condition
}

// Matches reports whether every condition in the policy matches the request.
// An empty condition list matches everything (a catch-all policy) — this is
// intentional and mirrors how most real ABAC engines treat a conditionless
// rule, but it's worth remembering when generating synthetic benchmark data.
func (p Policy) Matches(req Request) bool {
	for _, cond := range p.Conditions {
		if !cond.Matches(req) {
			return false
		}
	}
	return true
}

// Request represents a single access-check request. String-valued
// attributes (department, role, resource path, etc.) go in Attributes;
// numeric attributes used by range conditions (time-of-day, risk score)
// go in Numeric. Splitting these up avoids parsing/casting on every
// condition check in the hot path.
type Request struct {
	Attributes map[string]string
	Numeric    map[string]float64
}

// Decision is the result of evaluating a request against the policy set.
// PoliciesScanned is not just diagnostic — it's the core metric that
// proves indexing actually narrows the search space (naive scans ~N,
// indexed should scan a small fraction of N). Every evaluator MUST set
// this honestly for the benchmark harness to mean anything.
type Decision struct {
	Allowed         bool
	MatchedPolicyID string
	Effect          Effect
	PoliciesScanned int
}

func (d Decision) String() string {
	return fmt.Sprintf("Decision{Allowed:%v Effect:%s MatchedPolicy:%s Scanned:%d}",
		d.Allowed, d.Effect, d.MatchedPolicyID, d.PoliciesScanned)
}

// Evaluator is implemented by every evaluation strategy (naive, indexed, ...).
// The benchmark harness depends only on this interface, never on a concrete
// evaluator type, so swapping/comparing strategies requires no harness changes.
type Evaluator interface {
	Evaluate(req Request) Decision
}

// Evaluate runs deny-overrides, default-deny over the full policy slice.
func Evaluate(policies []Policy, req Request) Decision {
	var (
		denyMatchID  string
		allowMatchID string
		foundDeny    bool
		foundAllow   bool
	)
	for _, p := range policies {
		if !p.Matches(req) {
			continue
		}
		switch p.Effect {
		case Deny:
			if !foundDeny {
				foundDeny = true
				denyMatchID = p.ID
			}
		case Allow:
			if !foundAllow {
				foundAllow = true
				allowMatchID = p.ID
			}
		}
	}
	return ResolveDecision(foundDeny, denyMatchID, foundAllow, allowMatchID, len(policies))
}

// EvaluateIndices runs deny-overrides only over the given candidate positions,
// avoiding allocation of a new policy slice.
func EvaluateIndices(policies []Policy, positions []int, req Request) Decision {
	var (
		denyMatchID  string
		allowMatchID string
		foundDeny    bool
		foundAllow   bool
	)
	for _, idx := range positions {
		p := policies[idx]
		if !p.Matches(req) {
			continue
		}
		switch p.Effect {
		case Deny:
			if !foundDeny {
				foundDeny = true
				denyMatchID = p.ID
			}
		case Allow:
			if !foundAllow {
				foundAllow = true
				allowMatchID = p.ID
			}
		}
	}
	return ResolveDecision(foundDeny, denyMatchID, foundAllow, allowMatchID, len(positions))
}

func ResolveDecision(foundDeny bool, denyMatchID string, foundAllow bool, allowMatchID string, scanned int) Decision {
	switch {
	case foundDeny:
		return Decision{
			Allowed:         false,
			MatchedPolicyID: denyMatchID,
			Effect:          Deny,
			PoliciesScanned: scanned,
		}
	case foundAllow:
		return Decision{
			Allowed:         true,
			MatchedPolicyID: allowMatchID,
			Effect:          Allow,
			PoliciesScanned: scanned,
		}
	default:
		return Decision{
			Allowed:         false,
			MatchedPolicyID: "",
			Effect:          Deny,
			PoliciesScanned: scanned,
		}
	}
}
