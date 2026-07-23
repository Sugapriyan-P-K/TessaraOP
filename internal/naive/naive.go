// Package naive implements the baseline ABAC evaluator: a straight linear
// scan over every policy for every request. This is deliberately the
// "obviously correct, obviously unoptimized" implementation — it exists
// to (a) validate the data model and matching semantics before any
// indexing complexity is introduced, and (b) provide the O(N) reference
// point the benchmark harness compares the indexed evaluator against.
package naive

import "github.com/suga/tessaraop/internal/model"

// Evaluator scans the full policy slice on every call.
type Evaluator struct {
	Policies []model.Policy
}

// New constructs a naive evaluator over the given policy set.
func New(policies []model.Policy) *Evaluator {
	return &Evaluator{Policies: policies}
}

// Evaluate applies deny-overrides, default-deny semantics:
//   - If ANY matching policy has Effect == Deny, the request is denied,
//     regardless of how many Allow policies also matched.
//   - Else if AT LEAST ONE matching policy has Effect == Allow, the
//     request is allowed.
//   - Else (no policy matched at all), default-deny applies.
//
// The scan always walks every policy — it cannot short-circuit on the
// first Allow match, because a Deny appearing later in the slice must
// still override it. This keeps PoliciesScanned == len(Policies) on every
// call, which is exactly the O(N) baseline the indexed evaluator is
// measured against.
func (e *Evaluator) Evaluate(req model.Request) model.Decision {
	var (
		denyMatchID  string
		allowMatchID string
		foundDeny    bool
		foundAllow   bool
	)

	for _, p := range e.Policies {
		if !p.Matches(req) {
			continue
		}
		switch p.Effect {
		case model.Deny:
			if !foundDeny {
				foundDeny = true
				denyMatchID = p.ID
			}
		case model.Allow:
			if !foundAllow {
				foundAllow = true
				allowMatchID = p.ID
			}
		}
	}

	scanned := len(e.Policies)

	switch {
	case foundDeny:
		return model.Decision{
			Allowed:         false,
			MatchedPolicyID: denyMatchID,
			Effect:          model.Deny,
			PoliciesScanned: scanned,
		}
	case foundAllow:
		return model.Decision{
			Allowed:         true,
			MatchedPolicyID: allowMatchID,
			Effect:          model.Allow,
			PoliciesScanned: scanned,
		}
	default:
		return model.Decision{
			Allowed:         false,
			MatchedPolicyID: "",
			Effect:          model.Deny,
			PoliciesScanned: scanned,
		}
	}
}
