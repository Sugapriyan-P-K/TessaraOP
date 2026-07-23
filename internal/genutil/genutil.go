// Package genutil generates synthetic policy sets and requests for
// benchmarking. It uses a small, realistic shared vocabulary
// (10 departments x 4 sensitivity tiers x 5 actions) rather than random
// unique strings, because real IAM/Zero Trust rule sets have many policies
// sharing the same attribute values — unique values per policy would make
// hash-map indexing look artificially great.
package genutil

import (
	"fmt"
	"math/rand"

	"github.com/suga/tessaraop/internal/model"
)

var (
	departments   = []string{"engineering", "sales", "marketing", "finance", "hr", "legal", "ops", "security", "product", "support"}
	sensitivities = []string{"low", "medium", "high", "critical"}
	actions       = []string{"read", "write", "delete", "admin", "audit"}
)

func GeneratePolicies(n int, rng *rand.Rand) []model.Policy {
	policies := make([]model.Policy, n)
	for i := 0; i < n; i++ {
		effect := model.Allow
		if rng.Intn(5) == 0 {
			effect = model.Deny
		}

		var conditions []model.Condition

		if rng.Intn(5) != 0 {
			dept := departments[rng.Intn(len(departments))]
			conditions = append(conditions, model.Condition{
				Attribute: "department",
				Operator:  model.OpEquals,
				Values:    []string{dept},
			})
		}

		if rng.Intn(5) < 3 {
			nVals := 1 + rng.Intn(2)
			vals := make([]string, nVals)
			for j := range vals {
				vals[j] = sensitivities[rng.Intn(len(sensitivities))]
			}
			conditions = append(conditions, model.Condition{
				Attribute: "resource.sensitivity",
				Operator:  model.OpIn,
				Values:    vals,
			})
		}

		if rng.Intn(2) == 0 {
			act := actions[rng.Intn(len(actions))]
			conditions = append(conditions, model.Condition{
				Attribute: "action",
				Operator:  model.OpEquals,
				Values:    []string{act},
			})
		}

		if rng.Intn(10) < 3 {
			start := float64(rng.Intn(12))
			end := start + float64(4+rng.Intn(9))
			if end > 24 {
				end = 24
			}
			conditions = append(conditions, model.Condition{
				Attribute: "time.hour",
				Operator:  model.OpRange,
				Min:       start,
				Max:       end,
			})
		}

		policies[i] = model.Policy{
			ID:         fmt.Sprintf("p%d", i),
			Effect:     effect,
			Conditions: conditions,
		}
	}
	return policies
}

func GenerateRequest(rng *rand.Rand) model.Request {
	return model.Request{
		Attributes: map[string]string{
			"department":           departments[rng.Intn(len(departments))],
			"resource.sensitivity": sensitivities[rng.Intn(len(sensitivities))],
			"action":               actions[rng.Intn(len(actions))],
		},
		Numeric: map[string]float64{
			"time.hour": float64(rng.Intn(24)) + rng.Float64(),
		},
	}
}
