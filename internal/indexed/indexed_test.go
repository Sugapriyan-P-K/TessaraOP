package indexed

import (
	"math/rand"
	"testing"

	"github.com/suga/tessaraop/internal/genutil"
	"github.com/suga/tessaraop/internal/model"
	"github.com/suga/tessaraop/internal/naive"
)

func TestIndexed_BasicAllow(t *testing.T) {
	policies := []model.Policy{
		{ID: "p1", Effect: model.Allow, Conditions: []model.Condition{
			{Attribute: "department", Operator: model.OpEquals, Values: []string{"engineering"}},
		}},
	}
	e := New(policies)
	req := model.Request{Attributes: map[string]string{"department": "engineering"}}
	d := e.Evaluate(req)
	if !d.Allowed || d.MatchedPolicyID != "p1" {
		t.Fatalf("expected allow via p1, got %s", d)
	}
}

func TestIndexed_DenyOverrides(t *testing.T) {
	policies := []model.Policy{
		{ID: "allow-eng", Effect: model.Allow, Conditions: []model.Condition{
			{Attribute: "department", Operator: model.OpEquals, Values: []string{"engineering"}},
		}},
		{ID: "deny-critical", Effect: model.Deny, Conditions: []model.Condition{
			{Attribute: "resource.sensitivity", Operator: model.OpIn, Values: []string{"critical"}},
		}},
	}
	e := New(policies)
	req := model.Request{Attributes: map[string]string{
		"department":           "engineering",
		"resource.sensitivity": "critical",
	}}
	d := e.Evaluate(req)
	if d.Allowed {
		t.Fatalf("expected deny-overrides, got %s", d)
	}
	if d.MatchedPolicyID != "deny-critical" {
		t.Fatalf("expected deny-critical as matched policy, got %s", d)
	}
}

func TestIndexed_DefaultDeny(t *testing.T) {
	policies := []model.Policy{
		{ID: "p1", Effect: model.Allow, Conditions: []model.Condition{
			{Attribute: "department", Operator: model.OpEquals, Values: []string{"engineering"}},
		}},
	}
	e := New(policies)
	req := model.Request{Attributes: map[string]string{"department": "sales"}}
	d := e.Evaluate(req)
	if d.Allowed {
		t.Fatalf("expected default-deny for non-matching request, got %s", d)
	}
}

func TestIndexed_PoliciesScannedLessThanTotal(t *testing.T) {
	policies := make([]model.Policy, 100)
	for i := range policies {
		dept := "other"
		if i%10 == 0 {
			dept = "engineering"
		}
		policies[i] = model.Policy{
			ID:     "p",
			Effect: model.Allow,
			Conditions: []model.Condition{
				{Attribute: "department", Operator: model.OpEquals, Values: []string{dept}},
			},
		}
	}
	e := New(policies)
	req := model.Request{Attributes: map[string]string{"department": "engineering"}}
	d := e.Evaluate(req)

	if d.PoliciesScanned >= 100 {
		t.Fatalf("indexed evaluator should scan fewer than all 100 policies, scanned %d", d.PoliciesScanned)
	}
	if d.PoliciesScanned != 10 {
		t.Fatalf("expected exactly 10 candidates (every 10th policy), got %d", d.PoliciesScanned)
	}
}

func TestDifferential_MatchesNaive(t *testing.T) {
	for seed := int64(0); seed < 50; seed++ {
		rng := rand.New(rand.NewSource(seed))
		policies := genutil.GeneratePolicies(100, rng)

		naiveEval := naive.New(policies)
		indexedEval := New(policies)

		for j := 0; j < 20; j++ {
			req := genutil.GenerateRequest(rng)

			naiveD := naiveEval.Evaluate(req)
			indexedD := indexedEval.Evaluate(req)

			if naiveD.Allowed != indexedD.Allowed ||
				naiveD.MatchedPolicyID != indexedD.MatchedPolicyID ||
				naiveD.Effect != indexedD.Effect {
				t.Fatalf("seed=%d req=%d: naive=%s indexed=%s",
					seed, j, naiveD, indexedD)
			}
		}
	}
}
