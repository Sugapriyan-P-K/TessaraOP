package naive

import (
	"testing"

	"github.com/suga/tessaraop/internal/model"
)

func TestEmptyPolicySet_DefaultDeny(t *testing.T) {
	e := New([]model.Policy{})
	d := e.Evaluate(model.Request{Attributes: map[string]string{"department": "eng"}})
	if d.Allowed {
		t.Fatalf("expected default-deny on empty policy set, got %s", d)
	}
	if d.PoliciesScanned != 0 {
		t.Fatalf("expected 0 policies scanned, got %d", d.PoliciesScanned)
	}
}

func TestSingleAllowMatch(t *testing.T) {
	policies := []model.Policy{
		{
			ID:     "p1",
			Effect: model.Allow,
			Conditions: []model.Condition{
				{Attribute: "department", Operator: model.OpEquals, Values: []string{"engineering"}},
			},
		},
	}
	e := New(policies)

	req := model.Request{Attributes: map[string]string{"department": "engineering"}}
	d := e.Evaluate(req)
	if !d.Allowed || d.MatchedPolicyID != "p1" {
		t.Fatalf("expected allow via p1, got %s", d)
	}

	req2 := model.Request{Attributes: map[string]string{"department": "sales"}}
	d2 := e.Evaluate(req2)
	if d2.Allowed {
		t.Fatalf("expected default-deny for non-matching department, got %s", d2)
	}
}

func TestDenyOverridesAllow(t *testing.T) {
	// p1 (Allow) would match on department alone, but p2 (Deny) also
	// matches on resource sensitivity — deny-overrides means the
	// request must be denied even though p1 matched too, and even
	// though p1 appears first in the slice.
	policies := []model.Policy{
		{
			ID:     "p1",
			Effect: model.Allow,
			Conditions: []model.Condition{
				{Attribute: "department", Operator: model.OpEquals, Values: []string{"engineering"}},
			},
		},
		{
			ID:     "p2",
			Effect: model.Deny,
			Conditions: []model.Condition{
				{Attribute: "resource.sensitivity", Operator: model.OpIn, Values: []string{"critical"}},
			},
		},
	}
	e := New(policies)

	req := model.Request{
		Attributes: map[string]string{
			"department":           "engineering",
			"resource.sensitivity": "critical",
		},
	}
	d := e.Evaluate(req)
	if d.Allowed {
		t.Fatalf("expected deny-overrides to win, got %s", d)
	}
	if d.MatchedPolicyID != "p2" {
		t.Fatalf("expected p2 (deny) to be the matched policy, got %s", d)
	}
	if d.PoliciesScanned != len(policies) {
		t.Fatalf("expected full scan of %d policies, got %d", len(policies), d.PoliciesScanned)
	}
}

func TestRangeCondition_TimeOfDay(t *testing.T) {
	policies := []model.Policy{
		{
			ID:     "business-hours-only",
			Effect: model.Allow,
			Conditions: []model.Condition{
				{Attribute: "time.hour", Operator: model.OpRange, Min: 9, Max: 17},
			},
		},
	}
	e := New(policies)

	inHours := model.Request{Numeric: map[string]float64{"time.hour": 14.5}}
	if d := e.Evaluate(inHours); !d.Allowed {
		t.Fatalf("expected allow within business hours, got %s", d)
	}

	afterHours := model.Request{Numeric: map[string]float64{"time.hour": 22}}
	if d := e.Evaluate(afterHours); d.Allowed {
		t.Fatalf("expected deny outside business hours, got %s", d)
	}
}

func TestMultiConditionPolicy_AllMustMatch(t *testing.T) {
	policies := []model.Policy{
		{
			ID:     "eng-high-sensitivity",
			Effect: model.Allow,
			Conditions: []model.Condition{
				{Attribute: "department", Operator: model.OpEquals, Values: []string{"engineering"}},
				{Attribute: "resource.sensitivity", Operator: model.OpIn, Values: []string{"high", "critical"}},
			},
		},
	}
	e := New(policies)

	// Only one of two conditions satisfied -> should NOT match.
	partial := model.Request{
		Attributes: map[string]string{
			"department":           "engineering",
			"resource.sensitivity": "low",
		},
	}
	if d := e.Evaluate(partial); d.Allowed {
		t.Fatalf("expected deny when only one condition matches, got %s", d)
	}

	// Both conditions satisfied -> should match.
	full := model.Request{
		Attributes: map[string]string{
			"department":           "engineering",
			"resource.sensitivity": "high",
		},
	}
	if d := e.Evaluate(full); !d.Allowed {
		t.Fatalf("expected allow when all conditions match, got %s", d)
	}
}

func TestMissingAttribute_NeverMatches(t *testing.T) {
	policies := []model.Policy{
		{
			ID:     "p1",
			Effect: model.Allow,
			Conditions: []model.Condition{
				{Attribute: "department", Operator: model.OpEquals, Values: []string{"engineering"}},
			},
		},
	}
	e := New(policies)

	// Request simply doesn't carry the attribute the policy cares about.
	req := model.Request{Attributes: map[string]string{}}
	if d := e.Evaluate(req); d.Allowed {
		t.Fatalf("expected deny when attribute is absent, got %s", d)
	}
}

func TestConditionlessPolicy_MatchesEverything(t *testing.T) {
	policies := []model.Policy{
		{ID: "catch-all-deny", Effect: model.Deny, Conditions: []model.Condition{}},
	}
	e := New(policies)
	d := e.Evaluate(model.Request{Attributes: map[string]string{"anything": "goes"}})
	if d.Allowed {
		t.Fatalf("expected conditionless deny policy to match and deny, got %s", d)
	}
}

func TestPoliciesScanned_AlwaysFullScan(t *testing.T) {
	// Naive evaluator must scan every policy every time, even when an
	// Allow match is found early — because a later Deny could still
	// override it. This test locks that invariant in.
	policies := make([]model.Policy, 0, 50)
	for i := 0; i < 50; i++ {
		policies = append(policies, model.Policy{
			ID:     "p",
			Effect: model.Allow,
			Conditions: []model.Condition{
				{Attribute: "x", Operator: model.OpEquals, Values: []string{"never-matches"}},
			},
		})
	}
	e := New(policies)
	d := e.Evaluate(model.Request{Attributes: map[string]string{"x": "never-matches"}})
	if d.PoliciesScanned != 50 {
		t.Fatalf("expected PoliciesScanned == 50, got %d", d.PoliciesScanned)
	}
}
