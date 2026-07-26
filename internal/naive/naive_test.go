package naive

import (
	"testing"

	"github.com/suga/tessaraop/internal/model"
)

func pol(id, tenant string, effect model.Effect, conds ...model.Condition) model.Policy {
	return model.SimplePolicy(id, tenant, "", effect, 0, conds)
}

func TestEmptyPolicySet_DefaultDeny(t *testing.T) {
	e := New(nil)
	d := e.Evaluate(model.Request{TenantID: "t"})
	if d.Allowed {
		t.Fatalf("expected default-deny on an empty corpus, got %s", d)
	}
	if d.PoliciesScanned != 0 || d.RulesScanned != 0 {
		t.Fatalf("expected nothing scanned, got %d policies / %d rules",
			d.PoliciesScanned, d.RulesScanned)
	}
}

func TestSingleAllowMatch(t *testing.T) {
	e := New([]model.Policy{pol("p1", "t", model.Allow,
		model.Condition{Attribute: "role", Operator: model.OpEquals, Values: []string{"admin"}})})

	hit := e.Evaluate(model.Request{TenantID: "t",
		Attributes: map[string]string{"role": "admin"}})
	if !hit.Allowed || hit.MatchedPolicyID != "p1" {
		t.Fatalf("expected allow via p1, got %s", hit)
	}
	if hit.MatchedRuleID != "p1/r0" {
		t.Fatalf("expected the rule to be credited, got %q", hit.MatchedRuleID)
	}

	miss := e.Evaluate(model.Request{TenantID: "t",
		Attributes: map[string]string{"role": "viewer"}})
	if miss.Allowed {
		t.Fatalf("expected default-deny for a non-matching role, got %s", miss)
	}
}

func TestDenyOverridesRegardlessOfOrder(t *testing.T) {
	policies := []model.Policy{
		pol("allow", "t", model.Allow,
			model.Condition{Attribute: "role", Operator: model.OpEquals, Values: []string{"admin"}}),
		pol("deny", "t", model.Deny,
			model.Condition{Attribute: "sensitivity", Operator: model.OpIn, Values: []string{"critical"}}),
	}
	req := model.Request{TenantID: "t", Attributes: map[string]string{
		"role": "admin", "sensitivity": "critical"}}

	forward := New(policies).Evaluate(req)
	reversed := New([]model.Policy{policies[1], policies[0]}).Evaluate(req)

	for _, d := range []model.Decision{forward, reversed} {
		if d.Allowed || d.MatchedPolicyID != "deny" {
			t.Fatalf("deny must win irrespective of slice order, got %s", d)
		}
	}
}

func TestTenantScoping(t *testing.T) {
	// The naive evaluator has to apply the same tenant scoping the sharded engine
	// does, or the differential tests would be comparing different policy sets
	// and every mismatch would be noise.
	policies := []model.Policy{
		pol("a", "tenant-a", model.Allow),
		pol("b", "tenant-b", model.Deny),
		pol("g", model.GlobalTenant, model.Allow),
	}
	e := New(policies)

	d := e.Evaluate(model.Request{TenantID: "tenant-a"})
	if !d.Allowed {
		t.Fatalf("tenant-a should not see tenant-b's deny, got %s", d)
	}
	if d.PoliciesScanned != 2 {
		t.Fatalf("expected to scan tenant-a plus global (2), got %d", d.PoliciesScanned)
	}
}

func TestGlobalPolicyAppliesToEveryTenant(t *testing.T) {
	e := New([]model.Policy{
		pol("kill-switch", model.GlobalTenant, model.Deny),
		pol("grant", "tenant-a", model.Allow),
	})
	if d := e.Evaluate(model.Request{TenantID: "tenant-a"}); d.Allowed {
		t.Fatalf("a global deny must override a tenant grant, got %s", d)
	}
}

func TestMultiConditionPolicy_AllMustMatch(t *testing.T) {
	e := New([]model.Policy{pol("p", "t", model.Allow,
		model.Condition{Attribute: "role", Operator: model.OpEquals, Values: []string{"admin"}},
		model.Condition{Attribute: "sensitivity", Operator: model.OpIn, Values: []string{"high", "critical"}})})

	partial := e.Evaluate(model.Request{TenantID: "t", Attributes: map[string]string{
		"role": "admin", "sensitivity": "low"}})
	if partial.Allowed {
		t.Fatalf("expected deny when only one condition holds, got %s", partial)
	}

	full := e.Evaluate(model.Request{TenantID: "t", Attributes: map[string]string{
		"role": "admin", "sensitivity": "high"}})
	if !full.Allowed {
		t.Fatalf("expected allow when all conditions hold, got %s", full)
	}
}

func TestConditionlessPolicyMatchesEverything(t *testing.T) {
	e := New([]model.Policy{pol("catch-all", "t", model.Deny)})
	if d := e.Evaluate(model.Request{TenantID: "t",
		Attributes: map[string]string{"anything": "goes"}}); d.Allowed {
		t.Fatalf("a conditionless deny must match, got %s", d)
	}
}

func TestScannedCountsReflectInScopeSet(t *testing.T) {
	// The naive evaluator is the O(N) reference: it must touch every in-scope
	// policy and every rule inside them, since that is the baseline the index is
	// measured against.
	never := model.AllOf(model.Condition{
		Attribute: "x", Operator: model.OpEquals, Values: []string{"never"}})

	policies := make([]model.Policy, 50)
	for i := range policies {
		policies[i] = model.Policy{
			ID: "p", TenantID: "t",
			Rules: []model.Rule{
				{ID: "r0", Effect: model.Allow, When: never},
				{ID: "r1", Effect: model.Allow, When: never},
				{ID: "r2", Effect: model.Allow, When: never},
			},
		}
	}
	d := New(policies).Evaluate(model.Request{TenantID: "t",
		Attributes: map[string]string{"x": "other"}})
	if d.PoliciesScanned != 50 {
		t.Fatalf("naive must scan every in-scope policy, got %d", d.PoliciesScanned)
	}
	if d.RulesScanned != 150 {
		t.Fatalf("naive must scan every rule of every in-scope policy, got %d", d.RulesScanned)
	}
}

// TestRuleAlgorithmIsHonoured checks that the oracle applies tier one too. If it
// resolved rules any differently from the indexed engine, every differential test
// built on it would be measuring the wrong thing.
func TestRuleAlgorithmIsHonoured(t *testing.T) {
	rules := []model.Rule{
		{ID: "allow", Effect: model.Allow, Priority: 100},
		{ID: "deny", Effect: model.Deny, Priority: 1},
	}
	denyFirst := New([]model.Policy{
		{ID: "p", TenantID: "t", RuleAlgorithm: model.DenyOverrides, Rules: rules}})
	byPriority := New([]model.Policy{
		{ID: "p", TenantID: "t", RuleAlgorithm: model.FirstApplicable, Rules: rules}})

	if d := denyFirst.Evaluate(model.Request{TenantID: "t"}); d.Allowed {
		t.Errorf("deny-overrides inside the policy must deny, got %s", d)
	}
	if d := byPriority.Evaluate(model.Request{TenantID: "t"}); !d.Allowed {
		t.Errorf("first-applicable inside the policy must allow, got %s", d)
	}
}
