package naive

import (
	"testing"

	"github.com/suga/tessaraop/internal/model"
)

func TestEmptyPolicySet_DefaultDeny(t *testing.T) {
	e := New(nil)
	d := e.Evaluate(model.Request{TenantID: "t"})
	if d.Allowed {
		t.Fatalf("expected default-deny on an empty corpus, got %s", d)
	}
	if d.PoliciesScanned != 0 {
		t.Fatalf("expected 0 policies scanned, got %d", d.PoliciesScanned)
	}
}

func TestSingleAllowMatch(t *testing.T) {
	e := New([]model.Policy{{
		ID: "p1", TenantID: "t", Effect: model.Allow,
		Conditions: []model.Condition{
			{Attribute: "role", Operator: model.OpEquals, Values: []string{"admin"}}},
	}})

	hit := e.Evaluate(model.Request{TenantID: "t",
		Attributes: map[string]string{"role": "admin"}})
	if !hit.Allowed || hit.MatchedPolicyID != "p1" {
		t.Fatalf("expected allow via p1, got %s", hit)
	}

	miss := e.Evaluate(model.Request{TenantID: "t",
		Attributes: map[string]string{"role": "viewer"}})
	if miss.Allowed {
		t.Fatalf("expected default-deny for a non-matching role, got %s", miss)
	}
}

func TestDenyOverridesRegardlessOfOrder(t *testing.T) {
	policies := []model.Policy{
		{ID: "allow", TenantID: "t", Effect: model.Allow, Conditions: []model.Condition{
			{Attribute: "role", Operator: model.OpEquals, Values: []string{"admin"}}}},
		{ID: "deny", TenantID: "t", Effect: model.Deny, Conditions: []model.Condition{
			{Attribute: "sensitivity", Operator: model.OpIn, Values: []string{"critical"}}}},
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
	// The naive evaluator has to apply the same tenant scoping the sharded
	// engine does, or the differential tests would be comparing different
	// policy sets and every mismatch would be noise.
	policies := []model.Policy{
		{ID: "a", TenantID: "tenant-a", Effect: model.Allow},
		{ID: "b", TenantID: "tenant-b", Effect: model.Deny},
		{ID: "g", TenantID: model.GlobalTenant, Effect: model.Allow},
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
		{ID: "kill-switch", TenantID: model.GlobalTenant, Effect: model.Deny},
		{ID: "grant", TenantID: "tenant-a", Effect: model.Allow},
	})
	if d := e.Evaluate(model.Request{TenantID: "tenant-a"}); d.Allowed {
		t.Fatalf("a global deny must override a tenant grant, got %s", d)
	}
}

func TestMultiConditionPolicy_AllMustMatch(t *testing.T) {
	e := New([]model.Policy{{
		ID: "p", TenantID: "t", Effect: model.Allow,
		Conditions: []model.Condition{
			{Attribute: "role", Operator: model.OpEquals, Values: []string{"admin"}},
			{Attribute: "sensitivity", Operator: model.OpIn, Values: []string{"high", "critical"}}},
	}})

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
	e := New([]model.Policy{{ID: "catch-all", TenantID: "t", Effect: model.Deny}})
	if d := e.Evaluate(model.Request{TenantID: "t",
		Attributes: map[string]string{"anything": "goes"}}); d.Allowed {
		t.Fatalf("a conditionless deny must match, got %s", d)
	}
}

func TestPoliciesScannedReflectsInScopeSet(t *testing.T) {
	policies := make([]model.Policy, 50)
	for i := range policies {
		policies[i] = model.Policy{
			ID: "p", TenantID: "t", Effect: model.Allow,
			Conditions: []model.Condition{
				{Attribute: "x", Operator: model.OpEquals, Values: []string{"never"}}},
		}
	}
	d := New(policies).Evaluate(model.Request{TenantID: "t",
		Attributes: map[string]string{"x": "other"}})
	if d.PoliciesScanned != 50 {
		t.Fatalf("naive must scan every in-scope policy, got %d", d.PoliciesScanned)
	}
}
