package indexed

import (
	"math/rand"
	"testing"

	"github.com/suga/tessaraop/internal/genutil"
	"github.com/suga/tessaraop/internal/model"
	"github.com/suga/tessaraop/internal/naive"
)

func pol(id, tenant string, effect model.Effect, conds ...model.Condition) model.Policy {
	return model.SimplePolicy(id, tenant, "", effect, 0, conds)
}

func TestIndexed_BasicAllow(t *testing.T) {
	e := New([]model.Policy{pol("p1", "t", model.Allow,
		model.Condition{Attribute: "role", Operator: model.OpEquals, Values: []string{"admin"}})})
	d := e.Evaluate(model.Request{TenantID: "t",
		Attributes: map[string]string{"role": "admin"}})
	if !d.Allowed || d.MatchedPolicyID != "p1" {
		t.Fatalf("expected allow via p1, got %s", d)
	}
}

func TestIndexed_DenyOverrides(t *testing.T) {
	e := New([]model.Policy{
		pol("allow", "t", model.Allow,
			model.Condition{Attribute: "role", Operator: model.OpEquals, Values: []string{"admin"}}),
		pol("deny", "t", model.Deny,
			model.Condition{Attribute: "sensitivity", Operator: model.OpIn, Values: []string{"critical"}}),
	})
	d := e.Evaluate(model.Request{TenantID: "t", Attributes: map[string]string{
		"role": "admin", "sensitivity": "critical"}})
	if d.Allowed || d.MatchedPolicyID != "deny" {
		t.Fatalf("expected deny to win, got %s", d)
	}
}

func TestIndexed_DefaultDeny(t *testing.T) {
	e := New([]model.Policy{pol("p1", "t", model.Allow,
		model.Condition{Attribute: "role", Operator: model.OpEquals, Values: []string{"admin"}})})
	if d := e.Evaluate(model.Request{TenantID: "t",
		Attributes: map[string]string{"role": "viewer"}}); d.Allowed {
		t.Fatalf("expected default-deny, got %s", d)
	}
}

func TestIndexed_ScansFarFewerThanAll(t *testing.T) {
	policies := make([]model.Policy, 1000)
	for i := range policies {
		role := "viewer"
		if i%100 == 0 {
			role = "admin"
		}
		policies[i] = pol("p", "t", model.Allow,
			model.Condition{Attribute: "role", Operator: model.OpEquals, Values: []string{role}})
	}
	e := New(policies)
	d := e.Evaluate(model.Request{TenantID: "t",
		Attributes: map[string]string{"role": "admin"}})
	if e.TotalRules() != 1000 {
		t.Fatalf("expected a 1000-rule universe, got %d", e.TotalRules())
	}
	if d.RulesScanned != 10 {
		t.Fatalf("expected exactly the 10 admin rules to reach validation, got %d",
			d.RulesScanned)
	}
}

// TestIndexed_MultiRulePolicyScansOnlyCandidateRules checks that narrowing
// happens at rule granularity even inside a single policy. A policy-granular
// index would have to validate every rule of any policy it kept.
func TestIndexed_MultiRulePolicyScansOnlyCandidateRules(t *testing.T) {
	e := New([]model.Policy{{
		ID: "p", TenantID: "t",
		Rules: []model.Rule{
			{ID: "wants-admin", Effect: model.Allow, When: model.AllOf(
				model.Condition{Attribute: "role", Operator: model.OpEquals, Values: []string{"admin"}})},
			{ID: "wants-viewer", Effect: model.Allow, When: model.AllOf(
				model.Condition{Attribute: "role", Operator: model.OpEquals, Values: []string{"viewer"}})},
			{ID: "wants-auditor", Effect: model.Allow, When: model.AllOf(
				model.Condition{Attribute: "role", Operator: model.OpEquals, Values: []string{"auditor"}})},
		},
	}})
	d := e.Evaluate(model.Request{TenantID: "t",
		Attributes: map[string]string{"role": "admin"}})
	if d.RulesScanned != 1 {
		t.Fatalf("only the admin rule should reach validation, got %d", d.RulesScanned)
	}
	if d.MatchedRuleID != "wants-admin" {
		t.Fatalf("wrong rule credited: %q", d.MatchedRuleID)
	}
}

// TestDifferential_MatchesNaive checks the index in isolation, without the
// sharding and caching layered on top by the engine. Keeping this separate means
// a regression can be attributed to the index itself rather than to whichever
// engine feature was touched most recently.
//
// Unlike the engine's differential test, this one compares the credited IDs
// exactly. Both evaluators walk policies in slice order and candidate positions
// come back ascending, so the first rule each finds with the winning effect is
// the same rule — a divergence here means the index changed the order, not just
// the set.
func TestDifferential_MatchesNaive(t *testing.T) {
	for _, alg := range []model.Algorithm{
		model.DenyOverrides, model.PermitOverrides, model.FirstApplicable,
	} {
		t.Run(string(alg), func(t *testing.T) {
			for seed := int64(0); seed < 30; seed++ {
				rng := rand.New(rand.NewSource(seed))
				corpus := genutil.Generate(genutil.Options{
					Policies: 200, Tenants: 1, Global: 0, RulesPerPolicy: 4}, rng)

				// This evaluator does no sharding, so the corpus is flattened onto
				// one tenant at tenant-wide scope. Otherwise the naive oracle would
				// scope-filter while the index would not, and the two would be
				// answering questions about different policy sets.
				const tenant = "flat"
				for i := range corpus.Policies {
					corpus.Policies[i].TenantID = tenant
					corpus.Policies[i].Scope = model.TenantWideScope
				}

				ref := naive.NewWith(corpus.Policies, alg)
				idx := NewWith(corpus.Policies, alg)

				for q := 0; q < 25; q++ {
					req := corpus.GenerateRequest(rng)
					req.TenantID = tenant
					req.Scope = model.TenantWideScope
					want := ref.Evaluate(req)
					got := idx.Evaluate(req)
					if want.Allowed != got.Allowed ||
						want.Effect != got.Effect ||
						want.MatchedPolicyID != got.MatchedPolicyID ||
						want.MatchedRuleID != got.MatchedRuleID {
						t.Fatalf("seed=%d q=%d\n naive:   %s\n indexed: %s\n request: %+v",
							seed, q, want, got, req)
					}
				}
			}
		})
	}
}
