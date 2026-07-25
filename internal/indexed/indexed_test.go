package indexed

import (
	"math/rand"
	"testing"

	"github.com/suga/tessaraop/internal/genutil"
	"github.com/suga/tessaraop/internal/model"
	"github.com/suga/tessaraop/internal/naive"
)

func TestIndexed_BasicAllow(t *testing.T) {
	e := New([]model.Policy{{
		ID: "p1", TenantID: "t", Effect: model.Allow,
		Conditions: []model.Condition{
			{Attribute: "role", Operator: model.OpEquals, Values: []string{"admin"}}},
	}})
	d := e.Evaluate(model.Request{TenantID: "t",
		Attributes: map[string]string{"role": "admin"}})
	if !d.Allowed || d.MatchedPolicyID != "p1" {
		t.Fatalf("expected allow via p1, got %s", d)
	}
}

func TestIndexed_DenyOverrides(t *testing.T) {
	e := New([]model.Policy{
		{ID: "allow", TenantID: "t", Effect: model.Allow, Conditions: []model.Condition{
			{Attribute: "role", Operator: model.OpEquals, Values: []string{"admin"}}}},
		{ID: "deny", TenantID: "t", Effect: model.Deny, Conditions: []model.Condition{
			{Attribute: "sensitivity", Operator: model.OpIn, Values: []string{"critical"}}}},
	})
	d := e.Evaluate(model.Request{TenantID: "t", Attributes: map[string]string{
		"role": "admin", "sensitivity": "critical"}})
	if d.Allowed || d.MatchedPolicyID != "deny" {
		t.Fatalf("expected deny to win, got %s", d)
	}
}

func TestIndexed_DefaultDeny(t *testing.T) {
	e := New([]model.Policy{{
		ID: "p1", TenantID: "t", Effect: model.Allow,
		Conditions: []model.Condition{
			{Attribute: "role", Operator: model.OpEquals, Values: []string{"admin"}}},
	}})
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
		policies[i] = model.Policy{
			ID: "p", TenantID: "t", Effect: model.Allow,
			Conditions: []model.Condition{
				{Attribute: "role", Operator: model.OpEquals, Values: []string{role}}},
		}
	}
	d := New(policies).Evaluate(model.Request{TenantID: "t",
		Attributes: map[string]string{"role": "admin"}})
	if d.PoliciesScanned != 10 {
		t.Fatalf("expected exactly the 10 admin policies to reach validation, got %d",
			d.PoliciesScanned)
	}
}

// TestDifferential_MatchesNaive checks the index in isolation, without the
// sharding and caching layered on top by the engine. Keeping this separate
// means a regression can be attributed to the index itself rather than to
// whichever engine feature was touched most recently.
func TestDifferential_MatchesNaive(t *testing.T) {
	for _, alg := range []model.Algorithm{
		model.DenyOverrides, model.PermitOverrides, model.FirstApplicable,
	} {
		t.Run(string(alg), func(t *testing.T) {
			for seed := int64(0); seed < 30; seed++ {
				rng := rand.New(rand.NewSource(seed))
				corpus := genutil.Generate(genutil.Options{
					Policies: 200, Tenants: 1, Global: 0}, rng)

				// This evaluator does no sharding, so the corpus is flattened
				// onto one tenant at tenant-wide scope. Otherwise the naive
				// oracle would scope-filter while the index would not, and the
				// two would be answering questions about different policy sets.
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
						want.MatchedPolicyID != got.MatchedPolicyID {
						t.Fatalf("seed=%d q=%d\n naive:   %s\n indexed: %s\n request: %+v",
							seed, q, want, got, req)
					}
				}
			}
		})
	}
}
