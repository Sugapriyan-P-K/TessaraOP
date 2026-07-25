package genutil

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/suga/tessaraop/internal/model"
)

func TestGenerate_CountsAndTenants(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	c := Generate(Options{Policies: 1000, Tenants: 10, Global: 20}, rng)

	if got := len(c.Policies); got != 1020 {
		t.Fatalf("expected 1020 policies, got %d", got)
	}
	if got := len(c.Tenants); got != 10 {
		t.Fatalf("expected 10 tenants, got %d", got)
	}
}

func TestGenerate_TenantDistributionIsSkewed(t *testing.T) {
	// A uniform split would hide the case that actually matters: the request
	// landing on the largest shard. The generator must produce a long tail.
	rng := rand.New(rand.NewSource(2))
	c := Generate(Options{Policies: 10000, Tenants: 50, Global: 0}, rng)

	counts := map[string]int{}
	for _, p := range c.Policies {
		counts[p.TenantID]++
	}
	first, last := counts[c.Tenants[0]], counts[c.Tenants[49]]
	if first <= last {
		t.Fatalf("expected a skewed distribution, tenant0=%d tenant49=%d", first, last)
	}
	if first < last*5 {
		t.Fatalf("skew too shallow to be representative: tenant0=%d tenant49=%d", first, last)
	}
}

func TestGenerate_GlobalPoliciesAreTaggedAndDenyWeighted(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	c := Generate(Options{Policies: 100, Tenants: 4, Global: 40}, rng)

	globals := 0
	for _, p := range c.Policies {
		if p.TenantID != model.GlobalTenant {
			continue
		}
		globals++
		if p.Effect != model.Deny {
			t.Fatalf("global policy %s should be a deny", p.ID)
		}
	}
	if globals != 40 {
		t.Fatalf("expected 40 global policies, got %d", globals)
	}
}

func TestGenerate_CoversEveryOperatorFamily(t *testing.T) {
	// If the corpus never exercises an operator, the benchmarks and
	// differential tests silently stop covering that index structure.
	rng := rand.New(rand.NewSource(4))
	c := Generate(Options{Policies: 5000, Tenants: 10, Global: 40}, rng)

	seen := map[model.Operator]bool{}
	for _, p := range c.Policies {
		for _, cond := range p.Conditions {
			seen[cond.Operator] = true
		}
	}
	for _, op := range []model.Operator{
		model.OpEquals, model.OpIn, model.OpNotIn, model.OpRange,
		model.OpGreaterThan, model.OpCIDR, model.OpNotCIDR,
		model.OpDNSSuffix, model.OpPrefix,
	} {
		if !seen[op] {
			t.Errorf("generated corpus never uses operator %s", op)
		}
	}
}

func TestGenerate_Deterministic(t *testing.T) {
	opt := Options{Policies: 300, Tenants: 6, Global: 10}
	a := Generate(opt, rand.New(rand.NewSource(42)))
	b := Generate(opt, rand.New(rand.NewSource(42)))

	if len(a.Policies) != len(b.Policies) {
		t.Fatalf("same seed produced different sizes: %d vs %d", len(a.Policies), len(b.Policies))
	}
	for i := range a.Policies {
		if a.Policies[i].ID != b.Policies[i].ID ||
			a.Policies[i].Effect != b.Policies[i].Effect ||
			len(a.Policies[i].Conditions) != len(b.Policies[i].Conditions) {
			t.Fatalf("policy %d differs between runs with the same seed", i)
		}
	}
}

func TestGenerateRequest_IsWellFormed(t *testing.T) {
	rng := rand.New(rand.NewSource(5))
	c := Generate(Options{Policies: 100, Tenants: 4, Global: 5}, rng)

	for i := 0; i < 200; i++ {
		req := c.GenerateRequest(rng)

		if req.TenantID == "" {
			t.Fatal("request must carry a tenant")
		}
		for _, key := range []string{"subject.role", "action", "resource.domain", "resource.path"} {
			if _, ok := req.Attributes[key]; !ok {
				t.Fatalf("request missing attribute %q", key)
			}
		}
		if _, ok := req.Numeric["subject.risk_score"]; !ok {
			t.Fatal("request missing subject.risk_score")
		}
		if _, ok := req.IPs["network.source_ip"]; !ok {
			t.Fatal("request missing network.source_ip")
		}
		if !strings.HasSuffix(req.Attributes["resource.domain"], ".example.com") {
			t.Fatalf("unexpected domain %q", req.Attributes["resource.domain"])
		}
	}
}

func TestGenerateRequestFor_TargetsNamedTenant(t *testing.T) {
	rng := rand.New(rand.NewSource(6))
	c := Generate(Options{Policies: 100, Tenants: 8, Global: 2}, rng)
	req := c.GenerateRequestFor(c.Tenants[3], rng)
	if req.TenantID != c.Tenants[3] {
		t.Fatalf("expected tenant %s, got %s", c.Tenants[3], req.TenantID)
	}
}

func TestGenerate_SingleTenantIsValid(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	c := Generate(Options{Policies: 50, Tenants: 0, Global: 0}, rng)
	if len(c.Tenants) != 1 {
		t.Fatalf("tenant count should clamp to at least 1, got %d", len(c.Tenants))
	}
	if len(c.Policies) != 50 {
		t.Fatalf("expected 50 policies, got %d", len(c.Policies))
	}
}
