package genutil

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/suga/tessaraop/internal/attr"
	"github.com/suga/tessaraop/internal/model"
)

// operatorsUsed collects every operator appearing anywhere in a corpus,
// including leaves buried under Or and Not.
func operatorsUsed(c *Corpus) map[model.Operator]int {
	seen := map[model.Operator]int{}
	for i := range c.Policies {
		for ri := range c.Policies[i].Rules {
			_ = c.Policies[i].Rules[ri].When.Walk(func(e *model.ConditionExpr) error {
				if e.Kind == model.ExprLeaf {
					seen[e.Cond.Operator]++
				}
				return nil
			})
		}
	}
	return seen
}

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
	for i := range c.Policies {
		p := &c.Policies[i]
		if p.TenantID != model.GlobalTenant {
			continue
		}
		globals++
		if len(p.Rules) == 0 {
			t.Fatalf("global policy %s has no rules", p.ID)
		}
		for ri := range p.Rules {
			if p.Rules[ri].Effect != model.Deny {
				t.Fatalf("global rule %s should be a deny", p.Rules[ri].ID)
			}
		}
	}
	if globals != 40 {
		t.Fatalf("expected 40 global policies, got %d", globals)
	}
}

// TestGenerate_ProducesMultiRulePolicies checks the property the whole two-tier
// architecture rests on. A corpus of one-rule policies never exercises tier one,
// so the benchmarks would be measuring the old flat shape under a new name.
func TestGenerate_ProducesMultiRulePolicies(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	c := Generate(Options{Policies: 2000, Tenants: 10, Global: 20, RulesPerPolicy: 4}, rng)

	multi := 0
	for i := range c.Policies {
		if len(c.Policies[i].Rules) > 1 {
			multi++
		}
	}
	if multi < len(c.Policies)/4 {
		t.Fatalf("too few multi-rule policies to exercise tier one: %d of %d",
			multi, len(c.Policies))
	}
	if c.RuleCount() <= len(c.Policies) {
		t.Fatalf("rule count %d should exceed policy count %d",
			c.RuleCount(), len(c.Policies))
	}
}

func TestGenerate_RulesPerPolicyIsRespected(t *testing.T) {
	rng := rand.New(rand.NewSource(12))
	c := Generate(Options{Policies: 500, Tenants: 5, Global: 0, RulesPerPolicy: 2}, rng)
	for i := range c.Policies {
		if n := len(c.Policies[i].Rules); n < 1 || n > 2 {
			t.Fatalf("policy %s has %d rules, want 1..2", c.Policies[i].ID, n)
		}
	}

	// RulesPerPolicy=1 must reproduce the pre-Rule flat corpus exactly, which is
	// what makes a before/after comparison possible.
	flat := Generate(Options{Policies: 500, Tenants: 5, Global: 0, RulesPerPolicy: 1}, rng)
	if flat.RuleCount() != len(flat.Policies) {
		t.Fatalf("RulesPerPolicy=1 should give one rule per policy, got %d rules for %d policies",
			flat.RuleCount(), len(flat.Policies))
	}
}

// TestGenerate_ProducesOffSpineConditions is the honesty check on the benchmark
// corpus. Only AND-spine leaves can be indexed, so a corpus of pure conjunctions
// would report a speedup the engine does not deliver on expressive policy. A
// realistic share of rules must carry conditions the index cannot use.
func TestGenerate_ProducesOffSpineConditions(t *testing.T) {
	rng := rand.New(rand.NewSource(13))
	c := Generate(Options{Policies: 3000, Tenants: 10, Global: 30, RulesPerPolicy: 3}, rng)

	rules, offSpine := 0, 0
	var spine []model.Condition
	for i := range c.Policies {
		for ri := range c.Policies[i].Rules {
			when := c.Policies[i].Rules[ri].When
			rules++
			spine = when.ANDSpineLeaves(spine[:0])
			if len(spine) < when.CountLeaves() {
				offSpine++
			}
		}
	}
	share := float64(offSpine) / float64(rules)
	if share < 0.15 {
		t.Fatalf("only %.1f%% of rules have off-spine conditions; the corpus is too easy", 100*share)
	}
	if share > 0.75 {
		t.Fatalf("%.1f%% of rules are off-spine; the corpus no longer resembles real policy", 100*share)
	}
}

func TestGenerate_CoversEveryOperatorFamily(t *testing.T) {
	// If the corpus never exercises an operator, the benchmarks and differential
	// tests silently stop covering that index structure.
	rng := rand.New(rand.NewSource(4))
	c := Generate(Options{Policies: 5000, Tenants: 10, Global: 40}, rng)

	seen := operatorsUsed(c)
	for _, op := range []model.Operator{
		model.OpEquals, model.OpIn, model.OpNotIn, model.OpRange,
		model.OpGreaterThan, model.OpGreaterEq, model.OpLessEq,
		model.OpCIDR, model.OpNotCIDR,
		model.OpDNSSuffix, model.OpPrefix, model.OpSuffix,
		model.OpNumIn, model.OpContains, model.OpRegex,
	} {
		if seen[op] == 0 {
			t.Errorf("generated corpus never uses operator %s", op)
		}
	}
}

// TestGenerate_SpansEveryLayer checks the corpus reaches across layers 3, 4 and
// 7 rather than remaining a pure identity-attribute benchmark.
func TestGenerate_SpansEveryLayer(t *testing.T) {
	rng := rand.New(rand.NewSource(14))
	c := Generate(Options{Policies: 5000, Tenants: 10, Global: 40}, rng)

	layers := map[attr.Layer]int{}
	unregistered := map[string]int{}
	for i := range c.Policies {
		for ri := range c.Policies[i].Rules {
			_ = c.Policies[i].Rules[ri].When.Walk(func(e *model.ConditionExpr) error {
				if e.Kind != model.ExprLeaf {
					return nil
				}
				a, ok := attr.Lookup(e.Cond.Attribute)
				if !ok {
					unregistered[e.Cond.Attribute]++
					return nil
				}
				layers[a.Layer]++
				return nil
			})
		}
	}

	if len(unregistered) > 0 {
		t.Errorf("corpus references attributes not in the registry: %v", unregistered)
	}
	for _, l := range []attr.Layer{
		attr.LayerNetwork, attr.LayerTransport, attr.LayerInfra,
		attr.LayerHTTP, attr.LayerTLS, attr.LayerIdentity, attr.LayerResource,
	} {
		if layers[l] == 0 {
			t.Errorf("corpus has no conditions at layer %s", l)
		}
	}
}

// TestGenerate_OperatorsMatchAttributeTypes catches the mistake the registry
// exists to prevent: a numeric comparison against a string attribute fails
// closed at runtime and looks exactly like a rule that never fires, so a
// generator bug of that shape would quietly weaken every test built on it.
func TestGenerate_OperatorsMatchAttributeTypes(t *testing.T) {
	rng := rand.New(rand.NewSource(15))
	c := Generate(Options{Policies: 3000, Tenants: 8, Global: 30}, rng)

	for i := range c.Policies {
		for ri := range c.Policies[i].Rules {
			rule := &c.Policies[i].Rules[ri]
			_ = rule.When.Walk(func(e *model.ConditionExpr) error {
				if e.Kind != model.ExprLeaf {
					return nil
				}
				a, ok := attr.Lookup(e.Cond.Attribute)
				if !ok {
					return nil
				}
				if !a.Accepts(e.Cond.Operator) {
					t.Errorf("rule %s applies %s to %s, which is %s",
						rule.ID, e.Cond.Operator, a.Name, a.Kind)
				}
				return nil
			})
		}
	}
}

func TestGenerate_RegexesCompile(t *testing.T) {
	rng := rand.New(rand.NewSource(16))
	c := Generate(Options{Policies: 2000, Tenants: 8, Global: 30}, rng)
	for i := range c.Policies {
		if err := c.Policies[i].Prepare(); err != nil {
			t.Fatalf("policy %s carries an uncompilable pattern: %v", c.Policies[i].ID, err)
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
		pa, pb := &a.Policies[i], &b.Policies[i]
		if pa.ID != pb.ID || len(pa.Rules) != len(pb.Rules) {
			t.Fatalf("policy %d differs between runs with the same seed", i)
		}
		for ri := range pa.Rules {
			if pa.Rules[ri].Effect != pb.Rules[ri].Effect ||
				pa.Rules[ri].When.CountLeaves() != pb.Rules[ri].When.CountLeaves() {
				t.Fatalf("policy %d rule %d differs between runs with the same seed", i, ri)
			}
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
		for _, key := range []string{
			attr.SubjectRole, attr.Action, "resource.domain", attr.ResourcePath,
			attr.HTTPMethod, attr.UserAgent, attr.TLSVersion, attr.ConnState,
		} {
			if _, ok := req.Attributes[key]; !ok {
				t.Fatalf("request missing string attribute %q", key)
			}
		}
		for _, key := range []string{
			attr.RiskScore, attr.TimeHour, attr.DestPort, attr.ThreatRep, attr.TLSVersionNo,
		} {
			if _, ok := req.Numeric[key]; !ok {
				t.Fatalf("request missing numeric attribute %q", key)
			}
		}
		if _, ok := req.IPs[attr.SourceIP]; !ok {
			t.Fatalf("request missing %s", attr.SourceIP)
		}
		if !strings.HasSuffix(req.Attributes["resource.domain"], ".example.com") {
			t.Fatalf("unexpected domain %q", req.Attributes["resource.domain"])
		}
	}
}

// TestGenerateRequest_TypesMatchTheRegistry keeps the generated request stream
// consistent with the contract the ingest adapters follow. A value in the wrong
// typed map is invisible to its operators.
func TestGenerateRequest_TypesMatchTheRegistry(t *testing.T) {
	rng := rand.New(rand.NewSource(17))
	c := Generate(Options{Policies: 50, Tenants: 3, Global: 3}, rng)
	req := c.GenerateRequest(rng)

	check := func(name string, want attr.Kind) {
		a, ok := attr.Lookup(name)
		if !ok {
			t.Errorf("request carries unregistered attribute %q", name)
			return
		}
		if a.Kind != want {
			t.Errorf("attribute %q is registered as %s but supplied as %s", name, a.Kind, want)
		}
	}
	for name := range req.Attributes {
		check(name, attr.KindString)
	}
	for name := range req.Numeric {
		check(name, attr.KindNumeric)
	}
	for name := range req.IPs {
		check(name, attr.KindIP)
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
