// Package genutil generates synthetic policy corpora and request streams that
// resemble production authorization workloads.
//
// Two properties matter for the benchmarks to mean anything.
//
// First, a shared vocabulary. Values are drawn from small realistic sets
// (roles, departments, CIDR blocks, path roots) rather than being unique per
// policy. Unique values would give every hash bucket exactly one member and
// make indexing look far better than it is; real IAM corpora have thousands of
// policies referencing the same handful of roles and networks.
//
// Second, realistic tenancy. Policies are distributed across tenants with a
// skewed distribution rather than uniformly, because real platforms have a few
// enormous customers and a long tail of small ones. A uniform split would hide
// the worst case that actually matters — the request that lands on the biggest
// shard.
package genutil

import (
	"fmt"
	"math/rand"
	"net/netip"

	"github.com/suga/tessaraop/internal/model"
)

var (
	roles         = []string{"viewer", "editor", "admin", "security-admin", "auditor", "service-account"}
	departments   = []string{"engineering", "sales", "marketing", "finance", "hr", "legal", "ops", "security", "product", "support"}
	actions       = []string{"read", "write", "delete", "admin", "audit"}
	sensitivities = []string{"low", "medium", "high", "critical"}
	countries     = []string{"US", "CA", "GB", "DE", "IN", "JP", "AU", "BR"}
	pathRoots     = []string{"/api/v1", "/api/v2", "/api/v2/admin", "/internal", "/public", "/admin/console"}
	// Scopes subdivide a tenant, typically by resource family. Policies land
	// in one of these or at tenant-wide scope.
	scopes      = []string{"billing", "identity", "storage", "compute", "network", "analytics", "support", "audit"}
	obligations = []string{"require_mfa", "audit_log", "rate_limit", "step_up_auth", "notify_soc"}

	// Corporate network ranges policies commonly scope to.
	corpNets = []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("10.10.0.0/16"),
		netip.MustParsePrefix("10.20.0.0/16"),
	}
	// Ranges that appear on platform blocklists.
	blockedNets = []netip.Prefix{
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("198.51.100.0/24"),
	}
)

// Corpus is a generated policy set plus the tenants and scopes it spans.
type Corpus struct {
	Policies []model.Policy
	Tenants  []string
	Scopes   []string
}

// Options controls corpus generation.
type Options struct {
	Policies int // total policies to generate
	Tenants  int // number of tenants to spread them across
	Global   int // platform-wide policies applying to every request
}

// Generate builds a corpus. Tenant sizes follow a skewed distribution: tenant
// 0 is the whale, and size falls off from there, so benchmarks exercise both
// the common small shard and the pathological large one.
func Generate(opt Options, rng *rand.Rand) *Corpus {
	if opt.Tenants < 1 {
		opt.Tenants = 1
	}
	c := &Corpus{Tenants: make([]string, opt.Tenants), Scopes: scopes}
	for i := range c.Tenants {
		c.Tenants[i] = fmt.Sprintf("tenant-%04d", i)
	}

	c.Policies = make([]model.Policy, 0, opt.Policies+opt.Global)

	// Platform-wide policies: small, mostly denies, checked on every request.
	for i := 0; i < opt.Global; i++ {
		c.Policies = append(c.Policies, globalPolicy(i, rng))
	}

	// Skewed tenant weights: weight ~ 1/(rank+1), the classic long tail.
	weights := make([]float64, opt.Tenants)
	var total float64
	for i := range weights {
		weights[i] = 1.0 / float64(i+1)
		total += weights[i]
	}

	idx := 0
	for t := 0; t < opt.Tenants; t++ {
		share := int(float64(opt.Policies) * weights[t] / total)
		if t == opt.Tenants-1 {
			share = opt.Policies - idx // absorb rounding drift
		}
		for j := 0; j < share; j++ {
			c.Policies = append(c.Policies, tenantPolicy(c.Tenants[t], idx, rng))
			idx++
		}
	}
	return c
}

// globalPolicy produces a platform-level rule: IP blocklists, geo blocks and
// blanket kill switches. These are deliberately cheap to match and heavily
// deny-weighted, since that is what platform policy looks like in practice.
func globalPolicy(i int, rng *rand.Rand) model.Policy {
	p := model.Policy{
		ID:       fmt.Sprintf("global-%04d", i),
		TenantID: model.GlobalTenant,
		Effect:   model.Deny,
		Priority: 1000,
	}
	switch i % 4 {
	case 0:
		p.Conditions = []model.Condition{{
			Attribute: "network.source_ip",
			Operator:  model.OpCIDR,
			Prefixes:  []netip.Prefix{blockedNets[rng.Intn(len(blockedNets))]},
		}}
		p.Obligations = []string{"notify_soc"}
	case 1:
		p.Conditions = []model.Condition{{
			Attribute: "subject.risk_score",
			Operator:  model.OpGreaterThan,
			Min:       90,
		}}
		p.Obligations = []string{"step_up_auth", "notify_soc"}
	case 2:
		p.Conditions = []model.Condition{
			{Attribute: "geo.country", Operator: model.OpIn, Values: []string{"BR"}},
			{Attribute: "resource.sensitivity", Operator: model.OpIn, Values: []string{"critical"}},
		}
	default:
		p.Conditions = []model.Condition{
			{Attribute: "subject.mfa_verified", Operator: model.OpEquals, Values: []string{"false"}},
			{Attribute: "action", Operator: model.OpIn, Values: []string{"delete", "admin"}},
		}
		p.Obligations = []string{"require_mfa"}
	}
	return p
}

// tenantPolicy produces a customer-level rule spanning the full operator
// surface: set membership, negation, numeric ranges, CIDR, DNS suffix and
// path prefix.
func tenantPolicy(tenant string, i int, rng *rand.Rand) model.Policy {
	// Most policies belong to one resource scope; a minority apply tenant-wide.
	// That split is what keeps a large customer's shard from becoming a single
	// six-figure blob.
	scope := scopes[rng.Intn(len(scopes))]
	if rng.Intn(10) == 0 {
		scope = model.TenantWideScope
	}
	p := model.Policy{
		ID:       fmt.Sprintf("%s-p%06d", tenant, i),
		TenantID: tenant,
		Scope:    scope,
		Effect:   model.Allow,
		Priority: rng.Intn(100),
	}
	if rng.Intn(5) == 0 {
		p.Effect = model.Deny
	}

	var conds []model.Condition

	// Role — present on most policies, the workhorse equality condition.
	if rng.Intn(10) < 8 {
		if rng.Intn(3) == 0 {
			n := 1 + rng.Intn(2)
			vals := make([]string, n)
			for k := range vals {
				vals[k] = roles[rng.Intn(len(roles))]
			}
			conds = append(conds, model.Condition{
				Attribute: "subject.role", Operator: model.OpIn, Values: vals})
		} else {
			conds = append(conds, model.Condition{
				Attribute: "subject.role", Operator: model.OpEquals,
				Values: []string{roles[rng.Intn(len(roles))]}})
		}
	}

	if rng.Intn(10) < 6 {
		conds = append(conds, model.Condition{
			Attribute: "subject.department", Operator: model.OpEquals,
			Values: []string{departments[rng.Intn(len(departments))]}})
	}

	// Negated membership — the "everyone except contractors" shape.
	if rng.Intn(10) < 2 {
		conds = append(conds, model.Condition{
			Attribute: "subject.role", Operator: model.OpNotIn,
			Values: []string{"service-account"}})
	}

	if rng.Intn(10) < 5 {
		conds = append(conds, model.Condition{
			Attribute: "action", Operator: model.OpIn,
			Values: []string{actions[rng.Intn(len(actions))]}})
	}

	if rng.Intn(10) < 5 {
		conds = append(conds, model.Condition{
			Attribute: "resource.sensitivity", Operator: model.OpIn,
			Values: []string{sensitivities[rng.Intn(len(sensitivities))]}})
	}

	// Risk score ceiling — a handful of distinct bands across the corpus,
	// which is exactly the shape IntervalIndex is designed for.
	if rng.Intn(10) < 4 {
		conds = append(conds, model.Condition{
			Attribute: "subject.risk_score", Operator: model.OpRange,
			Min: 0, Max: float64(20 + 20*rng.Intn(4))})
	}

	if rng.Intn(10) < 3 {
		conds = append(conds, model.Condition{
			Attribute: "time.hour", Operator: model.OpRange,
			Min: 9, Max: 17})
	}

	// Source network scoping.
	if rng.Intn(10) < 4 {
		conds = append(conds, model.Condition{
			Attribute: "network.source_ip", Operator: model.OpCIDR,
			Prefixes: []netip.Prefix{corpNets[rng.Intn(len(corpNets))]}})
	}
	if rng.Intn(10) < 1 {
		conds = append(conds, model.Condition{
			Attribute: "network.source_ip", Operator: model.OpNotCIDR,
			Prefixes: []netip.Prefix{blockedNets[rng.Intn(len(blockedNets))]}})
	}

	// Resource host and path scoping.
	if rng.Intn(10) < 4 {
		conds = append(conds, model.Condition{
			Attribute: "resource.domain", Operator: model.OpDNSSuffix,
			Values: []string{fmt.Sprintf("%s.example.com", tenant)}})
	}
	if rng.Intn(10) < 4 {
		conds = append(conds, model.Condition{
			Attribute: "resource.path", Operator: model.OpPrefix,
			Values: []string{pathRoots[rng.Intn(len(pathRoots))]}})
	}

	if rng.Intn(10) < 3 {
		conds = append(conds, model.Condition{
			Attribute: "subject.mfa_verified", Operator: model.OpEquals,
			Values: []string{"true"}})
	}

	if rng.Intn(10) < 2 {
		conds = append(conds, model.Condition{
			Attribute: "geo.country", Operator: model.OpIn,
			Values: []string{countries[rng.Intn(len(countries))]}})
	}

	p.Conditions = conds

	if rng.Intn(10) < 3 {
		p.Obligations = []string{obligations[rng.Intn(len(obligations))]}
	}
	return p
}

// GenerateRequest produces a request against a random tenant in the corpus.
func (c *Corpus) GenerateRequest(rng *rand.Rand) model.Request {
	tenant := c.Tenants[rng.Intn(len(c.Tenants))]
	return c.requestFor(tenant, rng)
}

// GenerateRequestFor produces a request against a named tenant, for
// benchmarking a specific shard size.
func (c *Corpus) GenerateRequestFor(tenant string, rng *rand.Rand) model.Request {
	return c.requestFor(tenant, rng)
}

func (c *Corpus) requestFor(tenant string, rng *rand.Rand) model.Request {
	mfa := "true"
	if rng.Intn(4) == 0 {
		mfa = "false"
	}
	return model.Request{
		TenantID: tenant,
		Scope:    scopes[rng.Intn(len(scopes))],
		Attributes: map[string]string{
			"subject.role":         roles[rng.Intn(len(roles))],
			"subject.department":   departments[rng.Intn(len(departments))],
			"subject.mfa_verified": mfa,
			"action":               actions[rng.Intn(len(actions))],
			"resource.sensitivity": sensitivities[rng.Intn(len(sensitivities))],
			"resource.domain":      fmt.Sprintf("api.%s.example.com", tenant),
			"resource.path":        pathRoots[rng.Intn(len(pathRoots))] + "/items/42",
			"geo.country":          countries[rng.Intn(len(countries))],
		},
		Numeric: map[string]float64{
			"subject.risk_score": float64(rng.Intn(100)),
			"time.hour":          float64(rng.Intn(24)) + rng.Float64(),
		},
		IPs: map[string]netip.Addr{
			"network.source_ip": randomAddr(rng),
		},
	}
}

// randomAddr returns an address weighted toward corporate space, with a
// minority from public and blocklisted ranges — roughly the mix a corporate
// gateway sees.
func randomAddr(rng *rand.Rand) netip.Addr {
	switch rng.Intn(10) {
	case 0:
		return netip.AddrFrom4([4]byte{203, 0, 113, byte(rng.Intn(256))})
	case 1:
		return netip.AddrFrom4([4]byte{198, 51, 100, byte(rng.Intn(256))})
	case 2, 3:
		return netip.AddrFrom4([4]byte{172, 16, byte(rng.Intn(256)), byte(rng.Intn(256))})
	case 4:
		return netip.AddrFrom4([4]byte{192, 168, byte(rng.Intn(256)), byte(rng.Intn(256))})
	default:
		return netip.AddrFrom4([4]byte{10, byte(rng.Intn(40)), byte(rng.Intn(256)), byte(rng.Intn(256))})
	}
}
