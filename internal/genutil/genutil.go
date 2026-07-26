// Package genutil generates synthetic policy corpora and request streams that
// resemble production authorization workloads.
//
// Four properties matter for the benchmarks to mean anything.
//
// First, a shared vocabulary. Values are drawn from small realistic sets (roles,
// departments, CIDR blocks, ports, path roots) rather than being unique per
// policy. Unique values would give every hash bucket exactly one member and make
// indexing look far better than it is; real IAM corpora have thousands of
// policies referencing the same handful of roles and networks.
//
// Second, realistic tenancy. Policies are distributed across tenants with a
// skewed distribution rather than uniformly, because real platforms have a few
// enormous customers and a long tail of small ones. A uniform split would hide
// the worst case that actually matters — the request that lands on the biggest
// shard.
//
// Third, multi-rule policies. A policy carrying one implicitly-AND-ed condition
// list is the easy case for the index; a policy holding several rules that must
// be combined under a rule-level algorithm is the real one. Generated policies
// hold between one and RulesPerPolicy rules.
//
// Fourth, and most important now that conditions form boolean trees: a realistic
// share of rules must sit partly *off* the AND-spine. Only leaves reachable
// through exclusively And nodes can be indexed, so a corpus of pure conjunctions
// would report a speedup the engine does not actually deliver on expressive
// policy. Roughly a quarter of generated rules place a condition under an Or and
// a further sixth under a Not, both of which are invisible to the index and must
// be resolved by full validation.
package genutil

import (
	"fmt"
	"math/rand"
	"net/netip"

	"github.com/suga/tessaraop/internal/attr"
	"github.com/suga/tessaraop/internal/model"
)

var (
	roles         = []string{"viewer", "editor", "admin", "security-admin", "auditor", "service-account"}
	departments   = []string{"engineering", "sales", "marketing", "finance", "hr", "legal", "ops", "security", "product", "support"}
	actions       = []string{"read", "write", "delete", "admin", "audit"}
	sensitivities = []string{"low", "medium", "high", "critical"}
	countries     = []string{"US", "CA", "GB", "DE", "IN", "JP", "AU", "BR"}
	pathRoots     = []string{"/api/v1", "/api/v2", "/api/v2/admin", "/internal", "/public", "/admin/console"}
	// Scopes subdivide a tenant, typically by resource family. Policies land in
	// one of these or at tenant-wide scope.
	scopes      = []string{"billing", "identity", "storage", "compute", "network", "analytics", "support", "audit"}
	obligations = []string{"require_mfa", "audit_log", "rate_limit", "step_up_auth", "notify_soc"}

	// Layer 4 vocabulary. Service ports repeat heavily across a real corpus,
	// which is exactly the shape NumSetIndex is built for.
	servicePorts  = []float64{22, 80, 443, 3306, 3389, 5432, 6379, 8080, 8443, 9200}
	adminPorts    = []float64{22, 3389, 5985}
	tcpFlagCombos = []string{"syn", "syn,ack", "ack", "fin,ack", "psh,ack", "fin,syn", "rst"}
	connStates    = []string{"new", "established", "related", "invalid"}
	protocolNames = []string{"tcp", "udp", "icmp", "gre", "esp"}

	// Layer 7 vocabulary.
	httpMethods  = []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
	httpVersions = []string{"HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/3"}
	contentTypes = []string{"application/json", "application/x-www-form-urlencoded", "multipart/form-data", "text/xml"}
	scannerUAs   = []string{"sqlmap", "nikto", "nmap", "masscan", "dirbuster"}
	browserUAs   = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/17.0",
		"curl/8.4.0",
	}
	dangerousExts = []string{".exe", ".bat", ".php", ".sh", ".jsp", ".dll"}
	benignExts    = []string{".pdf", ".png", ".csv", ".txt", ".json"}

	// A small signature set, reused across the corpus. Regex is not indexable,
	// so every rule carrying one is validated in full whenever its shard is
	// reached — keeping the set small mirrors how WAF rule sets actually
	// deduplicate signatures rather than inventing one per rule.
	attackSignatures = []string{
		`(?i)union\s+all?\s*select`,
		`(?i)<script[^>]*>`,
		`(?i)\bexec\s*\(`,
		`\.\./\.\./`,
	}

	tlsVersions = []string{"SSLv3", "TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3"}
	// tls.version_num encodes the same versions on a scale monotonic in protocol
	// age, so a floor ("at least 1.2") is one comparison rather than an
	// enumerated set that needs editing whenever a new version ships. SSLv3 is 3,
	// not 30, so that it sorts below TLS 1.0 rather than above TLS 1.3.
	tlsVersionNums = []float64{3, 10, 11, 12, 13}
	proxyTypes     = []string{"none", "tor", "vpn", "proxy", "hosting"}

	// Body size ceilings policies commonly enforce, in bytes.
	bodyLimits = []float64{1 << 10, 1 << 12, 1 << 14, 1 << 16, 1 << 20}

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

	// RulesPerPolicy caps how many rules a generated policy holds. Zero means
	// 3. Set it to 1 to reproduce the pre-Rule flat corpus for comparison.
	RulesPerPolicy int
}

// Generate builds a corpus. Tenant sizes follow a skewed distribution: tenant 0
// is the whale, and size falls off from there, so benchmarks exercise both the
// common small shard and the pathological large one.
func Generate(opt Options, rng *rand.Rand) *Corpus {
	if opt.Tenants < 1 {
		opt.Tenants = 1
	}
	if opt.RulesPerPolicy < 1 {
		opt.RulesPerPolicy = 3
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
			c.Policies = append(c.Policies, tenantPolicy(c.Tenants[t], idx, opt.RulesPerPolicy, rng))
			idx++
		}
	}
	return c
}

// RuleCount reports the total rule count, which is the size of the indexed
// universe and the number the per-request cost actually tracks.
func (c *Corpus) RuleCount() int {
	n := 0
	for i := range c.Policies {
		n += c.Policies[i].RuleCount()
	}
	return n
}

// globalPolicy produces a platform-level policy: IP blocklists, geo blocks,
// scanner signatures and blanket kill switches. These are deliberately cheap to
// match and heavily deny-weighted, since that is what platform policy looks like
// in practice. Each holds several rules under deny-overrides, mirroring how a
// single "platform baseline" document accumulates independent tripwires.
func globalPolicy(i int, rng *rand.Rand) model.Policy {
	p := model.Policy{
		ID:            fmt.Sprintf("global-%04d", i),
		TenantID:      model.GlobalTenant,
		Priority:      1000,
		RuleAlgorithm: model.DenyOverrides,
	}
	rid := func(k int) string { return fmt.Sprintf("%s/r%d", p.ID, k) }

	switch i % 5 {
	case 0:
		// Blocklisted source, or a Tor/VPN exit — a disjunction, so neither
		// branch is indexable and both are resolved by validation.
		p.Rules = []model.Rule{{
			ID: rid(0), Effect: model.Deny, Priority: 1000,
			When: model.Or(
				model.Cond(model.Condition{
					Attribute: attr.SourceIP, Operator: model.OpCIDR,
					Prefixes: []netip.Prefix{blockedNets[rng.Intn(len(blockedNets))]}}),
				model.Cond(model.Condition{
					Attribute: attr.ProxyType, Operator: model.OpIn,
					Values: []string{"tor", "proxy"}}),
			),
			Obligations: []string{"notify_soc"},
		}}

	case 1:
		p.Rules = []model.Rule{
			{
				ID: rid(0), Effect: model.Deny, Priority: 1000,
				When: model.Cond(model.Condition{
					Attribute: attr.RiskScore, Operator: model.OpGreaterThan, Min: 90}),
				Obligations: []string{"step_up_auth", "notify_soc"},
			},
			{
				ID: rid(1), Effect: model.Deny, Priority: 900,
				When: model.Cond(model.Condition{
					Attribute: attr.ThreatRep, Operator: model.OpGreaterEq, Min: 80}),
				Obligations: []string{"notify_soc"},
			},
		}

	case 2:
		p.Rules = []model.Rule{{
			ID: rid(0), Effect: model.Deny, Priority: 1000,
			When: model.And(
				model.Cond(model.Condition{
					Attribute: attr.GeoCountry, Operator: model.OpIn, Values: []string{"BR"}}),
				model.Cond(model.Condition{
					Attribute: attr.Sensitivity, Operator: model.OpIn, Values: []string{"critical"}}),
			),
		}}

	case 3:
		// Scanner user agents and attack signatures. Both non-indexable, which
		// is realistic: WAF signature rules are validated, not looked up.
		p.Rules = []model.Rule{
			{
				ID: rid(0), Effect: model.Deny, Priority: 1000,
				When: model.Cond(model.Condition{
					Attribute: attr.UserAgent, Operator: model.OpContains,
					Values: scannerUAs}),
				Obligations: []string{"notify_soc"},
			},
			{
				ID: rid(1), Effect: model.Deny, Priority: 1000,
				When: model.Cond(model.Condition{
					Attribute: attr.HTTPQuery, Operator: model.OpRegex,
					Values: []string{attackSignatures[rng.Intn(len(attackSignatures))]}}),
				Obligations: []string{"notify_soc", "audit_log"},
			},
		}

	default:
		p.Rules = []model.Rule{
			{
				ID: rid(0), Effect: model.Deny, Priority: 1000,
				When: model.And(
					model.Cond(model.Condition{
						Attribute: attr.MFAVerified, Operator: model.OpEquals,
						Values: []string{"false"}}),
					model.Cond(model.Condition{
						Attribute: attr.Action, Operator: model.OpIn,
						Values: []string{"delete", "admin"}}),
				),
				Obligations: []string{"require_mfa"},
			},
			{
				// Weak TLS floor, expressed numerically so a new version does
				// not require editing the policy.
				ID: rid(1), Effect: model.Deny, Priority: 1000,
				When: model.Cond(model.Condition{
					Attribute: attr.TLSVersionNo, Operator: model.OpLessThan, Max: 12}),
			},
		}
	}
	return p
}

// tenantPolicy produces a customer-level policy holding one to maxRules rules,
// spanning the full operator surface across layers 3, 4 and 7.
func tenantPolicy(tenant string, i, maxRules int, rng *rand.Rand) model.Policy {
	// Most policies belong to one resource scope; a minority apply tenant-wide.
	// That split is what keeps a large customer's shard from becoming a single
	// six-figure blob.
	scope := scopes[rng.Intn(len(scopes))]
	if rng.Intn(10) == 0 {
		scope = model.TenantWideScope
	}

	p := model.Policy{
		ID:            fmt.Sprintf("%s-p%06d", tenant, i),
		TenantID:      tenant,
		Scope:         scope,
		Priority:      rng.Intn(100),
		RuleAlgorithm: model.DenyOverrides,
	}
	// A minority of policies resolve their rules by priority instead, which is
	// how "deny all except this one exception" is written.
	if rng.Intn(10) == 0 {
		p.RuleAlgorithm = model.FirstApplicable
	}

	nRules := 1 + rng.Intn(maxRules)
	p.Rules = make([]model.Rule, nRules)
	for k := 0; k < nRules; k++ {
		p.Rules[k] = tenantRule(tenant, p.ID, k, rng)
	}
	return p
}

// tenantRule builds one rule: a conjunctive core of indexable conditions, then
// with some probability an off-spine disjunction or negation layered on.
func tenantRule(tenant, policyID string, k int, rng *rand.Rand) model.Rule {
	r := model.Rule{
		ID:       fmt.Sprintf("%s/r%d", policyID, k),
		Effect:   model.Allow,
		Priority: rng.Intn(100),
	}
	if rng.Intn(5) == 0 {
		r.Effect = model.Deny
	}

	spine := make([]*model.ConditionExpr, 0, 8)
	add := func(c model.Condition) { spine = append(spine, model.Cond(c)) }

	// -- Identity: the workhorse equality conditions, present on most rules. --
	if rng.Intn(10) < 8 {
		if rng.Intn(3) == 0 {
			n := 1 + rng.Intn(2)
			vals := make([]string, n)
			for j := range vals {
				vals[j] = roles[rng.Intn(len(roles))]
			}
			add(model.Condition{Attribute: attr.SubjectRole, Operator: model.OpIn, Values: vals})
		} else {
			add(model.Condition{Attribute: attr.SubjectRole, Operator: model.OpEquals,
				Values: []string{roles[rng.Intn(len(roles))]}})
		}
	}
	if rng.Intn(10) < 6 {
		add(model.Condition{Attribute: "subject.department", Operator: model.OpEquals,
			Values: []string{departments[rng.Intn(len(departments))]}})
	}
	if rng.Intn(10) < 2 {
		add(model.Condition{Attribute: attr.SubjectRole, Operator: model.OpNotIn,
			Values: []string{"service-account"}})
	}
	if rng.Intn(10) < 5 {
		add(model.Condition{Attribute: attr.Action, Operator: model.OpIn,
			Values: []string{actions[rng.Intn(len(actions))]}})
	}
	if rng.Intn(10) < 5 {
		add(model.Condition{Attribute: attr.Sensitivity, Operator: model.OpIn,
			Values: []string{sensitivities[rng.Intn(len(sensitivities))]}})
	}
	// Risk score band — a handful of distinct bands across the corpus, which is
	// exactly the shape IntervalIndex is designed for.
	if rng.Intn(10) < 4 {
		add(model.Condition{Attribute: attr.RiskScore, Operator: model.OpRange,
			Min: 0, Max: float64(20 + 20*rng.Intn(4))})
	}
	if rng.Intn(10) < 3 {
		add(model.Condition{Attribute: attr.TimeHour, Operator: model.OpRange, Min: 9, Max: 17})
	}
	if rng.Intn(10) < 3 {
		add(model.Condition{Attribute: attr.MFAVerified, Operator: model.OpEquals,
			Values: []string{"true"}})
	}
	if rng.Intn(10) < 2 {
		add(model.Condition{Attribute: attr.GeoCountry, Operator: model.OpIn,
			Values: []string{countries[rng.Intn(len(countries))]}})
	}

	// -- Layer 3 / 4. --
	if rng.Intn(10) < 4 {
		add(model.Condition{Attribute: attr.SourceIP, Operator: model.OpCIDR,
			Prefixes: []netip.Prefix{corpNets[rng.Intn(len(corpNets))]}})
	}
	if rng.Intn(10) < 1 {
		add(model.Condition{Attribute: attr.SourceIP, Operator: model.OpNotCIDR,
			Prefixes: []netip.Prefix{blockedNets[rng.Intn(len(blockedNets))]}})
	}
	if rng.Intn(10) < 3 {
		// Discrete port set — the num_in case.
		n := 1 + rng.Intn(3)
		ports := make([]float64, n)
		for j := range ports {
			ports[j] = servicePorts[rng.Intn(len(servicePorts))]
		}
		add(model.Condition{Attribute: attr.DestPort, Operator: model.OpNumIn, Numbers: ports})
	}
	if rng.Intn(10) < 2 {
		add(model.Condition{Attribute: "network.protocol_name", Operator: model.OpEquals,
			Values: []string{protocolNames[rng.Intn(len(protocolNames))]}})
	}
	if rng.Intn(10) < 2 {
		add(model.Condition{Attribute: attr.ConnState, Operator: model.OpIn,
			Values: []string{connStates[rng.Intn(len(connStates))]}})
	}
	if rng.Intn(10) < 1 {
		add(model.Condition{Attribute: attr.TCPFlags, Operator: model.OpEquals,
			Values: []string{tcpFlagCombos[rng.Intn(len(tcpFlagCombos))]}})
	}
	if rng.Intn(10) < 1 {
		add(model.Condition{Attribute: "network.ttl", Operator: model.OpGreaterEq, Min: 32})
	}

	// -- Layer 7. --
	if rng.Intn(10) < 4 {
		add(model.Condition{Attribute: "resource.domain", Operator: model.OpDNSSuffix,
			Values: []string{fmt.Sprintf("%s.example.com", tenant)}})
	}
	if rng.Intn(10) < 4 {
		add(model.Condition{Attribute: attr.ResourcePath, Operator: model.OpPrefix,
			Values: []string{pathRoots[rng.Intn(len(pathRoots))]}})
	}
	if rng.Intn(10) < 3 {
		add(model.Condition{Attribute: attr.HTTPMethod, Operator: model.OpIn,
			Values: []string{httpMethods[rng.Intn(len(httpMethods))]}})
	}
	if rng.Intn(10) < 2 {
		add(model.Condition{Attribute: attr.ContentType, Operator: model.OpEquals,
			Values: []string{contentTypes[rng.Intn(len(contentTypes))]}})
	}
	if rng.Intn(10) < 2 {
		add(model.Condition{Attribute: attr.ContentLen, Operator: model.OpLessEq,
			Max: bodyLimits[rng.Intn(len(bodyLimits))]})
	}
	if rng.Intn(10) < 2 {
		// File extension filtering — the suffix index.
		exts := dangerousExts
		if rng.Intn(2) == 0 {
			exts = benignExts
		}
		add(model.Condition{Attribute: attr.FileExt, Operator: model.OpSuffix,
			Values: []string{exts[rng.Intn(len(exts))]}})
	}
	if rng.Intn(10) < 2 {
		add(model.Condition{Attribute: attr.TLSVersion, Operator: model.OpIn,
			Values: []string{tlsVersions[len(tlsVersions)-1-rng.Intn(2)]}})
	}
	if rng.Intn(10) < 1 {
		// A signature check: non-indexable, resolved by validation.
		add(model.Condition{Attribute: attr.HTTPQuery, Operator: model.OpRegex,
			Values: []string{attackSignatures[rng.Intn(len(attackSignatures))]}})
	}

	// -- Off-spine structure. This is what makes the corpus honest about the
	// cost of expressiveness: neither branch below can be indexed. --

	// A disjunction: "role is admin OR department is security".
	if rng.Intn(4) == 0 {
		spine = append(spine, model.Or(
			model.Cond(model.Condition{Attribute: attr.SubjectRole, Operator: model.OpEquals,
				Values: []string{roles[rng.Intn(len(roles))]}}),
			model.Cond(model.Condition{Attribute: "subject.department", Operator: model.OpEquals,
				Values: []string{departments[rng.Intn(len(departments))]}}),
		))
	}

	// A negation: "NOT (source is an admin port)".
	if rng.Intn(6) == 0 {
		spine = append(spine, model.Not(
			model.Cond(model.Condition{Attribute: attr.DestPort, Operator: model.OpNumIn,
				Numbers: adminPorts}),
		))
	}

	if rng.Intn(10) < 3 {
		r.Obligations = []string{obligations[rng.Intn(len(obligations))]}
	}
	r.When = model.And(spine...)
	return r
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

// requestFor builds one request carrying every attribute the generated policies
// reference. A request missing an attribute would be filtered out by the
// requires-present pruning rather than exercising the real indexes, so the
// benchmark would flatter the engine.
func (c *Corpus) requestFor(tenant string, rng *rand.Rand) model.Request {
	mfa := "true"
	if rng.Intn(4) == 0 {
		mfa = "false"
	}
	ua := browserUAs[rng.Intn(len(browserUAs))]
	if rng.Intn(20) == 0 {
		ua = scannerUAs[rng.Intn(len(scannerUAs))] + "/1.0"
	}
	query := fmt.Sprintf("page=%d&sort=name", rng.Intn(100))
	if rng.Intn(20) == 0 {
		query = "id=1%20UNION%20ALL%20SELECT%20password%20FROM%20users"
	}
	ext := benignExts[rng.Intn(len(benignExts))]
	if rng.Intn(8) == 0 {
		ext = dangerousExts[rng.Intn(len(dangerousExts))]
	}

	return model.Request{
		TenantID: tenant,
		Scope:    scopes[rng.Intn(len(scopes))],
		Attributes: map[string]string{
			attr.SubjectRole:           roles[rng.Intn(len(roles))],
			"subject.department":       departments[rng.Intn(len(departments))],
			attr.MFAVerified:           mfa,
			attr.Action:                actions[rng.Intn(len(actions))],
			attr.Sensitivity:           sensitivities[rng.Intn(len(sensitivities))],
			"resource.domain":          fmt.Sprintf("api.%s.example.com", tenant),
			attr.ResourcePath:          pathRoots[rng.Intn(len(pathRoots))] + "/items/42",
			attr.GeoCountry:            countries[rng.Intn(len(countries))],
			attr.ProxyType:             proxyTypes[rng.Intn(len(proxyTypes))],
			"network.protocol_name":    protocolNames[rng.Intn(len(protocolNames))],
			attr.ConnState:             connStates[rng.Intn(len(connStates))],
			attr.TCPFlags:              tcpFlagCombos[rng.Intn(len(tcpFlagCombos))],
			attr.HTTPMethod:            httpMethods[rng.Intn(len(httpMethods))],
			attr.HTTPVersion:           httpVersions[rng.Intn(len(httpVersions))],
			attr.ContentType:           contentTypes[rng.Intn(len(contentTypes))],
			attr.UserAgent:             ua,
			attr.HTTPQuery:             query,
			attr.FileExt:               ext,
			attr.TLSVersion:            tlsVersions[rng.Intn(len(tlsVersions))],
			"tls.client_cert_verified": boolStr(rng.Intn(4) != 0),
		},
		Numeric: map[string]float64{
			attr.RiskScore:    float64(rng.Intn(100)),
			attr.TimeHour:     float64(rng.Intn(24)) + rng.Float64(),
			attr.DestPort:     servicePorts[rng.Intn(len(servicePorts))],
			attr.SourcePort:   float64(32768 + rng.Intn(28000)),
			"network.ttl":     float64(1 + rng.Intn(64)),
			attr.ThreatRep:    float64(rng.Intn(100)),
			attr.ContentLen:   float64(rng.Intn(1 << 16)),
			attr.TLSVersionNo: tlsVersionNums[rng.Intn(len(tlsVersionNums))],
		},
		IPs: map[string]netip.Addr{
			attr.SourceIP: randomAddr(rng),
		},
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// randomAddr returns an address weighted toward corporate space, with a minority
// from public and blocklisted ranges — roughly the mix a corporate gateway sees.
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
