// Command tessaraop exercises the policy engine from the terminal.
//
//	-demo         walk a hand-written policy set covering every operator
//	-bench        generate a corpus and compare naive against the engine
//	-interactive  type request attributes and see decisions
package main

import (
	"bufio"
	"flag"
	"fmt"
	"math/rand"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/suga/tessaraop/internal/engine"
	"github.com/suga/tessaraop/internal/genutil"
	"github.com/suga/tessaraop/internal/model"
	"github.com/suga/tessaraop/internal/naive"
)

func main() {
	var (
		policies    = flag.Int("n", 100_000, "number of tenant policies to generate")
		tenants     = flag.Int("tenants", 1_000, "number of tenants to spread them across")
		globals     = flag.Int("globals", 50, "number of platform-wide policies")
		requests    = flag.Int("requests", 10, "requests to evaluate in bench mode")
		seed        = flag.Int64("seed", 42, "random seed")
		cacheSize   = flag.Int("cache", 0, "decision cache entries (0 disables)")
		algorithm   = flag.String("alg", "deny-overrides", "deny-overrides | permit-overrides | first-applicable")
		compare     = flag.Bool("compare", true, "also run the naive evaluator to verify agreement")
		demo        = flag.Bool("demo", false, "run the hand-written policy walkthrough")
		interactive = flag.Bool("interactive", false, "enter interactive request mode")
	)
	flag.Parse()

	if *demo {
		runDemo()
		return
	}

	cfg := engine.Config{
		Algorithm: model.Algorithm(*algorithm),
		CacheSize: *cacheSize,
	}

	fmt.Printf("Generating %s tenant policies across %s tenants (+%d global, seed=%d)...\n",
		comma(*policies), comma(*tenants), *globals, *seed)
	rng := rand.New(rand.NewSource(*seed))
	corpus := genutil.Generate(genutil.Options{
		Policies: *policies, Tenants: *tenants, Global: *globals,
	}, rng)

	fmt.Print("Building shards and indexes...\n")
	start := time.Now()
	eng := engine.New(corpus.Policies, cfg)
	buildTime := time.Since(start)

	printCorpusSummary(corpus, eng, buildTime)

	if *interactive {
		runInteractive(eng, corpus)
		return
	}
	runBench(eng, corpus, rng, *requests, *compare, cfg)
}

func printCorpusSummary(c *genutil.Corpus, eng *engine.Engine, build time.Duration) {
	counts := map[string]int{}
	condTotal, opCounts := 0, map[model.Operator]int{}
	for _, p := range c.Policies {
		counts[p.TenantID]++
		condTotal += len(p.Conditions)
		for _, cond := range p.Conditions {
			opCounts[cond.Operator]++
		}
	}

	sizes := make([]int, 0, len(counts))
	for tenant, n := range counts {
		if tenant != model.GlobalTenant {
			sizes = append(sizes, n)
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(sizes)))

	fmt.Printf("\nCorpus\n")
	fmt.Printf("  Policies:         %s\n", comma(eng.TotalPolicies()))
	fmt.Printf("  Tenants:          %s\n", comma(eng.TenantCount()))
	fmt.Printf("  Conditions:       %s (avg %.1f per policy)\n",
		comma(condTotal), float64(condTotal)/float64(len(c.Policies)))
	fmt.Printf("  Index build:      %v\n", build.Round(time.Millisecond))

	if len(sizes) > 0 {
		fmt.Printf("  Shards:           %s\n", comma(eng.ShardCount()))
		fmt.Printf("  Tenant sizes:     largest %s, median %s, smallest %s\n",
			comma(sizes[0]), comma(sizes[len(sizes)/2]), comma(sizes[len(sizes)-1]))
		worst := 0
		for _, sc := range c.Scopes {
			if n := eng.InScope(c.Tenants[0], sc); n > worst {
				worst = n
			}
		}
		fmt.Printf("  In scope / req:   %s worst case, on the largest tenant (%.4f%% of corpus)\n",
			comma(worst), 100*float64(worst)/float64(eng.TotalPolicies()))
	}

	fmt.Printf("\nOperator mix\n")
	ops := make([]model.Operator, 0, len(opCounts))
	for op := range opCounts {
		ops = append(ops, op)
	}
	sort.Slice(ops, func(i, j int) bool { return opCounts[ops[i]] > opCounts[ops[j]] })
	for _, op := range ops {
		fmt.Printf("  %-10s %s\n", op, comma(opCounts[op]))
	}
}

func runBench(eng *engine.Engine, c *genutil.Corpus, rng *rand.Rand,
	n int, compare bool, cfg engine.Config) {

	var ref *naive.Evaluator
	if compare {
		alg := cfg.Algorithm
		if alg == "" {
			alg = model.DenyOverrides
		}
		ref = naive.NewWith(c.Policies, alg)
	}

	fmt.Printf("\nEvaluating %d requests\n\n", n)
	fmt.Printf("%-4s %-8s %-22s %10s %10s %10s %9s %s\n",
		"#", "Result", "Matched", "Engine", "Naive", "Speedup", "Validated", "Agree")
	fmt.Println(strings.Repeat("-", 100))

	var totalEngine, totalNaive time.Duration
	mismatches := 0

	for i := 0; i < n; i++ {
		req := c.GenerateRequest(rng)

		start := time.Now()
		got := eng.Evaluate(req)
		engDur := time.Since(start)
		totalEngine += engDur

		result := "DENY"
		if got.Allowed {
			result = "ALLOW"
		}
		matched := got.MatchedPolicyID
		if matched == "" {
			matched = "(default-deny)"
		}

		naiveCol, speedup, agree := "-", "-", "-"
		if ref != nil {
			start = time.Now()
			want := ref.Evaluate(req)
			naiveDur := time.Since(start)
			totalNaive += naiveDur

			naiveCol = naiveDur.Round(time.Microsecond).String()
			speedup = fmt.Sprintf("%.0fx", float64(naiveDur)/float64(engDur))
			agree = "ok"
			if want.Allowed != got.Allowed || want.MatchedPolicyID != got.MatchedPolicyID {
				agree = "MISMATCH"
				mismatches++
			}
		}

		fmt.Printf("%-4d %-8s %-22s %10v %10s %10s %9d %s\n",
			i+1, result, truncate(matched, 22), engDur.Round(time.Microsecond),
			naiveCol, speedup, got.PoliciesScanned, agree)
	}

	fmt.Printf("\nSummary\n")
	fmt.Printf("  Engine total:  %v  (avg %v)\n",
		totalEngine.Round(time.Microsecond), (totalEngine / time.Duration(n)).Round(time.Nanosecond))
	if ref != nil {
		fmt.Printf("  Naive total:   %v  (avg %v)\n",
			totalNaive.Round(time.Microsecond), (totalNaive / time.Duration(n)).Round(time.Nanosecond))
		fmt.Printf("  Speedup:       %.0fx\n", float64(totalNaive)/float64(totalEngine))
		fmt.Printf("  Mismatches:    %d / %d\n", mismatches, n)
		if mismatches == 0 {
			fmt.Printf("  Correctness:   verified against the naive oracle\n")
		}
	}
	fmt.Printf("  Throughput:    %s requests/sec single-threaded\n",
		comma(int(float64(n)/totalEngine.Seconds())))
}

func runInteractive(eng *engine.Engine, c *genutil.Corpus) {
	fmt.Printf("\nInteractive mode. Enter key=value pairs; 'quit' to exit.\n")
	fmt.Printf("Recognized numeric keys: subject.risk_score, time.hour\n")
	fmt.Printf("Recognized IP keys:      network.source_ip\n\n")
	fmt.Printf("Example:\n  tenant=%s scope=%s subject.role=admin action=read "+
		"resource.domain=api.%s.example.com resource.path=/api/v2/x "+
		"subject.risk_score=10 network.source_ip=10.0.0.5\n\n",
		c.Tenants[0], c.Scopes[0], c.Tenants[0])

	ref := naive.New(c.Policies)
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("request> ")
		if !scanner.Scan() {
			return
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "quit" || line == "exit" {
			return
		}
		if line == "" {
			continue
		}

		req := parseRequest(line)

		start := time.Now()
		got := eng.Evaluate(req)
		engDur := time.Since(start)

		start = time.Now()
		want := ref.Evaluate(req)
		naiveDur := time.Since(start)

		result := "DENIED"
		if got.Allowed {
			result = "ALLOWED"
		}
		fmt.Printf("\n  Tenant:     %s / scope %q (%s policies in scope)\n",
			req.TenantID, req.Scope, comma(eng.InScope(req.TenantID, req.Scope)))
		fmt.Printf("  Result:     %s\n", result)
		if got.MatchedPolicyID != "" {
			fmt.Printf("  Matched:    %s (%s)\n", got.MatchedPolicyID, got.Effect)
		} else {
			fmt.Printf("  Matched:    none — default deny\n")
		}
		if len(got.Obligations) > 0 {
			fmt.Printf("  Obligations: %s\n", strings.Join(got.Obligations, ", "))
		}
		fmt.Printf("  Engine:     %v, validated %d policies\n",
			engDur.Round(time.Nanosecond), got.PoliciesScanned)
		fmt.Printf("  Naive:      %v, scanned %d policies (%.0fx slower)\n",
			naiveDur.Round(time.Microsecond), want.PoliciesScanned,
			float64(naiveDur)/float64(engDur))
		if want.Allowed != got.Allowed {
			fmt.Printf("  WARNING:    engine and naive disagree\n")
		}
		fmt.Println()
	}
}

func parseRequest(line string) model.Request {
	req := model.Request{
		Attributes: map[string]string{},
		Numeric:    map[string]float64{},
		IPs:        map[string]netip.Addr{},
	}
	for _, part := range strings.Fields(line) {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		switch {
		case k == "tenant":
			req.TenantID = v
		case k == "scope":
			req.Scope = v
		case strings.Contains(k, "source_ip") || strings.Contains(k, "dest_ip"):
			if addr, err := netip.ParseAddr(v); err == nil {
				req.IPs[k] = addr
			}
		default:
			if f, err := strconv.ParseFloat(v, 64); err == nil &&
				(strings.Contains(k, "score") || strings.Contains(k, "hour") ||
					strings.Contains(k, "count")) {
				req.Numeric[k] = f
				continue
			}
			req.Attributes[k] = v
		}
	}
	return req
}

func runDemo() {
	fmt.Println("=== TessaraOP: a realistic policy set ===")

	policies := []model.Policy{
		{
			ID: "global-ip-blocklist", TenantID: model.GlobalTenant,
			Effect: model.Deny, Priority: 1000,
			Obligations: []string{"notify_soc"},
			Conditions: []model.Condition{{
				Attribute: "network.source_ip", Operator: model.OpCIDR,
				Prefixes: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}}},
		},
		{
			ID: "global-high-risk", TenantID: model.GlobalTenant,
			Effect: model.Deny, Priority: 999,
			Obligations: []string{"step_up_auth"},
			Conditions: []model.Condition{{
				Attribute: "subject.risk_score", Operator: model.OpGreaterThan, Min: 90}},
		},
		{
			ID: "acme-admin-console", TenantID: "acme", Effect: model.Allow, Priority: 100,
			Obligations: []string{"require_mfa", "audit_log"},
			Conditions: []model.Condition{
				{Attribute: "subject.role", Operator: model.OpIn,
					Values: []string{"admin", "security-admin"}},
				{Attribute: "subject.risk_score", Operator: model.OpRange, Min: 0, Max: 30},
				{Attribute: "subject.mfa_verified", Operator: model.OpEquals,
					Values: []string{"true"}},
				{Attribute: "network.source_ip", Operator: model.OpCIDR,
					Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}},
				{Attribute: "resource.domain", Operator: model.OpDNSSuffix,
					Values: []string{"admin.acme.com"}},
				{Attribute: "resource.path", Operator: model.OpPrefix,
					Values: []string{"/api/v2/admin"}},
				{Attribute: "time.hour", Operator: model.OpRange, Min: 9, Max: 17},
			},
		},
		{
			ID: "acme-readonly", TenantID: "acme", Effect: model.Allow, Priority: 10,
			Conditions: []model.Condition{
				{Attribute: "subject.role", Operator: model.OpNotIn,
					Values: []string{"service-account"}},
				{Attribute: "action", Operator: model.OpEquals, Values: []string{"read"}},
				{Attribute: "resource.domain", Operator: model.OpDNSSuffix,
					Values: []string{"acme.com"}},
			},
		},
		{
			ID: "acme-deny-prod-delete", TenantID: "acme", Effect: model.Deny, Priority: 500,
			Conditions: []model.Condition{
				{Attribute: "action", Operator: model.OpEquals, Values: []string{"delete"}},
				{Attribute: "resource.sensitivity", Operator: model.OpIn,
					Values: []string{"critical"}},
			},
		},
	}

	for _, p := range policies {
		fmt.Printf("\n[%s] %s  (tenant=%s, priority=%d)\n",
			p.Effect, p.ID, p.TenantID, p.Priority)
		for _, c := range p.Conditions {
			fmt.Printf("    %s\n", describe(c))
		}
		if len(p.Obligations) > 0 {
			fmt.Printf("    -> obligations: %s\n", strings.Join(p.Obligations, ", "))
		}
	}

	eng := engine.New(policies, engine.Config{})
	ref := naive.New(policies)

	cases := []struct {
		name string
		req  model.Request
	}{
		{"Admin, MFA, corp network, business hours", model.Request{
			TenantID: "acme",
			Attributes: map[string]string{
				"subject.role": "admin", "subject.mfa_verified": "true",
				"action": "write", "resource.domain": "api.admin.acme.com",
				"resource.path": "/api/v2/admin/users"},
			Numeric: map[string]float64{"subject.risk_score": 12, "time.hour": 14},
			IPs:     map[string]netip.Addr{"network.source_ip": netip.MustParseAddr("10.1.2.3")},
		}},
		{"Same admin, but from a blocklisted IP", model.Request{
			TenantID: "acme",
			Attributes: map[string]string{
				"subject.role": "admin", "subject.mfa_verified": "true",
				"action": "write", "resource.domain": "api.admin.acme.com",
				"resource.path": "/api/v2/admin/users"},
			Numeric: map[string]float64{"subject.risk_score": 12, "time.hour": 14},
			IPs:     map[string]netip.Addr{"network.source_ip": netip.MustParseAddr("203.0.113.9")},
		}},
		{"Same admin, risk score 95", model.Request{
			TenantID: "acme",
			Attributes: map[string]string{
				"subject.role": "admin", "subject.mfa_verified": "true",
				"action": "write", "resource.domain": "api.admin.acme.com",
				"resource.path": "/api/v2/admin/users"},
			Numeric: map[string]float64{"subject.risk_score": 95, "time.hour": 14},
			IPs:     map[string]netip.Addr{"network.source_ip": netip.MustParseAddr("10.1.2.3")},
		}},
		{"Admin without MFA", model.Request{
			TenantID: "acme",
			Attributes: map[string]string{
				"subject.role": "admin", "subject.mfa_verified": "false",
				"action": "write", "resource.domain": "api.admin.acme.com",
				"resource.path": "/api/v2/admin/users"},
			Numeric: map[string]float64{"subject.risk_score": 12, "time.hour": 14},
			IPs:     map[string]netip.Addr{"network.source_ip": netip.MustParseAddr("10.1.2.3")},
		}},
		{"Viewer reading a public acme resource", model.Request{
			TenantID: "acme",
			Attributes: map[string]string{
				"subject.role": "viewer", "action": "read",
				"resource.domain": "www.acme.com", "resource.path": "/public/docs"},
			Numeric: map[string]float64{"subject.risk_score": 5, "time.hour": 11},
			IPs:     map[string]netip.Addr{"network.source_ip": netip.MustParseAddr("8.8.8.8")},
		}},
		{"Lookalike domain evilacme.com (bypass attempt)", model.Request{
			TenantID: "acme",
			Attributes: map[string]string{
				"subject.role": "viewer", "action": "read",
				"resource.domain": "evilacme.com", "resource.path": "/public/docs"},
			Numeric: map[string]float64{"subject.risk_score": 5, "time.hour": 11},
			IPs:     map[string]netip.Addr{"network.source_ip": netip.MustParseAddr("8.8.8.8")},
		}},
		{"Deleting a critical resource", model.Request{
			TenantID: "acme",
			Attributes: map[string]string{
				"subject.role": "admin", "subject.mfa_verified": "true",
				"action": "delete", "resource.sensitivity": "critical",
				"resource.domain": "api.admin.acme.com", "resource.path": "/api/v2/admin/db"},
			Numeric: map[string]float64{"subject.risk_score": 10, "time.hour": 14},
			IPs:     map[string]netip.Addr{"network.source_ip": netip.MustParseAddr("10.1.2.3")},
		}},
		{"Different tenant, same admin role", model.Request{
			TenantID: "other-corp",
			Attributes: map[string]string{
				"subject.role": "admin", "subject.mfa_verified": "true",
				"action": "read", "resource.domain": "api.admin.acme.com"},
			Numeric: map[string]float64{"subject.risk_score": 10, "time.hour": 14},
			IPs:     map[string]netip.Addr{"network.source_ip": netip.MustParseAddr("10.1.2.3")},
		}},
	}

	fmt.Printf("\n\n%-46s %-8s %-24s %s\n", "Scenario", "Result", "Matched", "Obligations")
	fmt.Println(strings.Repeat("-", 108))
	for _, tc := range cases {
		got := eng.Evaluate(tc.req)
		want := ref.Evaluate(tc.req)

		result := "DENY"
		if got.Allowed {
			result = "ALLOW"
		}
		matched := got.MatchedPolicyID
		if matched == "" {
			matched = "(default-deny)"
		}
		flag := ""
		if want.Allowed != got.Allowed || want.MatchedPolicyID != got.MatchedPolicyID {
			flag = "  <-- DISAGREES WITH NAIVE"
		}
		fmt.Printf("%-46s %-8s %-24s %s%s\n",
			truncate(tc.name, 46), result, truncate(matched, 24),
			strings.Join(got.Obligations, ","), flag)
	}

	fmt.Printf("\nNote the third and fourth rows: a global deny outranks a tenant's own\n")
	fmt.Printf("grant, which is deny-overrides doing its job. The sixth row is the\n")
	fmt.Printf("label-alignment check — evilacme.com does not inherit acme.com's grant.\n")
}

func describe(c model.Condition) string {
	switch c.Operator {
	case model.OpRange:
		return fmt.Sprintf("%s in [%g, %g]", c.Attribute, c.Min, c.Max)
	case model.OpGreaterThan:
		return fmt.Sprintf("%s > %g", c.Attribute, c.Min)
	case model.OpLessThan:
		return fmt.Sprintf("%s < %g", c.Attribute, c.Max)
	case model.OpCIDR, model.OpNotCIDR:
		parts := make([]string, len(c.Prefixes))
		for i, p := range c.Prefixes {
			parts[i] = p.String()
		}
		op := "in"
		if c.Operator == model.OpNotCIDR {
			op = "not in"
		}
		return fmt.Sprintf("%s %s %s", c.Attribute, op, strings.Join(parts, ", "))
	case model.OpExists:
		return fmt.Sprintf("%s exists", c.Attribute)
	case model.OpNotExists:
		return fmt.Sprintf("%s absent", c.Attribute)
	default:
		return fmt.Sprintf("%s %s %v", c.Attribute, c.Operator, c.Values)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func comma(n int) string {
	s := strconv.Itoa(n)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	pre := len(s) % 3
	if pre > 0 {
		b.WriteString(s[:pre])
	}
	for i := pre; i < len(s); i += 3 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(s[i : i+3])
	}
	return b.String()
}
