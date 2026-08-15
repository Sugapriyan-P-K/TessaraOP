// Command tessaraop exercises the policy engine from the terminal.
//
//	-demo          walk a hand-written policy set covering every operator family
//	-attrs         print the attribute registry an integration must populate
//	-lint FILE     validate and analyse a policy bundle; non-zero exit on errors
//	-export        write the demo policy set as a starter bundle on stdout
//	-import FORMAT translate a policy file from AWS IAM, Kubernetes NetworkPolicy
//	               or Envoy RBAC; bundle on stdout, fidelity report on stderr
//	-interactive   type request attributes and see decisions
//	(default)      generate a corpus and compare naive against the engine
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/suga/tessaraop/internal/attr"
	"github.com/suga/tessaraop/internal/bundle"
	"github.com/suga/tessaraop/internal/engine"
	"github.com/suga/tessaraop/internal/explain"
	"github.com/suga/tessaraop/internal/genutil"
	"github.com/suga/tessaraop/internal/model"
	"github.com/suga/tessaraop/internal/naive"
	"github.com/suga/tessaraop/pkg/tessaraop"
)

func main() {
	var (
		policies    = flag.Int("n", 100_000, "number of tenant policies to generate")
		tenants     = flag.Int("tenants", 1_000, "number of tenants to spread them across")
		globals     = flag.Int("globals", 50, "number of platform-wide policies")
		rulesPer    = flag.Int("rules", 3, "maximum rules per generated policy")
		requests    = flag.Int("requests", 10, "requests to evaluate in bench mode")
		seed        = flag.Int64("seed", 42, "random seed")
		cacheSize   = flag.Int("cache", 0, "decision cache entries (0 disables)")
		algorithm   = flag.String("alg", "deny-overrides", "deny-overrides | permit-overrides | first-applicable")
		compare     = flag.Bool("compare", true, "also run the naive evaluator to verify agreement")
		demo        = flag.Bool("demo", false, "run the hand-written policy walkthrough")
		attrs       = flag.Bool("attrs", false, "print the attribute registry and exit")
		interactive = flag.Bool("interactive", false, "enter interactive request mode")
		lintPath    = flag.String("lint", "", "validate a policy bundle and exit")
		strictAttrs = flag.Bool("strict-attributes", false,
			"with -lint, reject attributes outside the registry")
		export = flag.Bool("export", false,
			"write the demo policy set as a starter bundle on stdout and exit")
		importFormat = flag.String("import", "",
			"translate a policy file: aws-iam | k8s-networkpolicy | envoy-rbac")
		importFile = flag.String("import-file", "",
			"the file to translate with -import")
		importTenant = flag.String("import-tenant", "",
			"tenant for imported policies (NetworkPolicy defaults to the namespace)")
		importScope = flag.String("import-scope", "",
			"scope for imported policies")
		allowWidening = flag.Bool("allow-widening", false,
			"permit an import whose result accepts more than the source did; "+
				"read the report before setting this")
	)
	flag.Parse()

	if *importFormat != "" {
		os.Exit(runImport(*importFormat, *importFile, tessaraop.ImportOptions{
			Tenant:        *importTenant,
			Scope:         *importScope,
			AllowWidening: *allowWidening,
		}))
	}

	if *attrs {
		printRegistry()
		return
	}
	if *lintPath != "" {
		os.Exit(runLint(*lintPath, *strictAttrs))
	}
	if *export {
		if err := tessaraop.ExportBundle(demoPolicies(), os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "export: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if *demo {
		runDemo()
		return
	}

	cfg := engine.Config{
		Algorithm: model.Algorithm(*algorithm),
		CacheSize: *cacheSize,
	}

	fmt.Printf("Generating %s tenant policies across %s tenants (+%d global, <=%d rules each, seed=%d)...\n",
		comma(*policies), comma(*tenants), *globals, *rulesPer, *seed)
	rng := rand.New(rand.NewSource(*seed))
	corpus := genutil.Generate(genutil.Options{
		Policies: *policies, Tenants: *tenants, Global: *globals,
		RulesPerPolicy: *rulesPer,
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

// printExplanation renders why a request produced the decision it did.
//
// Values are shown rather than redacted, because this runs against a local
// synthetic corpus in a terminal the operator already owns. The server default is
// the opposite.
func printExplanation(policies []model.Policy, req model.Request, alg model.Algorithm) {
	opt := explain.DefaultOptions()
	opt.Redact = false
	opt.MaxPolicies = 6
	ex := explain.Explain(policies, req, alg, opt)

	fmt.Printf("  Why:         %s\n", ex.Summary)

	// The aggregate is usually the real answer during onboarding: a policy set
	// that denies everything normally does so because one attribute is never
	// supplied.
	if unmatched := ex.UnmatchedAttributes(); len(unmatched) > 0 {
		fmt.Printf("  Blocked on:  ")
		parts := make([]string, 0, 4)
		for i, u := range unmatched {
			if i == 4 {
				break
			}
			note := fmt.Sprintf("%s (%d)", u.Attribute, u.Failures)
			if u.Absent == u.Failures {
				note += " not supplied"
			}
			parts = append(parts, note)
		}
		fmt.Printf("%s\n", strings.Join(parts, ", "))
	}

	// One nearly-matching rule, which is what an author actually wants to see.
	for _, p := range ex.Policies {
		for _, r := range p.Rules {
			if !r.Matched && r.Why != "" {
				fmt.Printf("  Closest:     %s/%s — %s\n", p.PolicyID, r.RuleID, r.Why)
				return
			}
		}
	}
}

// runImport translates a policy file from another engine and writes a bundle on
// stdout, with the fidelity report on stderr so the two can be separated.
//
// A translation that would broaden access exits non-zero without emitting a
// bundle, unless -allow-widening says the operator has read the report and
// accepted it. Silently producing a more permissive policy set is the failure
// this whole path is designed around.
func runImport(format, path string, opt tessaraop.ImportOptions) int {
	if path == "" {
		fmt.Fprintln(os.Stderr, "-import requires -import-file")
		return 2
	}
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot read %s: %v\n", path, err)
		return 1
	}
	defer f.Close()

	name := filepath.Base(path)
	var res *tessaraop.ImportResult
	switch format {
	case "aws-iam":
		res, err = tessaraop.ImportAWSIAM(f, name, opt)
	case "k8s-networkpolicy":
		res, err = tessaraop.ImportK8sNetworkPolicy(f, name, opt)
	case "envoy-rbac":
		res, err = tessaraop.ImportEnvoyRBAC(f, name, opt)
	default:
		fmt.Fprintf(os.Stderr,
			"unknown format %q; valid values are aws-iam, k8s-networkpolicy, envoy-rbac\n",
			format)
		return 2
	}

	// The report goes to stderr whether or not the import succeeded, because it
	// is what the operator needs in order to decide about -allow-widening.
	if res != nil {
		fmt.Fprint(os.Stderr, res.Report.String())
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nimport failed: %v\n", err)
		if errors.Is(err, tessaraop.ErrImportWidensAccess) {
			fmt.Fprintln(os.Stderr,
				"Review the WIDENING ACCESS notes above. Each one is a construct whose\n"+
					"loss makes the result accept something the source refused. Fix the\n"+
					"source, or pass -allow-widening once you have accepted them.")
		}
		return 1
	}

	if err := tessaraop.ExportBundle(res.Policies, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "writing bundle: %v\n", err)
		return 1
	}

	// Lint and analyse what was produced, so a translation that is faithful but
	// nonsensical is caught here rather than at deploy time.
	diags := tessaraop.ValidatePolicies(res.Policies, tessaraop.LintOptions{})
	for _, d := range diags {
		fmt.Fprintf(os.Stderr, "%s\n", d)
	}
	if tessaraop.HasErrors(diags) {
		fmt.Fprintln(os.Stderr, "\nthe translated bundle does not lint cleanly")
		return 1
	}
	return 0
}

// runLint validates a bundle and reports findings, returning the process exit
// code. It is meant for CI: a policy change should fail the pipeline, not the
// request path.
func runLint(path string, strict bool) int {
	diags, err := tessaraop.LintBundleFile(path, tessaraop.LintOptions{StrictAttributes: strict})
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot read %s: %v\n", path, err)
		return 1
	}

	errs := tessaraop.Errors(diags)
	for _, d := range diags {
		fmt.Printf("%s\n", d)
	}

	// Report what the index will be able to prune on. A policy set written mostly
	// as disjunctions is correct but slow, and that is worth knowing before it
	// ships rather than after a latency alert.
	if b, rerr := bundle.ReadFile(path); rerr == nil {
		s := b.Summarize()
		fmt.Printf("\n%s: %d policies, %d rules, %d conditions across %d tenants\n",
			path, s.Policies, s.Rules, s.Conditions, s.Tenants)
		if s.Conditions > 0 {
			fmt.Printf("  indexable:        %d of %d conditions on the AND-spine (%.1f%%)\n",
				s.IndexableConds, s.Conditions,
				100*float64(s.IndexableConds)/float64(s.Conditions))
		}
		if s.Rules > 0 {
			fmt.Printf("  rules with OR/NOT: %d (%.1f%%) — validated in full when their shard is reached\n",
				s.RulesWithOrNot, 100*float64(s.RulesWithOrNot)/float64(s.Rules))
		}
		fmt.Printf("  attributes used:  %d\n", len(s.Attributes))
	}

	// Static analysis: defects no amount of testing would find, because they are
	// claims about every possible request rather than about one.
	if b, rerr := bundle.ReadFile(path); rerr == nil {
		if policies, _, cerr := b.Compile(tessaraop.LintOptions{}); cerr == nil {
			printAnalysis(policies)
		}
	}

	fmt.Printf("\n%d error(s), %d warning(s)\n", len(errs), len(diags)-len(errs))
	if len(errs) > 0 {
		return 1
	}
	return 0
}

// printAnalysis reports unreachable, shadowed, duplicate and conflicting rules.
func printAnalysis(policies []model.Policy) {
	report := tessaraop.Analyze(policies, tessaraop.DefaultAnalysisOptions())
	if len(report.Findings) == 0 {
		fmt.Printf("\nAnalysis: no unreachable, shadowed, duplicate or conflicting rules "+
			"across %d shards\n", report.Shards)
		return
	}

	fmt.Printf("\nAnalysis (%d rules across %d shards, %d atoms, %d BDD nodes)\n",
		report.RulesAnalysed, report.Shards, report.AtomsDerived, report.BDDNodes)
	for _, f := range report.Findings {
		fmt.Printf("  %s\n", f)
	}
}

// printRegistry lists every attribute an ingestion adapter is expected to
// populate, grouped by layer. This is the onboarding checklist: an integrator
// reads it to know what their adapter must supply and which operators each
// attribute accepts.
func printRegistry() {
	fmt.Printf("TessaraOP attribute registry — %d named attributes\n", len(attr.Catalog))
	fmt.Printf("The engine evaluates these names; package ingest populates them from\n")
	fmt.Printf("net.Conn / *http.Request / *tls.ConnectionState using stdlib parsers.\n")

	layers := []attr.Layer{
		attr.LayerNetwork, attr.LayerTransport, attr.LayerConn, attr.LayerInfra,
		attr.LayerHTTP, attr.LayerPayload, attr.LayerTLS, attr.LayerIdentity,
		attr.LayerResource,
	}
	for _, l := range layers {
		in := attr.ByLayer(l)
		if len(in) == 0 {
			continue
		}
		fmt.Printf("\n%s  (%d)\n", strings.ToUpper(l.String()), len(in))
		fmt.Println(strings.Repeat("-", 100))
		for _, a := range in {
			name := a.Name
			if a.Dynamic {
				name += "*"
			}
			fmt.Printf("  %-38s %-8s %s\n", name, a.Kind, a.Doc)
		}
	}

	fmt.Printf("\nOPERATORS  (%d)\n", len(model.AllOperators))
	fmt.Println(strings.Repeat("-", 100))
	var str, num, net, pres []string
	for _, op := range model.AllOperators {
		switch op.Family() {
		case model.FamilyString:
			str = append(str, string(op))
		case model.FamilyNumeric:
			num = append(num, string(op))
		case model.FamilyNetwork:
			net = append(net, string(op))
		case model.FamilyPresence:
			pres = append(pres, string(op))
		}
	}
	fmt.Printf("  string   %s\n", strings.Join(str, " "))
	fmt.Printf("  numeric  %s\n", strings.Join(num, " "))
	fmt.Printf("  network  %s\n", strings.Join(net, " "))
	fmt.Printf("  presence %s\n", strings.Join(pres, " "))
	fmt.Printf("\n  Conditions combine with AND / OR / NOT into a tree per rule.\n")
	fmt.Printf("  A * suffix marks an open-ended namespace: any key under it is valid.\n")
}

func printCorpusSummary(c *genutil.Corpus, eng *engine.Engine, build time.Duration) {
	counts := map[string]int{}
	ruleTotal, condTotal := 0, 0
	spineTotal := 0
	offSpine := 0
	opCounts := map[model.Operator]int{}

	var spine []model.Condition
	for i := range c.Policies {
		p := &c.Policies[i]
		counts[p.TenantID]++
		ruleTotal += len(p.Rules)
		for ri := range p.Rules {
			when := p.Rules[ri].When
			condTotal += when.CountLeaves()
			spine = when.ANDSpineLeaves(spine[:0])
			spineTotal += len(spine)
			if len(spine) < when.CountLeaves() {
				offSpine++
			}
			_ = when.Walk(func(e *model.ConditionExpr) error {
				if e.Kind == model.ExprLeaf {
					opCounts[e.Cond.Operator]++
				}
				return nil
			})
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
	fmt.Printf("  Rules:            %s (avg %.1f per policy) — this is the indexed universe\n",
		comma(ruleTotal), float64(ruleTotal)/float64(len(c.Policies)))
	fmt.Printf("  Tenants:          %s\n", comma(eng.TenantCount()))
	fmt.Printf("  Conditions:       %s (avg %.1f per rule)\n",
		comma(condTotal), float64(condTotal)/float64(ruleTotal))
	fmt.Printf("  Indexable:        %s of %s conditions on the AND-spine (%.1f%%)\n",
		comma(spineTotal), comma(condTotal), 100*float64(spineTotal)/float64(condTotal))
	fmt.Printf("  Rules with OR/NOT:%s (%.1f%%) — partly unindexable by construction\n",
		comma(offSpine), 100*float64(offSpine)/float64(ruleTotal))
	fmt.Printf("  Index build:      %v\n", build.Round(time.Millisecond))

	if len(sizes) > 0 {
		fmt.Printf("  Shards:           %s\n", comma(eng.ShardCount()))
		fmt.Printf("  Tenant sizes:     largest %s, median %s, smallest %s policies\n",
			comma(sizes[0]), comma(sizes[len(sizes)/2]), comma(sizes[len(sizes)-1]))
		worst := 0
		for _, sc := range c.Scopes {
			if n := eng.InScope(c.Tenants[0], sc); n > worst {
				worst = n
			}
		}
		fmt.Printf("  In scope / req:   %s rules worst case, on the largest tenant (%.4f%% of corpus)\n",
			comma(worst), 100*float64(worst)/float64(eng.TotalRules()))
	}

	fmt.Printf("\nOperator mix\n")
	ops := make([]model.Operator, 0, len(opCounts))
	for op := range opCounts {
		ops = append(ops, op)
	}
	sort.Slice(ops, func(i, j int) bool { return opCounts[ops[i]] > opCounts[ops[j]] })
	for _, op := range ops {
		fmt.Printf("  %-11s %s\n", op, comma(opCounts[op]))
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
	fmt.Printf("%-4s %-8s %-30s %10s %10s %9s %9s %s\n",
		"#", "Result", "Matched rule", "Engine", "Naive", "Speedup", "Validated", "Agree")
	fmt.Println(strings.Repeat("-", 110))

	var totalEngine, totalNaive time.Duration
	mismatches := 0

	for i := 0; i < n; i++ {
		req := c.GenerateRequest(rng)

		var got model.Decision
		engDur := timePerCall(func() { got = eng.Evaluate(req) })
		totalEngine += engDur

		result := "DENY"
		if got.Allowed {
			result = "ALLOW"
		}
		matched := got.MatchedRuleID
		if matched == "" {
			matched = "(default-deny)"
		}

		naiveCol, speedup, agree := "-", "-", "-"
		if ref != nil {
			var want model.Decision
			naiveDur := timePerCall(func() { want = ref.Evaluate(req) })
			totalNaive += naiveDur

			naiveCol = fmtDur(naiveDur)
			speedup = ratio(naiveDur, engDur)
			agree = "ok"
			if !sameDecision(want, got) {
				agree = "MISMATCH"
				mismatches++
			}
		}

		fmt.Printf("%-4d %-8s %-30s %10s %10s %9s %9d %s\n",
			i+1, result, truncate(matched, 30), fmtDur(engDur),
			naiveCol, speedup, got.RulesScanned, agree)
	}

	avgEngine := totalEngine / time.Duration(n)
	fmt.Printf("\nSummary\n")
	fmt.Printf("  Engine avg:    %s per request\n", fmtDur(avgEngine))
	if ref != nil {
		fmt.Printf("  Naive avg:     %s per request\n", fmtDur(totalNaive/time.Duration(n)))
		fmt.Printf("  Speedup:       %s\n", ratio(totalNaive, totalEngine))
		fmt.Printf("  Mismatches:    %d / %d\n", mismatches, n)
		if mismatches == 0 {
			fmt.Printf("  Correctness:   verified against the naive oracle\n")
		}
	}
	if avgEngine > 0 {
		fmt.Printf("  Throughput:    %s requests/sec single-threaded\n",
			comma(int(float64(time.Second)/float64(avgEngine))))
	}
	fmt.Printf("\n  Note: naive short-circuits on the first matching deny, and platform\n")
	fmt.Printf("  denies sit at the front of the corpus — so rows that hit a global deny\n")
	fmt.Printf("  flatter it. The default-deny rows, where it must scan everything, are\n")
	fmt.Printf("  the honest comparison. Run the Go benchmarks for rigorous numbers.\n")
}

// timePerCall measures one call by repeating it until the elapsed time is large
// enough to be meaningful, then dividing.
//
// A single call cannot be timed directly here: Go's monotonic clock on Windows
// has a granularity of roughly a millisecond, so a five-microsecond evaluation
// measures as exactly zero — which then produced a NaN speedup and a negative
// throughput from dividing by it. Repeating until the total clears the clock's
// resolution is the standard fix, and it is what testing.B does internally.
func timePerCall(fn func()) time.Duration {
	const minElapsed = 20 * time.Millisecond

	fn() // once for warm-up, and so callers always get a result
	for reps := 1; ; reps *= 4 {
		start := time.Now()
		for i := 0; i < reps; i++ {
			fn()
		}
		elapsed := time.Since(start)
		if elapsed >= minElapsed {
			return elapsed / time.Duration(reps)
		}
		if reps > 1<<24 {
			// Pathologically fast or a broken clock; report what we measured
			// rather than looping forever.
			return elapsed / time.Duration(reps)
		}
	}
}

// fmtDur renders a sub-microsecond duration usefully. Rounding to the nearest
// microsecond, as this used to, turns every cache hit into "1µs" or "0s".
func fmtDur(d time.Duration) string {
	switch {
	case d == 0:
		return "~0"
	case d < time.Microsecond:
		return fmt.Sprintf("%dns", d.Nanoseconds())
	case d < time.Millisecond:
		return fmt.Sprintf("%.1fµs", float64(d.Nanoseconds())/1e3)
	default:
		return fmt.Sprintf("%.2fms", float64(d.Nanoseconds())/1e6)
	}
}

func ratio(a, b time.Duration) string {
	if b <= 0 {
		return "-"
	}
	return fmt.Sprintf("%.1fx", float64(a)/float64(b))
}

// sameDecision compares only what the combining algorithms actually pin down:
// whether access is granted, and under which effect.
//
// It deliberately does not compare MatchedRuleID or Obligations. Under
// deny-overrides and permit-overrides several rules can match with the same
// effect, and the algorithms say nothing about which to credit — so two correct
// evaluators may name different rules, and since obligations travel with the
// rule that fired, they may report different obligations too. That is a real
// consequence of the model, not a defect in either evaluator, and it is why an
// integration that needs stable attribution or a guaranteed obligation set
// should use first-applicable. See DOCUMENTATION.md on obligation attribution.
func sameDecision(a, b model.Decision) bool {
	return a.Allowed == b.Allowed && a.Effect == b.Effect
}

func runInteractive(eng *engine.Engine, c *genutil.Corpus) {
	fmt.Printf("\nInteractive mode. Enter key=value pairs; 'quit' to exit.\n")
	fmt.Printf("Values are typed from the attribute registry — run -attrs for the full list.\n\n")
	fmt.Printf("Example:\n  tenant=%s scope=%s subject.role=admin action=read "+
		"resource.domain=api.%s.example.com resource.path=/api/v2/x "+
		"subject.risk_score=10 network.source_ip=10.0.0.5 transport.dest_port=443\n\n",
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

		req, unknown := parseRequest(line)
		if len(unknown) > 0 {
			fmt.Printf("  note: not in the registry, treated as strings: %s\n",
				strings.Join(unknown, ", "))
		}

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
		fmt.Printf("\n  Tenant:      %s / scope %q (%s rules in scope)\n",
			req.TenantID, req.Scope, comma(eng.InScope(req.TenantID, req.Scope)))
		fmt.Printf("  Result:      %s\n", result)
		if got.MatchedRuleID != "" {
			fmt.Printf("  Matched:     %s in %s (%s)\n",
				got.MatchedRuleID, got.MatchedPolicyID, got.Effect)
		} else {
			fmt.Printf("  Matched:     none — default deny\n")
		}
		if len(got.Obligations) > 0 {
			fmt.Printf("  Obligations: %s\n", strings.Join(got.Obligations, ", "))
		}
		// The explanation, which is why interactive mode is useful at all: a bare
		// DENY tells an author nothing about which condition defeated them.
		printExplanation(c.Policies, req, model.DenyOverrides)

		fmt.Printf("  Engine:      %v, validated %d rules across %d policies\n",
			engDur.Round(time.Nanosecond), got.RulesScanned, got.PoliciesScanned)
		fmt.Printf("  Naive:       %v, scanned %d rules (%.0fx slower)\n",
			naiveDur.Round(time.Microsecond), want.RulesScanned,
			float64(naiveDur)/float64(engDur))
		if !sameDecision(want, got) {
			fmt.Printf("  WARNING:     engine and naive disagree\n")
		}
		fmt.Println()
	}
}

// parseRequest types each value from the attribute registry rather than
// guessing from the key's spelling. The previous heuristic — "numeric if the
// name contains score or hour" — silently put transport.dest_port in the string
// map, where no numeric operator could ever see it.
func parseRequest(line string) (model.Request, []string) {
	req := model.Request{
		Attributes: map[string]string{},
		Numeric:    map[string]float64{},
		IPs:        map[string]netip.Addr{},
	}
	var unknown []string

	for _, part := range strings.Fields(line) {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		switch k {
		case "tenant":
			req.TenantID = v
			continue
		case "scope":
			req.Scope = v
			continue
		}

		a, known := attr.Lookup(k)
		if !known {
			unknown = append(unknown, k)
			req.Attributes[k] = v
			continue
		}
		switch a.Kind {
		case attr.KindNumeric:
			f, err := strconv.ParseFloat(v, 64)
			if err != nil {
				fmt.Printf("  skipped %s: %q is not a number\n", k, v)
				continue
			}
			req.Numeric[k] = f
		case attr.KindIP:
			addr, err := netip.ParseAddr(v)
			if err != nil {
				fmt.Printf("  skipped %s: %q is not an IP address\n", k, v)
				continue
			}
			req.IPs[k] = addr
		default:
			req.Attributes[k] = v
		}
	}
	return req, unknown
}

func runDemo() {
	fmt.Println("=== TessaraOP: a realistic policy set ===")

	policies := demoPolicies()

	for i := range policies {
		p := &policies[i]
		fmt.Printf("\nPOLICY %s  (tenant=%s, scope=%q, priority=%d, rules combine by %s)\n",
			p.ID, p.TenantID, p.Scope, p.Priority, ruleAlg(p))
		for ri := range p.Rules {
			r := &p.Rules[ri]
			fmt.Printf("  [%s] %s (priority %d)\n", r.Effect, r.ID, r.Priority)
			printExpr(r.When, "      ")
			if len(r.Obligations) > 0 {
				fmt.Printf("      -> obligations: %s\n", strings.Join(r.Obligations, ", "))
			}
		}
	}

	eng := engine.New(policies, engine.Config{})
	ref := naive.New(policies)

	fmt.Printf("\n\n%-46s %-8s %-30s %s\n", "Scenario", "Result", "Matched rule", "Obligations")
	fmt.Println(strings.Repeat("-", 116))
	for _, tc := range demoCases() {
		got := eng.Evaluate(tc.req)
		want := ref.Evaluate(tc.req)

		result := "DENY"
		if got.Allowed {
			result = "ALLOW"
		}
		matched := got.MatchedRuleID
		if matched == "" {
			matched = "(default-deny)"
		}
		mark := ""
		if !sameDecision(want, got) {
			mark = "  <-- DISAGREES WITH NAIVE"
		}
		fmt.Printf("%-46s %-8s %-30s %s%s\n",
			truncate(tc.name, 46), result, truncate(matched, 30),
			strings.Join(got.Obligations, ","), mark)
	}

	fmt.Printf("\nWhat to notice:\n")
	fmt.Printf("  - A global deny outranks a tenant's own grant: deny-overrides working.\n")
	fmt.Printf("  - evilacme.com does not inherit acme.com's grant — dnssuffix is\n")
	fmt.Printf("    label-aligned, where a plain suffix test would be a live bypass.\n")
	fmt.Printf("  - The break-glass policy resolves its own rules by priority, so its\n")
	fmt.Printf("    narrow exception beats its own broad deny without touching any\n")
	fmt.Printf("    other policy. That is the two-tier combination.\n")
	fmt.Printf("  - The OR in acme-admin-console is invisible to the index: that rule\n")
	fmt.Printf("    is filtered on its AND-spine only, then validated in full.\n")
	fmt.Printf("  - The break-glass row is ALLOW, but two different allow rules match it\n")
	fmt.Printf("    and deny-overrides does not say which to credit. The obligations you\n")
	fmt.Printf("    see depend on which one the evaluator reached first. Use\n")
	fmt.Printf("    -alg first-applicable when attribution has to be deterministic.\n")
}

func ruleAlg(p *model.Policy) model.Algorithm {
	if p.RuleAlgorithm == "" {
		return model.DenyOverrides
	}
	return p.RuleAlgorithm
}

func demoPolicies() []model.Policy {
	return []model.Policy{
		{
			// Every rule here is a DENY under deny-overrides, so rule priorities
			// would be ignored. They are left at zero rather than set to
			// plausible-looking values, because a priority that does nothing reads
			// as if it orders the rules — the linter flags exactly that.
			ID: "global-baseline", TenantID: model.GlobalTenant, Priority: 1000,
			Rules: []model.Rule{
				{
					ID: "block-listed-source", Effect: model.Deny,
					When: model.Cond(model.Condition{
						Attribute: attr.SourceIP, Operator: model.OpCIDR,
						Prefixes: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}}),
					Obligations: []string{"notify_soc"},
				},
				{
					ID: "block-high-risk", Effect: model.Deny,
					When: model.Cond(model.Condition{
						Attribute: attr.RiskScore, Operator: model.OpGreaterThan, Min: 90}),
					Obligations: []string{"step_up_auth"},
				},
				{
					ID: "block-weak-tls", Effect: model.Deny,
					When: model.Cond(model.Condition{
						Attribute: attr.TLSVersionNo, Operator: model.OpLessThan, Max: 12}),
				},
				{
					// Scanner and injection signatures. Neither is indexable, so
					// both are resolved by validation on every request reaching
					// the global shard — which is small, by design.
					ID: "block-scanners", Effect: model.Deny,
					When: model.Or(
						model.Cond(model.Condition{
							Attribute: attr.UserAgent, Operator: model.OpContains,
							Values: []string{"sqlmap", "nikto", "nmap"}}),
						model.Cond(model.Condition{
							Attribute: attr.HTTPQuery, Operator: model.OpRegex,
							Values: []string{`(?i)union\s+all?\s*select`}}),
					),
					Obligations: []string{"notify_soc", "audit_log"},
				},
			},
		},
		{
			ID: "acme-admin-console", TenantID: "acme", Scope: "identity", Priority: 100,
			Rules: []model.Rule{{
				ID: "grant-admin-console", Effect: model.Allow, Priority: 100,
				When: model.And(
					// A disjunction: either role qualifies. Off the AND-spine,
					// so the index cannot use it.
					model.Or(
						model.Cond(model.Condition{
							Attribute: attr.SubjectRole, Operator: model.OpEquals,
							Values: []string{"admin"}}),
						model.Cond(model.Condition{
							Attribute: attr.SubjectRole, Operator: model.OpEquals,
							Values: []string{"security-admin"}}),
					),
					// A negation: contractors are excluded however they are
					// labelled. Also off the spine.
					// has_any, not contains: subject.groups is a comma-delimited
					// set, and a substring test would also exclude a principal
					// in "subcontractor" or "contractor-liaison".
					model.Not(model.Cond(model.Condition{
						Attribute: "subject.groups", Operator: model.OpHasAny,
						Values: []string{"contractor"}})),
					// The rest is the AND-spine, and every one of these is indexed.
					model.Cond(model.Condition{
						Attribute: attr.RiskScore, Operator: model.OpRange, Min: 0, Max: 30}),
					model.Cond(model.Condition{
						Attribute: attr.MFAVerified, Operator: model.OpEquals,
						Values: []string{"true"}}),
					model.Cond(model.Condition{
						Attribute: attr.SourceIP, Operator: model.OpCIDR,
						Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}),
					model.Cond(model.Condition{
						Attribute: "resource.domain", Operator: model.OpDNSSuffix,
						Values: []string{"admin.acme.com"}}),
					model.Cond(model.Condition{
						Attribute: attr.ResourcePath, Operator: model.OpPrefix,
						Values: []string{"/api/v2/admin"}}),
					model.Cond(model.Condition{
						Attribute: attr.TimeHour, Operator: model.OpRange, Min: 9, Max: 17}),
				),
				Obligations: []string{"require_mfa", "audit_log"},
			}},
		},
		{
			ID: "acme-readonly", TenantID: "acme", Priority: 10,
			Rules: []model.Rule{{
				ID: "grant-read", Effect: model.Allow, Priority: 10,
				When: model.AllOf(
					model.Condition{Attribute: attr.SubjectRole, Operator: model.OpNotIn,
						Values: []string{"service-account"}},
					model.Condition{Attribute: attr.Action, Operator: model.OpEquals,
						Values: []string{"read"}},
					model.Condition{Attribute: "resource.domain", Operator: model.OpDNSSuffix,
						Values: []string{"acme.com"}},
				),
			}},
		},
		{
			// One policy, two rules, resolved by priority rather than by
			// deny-overrides. This is the shape flat policies could not express:
			// a broad deny and its own narrow exception, scoped together so the
			// exception cannot leak to any other policy.
			ID: "acme-break-glass", TenantID: "acme", Priority: 500,
			RuleAlgorithm: model.FirstApplicable,
			Rules: []model.Rule{
				{
					ID: "deny-critical-delete", Effect: model.Deny, Priority: 10,
					When: model.AllOf(
						model.Condition{Attribute: attr.Action, Operator: model.OpEquals,
							Values: []string{"delete"}},
						model.Condition{Attribute: attr.Sensitivity, Operator: model.OpIn,
							Values: []string{"critical"}},
					),
				},
				{
					ID: "except-approved-break-glass", Effect: model.Allow, Priority: 100,
					When: model.AllOf(
						model.Condition{Attribute: attr.Action, Operator: model.OpEquals,
							Values: []string{"delete"}},
						model.Condition{Attribute: attr.Sensitivity, Operator: model.OpIn,
							Values: []string{"critical"}},
						model.Condition{Attribute: "subject.claim.break_glass_ticket",
							Operator: model.OpExists},
						model.Condition{Attribute: attr.SubjectRole, Operator: model.OpEquals,
							Values: []string{"security-admin"}},
					),
					Obligations: []string{"audit_log", "notify_soc"},
				},
			},
		},
		{
			// Layer 3/4/7 perimeter policy: the shape a firewall or WAF rule set
			// takes, expressed in the same engine as the identity policies above.
			ID: "acme-perimeter", TenantID: "acme", Scope: "network", Priority: 800,
			Rules: []model.Rule{
				{
					ID: "deny-admin-ports-off-corp", Effect: model.Deny, Priority: 800,
					When: model.And(
						model.Cond(model.Condition{
							Attribute: attr.DestPort, Operator: model.OpNumIn,
							Numbers: []float64{22, 3389, 5985}}),
						model.Not(model.Cond(model.Condition{
							Attribute: attr.SourceIP, Operator: model.OpCIDR,
							Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}})),
					),
					Obligations: []string{"notify_soc"},
				},
				{
					ID: "deny-invalid-flags", Effect: model.Deny, Priority: 800,
					When: model.Cond(model.Condition{
						Attribute: attr.TCPFlags, Operator: model.OpIn,
						Values: []string{"fin,syn", "", "fin,psh,urg"}}),
				},
				{
					ID: "deny-executable-upload", Effect: model.Deny, Priority: 800,
					When: model.AllOf(
						model.Condition{Attribute: attr.HTTPMethod, Operator: model.OpIn,
							Values: []string{"POST", "PUT"}},
						model.Condition{Attribute: attr.FileExt, Operator: model.OpSuffix,
							Values: []string{".exe", ".bat", ".php", ".sh", ".jsp"}},
					),
					Obligations: []string{"audit_log"},
				},
			},
		},
	}
}

type demoCase struct {
	name string
	req  model.Request
}

// baseReq is the common shape of a demo request, so each case can state only
// what it changes.
//
// mods takes a pointer, not a value. Mutating the maps through a copy would
// work, but assigning TenantID or Scope would not — and two of the cases below
// do exactly that, so a value receiver here would silently drop them.
func baseReq(mods func(*model.Request)) model.Request {
	r := model.Request{
		TenantID: "acme",
		Scope:    "identity",
		Attributes: map[string]string{
			attr.SubjectRole:  "admin",
			attr.MFAVerified:  "true",
			attr.Action:       "write",
			"resource.domain": "api.admin.acme.com",
			attr.ResourcePath: "/api/v2/admin/users",
			attr.HTTPMethod:   "POST",
			attr.UserAgent:    "Mozilla/5.0 Chrome/120.0",
			attr.HTTPQuery:    "page=1",
			attr.FileExt:      ".pdf",
			"subject.groups":  "platform,oncall",
		},
		Numeric: map[string]float64{
			attr.RiskScore:    12,
			attr.TimeHour:     14,
			attr.TLSVersionNo: 13,
			attr.DestPort:     443,
		},
		IPs: map[string]netip.Addr{
			attr.SourceIP: netip.MustParseAddr("10.1.2.3"),
		},
	}
	mods(&r)
	return r
}

func demoCases() []demoCase {
	return []demoCase{
		{"Admin, MFA, corp network, business hours", baseReq(func(*model.Request) {})},
		{"Security-admin instead of admin (the OR branch)", baseReq(func(r *model.Request) {
			r.Attributes[attr.SubjectRole] = "security-admin"
		})},
		{"Same admin, but tagged as a contractor (the NOT)", baseReq(func(r *model.Request) {
			r.Attributes["subject.groups"] = "platform,contractor"
		})},
		{"Same admin, from a blocklisted IP", baseReq(func(r *model.Request) {
			r.IPs[attr.SourceIP] = netip.MustParseAddr("203.0.113.9")
		})},
		{"Same admin, risk score 95", baseReq(func(r *model.Request) {
			r.Numeric[attr.RiskScore] = 95
		})},
		{"Same admin, negotiated TLS 1.0", baseReq(func(r *model.Request) {
			r.Numeric[attr.TLSVersionNo] = 10
		})},
		{"Admin without MFA", baseReq(func(r *model.Request) {
			r.Attributes[attr.MFAVerified] = "false"
		})},
		{"sqlmap user agent", baseReq(func(r *model.Request) {
			r.Attributes[attr.UserAgent] = "sqlmap/1.7"
		})},
		{"SQL injection in the query string", baseReq(func(r *model.Request) {
			r.Attributes[attr.HTTPQuery] = "id=1 UNION ALL SELECT password FROM users"
		})},
		{"Viewer reading a public acme resource", baseReq(func(r *model.Request) {
			r.Scope = ""
			r.Attributes[attr.SubjectRole] = "viewer"
			r.Attributes[attr.Action] = "read"
			r.Attributes["resource.domain"] = "www.acme.com"
			r.Attributes[attr.ResourcePath] = "/public/docs"
		})},
		{"Lookalike domain evilacme.com (bypass attempt)", baseReq(func(r *model.Request) {
			r.Scope = ""
			r.Attributes[attr.SubjectRole] = "viewer"
			r.Attributes[attr.Action] = "read"
			r.Attributes["resource.domain"] = "evilacme.com"
			r.Attributes[attr.ResourcePath] = "/public/docs"
		})},
		{"Deleting a critical resource", baseReq(func(r *model.Request) {
			r.Attributes[attr.Action] = "delete"
			r.Attributes["resource.sensitivity"] = "critical"
		})},
		{"Same delete, with an approved break-glass ticket", baseReq(func(r *model.Request) {
			r.Attributes[attr.SubjectRole] = "security-admin"
			r.Attributes[attr.Action] = "delete"
			r.Attributes["resource.sensitivity"] = "critical"
			r.Attributes["subject.claim.break_glass_ticket"] = "INC-4417"
		})},
		{"SSH to an internal host from the public internet", baseReq(func(r *model.Request) {
			r.Scope = "network"
			r.Numeric[attr.DestPort] = 22
			r.IPs[attr.SourceIP] = netip.MustParseAddr("198.51.100.7")
		})},
		{"Same SSH, but from the corporate range", baseReq(func(r *model.Request) {
			r.Scope = "network"
			r.Numeric[attr.DestPort] = 22
		})},
		{"Uploading shell.php", baseReq(func(r *model.Request) {
			r.Scope = "network"
			r.Attributes[attr.FileExt] = ".php"
		})},
		{"Different tenant, same admin role", baseReq(func(r *model.Request) {
			r.TenantID = "other-corp"
		})},
	}
}

// printExpr renders a condition tree as an indented outline. A flat list cannot
// show which conditions sit under an Or or a Not, which is precisely the
// information needed to reason about what the index can and cannot prune.
func printExpr(e *model.ConditionExpr, indent string) {
	if e == nil {
		fmt.Printf("%s(always)\n", indent)
		return
	}
	switch e.Kind {
	case model.ExprLeaf:
		fmt.Printf("%s%s\n", indent, describe(e.Cond))
	case model.ExprAnd:
		if len(e.Sub) == 0 {
			fmt.Printf("%s(always)\n", indent)
			return
		}
		for _, c := range e.Sub {
			printExpr(c, indent)
		}
	case model.ExprOr:
		fmt.Printf("%sANY OF:\n", indent)
		for _, c := range e.Sub {
			printExpr(c, indent+"  ")
		}
	case model.ExprNot:
		fmt.Printf("%sNOT:\n", indent)
		for _, c := range e.Sub {
			printExpr(c, indent+"  ")
		}
	}
}

func describe(c model.Condition) string {
	switch c.Operator {
	case model.OpRange:
		return fmt.Sprintf("%s in [%g, %g]", c.Attribute, c.Min, c.Max)
	case model.OpNotRange:
		return fmt.Sprintf("%s outside [%g, %g]", c.Attribute, c.Min, c.Max)
	case model.OpGreaterThan:
		return fmt.Sprintf("%s > %g", c.Attribute, c.Min)
	case model.OpGreaterEq:
		return fmt.Sprintf("%s >= %g", c.Attribute, c.Min)
	case model.OpLessThan:
		return fmt.Sprintf("%s < %g", c.Attribute, c.Max)
	case model.OpLessEq:
		return fmt.Sprintf("%s <= %g", c.Attribute, c.Max)
	case model.OpNumEquals:
		return fmt.Sprintf("%s == %g", c.Attribute, c.Min)
	case model.OpNumNotEq:
		return fmt.Sprintf("%s != %g", c.Attribute, c.Min)
	case model.OpNumIn, model.OpNumNotIn:
		op := "in"
		if c.Operator == model.OpNumNotIn {
			op = "not in"
		}
		parts := make([]string, len(c.Numbers))
		for i, v := range c.Numbers {
			parts[i] = fmt.Sprintf("%g", v)
		}
		return fmt.Sprintf("%s %s {%s}", c.Attribute, op, strings.Join(parts, ", "))
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
