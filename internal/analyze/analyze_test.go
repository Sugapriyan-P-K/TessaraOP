package analyze

import (
	"math/rand"
	"net/netip"
	"strings"
	"testing"

	"github.com/suga/tessaraop/internal/genutil"
	"github.com/suga/tessaraop/internal/model"
)

func eq(attr, value string) model.Condition {
	return model.Condition{Attribute: attr, Operator: model.OpEquals, Values: []string{value}}
}

func in(attr string, values ...string) model.Condition {
	return model.Condition{Attribute: attr, Operator: model.OpIn, Values: values}
}

func numRange(attr string, min, max float64) model.Condition {
	return model.Condition{Attribute: attr, Operator: model.OpRange, Min: min, Max: max}
}

func policy(id string, rules ...model.Rule) model.Policy {
	return model.Policy{ID: id, TenantID: "t", Rules: rules}
}

func rule(id string, effect model.Effect, when *model.ConditionExpr) model.Rule {
	return model.Rule{ID: id, Effect: effect, When: when}
}

// find returns the first finding of a kind for a rule, or nil.
func find(r *Report, kind Kind, ruleID string) *Finding {
	for i := range r.Findings {
		if r.Findings[i].Kind == kind && r.Findings[i].RuleID == ruleID {
			return &r.Findings[i]
		}
	}
	return nil
}

func dump(r *Report) string {
	var sb strings.Builder
	for _, f := range r.Findings {
		sb.WriteString("\n  " + f.String())
	}
	if sb.Len() == 0 {
		return " (no findings)"
	}
	return sb.String()
}

// --- Unreachable -------------------------------------------------------------

// TestUnreachable_ContradictoryEquality is the case that motivates the whole
// theory layer. Treating each predicate as an independent boolean would call this
// satisfiable, and the analyser would be useless.
func TestUnreachable_ContradictoryEquality(t *testing.T) {
	p := policy("p", rule("impossible", model.Allow, model.AllOf(
		eq("subject.role", "admin"),
		eq("subject.role", "viewer"),
	)))

	r := Analyze([]model.Policy{p}, DefaultOptions())
	if find(r, Unreachable, "impossible") == nil {
		t.Fatalf("a rule requiring two different values of one attribute can never fire:%s", dump(r))
	}
}

func TestUnreachable_DisjointRanges(t *testing.T) {
	p := policy("p", rule("impossible", model.Allow, model.AllOf(
		numRange("subject.risk_score", 0, 10),
		numRange("subject.risk_score", 50, 100),
	)))
	r := Analyze([]model.Policy{p}, DefaultOptions())
	if find(r, Unreachable, "impossible") == nil {
		t.Fatalf("disjoint ranges cannot both hold:%s", dump(r))
	}
}

func TestUnreachable_ExistsAndNotExists(t *testing.T) {
	p := policy("p", rule("impossible", model.Allow, model.AllOf(
		model.Condition{Attribute: "token.valid", Operator: model.OpExists},
		model.Condition{Attribute: "token.valid", Operator: model.OpNotExists},
	)))
	r := Analyze([]model.Policy{p}, DefaultOptions())
	if find(r, Unreachable, "impossible") == nil {
		t.Fatalf("presence and absence are exclusive:%s", dump(r))
	}
}

// TestUnreachable_ValueOutsideSet covers the finite-domain technique: eq "auditor"
// is tested directly against `in [admin, viewer]` using the engine's own matcher.
func TestUnreachable_ValueOutsideSet(t *testing.T) {
	p := policy("p", rule("impossible", model.Allow, model.AllOf(
		eq("subject.role", "auditor"),
		in("subject.role", "admin", "viewer"),
	)))
	r := Analyze([]model.Policy{p}, DefaultOptions())
	if find(r, Unreachable, "impossible") == nil {
		t.Fatalf("a value outside the permitted set cannot satisfy both:%s", dump(r))
	}
}

// TestUnreachable_EqualityVersusRegex shows the reach of evaluating a finite
// domain against the other predicate: no structural rule could decide this, but
// running the regex against the one possible value does.
func TestUnreachable_EqualityVersusRegex(t *testing.T) {
	p := policy("p", rule("impossible", model.Allow, model.AllOf(
		eq("http.path", "/public/docs"),
		model.Condition{Attribute: "http.path", Operator: model.OpRegex,
			Values: []string{`^/admin/`}},
	)))
	r := Analyze([]model.Policy{p}, DefaultOptions())
	if find(r, Unreachable, "impossible") == nil {
		t.Fatalf("the only possible value does not match the pattern:%s", dump(r))
	}
}

func TestUnreachable_DisjointCIDR(t *testing.T) {
	p := policy("p", rule("impossible", model.Allow, model.AllOf(
		model.Condition{Attribute: "network.source_ip", Operator: model.OpCIDR,
			Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}},
		model.Condition{Attribute: "network.source_ip", Operator: model.OpCIDR,
			Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}},
	)))
	r := Analyze([]model.Policy{p}, DefaultOptions())
	if find(r, Unreachable, "impossible") == nil {
		t.Fatalf("disjoint prefixes cannot both contain one address:%s", dump(r))
	}
}

// TestUnreachable_NegatedSelf: A ∧ ¬A is false whatever A is, and this needs no
// theory at all — the BDD alone decides it.
func TestUnreachable_NegatedSelf(t *testing.T) {
	c := eq("subject.role", "admin")
	p := policy("p", rule("impossible", model.Allow, model.And(
		model.Cond(c),
		model.Not(model.Cond(c)),
	)))
	r := Analyze([]model.Policy{p}, DefaultOptions())
	if find(r, Unreachable, "impossible") == nil {
		t.Fatalf("A and not-A is unsatisfiable:%s", dump(r))
	}
}

func TestUnreachable_EmptyOr(t *testing.T) {
	// An empty disjunction matches nothing, matching the evaluator's convention.
	p := policy("p", rule("dead", model.Allow, model.Or()))
	r := Analyze([]model.Policy{p}, DefaultOptions())
	if find(r, Unreachable, "dead") == nil {
		t.Fatalf("an empty Or can never match:%s", dump(r))
	}
}

// TestReachable_NoFalsePositives is the property that makes the tool safe to act
// on. None of these rules is dead, and reporting one as unreachable would get a
// live rule deleted.
func TestReachable_NoFalsePositives(t *testing.T) {
	cases := []struct {
		name string
		when *model.ConditionExpr
	}{
		{"single equality", model.AllOf(eq("subject.role", "admin"))},
		{"compatible attributes", model.AllOf(
			eq("subject.role", "admin"), eq("action", "read"))},
		{"overlapping ranges", model.AllOf(
			numRange("s", 0, 50), numRange("s", 25, 100))},
		{"value inside set", model.AllOf(
			eq("subject.role", "admin"), in("subject.role", "admin", "viewer"))},
		{"nested prefix", model.AllOf(
			model.Condition{Attribute: "network.source_ip", Operator: model.OpCIDR,
				Prefixes: []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}},
			model.Condition{Attribute: "network.source_ip", Operator: model.OpCIDR,
				Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}})},
		{"disjunction", model.AnyOf(
			eq("subject.role", "admin"), eq("subject.role", "viewer"))},
		{"negation of a different value", model.And(
			model.Cond(eq("subject.role", "admin")),
			model.Not(model.Cond(eq("subject.role", "viewer"))))},
		{"regex and a matching literal", model.AllOf(
			eq("http.path", "/admin/x"),
			model.Condition{Attribute: "http.path", Operator: model.OpRegex,
				Values: []string{`^/admin/`}})},
		{"opaque operators", model.AllOf(
			model.Condition{Attribute: "payload.body", Operator: model.OpContains,
				Values: []string{"select"}},
			model.Condition{Attribute: "payload.body", Operator: model.OpRegex,
				Values: []string{"union"}})},
		{"multi-valued set", model.AllOf(
			model.Condition{Attribute: "subject.roles", Operator: model.OpHasAny,
				Values: []string{"admin"}},
			model.Condition{Attribute: "subject.roles", Operator: model.OpHasAny,
				Values: []string{"viewer"}})},
	}

	for _, tc := range cases {
		p := policy("p", rule("live", model.Allow, tc.when))
		r := Analyze([]model.Policy{p}, DefaultOptions())
		if f := find(r, Unreachable, "live"); f != nil {
			t.Errorf("%s: reported unreachable but is satisfiable: %s", tc.name, f)
		}
	}
}

// --- Shadowing and duplicates -----------------------------------------------

func TestShadowed_NarrowerRuleUnderBroaderOne(t *testing.T) {
	p := policy("p",
		rule("broad", model.Allow, model.AllOf(in("subject.role", "admin", "viewer"))),
		rule("narrow", model.Allow, model.AllOf(eq("subject.role", "admin"))),
	)
	r := Analyze([]model.Policy{p}, DefaultOptions())

	f := find(r, Shadowed, "narrow")
	if f == nil {
		t.Fatalf("the narrower rule adds nothing:%s", dump(r))
	}
	if f.RelatedRuleID != "broad" {
		t.Errorf("should name the covering rule, got %q", f.RelatedRuleID)
	}
	// And not the other way round.
	if find(r, Shadowed, "broad") != nil {
		t.Error("the broader rule is not shadowed by the narrower one")
	}
}

func TestShadowed_NestedRanges(t *testing.T) {
	p := policy("p",
		rule("wide", model.Allow, model.AllOf(numRange("s", 0, 100))),
		rule("tight", model.Allow, model.AllOf(numRange("s", 10, 20))),
	)
	r := Analyze([]model.Policy{p}, DefaultOptions())
	if find(r, Shadowed, "tight") == nil {
		t.Fatalf("a range inside another adds nothing:%s", dump(r))
	}
}

// TestShadowed_OnlyForTheSameEffect: a narrower DENY under a broader ALLOW is not
// shadowed — it changes the outcome, which is the entire point of an exception.
func TestShadowed_OnlyForTheSameEffect(t *testing.T) {
	p := policy("p",
		rule("broad-allow", model.Allow, model.AllOf(in("subject.role", "admin", "viewer"))),
		rule("narrow-deny", model.Deny, model.AllOf(eq("subject.role", "admin"))),
	)
	r := Analyze([]model.Policy{p}, DefaultOptions())
	if find(r, Shadowed, "narrow-deny") != nil {
		t.Fatalf("an opposite-effect exception is not redundant:%s", dump(r))
	}
}

func TestDuplicate(t *testing.T) {
	p := policy("p",
		rule("first", model.Allow, model.AllOf(eq("subject.role", "admin"))),
		rule("second", model.Allow, model.AllOf(eq("subject.role", "admin"))),
	)
	r := Analyze([]model.Policy{p}, DefaultOptions())

	if find(r, Duplicate, "second") == nil {
		t.Fatalf("identical rules should be reported once:%s", dump(r))
	}
	if find(r, Duplicate, "first") != nil {
		t.Error("a duplicate pair should be reported once, not twice")
	}
}

// TestDuplicate_IgnoresOrdering checks the canonical form: the same conjunction
// written in a different order is the same function.
func TestDuplicate_IgnoresOrdering(t *testing.T) {
	p := policy("p",
		rule("a", model.Allow, model.AllOf(eq("x", "1"), eq("y", "2"))),
		rule("b", model.Allow, model.AllOf(eq("y", "2"), eq("x", "1"))),
	)
	r := Analyze([]model.Policy{p}, DefaultOptions())
	if find(r, Duplicate, "b") == nil {
		t.Fatalf("condition order does not change the function:%s", dump(r))
	}
}

// --- Conflicts ---------------------------------------------------------------

func TestConflict_OppositeEffectsThatCanBothMatch(t *testing.T) {
	p := policy("p",
		rule("allow-admin", model.Allow, model.AllOf(eq("subject.role", "admin"))),
		rule("deny-delete", model.Deny, model.AllOf(eq("action", "delete"))),
	)
	r := Analyze([]model.Policy{p}, DefaultOptions())

	f := find(r, Conflict, "allow-admin")
	if f == nil {
		t.Fatalf("an admin deleting satisfies both:%s", dump(r))
	}
	// The example is what makes a finding actionable rather than ignorable.
	if len(f.Example) == 0 {
		t.Error("a conflict should carry a concrete example")
	}
	joined := strings.Join(f.Example, "; ")
	if !strings.Contains(joined, "subject.role") || !strings.Contains(joined, "action") {
		t.Errorf("the example should name both conditions, got %q", joined)
	}
}

// TestConflict_NotReportedWhenImpossible is where the theory earns its place. A
// naive analyser would flag these as conflicting; they are mutually exclusive.
func TestConflict_NotReportedWhenImpossible(t *testing.T) {
	p := policy("p",
		rule("allow-admin", model.Allow, model.AllOf(eq("subject.role", "admin"))),
		rule("deny-viewer", model.Deny, model.AllOf(eq("subject.role", "viewer"))),
	)
	r := Analyze([]model.Policy{p}, DefaultOptions())
	if f := find(r, Conflict, "allow-admin"); f != nil {
		t.Fatalf("no request can be both admin and viewer: %s", f)
	}
}

func TestConflict_CanBeDisabled(t *testing.T) {
	p := policy("p",
		rule("a", model.Allow, model.AllOf(eq("x", "1"))),
		rule("d", model.Deny, model.AllOf(eq("y", "2"))),
	)
	opt := DefaultOptions()
	opt.IncludeConflicts = false
	r := Analyze([]model.Policy{p}, opt)
	for _, f := range r.Findings {
		if f.Kind == Conflict {
			t.Fatalf("conflicts were disabled: %s", f)
		}
	}
}

// --- Scoping -----------------------------------------------------------------

// TestShards_AreAnalysedSeparately: rules in different shards can never be
// evaluated together, so an overlap between them is not a finding.
func TestShards_AreAnalysedSeparately(t *testing.T) {
	policies := []model.Policy{
		{ID: "billing", TenantID: "t", Scope: "billing", Rules: []model.Rule{
			rule("a", model.Allow, model.AllOf(eq("x", "1")))}},
		{ID: "storage", TenantID: "t", Scope: "storage", Rules: []model.Rule{
			rule("d", model.Deny, model.AllOf(eq("x", "1")))}},
	}
	opt := DefaultOptions()
	opt.CrossPolicy = true
	r := Analyze(policies, opt)

	for _, f := range r.Findings {
		if f.Kind == Conflict {
			t.Fatalf("different scopes never meet: %s", f)
		}
	}
	if r.Shards != 2 {
		t.Errorf("expected 2 shards, got %d", r.Shards)
	}
}

func TestCrossPolicy_IsOffByDefault(t *testing.T) {
	policies := []model.Policy{
		{ID: "one", TenantID: "t", Rules: []model.Rule{
			rule("a", model.Allow, model.AllOf(eq("x", "1")))}},
		{ID: "two", TenantID: "t", Rules: []model.Rule{
			rule("d", model.Deny, model.AllOf(eq("x", "1")))}},
	}
	if r := Analyze(policies, DefaultOptions()); len(r.Findings) != 0 {
		t.Fatalf("cross-policy comparison is off by default:%s", dump(r))
	}

	opt := DefaultOptions()
	opt.CrossPolicy = true
	r := Analyze(policies, opt)
	if find(r, Conflict, "a") == nil {
		t.Fatalf("with CrossPolicy on the overlap should be reported:%s", dump(r))
	}
}

// --- Catch-all ---------------------------------------------------------------

func TestAlwaysMatches(t *testing.T) {
	p := policy("p", rule("backstop", model.Deny, nil))
	r := Analyze([]model.Policy{p}, DefaultOptions())
	if find(r, AlwaysMatches, "backstop") == nil {
		t.Fatalf("a rule with no conditions matches everything:%s", dump(r))
	}
}

func TestAlwaysMatches_TautologicalDisjunction(t *testing.T) {
	// A ∨ ¬A is a tautology, and the BDD reduces it to the true terminal.
	c := eq("subject.role", "admin")
	p := policy("p", rule("tautology", model.Allow, model.Or(
		model.Cond(c),
		model.Not(model.Cond(c)),
	)))
	r := Analyze([]model.Policy{p}, DefaultOptions())
	if find(r, AlwaysMatches, "tautology") == nil {
		t.Fatalf("A or not-A always holds:%s", dump(r))
	}
}

// --- Budgets -----------------------------------------------------------------

// TestNodeBudget_ReportsRatherThanHangs: refusing to answer is acceptable,
// hanging in CI is not.
func TestNodeBudget_ReportsRatherThanHangs(t *testing.T) {
	// A wide disjunction of distinct atoms, then a tiny budget.
	var conds []model.Condition
	for i := 0; i < 60; i++ {
		conds = append(conds, eq("attr", string(rune('a'+i%26))+string(rune('a'+i/26))))
	}
	p := policy("p", rule("wide", model.Allow, model.AnyOf(conds...)))

	opt := DefaultOptions()
	opt.MaxNodes = 8
	r := Analyze([]model.Policy{p}, opt)

	if find(r, TooComplex, "wide") == nil {
		t.Fatalf("exceeding the budget should be reported:%s", dump(r))
	}
	// And it must not also claim the rule is unreachable, which would be a wrong
	// answer rather than no answer.
	if find(r, Unreachable, "wide") != nil {
		t.Fatal("a rule that could not be analysed must not be reported as dead")
	}
}

func TestPairwiseBudget(t *testing.T) {
	var rules []model.Rule
	for i := 0; i < 30; i++ {
		rules = append(rules, rule("r"+string(rune('a'+i)), model.Allow,
			model.AllOf(eq("attr", string(rune('a'+i))))))
	}
	opt := DefaultOptions()
	opt.MaxRulesPerShard = 10
	r := Analyze([]model.Policy{policy("p", rules...)}, opt)

	var skipped bool
	for _, f := range r.Findings {
		if f.Kind == TooComplex && strings.Contains(f.Message, "pairwise limit") {
			skipped = true
		}
	}
	if !skipped {
		t.Fatalf("exceeding the pairwise limit should be reported:%s", dump(r))
	}
}

// --- Determinism and scale ---------------------------------------------------

func TestAnalyze_IsDeterministic(t *testing.T) {
	rng := rand.New(rand.NewSource(9))
	corpus := genutil.Generate(genutil.Options{
		Policies: 60, Tenants: 3, Global: 5, RulesPerPolicy: 3}, rng)

	first := Analyze(corpus.Policies, DefaultOptions())
	for i := 0; i < 5; i++ {
		again := Analyze(corpus.Policies, DefaultOptions())
		if len(first.Findings) != len(again.Findings) {
			t.Fatalf("finding count varies between runs: %d then %d",
				len(first.Findings), len(again.Findings))
		}
		for j := range first.Findings {
			if first.Findings[j].String() != again.Findings[j].String() {
				t.Fatalf("finding %d differs between runs:\n %s\n %s",
					j, first.Findings[j], again.Findings[j])
			}
		}
	}
}

// TestAnalyze_RealCorpusTerminates runs against the generator's output, which
// mixes every operator family and boolean shape. The point is that it completes
// and produces no error-severity nonsense on a corpus known to be well-formed.
func TestAnalyze_RealCorpusTerminates(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	corpus := genutil.Generate(genutil.Options{
		Policies: 300, Tenants: 5, Global: 10, RulesPerPolicy: 4}, rng)

	r := Analyze(corpus.Policies, DefaultOptions())
	if r.RulesAnalysed == 0 {
		t.Fatal("expected rules to be analysed")
	}
	t.Logf("%d policies, %d rules, %d shards, %d atoms, %d pairs, %d BDD nodes, %d findings",
		r.PoliciesAnalysed, r.RulesAnalysed, r.Shards,
		r.AtomsDerived, r.PairsCompared, r.BDDNodes, len(r.Findings))

	// Every Unreachable finding must be real. The generator does not emit dead
	// rules deliberately, but rather than assume that, each one is verified: a
	// rule reported unreachable must genuinely fail on a large random sample.
	for _, f := range r.Errors() {
		if f.Kind != Unreachable {
			continue
		}
		if reachableBySampling(t, corpus.Policies, f, rng) {
			t.Errorf("rule %s/%s was reported unreachable but a request matched it",
				f.PolicyID, f.RuleID)
		}
	}
}

// reachableBySampling looks for a request the rule actually matches. It cannot
// prove unreachability — that is what the BDD is for — but it can refute a false
// positive, which is the direction that matters.
func reachableBySampling(t *testing.T, policies []model.Policy, f Finding, rng *rand.Rand) bool {
	t.Helper()
	var target *model.Rule
	for i := range policies {
		if policies[i].ID != f.PolicyID {
			continue
		}
		for j := range policies[i].Rules {
			if policies[i].Rules[j].ID == f.RuleID {
				target = &policies[i].Rules[j]
			}
		}
	}
	if target == nil {
		return false
	}

	corpus := genutil.Generate(genutil.Options{Policies: 1, Tenants: 1}, rng)
	for i := 0; i < 2000; i++ {
		if target.When.Matches(corpus.GenerateRequest(rng)) {
			return true
		}
	}
	return false
}

func TestReport_ErrorsAndSeverity(t *testing.T) {
	p := policy("p", rule("dead", model.Allow, model.AllOf(
		eq("x", "a"), eq("x", "b"))))
	r := Analyze([]model.Policy{p}, DefaultOptions())

	if !r.HasErrors() {
		t.Fatal("an unreachable rule is an error")
	}
	errs := r.Errors()
	if len(errs) != 1 || errs[0].Kind != Unreachable {
		t.Fatalf("unexpected errors: %+v", errs)
	}
	if errs[0].SeverityText != "error" {
		t.Errorf("SeverityText should be populated for JSON, got %q", errs[0].SeverityText)
	}
}

func TestAnalyze_EmptyInput(t *testing.T) {
	r := Analyze(nil, DefaultOptions())
	if len(r.Findings) != 0 || r.RulesAnalysed != 0 {
		t.Fatalf("empty input should produce nothing:%s", dump(r))
	}
}
