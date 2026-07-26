package bundle

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/suga/tessaraop/internal/model"
)

func read(t *testing.T, src string) *Bundle {
	t.Helper()
	b, err := Read(strings.NewReader(src))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	return b
}

// findDiag reports whether any diagnostic at the given severity mentions substr.
func findDiag(diags []Diagnostic, sev Severity, substr string) bool {
	for _, d := range diags {
		if d.Severity == sev && strings.Contains(d.Message, substr) {
			return true
		}
	}
	return false
}

func diagStrings(diags []Diagnostic) string {
	var b strings.Builder
	for _, d := range diags {
		b.WriteString("\n  " + d.String())
	}
	return b.String()
}

const goodBundle = `{
  "version": 1,
  "policies": [{
    "id": "acme-admin",
    "tenant": "acme",
    "scope": "identity",
    "priority": 100,
    "rule_algorithm": "first-applicable",
    "rules": [{
      "id": "grant",
      "effect": "ALLOW",
      "priority": 100,
      "obligations": ["require_mfa"],
      "when": {
        "all": [
          {"any": [
            {"attr": "subject.role", "op": "eq", "values": ["admin"]},
            {"attr": "subject.role", "op": "eq", "values": ["security-admin"]}
          ]},
          {"not": {"attr": "subject.groups", "op": "contains", "values": ["contractor"]}},
          {"attr": "subject.risk_score", "op": "range", "min": 0, "max": 30},
          {"attr": "network.source_ip", "op": "cidr", "prefixes": ["10.0.0.0/8"]},
          {"attr": "transport.dest_port", "op": "num_in", "numbers": [443, 8443]}
        ]
      }
    }]
  }]
}`

// --- Parsing and compiling --------------------------------------------------

func TestCompile_GoodBundle(t *testing.T) {
	b := read(t, goodBundle)
	policies, diags, err := b.Compile(LintOptions{})
	if err != nil {
		t.Fatalf("Compile: %v%s", err, diagStrings(diags))
	}
	if HasErrors(diags) {
		t.Fatalf("unexpected errors:%s", diagStrings(diags))
	}
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(policies))
	}

	p := policies[0]
	if p.ID != "acme-admin" || p.TenantID != "acme" || p.Scope != "identity" {
		t.Fatalf("policy metadata lost: %+v", p)
	}
	if p.RuleAlgorithm != model.FirstApplicable {
		t.Fatalf("rule algorithm lost: %q", p.RuleAlgorithm)
	}
	if len(p.Rules) != 1 || p.Rules[0].Effect != model.Allow {
		t.Fatalf("rules lost: %+v", p.Rules)
	}
	// Six leaves: two inside the "any", one under the "not", and three
	// conjunctive ones.
	if got := p.Rules[0].When.CountLeaves(); got != 6 {
		t.Fatalf("expected 6 conditions, got %d", got)
	}

	// The disjunction and the negation must survive as such, or the index would
	// wrongly treat their leaves as prunable.
	spine := p.Rules[0].When.ANDSpineLeaves(nil)
	if len(spine) != 3 {
		t.Fatalf("expected 3 AND-spine leaves (range, cidr, num_in), got %d", len(spine))
	}
}

func TestCompile_EvaluatesAsWritten(t *testing.T) {
	b := read(t, goodBundle)
	policies, _, err := b.Compile(LintOptions{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	base := func() model.Request {
		return model.Request{
			TenantID: "acme", Scope: "identity",
			Attributes: map[string]string{
				"subject.role":   "admin",
				"subject.groups": "platform,oncall",
			},
			Numeric: map[string]float64{
				"subject.risk_score":  12,
				"transport.dest_port": 443,
			},
			IPs: mustIPs("network.source_ip", "10.1.2.3"),
		}
	}

	if d := model.Evaluate(policies, base(), model.DenyOverrides); !d.Allowed {
		t.Fatalf("expected the grant to apply, got %s", d)
	}

	// The Or's second branch.
	r := base()
	r.Attributes["subject.role"] = "security-admin"
	if d := model.Evaluate(policies, r, model.DenyOverrides); !d.Allowed {
		t.Fatalf("the second Or branch must also grant, got %s", d)
	}

	// The Not.
	r = base()
	r.Attributes["subject.groups"] = "platform,contractor"
	if d := model.Evaluate(policies, r, model.DenyOverrides); d.Allowed {
		t.Fatalf("the negation must exclude contractors, got %s", d)
	}

	// The numeric set.
	r = base()
	r.Numeric["transport.dest_port"] = 22
	if d := model.Evaluate(policies, r, model.DenyOverrides); d.Allowed {
		t.Fatalf("port 22 is not in the allowed set, got %s", d)
	}
}

func TestRead_RejectsUnknownFields(t *testing.T) {
	// A typo'd key must not be silently ignored: "polices" would produce an empty
	// bundle that denies everything, which is an outage rather than a warning.
	_, err := Read(strings.NewReader(`{"version":1,"polices":[]}`))
	if err == nil {
		t.Fatal("expected an unknown-field error")
	}
}

// TestRead_SkipsUTF8BOM covers a real onboarding failure. Windows editors and
// shell redirections emit a BOM by default, JSON's grammar has no place for one,
// and encoding/json reports it as "invalid character 'ï'" — an error that tells
// the author nothing about what is wrong with their file.
func TestRead_SkipsUTF8BOM(t *testing.T) {
	withBOM := "\xEF\xBB\xBF" + goodBundle
	b, err := Read(strings.NewReader(withBOM))
	if err != nil {
		t.Fatalf("a leading BOM must be tolerated: %v", err)
	}
	if len(b.Policies) != 1 {
		t.Fatalf("expected the bundle to parse, got %d policies", len(b.Policies))
	}
	if _, _, err := b.Compile(LintOptions{}); err != nil {
		t.Fatalf("Compile after BOM: %v", err)
	}
}

func TestRead_DefaultsVersion(t *testing.T) {
	b := read(t, `{"policies":[]}`)
	if b.Version != FormatVersion {
		t.Fatalf("expected version to default to %d, got %d", FormatVersion, b.Version)
	}
}

func TestCompile_RejectsUnsupportedVersion(t *testing.T) {
	b := read(t, `{"version": 99, "policies": []}`)
	_, diags, err := b.Compile(LintOptions{})
	if err == nil {
		t.Fatal("expected a version error")
	}
	if !findDiag(diags, Error, "unsupported bundle version") {
		t.Fatalf("expected a version diagnostic:%s", diagStrings(diags))
	}
}

func TestCompile_EmptyTenantBecomesGlobal(t *testing.T) {
	// A policy with no tenant is a platform policy. Leaving TenantID empty would
	// work by accident (Request.InScope treats it as global) but making it
	// explicit means the shard it lands in is not a surprise.
	b := read(t, `{"policies":[{"id":"p","rules":[{"id":"r","effect":"DENY"}]}]}`)
	policies, _, err := b.Compile(LintOptions{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if policies[0].TenantID != model.GlobalTenant {
		t.Fatalf("expected the global tenant, got %q", policies[0].TenantID)
	}
}

func TestNode_Kind(t *testing.T) {
	cases := []struct {
		name string
		node *Node
		want NodeKind
	}{
		{"leaf", &Node{Attr: "a", Op: "eq"}, NodeLeaf},
		{"leaf attr only", &Node{Attr: "a"}, NodeLeaf},
		{"all", &Node{All: []*Node{}}, NodeAll},
		{"any", &Node{Any: []*Node{}}, NodeAny},
		{"not", &Node{Not: &Node{Attr: "a", Op: "eq"}}, NodeNot},
		{"empty", &Node{}, NodeInvalid},
		{"nil", nil, NodeInvalid},
		// Ambiguous nodes are invalid rather than resolved by precedence: a
		// reader and the engine must not be able to disagree about the meaning.
		{"all and leaf", &Node{All: []*Node{}, Attr: "a", Op: "eq"}, NodeInvalid},
		{"all and any", &Node{All: []*Node{}, Any: []*Node{}}, NodeInvalid},
	}
	for _, tc := range cases {
		if got := tc.node.Kind(); got != tc.want {
			t.Errorf("%s: Kind() = %v want %v", tc.name, got, tc.want)
		}
	}
}

// --- Round trip -------------------------------------------------------------

func TestRoundTrip_PreservesSemantics(t *testing.T) {
	original := read(t, goodBundle)
	policies, _, err := original.Compile(LintOptions{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	var out strings.Builder
	if err := FromPolicies(policies).Write(&out); err != nil {
		t.Fatalf("Write: %v", err)
	}

	reparsed := read(t, out.String())
	again, diags, err := reparsed.Compile(LintOptions{})
	if err != nil {
		t.Fatalf("recompile: %v%s", err, diagStrings(diags))
	}

	if len(again) != len(policies) {
		t.Fatalf("policy count changed: %d then %d", len(policies), len(again))
	}
	for i := range policies {
		a, b := &policies[i], &again[i]
		if a.ID != b.ID || a.TenantID != b.TenantID || a.Scope != b.Scope ||
			a.Priority != b.Priority || a.RuleAlgorithm != b.RuleAlgorithm {
			t.Fatalf("policy %d metadata changed:\n%+v\n%+v", i, a, b)
		}
		if len(a.Rules) != len(b.Rules) {
			t.Fatalf("policy %d rule count changed", i)
		}
		for ri := range a.Rules {
			ar, br := &a.Rules[ri], &b.Rules[ri]
			if ar.ID != br.ID || ar.Effect != br.Effect || ar.Priority != br.Priority {
				t.Fatalf("rule %d/%d changed:\n%+v\n%+v", i, ri, ar, br)
			}
			if ar.When.CountLeaves() != br.When.CountLeaves() ||
				ar.When.Depth() != br.When.Depth() ||
				len(ar.When.ANDSpineLeaves(nil)) != len(br.When.ANDSpineLeaves(nil)) {
				t.Fatalf("rule %d/%d tree shape changed", i, ri)
			}
		}
	}
}

// TestRoundTrip_OmitsBoundsForNonNumericOperators keeps the emitted form clean.
// Writing "min": 0 on every equality would make a round-tripped bundle diff
// noisily against the hand-written original for no semantic reason.
func TestRoundTrip_OmitsBoundsForNonNumericOperators(t *testing.T) {
	policies := []model.Policy{model.SimplePolicy("p", "t", "", model.Allow, 0,
		[]model.Condition{{Attribute: "subject.role", Operator: model.OpEquals,
			Values: []string{"admin"}}})}

	var out strings.Builder
	if err := FromPolicies(policies).Write(&out); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if strings.Contains(out.String(), `"min"`) || strings.Contains(out.String(), `"max"`) {
		t.Fatalf("equality condition emitted numeric bounds:\n%s", out.String())
	}
}

// TestRoundTrip_EmptyConjunctionStaysACatchAll guards a subtle encoding trap: an
// empty "all" is a meaningful catch-all, but if it serialized as null it would
// reload as a node with no form at all, which the linter rejects.
func TestRoundTrip_EmptyConjunctionStaysACatchAll(t *testing.T) {
	policies := []model.Policy{{
		ID: "catch-all", TenantID: "t",
		Rules: []model.Rule{{ID: "r", Effect: model.Deny, When: model.And()}},
	}}
	var out strings.Builder
	if err := FromPolicies(policies).Write(&out); err != nil {
		t.Fatalf("Write: %v", err)
	}

	back, diags, err := read(t, out.String()).Compile(LintOptions{})
	if err != nil {
		t.Fatalf("recompile: %v%s", err, diagStrings(diags))
	}
	if !back[0].Rules[0].When.Matches(model.Request{TenantID: "t"}) {
		t.Fatal("an empty conjunction must still match everything after a round trip")
	}
}

// --- Linter -----------------------------------------------------------------

// TestLint_OperatorTypeMismatch is the headline check. A numeric operator on a
// string attribute produces a rule that can never fire, which is
// indistinguishable at runtime from a rule the author meant to be narrow. Load
// time is the only place it can be caught.
func TestLint_OperatorTypeMismatch(t *testing.T) {
	b := read(t, `{"policies":[{"id":"p","tenant":"t","rules":[{"id":"r","effect":"ALLOW",
	  "when":{"attr":"subject.role","op":"gt","min":5}}]}]}`)
	diags := b.Lint(LintOptions{})
	if !findDiag(diags, Error, "can never match") {
		t.Fatalf("expected a type-mismatch error:%s", diagStrings(diags))
	}

	if _, _, err := b.Compile(LintOptions{}); err == nil {
		t.Fatal("Compile must refuse a bundle with errors")
	}
}

func TestLint_UnknownOperatorAndEffect(t *testing.T) {
	b := read(t, `{"policies":[{"id":"p","tenant":"t","rules":[{"id":"r","effect":"MAYBE",
	  "when":{"attr":"subject.role","op":"approximately","values":["a"]}}]}]}`)
	diags := b.Lint(LintOptions{})
	if !findDiag(diags, Error, "unknown operator") {
		t.Errorf("expected an unknown-operator error:%s", diagStrings(diags))
	}
	if !findDiag(diags, Error, "unknown effect") {
		t.Errorf("expected an unknown-effect error:%s", diagStrings(diags))
	}
}

// TestLint_EqWithSeveralValues catches a real trap: eq and ne consult Values[0]
// only, so extra values are silently dropped and the rule is narrower than it
// reads.
func TestLint_EqWithSeveralValues(t *testing.T) {
	b := read(t, `{"policies":[{"id":"p","tenant":"t","rules":[{"id":"r","effect":"ALLOW",
	  "when":{"attr":"subject.role","op":"eq","values":["admin","auditor"]}}]}]}`)
	diags := b.Lint(LintOptions{})
	if !findDiag(diags, Error, "reads only the first value") {
		t.Fatalf("expected an error about extra values:%s", diagStrings(diags))
	}
}

func TestLint_EmptyAnyIsAnError(t *testing.T) {
	// An empty disjunction matches nothing, making the whole rule dead code.
	b := read(t, `{"policies":[{"id":"p","tenant":"t","rules":[{"id":"r","effect":"ALLOW",
	  "when":{"any":[]}}]}]}`)
	diags := b.Lint(LintOptions{})
	if !findDiag(diags, Error, "can never fire") {
		t.Fatalf("expected an empty-any error:%s", diagStrings(diags))
	}
}

func TestLint_DuplicateIDs(t *testing.T) {
	b := read(t, `{"policies":[
	  {"id":"dup","tenant":"t","rules":[{"id":"r","effect":"ALLOW"}]},
	  {"id":"dup","tenant":"t","rules":[{"id":"r2","effect":"DENY"}]}
	]}`)
	if !findDiag(b.Lint(LintOptions{}), Error, "duplicate policy id") {
		t.Fatalf("expected a duplicate-policy error:%s", diagStrings(b.Lint(LintOptions{})))
	}

	b2 := read(t, `{"policies":[{"id":"p","tenant":"t","rules":[
	  {"id":"same","effect":"ALLOW"},{"id":"same","effect":"DENY"}]}]}`)
	if !findDiag(b2.Lint(LintOptions{}), Error, "duplicate rule id") {
		t.Fatalf("expected a duplicate-rule error:%s", diagStrings(b2.Lint(LintOptions{})))
	}
}

func TestLint_BadRegex(t *testing.T) {
	b := read(t, `{"policies":[{"id":"p","tenant":"t","rules":[{"id":"r","effect":"DENY",
	  "when":{"attr":"http.query","op":"regex","values":["("]}}]}]}`)
	if !findDiag(b.Lint(LintOptions{}), Error, "does not compile") {
		t.Fatalf("expected a regex error:%s", diagStrings(b.Lint(LintOptions{})))
	}
}

func TestLint_MissingOperands(t *testing.T) {
	cases := []struct {
		name, when, want string
	}{
		{"in without values",
			`{"attr":"subject.role","op":"in"}`, "needs at least one value"},
		{"range without bounds",
			`{"attr":"subject.risk_score","op":"range"}`, "needs both min and max"},
		{"gt without min",
			`{"attr":"subject.risk_score","op":"gt"}`, "needs min"},
		{"lt without max",
			`{"attr":"subject.risk_score","op":"lt"}`, "needs max"},
		{"num_in without numbers",
			`{"attr":"transport.dest_port","op":"num_in"}`, "needs at least one number"},
		{"cidr without prefixes",
			`{"attr":"network.source_ip","op":"cidr"}`, "needs at least one prefix"},
		{"inverted range",
			`{"attr":"subject.risk_score","op":"range","min":90,"max":10}`, "can never match"},
		{"bad cidr",
			`{"attr":"network.source_ip","op":"cidr","prefixes":["not-a-prefix"]}`, "not valid CIDR"},
	}
	for _, tc := range cases {
		src := `{"policies":[{"id":"p","tenant":"t","rules":[{"id":"r","effect":"ALLOW","when":` +
			tc.when + `}]}]}`
		diags := read(t, src).Lint(LintOptions{})
		if !findDiag(diags, Error, tc.want) {
			t.Errorf("%s: expected %q:%s", tc.name, tc.want, diagStrings(diags))
		}
	}
}

// TestLint_SuffixOnHostnameWarns catches the confusion that OpSuffix exists
// separately to permit: a byte suffix on a domain accepts the lookalike.
func TestLint_SuffixOnHostnameWarns(t *testing.T) {
	b := read(t, `{"policies":[{"id":"p","tenant":"t","rules":[{"id":"r","effect":"ALLOW",
	  "when":{"attr":"resource.domain","op":"suffix","values":["acme.com"]}}]}]}`)
	diags := b.Lint(LintOptions{})
	if !findDiag(diags, Warning, "Use dnssuffix for hostnames") {
		t.Fatalf("expected a suffix/dnssuffix warning:%s", diagStrings(diags))
	}
	// A file extension must not trip it.
	b2 := read(t, `{"policies":[{"id":"p","tenant":"t","rules":[{"id":"r","effect":"DENY",
	  "when":{"attr":"payload.file_ext","op":"suffix","values":[".php"]}}]}]}`)
	if findDiag(b2.Lint(LintOptions{}), Warning, "Use dnssuffix") {
		t.Error("a file extension must not trigger the hostname warning")
	}
}

func TestLint_UnregisteredAttribute(t *testing.T) {
	src := `{"policies":[{"id":"p","tenant":"t","rules":[{"id":"r","effect":"ALLOW",
	  "when":{"attr":"custom.internal_signal","op":"eq","values":["x"]}}]}]}`

	// Warning by default: customers legitimately carry their own vocabulary.
	diags := read(t, src).Lint(LintOptions{})
	if !findDiag(diags, Warning, "not in the registry") {
		t.Errorf("expected a warning:%s", diagStrings(diags))
	}
	if HasErrors(diags) {
		t.Errorf("an unregistered attribute must not block by default:%s", diagStrings(diags))
	}

	// Error under strict mode.
	strict := read(t, src).Lint(LintOptions{StrictAttributes: true})
	if !findDiag(strict, Error, "not in the registry") {
		t.Errorf("expected an error under StrictAttributes:%s", diagStrings(strict))
	}
}

func TestLint_RulePriorityIgnoredWarning(t *testing.T) {
	// Rule.Priority does nothing under the overrides algorithms, so setting it
	// there reads as ordering the rules when it has no effect at all.
	b := read(t, `{"policies":[{"id":"p","tenant":"t","rules":[
	  {"id":"a","effect":"DENY","priority":10},
	  {"id":"b","effect":"ALLOW","priority":100}]}]}`)
	if !findDiag(b.Lint(LintOptions{}), Warning, "use first-applicable") {
		t.Fatalf("expected a priority warning:%s", diagStrings(b.Lint(LintOptions{})))
	}

	// Not warned when the algorithm actually uses them.
	b2 := read(t, `{"policies":[{"id":"p","tenant":"t","rule_algorithm":"first-applicable","rules":[
	  {"id":"a","effect":"DENY","priority":10},
	  {"id":"b","effect":"ALLOW","priority":100}]}]}`)
	if findDiag(b2.Lint(LintOptions{}), Warning, "use first-applicable") {
		t.Error("first-applicable uses rule priorities, so no warning is due")
	}
}

func TestLint_DepthAndSizeCaps(t *testing.T) {
	// A deeply nested tree is a denial-of-service vector against every request
	// reaching the shard, since nothing inside a disjunction can be pruned.
	deep := `{"attr":"subject.role","op":"eq","values":["a"]}`
	for i := 0; i < 20; i++ {
		deep = `{"not":` + deep + `}`
	}
	src := `{"policies":[{"id":"p","tenant":"t","rules":[{"id":"r","effect":"ALLOW","when":` +
		deep + `}]}]}`
	if !findDiag(read(t, src).Lint(LintOptions{}), Error, "deep, limit is") {
		t.Error("expected a depth error")
	}

	var leaves []string
	for i := 0; i < 80; i++ {
		leaves = append(leaves, `{"attr":"subject.role","op":"eq","values":["a"]}`)
	}
	wide := `{"policies":[{"id":"p","tenant":"t","rules":[{"id":"r","effect":"ALLOW",
	  "when":{"all":[` + strings.Join(leaves, ",") + `]}}]}]}`
	if !findDiag(read(t, wide).Lint(LintOptions{}), Error, "conditions, limit is") {
		t.Error("expected a condition-count error")
	}
}

func TestLint_EmptyRuleSet(t *testing.T) {
	src := `{"policies":[{"id":"p","tenant":"t","rules":[]}]}`
	if !findDiag(read(t, src).Lint(LintOptions{}), Error, "can never produce a verdict") {
		t.Error("expected an empty-rules error")
	}
	if HasErrors(read(t, src).Lint(LintOptions{AllowEmptyRuleSet: true})) {
		t.Error("AllowEmptyRuleSet should permit it")
	}
}

func TestLint_CatchAllRuleWarns(t *testing.T) {
	src := `{"policies":[{"id":"p","tenant":"t","rules":[{"id":"r","effect":"ALLOW"}]}]}`
	if !findDiag(read(t, src).Lint(LintOptions{}), Warning, "matches every request in scope") {
		t.Error("expected a catch-all warning")
	}
}

func TestLint_InvalidNodeShape(t *testing.T) {
	src := `{"policies":[{"id":"p","tenant":"t","rules":[{"id":"r","effect":"ALLOW",
	  "when":{"all":[{"attr":"subject.role","op":"eq","values":["a"]}],"any":[]}}]}]}`
	if !findDiag(read(t, src).Lint(LintOptions{}), Error, "exactly one of") {
		t.Error("expected an ambiguous-node error")
	}
}

func TestLint_IgnoredOperandsWarn(t *testing.T) {
	src := `{"policies":[{"id":"p","tenant":"t","rules":[{"id":"r","effect":"ALLOW",
	  "when":{"attr":"subject.risk_score","op":"gt","min":5,"max":90}}]}]}`
	if !findDiag(read(t, src).Lint(LintOptions{}), Warning, "ignores max") {
		t.Error("expected a warning about the ignored max")
	}
}

func TestLint_NonCanonicalPrefixWarns(t *testing.T) {
	src := `{"policies":[{"id":"p","tenant":"t","rules":[{"id":"r","effect":"ALLOW",
	  "when":{"attr":"network.source_ip","op":"cidr","prefixes":["10.1.2.3/8"]}}]}]}`
	if !findDiag(read(t, src).Lint(LintOptions{}), Warning, "bits set below its mask") {
		t.Error("expected a non-canonical prefix warning")
	}
}

func TestLint_EmptyBundleWarns(t *testing.T) {
	if !findDiag(read(t, `{"policies":[]}`).Lint(LintOptions{}), Warning, "no policies") {
		t.Error("expected a warning for an empty bundle")
	}
}

// --- Summarize --------------------------------------------------------------

func TestSummarize(t *testing.T) {
	s := read(t, goodBundle).Summarize()
	if s.Policies != 1 || s.Rules != 1 {
		t.Fatalf("expected 1 policy and 1 rule, got %d and %d", s.Policies, s.Rules)
	}
	if s.Conditions != 6 {
		t.Fatalf("expected 6 conditions, got %d", s.Conditions)
	}
	// Only the three conjunctive leaves are indexable; the Or's two branches and
	// the Not's leaf are not.
	if s.IndexableConds != 3 {
		t.Fatalf("expected 3 indexable conditions, got %d", s.IndexableConds)
	}
	if s.RulesWithOrNot != 1 {
		t.Fatalf("expected 1 rule with off-spine structure, got %d", s.RulesWithOrNot)
	}
	if s.Operators["eq"] != 2 || s.Operators["cidr"] != 1 || s.Operators["num_in"] != 1 {
		t.Fatalf("operator counts wrong: %v", s.Operators)
	}
	if len(s.Attributes) == 0 {
		t.Fatal("expected attributes to be collected")
	}
	for i := 1; i < len(s.Attributes); i++ {
		if s.Attributes[i-1] >= s.Attributes[i] {
			t.Fatalf("attributes not sorted: %v", s.Attributes)
		}
	}
}

// TestSummarize_MatchesModelSpineExtraction pins the serialized-form spine count
// against the engine's own extraction. Two implementations of the same rule would
// otherwise drift, and the bundle report would misstate how much of a policy set
// the index can prune on.
func TestSummarize_MatchesModelSpineExtraction(t *testing.T) {
	b := read(t, goodBundle)
	policies, _, err := b.Compile(LintOptions{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	modelSpine := 0
	for i := range policies {
		for ri := range policies[i].Rules {
			modelSpine += len(policies[i].Rules[ri].When.ANDSpineLeaves(nil))
		}
	}
	if got := b.Summarize().IndexableConds; got != modelSpine {
		t.Fatalf("bundle reports %d indexable conditions, model extracts %d", got, modelSpine)
	}
}

func mustIPs(name, addr string) map[string]netip.Addr {
	return map[string]netip.Addr{name: netip.MustParseAddr(addr)}
}
