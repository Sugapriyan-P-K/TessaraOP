package model

import (
	"net/netip"
	"testing"
)

func req(attrs map[string]string) Request {
	return Request{TenantID: "t1", Attributes: attrs}
}

// one builds a single-rule policy, the shape most of these tests want.
func one(id string, effect Effect, priority int, when *ConditionExpr, obligations ...string) Policy {
	return Policy{
		ID:       id,
		Priority: priority,
		Rules: []Rule{{
			ID: id + "/r0", Effect: effect, Priority: priority,
			When: when, Obligations: obligations,
		}},
	}
}

// --- Condition semantics ----------------------------------------------------

func TestCondition_SetFamily(t *testing.T) {
	tests := []struct {
		name string
		cond Condition
		req  Request
		want bool
	}{
		{"eq match", Condition{Attribute: "r", Operator: OpEquals, Values: []string{"admin"}},
			req(map[string]string{"r": "admin"}), true},
		{"eq mismatch", Condition{Attribute: "r", Operator: OpEquals, Values: []string{"admin"}},
			req(map[string]string{"r": "viewer"}), false},
		{"ne match", Condition{Attribute: "r", Operator: OpNotEquals, Values: []string{"admin"}},
			req(map[string]string{"r": "viewer"}), true},
		{"ne mismatch", Condition{Attribute: "r", Operator: OpNotEquals, Values: []string{"admin"}},
			req(map[string]string{"r": "admin"}), false},
		{"in match", Condition{Attribute: "r", Operator: OpIn, Values: []string{"a", "b"}},
			req(map[string]string{"r": "b"}), true},
		{"in mismatch", Condition{Attribute: "r", Operator: OpIn, Values: []string{"a", "b"}},
			req(map[string]string{"r": "c"}), false},
		{"nin match", Condition{Attribute: "r", Operator: OpNotIn, Values: []string{"a", "b"}},
			req(map[string]string{"r": "c"}), true},
		{"nin mismatch", Condition{Attribute: "r", Operator: OpNotIn, Values: []string{"a", "b"}},
			req(map[string]string{"r": "a"}), false},
		{"exists", Condition{Attribute: "r", Operator: OpExists},
			req(map[string]string{"r": "anything"}), true},
		{"exists absent", Condition{Attribute: "r", Operator: OpExists},
			req(map[string]string{}), false},
		{"notexists absent", Condition{Attribute: "r", Operator: OpNotExists},
			req(map[string]string{}), true},
		{"notexists present", Condition{Attribute: "r", Operator: OpNotExists},
			req(map[string]string{"r": "x"}), false},
	}
	for _, tc := range tests {
		if got := tc.cond.Matches(tc.req); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

func TestCondition_StringOperators(t *testing.T) {
	r := req(map[string]string{
		"path": "/api/v2/admin/users",
		"ua":   "sqlmap/1.7 (linux)",
		"file": "payload.tar.gz",
		"host": "api.acme.com",
	})
	tests := []struct {
		name string
		cond Condition
		want bool
	}{
		{"contains hit", Condition{Attribute: "ua", Operator: OpContains, Values: []string{"nikto", "sqlmap"}}, true},
		{"contains miss", Condition{Attribute: "ua", Operator: OpContains, Values: []string{"nikto"}}, false},
		{"ncontains hit", Condition{Attribute: "ua", Operator: OpNotContains, Values: []string{"nikto"}}, true},
		{"ncontains miss", Condition{Attribute: "ua", Operator: OpNotContains, Values: []string{"sqlmap"}}, false},

		{"prefix hit", Condition{Attribute: "path", Operator: OpPrefix, Values: []string{"/api/v2"}}, true},
		{"prefix miss", Condition{Attribute: "path", Operator: OpPrefix, Values: []string{"/internal"}}, false},
		{"nprefix hit", Condition{Attribute: "path", Operator: OpNotPrefix, Values: []string{"/internal"}}, true},
		{"nprefix miss", Condition{Attribute: "path", Operator: OpNotPrefix, Values: []string{"/api"}}, false},

		{"suffix hit", Condition{Attribute: "file", Operator: OpSuffix, Values: []string{".gz", ".zip"}}, true},
		{"suffix miss", Condition{Attribute: "file", Operator: OpSuffix, Values: []string{".exe"}}, false},
		{"nsuffix hit", Condition{Attribute: "file", Operator: OpNotSuffix, Values: []string{".exe"}}, true},
		{"nsuffix miss", Condition{Attribute: "file", Operator: OpNotSuffix, Values: []string{".gz"}}, false},

		{"regex hit", Condition{Attribute: "ua", Operator: OpRegex, Values: []string{`(?i)sql(map|ninja)`}}, true},
		{"regex miss", Condition{Attribute: "ua", Operator: OpRegex, Values: []string{`^curl`}}, false},
		{"nregex hit", Condition{Attribute: "ua", Operator: OpNotRegex, Values: []string{`^curl`}}, true},
		{"nregex miss", Condition{Attribute: "ua", Operator: OpNotRegex, Values: []string{`(?i)sqlmap`}}, false},

		{"dnssuffix hit", Condition{Attribute: "host", Operator: OpDNSSuffix, Values: []string{"acme.com"}}, true},
		{"dnssuffix miss", Condition{Attribute: "host", Operator: OpDNSSuffix, Values: []string{"evil.net"}}, false},
		{"ndnssuffix hit", Condition{Attribute: "host", Operator: OpNotDNSSuffix, Values: []string{"evil.net"}}, true},
		{"ndnssuffix miss", Condition{Attribute: "host", Operator: OpNotDNSSuffix, Values: []string{"acme.com"}}, false},
	}
	for _, tc := range tests {
		if got := tc.cond.Matches(r); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

// TestCondition_SuffixIsNotLabelAligned pins the distinction that makes
// OpDNSSuffix a separate operator rather than a convenience wrapper. A byte
// suffix accepting evilacme.com for acme.com is the exact lookalike-domain
// bypass the DNS operator exists to prevent, so the two must not be conflated.
func TestCondition_SuffixIsNotLabelAligned(t *testing.T) {
	r := req(map[string]string{"host": "evilacme.com"})

	bytewise := Condition{Attribute: "host", Operator: OpSuffix, Values: []string{"acme.com"}}
	if !bytewise.Matches(r) {
		t.Error("OpSuffix is a raw byte test and must accept evilacme.com")
	}

	aligned := Condition{Attribute: "host", Operator: OpDNSSuffix, Values: []string{"acme.com"}}
	if aligned.Matches(r) {
		t.Error("OpDNSSuffix must reject the lookalike domain")
	}
}

func TestCondition_AbsentAttributeFailsClosed(t *testing.T) {
	// Every operator except NotExists must reject an absent attribute, including
	// the negations. "role != admin" must not silently pass for a request that
	// carries no role at all.
	empty := Request{TenantID: "t1", Attributes: map[string]string{}}
	for _, op := range AllOperators {
		if op == OpNotExists {
			continue
		}
		c := Condition{
			Attribute: "missing", Operator: op,
			Values: []string{"x"}, Min: 0, Max: 100, Numbers: []float64{1},
			Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		}
		if c.Matches(empty) {
			t.Errorf("operator %s matched an absent attribute", op)
		}
	}
}

func TestCondition_NumericFamily(t *testing.T) {
	r := Request{Numeric: map[string]float64{"score": 50}}
	cases := []struct {
		cond Condition
		want bool
	}{
		{Condition{Attribute: "score", Operator: OpRange, Min: 0, Max: 100}, true},
		{Condition{Attribute: "score", Operator: OpRange, Min: 60, Max: 100}, false},
		{Condition{Attribute: "score", Operator: OpRange, Min: 50, Max: 50}, true},
		{Condition{Attribute: "score", Operator: OpNotRange, Min: 60, Max: 100}, true},
		{Condition{Attribute: "score", Operator: OpNotRange, Min: 0, Max: 100}, false},
		{Condition{Attribute: "score", Operator: OpGreaterThan, Min: 49}, true},
		{Condition{Attribute: "score", Operator: OpGreaterThan, Min: 50}, false},
		{Condition{Attribute: "score", Operator: OpGreaterEq, Min: 50}, true},
		{Condition{Attribute: "score", Operator: OpGreaterEq, Min: 51}, false},
		{Condition{Attribute: "score", Operator: OpLessThan, Max: 51}, true},
		{Condition{Attribute: "score", Operator: OpLessThan, Max: 50}, false},
		{Condition{Attribute: "score", Operator: OpLessEq, Max: 50}, true},
		{Condition{Attribute: "score", Operator: OpLessEq, Max: 49}, false},
		{Condition{Attribute: "score", Operator: OpNumEquals, Min: 50}, true},
		{Condition{Attribute: "score", Operator: OpNumEquals, Min: 51}, false},
		{Condition{Attribute: "score", Operator: OpNumNotEq, Min: 51}, true},
		{Condition{Attribute: "score", Operator: OpNumNotEq, Min: 50}, false},
		{Condition{Attribute: "score", Operator: OpNumIn, Numbers: []float64{10, 50, 90}}, true},
		{Condition{Attribute: "score", Operator: OpNumIn, Numbers: []float64{10, 90}}, false},
		{Condition{Attribute: "score", Operator: OpNumNotIn, Numbers: []float64{10, 90}}, true},
		{Condition{Attribute: "score", Operator: OpNumNotIn, Numbers: []float64{10, 50}}, false},
	}
	for i, tc := range cases {
		if got := tc.cond.Matches(r); got != tc.want {
			t.Errorf("case %d (%s): got %v want %v", i, tc.cond.Operator, got, tc.want)
		}
	}
}

// TestCondition_NaNSatisfiesNothing guards a specific hole in IEEE semantics.
// Every comparison against NaN is false, so a negated numeric operator would
// return true for it by default — turning a malformed or missing measurement
// into a match. A rule saying "dest_port != 22" must not fire on a port that
// failed to parse.
func TestCondition_NaNSatisfiesNothing(t *testing.T) {
	nan := Request{Numeric: map[string]float64{"score": nanValue()}}
	for _, op := range []Operator{
		OpRange, OpNotRange, OpGreaterThan, OpGreaterEq, OpLessThan, OpLessEq,
		OpNumEquals, OpNumNotEq, OpNumIn, OpNumNotIn,
	} {
		c := Condition{Attribute: "score", Operator: op, Min: 0, Max: 100, Numbers: []float64{1}}
		if c.Matches(nan) {
			t.Errorf("operator %s matched a NaN attribute value", op)
		}
	}
}

func nanValue() float64 {
	zero := 0.0
	return zero / zero
}

func TestCondition_CIDR(t *testing.T) {
	r := Request{IPs: map[string]netip.Addr{"ip": netip.MustParseAddr("10.4.2.7")}}

	in := Condition{Attribute: "ip", Operator: OpCIDR,
		Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	if !in.Matches(r) {
		t.Error("expected address inside 10.0.0.0/8 to match")
	}

	out := Condition{Attribute: "ip", Operator: OpCIDR,
		Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}}
	if out.Matches(r) {
		t.Error("expected address outside the block not to match")
	}

	neg := Condition{Attribute: "ip", Operator: OpNotCIDR,
		Prefixes: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}}
	if !neg.Matches(r) {
		t.Error("expected !CIDR to pass for an address outside the blocked range")
	}

	negHit := Condition{Attribute: "ip", Operator: OpNotCIDR,
		Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	if negHit.Matches(r) {
		t.Error("expected !CIDR to fail for an address inside the blocked range")
	}
}

func TestCondition_ExistsAcrossTypedMaps(t *testing.T) {
	// OpExists must see an attribute wherever it lives, not only in the string
	// map. The index mirrors this, so a divergence here would desynchronize them.
	numeric := Request{Numeric: map[string]float64{"port": 443}}
	ip := Request{IPs: map[string]netip.Addr{"src": netip.MustParseAddr("10.0.0.1")}}

	if !(&Condition{Attribute: "port", Operator: OpExists}).Matches(numeric) {
		t.Error("exists must see a numeric attribute")
	}
	if !(&Condition{Attribute: "src", Operator: OpExists}).Matches(ip) {
		t.Error("exists must see an IP attribute")
	}
	if (&Condition{Attribute: "port", Operator: OpNotExists}).Matches(numeric) {
		t.Error("nexists must be defeated by a numeric attribute")
	}
	if (&Condition{Attribute: "src", Operator: OpNotExists}).Matches(ip) {
		t.Error("nexists must be defeated by an IP attribute")
	}
}

func TestMatchDNSSuffix(t *testing.T) {
	cases := []struct {
		host, suffix string
		want         bool
	}{
		{"acme.com", "acme.com", true},
		{"api.acme.com", "acme.com", true},
		{"a.b.acme.com", "acme.com", true},
		{"evilacme.com", "acme.com", false},
		{"acme.com.evil.net", "acme.com", false},
		{"com", "acme.com", false},
	}
	for _, tc := range cases {
		if got := MatchDNSSuffix(tc.host, tc.suffix); got != tc.want {
			t.Errorf("MatchDNSSuffix(%q,%q) = %v want %v", tc.host, tc.suffix, got, tc.want)
		}
	}
}

func TestCondition_PrepareRejectsBadPattern(t *testing.T) {
	c := Condition{Attribute: "q", Operator: OpRegex, Values: []string{"("}}
	if err := c.Prepare(); err == nil {
		t.Fatal("Prepare must report an unparsable pattern")
	}
}

// TestCondition_RegexWorksWithoutPrepare covers the SDK path where a caller
// builds policies by hand and never calls Prepare. Evaluation must still be
// correct — it just pays a cache lookup instead of nothing.
func TestCondition_RegexWorksWithoutPrepare(t *testing.T) {
	c := Condition{Attribute: "q", Operator: OpRegex, Values: []string{`^id=\d+$`}}
	if !c.Matches(req(map[string]string{"q": "id=42"})) {
		t.Error("uncompiled regex must still match")
	}
	if c.Matches(req(map[string]string{"q": "id=abc"})) {
		t.Error("uncompiled regex must still reject")
	}
	if err := c.Prepare(); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if !c.Matches(req(map[string]string{"q": "id=42"})) {
		t.Error("compiled regex must agree with the uncompiled result")
	}
}

func TestOperator_FamilyCoversEveryOperator(t *testing.T) {
	// An operator with no family reads no map and can never match, so a missing
	// entry in Family() is a silently dead operator.
	for _, op := range AllOperators {
		if op.Family() == FamilyUnknown {
			t.Errorf("operator %s has no family", op)
		}
	}
}

// --- Condition trees --------------------------------------------------------

func TestConditionExpr_Boolean(t *testing.T) {
	admin := Condition{Attribute: "role", Operator: OpEquals, Values: []string{"admin"}}
	secAdmin := Condition{Attribute: "role", Operator: OpEquals, Values: []string{"security-admin"}}
	contractor := Condition{Attribute: "dept", Operator: OpEquals, Values: []string{"contractor"}}

	// (role=admin OR role=security-admin) AND NOT dept=contractor
	tree := And(
		Or(Cond(admin), Cond(secAdmin)),
		Not(Cond(contractor)),
	)

	cases := []struct {
		attrs map[string]string
		want  bool
	}{
		{map[string]string{"role": "admin", "dept": "eng"}, true},
		{map[string]string{"role": "security-admin", "dept": "eng"}, true},
		{map[string]string{"role": "viewer", "dept": "eng"}, false},
		{map[string]string{"role": "admin", "dept": "contractor"}, false},
	}
	for _, tc := range cases {
		if got := tree.Matches(req(tc.attrs)); got != tc.want {
			t.Errorf("%v: got %v want %v", tc.attrs, got, tc.want)
		}
	}
}

func TestConditionExpr_EmptyAndMatchesEmptyOrDoesNot(t *testing.T) {
	// An empty conjunction is a catch-all: a rule with nothing to check applies
	// unconditionally. An empty disjunction must match nothing, so an empty
	// Or cannot silently grant access.
	if !And().Matches(req(nil)) {
		t.Error("empty And must match everything")
	}
	if Or().Matches(req(nil)) {
		t.Error("empty Or must match nothing")
	}
	var nilExpr *ConditionExpr
	if !nilExpr.Matches(req(nil)) {
		t.Error("a nil expression must match everything")
	}
}

func TestConditionExpr_MalformedNotFailsClosed(t *testing.T) {
	broken := &ConditionExpr{Kind: ExprNot} // no child
	if broken.Matches(req(map[string]string{"a": "b"})) {
		t.Error("a malformed Not must fail closed rather than granting")
	}
}

// TestANDSpineLeaves_ExcludesOrAndNot is the indexing-boundary test. A leaf
// under an Or is not necessary for the tree to match, and a leaf under a Not is
// required to be false rather than true. Either one, if indexed, lets the
// pre-filter exclude a rule that genuinely matches — the one failure mode that
// makes a fast engine a wrong one.
func TestANDSpineLeaves_ExcludesOrAndNot(t *testing.T) {
	spineCond := Condition{Attribute: "onspine", Operator: OpEquals, Values: []string{"x"}}
	orCond := Condition{Attribute: "inor", Operator: OpEquals, Values: []string{"x"}}
	notCond := Condition{Attribute: "innot", Operator: OpEquals, Values: []string{"x"}}
	deepCond := Condition{Attribute: "deep", Operator: OpEquals, Values: []string{"x"}}

	tree := And(
		Cond(spineCond),
		And(Cond(deepCond)), // nested And stays on the spine
		Or(Cond(orCond)),
		Not(Cond(notCond)),
	)

	got := map[string]bool{}
	for _, c := range tree.ANDSpineLeaves(nil) {
		got[c.Attribute] = true
	}

	if !got["onspine"] || !got["deep"] {
		t.Errorf("conjunctive leaves must be on the spine, got %v", got)
	}
	if got["inor"] {
		t.Error("a leaf under Or must not be indexable")
	}
	if got["innot"] {
		t.Error("a leaf under Not must not be indexable")
	}
	if len(got) != 2 {
		t.Errorf("expected exactly 2 spine leaves, got %v", got)
	}
}

func TestANDSpineLeaves_RootOrYieldsNothing(t *testing.T) {
	tree := Or(
		Cond(Condition{Attribute: "a", Operator: OpEquals, Values: []string{"1"}}),
		Cond(Condition{Attribute: "b", Operator: OpEquals, Values: []string{"2"}}),
	)
	if got := tree.ANDSpineLeaves(nil); len(got) != 0 {
		t.Fatalf("a rule rooted at Or gets no index help at all, got %v", got)
	}
}

func TestConditionExpr_DepthAndLeaves(t *testing.T) {
	tree := And(
		Cond(Condition{Attribute: "a", Operator: OpExists}),
		Or(
			Cond(Condition{Attribute: "b", Operator: OpExists}),
			Not(Cond(Condition{Attribute: "c", Operator: OpExists})),
		),
	)
	if got := tree.CountLeaves(); got != 3 {
		t.Errorf("CountLeaves = %d want 3", got)
	}
	if got := tree.Depth(); got != 4 {
		t.Errorf("Depth = %d want 4", got)
	}
}

func TestConditionExpr_PrepareWalksWholeTree(t *testing.T) {
	tree := And(
		Cond(Condition{Attribute: "a", Operator: OpExists}),
		Or(Cond(Condition{Attribute: "q", Operator: OpRegex, Values: []string{"("}})),
	)
	if err := tree.Prepare(); err == nil {
		t.Fatal("Prepare must find a bad pattern nested under an Or")
	}
}

// --- Rules and the inner tier -----------------------------------------------

func TestPolicy_RulesAreIndependent(t *testing.T) {
	p := Policy{
		ID: "p",
		Rules: []Rule{
			{ID: "r-allow", Effect: Allow, When: AllOf(
				Condition{Attribute: "role", Operator: OpEquals, Values: []string{"admin"}})},
			{ID: "r-deny", Effect: Deny, When: AllOf(
				Condition{Attribute: "action", Operator: OpEquals, Values: []string{"delete"}})},
		},
	}

	v, ok, _ := p.Resolve(req(map[string]string{"role": "admin"}))
	if !ok || v.Effect != Allow || v.RuleID != "r-allow" {
		t.Fatalf("expected the allow rule to fire, got %+v ok=%v", v, ok)
	}

	// Both rules match: deny-overrides is the default rule algorithm.
	v, ok, _ = p.Resolve(req(map[string]string{"role": "admin", "action": "delete"}))
	if !ok || v.Effect != Deny || v.RuleID != "r-deny" {
		t.Fatalf("deny must win inside the policy, got %+v ok=%v", v, ok)
	}

	if _, ok, _ := p.Resolve(req(map[string]string{"role": "viewer"})); ok {
		t.Fatal("no rule matches, so the policy must produce no verdict")
	}
}

// TestPolicy_AttributesTheRuleThatActuallyFired guards a specific bug that is
// easy to reintroduce: reconstructing the winning rule after the fact by
// scanning for "any rule with the winning effect". Two same-effect rules in one
// policy would then be misattributed, and an audit trail would name the wrong
// rule. The matched rule ID must be threaded through from the moment it matched.
func TestPolicy_AttributesTheRuleThatActuallyFired(t *testing.T) {
	p := Policy{
		ID: "p",
		Rules: []Rule{
			{ID: "deny-first", Effect: Deny, When: AllOf(
				Condition{Attribute: "a", Operator: OpEquals, Values: []string{"1"}})},
			{ID: "deny-second", Effect: Deny, When: AllOf(
				Condition{Attribute: "b", Operator: OpEquals, Values: []string{"2"}})},
		},
	}
	v, ok, _ := p.Resolve(req(map[string]string{"b": "2"}))
	if !ok {
		t.Fatal("expected a verdict")
	}
	if v.RuleID != "deny-second" {
		t.Fatalf("wrong rule credited: got %q want deny-second", v.RuleID)
	}
}

func TestPolicy_RuleAlgorithmAppliesWithinPolicy(t *testing.T) {
	// A broad deny with its own narrow exception, resolved by priority. This is
	// the shape a flat condition list could not express without leaking the
	// exception into a separate policy visible to the whole shard.
	broad := Condition{Attribute: "action", Operator: OpEquals, Values: []string{"delete"}}
	p := Policy{
		ID:            "break-glass",
		RuleAlgorithm: FirstApplicable,
		Rules: []Rule{
			{ID: "deny-delete", Effect: Deny, Priority: 10, When: AllOf(broad)},
			{ID: "allow-with-ticket", Effect: Allow, Priority: 100, When: AllOf(broad,
				Condition{Attribute: "ticket", Operator: OpExists})},
		},
	}

	v, _, _ := p.Resolve(req(map[string]string{"action": "delete"}))
	if v.Effect != Deny {
		t.Fatalf("without a ticket the broad deny must win, got %+v", v)
	}

	v, _, _ = p.Resolve(req(map[string]string{"action": "delete", "ticket": "INC-1"}))
	if v.Effect != Allow || v.RuleID != "allow-with-ticket" {
		t.Fatalf("the higher-priority exception must win, got %+v", v)
	}
}

func TestPolicy_ResolveAtMatchesFullResolve(t *testing.T) {
	p := Policy{
		ID: "p",
		Rules: []Rule{
			{ID: "r0", Effect: Allow, When: AllOf(
				Condition{Attribute: "a", Operator: OpEquals, Values: []string{"1"}})},
			{ID: "r1", Effect: Deny, When: AllOf(
				Condition{Attribute: "b", Operator: OpEquals, Values: []string{"2"}})},
			{ID: "r2", Effect: Allow, When: AllOf(
				Condition{Attribute: "c", Operator: OpEquals, Values: []string{"3"}})},
		},
	}
	r := req(map[string]string{"a": "1", "b": "2"})
	full, fullOK, _ := p.Resolve(r)
	part, partOK, _ := p.ResolveAt(r, []int{0, 1, 2})
	if fullOK != partOK || full.Effect != part.Effect {
		t.Fatalf("feeding every position must equal a full resolve: %+v vs %+v", full, part)
	}
}

func TestPolicy_ResolveAtIgnoresOutOfRangePositions(t *testing.T) {
	// An index that has drifted from its policies should degrade to
	// under-selective, not panic in the decision path.
	p := Policy{ID: "p", Rules: []Rule{{ID: "r0", Effect: Allow}}}
	v, ok, _ := p.ResolveAt(req(nil), []int{0, 5, -1})
	if !ok || v.RuleID != "r0" {
		t.Fatalf("expected r0 to resolve, got %+v ok=%v", v, ok)
	}
}

func TestPolicy_RulelessProducesNoVerdict(t *testing.T) {
	p := Policy{ID: "empty"}
	if _, ok, _ := p.Resolve(req(map[string]string{"a": "b"})); ok {
		t.Fatal("a policy with no rules cannot produce a verdict")
	}
}

func TestRule_NilWhenMatchesEverything(t *testing.T) {
	p := one("catch-all", Deny, 0, nil)
	v, ok, _ := p.Resolve(req(map[string]string{"anything": "goes"}))
	if !ok || v.Effect != Deny {
		t.Fatal("a rule with no condition tree must match every request")
	}
}

func TestSimplePolicy_IsAConjunction(t *testing.T) {
	p := SimplePolicy("p", "t1", "", Allow, 5, []Condition{
		{Attribute: "role", Operator: OpEquals, Values: []string{"admin"}},
		{Attribute: "dept", Operator: OpEquals, Values: []string{"eng"}},
	})
	if _, ok, _ := p.Resolve(req(map[string]string{"role": "admin"})); ok {
		t.Error("a partially satisfied conjunction must not match")
	}
	if _, ok, _ := p.Resolve(req(map[string]string{"role": "admin", "dept": "eng"})); !ok {
		t.Error("a fully satisfied conjunction must match")
	}
}

// --- Combining algorithms, outer tier ---------------------------------------

func policySet() []Policy {
	role := AllOf(Condition{Attribute: "role", Operator: OpEquals, Values: []string{"admin"}})
	return []Policy{
		one("allow-low", Allow, 1, role),
		one("deny-mid", Deny, 5, role),
		one("allow-high", Allow, 9, role),
	}
}

func TestDenyOverrides(t *testing.T) {
	d := Evaluate(policySet(), req(map[string]string{"role": "admin"}), DenyOverrides)
	if d.Allowed || d.MatchedPolicyID != "deny-mid" {
		t.Fatalf("deny must win regardless of position or priority, got %s", d)
	}
	if d.MatchedRuleID != "deny-mid/r0" {
		t.Fatalf("the decision must name the rule that fired, got %q", d.MatchedRuleID)
	}
}

func TestPermitOverrides(t *testing.T) {
	d := Evaluate(policySet(), req(map[string]string{"role": "admin"}), PermitOverrides)
	if !d.Allowed {
		t.Fatalf("permit must win under permit-overrides, got %s", d)
	}
}

func TestFirstApplicable_HighestPriorityWins(t *testing.T) {
	d := Evaluate(policySet(), req(map[string]string{"role": "admin"}), FirstApplicable)
	if !d.Allowed || d.MatchedPolicyID != "allow-high" {
		t.Fatalf("highest priority must win, got %s", d)
	}
}

// TestFirstApplicable_OuterTierUsesPolicyPriority pins which priority orders the
// cross-policy tier. The winning rule inside a policy carries its own priority
// for the inner comparison, and inheriting that outward would let a high-priority
// rule in a low-priority policy outrank an entire policy that should have won.
func TestFirstApplicable_OuterTierUsesPolicyPriority(t *testing.T) {
	always := AllOf(Condition{Attribute: "role", Operator: OpEquals, Values: []string{"admin"}})
	ps := []Policy{
		{
			ID: "low-policy-high-rule", Priority: 1,
			Rules: []Rule{{ID: "r", Effect: Allow, Priority: 9999, When: always}},
		},
		{
			ID: "high-policy-low-rule", Priority: 100,
			Rules: []Rule{{ID: "r", Effect: Deny, Priority: 0, When: always}},
		},
	}
	d := Evaluate(ps, req(map[string]string{"role": "admin"}), FirstApplicable)
	if d.MatchedPolicyID != "high-policy-low-rule" {
		t.Fatalf("the outer tier must order by policy priority, got %s", d.MatchedPolicyID)
	}
}

func TestFirstApplicable_TiesBreakDeterministically(t *testing.T) {
	// Equal priority must resolve the same way every time regardless of the order
	// candidates arrive in, since the index yields them arbitrarily.
	ps := []Policy{
		one("bbb", Allow, 5, nil),
		one("aaa", Deny, 5, nil),
	}
	forward := Evaluate(ps, req(nil), FirstApplicable)
	reversed := Evaluate([]Policy{ps[1], ps[0]}, req(nil), FirstApplicable)
	if forward.MatchedPolicyID != reversed.MatchedPolicyID {
		t.Fatalf("tie-break is order dependent: %s vs %s",
			forward.MatchedPolicyID, reversed.MatchedPolicyID)
	}
	if forward.MatchedPolicyID != "aaa" {
		t.Fatalf("expected lexicographically smallest ID to win, got %s", forward.MatchedPolicyID)
	}
}

func TestDenyOverrides_IsOrderIndependent(t *testing.T) {
	// The property that makes indexing sound: the index returns candidates in
	// arbitrary order, so the result must not depend on that order.
	ps := policySet()
	a := Evaluate(ps, req(map[string]string{"role": "admin"}), DenyOverrides)
	b := Evaluate([]Policy{ps[2], ps[0], ps[1]}, req(map[string]string{"role": "admin"}), DenyOverrides)
	if a.Allowed != b.Allowed || a.Effect != b.Effect {
		t.Fatalf("deny-overrides must be order independent: %s vs %s", a, b)
	}
}

// TestTwoTier_InnerAlgorithmCanFlipTheOuterResult demonstrates that the tiers are
// genuinely independent rather than one flattened scan. The same rules under a
// different rule algorithm inside the policy produce a different final decision.
func TestTwoTier_InnerAlgorithmCanFlipTheOuterResult(t *testing.T) {
	rules := []Rule{
		{ID: "allow", Effect: Allow, Priority: 100, When: nil},
		{ID: "deny", Effect: Deny, Priority: 1, When: nil},
	}
	denyFirst := []Policy{{ID: "p", RuleAlgorithm: DenyOverrides, Rules: rules}}
	byPriority := []Policy{{ID: "p", RuleAlgorithm: FirstApplicable, Rules: rules}}

	if d := Evaluate(denyFirst, req(nil), DenyOverrides); d.Allowed {
		t.Errorf("deny-overrides inside the policy must deny, got %s", d)
	}
	if d := Evaluate(byPriority, req(nil), DenyOverrides); !d.Allowed {
		t.Errorf("first-applicable inside the policy must let the higher-priority allow win, got %s", d)
	}
}

func TestDefaultDeny(t *testing.T) {
	d := Evaluate(policySet(), req(map[string]string{"role": "nobody"}), DenyOverrides)
	if d.Allowed {
		t.Fatalf("no match must default to deny, got %s", d)
	}
	if d.MatchedPolicyID != "" || d.MatchedRuleID != "" {
		t.Fatalf("default deny credits nothing, got policy %q rule %q",
			d.MatchedPolicyID, d.MatchedRuleID)
	}
}

func TestEmptyPolicySet_DefaultDeny(t *testing.T) {
	d := Evaluate(nil, req(map[string]string{"role": "admin"}), DenyOverrides)
	if d.Allowed || d.PoliciesScanned != 0 || d.RulesScanned != 0 {
		t.Fatalf("empty corpus must deny and scan nothing, got %s", d)
	}
}

func TestObligationsPropagate(t *testing.T) {
	ps := []Policy{one("p", Allow, 0, nil, "require_mfa", "audit_log")}
	d := Evaluate(ps, req(nil), DenyOverrides)
	if len(d.Obligations) != 2 || d.Obligations[0] != "require_mfa" {
		t.Fatalf("obligations must reach the decision, got %v", d.Obligations)
	}
}

// TestObligationsComeFromTheWinningRule checks that obligations follow the rule
// that fired, not the policy or some other rule in it. Attaching the wrong
// obligations is a security-relevant error: it can drop a require_mfa.
func TestObligationsComeFromTheWinningRule(t *testing.T) {
	ps := []Policy{{
		ID: "p",
		Rules: []Rule{
			{ID: "allow", Effect: Allow, When: nil, Obligations: []string{"audit_log"}},
			{ID: "deny", Effect: Deny, When: nil, Obligations: []string{"notify_soc"}},
		},
	}}
	d := Evaluate(ps, req(nil), DenyOverrides)
	if len(d.Obligations) != 1 || d.Obligations[0] != "notify_soc" {
		t.Fatalf("obligations must come from the deny rule that won, got %v", d.Obligations)
	}
}

func TestEvaluatePolicyPositions_MatchesFullScan(t *testing.T) {
	ps := policySet()
	r := req(map[string]string{"role": "admin"})
	full := Evaluate(ps, r, DenyOverrides)
	part := EvaluatePolicyPositions(ps, []int{0, 1, 2}, r, DenyOverrides)
	if full.Allowed != part.Allowed || full.MatchedPolicyID != part.MatchedPolicyID {
		t.Fatalf("index path disagrees with full scan: %s vs %s", full, part)
	}
}

func TestShortCircuit_OnlyForDenyOverrides(t *testing.T) {
	acc := NewAccumulator(DenyOverrides)
	acc.Consider(Verdict{PolicyID: "p", RuleID: "d", Effect: Deny})
	if !acc.CanShortCircuit() {
		t.Error("deny-overrides should short circuit once a deny is seen")
	}

	for _, alg := range AllAlgorithms {
		if alg == DenyOverrides {
			continue
		}
		a := NewAccumulator(alg)
		a.Consider(Verdict{PolicyID: "p", RuleID: "d", Effect: Deny})
		if a.CanShortCircuit() {
			t.Errorf("%s must examine every candidate before resolving", alg)
		}
	}
}

func TestAccumulator_ResetIsReusable(t *testing.T) {
	// The inner tier keeps one accumulator on the stack per policy and resets it
	// rather than allocating, so a stale field would leak one policy's verdict
	// into the next.
	var a Accumulator
	a.Reset(DenyOverrides)
	a.Consider(Verdict{PolicyID: "p1", RuleID: "r", Effect: Deny})
	if v, ok := a.Winner(); !ok || v.PolicyID != "p1" {
		t.Fatalf("expected p1, got %+v", v)
	}

	a.Reset(DenyOverrides)
	if _, ok := a.Winner(); ok {
		t.Fatal("Reset must clear the previous verdict")
	}
	a.Consider(Verdict{PolicyID: "p2", RuleID: "r", Effect: Allow})
	if v, _ := a.Winner(); v.PolicyID != "p2" {
		t.Fatalf("expected p2 after reset, got %+v", v)
	}
}

func TestRequest_InScope(t *testing.T) {
	r := Request{TenantID: "t1", Scope: "billing"}
	cases := []struct {
		p    Policy
		want bool
	}{
		{Policy{TenantID: GlobalTenant}, true},
		{Policy{TenantID: ""}, true},
		{Policy{TenantID: "t1", Scope: ""}, true},
		{Policy{TenantID: "t1", Scope: "billing"}, true},
		{Policy{TenantID: "t1", Scope: "identity"}, false},
		{Policy{TenantID: "t2", Scope: "billing"}, false},
	}
	for i, tc := range cases {
		if got := r.InScope(&tc.p); got != tc.want {
			t.Errorf("case %d (%s/%s): got %v want %v",
				i, tc.p.TenantID, tc.p.Scope, got, tc.want)
		}
	}
}
