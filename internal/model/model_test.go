package model

import (
	"net/netip"
	"testing"
)

func req(attrs map[string]string) Request {
	return Request{TenantID: "t1", Attributes: attrs}
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

func TestCondition_AbsentAttributeFailsClosed(t *testing.T) {
	// Every operator except NotExists must reject an absent attribute,
	// including the negations. "role != admin" must not silently pass for a
	// request that carries no role at all.
	empty := Request{TenantID: "t1", Attributes: map[string]string{}}
	for _, op := range []Operator{
		OpEquals, OpNotEquals, OpIn, OpNotIn, OpExists,
		OpRange, OpGreaterThan, OpLessThan, OpCIDR, OpNotCIDR,
		OpDNSSuffix, OpPrefix,
	} {
		c := Condition{Attribute: "missing", Operator: op, Values: []string{"x"}, Min: 0, Max: 100}
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
		{Condition{Attribute: "score", Operator: OpGreaterThan, Min: 49}, true},
		{Condition{Attribute: "score", Operator: OpGreaterThan, Min: 50}, false},
		{Condition{Attribute: "score", Operator: OpLessThan, Max: 51}, true},
		{Condition{Attribute: "score", Operator: OpLessThan, Max: 50}, false},
	}
	for i, tc := range cases {
		if got := tc.cond.Matches(r); got != tc.want {
			t.Errorf("case %d (%s): got %v want %v", i, tc.cond.Operator, got, tc.want)
		}
	}
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

func TestCondition_Prefix(t *testing.T) {
	r := req(map[string]string{"path": "/api/v2/admin/users"})
	yes := Condition{Attribute: "path", Operator: OpPrefix, Values: []string{"/api/v2"}}
	if !yes.Matches(r) {
		t.Error("expected prefix match")
	}
	no := Condition{Attribute: "path", Operator: OpPrefix, Values: []string{"/internal"}}
	if no.Matches(r) {
		t.Error("unexpected prefix match")
	}
}

// --- Policy -----------------------------------------------------------------

func TestPolicy_ConditionsAreAnded(t *testing.T) {
	p := Policy{ID: "p", Effect: Allow, Conditions: []Condition{
		{Attribute: "role", Operator: OpEquals, Values: []string{"admin"}},
		{Attribute: "dept", Operator: OpEquals, Values: []string{"eng"}},
	}}
	if p.Matches(req(map[string]string{"role": "admin"})) {
		t.Error("a partially satisfied policy must not match")
	}
	if !p.Matches(req(map[string]string{"role": "admin", "dept": "eng"})) {
		t.Error("a fully satisfied policy must match")
	}
}

func TestPolicy_ConditionlessMatchesEverything(t *testing.T) {
	p := Policy{ID: "catch-all", Effect: Deny}
	if !p.Matches(req(map[string]string{"anything": "goes"})) {
		t.Error("a conditionless policy must match every request")
	}
}

// --- Combining algorithms ---------------------------------------------------

func policySet() []Policy {
	return []Policy{
		{ID: "allow-low", Effect: Allow, Priority: 1, Conditions: []Condition{
			{Attribute: "role", Operator: OpEquals, Values: []string{"admin"}}}},
		{ID: "deny-mid", Effect: Deny, Priority: 5, Conditions: []Condition{
			{Attribute: "role", Operator: OpEquals, Values: []string{"admin"}}}},
		{ID: "allow-high", Effect: Allow, Priority: 9, Conditions: []Condition{
			{Attribute: "role", Operator: OpEquals, Values: []string{"admin"}}}},
	}
}

func TestDenyOverrides(t *testing.T) {
	d := Evaluate(policySet(), req(map[string]string{"role": "admin"}), DenyOverrides)
	if d.Allowed || d.MatchedPolicyID != "deny-mid" {
		t.Fatalf("deny must win regardless of position or priority, got %s", d)
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

func TestFirstApplicable_TiesBreakDeterministically(t *testing.T) {
	// Equal priority must resolve the same way every time regardless of the
	// order candidates arrive in, since the index yields them arbitrarily.
	ps := []Policy{
		{ID: "bbb", Effect: Allow, Priority: 5},
		{ID: "aaa", Effect: Deny, Priority: 5},
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

func TestDefaultDeny(t *testing.T) {
	d := Evaluate(policySet(), req(map[string]string{"role": "nobody"}), DenyOverrides)
	if d.Allowed {
		t.Fatalf("no match must default to deny, got %s", d)
	}
	if d.MatchedPolicyID != "" {
		t.Fatalf("default deny has no matched policy, got %q", d.MatchedPolicyID)
	}
}

func TestEmptyPolicySet_DefaultDeny(t *testing.T) {
	d := Evaluate(nil, req(map[string]string{"role": "admin"}), DenyOverrides)
	if d.Allowed || d.PoliciesScanned != 0 {
		t.Fatalf("empty corpus must deny and scan nothing, got %s", d)
	}
}

func TestObligationsPropagate(t *testing.T) {
	ps := []Policy{{ID: "p", Effect: Allow, Obligations: []string{"require_mfa", "audit_log"}}}
	d := Evaluate(ps, req(nil), DenyOverrides)
	if len(d.Obligations) != 2 || d.Obligations[0] != "require_mfa" {
		t.Fatalf("obligations must reach the decision, got %v", d.Obligations)
	}
}

func TestEvaluateIndices_MatchesFullScan(t *testing.T) {
	ps := policySet()
	r := req(map[string]string{"role": "admin"})
	full := Evaluate(ps, r, DenyOverrides)
	// Feeding every position is equivalent to a full scan.
	part := EvaluateIndices(ps, []int{0, 1, 2}, r, DenyOverrides)
	if full.Allowed != part.Allowed || full.MatchedPolicyID != part.MatchedPolicyID {
		t.Fatalf("index path disagrees with full scan: %s vs %s", full, part)
	}
}

func TestShortCircuit_OnlyForDenyOverrides(t *testing.T) {
	acc := NewAccumulator(DenyOverrides)
	acc.Consider(&Policy{ID: "d", Effect: Deny})
	if !acc.CanShortCircuit() {
		t.Error("deny-overrides should short circuit once a deny is seen")
	}

	for _, alg := range []Algorithm{PermitOverrides, FirstApplicable} {
		a := NewAccumulator(alg)
		a.Consider(&Policy{ID: "d", Effect: Deny})
		if a.CanShortCircuit() {
			t.Errorf("%s must examine every candidate before resolving", alg)
		}
	}
}
