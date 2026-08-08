package model

import "testing"

// always matches every request, so these tests exercise the combining algorithms
// rather than the condition evaluator.
func always(id string, effect Effect, priority int, obligations ...string) Policy {
	return Policy{
		ID: id, Priority: priority,
		Rules: []Rule{{
			ID: id + "/r0", Effect: effect, Priority: priority,
			Obligations: obligations,
		}},
	}
}

func TestDenyUnlessPermit(t *testing.T) {
	allowAndDeny := []Policy{always("a", Allow, 1), always("d", Deny, 2)}
	denyOnly := []Policy{always("d", Deny, 1)}
	none := []Policy{}

	if d := Evaluate(allowAndDeny, req(nil), DenyUnlessPermit); !d.Allowed {
		t.Errorf("any permit should win, got %s", d)
	}
	// Deny with no permit: denies, and credits nothing. XACML defines this
	// algorithm as resolving only to Permit or Deny, never to an attributed
	// Indeterminate.
	d := Evaluate(denyOnly, req(nil), DenyUnlessPermit)
	if d.Allowed {
		t.Errorf("no permit means deny, got %s", d)
	}
	if d.MatchedPolicyID != "" {
		t.Errorf("deny-unless-permit credits nothing on a deny, got %q", d.MatchedPolicyID)
	}
	if d := Evaluate(none, req(nil), DenyUnlessPermit); d.Allowed {
		t.Errorf("an empty set must deny, got %s", d)
	}
}

// TestDenyUnlessPermit_MatchesPermitOverridesOnOutcome documents the honest
// relationship between the two: absent an Indeterminate state they differ only in
// attribution, and the enforceable answer is identical.
func TestDenyUnlessPermit_MatchesPermitOverridesOnOutcome(t *testing.T) {
	corpora := [][]Policy{
		{always("a", Allow, 1)},
		{always("d", Deny, 1)},
		{always("a", Allow, 1), always("d", Deny, 2)},
		{},
	}
	for i, ps := range corpora {
		a := Evaluate(ps, req(nil), PermitOverrides)
		b := Evaluate(ps, req(nil), DenyUnlessPermit)
		if a.Allowed != b.Allowed || a.Effect != b.Effect {
			t.Errorf("corpus %d: permit-overrides %s vs deny-unless-permit %s", i, a, b)
		}
	}
}

// TestPermitUnlessDeny_GrantsByDefault is the one algorithm here that inverts the
// fail-closed posture, so the behaviour is pinned explicitly rather than left to
// be discovered.
func TestPermitUnlessDeny_GrantsByDefault(t *testing.T) {
	d := Evaluate(nil, req(nil), PermitUnlessDeny)
	if !d.Allowed || d.Effect != Allow {
		t.Fatalf("permit-unless-deny must allow an unmatched request, got %s", d)
	}
	if d.MatchedPolicyID != "" {
		t.Errorf("nothing matched, so nothing should be credited: %q", d.MatchedPolicyID)
	}

	// A matching deny still wins.
	if d := Evaluate([]Policy{always("d", Deny, 1)}, req(nil), PermitUnlessDeny); d.Allowed {
		t.Errorf("a matching deny must win, got %s", d)
	}
	// An allow alone is redundant but harmless.
	if d := Evaluate([]Policy{always("a", Allow, 1)}, req(nil), PermitUnlessDeny); !d.Allowed {
		t.Errorf("expected allow, got %s", d)
	}
}

// TestOnlyOneApplicable is the genuinely distinct addition: it detects ambiguity
// rather than arbitrating it, so overlapping policies fail closed instead of
// being silently resolved.
func TestOnlyOneApplicable(t *testing.T) {
	one := []Policy{always("only", Allow, 1)}
	d := Evaluate(one, req(nil), OnlyOneApplicable)
	if !d.Allowed || d.MatchedPolicyID != "only" {
		t.Fatalf("exactly one applicable should be credited, got %s", d)
	}

	two := []Policy{always("a", Allow, 1), always("b", Allow, 2)}
	if d := Evaluate(two, req(nil), OnlyOneApplicable); d.Allowed {
		t.Errorf("two applicable policies is Indeterminate and must deny, got %s", d)
	}

	// Even two that agree. The point is that the overlap itself is the error.
	twoDenies := []Policy{always("a", Deny, 1), always("b", Deny, 2)}
	if d := Evaluate(twoDenies, req(nil), OnlyOneApplicable); d.MatchedPolicyID != "" {
		t.Errorf("ambiguity must credit nothing, got %q", d.MatchedPolicyID)
	}

	if d := Evaluate(nil, req(nil), OnlyOneApplicable); d.Allowed {
		t.Errorf("nothing applicable must deny, got %s", d)
	}
}

func TestAllAlgorithms_AreRecognized(t *testing.T) {
	// The linter validates against this list, so an algorithm implemented but
	// unlisted would be rejected at load time.
	if len(AllAlgorithms) != 6 {
		t.Fatalf("expected 6 algorithms, got %d", len(AllAlgorithms))
	}
	for _, alg := range AllAlgorithms {
		// Every listed algorithm must produce a decision without panicking.
		_ = Evaluate([]Policy{always("p", Allow, 1)}, req(nil), alg)
	}
}

// --- Obligation union -------------------------------------------------------

// TestUnionObligations_CollectsFromEveryMatchingRule removes the caveat that
// obligations otherwise depend on which of several equally-valid matches the
// evaluator happened to reach first. Dropping a require_mfa that way is a
// security incident, not a cosmetic difference.
func TestUnionObligations_CollectsFromEveryMatchingRule(t *testing.T) {
	ps := []Policy{
		always("a", Allow, 1, "audit_log"),
		always("b", Allow, 2, "require_mfa"),
		always("c", Allow, 3, "audit_log", "notify_soc"),
	}

	// Without union, only the credited rule's obligations survive.
	plain := Evaluate(ps, req(nil), DenyOverrides)
	if len(plain.Obligations) != 1 {
		t.Fatalf("without union, expected one rule's obligations, got %v", plain.Obligations)
	}

	union := EvaluateUnion(ps, req(nil), DenyOverrides, true)
	if !union.Allowed {
		t.Fatalf("expected allow, got %s", union)
	}
	want := map[string]bool{"audit_log": true, "require_mfa": true, "notify_soc": true}
	if len(union.Obligations) != len(want) {
		t.Fatalf("expected %d obligations, got %v", len(want), union.Obligations)
	}
	for _, o := range union.Obligations {
		if !want[o] {
			t.Errorf("unexpected obligation %q", o)
		}
	}
}

// TestUnionObligations_OnlyTheWinningEffect checks that a deny's obligations do
// not leak into an allow decision, and vice versa.
func TestUnionObligations_OnlyTheWinningEffect(t *testing.T) {
	ps := []Policy{
		always("allow", Allow, 1, "audit_log"),
		always("deny", Deny, 2, "notify_soc"),
	}
	// Deny-overrides: the deny wins, so only its obligations apply.
	d := EvaluateUnion(ps, req(nil), DenyOverrides, true)
	if d.Allowed {
		t.Fatalf("expected deny, got %s", d)
	}
	if len(d.Obligations) != 1 || d.Obligations[0] != "notify_soc" {
		t.Fatalf("only the winning effect's obligations apply, got %v", d.Obligations)
	}
}

// TestUnionObligations_DisablesShortCircuit is the cost, pinned so it cannot be
// silently reintroduced: stopping at the first deny would miss obligations on
// candidates never seen.
func TestUnionObligations_DisablesShortCircuit(t *testing.T) {
	a := NewAccumulator(DenyOverrides)
	a.Consider(Verdict{PolicyID: "p", RuleID: "r", Effect: Deny})
	if !a.CanShortCircuit() {
		t.Fatal("sanity: deny-overrides short-circuits by default")
	}

	u := NewAccumulator(DenyOverrides)
	u.UnionObligations = true
	u.Consider(Verdict{PolicyID: "p", RuleID: "r", Effect: Deny})
	if u.CanShortCircuit() {
		t.Error("union mode must not short-circuit, or it would miss obligations")
	}
}

func TestUnionObligations_Deduplicates(t *testing.T) {
	ps := []Policy{
		always("a", Allow, 1, "audit_log"),
		always("b", Allow, 2, "audit_log"),
	}
	d := EvaluateUnion(ps, req(nil), DenyOverrides, true)
	if len(d.Obligations) != 1 {
		t.Fatalf("duplicate obligations should collapse, got %v", d.Obligations)
	}
}

// TestUnionObligations_AppliesWithinAPolicyToo checks the inner tier, since
// Reset must preserve the flag for it to reach a policy's own rules.
func TestUnionObligations_AppliesWithinAPolicyToo(t *testing.T) {
	ps := []Policy{{
		ID: "p",
		Rules: []Rule{
			{ID: "r1", Effect: Allow, Obligations: []string{"audit_log"}},
			{ID: "r2", Effect: Allow, Obligations: []string{"require_mfa"}},
		},
	}}
	d := EvaluateUnion(ps, req(nil), DenyOverrides, true)
	if len(d.Obligations) != 2 {
		t.Fatalf("two rules in one policy should both contribute, got %v", d.Obligations)
	}
}

func TestAccumulator_ResetPreservesUnionFlag(t *testing.T) {
	var a Accumulator
	a.UnionObligations = true
	a.Reset(DenyOverrides)
	if !a.UnionObligations {
		t.Fatal("Reset must preserve UnionObligations, or the inner tier diverges")
	}
}
