package explain

import (
	"encoding/json"
	"math/rand"
	"net/netip"
	"strings"
	"testing"

	"github.com/suga/tessaraop/internal/genutil"
	"github.com/suga/tessaraop/internal/model"
)

func cond(attr string, op model.Operator, values ...string) model.Condition {
	return model.Condition{Attribute: attr, Operator: op, Values: values}
}

// --- The property that matters most -----------------------------------------

// TestExplain_AgreesWithEvaluate is the backbone. An explanation that
// contradicts the decision it explains is worse than no explanation at all,
// because it will be believed and acted on.
//
// Explain deliberately walks a different path from the engine — no index, no
// short-circuiting, every rule evaluated — so agreement is a real property to
// check rather than a tautology.
func TestExplain_AgreesWithEvaluate(t *testing.T) {
	for _, alg := range model.AllAlgorithms {
		t.Run(string(alg), func(t *testing.T) {
			for seed := int64(0); seed < 25; seed++ {
				rng := rand.New(rand.NewSource(seed))
				corpus := genutil.Generate(genutil.Options{
					Policies: 150, Tenants: 4, Global: 8, RulesPerPolicy: 4,
				}, rng)

				for q := 0; q < 20; q++ {
					req := corpus.GenerateRequest(rng)

					// model.Evaluate applies no scoping, so scope here too.
					inScope := inScopePolicies(corpus.Policies, req)
					want := model.Evaluate(inScope, req, alg)
					got := Explain(corpus.Policies, req, alg, DefaultOptions())

					if got.Decision.Allowed != want.Allowed ||
						got.Decision.Effect != want.Effect {
						t.Fatalf("seed=%d q=%d alg=%s\n evaluate: %s\n explain:  %s",
							seed, q, alg, want, got.Decision)
					}
				}
			}
		})
	}
}

func inScopePolicies(policies []model.Policy, req model.Request) []model.Policy {
	var out []model.Policy
	for i := range policies {
		if req.InScope(&policies[i]) {
			out = append(out, policies[i])
		}
	}
	return out
}

// --- Tracing must not short-circuit -----------------------------------------

// TestExplain_ReportsEveryFailingCondition is the reason tracing evaluates every
// node. And stops at the first false child during evaluation, which is right for
// speed and wrong for explanation: an author wants every condition that failed,
// not whichever happened to be checked first.
func TestExplain_ReportsEveryFailingCondition(t *testing.T) {
	policies := []model.Policy{{
		ID: "p", TenantID: "t",
		Rules: []model.Rule{{
			ID: "r", Effect: model.Allow,
			When: model.AllOf(
				cond("role", model.OpEquals, "admin"),
				cond("dept", model.OpEquals, "eng"),
				cond("region", model.OpEquals, "eu"),
			),
		}},
	}}
	req := model.Request{TenantID: "t", Attributes: map[string]string{
		"role": "viewer", "dept": "sales", "region": "us",
	}}

	ex := Explain(policies, req, model.DenyOverrides, DefaultOptions())

	var failed []string
	walkLeaves(ex.Policies[0].Rules[0].Condition, func(l *LeafTrace) {
		if !l.Matched {
			failed = append(failed, l.Attribute)
		}
	})
	if len(failed) != 3 {
		t.Fatalf("expected all three conditions reported as failing, got %v", failed)
	}
}

// TestExplain_EvaluatesRulesAfterAShortCircuit covers the inner tier. Under
// deny-overrides evaluation stops at the first deny; a rule that would have been
// skipped is exactly the one an author may be asking about.
func TestExplain_EvaluatesRulesAfterAShortCircuit(t *testing.T) {
	policies := []model.Policy{{
		ID: "p", TenantID: "t",
		Rules: []model.Rule{
			{ID: "deny-first", Effect: model.Deny, When: nil},
			{ID: "would-be-skipped", Effect: model.Allow, When: model.AllOf(
				cond("role", model.OpEquals, "admin"))},
		},
	}}
	req := model.Request{TenantID: "t", Attributes: map[string]string{"role": "admin"}}

	ex := Explain(policies, req, model.DenyOverrides, DefaultOptions())
	if len(ex.Policies[0].Rules) != 2 {
		t.Fatalf("both rules must appear in the trace, got %d", len(ex.Policies[0].Rules))
	}
	if !ex.Policies[0].Rules[1].Matched {
		t.Error("the rule after the short-circuit must still be evaluated and reported")
	}
	// And the decision is still the deny.
	if ex.Decision.Allowed {
		t.Errorf("expected deny, got %s", ex.Decision)
	}
}

// --- The absent-attribute case ----------------------------------------------

// TestExplain_NamesTheAbsentAttribute covers what is, in practice, the most
// common cause of a surprising denial. The engine fails closed, so a missing
// attribute defeats every operator except nexists — including the negations,
// which is the part that surprises people.
func TestExplain_NamesTheAbsentAttribute(t *testing.T) {
	policies := []model.Policy{{
		ID: "p", TenantID: "t",
		Rules: []model.Rule{{
			ID: "r", Effect: model.Allow,
			When: model.AllOf(cond("subject.role", model.OpNotEquals, "banned")),
		}},
	}}
	// The request carries no role at all. A reader might expect "role != banned"
	// to pass vacuously; it does not.
	req := model.Request{TenantID: "t", Attributes: map[string]string{"other": "x"}}

	ex := Explain(policies, req, model.DenyOverrides, DefaultOptions())
	if ex.Decision.Allowed {
		t.Fatalf("expected deny, got %s", ex.Decision)
	}

	why := ex.Policies[0].Rules[0].Why
	if !strings.Contains(why, "absent") && !strings.Contains(why, "no \"subject.role\"") {
		t.Errorf("the explanation should point at the absent attribute, got %q", why)
	}
	if !strings.Contains(why, "including negated ones") {
		t.Errorf("the explanation should warn that negations do not pass either, got %q", why)
	}

	leaf := ex.Policies[0].Rules[0].Condition.Sub[0].Leaf
	if leaf.Present {
		t.Error("the leaf should report the attribute as absent")
	}
}

func TestUnmatchedAttributes_AggregatesTheRealCause(t *testing.T) {
	// The onboarding view: a policy set that denies everything usually does so
	// because one attribute is never supplied.
	policies := []model.Policy{{
		ID: "p", TenantID: "t",
		Rules: []model.Rule{
			{ID: "r1", Effect: model.Allow, When: model.AllOf(
				cond("token.valid", model.OpEquals, "true"))},
			{ID: "r2", Effect: model.Allow, When: model.AllOf(
				cond("token.valid", model.OpEquals, "true"),
				cond("role", model.OpEquals, "admin"))},
		},
	}}
	req := model.Request{TenantID: "t", Attributes: map[string]string{"role": "admin"}}

	ex := Explain(policies, req, model.DenyOverrides, DefaultOptions())
	counts := ex.UnmatchedAttributes()
	if len(counts) == 0 {
		t.Fatal("expected the failing attribute to be reported")
	}
	if counts[0].Attribute != "token.valid" {
		t.Fatalf("expected token.valid to lead, got %+v", counts)
	}
	if counts[0].Failures != 2 || counts[0].Absent != 2 {
		t.Errorf("expected 2 failures, both from absence, got %+v", counts[0])
	}
}

// --- Redaction ---------------------------------------------------------------

// TestExplain_RedactsByDefault keeps a trace from undoing the work package
// ingest does to keep credentials out of attributes. An explanation usually goes
// somewhere less trusted than the evaluator.
func TestExplain_RedactsByDefault(t *testing.T) {
	policies := []model.Policy{{
		ID: "p", TenantID: "t",
		Rules: []model.Rule{{ID: "r", Effect: model.Allow,
			When: model.AllOf(cond("session.id", model.OpEquals, "expected"))}},
	}}
	req := model.Request{TenantID: "t",
		Attributes: map[string]string{"session.id": "super-secret-session"}}

	ex := Explain(policies, req, model.DenyOverrides, DefaultOptions())
	blob, err := json.Marshal(ex)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(blob), "super-secret-session") {
		t.Fatal("a redacted trace must not contain the observed value")
	}

	// The policy's own expectation is not redacted — the reader is entitled to
	// see what the policy asked for.
	if !strings.Contains(string(blob), "expected") {
		t.Error("the expected value comes from the policy and should be shown")
	}
}

func TestExplain_RedactExceptShowsNamedAttributes(t *testing.T) {
	policies := []model.Policy{{
		ID: "p", TenantID: "t",
		Rules: []model.Rule{{ID: "r", Effect: model.Allow,
			When: model.AllOf(
				cond("subject.role", model.OpEquals, "admin"),
				cond("session.id", model.OpEquals, "x"))}},
	}}
	req := model.Request{TenantID: "t", Attributes: map[string]string{
		"subject.role": "viewer", "session.id": "secret-value"}}

	opt := DefaultOptions()
	opt.RedactExcept = map[string]bool{"subject.role": true}
	ex := Explain(policies, req, model.DenyOverrides, opt)

	var role, session *LeafTrace
	walkLeaves(ex.Policies[0].Rules[0].Condition, func(l *LeafTrace) {
		switch l.Attribute {
		case "subject.role":
			role = l
		case "session.id":
			session = l
		}
	})
	if role == nil || role.Actual != "viewer" {
		t.Errorf("an allowlisted attribute should show its value, got %+v", role)
	}
	if session == nil || session.Actual != Redacted {
		t.Errorf("a non-allowlisted attribute should be redacted, got %+v", session)
	}
}

func TestExplain_NoRedactionShowsValues(t *testing.T) {
	policies := []model.Policy{{
		ID: "p", TenantID: "t",
		Rules: []model.Rule{{ID: "r", Effect: model.Allow,
			When: model.AllOf(cond("role", model.OpEquals, "admin"))}},
	}}
	req := model.Request{TenantID: "t", Attributes: map[string]string{"role": "viewer"}}

	opt := DefaultOptions()
	opt.Redact = false
	ex := Explain(policies, req, model.DenyOverrides, opt)
	if got := ex.Policies[0].Rules[0].Condition.Sub[0].Leaf.Actual; got != "viewer" {
		t.Fatalf("expected the value, got %q", got)
	}
}

// --- Scoping -----------------------------------------------------------------

func TestExplain_ReportsOutOfScopeWithAReason(t *testing.T) {
	policies := []model.Policy{
		{ID: "other-tenant", TenantID: "other",
			Rules: []model.Rule{{ID: "r", Effect: model.Allow}}},
		{ID: "other-scope", TenantID: "t", Scope: "billing",
			Rules: []model.Rule{{ID: "r", Effect: model.Allow}}},
	}
	req := model.Request{TenantID: "t", Scope: "identity"}

	opt := DefaultOptions()
	opt.IncludeOutOfScope = true
	ex := Explain(policies, req, model.DenyOverrides, opt)

	if ex.PoliciesInScope != 0 {
		t.Fatalf("neither policy is in scope, got %d", ex.PoliciesInScope)
	}
	if len(ex.Policies) != 2 {
		t.Fatalf("expected both reported as out of scope, got %d", len(ex.Policies))
	}
	for _, p := range ex.Policies {
		if p.InScope || p.OutOfScopeReason == "" {
			t.Errorf("%s: expected an out-of-scope reason, got %+v", p.PolicyID, p)
		}
	}
	if !strings.Contains(ex.Policies[0].OutOfScopeReason, "tenant") {
		t.Errorf("tenant mismatch should say so: %q", ex.Policies[0].OutOfScopeReason)
	}
	if !strings.Contains(ex.Policies[1].OutOfScopeReason, "scope") {
		t.Errorf("scope mismatch should say so: %q", ex.Policies[1].OutOfScopeReason)
	}
}

func TestExplain_OmitsOutOfScopeByDefault(t *testing.T) {
	policies := []model.Policy{{ID: "other", TenantID: "other",
		Rules: []model.Rule{{ID: "r", Effect: model.Allow}}}}
	ex := Explain(policies, model.Request{TenantID: "t"}, model.DenyOverrides, DefaultOptions())
	if len(ex.Policies) != 0 {
		t.Fatalf("out-of-scope policies are omitted by default, got %d", len(ex.Policies))
	}
	if !strings.Contains(ex.Summary, "no policy is in scope") {
		t.Errorf("the summary should say why: %q", ex.Summary)
	}
}

// --- Indexability reporting --------------------------------------------------

// TestExplain_ReportsIndexability surfaces a performance property to the policy
// author: conditions under an Or or a Not cannot contribute an index filter, and
// a rule written entirely that way is validated on every request reaching its
// shard.
func TestExplain_ReportsIndexability(t *testing.T) {
	policies := []model.Policy{{
		ID: "p", TenantID: "t",
		Rules: []model.Rule{{ID: "r", Effect: model.Allow,
			When: model.And(
				model.Cond(cond("onspine", model.OpEquals, "x")),
				model.Or(model.Cond(cond("inor", model.OpEquals, "x"))),
				model.Not(model.Cond(cond("innot", model.OpEquals, "x"))),
				model.Cond(cond("unindexable", model.OpContains, "x")),
			)}},
	}}
	req := model.Request{TenantID: "t", Attributes: map[string]string{
		"onspine": "x", "inor": "x", "innot": "y", "unindexable": "x"}}

	ex := Explain(policies, req, model.DenyOverrides, DefaultOptions())

	got := map[string]bool{}
	walkLeaves(ex.Policies[0].Rules[0].Condition, func(l *LeafTrace) {
		got[l.Attribute] = l.Indexable
	})
	if !got["onspine"] {
		t.Error("a conjunctive leaf is indexable")
	}
	if got["inor"] {
		t.Error("a leaf under Or is not indexable")
	}
	if got["innot"] {
		t.Error("a leaf under Not is not indexable")
	}
	if got["unindexable"] {
		t.Error("contains is never indexable, even on the spine")
	}
}

// --- Summary and shape -------------------------------------------------------

func TestExplain_SummaryNamesTheDecidingRule(t *testing.T) {
	policies := []model.Policy{{
		ID: "acme-grant", TenantID: "t",
		Rules: []model.Rule{{ID: "allow-admin", Effect: model.Allow,
			Obligations: []string{"audit_log"},
			When:        model.AllOf(cond("role", model.OpEquals, "admin"))}},
	}}
	req := model.Request{TenantID: "t", Attributes: map[string]string{"role": "admin"}}

	ex := Explain(policies, req, model.DenyOverrides, DefaultOptions())
	for _, want := range []string{"ALLOWED", "allow-admin", "acme-grant", "audit_log"} {
		if !strings.Contains(ex.Summary, want) {
			t.Errorf("summary %q missing %q", ex.Summary, want)
		}
	}
	if !ex.Policies[0].Decisive {
		t.Error("the deciding policy should be marked")
	}
}

func TestExplain_DefaultDenySummary(t *testing.T) {
	policies := []model.Policy{{ID: "p", TenantID: "t",
		Rules: []model.Rule{{ID: "r", Effect: model.Allow,
			When: model.AllOf(cond("role", model.OpEquals, "admin"))}}}}
	req := model.Request{TenantID: "t", Attributes: map[string]string{"role": "viewer"}}

	ex := Explain(policies, req, model.DenyOverrides, DefaultOptions())
	if !strings.Contains(ex.Summary, "DENIED by default") {
		t.Errorf("summary = %q", ex.Summary)
	}
	if ex.RulesEvaluated != 1 || ex.RulesMatched != 0 {
		t.Errorf("counts wrong: evaluated=%d matched=%d", ex.RulesEvaluated, ex.RulesMatched)
	}
}

// TestExplain_PermitUnlessDenySummary covers the one algorithm that grants by
// default, since a reader seeing ALLOWED with nothing matched deserves to be
// told why.
func TestExplain_PermitUnlessDenySummary(t *testing.T) {
	ex := Explain(nil, model.Request{TenantID: "t"}, model.PermitUnlessDeny, DefaultOptions())
	if !ex.Decision.Allowed {
		t.Fatalf("permit-unless-deny allows an unmatched request, got %s", ex.Decision)
	}
	if !strings.Contains(ex.Summary, "ALLOWED by default") {
		t.Errorf("summary should explain the default-allow: %q", ex.Summary)
	}
}

func TestExplain_TruncatesLargeTraces(t *testing.T) {
	policies := make([]model.Policy, 500)
	for i := range policies {
		policies[i] = model.Policy{ID: "p", TenantID: "t",
			Rules: []model.Rule{{ID: "r", Effect: model.Allow,
				When: model.AllOf(cond("never", model.OpEquals, "x"))}}}
	}
	opt := DefaultOptions()
	opt.MaxPolicies = 10
	ex := Explain(policies, model.Request{TenantID: "t"}, model.DenyOverrides, opt)

	if len(ex.Policies) != 10 {
		t.Fatalf("expected 10 traced policies, got %d", len(ex.Policies))
	}
	if !ex.Truncated {
		t.Error("truncation should be reported")
	}
	// Counts still cover the whole corpus, not just the traced part.
	if ex.PoliciesInScope != 500 {
		t.Errorf("in-scope count should cover everything, got %d", ex.PoliciesInScope)
	}
}

func TestExplain_TypedAttributes(t *testing.T) {
	policies := []model.Policy{{
		ID: "p", TenantID: "t",
		Rules: []model.Rule{{ID: "r", Effect: model.Allow,
			When: model.AllOf(
				model.Condition{Attribute: "score", Operator: model.OpRange, Min: 0, Max: 10},
				model.Condition{Attribute: "ip", Operator: model.OpCIDR,
					Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}},
			)}},
	}}
	req := model.Request{TenantID: "t",
		Numeric: map[string]float64{"score": 42},
		IPs:     map[string]netip.Addr{"ip": netip.MustParseAddr("10.1.2.3")}}

	opt := DefaultOptions()
	opt.Redact = false
	ex := Explain(policies, req, model.DenyOverrides, opt)

	var score, ip *LeafTrace
	walkLeaves(ex.Policies[0].Rules[0].Condition, func(l *LeafTrace) {
		switch l.Attribute {
		case "score":
			score = l
		case "ip":
			ip = l
		}
	})
	if score == nil || score.Actual != "42" || score.Expected != "[0, 10]" {
		t.Errorf("numeric trace wrong: %+v", score)
	}
	if ip == nil || ip.Actual != "10.1.2.3" || !ip.Matched {
		t.Errorf("ip trace wrong: %+v", ip)
	}
}

func TestExplain_SerializesToJSON(t *testing.T) {
	// The trace is served over HTTP, so it has to round-trip.
	policies := []model.Policy{{ID: "p", TenantID: "t",
		Rules: []model.Rule{{ID: "r", Effect: model.Allow,
			When: model.AllOf(cond("role", model.OpEquals, "admin"))}}}}
	ex := Explain(policies, model.Request{TenantID: "t",
		Attributes: map[string]string{"role": "admin"}},
		model.DenyOverrides, DefaultOptions())

	blob, err := json.Marshal(ex)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Explanation
	if err := json.Unmarshal(blob, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Decision.Allowed != ex.Decision.Allowed || back.Summary != ex.Summary {
		t.Error("round trip lost information")
	}
}

func TestExplain_CatchAllRule(t *testing.T) {
	policies := []model.Policy{{ID: "p", TenantID: "t",
		Rules: []model.Rule{{ID: "backstop", Effect: model.Deny, When: nil}}}}
	ex := Explain(policies, model.Request{TenantID: "t"}, model.DenyOverrides, DefaultOptions())

	if ex.Decision.Allowed {
		t.Fatalf("expected deny, got %s", ex.Decision)
	}
	if !strings.Contains(ex.Policies[0].Rules[0].Why, "no conditions") {
		t.Errorf("why = %q", ex.Policies[0].Rules[0].Why)
	}
}
