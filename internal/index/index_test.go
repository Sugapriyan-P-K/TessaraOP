package index

import (
	"math/rand"
	"net/netip"
	"testing"

	"github.com/suga/tessaraop/internal/model"
)

// simple builds a one-rule policy from a conjunction of conditions.
func simple(id string, effect model.Effect, conds ...model.Condition) model.Policy {
	return model.Policy{
		ID: id,
		Rules: []model.Rule{{
			ID: id + "/r0", Effect: effect, When: model.AllOf(conds...),
		}},
	}
}

func candidateSet(t *testing.T, s *Shard, req model.Request) map[int]bool {
	t.Helper()
	out := map[int]bool{}
	for _, c := range s.Candidates(req, NewScratch()) {
		out[c] = true
	}
	return out
}

// rulePos maps a (policy, rule) pair to its indexed position. Positions are
// assigned in policy order, so this is just the running rule total.
func rulePos(policies []model.Policy, policyIdx, ruleIdx int) int {
	pos := 0
	for i := 0; i < policyIdx; i++ {
		pos += len(policies[i].Rules)
	}
	return pos + ruleIdx
}

// --- The pre-filter invariant ----------------------------------------------

// TestCandidates_NeverExcludesAMatchingRule is the single most important test in
// this package. The index is only ever allowed to be over-inclusive: dropping a
// rule that genuinely matches turns a performance structure into a correctness
// bug, and one that fails silently with a wrong ALLOW or DENY rather than an
// error. This drives randomized corpora spanning every operator family and every
// tree shape — including conditions buried under Or and Not, which must not be
// indexed — and asserts the invariant directly.
func TestCandidates_NeverExcludesAMatchingRule(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for iter := 0; iter < 200; iter++ {
		policies := randomPolicies(rng, 40)
		shard := BuildShard(policies)
		sc := NewScratch()

		for q := 0; q < 20; q++ {
			req := randomRequest(rng)
			got := map[int]bool{}
			for _, c := range shard.Candidates(req, sc) {
				got[c] = true
			}
			for pi := range policies {
				for ri := range policies[pi].Rules {
					if !policies[pi].Rules[ri].When.Matches(req) {
						continue
					}
					pos := rulePos(policies, pi, ri)
					if !got[pos] {
						t.Fatalf("iter %d: rule %s (pos %d) matches but was excluded\nrequest: %+v",
							iter, policies[pi].Rules[ri].ID, pos, req)
					}
				}
			}
		}
	}
}

// TestCandidates_OffSpineConditionIsNotIndexed pins the AND-spine boundary from
// the index side. A rule whose only condition on an attribute sits under an Or
// must survive the filter even when the request value contradicts that
// condition, because its sibling branch may still satisfy the disjunction.
func TestCandidates_OffSpineConditionIsNotIndexed(t *testing.T) {
	roleAdmin := model.Condition{Attribute: "role", Operator: model.OpEquals, Values: []string{"admin"}}
	deptSec := model.Condition{Attribute: "dept", Operator: model.OpEquals, Values: []string{"security"}}

	policies := []model.Policy{{
		ID: "p",
		Rules: []model.Rule{{
			ID: "p/r0", Effect: model.Allow,
			When: model.Or(model.Cond(roleAdmin), model.Cond(deptSec)),
		}},
	}}
	shard := BuildShard(policies)

	// role=viewer contradicts the first branch, but dept=security satisfies the
	// second. If the index had used the role condition, this rule would be gone.
	req := model.Request{Attributes: map[string]string{"role": "viewer", "dept": "security"}}
	if !candidateSet(t, shard, req)[0] {
		t.Fatal("a rule whose condition sits under an Or must not be filtered on it")
	}
	if !policies[0].Rules[0].When.Matches(req) {
		t.Fatal("sanity: the rule really does match this request")
	}
}

// TestCandidates_NegatedSubtreeIsNotIndexed is the same boundary for Not. A leaf
// under a Not requires the value to be absent or different, so indexing it as
// though it required a match would exclude exactly the rules that do match.
func TestCandidates_NegatedSubtreeIsNotIndexed(t *testing.T) {
	policies := []model.Policy{{
		ID: "p",
		Rules: []model.Rule{{
			ID: "p/r0", Effect: model.Deny,
			When: model.And(
				model.Cond(model.Condition{Attribute: "action", Operator: model.OpEquals,
					Values: []string{"delete"}}),
				model.Not(model.Cond(model.Condition{Attribute: "role", Operator: model.OpEquals,
					Values: []string{"admin"}})),
			),
		}},
	}}
	shard := BuildShard(policies)

	req := model.Request{Attributes: map[string]string{"action": "delete", "role": "viewer"}}
	if !policies[0].Rules[0].When.Matches(req) {
		t.Fatal("sanity: the rule matches — action is delete and role is not admin")
	}
	if !candidateSet(t, shard, req)[0] {
		t.Fatal("a rule with a negated subtree must survive the filter")
	}
}

// TestCandidates_SpineStillPrunesAroundOffSpineNodes checks that adding an Or to
// a rule does not disable indexing for the rest of it. The conjunctive part must
// still prune, or expressiveness would cost far more than it should.
func TestCandidates_SpineStillPrunesAroundOffSpineNodes(t *testing.T) {
	offSpine := model.Or(
		model.Cond(model.Condition{Attribute: "dept", Operator: model.OpEquals, Values: []string{"a"}}),
		model.Cond(model.Condition{Attribute: "dept", Operator: model.OpEquals, Values: []string{"b"}}),
	)
	policies := []model.Policy{{
		ID: "p",
		Rules: []model.Rule{{
			ID: "p/r0", Effect: model.Allow,
			When: model.And(
				model.Cond(model.Condition{Attribute: "action", Operator: model.OpEquals,
					Values: []string{"read"}}),
				offSpine,
			),
		}},
	}}
	shard := BuildShard(policies)

	// The spine condition fails, so the rule cannot match however the Or resolves.
	req := model.Request{Attributes: map[string]string{"action": "write", "dept": "a"}}
	if candidateSet(t, shard, req)[0] {
		t.Fatal("the AND-spine must still prune even when part of the tree is off it")
	}
}

// --- Rule granularity -------------------------------------------------------

// TestCandidates_IndexesRulesNotPolicies checks the change in indexed unit. Two
// rules in one policy asking for different things must be filtered
// independently: if a policy were the indexed unit its entry would be the union
// of both, and neither would ever prune.
func TestCandidates_IndexesRulesNotPolicies(t *testing.T) {
	policies := []model.Policy{{
		ID: "p",
		Rules: []model.Rule{
			{ID: "p/r0", Effect: model.Allow, When: model.AllOf(
				model.Condition{Attribute: "role", Operator: model.OpEquals, Values: []string{"admin"}})},
			{ID: "p/r1", Effect: model.Allow, When: model.AllOf(
				model.Condition{Attribute: "role", Operator: model.OpEquals, Values: []string{"viewer"}})},
		},
	}}
	shard := BuildShard(policies)
	if shard.Size() != 2 {
		t.Fatalf("universe should be the rule count, got %d", shard.Size())
	}

	got := candidateSet(t, shard, model.Request{Attributes: map[string]string{"role": "admin"}})
	if !got[0] {
		t.Error("the admin rule must be a candidate")
	}
	if got[1] {
		t.Error("the viewer rule must be pruned")
	}
}

// TestRuleRef_GroupsRulesByPolicyContiguously pins the property the two-tier walk
// depends on: positions are assigned in policy order, so ascending candidate
// positions form one contiguous run per policy and need no map to group.
func TestRuleRef_GroupsRulesByPolicyContiguously(t *testing.T) {
	policies := []model.Policy{
		{ID: "a", Rules: []model.Rule{{ID: "a/0"}, {ID: "a/1"}}},
		{ID: "b", Rules: []model.Rule{{ID: "b/0"}}},
		{ID: "c", Rules: []model.Rule{{ID: "c/0"}, {ID: "c/1"}, {ID: "c/2"}}},
	}
	shard := BuildShard(policies)
	if shard.Size() != 6 {
		t.Fatalf("expected 6 rules, got %d", shard.Size())
	}

	lastPolicy := -1
	seen := map[int]bool{}
	for pos := 0; pos < shard.Size(); pos++ {
		pi, ri := shard.RuleRef(pos)
		if pi != lastPolicy {
			if seen[pi] {
				t.Fatalf("policy %d's rules are not contiguous at position %d", pi, pos)
			}
			seen[pi] = true
			lastPolicy = pi
		}
		if policies[pi].Rules[ri].ID == "" {
			t.Fatalf("position %d resolved to an empty rule", pos)
		}
	}
}

// TestShardEvaluate_AgreesWithNaiveTwoTier drives the full two-tier walk through
// the index and compares it against resolving every policy directly. This is
// where a grouping bug in the contiguous-run walk would surface.
func TestShardEvaluate_AgreesWithNaiveTwoTier(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for iter := 0; iter < 100; iter++ {
		policies := randomPolicies(rng, 25)
		shard := BuildShard(policies)
		sc := NewScratch()

		for q := 0; q < 15; q++ {
			req := randomRequest(rng)

			for _, alg := range []model.Algorithm{
				model.DenyOverrides, model.PermitOverrides, model.FirstApplicable,
			} {
				var indexed model.Accumulator
				indexed.Reset(alg)
				shard.Evaluate(req, sc, &indexed)
				want := model.Evaluate(policies, req, alg)
				got := indexed.Resolve()

				if got.Allowed != want.Allowed || got.Effect != want.Effect {
					t.Fatalf("iter %d alg %s: indexed %s vs full %s", iter, alg, got, want)
				}
			}
		}
	}
}

// --- noCondition property, per sub-index ------------------------------------

func TestCandidates_RuleWithNoConditionOnAttributeSurvives(t *testing.T) {
	// Each case pairs a rule conditioned on some attribute with a rule that
	// ignores it. Whatever the request says about that attribute, the second rule
	// must never be filtered out.
	cases := []struct {
		name string
		cond model.Condition
		req  model.Request
	}{
		{
			"set family",
			model.Condition{Attribute: "role", Operator: model.OpEquals, Values: []string{"admin"}},
			model.Request{Attributes: map[string]string{"role": "viewer"}},
		},
		{
			"numeric range",
			model.Condition{Attribute: "score", Operator: model.OpRange, Min: 0, Max: 10},
			model.Request{Numeric: map[string]float64{"score": 99}},
		},
		{
			"numeric set",
			model.Condition{Attribute: "port", Operator: model.OpNumIn, Numbers: []float64{80, 443}},
			model.Request{Numeric: map[string]float64{"port": 22}},
		},
		{
			"network family",
			model.Condition{Attribute: "ip", Operator: model.OpCIDR,
				Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}},
			model.Request{IPs: map[string]netip.Addr{"ip": netip.MustParseAddr("8.8.8.8")}},
		},
		{
			"dns suffix",
			model.Condition{Attribute: "host", Operator: model.OpDNSSuffix, Values: []string{"acme.com"}},
			model.Request{Attributes: map[string]string{"host": "other.net"}},
		},
		{
			"path prefix",
			model.Condition{Attribute: "path", Operator: model.OpPrefix, Values: []string{"/admin"}},
			model.Request{Attributes: map[string]string{"path": "/public/x"}},
		},
		{
			"byte suffix",
			model.Condition{Attribute: "file", Operator: model.OpSuffix, Values: []string{".exe"}},
			model.Request{Attributes: map[string]string{"file": "report.pdf"}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policies := []model.Policy{
				simple("conditioned", model.Allow, tc.cond),
				simple("indifferent", model.Deny),
			}
			got := candidateSet(t, BuildShard(policies), tc.req)
			if !got[1] {
				t.Fatal("a rule with no condition on the attribute must always survive")
			}
			if got[0] {
				t.Fatal("the conditioned rule should have been filtered out here")
			}
		})
	}
}

// --- Selectivity ------------------------------------------------------------

func TestCandidates_NarrowsOnEquality(t *testing.T) {
	policies := make([]model.Policy, 100)
	for i := range policies {
		role := "viewer"
		if i%10 == 0 {
			role = "admin"
		}
		policies[i] = simple("p", model.Allow,
			model.Condition{Attribute: "role", Operator: model.OpEquals, Values: []string{role}})
	}
	got := candidateSet(t, BuildShard(policies),
		model.Request{Attributes: map[string]string{"role": "admin"}})
	if len(got) != 10 {
		t.Fatalf("expected the 10 admin rules, got %d", len(got))
	}
}

func TestCandidates_NumSetNarrows(t *testing.T) {
	// The discrete-numeric case: a port set must behave like a hash lookup, not
	// fall back to every participating rule.
	policies := make([]model.Policy, 100)
	for i := range policies {
		port := float64(8000 + i)
		if i%10 == 0 {
			port = 443
		}
		policies[i] = simple("p", model.Allow,
			model.Condition{Attribute: "port", Operator: model.OpNumIn, Numbers: []float64{port}})
	}
	got := candidateSet(t, BuildShard(policies),
		model.Request{Numeric: map[string]float64{"port": 443}})
	if len(got) != 10 {
		t.Fatalf("expected the 10 rules accepting 443, got %d", len(got))
	}
}

func TestCandidates_SuffixNarrows(t *testing.T) {
	policies := []model.Policy{
		simple("exe", model.Deny,
			model.Condition{Attribute: "file", Operator: model.OpSuffix, Values: []string{".exe"}}),
		simple("php", model.Deny,
			model.Condition{Attribute: "file", Operator: model.OpSuffix, Values: []string{".php"}}),
	}
	got := candidateSet(t, BuildShard(policies),
		model.Request{Attributes: map[string]string{"file": "shell.php"}})
	if got[0] {
		t.Error("the .exe rule must be pruned")
	}
	if !got[1] {
		t.Error("the .php rule must be a candidate")
	}
}

func TestCandidates_UnknownValueMatchesNothing(t *testing.T) {
	policies := []model.Policy{simple("p", model.Allow,
		model.Condition{Attribute: "role", Operator: model.OpEquals, Values: []string{"admin"}})}
	got := candidateSet(t, BuildShard(policies),
		model.Request{Attributes: map[string]string{"role": "nobody"}})
	if len(got) != 0 {
		t.Fatalf("a value no rule accepts should yield no candidates, got %v", got)
	}
}

func TestCandidates_AbsentAttributePrunes(t *testing.T) {
	// A rule requiring an attribute cannot match a request lacking it, so the
	// index should prune it rather than defer to validation.
	policies := []model.Policy{
		simple("needs-role", model.Allow,
			model.Condition{Attribute: "role", Operator: model.OpEquals, Values: []string{"admin"}}),
		simple("needs-nothing", model.Allow),
	}
	got := candidateSet(t, BuildShard(policies),
		model.Request{Attributes: map[string]string{"unrelated": "x"}})
	if got[0] {
		t.Fatal("rule requiring an absent attribute should be pruned")
	}
	if !got[1] {
		t.Fatal("unconditioned rule must survive")
	}
}

// TestCandidates_UnindexableOperatorsStillPruneOnPresence covers the only filter
// contains and regex can contribute. Getting no help from them at all would be
// correct but would leave a WAF-style corpus fully unfiltered.
func TestCandidates_UnindexableOperatorsStillPruneOnPresence(t *testing.T) {
	for _, op := range []model.Operator{
		model.OpContains, model.OpNotContains, model.OpRegex, model.OpNotRegex,
		model.OpNotPrefix, model.OpNotSuffix, model.OpNotDNSSuffix,
	} {
		policies := []model.Policy{
			simple("needs-body", model.Deny,
				model.Condition{Attribute: "body", Operator: op, Values: []string{"x"}}),
			simple("indifferent", model.Allow),
		}
		got := candidateSet(t, BuildShard(policies),
			model.Request{Attributes: map[string]string{"other": "y"}})
		if got[0] {
			t.Errorf("%s: rule requiring an absent attribute should be pruned", op)
		}
		if !got[1] {
			t.Errorf("%s: indifferent rule must survive", op)
		}
	}
}

// TestCandidates_UnindexableOperatorsAreOverInclusive is the other half: when the
// attribute IS present, the rule must survive regardless of value, because no
// structure can decide a substring or regex test at filter time.
func TestCandidates_UnindexableOperatorsAreOverInclusive(t *testing.T) {
	policies := []model.Policy{simple("sig", model.Deny,
		model.Condition{Attribute: "body", Operator: model.OpRegex,
			Values: []string{`(?i)union\s+select`}})}
	shard := BuildShard(policies)

	for _, body := range []string{"harmless", "1 UNION SELECT x"} {
		got := candidateSet(t, shard, model.Request{Attributes: map[string]string{"body": body}})
		if !got[0] {
			t.Errorf("body %q: a regex rule must reach validation whenever its attribute is present", body)
		}
	}
}

func TestCandidates_NotExistsSurvivesWhenAbsent(t *testing.T) {
	policies := []model.Policy{simple("must-be-absent", model.Deny,
		model.Condition{Attribute: "token", Operator: model.OpNotExists})}
	shard := BuildShard(policies)

	absent := candidateSet(t, shard, model.Request{Attributes: map[string]string{}})
	if !absent[0] {
		t.Fatal("NotExists rule must be a candidate when the attribute is absent")
	}

	present := candidateSet(t, shard,
		model.Request{Attributes: map[string]string{"token": "abc"}})
	if present[0] {
		t.Fatal("NotExists rule must be pruned when the attribute is present")
	}
}

// TestCandidates_NotExistsDefeatedByTypedMaps guards a gap the previous
// implementation had: the notExists rejection was applied only when the
// attribute appeared in the string map, so a numeric or IP attribute of the same
// name left the rule as a candidate. Under-selective rather than wrong, but the
// two presence checks must agree with Condition.Matches.
func TestCandidates_NotExistsDefeatedByTypedMaps(t *testing.T) {
	policies := []model.Policy{simple("absent-port", model.Deny,
		model.Condition{Attribute: "port", Operator: model.OpNotExists})}
	shard := BuildShard(policies)

	numeric := model.Request{Numeric: map[string]float64{"port": 443}}
	if candidateSet(t, shard, numeric)[0] {
		t.Error("a numeric attribute must defeat NotExists at the index too")
	}

	policies = []model.Policy{simple("absent-ip", model.Deny,
		model.Condition{Attribute: "src", Operator: model.OpNotExists})}
	shard = BuildShard(policies)
	ip := model.Request{IPs: map[string]netip.Addr{"src": netip.MustParseAddr("10.0.0.1")}}
	if candidateSet(t, shard, ip)[0] {
		t.Error("an IP attribute must defeat NotExists at the index too")
	}
}

func TestCandidates_NegationRejects(t *testing.T) {
	policies := []model.Policy{simple("not-service", model.Allow,
		model.Condition{Attribute: "role", Operator: model.OpNotIn,
			Values: []string{"service-account"}})}
	shard := BuildShard(policies)

	if candidateSet(t, shard,
		model.Request{Attributes: map[string]string{"role": "service-account"}})[0] {
		t.Fatal("a negated condition must reject the excluded value")
	}
	if !candidateSet(t, shard,
		model.Request{Attributes: map[string]string{"role": "admin"}})[0] {
		t.Fatal("a negated condition must accept other values")
	}
}

// TestCandidates_NotEqualsIndexesOnlyTheFirstValue guards a latent
// under-inclusiveness bug. Condition.Matches for `ne` compares against Values[0]
// alone, so indexing a second value as also-rejected would filter out a rule
// that actually matches.
func TestCandidates_NotEqualsIndexesOnlyTheFirstValue(t *testing.T) {
	policies := []model.Policy{simple("ne", model.Allow,
		model.Condition{Attribute: "role", Operator: model.OpNotEquals,
			Values: []string{"admin", "viewer"}})}
	shard := BuildShard(policies)

	// role=viewer: Matches returns true, since only Values[0] ("admin") counts.
	req := model.Request{Attributes: map[string]string{"role": "viewer"}}
	if !policies[0].Rules[0].When.Matches(req) {
		t.Fatal("sanity: ne compares against Values[0] only, so viewer matches")
	}
	if !candidateSet(t, shard, req)[0] {
		t.Fatal("the index rejected a rule that matches — under-inclusive")
	}
}

func TestCandidates_NegatedCIDRRejects(t *testing.T) {
	policies := []model.Policy{simple("not-blocked", model.Allow,
		model.Condition{Attribute: "ip", Operator: model.OpNotCIDR,
			Prefixes: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}})}
	shard := BuildShard(policies)

	blocked := model.Request{IPs: map[string]netip.Addr{"ip": netip.MustParseAddr("203.0.113.9")}}
	if candidateSet(t, shard, blocked)[0] {
		t.Fatal("an address inside the excluded block must be rejected")
	}

	ok := model.Request{IPs: map[string]netip.Addr{"ip": netip.MustParseAddr("10.0.0.1")}}
	if !candidateSet(t, shard, ok)[0] {
		t.Fatal("an address outside the excluded block must survive")
	}
}

func TestCandidates_MultipleAttributesIntersect(t *testing.T) {
	policies := []model.Policy{
		simple("both", model.Allow,
			model.Condition{Attribute: "role", Operator: model.OpEquals, Values: []string{"admin"}},
			model.Condition{Attribute: "dept", Operator: model.OpEquals, Values: []string{"eng"}}),
		simple("wrong-dept", model.Allow,
			model.Condition{Attribute: "role", Operator: model.OpEquals, Values: []string{"admin"}},
			model.Condition{Attribute: "dept", Operator: model.OpEquals, Values: []string{"sales"}}),
	}
	got := candidateSet(t, BuildShard(policies),
		model.Request{Attributes: map[string]string{"role": "admin", "dept": "eng"}})
	if !got[0] || got[1] {
		t.Fatalf("intersection should keep only the matching rule, got %v", got)
	}
}

func TestBuildShard_Empty(t *testing.T) {
	s := BuildShard(nil)
	if s.Size() != 0 {
		t.Fatalf("expected empty shard, got size %d", s.Size())
	}
	if got := s.Candidates(model.Request{}, NewScratch()); len(got) != 0 {
		t.Fatalf("empty shard must yield no candidates, got %v", got)
	}
}

func TestBuildShard_PoliciesWithNoRules(t *testing.T) {
	// A policy holding no rules contributes nothing to the universe and must not
	// shift any other policy's positions.
	policies := []model.Policy{
		{ID: "empty"},
		simple("real", model.Allow,
			model.Condition{Attribute: "role", Operator: model.OpEquals, Values: []string{"admin"}}),
	}
	shard := BuildShard(policies)
	if shard.Size() != 1 {
		t.Fatalf("expected 1 rule in the universe, got %d", shard.Size())
	}
	pi, ri := shard.RuleRef(0)
	if pi != 1 || ri != 0 {
		t.Fatalf("position 0 should resolve to policy 1 rule 0, got %d/%d", pi, ri)
	}
}

func TestBuildShard_CompilesRegexes(t *testing.T) {
	// BuildShard runs Prepare so evaluation never compiles. The observable effect
	// is only performance, so this checks the semantics still hold afterwards.
	policies := []model.Policy{simple("sig", model.Deny,
		model.Condition{Attribute: "q", Operator: model.OpRegex, Values: []string{`^id=\d+$`}})}
	shard := BuildShard(policies)

	var acc model.Accumulator
	acc.Reset(model.DenyOverrides)
	shard.Evaluate(model.Request{Attributes: map[string]string{"q": "id=42"}}, NewScratch(), &acc)
	if d := acc.Resolve(); d.Effect != model.Deny {
		t.Fatalf("expected the regex rule to fire, got %s", d)
	}
}

func TestScratch_IsReusable(t *testing.T) {
	policies := randomPolicies(rand.New(rand.NewSource(3)), 30)
	shard := BuildShard(policies)
	sc := NewScratch()
	rng := rand.New(rand.NewSource(4))

	for i := 0; i < 50; i++ {
		req := randomRequest(rng)
		got := map[int]bool{}
		for _, c := range shard.Candidates(req, sc) {
			got[c] = true
		}
		for pi := range policies {
			for ri := range policies[pi].Rules {
				if policies[pi].Rules[ri].When.Matches(req) && !got[rulePos(policies, pi, ri)] {
					t.Fatalf("reused scratch dropped matching rule %s on iteration %d",
						policies[pi].Rules[ri].ID, i)
				}
			}
		}
	}
}

// TestScratch_EvaluateReusesRuleBuffer checks that the per-policy rule list is
// not carried between policies. A stale buffer would feed one policy's rule
// positions into the next, which is a wrong-answer bug rather than a slow one.
func TestScratch_EvaluateReusesRuleBuffer(t *testing.T) {
	policies := []model.Policy{
		{ID: "a", Rules: []model.Rule{
			{ID: "a/0", Effect: model.Allow, When: model.AllOf(
				model.Condition{Attribute: "x", Operator: model.OpEquals, Values: []string{"1"}})},
		}},
		{ID: "b", Rules: []model.Rule{
			{ID: "b/0", Effect: model.Allow, When: model.AllOf(
				model.Condition{Attribute: "y", Operator: model.OpEquals, Values: []string{"9"}})},
			{ID: "b/1", Effect: model.Deny, When: model.AllOf(
				model.Condition{Attribute: "x", Operator: model.OpEquals, Values: []string{"1"}})},
		}},
	}
	shard := BuildShard(policies)
	sc := NewScratch()

	req := model.Request{Attributes: map[string]string{"x": "1"}}
	var acc model.Accumulator
	acc.Reset(model.DenyOverrides)
	shard.Evaluate(req, sc, &acc)

	want := model.Evaluate(policies, req, model.DenyOverrides)
	got := acc.Resolve()
	if got.Effect != want.Effect || got.MatchedPolicyID != want.MatchedPolicyID {
		t.Fatalf("indexed %s disagrees with full scan %s", got, want)
	}
}

// --- Randomized corpus helpers ---------------------------------------------

var (
	tRoles  = []string{"admin", "viewer", "editor", "service-account"}
	tDepts  = []string{"eng", "sales", "hr"}
	tHosts  = []string{"acme.com", "admin.acme.com", "other.net"}
	tPaths  = []string{"/api", "/api/v2", "/admin"}
	tFiles  = []string{".exe", ".php", ".pdf"}
	tPorts  = []float64{22, 80, 443, 8080}
	tBlocks = []string{"10.0.0.0/8", "192.168.0.0/16", "203.0.113.0/24"}
	tSigs   = []string{`(?i)select`, `^/adm`, `\d{3,}`}
)

// randomPolicies builds multi-rule policies whose trees mix conjunctions,
// disjunctions and negations, so the AND-spine boundary is exercised by the
// randomized invariant rather than only by the hand-written cases.
func randomPolicies(rng *rand.Rand, n int) []model.Policy {
	out := make([]model.Policy, n)
	for i := range out {
		p := model.Policy{ID: string(rune('a' + i%26))}
		if rng.Intn(5) == 0 {
			p.RuleAlgorithm = model.FirstApplicable
		}
		nRules := 1 + rng.Intn(3)
		for k := 0; k < nRules; k++ {
			r := model.Rule{
				ID:       p.ID + "/" + string(rune('0'+k)),
				Effect:   model.Allow,
				Priority: rng.Intn(10),
			}
			if rng.Intn(4) == 0 {
				r.Effect = model.Deny
			}
			r.When = randomExpr(rng)
			p.Rules = append(p.Rules, r)
		}
		out[i] = p
	}
	return out
}

func randomExpr(rng *rand.Rand) *model.ConditionExpr {
	sub := make([]*model.ConditionExpr, 0, 5)
	for c := rng.Intn(4); c > 0; c-- {
		sub = append(sub, model.Cond(randomCondition(rng)))
	}
	switch rng.Intn(6) {
	case 0:
		sub = append(sub, model.Or(
			model.Cond(randomCondition(rng)), model.Cond(randomCondition(rng))))
	case 1:
		sub = append(sub, model.Not(model.Cond(randomCondition(rng))))
	case 2:
		// Nested: an Or holding a conjunction. The conjunction's leaves are still
		// off the spine, since the Or above them breaks it.
		sub = append(sub, model.Or(
			model.And(model.Cond(randomCondition(rng)), model.Cond(randomCondition(rng))),
			model.Cond(randomCondition(rng)),
		))
	case 3:
		// A rule rooted at Or gets no index help at all.
		return model.Or(model.Cond(randomCondition(rng)), model.Cond(randomCondition(rng)))
	}
	return model.And(sub...)
}

func randomCondition(rng *rand.Rand) model.Condition {
	switch rng.Intn(18) {
	case 0:
		return model.Condition{Attribute: "role", Operator: model.OpEquals,
			Values: []string{tRoles[rng.Intn(len(tRoles))]}}
	case 1:
		return model.Condition{Attribute: "role", Operator: model.OpIn,
			Values: []string{tRoles[rng.Intn(len(tRoles))], tRoles[rng.Intn(len(tRoles))]}}
	case 2:
		return model.Condition{Attribute: "role", Operator: model.OpNotIn,
			Values: []string{tRoles[rng.Intn(len(tRoles))]}}
	case 3:
		return model.Condition{Attribute: "role", Operator: model.OpNotEquals,
			Values: []string{tRoles[rng.Intn(len(tRoles))]}}
	case 4:
		return model.Condition{Attribute: "dept", Operator: model.OpEquals,
			Values: []string{tDepts[rng.Intn(len(tDepts))]}}
	case 5:
		return model.Condition{Attribute: "score", Operator: model.OpRange,
			Min: float64(rng.Intn(50)), Max: float64(50 + rng.Intn(50))}
	case 6:
		return model.Condition{Attribute: "score", Operator: model.OpGreaterThan,
			Min: float64(rng.Intn(100))}
	case 7:
		return model.Condition{Attribute: "score", Operator: model.OpLessEq,
			Max: float64(rng.Intn(100))}
	case 8:
		return model.Condition{Attribute: "ip", Operator: model.OpCIDR,
			Prefixes: []netip.Prefix{netip.MustParsePrefix(tBlocks[rng.Intn(len(tBlocks))])}}
	case 9:
		return model.Condition{Attribute: "ip", Operator: model.OpNotCIDR,
			Prefixes: []netip.Prefix{netip.MustParsePrefix(tBlocks[rng.Intn(len(tBlocks))])}}
	case 10:
		return model.Condition{Attribute: "host", Operator: model.OpDNSSuffix,
			Values: []string{tHosts[rng.Intn(len(tHosts))]}}
	case 11:
		return model.Condition{Attribute: "path", Operator: model.OpPrefix,
			Values: []string{tPaths[rng.Intn(len(tPaths))]}}
	case 12:
		return model.Condition{Attribute: "file", Operator: model.OpSuffix,
			Values: []string{tFiles[rng.Intn(len(tFiles))]}}
	case 13:
		return model.Condition{Attribute: "port", Operator: model.OpNumIn,
			Numbers: []float64{tPorts[rng.Intn(len(tPorts))], tPorts[rng.Intn(len(tPorts))]}}
	case 14:
		return model.Condition{Attribute: "port", Operator: model.OpNumEquals,
			Min: tPorts[rng.Intn(len(tPorts))]}
	case 15:
		return model.Condition{Attribute: "path", Operator: model.OpContains,
			Values: []string{tPaths[rng.Intn(len(tPaths))]}}
	case 16:
		return model.Condition{Attribute: "path", Operator: model.OpRegex,
			Values: []string{tSigs[rng.Intn(len(tSigs))]}}
	default:
		return model.Condition{Attribute: "token", Operator: model.OpNotExists}
	}
}

func randomRequest(rng *rand.Rand) model.Request {
	r := model.Request{
		Attributes: map[string]string{},
		Numeric:    map[string]float64{},
		IPs:        map[string]netip.Addr{},
	}
	// Attributes are omitted sometimes on purpose, so the absent-attribute paths
	// get exercised alongside the present ones.
	if rng.Intn(10) < 9 {
		r.Attributes["role"] = tRoles[rng.Intn(len(tRoles))]
	}
	if rng.Intn(10) < 8 {
		r.Attributes["dept"] = tDepts[rng.Intn(len(tDepts))]
	}
	if rng.Intn(10) < 8 {
		r.Attributes["host"] = []string{"api.acme.com", "admin.acme.com", "evilacme.com", "other.net"}[rng.Intn(4)]
	}
	if rng.Intn(10) < 8 {
		r.Attributes["path"] = []string{"/api/v2/x", "/admin/y", "/public/z"}[rng.Intn(3)]
	}
	if rng.Intn(10) < 7 {
		r.Attributes["file"] = []string{"a.exe", "b.php", "c.pdf", "d"}[rng.Intn(4)]
	}
	if rng.Intn(10) < 3 {
		r.Attributes["token"] = "present"
	}
	if rng.Intn(10) < 8 {
		r.Numeric["score"] = float64(rng.Intn(120))
	}
	if rng.Intn(10) < 8 {
		r.Numeric["port"] = tPorts[rng.Intn(len(tPorts))]
	}
	if rng.Intn(10) < 8 {
		r.IPs["ip"] = netip.AddrFrom4([4]byte{
			[]byte{10, 192, 203, 8}[rng.Intn(4)],
			byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256))})
	}
	return r
}
