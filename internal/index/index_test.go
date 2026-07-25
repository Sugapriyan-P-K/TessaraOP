package index

import (
	"math/rand"
	"net/netip"
	"testing"

	"github.com/suga/tessaraop/internal/model"
)

func candidateSet(t *testing.T, s *Shard, req model.Request) map[int]bool {
	t.Helper()
	out := map[int]bool{}
	for _, c := range s.Candidates(req, NewScratch()) {
		out[c] = true
	}
	return out
}

// --- The pre-filter invariant ----------------------------------------------

// TestCandidates_NeverExcludesAMatchingPolicy is the single most important
// test in this package. The index is only ever allowed to be over-inclusive:
// dropping a policy that genuinely matches turns a performance structure into
// a correctness bug, and one that fails silently with a wrong ALLOW or DENY
// rather than an error. This drives randomized corpora spanning every operator
// family and asserts the invariant directly.
func TestCandidates_NeverExcludesAMatchingPolicy(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for iter := 0; iter < 200; iter++ {
		policies := randomPolicies(rng, 60)
		shard := BuildShard(policies)
		sc := NewScratch()

		for q := 0; q < 20; q++ {
			req := randomRequest(rng)
			got := map[int]bool{}
			for _, c := range shard.Candidates(req, sc) {
				got[c] = true
			}
			for i := range policies {
				if policies[i].Matches(req) && !got[i] {
					t.Fatalf("iter %d: policy %d matches but was excluded\npolicy: %+v\nrequest: %+v",
						iter, i, policies[i], req)
				}
			}
		}
	}
}

// --- noCondition property, per sub-index ------------------------------------

func TestCandidates_PolicyWithNoConditionOnAttributeSurvives(t *testing.T) {
	// Each case pairs a policy conditioned on some attribute with a policy
	// that ignores it. Whatever the request says about that attribute, the
	// second policy must never be filtered out.
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
			"numeric family",
			model.Condition{Attribute: "score", Operator: model.OpRange, Min: 0, Max: 10},
			model.Request{Numeric: map[string]float64{"score": 99}},
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
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policies := []model.Policy{
				{ID: "conditioned", Effect: model.Allow, Conditions: []model.Condition{tc.cond}},
				{ID: "indifferent", Effect: model.Deny},
			}
			got := candidateSet(t, BuildShard(policies), tc.req)
			if !got[1] {
				t.Fatal("a policy with no condition on the attribute must always survive")
			}
			if got[0] {
				t.Fatal("the conditioned policy should have been filtered out here")
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
		policies[i] = model.Policy{
			ID: "p", Effect: model.Allow,
			Conditions: []model.Condition{
				{Attribute: "role", Operator: model.OpEquals, Values: []string{role}}},
		}
	}
	got := candidateSet(t, BuildShard(policies),
		model.Request{Attributes: map[string]string{"role": "admin"}})
	if len(got) != 10 {
		t.Fatalf("expected the 10 admin policies, got %d", len(got))
	}
}

func TestCandidates_UnknownValueMatchesNothing(t *testing.T) {
	policies := []model.Policy{{
		ID: "p", Effect: model.Allow,
		Conditions: []model.Condition{
			{Attribute: "role", Operator: model.OpEquals, Values: []string{"admin"}}},
	}}
	got := candidateSet(t, BuildShard(policies),
		model.Request{Attributes: map[string]string{"role": "nobody"}})
	if len(got) != 0 {
		t.Fatalf("a value no policy accepts should yield no candidates, got %v", got)
	}
}

func TestCandidates_AbsentAttributePrunes(t *testing.T) {
	// A policy requiring an attribute cannot match a request lacking it, so
	// the index should prune it rather than defer to validation.
	policies := []model.Policy{
		{ID: "needs-role", Effect: model.Allow, Conditions: []model.Condition{
			{Attribute: "role", Operator: model.OpEquals, Values: []string{"admin"}}}},
		{ID: "needs-nothing", Effect: model.Allow},
	}
	got := candidateSet(t, BuildShard(policies),
		model.Request{Attributes: map[string]string{"unrelated": "x"}})
	if got[0] {
		t.Fatal("policy requiring an absent attribute should be pruned")
	}
	if !got[1] {
		t.Fatal("unconditioned policy must survive")
	}
}

func TestCandidates_NotExistsSurvivesWhenAbsent(t *testing.T) {
	policies := []model.Policy{{
		ID: "must-be-absent", Effect: model.Deny,
		Conditions: []model.Condition{{Attribute: "token", Operator: model.OpNotExists}},
	}}
	shard := BuildShard(policies)

	absent := candidateSet(t, shard, model.Request{Attributes: map[string]string{}})
	if !absent[0] {
		t.Fatal("NotExists policy must be a candidate when the attribute is absent")
	}

	present := candidateSet(t, shard,
		model.Request{Attributes: map[string]string{"token": "abc"}})
	if present[0] {
		t.Fatal("NotExists policy must be pruned when the attribute is present")
	}
}

func TestCandidates_NegationRejects(t *testing.T) {
	policies := []model.Policy{
		{ID: "not-service", Effect: model.Allow, Conditions: []model.Condition{
			{Attribute: "role", Operator: model.OpNotIn, Values: []string{"service-account"}}}},
	}
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

func TestCandidates_NegatedCIDRRejects(t *testing.T) {
	policies := []model.Policy{{
		ID: "not-blocked", Effect: model.Allow,
		Conditions: []model.Condition{{
			Attribute: "ip", Operator: model.OpNotCIDR,
			Prefixes: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}}},
	}}
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
		{ID: "both", Effect: model.Allow, Conditions: []model.Condition{
			{Attribute: "role", Operator: model.OpEquals, Values: []string{"admin"}},
			{Attribute: "dept", Operator: model.OpEquals, Values: []string{"eng"}}}},
		{ID: "wrong-dept", Effect: model.Allow, Conditions: []model.Condition{
			{Attribute: "role", Operator: model.OpEquals, Values: []string{"admin"}},
			{Attribute: "dept", Operator: model.OpEquals, Values: []string{"sales"}}}},
	}
	got := candidateSet(t, BuildShard(policies),
		model.Request{Attributes: map[string]string{"role": "admin", "dept": "eng"}})
	if !got[0] || got[1] {
		t.Fatalf("intersection should keep only the matching policy, got %v", got)
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

func TestScratch_IsReusable(t *testing.T) {
	policies := randomPolicies(rand.New(rand.NewSource(3)), 40)
	shard := BuildShard(policies)
	sc := NewScratch()
	rng := rand.New(rand.NewSource(4))

	for i := 0; i < 50; i++ {
		req := randomRequest(rng)
		got := map[int]bool{}
		for _, c := range shard.Candidates(req, sc) {
			got[c] = true
		}
		for j := range policies {
			if policies[j].Matches(req) && !got[j] {
				t.Fatalf("reused scratch dropped matching policy %d on iteration %d", j, i)
			}
		}
	}
}

// --- Randomized corpus helpers ---------------------------------------------

var (
	tRoles  = []string{"admin", "viewer", "editor", "service-account"}
	tDepts  = []string{"eng", "sales", "hr"}
	tHosts  = []string{"acme.com", "admin.acme.com", "other.net"}
	tPaths  = []string{"/api", "/api/v2", "/admin"}
	tBlocks = []string{"10.0.0.0/8", "192.168.0.0/16", "203.0.113.0/24"}
)

func randomPolicies(rng *rand.Rand, n int) []model.Policy {
	out := make([]model.Policy, n)
	for i := range out {
		p := model.Policy{ID: string(rune('a' + i%26)), Effect: model.Allow}
		if rng.Intn(4) == 0 {
			p.Effect = model.Deny
		}
		nc := rng.Intn(4)
		for c := 0; c < nc; c++ {
			p.Conditions = append(p.Conditions, randomCondition(rng))
		}
		out[i] = p
	}
	return out
}

func randomCondition(rng *rand.Rand) model.Condition {
	switch rng.Intn(10) {
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
		return model.Condition{Attribute: "dept", Operator: model.OpEquals,
			Values: []string{tDepts[rng.Intn(len(tDepts))]}}
	case 4:
		return model.Condition{Attribute: "score", Operator: model.OpRange,
			Min: float64(rng.Intn(50)), Max: float64(50 + rng.Intn(50))}
	case 5:
		return model.Condition{Attribute: "score", Operator: model.OpGreaterThan,
			Min: float64(rng.Intn(100))}
	case 6:
		return model.Condition{Attribute: "ip", Operator: model.OpCIDR,
			Prefixes: []netip.Prefix{netip.MustParsePrefix(tBlocks[rng.Intn(len(tBlocks))])}}
	case 7:
		return model.Condition{Attribute: "ip", Operator: model.OpNotCIDR,
			Prefixes: []netip.Prefix{netip.MustParsePrefix(tBlocks[rng.Intn(len(tBlocks))])}}
	case 8:
		return model.Condition{Attribute: "host", Operator: model.OpDNSSuffix,
			Values: []string{tHosts[rng.Intn(len(tHosts))]}}
	default:
		return model.Condition{Attribute: "path", Operator: model.OpPrefix,
			Values: []string{tPaths[rng.Intn(len(tPaths))]}}
	}
}

func randomRequest(rng *rand.Rand) model.Request {
	r := model.Request{
		Attributes: map[string]string{},
		Numeric:    map[string]float64{},
		IPs:        map[string]netip.Addr{},
	}
	// Attributes are omitted sometimes on purpose, so the absent-attribute
	// paths get exercised alongside the present ones.
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
	if rng.Intn(10) < 8 {
		r.Numeric["score"] = float64(rng.Intn(120))
	}
	if rng.Intn(10) < 8 {
		r.IPs["ip"] = netip.AddrFrom4([4]byte{
			[]byte{10, 192, 203, 8}[rng.Intn(4)],
			byte(rng.Intn(256)), byte(rng.Intn(256)), byte(rng.Intn(256))})
	}
	return r
}
