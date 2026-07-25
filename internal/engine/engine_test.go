package engine

import (
	"fmt"
	"math/rand"
	"net/netip"
	"sync"
	"testing"

	"github.com/suga/tessaraop/internal/genutil"
	"github.com/suga/tessaraop/internal/model"
	"github.com/suga/tessaraop/internal/naive"
)

// --- Differential testing ---------------------------------------------------

// checkDecision asserts the engine agrees with the oracle on the enforceable
// outcome, and that whatever policy it credits genuinely justifies that
// outcome.
//
// Comparing MatchedPolicyID directly would be wrong for the overrides
// algorithms: when several policies match with the winning effect, they do not
// specify which to report, and the engine short-circuits on the first one it
// reaches. So the ID is verified against the corpus — it must name a policy
// that is in scope, actually matches, and carries the winning effect — rather
// than against the oracle's arbitrary choice. FirstApplicable orders its
// candidates deterministically, so there the IDs must agree exactly.
func checkDecision(t *testing.T, policies []model.Policy, req model.Request,
	want, got model.Decision, alg model.Algorithm, ctx string) {
	t.Helper()

	if want.Allowed != got.Allowed || want.Effect != got.Effect {
		t.Fatalf("%s\n naive:  %s\n engine: %s\n request: %+v", ctx, want, got, req)
	}

	if alg == model.FirstApplicable {
		if want.MatchedPolicyID != got.MatchedPolicyID {
			t.Fatalf("%s: first-applicable must be deterministic\n naive:  %s\n engine: %s",
				ctx, want, got)
		}
		return
	}

	if got.MatchedPolicyID == "" {
		if want.MatchedPolicyID != "" {
			t.Fatalf("%s: engine reported default-deny but oracle matched %s",
				ctx, want.MatchedPolicyID)
		}
		return
	}
	for i := range policies {
		p := &policies[i]
		if p.ID != got.MatchedPolicyID {
			continue
		}
		if !req.InScope(p) {
			t.Fatalf("%s: credited policy %s is out of scope for the request", ctx, p.ID)
		}
		if !p.Matches(req) {
			t.Fatalf("%s: credited policy %s does not match the request", ctx, p.ID)
		}
		if p.Effect != got.Effect {
			t.Fatalf("%s: credited policy %s has effect %s but decision was %s",
				ctx, p.ID, p.Effect, got.Effect)
		}
		return
	}
	t.Fatalf("%s: credited policy %s does not exist", ctx, got.MatchedPolicyID)
}

// TestDifferential_EngineMatchesNaive is the correctness backbone. The naive
// evaluator is trivially auditable; the engine is not. Rather than trusting
// the index, sharding, scoping, negation handling and combining logic to be
// right, this runs both over randomized corpora spanning every operator family
// and checks they agree. A discrepancy anywhere in the fast path surfaces here
// as a concrete failing request rather than as a silent wrong answer.
func TestDifferential_EngineMatchesNaive(t *testing.T) {
	for _, alg := range []model.Algorithm{
		model.DenyOverrides, model.PermitOverrides, model.FirstApplicable,
	} {
		t.Run(string(alg), func(t *testing.T) {
			for seed := int64(0); seed < 40; seed++ {
				rng := rand.New(rand.NewSource(seed))
				corpus := genutil.Generate(genutil.Options{
					Policies: 300, Tenants: 8, Global: 12,
				}, rng)

				ref := naive.NewWith(corpus.Policies, alg)
				eng := New(corpus.Policies, Config{Algorithm: alg})

				for q := 0; q < 25; q++ {
					req := corpus.GenerateRequest(rng)
					checkDecision(t, corpus.Policies, req,
						ref.Evaluate(req), eng.Evaluate(req), alg,
						fmt.Sprintf("seed=%d q=%d alg=%s", seed, q, alg))
				}
			}
		})
	}
}

// TestDifferential_SurvivesAdversarialRequests pushes shapes the generator
// does not produce: missing attributes, unknown tenants, empty requests. These
// are exactly the cases where an over-eager index prune would go wrong.
func TestDifferential_SurvivesAdversarialRequests(t *testing.T) {
	rng := rand.New(rand.NewSource(99))
	corpus := genutil.Generate(genutil.Options{Policies: 400, Tenants: 5, Global: 10}, rng)
	ref := naive.New(corpus.Policies)
	eng := New(corpus.Policies, Config{})

	requests := []model.Request{
		{},
		{TenantID: corpus.Tenants[0]},
		{TenantID: "tenant-does-not-exist", Attributes: map[string]string{"subject.role": "admin"}},
		{TenantID: corpus.Tenants[0], Attributes: map[string]string{"subject.role": "admin"}},
		{TenantID: corpus.Tenants[0], Numeric: map[string]float64{"subject.risk_score": 95}},
		{TenantID: corpus.Tenants[0], IPs: map[string]netip.Addr{
			"network.source_ip": netip.MustParseAddr("203.0.113.5")}},
		{TenantID: corpus.Tenants[1], Attributes: map[string]string{
			"resource.domain": "evilacme.example.com"}},
	}
	for i, req := range requests {
		checkDecision(t, corpus.Policies, req,
			ref.Evaluate(req), eng.Evaluate(req), model.DenyOverrides,
			fmt.Sprintf("adversarial request %d", i))
	}
}

// --- Sharding ---------------------------------------------------------------

func TestSharding_TenantIsolation(t *testing.T) {
	policies := []model.Policy{
		{ID: "a-allow", TenantID: "tenant-a", Effect: model.Allow, Conditions: []model.Condition{
			{Attribute: "role", Operator: model.OpEquals, Values: []string{"admin"}}}},
		{ID: "b-deny", TenantID: "tenant-b", Effect: model.Deny, Conditions: []model.Condition{
			{Attribute: "role", Operator: model.OpEquals, Values: []string{"admin"}}}},
	}
	eng := New(policies, Config{})

	a := eng.Evaluate(model.Request{TenantID: "tenant-a",
		Attributes: map[string]string{"role": "admin"}})
	if !a.Allowed || a.MatchedPolicyID != "a-allow" {
		t.Fatalf("tenant-a must see only its own policy, got %s", a)
	}

	b := eng.Evaluate(model.Request{TenantID: "tenant-b",
		Attributes: map[string]string{"role": "admin"}})
	if b.Allowed || b.MatchedPolicyID != "b-deny" {
		t.Fatalf("tenant-b must see only its own policy, got %s", b)
	}
}

func TestSharding_GlobalAppliesEverywhere(t *testing.T) {
	policies := []model.Policy{
		{ID: "blocklist", TenantID: model.GlobalTenant, Effect: model.Deny,
			Conditions: []model.Condition{{Attribute: "ip", Operator: model.OpCIDR,
				Prefixes: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}}}},
		{ID: "tenant-grant", TenantID: "tenant-a", Effect: model.Allow},
	}
	eng := New(policies, Config{})

	clean := eng.Evaluate(model.Request{TenantID: "tenant-a",
		IPs: map[string]netip.Addr{"ip": netip.MustParseAddr("10.0.0.1")}})
	if !clean.Allowed {
		t.Fatalf("clean address should be allowed by the tenant grant, got %s", clean)
	}

	blocked := eng.Evaluate(model.Request{TenantID: "tenant-a",
		IPs: map[string]netip.Addr{"ip": netip.MustParseAddr("203.0.113.9")}})
	if blocked.Allowed || blocked.MatchedPolicyID != "blocklist" {
		t.Fatalf("global blocklist must override the tenant grant, got %s", blocked)
	}
}

func TestSharding_UnknownTenantGetsGlobalOnly(t *testing.T) {
	policies := []model.Policy{
		{ID: "global-allow", TenantID: model.GlobalTenant, Effect: model.Allow},
		{ID: "tenant-deny", TenantID: "tenant-a", Effect: model.Deny},
	}
	eng := New(policies, Config{})
	d := eng.Evaluate(model.Request{TenantID: "nonexistent"})
	if !d.Allowed || d.MatchedPolicyID != "global-allow" {
		t.Fatalf("unknown tenant should see global policy only, got %s", d)
	}
}

func TestInScope_CountsOnlyReachablePolicies(t *testing.T) {
	rng := rand.New(rand.NewSource(5))
	corpus := genutil.Generate(genutil.Options{Policies: 2000, Tenants: 20, Global: 10}, rng)
	eng := New(corpus.Policies, Config{})

	scope := eng.InScope(corpus.Tenants[10], corpus.Scopes[0])
	if scope >= eng.TotalPolicies() {
		t.Fatalf("a single tenant scope should reach far fewer than the whole corpus: %d of %d",
			scope, eng.TotalPolicies())
	}
	if scope == 0 {
		t.Fatal("tenant should reach at least the global shard")
	}
}

func TestScoping_IsolatesWithinATenant(t *testing.T) {
	policies := []model.Policy{
		{ID: "billing-only", TenantID: "t", Scope: "billing", Effect: model.Allow},
		{ID: "storage-only", TenantID: "t", Scope: "storage", Effect: model.Deny},
		{ID: "tenant-wide", TenantID: "t", Scope: model.TenantWideScope, Effect: model.Allow,
			Conditions: []model.Condition{
				{Attribute: "role", Operator: model.OpEquals, Values: []string{"admin"}}}},
	}
	eng := New(policies, Config{})

	// A billing request must not be denied by a storage-scoped policy.
	billing := eng.Evaluate(model.Request{TenantID: "t", Scope: "billing"})
	if !billing.Allowed || billing.MatchedPolicyID != "billing-only" {
		t.Fatalf("billing scope should see only its own policy, got %s", billing)
	}

	storage := eng.Evaluate(model.Request{TenantID: "t", Scope: "storage"})
	if storage.Allowed {
		t.Fatalf("storage scope should hit its own deny, got %s", storage)
	}
}

func TestScoping_TenantWideAppliesToEveryScope(t *testing.T) {
	policies := []model.Policy{
		{ID: "wide-deny", TenantID: "t", Scope: model.TenantWideScope, Effect: model.Deny},
		{ID: "scoped-allow", TenantID: "t", Scope: "billing", Effect: model.Allow},
	}
	eng := New(policies, Config{})
	d := eng.Evaluate(model.Request{TenantID: "t", Scope: "billing"})
	if d.Allowed || d.MatchedPolicyID != "wide-deny" {
		t.Fatalf("a tenant-wide deny must reach every scope, got %s", d)
	}
}

func TestScoping_ShrinksTheWorstCaseShard(t *testing.T) {
	// The point of scoping: the largest tenant's per-request working set must
	// be a fraction of that tenant's total policy count, not all of it.
	rng := rand.New(rand.NewSource(8))
	corpus := genutil.Generate(genutil.Options{
		Policies: 100_000, Tenants: 1_000, Global: 20}, rng)
	eng := New(corpus.Policies, Config{})

	whale := corpus.Tenants[0]
	whaleTotal := 0
	for _, p := range corpus.Policies {
		if p.TenantID == whale {
			whaleTotal++
		}
	}

	worst := 0
	for _, sc := range corpus.Scopes {
		if n := eng.InScope(whale, sc); n > worst {
			worst = n
		}
	}
	if worst >= whaleTotal/2 {
		t.Fatalf("scoping should cut the whale's working set well below half: %d of %d",
			worst, whaleTotal)
	}
}

func TestEmptyCorpus_DefaultDeny(t *testing.T) {
	eng := New(nil, Config{})
	if d := eng.Evaluate(model.Request{TenantID: "x"}); d.Allowed {
		t.Fatalf("empty corpus must deny, got %s", d)
	}
}

// --- Obligations ------------------------------------------------------------

func TestObligationsSurviveTheFastPath(t *testing.T) {
	policies := []model.Policy{{
		ID: "p", TenantID: "t", Effect: model.Allow,
		Obligations: []string{"require_mfa", "audit_log"},
		Conditions: []model.Condition{
			{Attribute: "role", Operator: model.OpEquals, Values: []string{"admin"}}},
	}}
	eng := New(policies, Config{})
	d := eng.Evaluate(model.Request{TenantID: "t",
		Attributes: map[string]string{"role": "admin"}})
	if len(d.Obligations) != 2 {
		t.Fatalf("obligations must survive indexing, got %v", d.Obligations)
	}
}

// --- Cache ------------------------------------------------------------------

func TestCache_HitReturnsSameDecision(t *testing.T) {
	rng := rand.New(rand.NewSource(21))
	corpus := genutil.Generate(genutil.Options{Policies: 500, Tenants: 4, Global: 8}, rng)
	eng := New(corpus.Policies, Config{CacheSize: 1024})

	req := corpus.GenerateRequest(rng)
	first := eng.Evaluate(req)
	if first.CacheHit {
		t.Fatal("first evaluation cannot be a cache hit")
	}
	second := eng.Evaluate(req)
	if !second.CacheHit {
		t.Fatal("second evaluation of an identical request should hit")
	}
	if first.Allowed != second.Allowed || first.MatchedPolicyID != second.MatchedPolicyID {
		t.Fatalf("cache changed the decision: %s vs %s", first, second)
	}
}

func TestCache_NeverServesAcrossDifferentRequests(t *testing.T) {
	// The cache verifies the full request on hit rather than trusting the
	// hash. A collision handing one subject another's decision would be an
	// authorization bug, so this drives many distinct requests through a
	// deliberately tiny cache to force heavy slot contention.
	rng := rand.New(rand.NewSource(33))
	corpus := genutil.Generate(genutil.Options{Policies: 600, Tenants: 6, Global: 10}, rng)
	cached := New(corpus.Policies, Config{CacheSize: 8})
	uncached := New(corpus.Policies, Config{})

	for i := 0; i < 3000; i++ {
		req := corpus.GenerateRequest(rng)
		want := uncached.Evaluate(req)
		got := cached.Evaluate(req)
		// Both sides are the same engine, so here the credited policy must
		// agree too — a divergence means the cache served another request's
		// entry, which is exactly the failure this test exists to catch.
		if want.Allowed != got.Allowed || want.MatchedPolicyID != got.MatchedPolicyID {
			t.Fatalf("iteration %d: cache served a wrong decision\n want: %s\n got:  %s\n request: %+v",
				i, want, got, req)
		}
	}
}

func TestCache_KeyIsOrderIndependent(t *testing.T) {
	// Go randomizes map iteration order, so the same logical request must
	// hash identically across calls or the cache would never hit.
	req := model.Request{
		TenantID: "t",
		Attributes: map[string]string{
			"a": "1", "b": "2", "c": "3", "d": "4", "e": "5", "f": "6"},
		Numeric: map[string]float64{"n1": 1, "n2": 2},
		IPs:     map[string]netip.Addr{"ip": netip.MustParseAddr("10.0.0.1")},
	}
	first := hashRequest(req)
	for i := 0; i < 200; i++ {
		if got := hashRequest(req); got != first {
			t.Fatalf("hash is not stable across calls: %d vs %d", first, got)
		}
	}
}

func TestCache_DistinguishesNearIdenticalRequests(t *testing.T) {
	policies := []model.Policy{
		{ID: "allow-admin", TenantID: "t", Effect: model.Allow, Conditions: []model.Condition{
			{Attribute: "role", Operator: model.OpEquals, Values: []string{"admin"}}}},
	}
	eng := New(policies, Config{CacheSize: 512})

	admin := eng.Evaluate(model.Request{TenantID: "t",
		Attributes: map[string]string{"role": "admin"}})
	viewer := eng.Evaluate(model.Request{TenantID: "t",
		Attributes: map[string]string{"role": "viewer"}})

	if !admin.Allowed {
		t.Fatal("admin should be allowed")
	}
	if viewer.Allowed {
		t.Fatal("viewer must not inherit the admin decision from the cache")
	}
}

func TestCache_DoesNotAliasCallerMaps(t *testing.T) {
	// Callers routinely reuse request maps. If the cache retained a reference
	// instead of copying, a later mutation would corrupt the stored key and
	// start serving the wrong decisions.
	policies := []model.Policy{
		{ID: "allow-admin", TenantID: "t", Effect: model.Allow, Conditions: []model.Condition{
			{Attribute: "role", Operator: model.OpEquals, Values: []string{"admin"}}}},
	}
	eng := New(policies, Config{CacheSize: 512})

	attrs := map[string]string{"role": "admin"}
	req := model.Request{TenantID: "t", Attributes: attrs}
	if d := eng.Evaluate(req); !d.Allowed {
		t.Fatal("expected admin to be allowed")
	}

	attrs["role"] = "viewer" // caller mutates the map it still owns
	if d := eng.Evaluate(model.Request{TenantID: "t",
		Attributes: map[string]string{"role": "viewer"}}); d.Allowed {
		t.Fatal("mutating the caller's map must not corrupt the cached key")
	}
}

// --- Concurrency ------------------------------------------------------------

// TestConcurrentEvaluation guards the claim that one engine serves many
// request goroutines. Shards are immutable after construction, scratch buffers
// come from a pool, and the cache stripes its locks — this exercises all three
// together under -race.
func TestConcurrentEvaluation(t *testing.T) {
	rng := rand.New(rand.NewSource(77))
	corpus := genutil.Generate(genutil.Options{Policies: 2000, Tenants: 16, Global: 10}, rng)
	eng := New(corpus.Policies, Config{CacheSize: 2048})

	// Precompute expectations single-threaded so the goroutines only read.
	// These come from the same engine: the property under test is that
	// concurrency does not perturb a decision, so any divergence from the
	// serial answer — including which policy is credited — is a real defect.
	const n = 400
	reqs := make([]model.Request, n)
	want := make([]model.Decision, n)
	for i := range reqs {
		reqs[i] = corpus.GenerateRequest(rng)
		want[i] = eng.Evaluate(reqs[i])
	}

	var wg sync.WaitGroup
	errs := make(chan string, 16)
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pass := 0; pass < 5; pass++ {
				for i := range reqs {
					got := eng.Evaluate(reqs[i])
					if got.Allowed != want[i].Allowed ||
						got.MatchedPolicyID != want[i].MatchedPolicyID {
						select {
						case errs <- "concurrent evaluation produced a wrong decision":
						default:
						}
						return
					}
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
}
