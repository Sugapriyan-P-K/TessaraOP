package index

import (
	"math/rand"
	"testing"

	"github.com/suga/tessaraop/internal/model"
)

// candidatesVia runs one specific intersection strategy, bypassing the size
// heuristic, so both paths can be exercised on the same input regardless of
// which one Candidates would pick.
func (s *Shard) candidatesVia(req model.Request, sc *Scratch, wordParallel bool) []int {
	if s.n == 0 {
		return nil
	}
	best := s.collect(req, sc)
	if wordParallel {
		return s.intersectWordParallel(sc, best)
	}
	return s.intersectPerElement(sc, best)
}

func copyInts(in []int) []int {
	out := make([]int, len(in))
	copy(out, in)
	return out
}

// TestIntersectStrategies_Agree pins the two intersection paths together.
//
// They are chosen by a size heuristic, so on any given request only one of them
// runs in production. That makes a divergence between them invisible until the
// corpus grows past the threshold and the answers quietly change — which is the
// worst possible failure mode for an authorization engine. This asserts they
// produce identical candidate sets across randomized corpora spanning every
// operator family and every tree shape.
func TestIntersectStrategies_Agree(t *testing.T) {
	rng := rand.New(rand.NewSource(2024))
	for iter := 0; iter < 150; iter++ {
		policies := randomPolicies(rng, 40)
		shard := BuildShard(policies)
		sc := NewScratch()

		for q := 0; q < 20; q++ {
			req := randomRequest(rng)

			perElement := copyInts(shard.candidatesVia(req, sc, false))
			wordParallel := copyInts(shard.candidatesVia(req, sc, true))

			if len(perElement) != len(wordParallel) {
				t.Fatalf("iter %d q %d: sizes differ, per-element %d vs word-parallel %d\n%v\n%v",
					iter, q, len(perElement), len(wordParallel), perElement, wordParallel)
			}
			for i := range perElement {
				if perElement[i] != wordParallel[i] {
					t.Fatalf("iter %d q %d: differ at %d: per-element %d vs word-parallel %d",
						iter, q, i, perElement[i], wordParallel[i])
				}
			}
		}
	}
}

// TestIntersectStrategies_BothAscending guards the ordering both the two-tier
// walk and the differential tests depend on. Per-element inherits its order from
// the seed's member list; word-parallel from the word scan. Both must be
// ascending, or the contiguous-run grouping in Evaluate would split a policy.
func TestIntersectStrategies_BothAscending(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	policies := randomPolicies(rng, 60)
	shard := BuildShard(policies)
	sc := NewScratch()

	for _, wordParallel := range []bool{false, true} {
		for q := 0; q < 60; q++ {
			got := shard.candidatesVia(randomRequest(rng), sc, wordParallel)
			for i := 1; i < len(got); i++ {
				if got[i] <= got[i-1] {
					t.Fatalf("wordParallel=%v: positions not ascending at %d: %d then %d",
						wordParallel, i, got[i-1], got[i])
				}
			}
		}
	}
}

// TestIntersectWordParallel_NeverExcludesAMatchingRule repeats the core
// never-under-inclusive invariant against the word-parallel path specifically.
// The heuristic means small test corpora would otherwise only ever exercise
// per-element filtering, leaving this path unverified against the property that
// matters most.
func TestIntersectWordParallel_NeverExcludesAMatchingRule(t *testing.T) {
	rng := rand.New(rand.NewSource(31))
	for iter := 0; iter < 120; iter++ {
		policies := randomPolicies(rng, 45)
		shard := BuildShard(policies)
		sc := NewScratch()

		for q := 0; q < 20; q++ {
			req := randomRequest(rng)
			got := map[int]bool{}
			for _, c := range shard.candidatesVia(req, sc, true) {
				got[c] = true
			}
			for pi := range policies {
				for ri := range policies[pi].Rules {
					if !policies[pi].Rules[ri].When.Matches(req) {
						continue
					}
					if pos := rulePos(policies, pi, ri); !got[pos] {
						t.Fatalf("iter %d: word-parallel excluded matching rule %s (pos %d)\nrequest: %+v",
							iter, policies[pi].Rules[ri].ID, pos, req)
					}
				}
			}
		}
	}
}

// TestIntersectWordParallel_HandlesPaddingBits checks a universe that is not a
// multiple of 64. The final word holds bits above the universe, and if the full
// set or a complement left them set, the enumeration would report rule positions
// that do not exist and the two-tier walk would index out of range.
func TestIntersectWordParallel_HandlesPaddingBits(t *testing.T) {
	for _, n := range []int{1, 7, 63, 64, 65, 127, 130} {
		policies := make([]model.Policy, n)
		for i := range policies {
			// No conditions at all, so no filter can enumerate and the seed is the
			// whole universe — the case where padding bits would surface.
			policies[i] = model.Policy{
				ID:    "p",
				Rules: []model.Rule{{ID: "r", Effect: model.Allow}},
			}
		}
		shard := BuildShard(policies)
		got := shard.candidatesVia(model.Request{}, NewScratch(), true)

		if len(got) != n {
			t.Fatalf("n=%d: expected every rule to be a candidate, got %d", n, len(got))
		}
		for _, pos := range got {
			if pos < 0 || pos >= n {
				t.Fatalf("n=%d: enumerated out-of-universe position %d", n, pos)
			}
		}
	}
}

// TestIntersectWordParallel_EmptyResult covers the early exit. Once the
// accumulator is all zero no later filter can revive a rule, so the loop stops —
// and it must stop with an empty slice rather than a stale one from the previous
// request.
func TestIntersectWordParallel_EmptyResult(t *testing.T) {
	policies := []model.Policy{
		simple("wants-admin", model.Allow,
			model.Condition{Attribute: "role", Operator: model.OpEquals, Values: []string{"admin"}}),
		simple("wants-eng", model.Allow,
			model.Condition{Attribute: "dept", Operator: model.OpEquals, Values: []string{"eng"}}),
	}
	shard := BuildShard(policies)
	sc := NewScratch()

	// First a request that matches something, so the scratch holds candidates.
	if got := shard.candidatesVia(
		model.Request{Attributes: map[string]string{"role": "admin"}}, sc, true); len(got) == 0 {
		t.Fatal("expected the admin rule to be a candidate")
	}
	// Then one that matches nothing.
	if got := shard.candidatesVia(
		model.Request{Attributes: map[string]string{"role": "nobody", "dept": "nowhere"}},
		sc, true); len(got) != 0 {
		t.Fatalf("expected no candidates, got %v", got)
	}
}

// TestScratchWords_ReusedWithoutStaleBits checks the word buffers are cleared
// between requests. A stale bit would add a rule the current request's filters
// rejected, which is over-inclusive and so not a wrong decision — but it would
// silently erode the selectivity the whole design rests on.
func TestScratchWords_ReusedWithoutStaleBits(t *testing.T) {
	policies := make([]model.Policy, 200)
	for i := range policies {
		role := "viewer"
		if i%20 == 0 {
			role = "admin"
		}
		policies[i] = simple("p", model.Allow,
			model.Condition{Attribute: "role", Operator: model.OpEquals, Values: []string{role}})
	}
	shard := BuildShard(policies)
	sc := NewScratch()

	for pass := 0; pass < 5; pass++ {
		admin := shard.candidatesVia(
			model.Request{Attributes: map[string]string{"role": "admin"}}, sc, true)
		if len(admin) != 10 {
			t.Fatalf("pass %d: expected 10 admin rules, got %d", pass, len(admin))
		}
		viewer := shard.candidatesVia(
			model.Request{Attributes: map[string]string{"role": "viewer"}}, sc, true)
		if len(viewer) != 190 {
			t.Fatalf("pass %d: expected 190 viewer rules, got %d", pass, len(viewer))
		}
	}
}

// TestCandidates_LargeFlatShardUsesWordParallel documents the case that motivated
// the second strategy: one tenant, no scoping, a large rule universe. The
// heuristic must actually route here, or the fix is dead code.
func TestCandidates_LargeFlatShardUsesWordParallel(t *testing.T) {
	const n = 20000
	policies := make([]model.Policy, n)
	for i := range policies {
		role := "viewer"
		if i%1000 == 0 {
			role = "admin"
		}
		policies[i] = simple("p", model.Allow,
			model.Condition{Attribute: "role", Operator: model.OpEquals, Values: []string{role}})
	}
	shard := BuildShard(policies)
	sc := NewScratch()

	// role=viewer selects most of the shard, so the seed is far above n/32.
	req := model.Request{Attributes: map[string]string{"role": "viewer"}}
	best := shard.collect(req, sc)
	if best < 0 {
		t.Fatal("expected an enumerable filter")
	}
	if seed := sc.filters[best].est; seed <= shard.Size()/wordParallelDivisor {
		t.Fatalf("seed %d should exceed the word-parallel threshold %d",
			seed, shard.Size()/wordParallelDivisor)
	}

	// And the public entry point must agree with the forced path.
	viaPublic := copyInts(shard.Candidates(req, sc))
	viaForced := copyInts(shard.candidatesVia(req, sc, true))
	if len(viaPublic) != len(viaForced) {
		t.Fatalf("public path returned %d candidates, forced word-parallel %d",
			len(viaPublic), len(viaForced))
	}
	for i := range viaPublic {
		if viaPublic[i] != viaForced[i] {
			t.Fatalf("differ at %d: %d vs %d", i, viaPublic[i], viaForced[i])
		}
	}
}
