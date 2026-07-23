package genutil

import (
	"math/rand"
	"testing"

	"github.com/suga/tessaraop/internal/model"
)

func TestGeneratePolicies_Count(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	policies := GeneratePolicies(500, rng)
	if len(policies) != 500 {
		t.Fatalf("expected 500 policies, got %d", len(policies))
	}
}

func TestGeneratePolicies_ValidEffects(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	policies := GeneratePolicies(1000, rng)
	for _, p := range policies {
		if p.Effect != model.Allow && p.Effect != model.Deny {
			t.Fatalf("invalid effect %q in policy %s", p.Effect, p.ID)
		}
	}
}

func TestGeneratePolicies_Deterministic(t *testing.T) {
	a := GeneratePolicies(100, rand.New(rand.NewSource(99)))
	b := GeneratePolicies(100, rand.New(rand.NewSource(99)))
	for i := range a {
		if a[i].ID != b[i].ID || a[i].Effect != b[i].Effect || len(a[i].Conditions) != len(b[i].Conditions) {
			t.Fatalf("policy %d differs between runs with same seed", i)
		}
	}
}

func TestGenerateRequest_HasExpectedAttributes(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	req := GenerateRequest(rng)
	for _, key := range []string{"department", "resource.sensitivity", "action"} {
		if _, ok := req.Attributes[key]; !ok {
			t.Fatalf("request missing expected attribute %q", key)
		}
	}
	if _, ok := req.Numeric["time.hour"]; !ok {
		t.Fatal("request missing expected numeric attribute time.hour")
	}
}
