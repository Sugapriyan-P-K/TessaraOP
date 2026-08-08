package index

import (
	"testing"

	"github.com/suga/tessaraop/internal/model"
)

// TestCandidates_SetOperatorsAreIndexed is the reason has_any exists in the index
// rather than falling back to full validation.
//
// Once a role hierarchy expands one role into a closure of several, the request
// side carries a set. Matching that with `contains` on a joined string would be
// both wrong and unindexable, so the index splits the request value and unions
// the postings for each element — the mirror of the single-valued lookup.
func TestCandidates_SetOperatorsAreIndexed(t *testing.T) {
	policies := make([]model.Policy, 100)
	for i := range policies {
		want := "viewer"
		if i%10 == 0 {
			want = "admin"
		}
		policies[i] = simple("p", model.Allow,
			model.Condition{Attribute: "subject.roles", Operator: model.OpHasAny,
				Values: []string{want}})
	}
	shard := BuildShard(policies)

	// A principal whose closure holds admin and viewer reaches both groups.
	both := candidateSet(t, shard,
		model.Request{Attributes: map[string]string{"subject.roles": "admin,viewer"}})
	if len(both) != 100 {
		t.Fatalf("a set holding both elements should reach every rule, got %d", len(both))
	}

	// One holding only admin reaches just the ten admin rules — the index really
	// is pruning, not passing everything through.
	adminOnly := candidateSet(t, shard,
		model.Request{Attributes: map[string]string{"subject.roles": "admin"}})
	if len(adminOnly) != 10 {
		t.Fatalf("expected the 10 admin rules, got %d", len(adminOnly))
	}

	// And one holding neither reaches nothing.
	none := candidateSet(t, shard,
		model.Request{Attributes: map[string]string{"subject.roles": "auditor"}})
	if len(none) != 0 {
		t.Fatalf("expected no candidates, got %d", len(none))
	}
}

// TestCandidates_HasAllIsOverInclusive pins the deliberate imprecision. A rule
// requiring {a, b} is registered under both, so a request carrying only a still
// reaches validation — where the exact subset test rejects it. Over-inclusive is
// the contract every filter here honours; under-inclusive would be a wrong answer.
func TestCandidates_HasAllIsOverInclusive(t *testing.T) {
	policies := []model.Policy{simple("needs-both", model.Allow,
		model.Condition{Attribute: "roles", Operator: model.OpHasAll,
			Values: []string{"admin", "auditor"}})}
	shard := BuildShard(policies)

	req := model.Request{Attributes: map[string]string{"roles": "admin"}}

	// The index keeps it...
	if !candidateSet(t, shard, req)[0] {
		t.Fatal("has_all must not be filtered out by a partial match")
	}
	// ...and validation rejects it.
	if policies[0].Rules[0].When.Matches(req) {
		t.Fatal("sanity: has_all requires every element")
	}
}

func TestCandidates_HasNoneRejects(t *testing.T) {
	policies := []model.Policy{simple("not-contractor", model.Allow,
		model.Condition{Attribute: "subject.groups", Operator: model.OpHasNone,
			Values: []string{"contractor"}})}
	shard := BuildShard(policies)

	if candidateSet(t, shard,
		model.Request{Attributes: map[string]string{"subject.groups": "platform,contractor"}})[0] {
		t.Error("has_none must reject a set holding the forbidden element")
	}
	if !candidateSet(t, shard,
		model.Request{Attributes: map[string]string{"subject.groups": "platform,oncall"}})[0] {
		t.Error("has_none must accept a set without it")
	}
	// And the whole-element rule holds at the index too: "subcontractor" is not
	// "contractor".
	if !candidateSet(t, shard,
		model.Request{Attributes: map[string]string{"subject.groups": "subcontractor"}})[0] {
		t.Error("has_none must not reject on a substring")
	}
}

// TestCandidates_SetOperatorsRespectNonParticipants is the noCondition property
// for the new family: a rule placing no set condition on the attribute must never
// be filtered out by one.
func TestCandidates_SetOperatorsRespectNonParticipants(t *testing.T) {
	policies := []model.Policy{
		simple("wants-admin", model.Allow,
			model.Condition{Attribute: "roles", Operator: model.OpHasAny,
				Values: []string{"admin"}}),
		simple("indifferent", model.Deny),
	}
	got := candidateSet(t, BuildShard(policies),
		model.Request{Attributes: map[string]string{"roles": "viewer"}})

	if got[0] {
		t.Error("the conditioned rule should have been pruned")
	}
	if !got[1] {
		t.Error("a rule with no set condition must always survive")
	}
}

// TestShardEvaluate_SetOperatorsAgreeWithFullScan drives the operators through
// the whole two-tier path against the reference implementation.
func TestShardEvaluate_SetOperatorsAgreeWithFullScan(t *testing.T) {
	policies := []model.Policy{
		simple("a", model.Allow, model.Condition{Attribute: "roles",
			Operator: model.OpHasAny, Values: []string{"admin", "auditor"}}),
		simple("b", model.Deny, model.Condition{Attribute: "roles",
			Operator: model.OpHasAll, Values: []string{"admin", "editor"}}),
		simple("c", model.Allow, model.Condition{Attribute: "groups",
			Operator: model.OpHasNone, Values: []string{"contractor"}}),
	}
	shard := BuildShard(policies)
	sc := NewScratch()

	values := []string{"", "admin", "admin,editor", "auditor", "viewer", "admin,editor,viewer"}
	groups := []string{"", "platform", "contractor", "subcontractor,platform"}

	for _, rv := range values {
		for _, gv := range groups {
			req := model.Request{Attributes: map[string]string{"roles": rv, "groups": gv}}
			var acc model.Accumulator
			acc.Reset(model.DenyOverrides)
			shard.Evaluate(req, sc, &acc)

			got := acc.Resolve()
			want := model.Evaluate(policies, req, model.DenyOverrides)
			if got.Allowed != want.Allowed || got.Effect != want.Effect {
				t.Fatalf("roles=%q groups=%q: indexed %s vs full %s", rv, gv, got, want)
			}
		}
	}
}
