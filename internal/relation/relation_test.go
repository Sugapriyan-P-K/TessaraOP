package relation

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/suga/tessaraop/internal/hierarchy"
	"github.com/suga/tessaraop/internal/model"
)

func ctx() context.Context { return context.Background() }

func TestStatic_DirectTuples(t *testing.T) {
	s := NewStatic().Add(
		Tuple{"user:anne", "owner", "doc:budget"},
		Tuple{"user:anne", "viewer", "doc:budget"},
		Tuple{"user:bob", "viewer", "doc:budget"},
	)

	rels, err := s.Relations(ctx(), "user:anne", "doc:budget")
	if err != nil {
		t.Fatalf("Relations: %v", err)
	}
	if strings.Join(rels, ",") != "owner,viewer" {
		t.Fatalf("got %v", rels)
	}

	// No relationship is an ordinary answer, not an error.
	rels, err = s.Relations(ctx(), "user:carol", "doc:budget")
	if err != nil {
		t.Fatalf("Relations: %v", err)
	}
	if len(rels) != 0 {
		t.Fatalf("expected no relations, got %v", rels)
	}
}

// TestStatic_ObjectContainment is the case that makes ReBAC worth having: Anne
// can view the document because she can view the folder it lives in, and nobody
// wrote a tuple for the document.
func TestStatic_ObjectContainment(t *testing.T) {
	objects, err := hierarchy.FromMap(map[string][]string{
		"doc:budget":     {"folder:finance"},
		"folder:finance": {"org:acme"},
	})
	if err != nil {
		t.Fatalf("hierarchy: %v", err)
	}

	s := NewStatic().
		WithObjectHierarchy(objects).
		Add(Tuple{"user:anne", "viewer", "folder:finance"})

	rels, err := s.Relations(ctx(), "user:anne", "doc:budget")
	if err != nil {
		t.Fatalf("Relations: %v", err)
	}
	if len(rels) != 1 || rels[0] != "viewer" {
		t.Fatalf("a relation on the folder should cover the document, got %v", rels)
	}

	// And it does not run the other way: a relation on the document must not
	// grant anything on the folder.
	rels, _ = s.Relations(ctx(), "user:anne", "folder:finance")
	if len(rels) != 1 {
		t.Fatalf("expected the direct viewer relation only, got %v", rels)
	}
	s2 := NewStatic().WithObjectHierarchy(objects).
		Add(Tuple{"user:bob", "owner", "doc:budget"})
	if rels, _ := s2.Relations(ctx(), "user:bob", "folder:finance"); len(rels) != 0 {
		t.Fatalf("containment must not run upward, got %v", rels)
	}
}

// TestStatic_SubjectGroups covers the other half: a relation held by a group is
// held by its members, transitively.
func TestStatic_SubjectGroups(t *testing.T) {
	groups, err := hierarchy.FromMap(map[string][]string{
		"user:anne":     {"group:finance"},
		"group:finance": {"group:everyone"},
	})
	if err != nil {
		t.Fatalf("hierarchy: %v", err)
	}

	s := NewStatic().
		WithGroupHierarchy(groups).
		Add(
			Tuple{"group:finance", "editor", "doc:budget"},
			Tuple{"group:everyone", "viewer", "doc:budget"},
		)

	rels, err := s.Relations(ctx(), "user:anne", "doc:budget")
	if err != nil {
		t.Fatalf("Relations: %v", err)
	}
	if strings.Join(rels, ",") != "editor,viewer" {
		t.Fatalf("expected both the direct and transitive group relations, got %v", rels)
	}

	// A user outside the groups gets nothing.
	if rels, _ := s.Relations(ctx(), "user:stranger", "doc:budget"); len(rels) != 0 {
		t.Fatalf("expected none, got %v", rels)
	}
}

func TestStatic_GroupsAndContainmentTogether(t *testing.T) {
	objects, _ := hierarchy.FromMap(map[string][]string{"doc:x": {"folder:f"}})
	groups, _ := hierarchy.FromMap(map[string][]string{"user:anne": {"group:g"}})

	s := NewStatic().
		WithObjectHierarchy(objects).
		WithGroupHierarchy(groups).
		Add(Tuple{"group:g", "viewer", "folder:f"})

	// Anne is in g; g can view folder f; doc x is in f. So Anne can view doc x.
	rels, err := s.Relations(ctx(), "user:anne", "doc:x")
	if err != nil {
		t.Fatalf("Relations: %v", err)
	}
	if len(rels) != 1 || rels[0] != "viewer" {
		t.Fatalf("expected viewer through both hops, got %v", rels)
	}
}

func TestMaterialize_RendersTheDelimitedForm(t *testing.T) {
	s := NewStatic().Add(
		Tuple{"user:anne", "viewer", "doc:x"},
		Tuple{"user:anne", "owner", "doc:x"},
	)
	got, err := Materialize(ctx(), s, "user:anne", "doc:x")
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	if got != "owner,viewer" {
		t.Fatalf("got %q", got)
	}

	// Nil resolver and empty identifiers are no-ops rather than errors, so a
	// caller need not branch on whether relationships are configured.
	for _, tc := range []struct {
		r    Resolver
		s, o string
	}{
		{nil, "user:anne", "doc:x"},
		{s, "", "doc:x"},
		{s, "user:anne", ""},
	} {
		if got, err := Materialize(ctx(), tc.r, tc.s, tc.o); err != nil || got != "" {
			t.Errorf("expected an empty no-op, got %q %v", got, err)
		}
	}
}

// TestMaterialize_IsStable matters for the decision cache, which keys on
// attribute values: an unstable ordering would turn one logical request into
// several cache entries.
func TestMaterialize_IsStable(t *testing.T) {
	s := NewStatic().Add(
		Tuple{"u", "zeta", "o"}, Tuple{"u", "alpha", "o"}, Tuple{"u", "mid", "o"},
	)
	first, _ := Materialize(ctx(), s, "u", "o")
	for i := 0; i < 50; i++ {
		got, _ := Materialize(ctx(), s, "u", "o")
		if got != first {
			t.Fatalf("unstable: %q then %q", first, got)
		}
	}
	if first != "alpha,mid,zeta" {
		t.Fatalf("expected sorted output, got %q", first)
	}
}

func TestApply_WritesTheAttribute(t *testing.T) {
	s := NewStatic().Add(Tuple{"user:anne", "owner", "doc:x"})
	req := model.Request{TenantID: "t"}

	if err := Apply(ctx(), s, &req, "user:anne", "doc:x"); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if req.Attributes[SubjectRelations] != "owner" {
		t.Fatalf("got %q", req.Attributes[SubjectRelations])
	}

	// And the result is matchable by the operator it is meant for.
	c := model.Condition{Attribute: SubjectRelations, Operator: model.OpHasAny,
		Values: []string{"owner", "editor"}}
	if !c.Matches(req) {
		t.Error("has_any should match the materialized relations")
	}
}

func TestApply_NoRelationsLeavesAttributeAbsent(t *testing.T) {
	// Absent rather than empty: the engine fails closed on absent attributes,
	// which is the right posture, and an empty string would be a present-but-empty
	// set that reads differently.
	s := NewStatic()
	req := model.Request{TenantID: "t"}
	if err := Apply(ctx(), s, &req, "user:nobody", "doc:x"); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if _, ok := req.Attributes[SubjectRelations]; ok {
		t.Error("no relations should leave the attribute absent")
	}
}

// --- Composition -------------------------------------------------------------

func TestChain_UnionsAnswers(t *testing.T) {
	a := NewStatic().Add(Tuple{"u", "viewer", "o"})
	b := NewStatic().Add(Tuple{"u", "editor", "o"})

	rels, err := Chain{a, b, nil}.Relations(ctx(), "u", "o")
	if err != nil {
		t.Fatalf("Chain: %v", err)
	}
	if strings.Join(rels, ",") != "editor,viewer" {
		t.Fatalf("got %v", rels)
	}
}

// TestChain_FailsWholeOnError pins the deliberate choice. Returning the relations
// gathered so far would narrow access silently, which in an authorization path is
// an outage disguised as a decision.
func TestChain_FailsWholeOnError(t *testing.T) {
	boom := errors.New("store unavailable")
	c := Chain{
		NewStatic().Add(Tuple{"u", "viewer", "o"}),
		ResolverFunc(func(context.Context, string, string) ([]string, error) {
			return nil, boom
		}),
	}
	rels, err := c.Relations(ctx(), "u", "o")
	if !errors.Is(err, boom) {
		t.Fatalf("expected the error to propagate, got %v", err)
	}
	if rels != nil {
		t.Fatalf("a failed chain must return no relations, got %v", rels)
	}
}

func TestWithTimeout(t *testing.T) {
	slow := ResolverFunc(func(c context.Context, _, _ string) ([]string, error) {
		select {
		case <-time.After(2 * time.Second):
			return []string{"too-late"}, nil
		case <-c.Done():
			return nil, c.Err()
		}
	})
	_, err := WithTimeout(slow, 20*time.Millisecond).Relations(ctx(), "u", "o")
	if !errors.Is(err, ErrResolverTimeout) {
		t.Fatalf("expected ErrResolverTimeout, got %v", err)
	}

	fast := ResolverFunc(func(context.Context, string, string) ([]string, error) {
		return []string{"viewer"}, nil
	})
	rels, err := WithTimeout(fast, time.Second).Relations(ctx(), "u", "o")
	if err != nil || len(rels) != 1 {
		t.Fatalf("a fast resolver should pass through, got %v %v", rels, err)
	}
}

func TestCache(t *testing.T) {
	var calls int
	var mu sync.Mutex
	inner := ResolverFunc(func(context.Context, string, string) ([]string, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		return []string{"viewer"}, nil
	})

	now := time.Now()
	c := NewCache(inner, time.Minute)
	c.now = func() time.Time { return now }

	for i := 0; i < 5; i++ {
		if _, err := c.Relations(ctx(), "u", "o"); err != nil {
			t.Fatalf("Relations: %v", err)
		}
	}
	if calls != 1 {
		t.Fatalf("expected one underlying call, got %d", calls)
	}

	// Past the TTL it resolves again: a cached relationship is a stale
	// authorization decision, so entries must actually expire.
	now = now.Add(2 * time.Minute)
	if _, err := c.Relations(ctx(), "u", "o"); err != nil {
		t.Fatalf("Relations: %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected a refresh after the TTL, got %d calls", calls)
	}

	// A different pair is a different entry.
	_, _ = c.Relations(ctx(), "u", "other")
	if c.Len() != 2 {
		t.Fatalf("expected two entries, got %d", c.Len())
	}
}

func TestCache_DoesNotCacheErrors(t *testing.T) {
	// Caching a failure would extend an outage past its cause.
	var calls int
	inner := ResolverFunc(func(context.Context, string, string) ([]string, error) {
		calls++
		return nil, errors.New("down")
	})
	c := NewCache(inner, time.Minute)
	for i := 0; i < 3; i++ {
		if _, err := c.Relations(ctx(), "u", "o"); err == nil {
			t.Fatal("expected an error")
		}
	}
	if calls != 3 {
		t.Fatalf("errors must not be cached, got %d calls", calls)
	}
}

func TestStatic_ConcurrentReadsAndWrites(t *testing.T) {
	s := NewStatic()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); s.Add(Tuple{"u", "viewer", "o"}) }()
		go func() { defer wg.Done(); _, _ = s.Relations(ctx(), "u", "o") }()
	}
	wg.Wait()
	if s.Size() != 1 {
		t.Fatalf("expected one pair, got %d", s.Size())
	}
}

// TestEndToEnd_RelationshipPolicy is the point of the package: a policy written
// against relations, evaluated through the ordinary engine path.
func TestEndToEnd_RelationshipPolicy(t *testing.T) {
	objects, _ := hierarchy.FromMap(map[string][]string{"doc:budget": {"folder:finance"}})
	groups, _ := hierarchy.FromMap(map[string][]string{"user:anne": {"group:finance"}})

	resolver := NewStatic().
		WithObjectHierarchy(objects).
		WithGroupHierarchy(groups).
		Add(Tuple{"group:finance", "editor", "folder:finance"})

	policies := []model.Policy{{
		ID: "doc-access", TenantID: "acme",
		Rules: []model.Rule{{
			ID: "editors-may-write", Effect: model.Allow,
			When: model.AllOf(
				model.Condition{Attribute: SubjectRelations, Operator: model.OpHasAny,
					Values: []string{"owner", "editor"}},
				model.Condition{Attribute: "action", Operator: model.OpEquals,
					Values: []string{"write"}},
			),
		}},
	}}

	build := func(user string) model.Request {
		req := model.Request{TenantID: "acme",
			Attributes: map[string]string{"action": "write"}}
		if err := Apply(ctx(), resolver, &req, user, "doc:budget"); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		return req
	}

	// Anne reaches editor on the document through her group and the folder.
	if d := model.Evaluate(policies, build("user:anne"), model.DenyOverrides); !d.Allowed {
		t.Fatalf("anne should be allowed: %s", d)
	}
	// A stranger has no relationship, so the attribute is absent and the rule
	// fails closed.
	if d := model.Evaluate(policies, build("user:stranger"), model.DenyOverrides); d.Allowed {
		t.Fatalf("a stranger must be denied: %s", d)
	}
}
