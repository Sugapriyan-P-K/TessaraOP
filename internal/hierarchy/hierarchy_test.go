package hierarchy

import (
	"errors"
	"strings"
	"testing"
)

// roleModel is the shape a real role hierarchy takes: a diamond, so the closure
// has to deduplicate, plus an unrelated branch.
//
//	admin ──► editor ──► viewer ──► base
//	  └─────► auditor ─────────────► base
//	security-admin ──► viewer
func roleModel(t *testing.T) *Graph {
	t.Helper()
	g, err := FromMap(map[string][]string{
		"admin":          {"editor", "auditor"},
		"editor":         {"viewer"},
		"viewer":         {"base"},
		"auditor":        {"base"},
		"security-admin": {"viewer"},
	})
	if err != nil {
		t.Fatalf("FromMap: %v", err)
	}
	return g
}

// TestClosure_DirectionIsChildToParent pins the direction, which is the easiest
// thing to get backwards. admin *inherits* editor's permissions, so admin is the
// child and editor is in admin's closure — not the reverse.
func TestClosure_DirectionIsChildToParent(t *testing.T) {
	g := roleModel(t)

	if !g.Subsumes("admin", "viewer") {
		t.Error("admin should subsume viewer")
	}
	if g.Subsumes("viewer", "admin") {
		t.Error("viewer must NOT subsume admin — that would be privilege escalation")
	}
}

func TestClosure_IncludesSelfAndAllAncestors(t *testing.T) {
	g := roleModel(t)

	got := strings.Join(g.Closure("admin"), ",")
	want := "admin,auditor,base,editor,viewer"
	if got != want {
		t.Fatalf("Closure(admin) = %q want %q", got, want)
	}

	if got := strings.Join(g.Closure("base"), ","); got != "base" {
		t.Errorf("a root's closure is just itself, got %q", got)
	}
}

// TestClosure_DiamondDeduplicates covers the reason closures are built with a set
// rather than by concatenation: base is reachable via both editor and auditor.
func TestClosure_DiamondDeduplicates(t *testing.T) {
	g := roleModel(t)
	seen := map[string]int{}
	for _, r := range g.Closure("admin") {
		seen[r]++
	}
	for role, n := range seen {
		if n != 1 {
			t.Errorf("role %q appears %d times in the closure", role, n)
		}
	}
}

// TestClosure_IsSorted matters more than it looks: the delimited form becomes an
// attribute value, and the decision cache keys on attribute values. An unstable
// order would turn one logical request into several cache entries.
func TestClosure_IsSorted(t *testing.T) {
	g := roleModel(t)
	for _, node := range g.Nodes() {
		c := g.Closure(node)
		for i := 1; i < len(c); i++ {
			if c[i-1] >= c[i] {
				t.Fatalf("closure of %q is not sorted: %v", node, c)
			}
		}
	}
}

func TestClosureOf_UnionsSeveralNodes(t *testing.T) {
	g := roleModel(t)
	got := strings.Join(g.ClosureOf("editor", "auditor"), ",")
	want := "auditor,base,editor,viewer"
	if got != want {
		t.Fatalf("ClosureOf(editor, auditor) = %q want %q", got, want)
	}
}

// TestClosure_UnknownNodeYieldsItself is a deliberate choice worth pinning. A
// principal carrying a role the graph never heard of must still match policies
// naming that role exactly; dropping it would narrow access silently on a typo
// in the *graph* rather than in the policy.
func TestClosure_UnknownNodeYieldsItself(t *testing.T) {
	g := roleModel(t)
	got := g.Closure("some-new-role")
	if len(got) != 1 || got[0] != "some-new-role" {
		t.Fatalf("unknown node should yield itself, got %v", got)
	}
}

// TestFreeze_RejectsCycles is the important failure case. A cycle left in would
// make closure computation non-terminating; "handled" by cutting the traversal it
// would make the answer depend on the starting node, so two principals with the
// same roles could get different decisions.
func TestFreeze_RejectsCycles(t *testing.T) {
	cases := map[string]map[string][]string{
		"two-node":   {"a": {"b"}, "b": {"a"}},
		"three-node": {"a": {"b"}, "b": {"c"}, "c": {"a"}},
		"long":       {"a": {"b"}, "b": {"c"}, "c": {"d"}, "d": {"b"}},
	}
	for name, m := range cases {
		if _, err := FromMap(m); err == nil {
			t.Errorf("%s: expected a cycle error", name)
		} else if !errors.Is(err, ErrCycle) {
			t.Errorf("%s: expected ErrCycle, got %v", name, err)
		}
	}
}

func TestFreeze_SelfEdgeIsHarmless(t *testing.T) {
	// A self-edge is meaningless rather than cyclic — every closure already
	// contains its own node — so it must not be reported as a cycle.
	g, err := FromMap(map[string][]string{"a": {"a", "b"}})
	if err != nil {
		t.Fatalf("a self-edge should not be a cycle: %v", err)
	}
	if got := strings.Join(g.Closure("a"), ","); got != "a,b" {
		t.Fatalf("Closure(a) = %q want \"a,b\"", got)
	}
}

func TestFreeze_IsIdempotent(t *testing.T) {
	g := roleModel(t)
	if err := g.Freeze(); err != nil {
		t.Fatalf("second Freeze: %v", err)
	}
	if !g.Frozen() {
		t.Error("graph should report frozen")
	}
}

func TestAdd_AfterFreezePanics(t *testing.T) {
	// A graph mutated under a running engine would produce closures inconsistent
	// with the ones already computed, so this is a programming error.
	defer func() {
		if recover() == nil {
			t.Fatal("expected a panic on Add after Freeze")
		}
	}()
	roleModel(t).Add("late", "viewer")
}

func TestExpand_RoundTripsTheDelimitedForm(t *testing.T) {
	g := roleModel(t)

	if got := g.Expand("editor"); got != "base,editor,viewer" {
		t.Errorf("Expand(editor) = %q", got)
	}
	// Whitespace and empty elements are tolerated on input.
	if got := g.Expand(" editor , , auditor "); got != "auditor,base,editor,viewer" {
		t.Errorf("Expand with untidy input = %q", got)
	}
	if got := g.Expand(""); got != "" {
		t.Errorf("Expand(\"\") = %q want empty", got)
	}
}

func TestRootsAndParents(t *testing.T) {
	g := roleModel(t)
	if got := strings.Join(g.Roots(), ","); got != "base" {
		t.Errorf("Roots = %q want \"base\"", got)
	}
	if got := strings.Join(g.Parents("admin"), ","); got != "auditor,editor" {
		t.Errorf("Parents(admin) = %q", got)
	}
	// The returned slice is a copy.
	p := g.Parents("admin")
	p[0] = "mutated"
	if g.Parents("admin")[0] == "mutated" {
		t.Error("Parents must return a copy")
	}
}

func TestEmptyGraph(t *testing.T) {
	g := New()
	if err := g.Freeze(); err != nil {
		t.Fatalf("freezing an empty graph: %v", err)
	}
	if got := g.Closure("anything"); len(got) != 1 || got[0] != "anything" {
		t.Fatalf("empty graph closure = %v", got)
	}
	if g.Size() != 0 {
		t.Errorf("Size = %d want 0", g.Size())
	}
}

// TestDeepChain checks that a long inheritance chain resolves, since closures are
// computed by recursive DFS.
func TestDeepChain(t *testing.T) {
	const depth = 500
	m := map[string][]string{}
	for i := 0; i < depth; i++ {
		m[nodeName(i)] = []string{nodeName(i + 1)}
	}
	g, err := FromMap(m)
	if err != nil {
		t.Fatalf("FromMap: %v", err)
	}
	if got := len(g.Closure(nodeName(0))); got != depth+1 {
		t.Fatalf("closure of the deepest node has %d entries, want %d", got, depth+1)
	}
}

func nodeName(i int) string {
	return "n" + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26)) + string(rune('a'+(i/676)%26))
}
