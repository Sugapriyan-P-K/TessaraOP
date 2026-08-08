// Package hierarchy resolves transitive membership over a directed acyclic
// graph: role inheritance, group nesting, and resource containment.
//
// # Why this is not part of the engine
//
// It would be natural to add a "role inherits" operator that walked a graph
// during evaluation. That is the wrong place for it, for the same reason package
// ingest does no I/O: the evaluation path is allocation-free and measured in
// microseconds, and a traversal inside it would be neither.
//
// So the closure is computed here, once, and handed to the engine as an ordinary
// attribute. A principal with role "admin" arrives carrying
// subject.roles = "admin,editor,viewer", and an existing indexed operator
// (has_any) answers the question. The engine needs no new concept, the index
// still prunes, and the hot path is untouched.
//
// # Why it is a DAG and not a tree
//
// Real role models are not trees. "on-call engineer" inherits from both
// "engineer" and "incident responder"; a resource belongs to a folder and a
// project. Multiple parents are the normal case, so this is a DAG, and the
// closure of a node is the union over all its ancestors.
//
// # Immutable after Freeze
//
// Freeze detects cycles and precomputes every closure, so a request-time lookup
// is one map read. That mirrors how index shards work: pay at build time, read
// at request time. A Graph must not be mutated after Freeze, and Add reports an
// error if it is.
package hierarchy

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/suga/tessaraop/internal/model"
)

// Graph is a membership DAG: each node names its immediate parents.
//
// "Parent" means "is subsumed by". If admin inherits editor's permissions, admin
// is the child and editor is the parent, and the closure of admin contains
// editor. Getting this direction backwards is the easiest mistake to make here,
// so the tests state it explicitly.
type Graph struct {
	parents map[string][]string
	closure map[string][]string
	frozen  bool
}

// New returns an empty, unfrozen graph.
func New() *Graph {
	return &Graph{parents: make(map[string][]string)}
}

// Add records that child is subsumed by each of parents. It may be called
// repeatedly for the same child; parents accumulate.
//
// Adding after Freeze is a programming error rather than a runtime condition, so
// it panics: a graph that changed under a running engine would silently produce
// closures inconsistent with the ones already computed.
func (g *Graph) Add(child string, parents ...string) *Graph {
	if g.frozen {
		panic("hierarchy: Add after Freeze")
	}
	if child == "" {
		return g
	}
	if _, ok := g.parents[child]; !ok {
		g.parents[child] = nil
	}
	for _, p := range parents {
		if p == "" || p == child {
			// A self-edge is harmless but meaningless: every closure already
			// contains its own node.
			continue
		}
		if _, ok := g.parents[p]; !ok {
			g.parents[p] = nil
		}
		if !containsStr(g.parents[child], p) {
			g.parents[child] = append(g.parents[child], p)
		}
	}
	return g
}

// ErrCycle is returned by Freeze when the graph is not acyclic.
var ErrCycle = errors.New("hierarchy: cycle")

// Freeze validates the graph and precomputes every node's closure.
//
// A cycle is an error rather than something to tolerate. Left in, it would make
// closure computation non-terminating; "handled" by cutting the traversal, it
// would make the closure depend on which node you started from, so two
// principals with the same roles could get different answers. Neither is
// acceptable in an authorization path, and a cycle in a role model is always an
// authoring mistake.
func (g *Graph) Freeze() error {
	if g.frozen {
		return nil
	}

	const (
		white = 0 // unvisited
		grey  = 1 // on the current path
		black = 2 // finished
	)
	colour := make(map[string]int, len(g.parents))
	g.closure = make(map[string][]string, len(g.parents))

	// Iterative-friendly recursive DFS. Depth is bounded by the graph, which is
	// authored by hand and shallow in practice.
	var visit func(node string, path []string) error
	visit = func(node string, path []string) error {
		switch colour[node] {
		case black:
			return nil
		case grey:
			return fmt.Errorf("%w: %s -> %s", ErrCycle,
				strings.Join(append(path, node), " -> "), node)
		}
		colour[node] = grey
		path = append(path, node)

		// A set rather than a slice: a diamond (admin -> a -> base,
		// admin -> b -> base) would otherwise list base twice.
		seen := map[string]bool{node: true}
		acc := []string{node}

		for _, parent := range g.parents[node] {
			if err := visit(parent, path); err != nil {
				return err
			}
			for _, anc := range g.closure[parent] {
				if !seen[anc] {
					seen[anc] = true
					acc = append(acc, anc)
				}
			}
		}

		// Sorted so the joined form is stable. That matters more than it looks:
		// the decision cache keys on attribute values, so an unstable ordering
		// would turn one logical request into several cache entries.
		sort.Strings(acc)
		g.closure[node] = acc
		colour[node] = black
		return nil
	}

	// Sorted iteration so a cycle error names the same path every run.
	nodes := make([]string, 0, len(g.parents))
	for n := range g.parents {
		nodes = append(nodes, n)
	}
	sort.Strings(nodes)

	for _, n := range nodes {
		if err := visit(n, nil); err != nil {
			g.closure = nil
			return err
		}
	}
	g.frozen = true
	return nil
}

// Frozen reports whether Freeze has run successfully.
func (g *Graph) Frozen() bool { return g.frozen }

// Size reports how many distinct nodes the graph holds.
func (g *Graph) Size() int { return len(g.parents) }

// Closure returns the node together with all of its transitive parents, sorted.
//
// An unknown node yields just itself. That is deliberate: a principal carrying a
// role the graph has never heard of should still match policies naming that role
// exactly, rather than vanishing. The alternative — dropping it — would silently
// narrow access on a typo in the graph rather than in the policy.
//
// The returned slice is shared and must not be modified.
func (g *Graph) Closure(node string) []string {
	if c, ok := g.closure[node]; ok {
		return c
	}
	return []string{node}
}

// ClosureOf returns the union of the closures of several nodes, sorted and
// deduplicated.
func (g *Graph) ClosureOf(nodes ...string) []string {
	if len(nodes) == 1 {
		return g.Closure(nodes[0])
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(nodes)*2)
	for _, n := range nodes {
		if n == "" {
			continue
		}
		for _, anc := range g.Closure(n) {
			if !seen[anc] {
				seen[anc] = true
				out = append(out, anc)
			}
		}
	}
	sort.Strings(out)
	return out
}

// Expand returns the closure of a delimited multi-valued attribute value, in the
// same delimited form. This is the shape the engine consumes: pass the result
// straight to a subject.roles or subject.groups attribute and match it with
// has_any / has_all / has_none.
func (g *Graph) Expand(value string) string {
	var nodes []string
	model.ForEachSetMember(value, func(elem string) bool {
		nodes = append(nodes, elem)
		return true
	})
	if len(nodes) == 0 {
		return ""
	}
	return Join(g.ClosureOf(nodes...))
}

// Subsumes reports whether node inherits from ancestor, directly or transitively.
// A node subsumes itself.
func (g *Graph) Subsumes(node, ancestor string) bool {
	return containsStr(g.Closure(node), ancestor)
}

// Join renders elements in the delimited form the engine's set operators read.
func Join(elems []string) string { return strings.Join(elems, string(model.SetDelimiter)) }

// Roots returns nodes with no parents — the top of the hierarchy. Useful for
// rendering a role model and for spotting an accidentally orphaned role.
func (g *Graph) Roots() []string {
	var out []string
	for node, parents := range g.parents {
		if len(parents) == 0 {
			out = append(out, node)
		}
	}
	sort.Strings(out)
	return out
}

// Nodes returns every node, sorted.
func (g *Graph) Nodes() []string {
	out := make([]string, 0, len(g.parents))
	for n := range g.parents {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Parents returns a node's immediate parents, sorted. The returned slice is a
// copy and is safe to modify.
func (g *Graph) Parents(node string) []string {
	p := g.parents[node]
	out := make([]string, len(p))
	copy(out, p)
	sort.Strings(out)
	return out
}

// FromMap builds and freezes a graph from a child -> parents mapping, which is
// the shape a bundle or a configuration file naturally carries.
func FromMap(m map[string][]string) (*Graph, error) {
	g := New()
	// Sorted so a cycle error is reproducible.
	children := make([]string, 0, len(m))
	for child := range m {
		children = append(children, child)
	}
	sort.Strings(children)
	for _, child := range children {
		g.Add(child, m[child]...)
	}
	if err := g.Freeze(); err != nil {
		return nil, err
	}
	return g, nil
}

func containsStr(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
