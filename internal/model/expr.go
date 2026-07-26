package model

// ConditionExpr is a boolean expression over Conditions: the predicate a Rule
// fires on.
//
// v1 held a flat `[]Condition` that was implicitly AND-ed. That cannot express
// the shape most real security policy takes — "(role is admin OR role is
// security-admin) AND NOT department is contractor" — and forcing authors to
// expand it into a cross product of AND-only rules multiplies the corpus and
// makes the resulting policies unreviewable. So the predicate is a tree.
//
// The zero value is not meaningful; build trees with Cond, And, Or and Not. A
// nil *ConditionExpr matches everything, which is how a catch-all rule
// (default-deny backstop, blanket grant) is expressed.
type ConditionExpr struct {
	Kind ExprKind

	// Cond is the predicate when Kind is ExprLeaf.
	Cond Condition

	// Sub holds the children of And, Or and Not. Not has exactly one.
	Sub []*ConditionExpr
}

// ExprKind tags a node in a condition tree.
type ExprKind uint8

const (
	ExprLeaf ExprKind = iota
	ExprAnd
	ExprOr
	ExprNot
)

func (k ExprKind) String() string {
	switch k {
	case ExprLeaf:
		return "leaf"
	case ExprAnd:
		return "and"
	case ExprOr:
		return "or"
	case ExprNot:
		return "not"
	}
	return "invalid"
}

// Cond wraps a single condition as a leaf node.
func Cond(c Condition) *ConditionExpr {
	return &ConditionExpr{Kind: ExprLeaf, Cond: c}
}

// And returns the conjunction of its arguments. And() with no arguments
// matches everything, mirroring the empty-conjunction convention: a rule with
// nothing to check applies unconditionally.
func And(sub ...*ConditionExpr) *ConditionExpr {
	return &ConditionExpr{Kind: ExprAnd, Sub: sub}
}

// Or returns the disjunction of its arguments. Or() with no arguments matches
// nothing, so an empty disjunction cannot silently grant access.
func Or(sub ...*ConditionExpr) *ConditionExpr {
	return &ConditionExpr{Kind: ExprOr, Sub: sub}
}

// Not returns the negation of e.
func Not(e *ConditionExpr) *ConditionExpr {
	return &ConditionExpr{Kind: ExprNot, Sub: []*ConditionExpr{e}}
}

// AllOf is a convenience for the common flat case: every condition AND-ed.
// It is the direct translation of the pre-Rule `[]Condition` shape.
func AllOf(conds ...Condition) *ConditionExpr {
	sub := make([]*ConditionExpr, len(conds))
	for i := range conds {
		sub[i] = Cond(conds[i])
	}
	return And(sub...)
}

// AnyOf is a convenience for a flat disjunction of conditions.
func AnyOf(conds ...Condition) *ConditionExpr {
	sub := make([]*ConditionExpr, len(conds))
	for i := range conds {
		sub[i] = Cond(conds[i])
	}
	return Or(sub...)
}

// Matches evaluates the tree against a request. A nil expression matches.
//
// Evaluation short-circuits: And stops at the first false child, Or at the
// first true one. Since the index orders nothing about child order, authors
// control cost by putting cheap conditions first — a regex behind an equality
// check runs only when the equality passed.
func (e *ConditionExpr) Matches(req Request) bool {
	if e == nil {
		return true
	}
	switch e.Kind {
	case ExprLeaf:
		return e.Cond.Matches(req)
	case ExprAnd:
		for _, c := range e.Sub {
			if !c.Matches(req) {
				return false
			}
		}
		return true
	case ExprOr:
		for _, c := range e.Sub {
			if c.Matches(req) {
				return true
			}
		}
		return false
	case ExprNot:
		if len(e.Sub) != 1 {
			// A malformed Not cannot be evaluated. Fail closed: report no
			// match, so a broken tree denies rather than grants.
			return false
		}
		return !e.Sub[0].Matches(req)
	}
	return false
}

// ANDSpineLeaves appends every condition that is logically necessary for the
// whole tree to match, and returns the extended slice.
//
// This is the indexing boundary, and it is the one correctness rule in this
// package that is easy to get wrong. Only leaves reachable from the root by
// following *exclusively* And nodes qualify — call that the AND-spine. A leaf
// under an Or is not necessary (its sibling may satisfy the disjunction), and a
// leaf under a Not is required to be false rather than true. Indexing on either
// would let the pre-filter exclude a rule that actually matches, which is the
// one failure mode that turns a fast engine into a wrong one.
//
// Leaves off the spine simply contribute no filter and fall through to exact
// validation: over-inclusive, never under-inclusive, consistent with every
// other index in this codebase. A rule whose root is an Or therefore gets no
// index help at all and is validated on every request that reaches its shard —
// the cost of expressiveness, paid only by the rules that use it.
func (e *ConditionExpr) ANDSpineLeaves(dst []Condition) []Condition {
	if e == nil {
		return dst
	}
	switch e.Kind {
	case ExprLeaf:
		return append(dst, e.Cond)
	case ExprAnd:
		for _, c := range e.Sub {
			dst = c.ANDSpineLeaves(dst)
		}
		return dst
	default: // ExprOr, ExprNot — off the spine, contribute nothing
		return dst
	}
}

// Prepare compiles every regular expression in the tree, reporting the first
// failure. Callers that build policies programmatically should run it once at
// load time; index.BuildShard and the naive evaluator both do so on their own
// inputs, so evaluation never pays for compilation.
func (e *ConditionExpr) Prepare() error {
	if e == nil {
		return nil
	}
	if e.Kind == ExprLeaf {
		return e.Cond.Prepare()
	}
	for _, c := range e.Sub {
		if err := c.Prepare(); err != nil {
			return err
		}
	}
	return nil
}

// Walk calls fn for every node in the tree, parents before children. It stops
// and returns the first error fn reports.
func (e *ConditionExpr) Walk(fn func(*ConditionExpr) error) error {
	if e == nil {
		return nil
	}
	if err := fn(e); err != nil {
		return err
	}
	for _, c := range e.Sub {
		if err := c.Walk(fn); err != nil {
			return err
		}
	}
	return nil
}

// Depth reports the height of the tree. The linter caps it, because an
// unbounded tree submitted by a tenant is a denial-of-service vector against
// every request that reaches its shard.
func (e *ConditionExpr) Depth() int {
	if e == nil {
		return 0
	}
	deepest := 0
	for _, c := range e.Sub {
		if d := c.Depth(); d > deepest {
			deepest = d
		}
	}
	return deepest + 1
}

// CountLeaves reports how many conditions the tree holds.
func (e *ConditionExpr) CountLeaves() int {
	if e == nil {
		return 0
	}
	if e.Kind == ExprLeaf {
		return 1
	}
	n := 0
	for _, c := range e.Sub {
		n += c.CountLeaves()
	}
	return n
}
