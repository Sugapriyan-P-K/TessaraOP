package analyze

import "fmt"

// A reduced ordered binary decision diagram.
//
// # Why a BDD rather than enumerating cases
//
// The questions this package answers — is this rule reachable, does that rule
// subsume it, can these two ever both fire — are satisfiability questions over
// boolean combinations of predicates. Enumerating attribute values is hopeless:
// the space is infinite for numerics and effectively so for strings.
//
// A BDD represents a boolean function canonically. Two functions are equal
// exactly when their root nodes are identical, so "is this rule unreachable"
// becomes a pointer comparison against the false terminal, and "does A imply B"
// becomes checking that A ∧ ¬B is false. No search, no enumeration.
//
// # Reduced and ordered
//
// *Ordered* means every path from root to leaf tests variables in the same
// order. *Reduced* means two things: a node whose branches are identical is
// replaced by that branch, and structurally identical nodes are shared rather
// than duplicated. Together these make the representation canonical, which is
// what turns equality into a pointer comparison.
//
// Both are enforced by construction in mk: it never returns a redundant node and
// never returns a duplicate.
//
// # The size problem, and why there is a cap
//
// BDD size is exponential in the worst case and highly sensitive to variable
// order. A policy set that happens to hit a bad case would make an analysis run
// hang or exhaust memory, which for a tool people run in CI is unacceptable.
//
// So the builder has a hard node cap. Past it, operations return errBDDTooLarge
// and the analyzer reports "too complex to analyze" for that rule rather than
// producing a wrong answer or no answer at all. Refusing to answer is a fine
// outcome; hanging is not.
type bdd struct {
	// nodes[0] and nodes[1] are the false and true terminals. A terminal's
	// variable index is sentinelVar so it sorts after every real variable.
	nodes  []bddNode
	unique map[bddNode]nodeID

	andMemo map[[2]nodeID]nodeID
	orMemo  map[[2]nodeID]nodeID
	notMemo map[nodeID]nodeID

	maxNodes int
}

type nodeID uint32

type bddNode struct {
	variable  int    // index into the variable order
	low, high nodeID // low = variable false, high = variable true
}

const (
	bddFalse nodeID = 0
	bddTrue  nodeID = 1

	// sentinelVar is the variable index of the terminals, chosen so that
	// comparisons in apply always treat a terminal as "later" than any real
	// variable.
	sentinelVar = int(^uint(0) >> 1)
)

// DefaultMaxNodes bounds a single analysis. Generous enough for realistic policy
// sets, small enough that hitting it fails fast rather than swapping.
const DefaultMaxNodes = 1 << 20

// errBDDTooLarge is returned when construction exceeds the node cap.
var errBDDTooLarge = fmt.Errorf("analyze: condition too complex to analyze within the node budget")

func newBDD(maxNodes int) *bdd {
	if maxNodes <= 0 {
		maxNodes = DefaultMaxNodes
	}
	b := &bdd{
		nodes:    make([]bddNode, 2, 64),
		unique:   make(map[bddNode]nodeID, 64),
		andMemo:  make(map[[2]nodeID]nodeID),
		orMemo:   make(map[[2]nodeID]nodeID),
		notMemo:  make(map[nodeID]nodeID),
		maxNodes: maxNodes,
	}
	b.nodes[bddFalse] = bddNode{variable: sentinelVar}
	b.nodes[bddTrue] = bddNode{variable: sentinelVar}
	return b
}

func (b *bdd) isTerminal(n nodeID) bool { return n == bddFalse || n == bddTrue }

// mk returns the node for (variable, low, high), enforcing both reduction rules.
func (b *bdd) mk(variable int, low, high nodeID) (nodeID, error) {
	// Reduction 1: a node that branches the same way either way is redundant.
	if low == high {
		return low, nil
	}
	key := bddNode{variable: variable, low: low, high: high}

	// Reduction 2: share structurally identical nodes rather than duplicating.
	if id, ok := b.unique[key]; ok {
		return id, nil
	}
	if len(b.nodes) >= b.maxNodes {
		return bddFalse, errBDDTooLarge
	}
	id := nodeID(len(b.nodes))
	b.nodes = append(b.nodes, key)
	b.unique[key] = id
	return id, nil
}

// variableNode returns the BDD for a single variable.
func (b *bdd) variableNode(index int) (nodeID, error) {
	return b.mk(index, bddFalse, bddTrue)
}

// and computes the conjunction.
func (b *bdd) and(x, y nodeID) (nodeID, error) {
	switch {
	case x == bddFalse || y == bddFalse:
		return bddFalse, nil
	case x == bddTrue:
		return y, nil
	case y == bddTrue:
		return x, nil
	case x == y:
		return x, nil
	}
	// Memo keys are normalized on the commutative operators, halving the cache.
	if x > y {
		x, y = y, x
	}
	key := [2]nodeID{x, y}
	if id, ok := b.andMemo[key]; ok {
		return id, nil
	}

	id, err := b.apply(x, y, b.and)
	if err != nil {
		return bddFalse, err
	}
	b.andMemo[key] = id
	return id, nil
}

// or computes the disjunction.
func (b *bdd) or(x, y nodeID) (nodeID, error) {
	switch {
	case x == bddTrue || y == bddTrue:
		return bddTrue, nil
	case x == bddFalse:
		return y, nil
	case y == bddFalse:
		return x, nil
	case x == y:
		return x, nil
	}
	if x > y {
		x, y = y, x
	}
	key := [2]nodeID{x, y}
	if id, ok := b.orMemo[key]; ok {
		return id, nil
	}

	id, err := b.apply(x, y, b.or)
	if err != nil {
		return bddFalse, err
	}
	b.orMemo[key] = id
	return id, nil
}

// apply is the Shannon expansion shared by and/or: split both operands on
// whichever variable comes first in the order, recurse on each branch, and
// rebuild.
func (b *bdd) apply(x, y nodeID, op func(nodeID, nodeID) (nodeID, error)) (nodeID, error) {
	xn, yn := b.nodes[x], b.nodes[y]

	variable := xn.variable
	if yn.variable < variable {
		variable = yn.variable
	}

	xLow, xHigh := x, x
	if xn.variable == variable {
		xLow, xHigh = xn.low, xn.high
	}
	yLow, yHigh := y, y
	if yn.variable == variable {
		yLow, yHigh = yn.low, yn.high
	}

	low, err := op(xLow, yLow)
	if err != nil {
		return bddFalse, err
	}
	high, err := op(xHigh, yHigh)
	if err != nil {
		return bddFalse, err
	}
	return b.mk(variable, low, high)
}

// not computes the negation.
func (b *bdd) not(x nodeID) (nodeID, error) {
	switch x {
	case bddFalse:
		return bddTrue, nil
	case bddTrue:
		return bddFalse, nil
	}
	if id, ok := b.notMemo[x]; ok {
		return id, nil
	}

	n := b.nodes[x]
	low, err := b.not(n.low)
	if err != nil {
		return bddFalse, err
	}
	high, err := b.not(n.high)
	if err != nil {
		return bddFalse, err
	}
	id, err := b.mk(n.variable, low, high)
	if err != nil {
		return bddFalse, err
	}
	b.notMemo[x] = id
	return id, nil
}

// satisfiable reports whether the function can be true. Because the diagram is
// reduced and canonical, this is exactly "is it not the false terminal" — no
// search required.
func (b *bdd) satisfiable(x nodeID) bool { return x != bddFalse }

// tautology reports whether the function is always true.
func (b *bdd) tautology(x nodeID) bool { return x == bddTrue }

// implies reports whether x → y holds for every assignment, which is true
// exactly when x ∧ ¬y is unsatisfiable.
func (b *bdd) implies(x, y nodeID) (bool, error) {
	notY, err := b.not(y)
	if err != nil {
		return false, err
	}
	conj, err := b.and(x, notY)
	if err != nil {
		return false, err
	}
	return conj == bddFalse, nil
}

// equivalent reports whether two functions are the same. Canonicity makes this a
// comparison rather than a proof.
func (b *bdd) equivalent(x, y nodeID) bool { return x == y }

// size reports how many nodes the shared diagram holds, terminals included. It
// is the number to watch when tuning the cap.
func (b *bdd) size() int { return len(b.nodes) }

// anySolution returns one assignment making the function true, or nil when it is
// unsatisfiable.
//
// The analyzer uses it to turn "these two rules conflict" into a concrete
// example, which is the difference between a finding somebody acts on and one
// they ignore. Variables not on the returned path are genuinely irrelevant and
// are omitted rather than given an arbitrary value.
func (b *bdd) anySolution(x nodeID) map[int]bool {
	if x == bddFalse {
		return nil
	}
	out := map[int]bool{}
	for !b.isTerminal(x) {
		n := b.nodes[x]
		// Prefer the branch that keeps the function satisfiable, trying the
		// positive one first so examples read as "these things are true".
		if n.high != bddFalse {
			out[n.variable] = true
			x = n.high
			continue
		}
		out[n.variable] = false
		x = n.low
	}
	return out
}
