package analyze

import (
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strings"

	"github.com/suga/tessaraop/internal/model"
)

// An atom is one distinct predicate appearing anywhere in the analysed policy
// set. Atoms become the BDD's boolean variables.
//
// # Why atoms alone are not enough
//
// Mapping each predicate to an independent boolean variable is the obvious move
// and it produces nonsense. `subject.role == "admin"` and
// `subject.role == "viewer"` would be independent variables, so the analyser
// would happily report that a rule requiring both is satisfiable — and every
// pair of mutually exclusive rules would be flagged as a conflict. The tool would
// be noise.
//
// So the atoms carry a *theory*: a set of implications and exclusions between
// them, derived from what the operators actually mean. Those become constraint
// clauses conjoined with every query, so the BDD reasons about attribute
// semantics rather than about opaque booleans.
type atom struct {
	index int // its BDD variable
	cond  model.Condition
	key   string
}

// presence is the synthetic atom "this attribute is present on the request".
//
// It exists because the engine fails closed: every operator except nexists
// requires the attribute, so `role == "admin"` and `role != "admin"` are *both*
// false on a request carrying no role. Without a presence variable those two
// would look like complements, and the analyser would conclude that one of them
// must always hold — which is exactly wrong.
//
// With it, every value atom implies presence, `exists` *is* presence, and
// `nexists` is its negation. The absent case then falls out correctly.
type presence struct {
	index     int
	attribute string
}

// relation is what one atom says about another.
type relation uint8

const (
	relIndependent relation = iota // no derivable relationship
	relImplies                     // a true ⇒ b true
	relExcludes                    // a and b cannot both be true
	relEquivalent                  // a ⇔ b
)

// theory holds the atoms, their presence variables, and the constraint BDD
// expressing everything derivable about how they relate.
type theory struct {
	b *bdd

	atoms     []*atom
	byKey     map[string]*atom
	presences map[string]*presence

	// nodes maps a variable index to its BDD node, so building a condition tree
	// is a lookup rather than a construction.
	nodes map[int]nodeID

	constraints nodeID
	nextVar     int

	// pairsChecked counts relation derivations, reported so an operator can see
	// why a large policy set took a while.
	pairsChecked int

	// degraded records that at least one constraint clause could not be built
	// within the node budget, so the theory is *under*-constrained.
	//
	// That direction is safe for the findings that matter: a weaker theory admits
	// more assignments, so a rule can only look more reachable, never less. What
	// it can do is inflate conflict reports and miss shadowing, so the analyser
	// says so rather than presenting partial coverage as complete.
	degraded bool
}

func newTheory(b *bdd) *theory {
	return &theory{
		b:           b,
		byKey:       make(map[string]*atom),
		presences:   make(map[string]*presence),
		nodes:       make(map[int]nodeID),
		constraints: bddTrue,
	}
}

// atomKey canonicalizes a condition so equal predicates share an atom.
func atomKey(c model.Condition) string {
	var sb strings.Builder
	sb.WriteString(c.Attribute)
	sb.WriteByte('|')
	sb.WriteString(string(c.Operator))
	sb.WriteByte('|')

	// Values are sorted for the set-valued operators, where order carries no
	// meaning, and left alone for eq/ne, where only the first is read.
	vals := append([]string(nil), c.Values...)
	switch c.Operator {
	case model.OpEquals, model.OpNotEquals:
		if len(vals) > 1 {
			vals = vals[:1]
		}
	default:
		sort.Strings(vals)
	}
	sb.WriteString(strings.Join(vals, "\x00"))

	sb.WriteByte('|')
	nums := append([]float64(nil), c.Numbers...)
	sort.Float64s(nums)
	for _, n := range nums {
		fmt.Fprintf(&sb, "%g,", n)
	}
	fmt.Fprintf(&sb, "|%g|%g|", c.Min, c.Max)

	prefixes := make([]string, 0, len(c.Prefixes))
	for _, p := range c.Prefixes {
		prefixes = append(prefixes, p.String())
	}
	sort.Strings(prefixes)
	sb.WriteString(strings.Join(prefixes, ","))
	return sb.String()
}

// presenceOf returns the presence variable for an attribute, creating it on first
// use.
func (t *theory) presenceOf(attribute string) (*presence, error) {
	if p, ok := t.presences[attribute]; ok {
		return p, nil
	}
	p := &presence{index: t.nextVar, attribute: attribute}
	t.nextVar++
	node, err := t.b.variableNode(p.index)
	if err != nil {
		return nil, err
	}
	t.nodes[p.index] = node
	t.presences[attribute] = p
	return p, nil
}

// prepare registers every condition up front, assigning variable indices grouped
// by attribute.
//
// # Why the order matters this much
//
// BDD size is famously sensitive to variable ordering, and the constraint set
// here is dominated by *within-attribute* relations: the values of one attribute
// are mutually exclusive, ranges nest, prefixes nest. If those variables are
// scattered through the order — which is what happens when they are numbered in
// the order conditions happen to be encountered — every exclusion clause spans
// the whole diagram and the shared structure explodes.
//
// Grouping an attribute's variables together keeps each clause local. On the
// corpus that first exposed this, the difference was an analysis that exhausted a
// million-node budget versus one that finishes in a few thousand nodes.
//
// Calling this is optional: intern still works on demand. It is simply much
// cheaper to tell the theory what is coming.
func (t *theory) prepare(conds []model.Condition) {
	byAttribute := map[string][]model.Condition{}
	var order []string
	for _, c := range conds {
		if _, seen := byAttribute[c.Attribute]; !seen {
			order = append(order, c.Attribute)
		}
		byAttribute[c.Attribute] = append(byAttribute[c.Attribute], c)
	}
	// Sorted so a run is reproducible regardless of map iteration.
	sort.Strings(order)

	for _, attribute := range order {
		// The presence variable leads its attribute's block: every value atom
		// implies it, so keeping it adjacent keeps those clauses two levels deep.
		if _, err := t.presenceOf(attribute); err != nil {
			t.degraded = true
			return
		}
		// Deterministic atom order within the attribute.
		group := byAttribute[attribute]
		sort.Slice(group, func(i, j int) bool {
			return atomKey(group[i]) < atomKey(group[j])
		})
		for _, c := range group {
			if _, err := t.intern(c); err != nil {
				t.degraded = true
				return
			}
		}
	}
}

// intern returns the BDD node for a condition, registering a new atom if needed
// and extending the constraint set with everything derivable about it.
func (t *theory) intern(c model.Condition) (nodeID, error) {
	p, err := t.presenceOf(c.Attribute)
	if err != nil {
		return bddFalse, err
	}

	// exists and nexists are presence itself, not separate variables. Giving them
	// their own would require constraints to tie them back, and there is nothing
	// to gain from the indirection.
	switch c.Operator {
	case model.OpExists:
		return t.nodes[p.index], nil
	case model.OpNotExists:
		return t.b.not(t.nodes[p.index])
	}

	key := atomKey(c)
	if a, ok := t.byKey[key]; ok {
		return t.nodes[a.index], nil
	}

	a := &atom{index: t.nextVar, cond: c, key: key}
	t.nextVar++
	node, err := t.b.variableNode(a.index)
	if err != nil {
		return bddFalse, err
	}
	t.nodes[a.index] = node
	t.byKey[key] = a

	// Every value atom requires its attribute to be present.
	if err := t.addImplication(node, t.nodes[p.index]); err != nil {
		return bddFalse, err
	}

	// Relate it to every existing atom on the same attribute. Atoms on different
	// attributes are independent, so only the same-attribute set is walked.
	for _, other := range t.atoms {
		if other.cond.Attribute != c.Attribute {
			continue
		}
		t.pairsChecked++

		// Both directions are evaluated, because relate is not symmetric and each
		// direction carries a different fact. Implication is directional by
		// nature; exclusion is symmetric but only *derivable* from one side —
		// `eq "/public/docs"` excludes `regex ^/admin/` because the one possible
		// value fails the pattern, while the reverse comparison has no finite
		// domain to test and yields nothing. Checking only the forward direction
		// silently dropped exclusions like that one.
		forward := relate(a.cond, other.cond)
		reverse := relate(other.cond, a.cond)
		otherNode := t.nodes[other.index]

		if forward == relEquivalent || reverse == relEquivalent {
			err = t.addEquivalence(node, otherNode)
		} else if forward == relExcludes || reverse == relExcludes {
			err = t.addExclusion(node, otherNode)
		} else {
			if forward == relImplies {
				err = t.addImplication(node, otherNode)
			}
			if err == nil && reverse == relImplies {
				err = t.addImplication(otherNode, node)
			}
		}
		if err != nil {
			// The clause was dropped and the theory marked degraded, which leaves
			// it under-constrained — safe. Keep going rather than abandoning the
			// remaining relations, which are still worth having.
			err = nil
		}
	}

	t.atoms = append(t.atoms, a)
	return node, nil
}

// conjoin adds a clause to the constraint set, transactionally.
//
// The transactional part is not fastidiousness, it is the fix for a real bug. mk
// returns bddFalse alongside its error when the node budget is exhausted, and
// bddFalse is a perfectly valid node — so a caller that assigned the result
// before checking the error would set the constraint set to *false*. Every rule
// in the shard then looks unreachable, which is the single worst wrong answer
// this package can give: it tells an operator to delete rules that work.
//
// So the new value is computed into a local and only committed on success. A
// clause that cannot be built is dropped and the theory marked degraded, which
// leaves it under-constrained — the safe direction.
func (t *theory) conjoin(clause nodeID, err error) error {
	if err != nil {
		t.degraded = true
		return err
	}
	next, err := t.b.and(t.constraints, clause)
	if err != nil {
		t.degraded = true
		return err
	}
	t.constraints = next
	return nil
}

func (t *theory) addImplication(from, to nodeID) error {
	notFrom, err := t.b.not(from)
	if err != nil {
		t.degraded = true
		return err
	}
	return t.conjoin(t.b.or(notFrom, to))
}

func (t *theory) addExclusion(x, y nodeID) error {
	conj, err := t.b.and(x, y)
	if err != nil {
		t.degraded = true
		return err
	}
	return t.conjoin(t.b.not(conj))
}

func (t *theory) addEquivalence(x, y nodeID) error {
	if err := t.addImplication(x, y); err != nil {
		return err
	}
	return t.addImplication(y, x)
}

// --- Deriving relations ------------------------------------------------------

// relate reports what condition a says about condition b, on the same attribute.
//
// It is deliberately *incomplete*: when nothing can be derived it returns
// relIndependent rather than guessing. That direction is the safe one. Missing an
// exclusion means the analyser thinks two rules might both fire when they cannot,
// so it may report a conflict that is not real — noise. Inventing an exclusion
// would mean declaring a live rule unreachable, and somebody would delete it.
func relate(a, b model.Condition) relation {
	if a.Attribute != b.Attribute {
		return relIndependent
	}
	if a.Operator == b.Operator && atomKey(a) == atomKey(b) {
		return relEquivalent
	}

	// The strongest technique available: when one side admits only finitely many
	// values, test each of them against the other using the engine's own
	// Condition.Matches.
	//
	// This is exact, and it reuses the evaluator rather than reimplementing
	// operator semantics — so the analyser cannot drift from what the engine
	// actually does. It also decides pairs no structural rule could, including
	// anything involving regex or contains.
	if values, ok := finiteDomain(a); ok {
		all, none := true, true
		for _, v := range values {
			if satisfies(b, a.Attribute, v) {
				none = false
			} else {
				all = false
			}
		}
		switch {
		case none:
			return relExcludes
		case all:
			return relImplies
		default:
			return relIndependent
		}
	}

	// Neither side is finite: fall back to structural reasoning per family.
	switch a.Operator.Family() {
	case model.FamilyNumeric:
		return relateNumeric(a, b)
	case model.FamilyNetwork:
		return relateNetwork(a, b)
	case model.FamilyString:
		return relateString(a, b)
	}
	return relIndependent
}

// finiteDomain returns the complete set of values satisfying a condition, when
// there is one.
func finiteDomain(c model.Condition) ([]typedValue, bool) {
	switch c.Operator {
	case model.OpEquals:
		if len(c.Values) == 0 {
			return nil, false
		}
		return []typedValue{{str: c.Values[0], kind: kindString}}, true
	case model.OpIn:
		if len(c.Values) == 0 {
			return nil, false
		}
		out := make([]typedValue, 0, len(c.Values))
		for _, v := range c.Values {
			out = append(out, typedValue{str: v, kind: kindString})
		}
		return out, true
	case model.OpNumEquals:
		return []typedValue{{num: c.Min, kind: kindNumeric}}, true
	case model.OpNumIn:
		if len(c.Numbers) == 0 {
			return nil, false
		}
		out := make([]typedValue, 0, len(c.Numbers))
		for _, n := range c.Numbers {
			out = append(out, typedValue{num: n, kind: kindNumeric})
		}
		return out, true
	}
	return nil, false
}

type valueKind uint8

const (
	kindString valueKind = iota
	kindNumeric
)

type typedValue struct {
	str  string
	num  float64
	kind valueKind
}

// satisfies evaluates a condition against a single concrete value, using the
// engine's own matcher.
func satisfies(c model.Condition, attribute string, v typedValue) bool {
	req := model.Request{}
	switch v.kind {
	case kindNumeric:
		req.Numeric = map[string]float64{attribute: v.num}
	default:
		req.Attributes = map[string]string{attribute: v.str}
	}
	// A condition reading a different map than the value occupies cannot match,
	// which is exactly what Matches reports, so no special case is needed.
	return c.Matches(req)
}

// --- Numeric ----------------------------------------------------------------

// span is a closed-or-open interval on the reals.
type span struct {
	lo, hi         float64
	loOpen, hiOpen bool
}

func (s span) empty() bool {
	if s.lo > s.hi {
		return true
	}
	return s.lo == s.hi && (s.loOpen || s.hiOpen)
}

// numericSpans converts a numeric condition to the set of values satisfying it.
// Returns false when the operator is not one this can model.
func numericSpans(c model.Condition) ([]span, bool) {
	inf := math.Inf(1)
	switch c.Operator {
	case model.OpRange:
		return []span{{lo: c.Min, hi: c.Max}}, true
	case model.OpNotRange:
		return []span{
			{lo: -inf, hi: c.Min, hiOpen: true},
			{lo: c.Max, hi: inf, loOpen: true},
		}, true
	case model.OpGreaterThan:
		return []span{{lo: c.Min, hi: inf, loOpen: true}}, true
	case model.OpGreaterEq:
		return []span{{lo: c.Min, hi: inf}}, true
	case model.OpLessThan:
		return []span{{lo: -inf, hi: c.Max, hiOpen: true}}, true
	case model.OpLessEq:
		return []span{{lo: -inf, hi: c.Max}}, true
	case model.OpNumEquals:
		return []span{{lo: c.Min, hi: c.Min}}, true
	case model.OpNumNotEq:
		return []span{
			{lo: -inf, hi: c.Min, hiOpen: true},
			{lo: c.Min, hi: inf, loOpen: true},
		}, true
	case model.OpNumIn:
		out := make([]span, 0, len(c.Numbers))
		for _, n := range c.Numbers {
			out = append(out, span{lo: n, hi: n})
		}
		return out, true
	}
	return nil, false
}

func relateNumeric(a, b model.Condition) relation {
	as, ok := numericSpans(a)
	if !ok {
		return relIndependent
	}
	bs, ok := numericSpans(b)
	if !ok {
		return relIndependent
	}

	if disjoint(as, bs) {
		return relExcludes
	}
	if subset(as, bs) {
		return relImplies
	}
	return relIndependent
}

func overlaps(x, y span) bool {
	lo, loOpen := x.lo, x.loOpen
	if y.lo > lo || (y.lo == lo && y.loOpen) {
		lo, loOpen = y.lo, y.loOpen
	}
	hi, hiOpen := x.hi, x.hiOpen
	if y.hi < hi || (y.hi == hi && y.hiOpen) {
		hi, hiOpen = y.hi, y.hiOpen
	}
	return !span{lo: lo, hi: hi, loOpen: loOpen, hiOpen: hiOpen}.empty()
}

func disjoint(as, bs []span) bool {
	for _, x := range as {
		for _, y := range bs {
			if overlaps(x, y) {
				return false
			}
		}
	}
	return true
}

// contains reports whether every value in x also lies in y.
func contains(y, x span) bool {
	loOK := y.lo < x.lo || (y.lo == x.lo && (!y.loOpen || x.loOpen))
	hiOK := y.hi > x.hi || (y.hi == x.hi && (!y.hiOpen || x.hiOpen))
	return loOK && hiOK
}

// subset reports whether every span in as lies within some single span of bs.
//
// Checking against one span at a time under-approximates: a span split across two
// adjacent spans of bs would be missed. That is the safe direction — it reports
// relIndependent instead of relImplies, so the analyser misses a redundancy
// rather than inventing one.
func subset(as, bs []span) bool {
	for _, x := range as {
		covered := false
		for _, y := range bs {
			if contains(y, x) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

// --- Network ----------------------------------------------------------------

func relateNetwork(a, b model.Condition) relation {
	// Only the positive form is modelled structurally. ncidr is a complement, and
	// reasoning about complements of prefix unions is more machinery than the
	// payoff justifies — it falls through to independent, which is safe.
	if a.Operator != model.OpCIDR || b.Operator != model.OpCIDR {
		if a.Operator == model.OpCIDR && b.Operator == model.OpNotCIDR &&
			samePrefixSet(a.Prefixes, b.Prefixes) {
			return relExcludes
		}
		return relIndependent
	}

	// a implies b when every prefix of a sits inside some prefix of b.
	implies := true
	for _, pa := range a.Prefixes {
		inside := false
		for _, pb := range b.Prefixes {
			if prefixContains(pb, pa) {
				inside = true
				break
			}
		}
		if !inside {
			implies = false
			break
		}
	}
	if implies && len(a.Prefixes) > 0 {
		return relImplies
	}

	// Exclusive when no prefix of a overlaps any prefix of b.
	for _, pa := range a.Prefixes {
		for _, pb := range b.Prefixes {
			if prefixContains(pa, pb) || prefixContains(pb, pa) {
				return relIndependent
			}
		}
	}
	return relExcludes
}

// prefixContains reports whether outer covers every address in inner.
func prefixContains(outer, inner netip.Prefix) bool {
	if outer.Addr().Is4() != inner.Addr().Is4() {
		return false
	}
	if outer.Bits() > inner.Bits() {
		return false
	}
	return outer.Contains(inner.Masked().Addr())
}

func samePrefixSet(a, b []netip.Prefix) bool {
	if len(a) != len(b) || len(a) == 0 {
		return false
	}
	as := make([]string, 0, len(a))
	bs := make([]string, 0, len(b))
	for i := range a {
		as = append(as, a[i].String())
		bs = append(bs, b[i].String())
	}
	sort.Strings(as)
	sort.Strings(bs)
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}

// --- String affixes ----------------------------------------------------------

func relateString(a, b model.Condition) relation {
	// A longer prefix implies a shorter one: everything starting with
	// "/api/v2/admin" also starts with "/api".
	if a.Operator == model.OpPrefix && b.Operator == model.OpPrefix {
		return affixRelation(a.Values, b.Values, strings.HasPrefix)
	}
	if a.Operator == model.OpSuffix && b.Operator == model.OpSuffix {
		return affixRelation(a.Values, b.Values, strings.HasSuffix)
	}
	// A deeper domain implies a shallower one: api.admin.acme.com is under
	// acme.com.
	if a.Operator == model.OpDNSSuffix && b.Operator == model.OpDNSSuffix {
		return affixRelation(a.Values, b.Values, model.MatchDNSSuffix)
	}
	// has_all implies has_any over the same elements: holding every one of them
	// certainly means holding at least one.
	if a.Operator == model.OpHasAll && b.Operator == model.OpHasAny && len(a.Values) > 0 {
		if subsetOfStrings(b.Values, a.Values) {
			return relImplies
		}
	}
	if a.Operator == model.OpHasAny && b.Operator == model.OpHasNone {
		if sameStringSet(a.Values, b.Values) {
			return relExcludes
		}
	}
	return relIndependent
}

// affixRelation decides whether every value of a is covered by some value of b.
func affixRelation(as, bs []string, covers func(value, pattern string) bool) relation {
	if len(as) == 0 || len(bs) == 0 {
		return relIndependent
	}
	all := true
	for _, av := range as {
		found := false
		for _, bv := range bs {
			if covers(av, bv) {
				found = true
				break
			}
		}
		if !found {
			all = false
			break
		}
	}
	if all {
		return relImplies
	}
	return relIndependent
}

// subsetOfStrings reports whether every element of want appears in have.
func subsetOfStrings(want, have []string) bool {
	if len(want) == 0 {
		return false
	}
	set := make(map[string]bool, len(have))
	for _, h := range have {
		set[h] = true
	}
	for _, w := range want {
		if !set[w] {
			return false
		}
	}
	return true
}

func sameStringSet(a, b []string) bool {
	return len(a) == len(b) && len(a) > 0 &&
		subsetOfStrings(a, b) && subsetOfStrings(b, a)
}

// --- Compiling condition trees ----------------------------------------------

// compile turns a rule's condition tree into a BDD node.
//
// A nil tree is the catch-all rule and compiles to true. The empty-combinator
// conventions match the evaluator exactly: an empty And matches everything, an
// empty Or matches nothing.
func (t *theory) compile(e *model.ConditionExpr) (nodeID, error) {
	if e == nil {
		return bddTrue, nil
	}
	switch e.Kind {
	case model.ExprLeaf:
		return t.intern(e.Cond)

	case model.ExprAnd:
		acc := bddTrue
		for _, sub := range e.Sub {
			node, err := t.compile(sub)
			if err != nil {
				return bddFalse, err
			}
			if acc, err = t.b.and(acc, node); err != nil {
				return bddFalse, err
			}
		}
		return acc, nil

	case model.ExprOr:
		acc := bddFalse
		for _, sub := range e.Sub {
			node, err := t.compile(sub)
			if err != nil {
				return bddFalse, err
			}
			if acc, err = t.b.or(acc, node); err != nil {
				return bddFalse, err
			}
		}
		return acc, nil

	case model.ExprNot:
		if len(e.Sub) != 1 {
			// A malformed Not fails closed in the evaluator, so it is false here.
			return bddFalse, nil
		}
		node, err := t.compile(e.Sub[0])
		if err != nil {
			return bddFalse, err
		}
		return t.b.not(node)
	}
	return bddFalse, nil
}

// satisfiableUnderTheory reports whether a compiled condition can hold given
// everything derivable about the atoms.
func (t *theory) satisfiableUnderTheory(x nodeID) (bool, error) {
	conj, err := t.b.and(t.constraints, x)
	if err != nil {
		return false, err
	}
	return t.b.satisfiable(conj), nil
}

// impliesUnderTheory reports whether x ⇒ y holds given the constraints.
func (t *theory) impliesUnderTheory(x, y nodeID) (bool, error) {
	premise, err := t.b.and(t.constraints, x)
	if err != nil {
		return false, err
	}
	notY, err := t.b.not(y)
	if err != nil {
		return false, err
	}
	counterexample, err := t.b.and(premise, notY)
	if err != nil {
		return false, err
	}
	return !t.b.satisfiable(counterexample), nil
}

// describeSolution renders a satisfying assignment as human-readable conditions,
// so a conflict finding carries a concrete example rather than an assertion.
func (t *theory) describeSolution(assignment map[int]bool) []string {
	if assignment == nil {
		return nil
	}
	byVar := make(map[int]*atom, len(t.atoms))
	for _, a := range t.atoms {
		byVar[a.index] = a
	}
	presenceByVar := make(map[int]*presence, len(t.presences))
	for _, p := range t.presences {
		presenceByVar[p.index] = p
	}

	var out []string
	for index, value := range assignment {
		if a, ok := byVar[index]; ok {
			if value {
				out = append(out, describeCondition(a.cond))
			}
			continue
		}
		if p, ok := presenceByVar[index]; ok && !value {
			out = append(out, fmt.Sprintf("%s is absent", p.attribute))
		}
	}
	sort.Strings(out)
	return out
}

func describeCondition(c model.Condition) string {
	switch c.Operator {
	case model.OpExists:
		return c.Attribute + " is present"
	case model.OpNotExists:
		return c.Attribute + " is absent"
	case model.OpRange, model.OpNotRange:
		return fmt.Sprintf("%s %s [%g, %g]", c.Attribute, c.Operator, c.Min, c.Max)
	case model.OpGreaterThan, model.OpGreaterEq, model.OpNumEquals, model.OpNumNotEq:
		return fmt.Sprintf("%s %s %g", c.Attribute, c.Operator, c.Min)
	case model.OpLessThan, model.OpLessEq:
		return fmt.Sprintf("%s %s %g", c.Attribute, c.Operator, c.Max)
	case model.OpNumIn, model.OpNumNotIn:
		parts := make([]string, len(c.Numbers))
		for i, n := range c.Numbers {
			parts[i] = fmt.Sprintf("%g", n)
		}
		return fmt.Sprintf("%s %s {%s}", c.Attribute, c.Operator, strings.Join(parts, ", "))
	case model.OpCIDR, model.OpNotCIDR:
		parts := make([]string, len(c.Prefixes))
		for i, p := range c.Prefixes {
			parts[i] = p.String()
		}
		return fmt.Sprintf("%s %s %s", c.Attribute, c.Operator, strings.Join(parts, ", "))
	default:
		if len(c.Values) == 1 {
			return fmt.Sprintf("%s %s %q", c.Attribute, c.Operator, c.Values[0])
		}
		return fmt.Sprintf("%s %s {%s}", c.Attribute, c.Operator, strings.Join(c.Values, ", "))
	}
}
