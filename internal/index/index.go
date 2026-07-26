// Package index builds the per-attribute structures that turn a request into a
// small candidate set, and performs the intersection that produces it.
//
// # The indexed unit is a rule, not a policy
//
// A policy holds many rules and each rule carries its own condition tree, so
// indexing at policy granularity would mean a policy's index entry is the union
// of what all its rules ask for — near-useless as a filter. The universe here is
// therefore the shard's flattened rule list, and a candidate position names a
// rule. Positions are assigned in policy order, which matters: candidate
// positions come back ascending, so all surviving rules of one policy form a
// contiguous run and the two-tier evaluation walks them without a map or an
// allocation.
//
// # Only the AND-spine may be indexed
//
// A rule's conditions are a boolean tree, and only the leaves reachable from the
// root through exclusively And nodes are logically necessary for the rule to
// match. Those are the only ones that may build a filter — see
// model.ConditionExpr.ANDSpineLeaves for why indexing a leaf under an Or or a
// Not would let the pre-filter drop a rule that actually matches. Leaves off the
// spine contribute nothing and fall through to exact validation.
//
// # How a candidate set is derived
//
// Each attribute contributes one or more sub-indexes, one per operator family
// present on it. For a request value v, a sub-index S yields the set of rules
// that pass it:
//
//	pass_S(v) = notParticipating_S ∪ accepted_S(v)
//
// The notParticipating term is the correctness keystone. A rule that places no
// condition of kind S on the attribute must never be filtered out by S — get
// that wrong and the engine returns confidently wrong answers rather than merely
// slow ones.
//
// Negated operators (ne, nin, !cidr) collapse to something much cheaper. For
// them, notParticipating ∪ (participating \ rejected) is just the whole universe
// minus the rejected set, so a negation needs no complement at query time — it
// is simply "reject these, pass everything else".
//
// Substring and regular-expression operators are not indexable at all: there is
// no structure a pre-filter can exploit. They still contribute the requirement
// that their attribute be present, which on real corpora prunes a great deal,
// and then resolve exactly during validation.
//
// # How the intersection runs
//
// v1 AND-ed dense bitsets pairwise, so every step cost O(N/64) no matter how few
// candidates survived; at a million policies that dominated everything and the
// speedup collapsed to 1.1x. Instead this package materializes only the single
// most selective sub-index, then filters that list in place against the
// remaining ones. Cost tracks the surviving candidate count rather than the
// corpus size, and the list only ever shrinks.
package index

import (
	"math"
	"math/bits"
	"sort"

	"github.com/suga/tessaraop/internal/bitset"
	"github.com/suga/tessaraop/internal/matcher"
	"github.com/suga/tessaraop/internal/model"
)

// ruleRef locates one indexed rule inside the shard's policy slice.
//
// int32 rather than int: the pair is 8 bytes instead of 16, so a million-rule
// shard's mapping table halves and the run-detection walk in Evaluate touches
// half the cache lines. Two billion rules per shard is not a limit worth paying
// for.
type ruleRef struct {
	policy int32
	rule   int32
}

// Shard indexes one tenant's policies. Requests are evaluated against their own
// tenant's shard plus the global shard, never the whole corpus.
type Shard struct {
	Policies []model.Policy

	refs  []ruleRef // universe position -> (policy, rule), in policy order
	attrs map[string]*attrIndex
	names []string
	n     int // total rule count: the size of the indexed universe
	all   *bitset.Set
}

// attrIndex holds every sub-index built for a single attribute.
type attrIndex struct {
	// Set family, positive (eq, in): value -> rules accepting it.
	posValues map[string]*bitset.Set
	posPart   *bitset.Set
	posNot    *bitset.Set

	// Set family, negated (ne, nin): value -> rules rejecting it.
	negValues map[string]*bitset.Set
	negPart   *bitset.Set

	// Existence.
	existsSet    *bitset.Set // rules requiring the attribute present
	notExistsSet *bitset.Set // rules requiring it absent

	// Network.
	cidr     *matcher.CIDRIndex
	cidrPart *bitset.Set
	cidrNot  *bitset.Set
	ncidr    *matcher.CIDRIndex // rules rejecting addresses in these blocks

	// Name and affix.
	domain     *matcher.DomainIndex
	domainPart *bitset.Set
	domainNot  *bitset.Set
	prefix     *matcher.PrefixIndex
	prefixPart *bitset.Set
	prefixNot  *bitset.Set
	suffix     *matcher.SuffixIndex
	suffixPart *bitset.Set
	suffixNot  *bitset.Set

	// Numeric ranges.
	interval     *matcher.IntervalIndex
	intervalPart *bitset.Set
	intervalNot  *bitset.Set

	// Numeric discrete sets.
	numset     *matcher.NumSetIndex
	numsetPart *bitset.Set
	numsetNot  *bitset.Set

	// Rules needing the attribute present for any reason. Used to prune when a
	// request omits the attribute entirely, and the only filter the
	// non-indexable operators (contains, regex, negated affixes) contribute.
	requiresPresent *bitset.Set
	allowsAbsent    *bitset.Set
}

// attrBuilder accumulates one attribute's sub-indexes during construction.
//
// Every sub-structure is created on first use rather than up front. An attribute
// almost always carries a single operator family — roles are equality, source
// addresses are CIDR, risk scores are ranges — so eagerly allocating every
// builder and matcher index per attribute meant the overwhelming majority were
// built, sized to the shard, and thrown away empty. With a corpus partitioned
// into tens of thousands of shards that dominated both build time and peak
// memory.
type attrBuilder struct {
	n int

	posValues map[string]*bitset.Builder
	posPart   *bitset.Builder
	negValues map[string]*bitset.Builder
	negPart   *bitset.Builder
	exists    *bitset.Builder
	notExists *bitset.Builder

	cidr     *matcher.CIDRIndex
	cidrPart *bitset.Builder
	ncidr    *matcher.CIDRIndex

	domain     *matcher.DomainIndex
	domainPart *bitset.Builder
	prefix     *matcher.PrefixIndex
	prefixPart *bitset.Builder
	suffix     *matcher.SuffixIndex
	suffixPart *bitset.Builder

	interval     *matcher.IntervalIndex
	intervalPart *bitset.Builder

	numset     *matcher.NumSetIndex
	numsetPart *bitset.Builder

	requiresPresent *bitset.Builder
	used            bool
}

func newAttrBuilder(n int) *attrBuilder { return &attrBuilder{n: n} }

// bs returns the builder at *dst, creating it on first use.
func (b *attrBuilder) bs(dst **bitset.Builder) *bitset.Builder {
	if *dst == nil {
		*dst = bitset.NewBuilder(b.n)
	}
	return *dst
}

func (b *attrBuilder) valueBuilder(m *map[string]*bitset.Builder, v string) *bitset.Builder {
	if *m == nil {
		*m = make(map[string]*bitset.Builder, 4)
	}
	vb, ok := (*m)[v]
	if !ok {
		vb = bitset.NewBuilder(b.n)
		(*m)[v] = vb
	}
	return vb
}

func (b *attrBuilder) cidrIndex(dst **matcher.CIDRIndex) *matcher.CIDRIndex {
	if *dst == nil {
		*dst = matcher.NewCIDRIndex()
	}
	return *dst
}

func (b *attrBuilder) domainIndex() *matcher.DomainIndex {
	if b.domain == nil {
		b.domain = matcher.NewDomainIndex(b.n)
	}
	return b.domain
}

func (b *attrBuilder) prefixIndex() *matcher.PrefixIndex {
	if b.prefix == nil {
		b.prefix = matcher.NewPrefixIndex(b.n)
	}
	return b.prefix
}

func (b *attrBuilder) suffixIndex() *matcher.SuffixIndex {
	if b.suffix == nil {
		b.suffix = matcher.NewSuffixIndex(b.n)
	}
	return b.suffix
}

func (b *attrBuilder) intervalIndex() *matcher.IntervalIndex {
	if b.interval == nil {
		b.interval = matcher.NewIntervalIndex(b.n)
	}
	return b.interval
}

func (b *attrBuilder) numSetIndex() *matcher.NumSetIndex {
	if b.numset == nil {
		b.numset = matcher.NewNumSetIndex(b.n)
	}
	return b.numset
}

// build finalizes a builder that may never have been created, yielding an empty
// set of the right universe rather than nil.
func buildOrEmpty(b *bitset.Builder, n int) *bitset.Set {
	if b == nil {
		return bitset.New(n)
	}
	return b.Build()
}

// BuildShard indexes a slice of policies, flattening their rules into one
// indexed universe. The slice is retained by reference; callers must not mutate
// it afterwards.
//
// It also runs model.Policy.Prepare on every policy, so regular expressions are
// compiled once here rather than looked up per evaluation. A pattern that fails
// to compile is left to the cache fallback in Condition.Matches — BuildShard
// cannot return an error without every caller in the tree growing one, and
// package bundle's linter is where an unparsable pattern is meant to be caught.
func BuildShard(policies []model.Policy) *Shard {
	n := 0
	for i := range policies {
		_ = policies[i].Prepare()
		n += policies[i].RuleCount()
	}

	s := &Shard{
		Policies: policies,
		refs:     make([]ruleRef, 0, n),
		attrs:    make(map[string]*attrIndex),
		n:        n,
		all:      bitset.Full(n),
	}

	builders := map[string]*attrBuilder{}
	get := func(attr string) *attrBuilder {
		b, ok := builders[attr]
		if !ok {
			b = newAttrBuilder(n)
			builders[attr] = b
		}
		b.used = true
		return b
	}

	// spine is reused across rules so extracting the AND-spine does not
	// allocate per rule on a million-rule build.
	var spine []model.Condition

	pos := 0
	for pi := range policies {
		for ri := range policies[pi].Rules {
			s.refs = append(s.refs, ruleRef{policy: int32(pi), rule: int32(ri)})

			spine = policies[pi].Rules[ri].When.ANDSpineLeaves(spine[:0])
			for k := range spine {
				indexCondition(get, &spine[k], pos, n)
			}
			pos++
		}
	}

	for name, b := range builders {
		if !b.used {
			continue
		}
		freezeAll(b)

		ai := &attrIndex{
			posValues:    freezeValues(b.posValues),
			posPart:      buildOrEmpty(b.posPart, n),
			negValues:    freezeValues(b.negValues),
			negPart:      buildOrEmpty(b.negPart, n),
			existsSet:    buildOrEmpty(b.exists, n),
			notExistsSet: buildOrEmpty(b.notExists, n),
			cidr:         b.cidr,
			cidrPart:     buildOrEmpty(b.cidrPart, n),
			ncidr:        b.ncidr,
			domain:       b.domain,
			domainPart:   buildOrEmpty(b.domainPart, n),
			prefix:       b.prefix,
			prefixPart:   buildOrEmpty(b.prefixPart, n),
			suffix:       b.suffix,
			suffixPart:   buildOrEmpty(b.suffixPart, n),
			interval:     b.interval,
			intervalPart: buildOrEmpty(b.intervalPart, n),
			numset:       b.numset,
			numsetPart:   buildOrEmpty(b.numsetPart, n),
		}
		ai.requiresPresent = buildOrEmpty(b.requiresPresent, n)

		// Complements: the rules each sub-index must never filter out. Only
		// computed for families the attribute actually uses, since a complement
		// over an unused family is the whole shard and would be both the largest
		// set built and never consulted.
		if ai.posPart.Cardinality() > 0 {
			ai.posNot = ai.posPart.Complement()
		}
		if ai.cidrPart.Cardinality() > 0 {
			ai.cidrNot = ai.cidrPart.Complement()
		}
		if ai.domainPart.Cardinality() > 0 {
			ai.domainNot = ai.domainPart.Complement()
		}
		if ai.prefixPart.Cardinality() > 0 {
			ai.prefixNot = ai.prefixPart.Complement()
		}
		if ai.suffixPart.Cardinality() > 0 {
			ai.suffixNot = ai.suffixPart.Complement()
		}
		if ai.intervalPart.Cardinality() > 0 {
			ai.intervalNot = ai.intervalPart.Complement()
		}
		if ai.numsetPart.Cardinality() > 0 {
			ai.numsetNot = ai.numsetPart.Complement()
		}
		ai.allowsAbsent = ai.requiresPresent.Complement()

		s.attrs[name] = ai
		s.names = append(s.names, name)
	}
	sort.Strings(s.names)
	return s
}

// indexCondition records one AND-spine condition at rule position pos.
//
// Every operator lands in exactly one of three groups. Enumerable operators
// build a positive posting structure. Rejecting operators build a negative one.
// Everything else — substring, regex, negated affix and negated range — is not
// indexable, and contributes only the fact that its attribute must be present.
// That last group is deliberately explicit rather than a default case: a new
// operator added to package model with no entry here would silently become
// unindexed but still correct, and silence is the wrong outcome for something
// that costs this much performance.
func indexCondition(get func(string) *attrBuilder, c *model.Condition, pos, n int) {
	b := get(c.Attribute)

	switch c.Operator {

	// -- Enumerable string set --
	case model.OpEquals:
		b.bs(&b.posPart).Add(pos)
		b.bs(&b.requiresPresent).Add(pos)
		// Only Values[0] is consulted by Condition.Matches for eq, so only
		// Values[0] is indexed. Indexing the rest would merely be
		// over-inclusive, but it would also make the posting lists lie about
		// what the condition accepts.
		if len(c.Values) > 0 {
			b.valueBuilder(&b.posValues, c.Values[0]).Add(pos)
		}

	case model.OpIn:
		b.bs(&b.posPart).Add(pos)
		b.bs(&b.requiresPresent).Add(pos)
		for _, v := range c.Values {
			b.valueBuilder(&b.posValues, v).Add(pos)
		}

	// -- Rejecting string set --
	case model.OpNotEquals:
		b.bs(&b.negPart).Add(pos)
		b.bs(&b.requiresPresent).Add(pos)
		// Critically, only Values[0]. Condition.Matches for `ne` compares
		// against Values[0] alone, so indexing a second value as also-rejected
		// would make the filter reject a rule that actually matches — the one
		// error class that produces wrong decisions rather than slow ones.
		if len(c.Values) > 0 {
			b.valueBuilder(&b.negValues, c.Values[0]).Add(pos)
		}

	case model.OpNotIn:
		b.bs(&b.negPart).Add(pos)
		b.bs(&b.requiresPresent).Add(pos)
		for _, v := range c.Values {
			b.valueBuilder(&b.negValues, v).Add(pos)
		}

	// -- Presence --
	case model.OpExists:
		b.bs(&b.exists).Add(pos)
		b.bs(&b.requiresPresent).Add(pos)

	case model.OpNotExists:
		b.bs(&b.notExists).Add(pos)

	// -- Numeric ranges. Strict and non-strict bounds index identically; the
	// index is inclusive at the boundary and validation applies the exact
	// comparison, which is over-inclusive by at most the boundary value. --
	case model.OpRange:
		b.bs(&b.intervalPart).Add(pos)
		b.bs(&b.requiresPresent).Add(pos)
		b.intervalIndex().Insert(c.Min, c.Max, pos)

	case model.OpGreaterThan, model.OpGreaterEq:
		b.bs(&b.intervalPart).Add(pos)
		b.bs(&b.requiresPresent).Add(pos)
		b.intervalIndex().Insert(c.Min, posInf, pos)

	case model.OpLessThan, model.OpLessEq:
		b.bs(&b.intervalPart).Add(pos)
		b.bs(&b.requiresPresent).Add(pos)
		b.intervalIndex().Insert(negInf, c.Max, pos)

	case model.OpNumEquals:
		b.bs(&b.numsetPart).Add(pos)
		b.bs(&b.requiresPresent).Add(pos)
		b.numSetIndex().Insert(c.Min, pos)

	case model.OpNumIn:
		b.bs(&b.numsetPart).Add(pos)
		b.bs(&b.requiresPresent).Add(pos)
		for _, v := range c.Numbers {
			b.numSetIndex().Insert(v, pos)
		}

	// -- Network --
	case model.OpCIDR:
		b.bs(&b.cidrPart).Add(pos)
		b.bs(&b.requiresPresent).Add(pos)
		for _, p := range c.Prefixes {
			b.cidrIndex(&b.cidr).Insert(p, pos, n)
		}

	case model.OpNotCIDR:
		b.bs(&b.requiresPresent).Add(pos)
		for _, p := range c.Prefixes {
			b.cidrIndex(&b.ncidr).Insert(p, pos, n)
		}

	// -- Name and affix --
	case model.OpDNSSuffix:
		b.bs(&b.domainPart).Add(pos)
		b.bs(&b.requiresPresent).Add(pos)
		for _, v := range c.Values {
			b.domainIndex().Insert(v, pos)
		}

	case model.OpPrefix:
		b.bs(&b.prefixPart).Add(pos)
		b.bs(&b.requiresPresent).Add(pos)
		for _, v := range c.Values {
			b.prefixIndex().Insert(v, pos)
		}

	case model.OpSuffix:
		b.bs(&b.suffixPart).Add(pos)
		b.bs(&b.requiresPresent).Add(pos)
		for _, v := range c.Values {
			b.suffixIndex().Insert(v, pos)
		}

	// -- Not indexable. Presence is the only filter available. --
	case model.OpContains, model.OpNotContains,
		model.OpNotPrefix, model.OpNotSuffix,
		model.OpRegex, model.OpNotRegex,
		model.OpNotDNSSuffix,
		model.OpNotRange, model.OpNumNotEq, model.OpNumNotIn:
		b.bs(&b.requiresPresent).Add(pos)
	}
}

func freezeAll(b *attrBuilder) {
	if b.cidr != nil {
		b.cidr.Freeze()
	}
	if b.ncidr != nil {
		b.ncidr.Freeze()
	}
	if b.domain != nil {
		b.domain.Freeze()
	}
	if b.prefix != nil {
		b.prefix.Freeze()
	}
	if b.suffix != nil {
		b.suffix.Freeze()
	}
	if b.interval != nil {
		b.interval.Freeze()
	}
	if b.numset != nil {
		b.numset.Freeze()
	}
}

func freezeValues(in map[string]*bitset.Builder) map[string]*bitset.Set {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]*bitset.Set, len(in))
	for k, v := range in {
		out[k] = v.Build()
	}
	return out
}

// Size reports how many rules this shard indexes.
func (s *Shard) Size() int { return s.n }

// PolicyCount reports how many policies this shard holds.
func (s *Shard) PolicyCount() int { return len(s.Policies) }

// RuleRef resolves an indexed position to its policy and rule indices.
func (s *Shard) RuleRef(pos int) (policyIdx, ruleIdx int) {
	r := s.refs[pos]
	return int(r.policy), int(r.rule)
}

// filterKind distinguishes filters that can enumerate their members from those
// that can only reject.
type filterKind uint8

const (
	filterPositive filterKind = iota // pass = accepted ∪ notParticipating
	filterNegative                   // pass = everything except rejected
)

type filter struct {
	kind   filterKind
	pass   matcher.MatchSet
	reject matcher.MatchSet
	est    int
}

func (f filter) allows(i int) bool {
	if f.kind == filterNegative {
		return !f.reject.Contains(i)
	}
	return f.pass.Contains(i)
}

// Scratch holds the reusable buffers one evaluation goroutine needs. Reusing it
// across requests is what keeps the steady-state hot path free of allocation;
// each goroutine must own its own.
type Scratch struct {
	filters []filter
	cands   []int
	rules   []int

	// Word-parallel intersection buffers, grown on demand and reused.
	acc []uint64
	tmp []uint64
}

// NewScratch returns a scratch buffer sized for the expected candidate count.
func NewScratch() *Scratch {
	return &Scratch{
		filters: make([]filter, 0, 16),
		cands:   make([]int, 0, 1024),
		rules:   make([]int, 0, 32),
	}
}

// words returns a zeroed slice of nw words from dst, growing it if needed.
func words(dst []uint64, nw int) []uint64 {
	if cap(dst) < nw {
		return make([]uint64, nw)
	}
	dst = dst[:nw]
	for i := range dst {
		dst[i] = 0
	}
	return dst
}

// wordParallelDivisor sets the seed size at which the word-parallel intersection
// overtakes per-element filtering: word-parallel is chosen once the seed exceeds
// s.n / wordParallelDivisor.
//
// The two costs are seed × filters of O(1)-ish membership probes against
// filters × n/64 of word operations. They cross near n/64, and the divisor is 32
// rather than 64 to bias toward per-element filtering, which has the better
// constant factor and does not touch a word per 64 rules that survived nothing.
const wordParallelDivisor = 32

// Candidates returns the rule positions in this shard that survive index
// filtering. The returned slice aliases sc and is valid only until the next call
// with the same Scratch. Positions are ascending, which the two-tier walk in
// Evaluate relies on to group rules by policy.
func (s *Shard) Candidates(req model.Request, sc *Scratch) []int {
	if s.n == 0 {
		return nil
	}
	best := s.collect(req, sc)

	// Two intersection strategies, because one of them falls apart at each end of
	// the range.
	//
	// Per-element filtering materializes the most selective posting list and
	// probes the rest, so its cost tracks the surviving candidate count. That is
	// exactly right on a well-partitioned corpus, where a request reaches a few
	// hundred rules and the seed is small.
	//
	// It collapses on a large *flat* shard — one tenant, no scoping. There the
	// seed is drawn from a filter whose non-participant complement is itself
	// enormous, so the engine materializes tens of thousands of ints and probes
	// each against every filter. Measured on a 200k-rule flat shard that came to
	// 5ms per request and 10KB of allocation, against 200µs for a plain linear
	// scan: the index was 25x slower than the baseline it exists to beat.
	//
	// Above the threshold the intersection runs as a bitmap AND over words
	// instead. Cost becomes O(filters × n/64) with no allocation and no
	// per-candidate probe, which is what makes a single-tenant deployment
	// viable rather than a cliff.
	seed := s.n
	if best >= 0 {
		seed = sc.filters[best].est
	}
	if seed > s.n/wordParallelDivisor {
		return s.intersectWordParallel(sc, best)
	}
	return s.intersectPerElement(sc, best)
}

// collect builds and orders this request's filters, returning the index of the
// filter to seed from, or -1 if none can enumerate.
func (s *Shard) collect(req model.Request, sc *Scratch) int {
	sc.filters = sc.filters[:0]
	for _, name := range s.names {
		s.collectFilters(name, s.attrs[name], req, sc)
	}

	// Order filters cheapest-first. The seed comes from the most selective
	// enumerable filter, and applying the rest in ascending order shrinks the
	// working list as fast as possible — every later pass then walks a shorter
	// slice.
	//
	// Insertion sort rather than sort.Slice: the list holds one filter per
	// indexed attribute, so it is short and usually near-sorted, and sort.Slice's
	// closure escapes to the heap on every request.
	for i := 1; i < len(sc.filters); i++ {
		f := sc.filters[i]
		j := i - 1
		for j >= 0 && sc.filters[j].est > f.est {
			sc.filters[j+1] = sc.filters[j]
			j--
		}
		sc.filters[j+1] = f
	}

	for i := range sc.filters {
		if sc.filters[i].kind == filterPositive {
			return i
		}
	}
	return -1
}

// intersectPerElement materializes the seed filter and probes the survivors
// against the rest. Best when the seed is small.
func (s *Shard) intersectPerElement(sc *Scratch, best int) []int {
	sc.cands = sc.cands[:0]
	if best == -1 {
		// No enumerable filter: every rule is a candidate. Happens when the
		// request carries nothing this shard indexes.
		sc.cands = s.all.AppendMembers(sc.cands)
	} else {
		sc.cands = sc.filters[best].pass.AppendMembers(sc.cands)
	}

	// Filter in place against every remaining filter, shrinking as we go.
	//
	// Every filter is applied rather than bailing out below some candidate count.
	// A filter pass over k candidates is k Contains probes, which is cheaper than
	// letting those k rules reach exact validation and run their full condition
	// trees — so stopping early would trade a cheap probe for expensive
	// validation, and make pruning depend on the arbitrary order filters happen
	// to sit in.
	for i := range sc.filters {
		if i == best {
			continue
		}
		if len(sc.cands) == 0 {
			break
		}
		f := sc.filters[i]
		w := 0
		for _, c := range sc.cands {
			if f.allows(c) {
				sc.cands[w] = c
				w++
			}
		}
		sc.cands = sc.cands[:w]
	}
	return sc.cands
}

// intersectWordParallel AND-s the filters together as bitmaps, then enumerates
// what survives. Best when the seed is a large fraction of the shard.
func (s *Shard) intersectWordParallel(sc *Scratch, best int) []int {
	nw := bitset.WordCount(s.n)
	sc.acc = words(sc.acc, nw)

	if best == -1 {
		s.all.OrWords(sc.acc)
	} else {
		sc.filters[best].pass.OrWords(sc.acc)
	}

	for i := range sc.filters {
		if i == best {
			continue
		}
		sc.tmp = words(sc.tmp, nw)
		f := sc.filters[i]

		var any uint64
		if f.kind == filterNegative {
			f.reject.OrWords(sc.tmp)
			for w := range sc.acc {
				sc.acc[w] &^= sc.tmp[w]
				any |= sc.acc[w]
			}
		} else {
			f.pass.OrWords(sc.tmp)
			for w := range sc.acc {
				sc.acc[w] &= sc.tmp[w]
				any |= sc.acc[w]
			}
		}
		if any == 0 {
			// Nothing survives; further filters cannot revive a rule.
			return sc.cands[:0]
		}
	}

	sc.cands = sc.cands[:0]
	for w, word := range sc.acc {
		for word != 0 {
			sc.cands = append(sc.cands, w*64+bits.TrailingZeros64(word))
			word &= word - 1
		}
	}
	return sc.cands
}

// Evaluate narrows the shard to candidate rules and runs the two-tier
// combination over them, feeding resolved policy verdicts into acc. It reports
// how many policies and how many rules reached exact validation.
//
// Candidate positions arrive ascending and refs are assigned in policy order, so
// every policy's surviving rules form one contiguous run. Walking runs rather
// than grouping through a map is what keeps this allocation-free: the per-policy
// rule list is gathered into a scratch buffer that is reused across policies and
// across requests.
func (s *Shard) Evaluate(req model.Request, sc *Scratch, acc *model.Accumulator) (policies, rules int) {
	cands := s.Candidates(req, sc)

	for i := 0; i < len(cands); {
		pi, ri := s.RuleRef(cands[i])

		sc.rules = append(sc.rules[:0], ri)
		j := i + 1
		for j < len(cands) {
			pj, rj := s.RuleRef(cands[j])
			if pj != pi {
				break
			}
			sc.rules = append(sc.rules, rj)
			j++
		}

		policies++
		rules += model.ConsiderPolicy(&s.Policies[pi], req, sc.rules, acc)
		if acc.CanShortCircuit() {
			break
		}
		i = j
	}
	return policies, rules
}

// collectFilters appends every filter attribute `name` contributes for req.
func (s *Shard) collectFilters(name string, ai *attrIndex, req model.Request, sc *Scratch) {
	present := req.Has(name)

	if sv, ok := req.Attributes[name]; ok {
		// Positive set family: accepted values, plus non-participants.
		if ai.posPart.Cardinality() > 0 {
			ms := matcher.Single(ai.posNot)
			if set, ok := ai.posValues[sv]; ok {
				ms = ms.Union(set)
			}
			sc.push(filterPositive, ms)
		}
		// Negated set family: reject rules excluding this exact value.
		if set, ok := ai.negValues[sv]; ok {
			sc.pushNegative(matcher.Single(set), s.n)
		}
		// Domain suffix, label-aligned.
		if ai.domainPart.Cardinality() > 0 {
			sc.push(filterPositive, ai.domain.Lookup(sv, matcher.Single(ai.domainNot)))
		}
		// Path prefix.
		if ai.prefixPart.Cardinality() > 0 {
			sc.push(filterPositive, ai.prefix.Lookup(sv, matcher.Single(ai.prefixNot)))
		}
		// Byte suffix — file extensions and the like.
		if ai.suffixPart.Cardinality() > 0 {
			sc.push(filterPositive, ai.suffix.Lookup(sv, matcher.Single(ai.suffixNot)))
		}
	}

	if nv, ok := req.Numeric[name]; ok {
		if ai.intervalPart.Cardinality() > 0 && !ai.interval.Degraded() {
			// A degraded interval index gave up on selectivity; every
			// participant stays a candidate and validation sorts it out. Note
			// that this skips only the interval filter — the other families on
			// this attribute still contribute.
			sc.push(filterPositive, ai.interval.Lookup(nv, matcher.Single(ai.intervalNot)))
		}
		if ai.numsetPart.Cardinality() > 0 {
			sc.push(filterPositive, ai.numset.Lookup(nv, matcher.Single(ai.numsetNot)))
		}
	}

	if addr, ok := req.IPs[name]; ok {
		if ai.cidrPart.Cardinality() > 0 {
			sc.push(filterPositive, ai.cidr.Lookup(addr, matcher.Single(ai.cidrNot)))
		}
		// Negated CIDR: reject rules whose excluded blocks contain the address.
		if ai.ncidr != nil {
			if rejected := ai.ncidr.Lookup(addr, matcher.MatchSet{}); !rejected.IsEmpty() {
				sc.pushNegative(rejected, s.n)
			}
		}
	}

	if present {
		// Rules demanding this attribute be absent cannot match. Checked against
		// presence in any of the three maps, not just Attributes — a numeric or
		// IP attribute satisfies OpExists just as a string one does, so it must
		// defeat OpNotExists the same way.
		if ai.notExistsSet.Cardinality() > 0 {
			sc.pushNegative(matcher.Single(ai.notExistsSet), s.n)
		}
		return
	}

	// Attribute absent from the request entirely: only rules that tolerate its
	// absence can match. This is the sole filter the non-indexable operators
	// contribute, and on real corpora it is a substantial one.
	if ai.requiresPresent.Cardinality() > 0 {
		sc.push(filterPositive, matcher.Single(ai.allowsAbsent))
	}
}

func (sc *Scratch) push(kind filterKind, ms matcher.MatchSet) {
	sc.filters = append(sc.filters, filter{
		kind: kind, pass: ms, est: ms.EstimatedCardinality()})
}

func (sc *Scratch) pushNegative(ms matcher.MatchSet, universe int) {
	sc.filters = append(sc.filters, filter{
		kind: filterNegative, reject: ms, est: universe - ms.EstimatedCardinality()})
}

var (
	posInf = math.Inf(1)
	negInf = math.Inf(-1)
)
