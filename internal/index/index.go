// Package index builds the per-attribute structures that turn a request into
// a small candidate set, and performs the intersection that produces it.
//
// # How a candidate set is derived
//
// Each attribute contributes one or more sub-indexes, one per operator family
// present on it. For a request value v, a sub-index S yields the set of
// policies that pass it:
//
//	pass_S(v) = notParticipating_S ∪ accepted_S(v)
//
// The notParticipating term is the correctness keystone. A policy that places
// no condition of kind S on the attribute must never be filtered out by S —
// get that wrong and the engine returns confidently wrong answers rather than
// merely slow ones.
//
// Negated operators (ne, nin, !cidr) collapse to something much cheaper. For
// them, notParticipating ∪ (participating \ rejected) is just the whole
// universe minus the rejected set, so a negation needs no complement at query
// time — it is simply "reject these, pass everything else".
//
// # How the intersection runs
//
// v1 AND-ed dense bitsets pairwise, so every step cost O(N/64) no matter how
// few candidates survived; at a million policies that dominated everything and
// the speedup collapsed to 1.1x. Instead this package materializes only the
// single most selective sub-index, then filters that list in place against the
// remaining ones. Cost tracks the surviving candidate count rather than the
// corpus size, and the list only ever shrinks.
package index

import (
	"math"
	"sort"

	"github.com/suga/tessaraop/internal/bitset"
	"github.com/suga/tessaraop/internal/matcher"
	"github.com/suga/tessaraop/internal/model"
)

// Shard indexes one tenant's policies. Requests are evaluated against their
// own tenant's shard plus the global shard, never the whole corpus.
type Shard struct {
	Policies []model.Policy
	attrs    map[string]*attrIndex
	names    []string
	n        int
	all      *bitset.Set
}

// attrIndex holds every sub-index built for a single attribute.
type attrIndex struct {
	// Set family, positive (eq, in): value -> policies accepting it.
	posValues map[string]*bitset.Set
	posPart   *bitset.Set
	posNot    *bitset.Set

	// Set family, negated (ne, nin): value -> policies rejecting it.
	negValues map[string]*bitset.Set
	negPart   *bitset.Set

	// Existence.
	existsSet    *bitset.Set // policies requiring the attribute present
	notExistsSet *bitset.Set // policies requiring it absent

	// Network.
	cidr     *matcher.CIDRIndex
	cidrPart *bitset.Set
	cidrNot  *bitset.Set
	ncidr    *matcher.CIDRIndex // policies rejecting addresses in these blocks

	// Name.
	domain     *matcher.DomainIndex
	domainPart *bitset.Set
	domainNot  *bitset.Set
	prefix     *matcher.PrefixIndex
	prefixPart *bitset.Set
	prefixNot  *bitset.Set

	// Numeric.
	interval     *matcher.IntervalIndex
	intervalPart *bitset.Set
	intervalNot  *bitset.Set

	// Policies needing the attribute present for any reason. Used to prune
	// when a request omits the attribute entirely.
	requiresPresent *bitset.Set
	allowsAbsent    *bitset.Set
}

// attrBuilder accumulates one attribute's sub-indexes during construction.
//
// Every sub-structure is created on first use rather than up front. An
// attribute almost always carries a single operator family — roles are
// equality, source addresses are CIDR, risk scores are ranges — so eagerly
// allocating all twelve builders and five matcher indexes per attribute meant
// the overwhelming majority were built, sized to the shard, and thrown away
// empty. With a corpus partitioned into tens of thousands of shards that
// dominated both build time and peak memory.
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

	interval     *matcher.IntervalIndex
	intervalPart *bitset.Builder

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

func (b *attrBuilder) intervalIndex() *matcher.IntervalIndex {
	if b.interval == nil {
		b.interval = matcher.NewIntervalIndex(b.n)
	}
	return b.interval
}

// build finalizes a builder that may never have been created, yielding an
// empty set of the right universe rather than nil.
func buildOrEmpty(b *bitset.Builder, n int) *bitset.Set {
	if b == nil {
		return bitset.New(n)
	}
	return b.Build()
}

// BuildShard indexes a slice of policies. The slice is retained by reference;
// callers must not mutate it afterwards.
func BuildShard(policies []model.Policy) *Shard {
	n := len(policies)
	s := &Shard{
		Policies: policies,
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

	for i := range policies {
		for _, c := range policies[i].Conditions {
			b := get(c.Attribute)
			switch c.Operator {

			case model.OpEquals, model.OpIn:
				b.bs(&b.posPart).Add(i)
				b.bs(&b.requiresPresent).Add(i)
				for _, v := range c.Values {
					b.valueBuilder(&b.posValues, v).Add(i)
				}

			case model.OpNotEquals, model.OpNotIn:
				b.bs(&b.negPart).Add(i)
				b.bs(&b.requiresPresent).Add(i)
				for _, v := range c.Values {
					b.valueBuilder(&b.negValues, v).Add(i)
				}

			case model.OpExists:
				b.bs(&b.exists).Add(i)
				b.bs(&b.requiresPresent).Add(i)

			case model.OpNotExists:
				b.bs(&b.notExists).Add(i)

			case model.OpRange:
				b.bs(&b.intervalPart).Add(i)
				b.bs(&b.requiresPresent).Add(i)
				b.intervalIndex().Insert(c.Min, c.Max, i)

			case model.OpGreaterThan:
				b.bs(&b.intervalPart).Add(i)
				b.bs(&b.requiresPresent).Add(i)
				b.intervalIndex().Insert(inclusiveLower(c.Min), posInf, i)

			case model.OpLessThan:
				b.bs(&b.intervalPart).Add(i)
				b.bs(&b.requiresPresent).Add(i)
				b.intervalIndex().Insert(negInf, inclusiveUpper(c.Max), i)

			case model.OpCIDR:
				b.bs(&b.cidrPart).Add(i)
				b.bs(&b.requiresPresent).Add(i)
				for _, p := range c.Prefixes {
					b.cidrIndex(&b.cidr).Insert(p, i, n)
				}

			case model.OpNotCIDR:
				b.bs(&b.requiresPresent).Add(i)
				for _, p := range c.Prefixes {
					b.cidrIndex(&b.ncidr).Insert(p, i, n)
				}

			case model.OpDNSSuffix:
				b.bs(&b.domainPart).Add(i)
				b.bs(&b.requiresPresent).Add(i)
				for _, v := range c.Values {
					b.domainIndex().Insert(v, i)
				}

			case model.OpPrefix:
				b.bs(&b.prefixPart).Add(i)
				b.bs(&b.requiresPresent).Add(i)
				for _, v := range c.Values {
					b.prefixIndex().Insert(v, i)
				}
			}
		}
	}

	for name, b := range builders {
		if !b.used {
			continue
		}
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
		if b.interval != nil {
			b.interval.Freeze()
		}

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
			interval:     b.interval,
			intervalPart: buildOrEmpty(b.intervalPart, n),
		}
		ai.requiresPresent = buildOrEmpty(b.requiresPresent, n)

		// Complements: the policies each sub-index must never filter out.
		// Only computed for families the attribute actually uses, since a
		// complement over an unused family is the whole shard and would be
		// both the largest set built and never consulted.
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
		if ai.intervalPart.Cardinality() > 0 {
			ai.intervalNot = ai.intervalPart.Complement()
		}
		ai.allowsAbsent = ai.requiresPresent.Complement()

		s.attrs[name] = ai
		s.names = append(s.names, name)
	}
	sort.Strings(s.names)
	return s
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

// Size reports how many policies this shard holds.
func (s *Shard) Size() int { return s.n }

// filterKind distinguishes filters that can enumerate their members from
// those that can only reject.
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

// Scratch holds the reusable buffers one evaluation goroutine needs. Reusing
// it across requests is what keeps the steady-state hot path free of
// allocation; each goroutine must own its own.
type Scratch struct {
	filters []filter
	cands   []int
}

// NewScratch returns a scratch buffer sized for the expected candidate count.
func NewScratch() *Scratch {
	return &Scratch{
		filters: make([]filter, 0, 16),
		cands:   make([]int, 0, 1024),
	}
}

// Candidates returns the policy positions in this shard that survive index
// filtering. The returned slice aliases sc and is valid only until the next
// call with the same Scratch.
func (s *Shard) Candidates(req model.Request, sc *Scratch) []int {
	if s.n == 0 {
		return nil
	}
	sc.filters = sc.filters[:0]

	for _, name := range s.names {
		ai := s.attrs[name]
		s.collectFilters(name, ai, req, sc)
	}

	// Order filters cheapest-first. The seed comes from the most selective
	// enumerable filter, and applying the rest in ascending order shrinks the
	// working list as fast as possible — every later pass then walks a
	// shorter slice.
	//
	// Insertion sort rather than sort.Slice: the list holds one filter per
	// indexed attribute, so it is short and usually near-sorted, and
	// sort.Slice's closure escapes to the heap on every request.
	for i := 1; i < len(sc.filters); i++ {
		f := sc.filters[i]
		j := i - 1
		for j >= 0 && sc.filters[j].est > f.est {
			sc.filters[j+1] = sc.filters[j]
			j--
		}
		sc.filters[j+1] = f
	}

	best := -1
	for i := range sc.filters {
		if sc.filters[i].kind == filterPositive {
			best = i
			break
		}
	}

	sc.cands = sc.cands[:0]
	if best == -1 {
		// No enumerable filter: every policy is a candidate. Happens when the
		// request carries nothing this shard indexes.
		sc.cands = s.all.AppendMembers(sc.cands)
	} else {
		sc.cands = sc.filters[best].pass.AppendMembers(sc.cands)
	}

	// Filter in place against every remaining filter, shrinking as we go.
	//
	// Every filter is applied rather than bailing out below some candidate
	// count. A filter pass over k candidates is k Contains probes, which is
	// cheaper than letting those k policies reach Policy.Matches and run
	// their full condition lists — so stopping early would trade a cheap
	// probe for expensive validation, and make pruning depend on the
	// arbitrary order filters happen to sit in.
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

// collectFilters appends every filter attribute `name` contributes for req.
func (s *Shard) collectFilters(name string, ai *attrIndex, req model.Request, sc *Scratch) {
	if sv, ok := req.Attributes[name]; ok {
		// Positive set family: accepted values, plus non-participants.
		if ai.posPart.Cardinality() > 0 {
			ms := matcher.Single(ai.posNot)
			if set, ok := ai.posValues[sv]; ok {
				ms = ms.Union(set)
			}
			sc.filters = append(sc.filters, filter{
				kind: filterPositive, pass: ms, est: ms.EstimatedCardinality()})
		}
		// Negated set family: reject policies excluding this exact value.
		if set, ok := ai.negValues[sv]; ok {
			ms := matcher.Single(set)
			sc.filters = append(sc.filters, filter{
				kind: filterNegative, reject: ms, est: s.n - ms.EstimatedCardinality()})
		}
		// Domain suffix.
		if ai.domainPart.Cardinality() > 0 {
			ms := ai.domain.Lookup(sv, matcher.Single(ai.domainNot))
			sc.filters = append(sc.filters, filter{
				kind: filterPositive, pass: ms, est: ms.EstimatedCardinality()})
		}
		// Path prefix.
		if ai.prefixPart.Cardinality() > 0 {
			ms := ai.prefix.Lookup(sv, matcher.Single(ai.prefixNot))
			sc.filters = append(sc.filters, filter{
				kind: filterPositive, pass: ms, est: ms.EstimatedCardinality()})
		}
		// Policies demanding this attribute be absent cannot match.
		if ai.notExistsSet.Cardinality() > 0 {
			ms := matcher.Single(ai.notExistsSet)
			sc.filters = append(sc.filters, filter{
				kind: filterNegative, reject: ms, est: s.n - ms.EstimatedCardinality()})
		}
	}

	if nv, ok := req.Numeric[name]; ok {
		if ai.intervalPart.Cardinality() > 0 {
			if ai.interval.Degraded() {
				// Index gave up on selectivity; every participant stays a
				// candidate and validation sorts it out.
				return
			}
			ms := ai.interval.Lookup(nv, matcher.Single(ai.intervalNot))
			sc.filters = append(sc.filters, filter{
				kind: filterPositive, pass: ms, est: ms.EstimatedCardinality()})
		}
	}

	if ip, ok := req.IPs[name]; ok {
		if ai.cidrPart.Cardinality() > 0 {
			ms := ai.cidr.Lookup(ip, matcher.Single(ai.cidrNot))
			sc.filters = append(sc.filters, filter{
				kind: filterPositive, pass: ms, est: ms.EstimatedCardinality()})
		}
		// Negated CIDR: reject policies whose excluded blocks contain the address.
		if ai.ncidr != nil {
			rejected := ai.ncidr.Lookup(ip, matcher.MatchSet{})
			if !rejected.IsEmpty() {
				sc.filters = append(sc.filters, filter{
					kind: filterNegative, reject: rejected,
					est: s.n - rejected.EstimatedCardinality()})
			}
		}
	}

	// Attribute absent from the request entirely: only policies that tolerate
	// its absence can match.
	if !s.attributePresent(name, req) && ai.requiresPresent.Cardinality() > 0 {
		ms := matcher.Single(ai.allowsAbsent)
		sc.filters = append(sc.filters, filter{
			kind: filterPositive, pass: ms, est: ms.EstimatedCardinality()})
	}
}

func (s *Shard) attributePresent(name string, req model.Request) bool {
	if _, ok := req.Attributes[name]; ok {
		return true
	}
	if _, ok := req.Numeric[name]; ok {
		return true
	}
	_, ok := req.IPs[name]
	return ok
}

var (
	posInf = math.Inf(1)
	negInf = math.Inf(-1)
)

// Strict inequalities (gt, lt) are indexed as inclusive ranges. That is
// deliberately one hair over-inclusive at the boundary value, which a
// pre-filter is always allowed to be — validation applies the exact strict
// comparison and drops the boundary case.
func inclusiveLower(v float64) float64 { return v }
func inclusiveUpper(v float64) float64 { return v }
