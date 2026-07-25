package matcher

import (
	"math"
	"sort"

	"github.com/suga/tessaraop/internal/bitset"
)

// MaxDistinctIntervals caps how many distinct numeric ranges an IntervalIndex
// will track before it gives up on being selective. Past the cap the index
// reports Degraded and the engine treats every policy carrying the condition
// as a candidate — conservative, still correct, just less selective.
const MaxDistinctIntervals = 4096

// IntervalIndex answers "which policies have a numeric condition whose range
// covers this value".
//
// It groups policies by *distinct* range rather than building a per-value or
// per-bucket structure. That choice comes from what real policy corpora look
// like: a million policies referencing time-of-day windows still only use a
// handful of distinct windows (business hours, after hours, maintenance
// windows), and risk-score conditions collapse onto a few bands. So the
// number of distinct ranges stays small even as the corpus grows, and a query
// is a binary search plus a short scan over ranges whose lower bound is below
// the query value.
//
// Ranges are stored half-inclusive-agnostic: OpGreaterThan and OpLessThan
// arrive as ranges with an infinite end, which sort and compare correctly
// against ±Inf without special cases.
type IntervalIndex struct {
	entries  []intervalEntry // sorted by min ascending
	builders map[[2]float64]*bitset.Builder
	n        int
	degraded bool
}

type intervalEntry struct {
	min, max float64
	set      *bitset.Set
}

// NewIntervalIndex returns an empty index over a shard of `universe` policies.
func NewIntervalIndex(universe int) *IntervalIndex {
	return &IntervalIndex{
		builders: make(map[[2]float64]*bitset.Builder),
		n:        universe,
	}
}

// Insert records that the policy at policyIdx accepts values in [min, max].
// Use math.Inf for open ends.
func (x *IntervalIndex) Insert(min, max float64, policyIdx int) {
	if x.degraded {
		return
	}
	key := [2]float64{min, max}
	b, ok := x.builders[key]
	if !ok {
		if len(x.builders) >= MaxDistinctIntervals {
			// Too many distinct ranges for this structure to stay selective.
			x.degraded = true
			x.builders = nil
			return
		}
		b = bitset.NewBuilder(x.n)
		x.builders[key] = b
	}
	b.Add(policyIdx)
}

// Degraded reports whether the index gave up on selectivity. The engine must
// then fall back to the attribute's has-condition set.
func (x *IntervalIndex) Degraded() bool { return x.degraded }

// Freeze sorts and finalizes the entries. Call once after all Inserts.
func (x *IntervalIndex) Freeze() {
	if x.degraded {
		return
	}
	x.entries = make([]intervalEntry, 0, len(x.builders))
	for k, b := range x.builders {
		x.entries = append(x.entries, intervalEntry{min: k[0], max: k[1], set: b.Build()})
	}
	x.builders = nil
	sort.Slice(x.entries, func(i, j int) bool { return x.entries[i].min < x.entries[j].min })
}

// Lookup unions into base the policy set of every range covering v.
func (x *IntervalIndex) Lookup(v float64, base MatchSet) MatchSet {
	if x.degraded || math.IsNaN(v) {
		return base
	}
	// Ranges are sorted by min, so every range that can cover v lies in the
	// prefix with min <= v. Binary search that cut, then test max on it.
	hi := sort.Search(len(x.entries), func(i int) bool { return x.entries[i].min > v })
	for i := 0; i < hi; i++ {
		if x.entries[i].max >= v {
			base = base.Union(x.entries[i].set)
		}
	}
	return base
}
