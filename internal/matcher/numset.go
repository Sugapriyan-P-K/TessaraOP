package matcher

import (
	"math"

	"github.com/suga/tessaraop/internal/bitset"
)

// NumSetIndex answers "which rules accept this exact numeric value" for
// discrete numeric set membership (model.OpNumIn).
//
// IntervalIndex could serve this by inserting a degenerate [v, v] range per
// value, and for a handful of values it would. It stops working at the shape
// that actually motivates the operator: `dest_port IN {…}` over a couple of
// hundred ports turns every value into its own distinct interval, burns through
// MaxDistinctIntervals, and drops the whole attribute into degraded mode where
// every participating rule stays a candidate. Discrete membership wants a hash
// map — O(1), no cap, no binary search — so it gets one.
//
// Float64 keys are exact here rather than approximate, and that is correct for
// the intended domain: ports, protocol numbers, status codes, ICMP types. All
// are small integers, exactly representable, and compared with == by
// Condition.Matches. NaN is dropped on insert since no NaN comparison can
// succeed anyway.
type NumSetIndex struct {
	builders map[float64]*bitset.Builder
	frozen   map[float64]*bitset.Set
	n        int
}

// NewNumSetIndex returns an empty index over a shard of `universe` rules.
func NewNumSetIndex(universe int) *NumSetIndex {
	return &NumSetIndex{
		builders: make(map[float64]*bitset.Builder),
		n:        universe,
	}
}

// Insert records that the rule at ruleIdx accepts the value v.
func (x *NumSetIndex) Insert(v float64, ruleIdx int) {
	if math.IsNaN(v) {
		return
	}
	// Normalize negative zero so -0 and +0 share a bucket, matching ==.
	if v == 0 {
		v = 0
	}
	b, ok := x.builders[v]
	if !ok {
		b = bitset.NewBuilder(x.n)
		x.builders[v] = b
	}
	b.Add(ruleIdx)
}

// Freeze finalizes every value set. Call once after all Inserts.
func (x *NumSetIndex) Freeze() {
	x.frozen = make(map[float64]*bitset.Set, len(x.builders))
	for v, b := range x.builders {
		x.frozen[v] = b.Build()
	}
	x.builders = nil
}

// Lookup unions into base the rule set accepting v.
func (x *NumSetIndex) Lookup(v float64, base MatchSet) MatchSet {
	if math.IsNaN(v) {
		return base
	}
	if v == 0 {
		v = 0
	}
	if s, ok := x.frozen[v]; ok {
		return base.Union(s)
	}
	return base
}
