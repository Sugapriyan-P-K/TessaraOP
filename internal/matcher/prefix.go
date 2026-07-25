package matcher

import "github.com/suga/tessaraop/internal/bitset"

// PrefixIndex answers "which policies have a prefix condition satisfied by
// this path".
//
// Rather than a character trie, it records the distinct prefix lengths that
// actually occur in the corpus and probes only those. A path is checked
// against however many distinct lengths exist — typically a handful, since
// real policy sets reuse a small number of path roots (/api, /api/v2,
// /api/v2/admin) — instead of one probe per character. Substring slicing in
// Go shares the backing array, so the probes do not allocate.
//
// Semantics match model.OpPrefix exactly: a raw byte-prefix test, so
// /api/v2/admin does match /api/v2/adminfoo. That is deliberately the same
// rule the validation pass applies, since an index that disagreed with
// validation in the stricter direction would wrongly drop matching policies.
type PrefixIndex struct {
	lengths  []int // ascending, distinct
	byPrefix map[string]*bitset.Builder
	frozen   map[string]*bitset.Set
	n        int
}

// NewPrefixIndex returns an empty index over a shard of `universe` policies.
func NewPrefixIndex(universe int) *PrefixIndex {
	return &PrefixIndex{
		byPrefix: make(map[string]*bitset.Builder),
		n:        universe,
	}
}

// Insert records that the policy at policyIdx accepts paths starting with p.
func (x *PrefixIndex) Insert(p string, policyIdx int) {
	b, ok := x.byPrefix[p]
	if !ok {
		b = bitset.NewBuilder(x.n)
		x.byPrefix[p] = b
		x.insertLength(len(p))
	}
	b.Add(policyIdx)
}

func (x *PrefixIndex) insertLength(l int) {
	lo, hi := 0, len(x.lengths)
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		if x.lengths[mid] < l {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo < len(x.lengths) && x.lengths[lo] == l {
		return
	}
	x.lengths = append(x.lengths, 0)
	copy(x.lengths[lo+1:], x.lengths[lo:])
	x.lengths[lo] = l
}

// Freeze finalizes every prefix set. Call once after all Inserts.
func (x *PrefixIndex) Freeze() {
	x.frozen = make(map[string]*bitset.Set, len(x.byPrefix))
	for p, b := range x.byPrefix {
		x.frozen[p] = b.Build()
	}
	x.byPrefix = nil
}

// Lookup unions into base the policy set of every recorded prefix of path.
func (x *PrefixIndex) Lookup(path string, base MatchSet) MatchSet {
	for _, l := range x.lengths {
		if l > len(path) {
			break // lengths ascending: nothing longer can be a prefix
		}
		if s, ok := x.frozen[path[:l]]; ok {
			base = base.Union(s)
		}
	}
	return base
}
