package matcher

import "github.com/suga/tessaraop/internal/bitset"

// SuffixIndex answers "which rules have a byte-suffix condition satisfied by
// this string". It is the mirror of PrefixIndex and shares its reasoning:
// record the distinct suffix lengths the corpus actually uses and probe only
// those, since real policy sets reuse a small number of endings.
//
// The obvious implementation — reverse the string and reuse PrefixIndex —
// allocates on every lookup, which is unacceptable on a hot path that is
// otherwise allocation-free. Slicing from the right instead shares the backing
// array exactly as prefix slicing does, so this stays free.
//
// Semantics match model.OpSuffix exactly: a raw byte test, so ".php" matches
// "shell.php" and also "x.notphp"'s ending only if the bytes align. File
// extension filtering is the main user, which is why OpSuffix exists separately
// from OpDNSSuffix — hostnames need label alignment, filenames do not.
type SuffixIndex struct {
	lengths  []int // ascending, distinct
	bySuffix map[string]*bitset.Builder
	frozen   map[string]*bitset.Set
	n        int
}

// NewSuffixIndex returns an empty index over a shard of `universe` rules.
func NewSuffixIndex(universe int) *SuffixIndex {
	return &SuffixIndex{
		bySuffix: make(map[string]*bitset.Builder),
		n:        universe,
	}
}

// Insert records that the rule at ruleIdx accepts strings ending with s.
func (x *SuffixIndex) Insert(s string, ruleIdx int) {
	b, ok := x.bySuffix[s]
	if !ok {
		b = bitset.NewBuilder(x.n)
		x.bySuffix[s] = b
		x.insertLength(len(s))
	}
	b.Add(ruleIdx)
}

func (x *SuffixIndex) insertLength(l int) {
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

// Freeze finalizes every suffix set. Call once after all Inserts.
func (x *SuffixIndex) Freeze() {
	x.frozen = make(map[string]*bitset.Set, len(x.bySuffix))
	for s, b := range x.bySuffix {
		x.frozen[s] = b.Build()
	}
	x.bySuffix = nil
}

// Lookup unions into base the rule set of every recorded suffix of val.
func (x *SuffixIndex) Lookup(val string, base MatchSet) MatchSet {
	for _, l := range x.lengths {
		if l > len(val) {
			break // lengths ascending: nothing longer can be a suffix
		}
		if s, ok := x.frozen[val[len(val)-l:]]; ok {
			base = base.Union(s)
		}
	}
	return base
}
