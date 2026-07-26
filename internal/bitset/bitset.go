// Package bitset implements a hybrid sparse/dense integer set.
//
// v1 of this project used a purely dense []uint64 bitset. Benchmarking at 1M
// policies showed why that caps out: every AND touched N/64 words and every
// enumeration walked the whole universe, so cost scaled with the corpus size
// rather than with the number of surviving candidates. End-to-end speedup
// collapsed to ~1.1x even though the index was still cutting candidates 10x.
//
// A Set here carries whichever representation fits its cardinality:
//
//	sparse: sorted []uint32 of members   — O(k) space, O(log k) membership
//	dense:  []uint64 bitmap              — O(n/64) space, O(1) membership
//
// The engine's hot path exploits this: it materializes the single most
// selective posting list, then filters that list in place against the
// remaining sets using Contains. Cost becomes proportional to the candidate
// set, not to the corpus — which is the property v1 was missing.
package bitset

import (
	"math/bits"
	"sort"
)

// Set is an immutable-after-Compact set of non-negative ints below Universe.
type Set struct {
	sparse []uint32 // sorted ascending; non-nil when sparse
	dense  []uint64 // bitmap; non-nil when dense
	n      int      // universe size
	card   int      // cardinality, always maintained
}

// sparseLimit reports the cardinality below which the sparse representation
// is the smaller of the two. A sparse entry costs 4 bytes; the dense bitmap
// costs n/8 bytes total, so sparse wins below n/32. The floor keeps small
// universes from flapping between representations.
func sparseLimit(n int) int {
	limit := n / 32
	if limit < 64 {
		limit = 64
	}
	return limit
}

// New returns an empty set over [0, n).
func New(n int) *Set {
	return &Set{n: n, sparse: []uint32{}}
}

// NewDense returns an empty dense set over [0, n). Used by builders that will
// set many bits and compact afterwards.
func NewDense(n int) *Set {
	return &Set{n: n, dense: make([]uint64, (n+63)/64)}
}

// Full returns the set containing every element of [0, n).
func Full(n int) *Set {
	s := NewDense(n)
	for i := range s.dense {
		s.dense[i] = ^uint64(0)
	}
	// Clear the padding bits above n in the final word so Cardinality and
	// iteration never report members outside the universe.
	if rem := n % 64; rem != 0 && len(s.dense) > 0 {
		s.dense[len(s.dense)-1] = (uint64(1) << uint(rem)) - 1
	}
	s.card = n
	return s
}

// Universe returns the size of the domain this set is defined over.
func (s *Set) Universe() int { return s.n }

// Cardinality returns the number of members.
func (s *Set) Cardinality() int { return s.card }

// IsSparse reports which representation is in use (exposed for tests and for
// the benchmark harness's reporting).
func (s *Set) IsSparse() bool { return s.dense == nil }

// Add inserts i. Only valid on dense sets during construction; call Compact
// when the build is finished.
func (s *Set) Add(i int) {
	if s.dense == nil {
		panic("bitset: Add on a sparse set; build with NewDense")
	}
	w, b := i/64, uint(i)%64
	if s.dense[w]&(1<<b) == 0 {
		s.dense[w] |= 1 << b
		s.card++
	}
}

// Contains reports membership: O(1) on dense sets, O(log k) on sparse ones.
// This is the hot-path primitive — the engine's intersection filter calls it
// once per surviving candidate per attribute.
func (s *Set) Contains(i int) bool {
	if i < 0 || i >= s.n {
		return false
	}
	if s.dense != nil {
		return s.dense[i/64]&(1<<(uint(i)%64)) != 0
	}
	v := uint32(i)
	lo, hi := 0, len(s.sparse)
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		if s.sparse[mid] < v {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return lo < len(s.sparse) && s.sparse[lo] == v
}

// Compact converts to whichever representation is smaller for the current
// cardinality. Called once at the end of index construction.
func (s *Set) Compact() *Set {
	if s.dense != nil && s.card <= sparseLimit(s.n) {
		out := make([]uint32, 0, s.card)
		for w, word := range s.dense {
			for word != 0 {
				out = append(out, uint32(w*64+bits.TrailingZeros64(word)))
				word &= word - 1
			}
		}
		s.sparse, s.dense = out, nil
	}
	return s
}

// AppendMembers appends every member in ascending order to dst and returns
// the extended slice. Passing a reusable buffer keeps the hot path
// allocation-free across requests.
func (s *Set) AppendMembers(dst []int) []int {
	if s.dense == nil {
		for _, v := range s.sparse {
			dst = append(dst, int(v))
		}
		return dst
	}
	for w, word := range s.dense {
		for word != 0 {
			dst = append(dst, w*64+bits.TrailingZeros64(word))
			word &= word - 1
		}
	}
	return dst
}

// Members returns a freshly allocated slice of all members. Convenience for
// tests; the hot path uses AppendMembers with a reused buffer.
func (s *Set) Members() []int { return s.AppendMembers(make([]int, 0, s.card)) }

// WordCount reports how many 64-bit words a bitmap over [0, n) needs. The index
// layer sizes its word-parallel scratch buffers with it.
func WordCount(n int) int { return (n + 63) / 64 }

// OrWords sets, in dst, every bit this set holds. dst must hold at least
// WordCount(s.Universe()) words and is not cleared first, so successive calls
// accumulate a union.
//
// This is the bridge to the word-parallel intersection path. It exists because
// the alternative — exposing the backing array — would let a caller mutate a set
// that shards share across every request, and because a sparse set has no
// backing array to expose. Both representations can write themselves into a
// caller-owned buffer, and the buffer is what gets AND-ed.
func (s *Set) OrWords(dst []uint64) {
	if s.dense == nil {
		for _, v := range s.sparse {
			dst[v/64] |= 1 << (uint(v) % 64)
		}
		return
	}
	n := len(s.dense)
	if n > len(dst) {
		n = len(dst)
	}
	for i := 0; i < n; i++ {
		dst[i] |= s.dense[i]
	}
}

// Or returns the union. Used at build time to fold multiple value postings
// into one set (e.g. an `in [a,b,c]` condition).
func (s *Set) Or(other *Set) *Set {
	n := max(s.n, other.n)
	out := NewDense(n)
	s.writeInto(out)
	other.writeInto(out)
	out.recount()
	return out.Compact()
}

// And returns the intersection. Build-time helper; the request hot path uses
// the filter-in-place approach in the index layer instead.
func (s *Set) And(other *Set) *Set {
	n := max(s.n, other.n)
	// Drive the scan from the smaller side so cost tracks the smaller set.
	small, large := s, other
	if large.card < small.card {
		small, large = large, small
	}
	out := NewDense(n)
	if small.dense == nil {
		for _, v := range small.sparse {
			if large.Contains(int(v)) {
				out.Add(int(v))
			}
		}
	} else {
		for w, word := range small.dense {
			for word != 0 {
				i := w*64 + bits.TrailingZeros64(word)
				word &= word - 1
				if large.Contains(i) {
					out.Add(i)
				}
			}
		}
	}
	return out.Compact()
}

// AndNot returns the difference s \ other. This is how negated conditions
// (ne, nin, ncidr) build their candidate sets: start from the universe of
// policies carrying the condition, remove the ones the request value hits.
func (s *Set) AndNot(other *Set) *Set {
	out := NewDense(max(s.n, other.n))
	if s.dense == nil {
		for _, v := range s.sparse {
			if !other.Contains(int(v)) {
				out.Add(int(v))
			}
		}
	} else {
		for w, word := range s.dense {
			for word != 0 {
				i := w*64 + bits.TrailingZeros64(word)
				word &= word - 1
				if !other.Contains(i) {
					out.Add(i)
				}
			}
		}
	}
	return out.Compact()
}

// Complement returns [0, n) \ s.
func (s *Set) Complement() *Set { return Full(s.n).AndNot(s) }

func (s *Set) writeInto(dst *Set) {
	if s.dense == nil {
		for _, v := range s.sparse {
			dst.dense[v/64] |= 1 << (uint(v) % 64)
		}
		return
	}
	for i, word := range s.dense {
		if i < len(dst.dense) {
			dst.dense[i] |= word
		}
	}
}

func (s *Set) recount() {
	c := 0
	for _, w := range s.dense {
		c += bits.OnesCount64(w)
	}
	s.card = c
}

// Builder accumulates members efficiently when the final cardinality is not
// known in advance, deferring the representation choice to Build.
type Builder struct {
	n    int
	dst  *Set
	seen map[uint32]struct{}
}

func NewBuilder(n int) *Builder { return &Builder{n: n, dst: NewDense(n)} }

func (b *Builder) Add(i int) { b.dst.Add(i) }

func (b *Builder) Build() *Set { return b.dst.Compact() }

// FromSorted wraps an already-sorted, duplicate-free slice as a sparse set
// without copying. The caller must not mutate the slice afterwards.
func FromSorted(members []uint32, n int) *Set {
	return &Set{sparse: members, n: n, card: len(members)}
}

// FromUnsorted sorts and dedupes members into a sparse set.
func FromUnsorted(members []uint32, n int) *Set {
	sort.Slice(members, func(i, j int) bool { return members[i] < members[j] })
	out := members[:0]
	var last uint32
	for i, v := range members {
		if i == 0 || v != last {
			out = append(out, v)
			last = v
		}
	}
	return FromSorted(out, n)
}
