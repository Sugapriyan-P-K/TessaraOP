// Package matcher provides the per-attribute index structures the engine
// uses to turn a request value into a candidate policy set.
//
// A hash map answers "which policies require department == engineering".
// It cannot answer "which policies have a CIDR block containing 10.4.2.7",
// "which policies accept the host api.admin.acme.com", or "which policies
// have a time window covering 14:30". Those need a radix trie, a reversed
// label trie, and an interval structure respectively — that is what lives
// here.
//
// Every matcher answers the same shape of question and returns a MatchSet.
package matcher

import (
	"sort"

	"github.com/suga/tessaraop/internal/bitset"
)

// maxInlineSets bounds the lazy union's inline capacity. Unions arise from
// nested matches — enclosing CIDR prefixes, enclosing DNS suffixes, covering
// numeric ranges — plus one non-participant set. Real corpora nest a handful
// deep, so eight covers essentially everything inline; deeper unions still
// work, they just spill to the heap.
const maxInlineSets = 8

// MatchSet is the union of zero or more precomputed sets, evaluated lazily.
//
// Two things keep this off the heap. The union is lazy, so a CIDR lookup
// matching several nested prefixes never OR-s them into a new set — the engine
// materializes only the single most selective MatchSet and probes the rest with
// Contains. And the members live in a fixed array rather than a slice, because
// a slice would allocate once per filter per request, which measured as the
// bulk of the engine's allocation traffic.
type MatchSet struct {
	inline   [maxInlineSets]*bitset.Set
	n        int
	overflow []*bitset.Set // used only past maxInlineSets
	est      int
}

// Empty is the MatchSet matching nothing — used when a request carries an
// attribute whose value no policy condition accepts.
var Empty = MatchSet{}

// Single wraps one set.
func Single(s *bitset.Set) MatchSet {
	if s == nil || s.Cardinality() == 0 {
		return Empty
	}
	var m MatchSet
	m.inline[0] = s
	m.n = 1
	m.est = s.Cardinality()
	return m
}

// Union adds another set to the lazy union.
func (m MatchSet) Union(s *bitset.Set) MatchSet {
	if s == nil || s.Cardinality() == 0 {
		return m
	}
	if m.n < maxInlineSets {
		m.inline[m.n] = s
		m.n++
	} else {
		m.overflow = append(m.overflow, s)
	}
	m.est += s.Cardinality()
	return m
}

// Contains reports whether any constituent set holds i.
func (m *MatchSet) Contains(i int) bool {
	for k := 0; k < m.n; k++ {
		if m.inline[k].Contains(i) {
			return true
		}
	}
	for _, s := range m.overflow {
		if s.Contains(i) {
			return true
		}
	}
	return false
}

// count reports the total number of constituent sets.
func (m *MatchSet) count() int { return m.n + len(m.overflow) }

// at returns the k'th constituent set.
func (m *MatchSet) at(k int) *bitset.Set {
	if k < m.n {
		return m.inline[k]
	}
	return m.overflow[k-m.n]
}

// EstimatedCardinality is the sum of member cardinalities: an upper bound on
// the true union size, since the sets may overlap. The engine uses it only to
// order intersections cheapest-first, so an upper bound is fine — a bad
// estimate costs a little speed, never correctness.
func (m *MatchSet) EstimatedCardinality() int { return m.est }

// IsEmpty reports whether the union holds nothing.
func (m *MatchSet) IsEmpty() bool { return m.count() == 0 || m.est == 0 }

// AppendMembers appends the deduplicated union to dst. The engine calls this
// exactly once per request, on the most selective MatchSet only.
func (m *MatchSet) AppendMembers(dst []int) []int {
	switch m.count() {
	case 0:
		return dst
	case 1:
		return m.at(0).AppendMembers(dst)
	}
	start := len(dst)
	for k := 0; k < m.count(); k++ {
		dst = m.at(k).AppendMembers(dst)
	}
	// Constituent sets may overlap, so sort and dedupe the appended region.
	region := dst[start:]
	sort.Ints(region)
	w := start
	for i, v := range region {
		if i == 0 || v != dst[w-1] {
			dst[w] = v
			w++
		}
	}
	return dst[:w]
}
