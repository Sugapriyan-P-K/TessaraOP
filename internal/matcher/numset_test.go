package matcher

import (
	"math"
	"testing"

	"github.com/suga/tessaraop/internal/bitset"
)

func numMembers(x *NumSetIndex, v float64) map[int]bool {
	ms := x.Lookup(v, MatchSet{})
	out := map[int]bool{}
	for _, m := range ms.AppendMembers(nil) {
		out[m] = true
	}
	return out
}

func TestNumSetIndex_ExactMembership(t *testing.T) {
	x := NewNumSetIndex(8)
	x.Insert(80, 0)
	x.Insert(443, 0)
	x.Insert(22, 1)
	x.Insert(443, 2)
	x.Freeze()

	got := numMembers(x, 443)
	if !got[0] || !got[2] {
		t.Errorf("both rules accepting 443 must match, got %v", got)
	}
	if got[1] {
		t.Error("the rule accepting only 22 must not match")
	}
	if len(numMembers(x, 8080)) != 0 {
		t.Error("an unregistered value must match nothing")
	}
}

// TestNumSetIndex_HighCardinalityStaysSelective is the reason this index exists
// rather than reusing IntervalIndex with degenerate [v,v] ranges. Well past
// MaxDistinctIntervals distinct values, a lookup must still return only the
// rules that actually accept the value.
func TestNumSetIndex_HighCardinalityStaysSelective(t *testing.T) {
	const n = MaxDistinctIntervals * 2
	x := NewNumSetIndex(n)
	for i := 0; i < n; i++ {
		x.Insert(float64(i), i)
	}
	x.Freeze()

	const probe = n - 7 // well past MaxDistinctIntervals, inside the inserted range
	got := numMembers(x, probe)
	if len(got) != 1 || !got[probe] {
		t.Fatalf("expected exactly the rule accepting %d, got %v", probe, got)
	}
}

func TestNumSetIndex_NaNIsDropped(t *testing.T) {
	x := NewNumSetIndex(4)
	nan := math.NaN()
	x.Insert(nan, 0)
	x.Insert(1, 1)
	x.Freeze()

	if len(numMembers(x, nan)) != 0 {
		t.Error("a NaN lookup must match nothing")
	}
	if !numMembers(x, 1)[1] {
		t.Error("a real value must still match after a NaN insert")
	}
}

// TestNumSetIndex_NegativeZeroSharesABucket keeps the index consistent with
// Condition.Matches, which compares with == and therefore treats -0 and +0 as
// equal.
func TestNumSetIndex_NegativeZeroSharesABucket(t *testing.T) {
	x := NewNumSetIndex(4)
	x.Insert(math.Copysign(0, -1), 0)
	x.Freeze()

	if !numMembers(x, 0)[0] {
		t.Error("+0 must find a rule inserted under -0")
	}
	if !numMembers(x, math.Copysign(0, -1))[0] {
		t.Error("-0 must find its own rule")
	}
}

func TestNumSetIndex_UnionsIntoBase(t *testing.T) {
	base := bitset.NewBuilder(8)
	base.Add(7)

	x := NewNumSetIndex(8)
	x.Insert(443, 0)
	x.Freeze()

	ms := x.Lookup(443, Single(base.Build()))
	got := map[int]bool{}
	for _, m := range ms.AppendMembers(nil) {
		got[m] = true
	}
	if !got[0] || !got[7] {
		t.Fatalf("expected both the match and the base member, got %v", got)
	}
}
