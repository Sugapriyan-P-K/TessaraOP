package matcher

import (
	"testing"

	"github.com/suga/tessaraop/internal/bitset"
)

func suffixMembers(x *SuffixIndex, val string) map[int]bool {
	ms := x.Lookup(val, MatchSet{})
	out := map[int]bool{}
	for _, m := range ms.AppendMembers(nil) {
		out[m] = true
	}
	return out
}

func TestSuffixIndex_MatchesRegisteredEndings(t *testing.T) {
	x := NewSuffixIndex(8)
	x.Insert(".exe", 0)
	x.Insert(".php", 1)
	x.Insert("shell.php", 2)
	x.Freeze()

	got := suffixMembers(x, "upload/shell.php")
	if !got[1] {
		t.Error("the .php rule must match")
	}
	if !got[2] {
		t.Error("the longer shell.php suffix must also match")
	}
	if got[0] {
		t.Error("the .exe rule must not match")
	}
}

func TestSuffixIndex_NoMatchYieldsNothing(t *testing.T) {
	x := NewSuffixIndex(4)
	x.Insert(".exe", 0)
	x.Freeze()
	if got := suffixMembers(x, "report.pdf"); len(got) != 0 {
		t.Fatalf("expected no matches, got %v", got)
	}
}

// TestSuffixIndex_SuffixLongerThanValue guards the length cut. Slicing
// val[len(val)-l:] with l greater than len(val) would panic, so the ascending
// length scan must stop before it.
func TestSuffixIndex_SuffixLongerThanValue(t *testing.T) {
	x := NewSuffixIndex(4)
	x.Insert("averylongsuffix", 0)
	x.Insert("x", 1)
	x.Freeze()

	got := suffixMembers(x, "x")
	if got[0] {
		t.Error("a suffix longer than the value cannot match")
	}
	if !got[1] {
		t.Error("the one-byte suffix must match")
	}
	if len(suffixMembers(x, "")) != 0 {
		t.Error("an empty value matches no non-empty suffix")
	}
}

func TestSuffixIndex_ExactEqualityIsASuffix(t *testing.T) {
	x := NewSuffixIndex(2)
	x.Insert("config.yaml", 0)
	x.Freeze()
	if !suffixMembers(x, "config.yaml")[0] {
		t.Fatal("a value equal to the suffix must match")
	}
}

func TestSuffixIndex_UnionsIntoBase(t *testing.T) {
	// Lookup must add to whatever base it is handed, since the index layer passes
	// the non-participant set in as the starting point.
	base := bitset.NewBuilder(8)
	base.Add(7)

	x := NewSuffixIndex(8)
	x.Insert(".php", 0)
	x.Freeze()

	ms := x.Lookup("a.php", Single(base.Build()))
	got := map[int]bool{}
	for _, m := range ms.AppendMembers(nil) {
		got[m] = true
	}
	if !got[0] || !got[7] {
		t.Fatalf("expected both the match and the base member, got %v", got)
	}
}
