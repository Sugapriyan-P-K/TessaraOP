package matcher

import (
	"math"
	"net/netip"
	"reflect"
	"testing"

	"github.com/suga/tessaraop/internal/bitset"
)

func setOf(n int, members ...int) *bitset.Set {
	b := bitset.NewBuilder(n)
	for _, m := range members {
		b.Add(m)
	}
	return b.Build()
}

// --- MatchSet ---------------------------------------------------------------

func TestMatchSet_LazyUnion(t *testing.T) {
	a := setOf(64, 1, 2)
	b := setOf(64, 2, 3)
	ms := Single(a).Union(b)

	for _, want := range []int{1, 2, 3} {
		if !ms.Contains(want) {
			t.Fatalf("expected %d in union", want)
		}
	}
	if ms.Contains(4) {
		t.Fatal("4 is in neither set")
	}
}

func TestMatchSet_AppendMembersDedupes(t *testing.T) {
	ms := Single(setOf(64, 1, 2)).Union(setOf(64, 2, 3))
	if got, want := ms.AppendMembers(nil), []int{1, 2, 3}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestMatchSet_EstimateIsUpperBound(t *testing.T) {
	// Overlapping sets: the estimate may exceed the true union size, which is
	// fine because it only orders intersections.
	ms := Single(setOf(64, 1, 2)).Union(setOf(64, 2, 3))
	if ms.EstimatedCardinality() < len(ms.AppendMembers(nil)) {
		t.Fatal("estimate must be an upper bound on the true union size")
	}
}

func TestMatchSet_Empty(t *testing.T) {
	if !Empty.IsEmpty() {
		t.Fatal("Empty must report empty")
	}
	if Empty.Contains(0) {
		t.Fatal("Empty must contain nothing")
	}
}

// --- CIDR -------------------------------------------------------------------

func TestCIDR_MatchesEnclosingPrefixes(t *testing.T) {
	const n = 64
	idx := NewCIDRIndex()
	idx.Insert(netip.MustParsePrefix("10.0.0.0/8"), 0, n)
	idx.Insert(netip.MustParsePrefix("10.4.0.0/16"), 1, n)
	idx.Insert(netip.MustParsePrefix("192.168.0.0/16"), 2, n)
	idx.Freeze()

	got := idx.Lookup(netip.MustParseAddr("10.4.2.7"), MatchSet{})
	// Both 10.0.0.0/8 and 10.4.0.0/16 contain this address; every enclosing
	// prefix must match, not merely the longest.
	if !got.Contains(0) || !got.Contains(1) {
		t.Fatalf("expected policies 0 and 1, got %v", got.AppendMembers(nil))
	}
	if got.Contains(2) {
		t.Fatal("192.168.0.0/16 does not contain 10.4.2.7")
	}
}

func TestCIDR_NoMatch(t *testing.T) {
	idx := NewCIDRIndex()
	idx.Insert(netip.MustParsePrefix("10.0.0.0/8"), 0, 64)
	idx.Freeze()

	got := idx.Lookup(netip.MustParseAddr("8.8.8.8"), MatchSet{})
	if !got.IsEmpty() {
		t.Fatalf("expected no match, got %v", got.AppendMembers(nil))
	}
}

func TestCIDR_DefaultRouteMatchesEverything(t *testing.T) {
	idx := NewCIDRIndex()
	idx.Insert(netip.MustParsePrefix("0.0.0.0/0"), 0, 64)
	idx.Freeze()

	for _, addr := range []string{"1.2.3.4", "10.0.0.1", "255.255.255.255"} {
		got := idx.Lookup(netip.MustParseAddr(addr), MatchSet{})
		if !got.Contains(0) {
			t.Fatalf("0.0.0.0/0 must contain %s", addr)
		}
	}
}

func TestCIDR_HostRoute(t *testing.T) {
	idx := NewCIDRIndex()
	idx.Insert(netip.MustParsePrefix("10.1.2.3/32"), 0, 64)
	idx.Freeze()

	hit := idx.Lookup(netip.MustParseAddr("10.1.2.3"), MatchSet{})
	if !hit.Contains(0) {
		t.Fatal("/32 must match its exact address")
	}
	miss := idx.Lookup(netip.MustParseAddr("10.1.2.4"), MatchSet{})
	if miss.Contains(0) {
		t.Fatal("/32 must not match a neighbouring address")
	}
}

func TestCIDR_IPv6(t *testing.T) {
	idx := NewCIDRIndex()
	idx.Insert(netip.MustParsePrefix("2001:db8::/32"), 0, 64)
	idx.Freeze()

	hit := idx.Lookup(netip.MustParseAddr("2001:db8:1234::1"), MatchSet{})
	if !hit.Contains(0) {
		t.Fatal("expected IPv6 prefix match")
	}
	miss := idx.Lookup(netip.MustParseAddr("2001:db9::1"), MatchSet{})
	if miss.Contains(0) {
		t.Fatal("unexpected IPv6 match outside the prefix")
	}
}

func TestCIDR_V4MappedFormsAreEquivalent(t *testing.T) {
	// A v4 prefix must be found whether the query arrives as 10.4.2.7 or as
	// ::ffff:10.4.2.7, since both denote the same host.
	idx := NewCIDRIndex()
	idx.Insert(netip.MustParsePrefix("10.0.0.0/8"), 0, 64)
	idx.Freeze()

	plain := idx.Lookup(netip.MustParseAddr("10.4.2.7"), MatchSet{})
	mapped := idx.Lookup(netip.MustParseAddr("::ffff:10.4.2.7"), MatchSet{})
	if !plain.Contains(0) || !mapped.Contains(0) {
		t.Fatal("v4 and v4-mapped queries must agree")
	}
}

func TestCIDR_UnmaskedPrefixIsNormalized(t *testing.T) {
	// 10.4.2.7/8 has bits set below the mask; Masked() must normalize it to
	// 10.0.0.0/8 or lookups land in the wrong subtree.
	idx := NewCIDRIndex()
	idx.Insert(netip.MustParsePrefix("10.4.2.7/8"), 0, 64)
	idx.Freeze()

	got := idx.Lookup(netip.MustParseAddr("10.9.9.9"), MatchSet{})
	if !got.Contains(0) {
		t.Fatal("unmasked prefix should still cover its whole block")
	}
}

// --- Domain -----------------------------------------------------------------

func TestDomain_ExactAndSubdomain(t *testing.T) {
	idx := NewDomainIndex(64)
	idx.Insert("acme.com", 0)
	idx.Freeze()

	for _, host := range []string{"acme.com", "api.acme.com", "a.b.acme.com"} {
		got := idx.Lookup(host, MatchSet{})
		if !got.Contains(0) {
			t.Fatalf("expected %s to match acme.com", host)
		}
	}
}

func TestDomain_RejectsUnalignedSuffix(t *testing.T) {
	// The bug this guards: strings.HasSuffix("evilacme.com", "acme.com") is
	// true, so a naive suffix check would hand evilacme.com the authorization
	// scoped to acme.com. Label alignment is what prevents it.
	idx := NewDomainIndex(64)
	idx.Insert("acme.com", 0)
	idx.Freeze()

	for _, host := range []string{"evilacme.com", "notacme.com", "acme.com.attacker.net"} {
		got := idx.Lookup(host, MatchSet{})
		if got.Contains(0) {
			t.Fatalf("%s must not match acme.com", host)
		}
	}
}

func TestDomain_NestedSuffixesBothMatch(t *testing.T) {
	idx := NewDomainIndex(64)
	idx.Insert("acme.com", 0)
	idx.Insert("admin.acme.com", 1)
	idx.Freeze()

	got := idx.Lookup("api.admin.acme.com", MatchSet{})
	if !got.Contains(0) || !got.Contains(1) {
		t.Fatalf("both enclosing suffixes should match, got %v", got.AppendMembers(nil))
	}

	only := idx.Lookup("api.acme.com", MatchSet{})
	if !only.Contains(0) || only.Contains(1) {
		t.Fatal("api.acme.com is not under admin.acme.com")
	}
}

func TestDomain_SiblingDoesNotMatch(t *testing.T) {
	idx := NewDomainIndex(64)
	idx.Insert("admin.acme.com", 0)
	idx.Freeze()

	got := idx.Lookup("public.acme.com", MatchSet{})
	if got.Contains(0) {
		t.Fatal("sibling label must not match")
	}
}

// --- Prefix -----------------------------------------------------------------

func TestPrefix_Matches(t *testing.T) {
	idx := NewPrefixIndex(64)
	idx.Insert("/api/v2", 0)
	idx.Insert("/api/v2/admin", 1)
	idx.Freeze()

	got := idx.Lookup("/api/v2/admin/users", MatchSet{})
	if !got.Contains(0) || !got.Contains(1) {
		t.Fatalf("both prefixes should match, got %v", got.AppendMembers(nil))
	}
}

func TestPrefix_ShorterPathDoesNotMatchLongerPrefix(t *testing.T) {
	idx := NewPrefixIndex(64)
	idx.Insert("/api/v2/admin", 0)
	idx.Freeze()

	got := idx.Lookup("/api/v2", MatchSet{})
	if got.Contains(0) {
		t.Fatal("a path shorter than the prefix cannot match it")
	}
}

func TestPrefix_ByteSemanticsMatchValidation(t *testing.T) {
	// model.OpPrefix is a raw byte prefix test, so /api/v2/admin does match
	// /api/v2/adminfoo. The index has to agree, since an index stricter than
	// validation would drop policies that genuinely match.
	idx := NewPrefixIndex(64)
	idx.Insert("/api/v2/admin", 0)
	idx.Freeze()

	got := idx.Lookup("/api/v2/adminfoo", MatchSet{})
	if !got.Contains(0) {
		t.Fatal("index must mirror byte-prefix validation semantics")
	}
}

// --- Interval ---------------------------------------------------------------

func TestInterval_CoversValue(t *testing.T) {
	idx := NewIntervalIndex(64)
	idx.Insert(9, 17, 0)
	idx.Insert(0, 6, 1)
	idx.Freeze()

	got := idx.Lookup(14, MatchSet{})
	if !got.Contains(0) || got.Contains(1) {
		t.Fatalf("only the 9-17 window covers 14, got %v", got.AppendMembers(nil))
	}
}

func TestInterval_Boundaries(t *testing.T) {
	idx := NewIntervalIndex(64)
	idx.Insert(9, 17, 0)
	idx.Freeze()

	for _, v := range []float64{9, 17} {
		got := idx.Lookup(v, MatchSet{})
		if !got.Contains(0) {
			t.Fatalf("range is inclusive; %v must match", v)
		}
	}
	for _, v := range []float64{8.999, 17.001} {
		got := idx.Lookup(v, MatchSet{})
		if got.Contains(0) {
			t.Fatalf("%v lies outside the range", v)
		}
	}
}

func TestInterval_UnboundedEnds(t *testing.T) {
	idx := NewIntervalIndex(64)
	idx.Insert(90, math.Inf(1), 0)  // risk_score > 90
	idx.Insert(math.Inf(-1), 10, 1) // risk_score < 10
	idx.Freeze()

	big := idx.Lookup(1e6, MatchSet{})
	if !big.Contains(0) {
		t.Fatal("open upper bound must match arbitrarily large values")
	}
	small := idx.Lookup(-1e6, MatchSet{})
	if !small.Contains(1) {
		t.Fatal("open lower bound must match arbitrarily small values")
	}
	mid := idx.Lookup(50, MatchSet{})
	if mid.Contains(0) {
		t.Fatal("50 is not above 90")
	}
}

func TestInterval_SharedRangesCollapse(t *testing.T) {
	// Many policies referencing one window must collapse to a single entry —
	// that is the property keeping lookups cheap at corpus scale.
	idx := NewIntervalIndex(4096)
	for i := 0; i < 1000; i++ {
		idx.Insert(9, 17, i)
	}
	idx.Freeze()

	got := idx.Lookup(12, MatchSet{})
	if n := len(got.AppendMembers(nil)); n != 1000 {
		t.Fatalf("expected all 1000 policies, got %d", n)
	}
	if len(idx.entries) != 1 {
		t.Fatalf("1000 identical ranges should collapse to 1 entry, got %d", len(idx.entries))
	}
}

func TestInterval_DegradesPastCap(t *testing.T) {
	idx := NewIntervalIndex(MaxDistinctIntervals * 2)
	for i := 0; i < MaxDistinctIntervals+10; i++ {
		idx.Insert(float64(i), float64(i)+1, i)
	}
	idx.Freeze()

	if !idx.Degraded() {
		t.Fatal("exceeding the distinct-range cap must set Degraded")
	}
	got := idx.Lookup(5, MatchSet{})
	if !got.IsEmpty() {
		t.Fatal("a degraded index must return nothing so the caller falls back")
	}
}

func TestInterval_NaNMatchesNothing(t *testing.T) {
	idx := NewIntervalIndex(64)
	idx.Insert(math.Inf(-1), math.Inf(1), 0)
	idx.Freeze()

	got := idx.Lookup(math.NaN(), MatchSet{})
	if !got.IsEmpty() {
		t.Fatal("NaN compares false against every bound and must match nothing")
	}
}
