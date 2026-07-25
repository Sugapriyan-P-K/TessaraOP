package bitset

import (
	"math/rand"
	"reflect"
	"testing"
)

func TestNewDense_Empty(t *testing.T) {
	b := NewDense(100)
	if b.Cardinality() != 0 {
		t.Fatalf("new set should be empty, got %d", b.Cardinality())
	}
	if b.Universe() != 100 {
		t.Fatalf("expected universe 100, got %d", b.Universe())
	}
}

func TestAddContains(t *testing.T) {
	b := NewDense(200)
	want := []int{0, 1, 63, 64, 65, 127, 199}
	for _, v := range want {
		b.Add(v)
	}
	for _, v := range want {
		if !b.Contains(v) {
			t.Fatalf("expected %d present", v)
		}
	}
	if b.Contains(2) {
		t.Fatal("expected 2 absent")
	}
	if b.Cardinality() != len(want) {
		t.Fatalf("expected cardinality %d, got %d", len(want), b.Cardinality())
	}
}

func TestAdd_IsIdempotent(t *testing.T) {
	b := NewDense(64)
	b.Add(7)
	b.Add(7)
	if b.Cardinality() != 1 {
		t.Fatalf("re-adding must not double count, got %d", b.Cardinality())
	}
}

func TestFull_ExcludesPaddingBits(t *testing.T) {
	// A universe that is not a multiple of 64 leaves padding bits in the last
	// word. If Full sets them, cardinality and iteration report members that
	// do not exist.
	b := Full(100)
	if b.Cardinality() != 100 {
		t.Fatalf("expected cardinality 100, got %d", b.Cardinality())
	}
	if b.Contains(100) || b.Contains(127) {
		t.Fatal("padding bits must not be reported as members")
	}
	if got := len(b.Members()); got != 100 {
		t.Fatalf("expected 100 members, got %d", got)
	}
}

func TestCompact_SwitchesToSparse(t *testing.T) {
	b := NewDense(100000)
	for i := 0; i < 10; i++ {
		b.Add(i * 1000)
	}
	b.Compact()
	if !b.IsSparse() {
		t.Fatal("a 10-member set over a 100k universe should compact to sparse")
	}
	for i := 0; i < 10; i++ {
		if !b.Contains(i * 1000) {
			t.Fatalf("member %d lost in compaction", i*1000)
		}
	}
	if b.Contains(500) {
		t.Fatal("compaction invented a member")
	}
}

func TestCompact_StaysDenseWhenLarge(t *testing.T) {
	b := NewDense(1000)
	for i := 0; i < 900; i++ {
		b.Add(i)
	}
	b.Compact()
	if b.IsSparse() {
		t.Fatal("a 900-member set over a 1000 universe should stay dense")
	}
}

func TestContains_BothRepresentationsAgree(t *testing.T) {
	const n = 5000
	rng := rand.New(rand.NewSource(7))
	truth := map[int]bool{}
	dense := NewDense(n)
	for i := 0; i < 60; i++ {
		v := rng.Intn(n)
		truth[v] = true
		dense.Add(v)
	}
	sparse := NewDense(n)
	for v := range truth {
		sparse.Add(v)
	}
	sparse.Compact()

	if !sparse.IsSparse() {
		t.Fatal("expected sparse representation for this cardinality")
	}
	for i := 0; i < n; i++ {
		if dense.Contains(i) != sparse.Contains(i) {
			t.Fatalf("representations disagree at %d", i)
		}
		if dense.Contains(i) != truth[i] {
			t.Fatalf("wrong membership at %d", i)
		}
	}
}

func TestAnd(t *testing.T) {
	a := NewDense(64)
	b := NewDense(64)
	for _, v := range []int{0, 1, 2} {
		a.Add(v)
	}
	for _, v := range []int{1, 2, 3} {
		b.Add(v)
	}
	if got, want := a.And(b).Members(), []int{1, 2}; !reflect.DeepEqual(got, want) {
		t.Fatalf("And: got %v want %v", got, want)
	}
}

func TestOr(t *testing.T) {
	a := NewDense(64)
	b := NewDense(64)
	a.Add(0)
	a.Add(1)
	b.Add(1)
	b.Add(2)
	if got, want := a.Or(b).Members(), []int{0, 1, 2}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Or: got %v want %v", got, want)
	}
}

func TestAndNot(t *testing.T) {
	a := NewDense(64)
	b := NewDense(64)
	for _, v := range []int{0, 1, 2, 3} {
		a.Add(v)
	}
	b.Add(1)
	b.Add(3)
	if got, want := a.AndNot(b).Members(), []int{0, 2}; !reflect.DeepEqual(got, want) {
		t.Fatalf("AndNot: got %v want %v", got, want)
	}
}

func TestComplement(t *testing.T) {
	a := NewDense(10)
	a.Add(0)
	a.Add(9)
	if got, want := a.Complement().Members(),
		[]int{1, 2, 3, 4, 5, 6, 7, 8}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Complement: got %v want %v", got, want)
	}
}

func TestComplement_RoundTrips(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	const n = 300
	a := NewDense(n)
	for i := 0; i < 50; i++ {
		a.Add(rng.Intn(n))
	}
	a.Compact()
	back := a.Complement().Complement()
	for i := 0; i < n; i++ {
		if a.Contains(i) != back.Contains(i) {
			t.Fatalf("double complement differs at %d", i)
		}
	}
}

func TestAppendMembers_ReusesBuffer(t *testing.T) {
	a := NewDense(128)
	a.Add(5)
	a.Add(70)
	buf := make([]int, 0, 8)
	buf = a.AppendMembers(buf)
	if !reflect.DeepEqual(buf, []int{5, 70}) {
		t.Fatalf("unexpected members %v", buf)
	}
	buf = a.AppendMembers(buf[:0])
	if !reflect.DeepEqual(buf, []int{5, 70}) {
		t.Fatalf("reuse produced %v", buf)
	}
}

func TestBuilder(t *testing.T) {
	b := NewBuilder(10000)
	for i := 0; i < 5; i++ {
		b.Add(i * 100)
	}
	s := b.Build()
	if s.Cardinality() != 5 {
		t.Fatalf("expected 5 members, got %d", s.Cardinality())
	}
	if !s.IsSparse() {
		t.Fatal("small set over large universe should build sparse")
	}
}

func TestFromUnsorted_SortsAndDedupes(t *testing.T) {
	s := FromUnsorted([]uint32{9, 3, 3, 7, 1, 9}, 16)
	if got, want := s.Members(), []int{1, 3, 7, 9}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestLargeUniverse(t *testing.T) {
	const n = 1_000_000
	b := NewDense(n)
	for i := 0; i < n; i += 1000 {
		b.Add(i)
	}
	if b.Cardinality() != 1000 {
		t.Fatalf("expected 1000 members, got %d", b.Cardinality())
	}
	b.Compact()
	if !b.IsSparse() {
		t.Fatal("1000 members over 1M universe should be sparse")
	}
	m := b.Members()
	if len(m) != 1000 || m[0] != 0 || m[999] != 999000 {
		t.Fatalf("unexpected members: len=%d first=%d last=%d", len(m), m[0], m[999])
	}
}
