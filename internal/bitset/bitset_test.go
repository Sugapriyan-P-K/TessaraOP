package bitset

import (
	"reflect"
	"testing"
)

func TestNew_ZeroBits(t *testing.T) {
	b := New(100)
	if b.Count() != 0 {
		t.Fatalf("new bitset should have 0 bits set, got %d", b.Count())
	}
	if b.Len() != 100 {
		t.Fatalf("expected Len() == 100, got %d", b.Len())
	}
}

func TestSetAndTest(t *testing.T) {
	b := New(128)
	positions := []int{0, 1, 63, 64, 65, 127}
	for _, p := range positions {
		b.Set(p)
	}
	for _, p := range positions {
		if !b.Test(p) {
			t.Fatalf("expected bit %d to be set", p)
		}
	}
	if b.Test(2) {
		t.Fatal("expected bit 2 to be unset")
	}
}

func TestAnd(t *testing.T) {
	a := New(64)
	b := New(64)
	a.Set(0)
	a.Set(1)
	a.Set(2)
	b.Set(1)
	b.Set(2)
	b.Set(3)

	result := a.And(b)
	want := []int{1, 2}
	if got := result.Ones(); !reflect.DeepEqual(got, want) {
		t.Fatalf("And: got %v, want %v", got, want)
	}
}

func TestOr(t *testing.T) {
	a := New(64)
	b := New(64)
	a.Set(0)
	a.Set(1)
	b.Set(1)
	b.Set(2)

	result := a.Or(b)
	want := []int{0, 1, 2}
	if got := result.Ones(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Or: got %v, want %v", got, want)
	}
}

func TestXor(t *testing.T) {
	a := New(64)
	b := New(64)
	a.Set(0)
	a.Set(1)
	b.Set(1)
	b.Set(2)

	result := a.Xor(b)
	want := []int{0, 2}
	if got := result.Ones(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Xor: got %v, want %v", got, want)
	}
}

func TestCount(t *testing.T) {
	b := New(256)
	b.Set(0)
	b.Set(63)
	b.Set(64)
	b.Set(255)
	if b.Count() != 4 {
		t.Fatalf("expected Count() == 4, got %d", b.Count())
	}
}

func TestOnes(t *testing.T) {
	b := New(200)
	positions := []int{5, 63, 64, 100, 199}
	for _, p := range positions {
		b.Set(p)
	}
	if got := b.Ones(); !reflect.DeepEqual(got, positions) {
		t.Fatalf("Ones: got %v, want %v", got, positions)
	}
}

func TestClone(t *testing.T) {
	a := New(128)
	a.Set(0)
	a.Set(127)
	b := a.Clone()

	if !b.Test(0) || !b.Test(127) {
		t.Fatal("clone should preserve set bits")
	}

	b.Set(50)
	if a.Test(50) {
		t.Fatal("mutating clone should not affect original")
	}
}

func TestLargeBitset(t *testing.T) {
	n := 100000
	b := New(n)
	for i := 0; i < n; i += 100 {
		b.Set(i)
	}
	if b.Count() != 1000 {
		t.Fatalf("expected 1000 bits set, got %d", b.Count())
	}
	ones := b.Ones()
	if len(ones) != 1000 {
		t.Fatalf("expected 1000 ones, got %d", len(ones))
	}
	if ones[0] != 0 || ones[999] != 99900 {
		t.Fatalf("unexpected first/last: %d, %d", ones[0], ones[999])
	}
}
