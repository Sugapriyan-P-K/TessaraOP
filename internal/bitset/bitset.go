// Package bitset implements a dense word-packed bitset using []uint64.
// This is a deliberate tradeoff: a dense bitset pays O(N/64) for every
// AND/OR/Ones call regardless of how sparse the set is, which is why the
// indexed evaluator's speedup shrinks at larger N. Swapping in a compressed
// bitmap (RoaringBitmap) is the natural next optimization.
package bitset

import "math/bits"

type Bitset struct {
	words []uint64
	n     int
}

func New(n int) *Bitset {
	return &Bitset{
		words: make([]uint64, (n+63)/64),
		n:     n,
	}
}

func (b *Bitset) Len() int { return b.n }

func (b *Bitset) Set(i int) {
	b.words[i/64] |= 1 << (uint(i) % 64)
}

func (b *Bitset) Test(i int) bool {
	return b.words[i/64]&(1<<(uint(i)%64)) != 0
}

func (b *Bitset) Clone() *Bitset {
	out := &Bitset{
		words: make([]uint64, len(b.words)),
		n:     b.n,
	}
	copy(out.words, b.words)
	return out
}

func (b *Bitset) And(other *Bitset) *Bitset {
	n := max(b.n, other.n)
	out := New(n)
	minLen := min(len(b.words), len(other.words))
	for i := 0; i < minLen; i++ {
		out.words[i] = b.words[i] & other.words[i]
	}
	return out
}

func (b *Bitset) Or(other *Bitset) *Bitset {
	n := max(b.n, other.n)
	out := New(n)
	for i := range out.words {
		var w1, w2 uint64
		if i < len(b.words) {
			w1 = b.words[i]
		}
		if i < len(other.words) {
			w2 = other.words[i]
		}
		out.words[i] = w1 | w2
	}
	return out
}

func (b *Bitset) Xor(other *Bitset) *Bitset {
	n := max(b.n, other.n)
	out := New(n)
	for i := range out.words {
		var w1, w2 uint64
		if i < len(b.words) {
			w1 = b.words[i]
		}
		if i < len(other.words) {
			w2 = other.words[i]
		}
		out.words[i] = w1 ^ w2
	}
	return out
}

func (b *Bitset) Count() int {
	n := 0
	for _, w := range b.words {
		n += bits.OnesCount64(w)
	}
	return n
}

func (b *Bitset) Ones() []int {
	var result []int
	for i, w := range b.words {
		for w != 0 {
			tz := bits.TrailingZeros64(w)
			result = append(result, i*64+tz)
			w &= w - 1
		}
	}
	return result
}
