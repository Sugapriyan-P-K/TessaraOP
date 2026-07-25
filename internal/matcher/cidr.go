package matcher

import (
	"net/netip"

	"github.com/suga/tessaraop/internal/bitset"
)

// CIDRIndex answers "which policies have a CIDR condition whose block
// contains this address" via a binary radix trie over address bits.
//
// A query walks at most 32 (IPv4) or 128 (IPv6) levels and collects the
// policy set at every terminal node it passes through, because an address
// inside 10.0.0.0/8 is also inside 10.4.0.0/16 — every enclosing prefix
// matches, not just the longest. Walk cost is bounded by address width and is
// independent of how many blocks the corpus holds, which is the point versus
// testing every prefix in turn.
//
// Addresses are canonicalized with Unmap, so 10.0.0.0/8 and ::ffff:10.0.0.0/104
// land in the same trie and a query for either form finds both. A genuine
// IPv6 prefix written to deliberately cover IPv4-mapped space is not modeled;
// real policy corpora do not mix the families that way.
type CIDRIndex struct {
	v4 cidrTrie
	v6 cidrTrie
}

type cidrTrie struct {
	nodes []cidrNode
}

type cidrNode struct {
	children [2]int32
	builder  *bitset.Builder
	set      *bitset.Set
}

func newCIDRTrie() cidrTrie {
	return cidrTrie{nodes: []cidrNode{{children: [2]int32{-1, -1}}}}
}

// NewCIDRIndex returns an empty index ready for Insert.
func NewCIDRIndex() *CIDRIndex {
	return &CIDRIndex{v4: newCIDRTrie(), v6: newCIDRTrie()}
}

// Insert records that the policy at policyIdx carries a condition accepting
// prefix. universe is the policy count of the shard being indexed.
func (c *CIDRIndex) Insert(p netip.Prefix, policyIdx, universe int) {
	p = p.Masked()
	addr := p.Addr()
	bits := p.Bits()

	if addr.Is4In6() {
		addr = addr.Unmap()
		bits -= 96
	}
	if addr.Is4() {
		if bits < 0 {
			bits = 0
		}
		raw := addr.As4()
		var buf [16]byte
		copy(buf[:], raw[:])
		c.v4.insert(&buf, bits, policyIdx, universe)
		return
	}
	buf := addr.As16()
	c.v6.insert(&buf, bits, policyIdx, universe)
}

func (t *cidrTrie) insert(addr *[16]byte, bits, policyIdx, universe int) {
	cur := int32(0)
	for i := 0; i < bits; i++ {
		b := (addr[i/8] >> (7 - uint(i)%8)) & 1
		next := t.nodes[cur].children[b]
		if next == -1 {
			t.nodes = append(t.nodes, cidrNode{children: [2]int32{-1, -1}})
			next = int32(len(t.nodes) - 1)
			t.nodes[cur].children[b] = next
		}
		cur = next
	}
	n := &t.nodes[cur]
	if n.builder == nil {
		n.builder = bitset.NewBuilder(universe)
	}
	n.builder.Add(policyIdx)
}

// Freeze finalizes every terminal set. Call once after all Inserts.
func (c *CIDRIndex) Freeze() {
	c.v4.freeze()
	c.v6.freeze()
}

func (t *cidrTrie) freeze() {
	for i := range t.nodes {
		if t.nodes[i].builder != nil {
			t.nodes[i].set = t.nodes[i].builder.Build()
			t.nodes[i].builder = nil
		}
	}
}

// Lookup unions into base the policy set of every prefix containing addr.
// The address buffer stays on the stack, so lookups do not allocate.
func (c *CIDRIndex) Lookup(addr netip.Addr, base MatchSet) MatchSet {
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	if addr.Is4() {
		raw := addr.As4()
		var buf [16]byte
		copy(buf[:], raw[:])
		return c.v4.lookup(&buf, 32, base)
	}
	buf := addr.As16()
	return c.v6.lookup(&buf, 128, base)
}

func (t *cidrTrie) lookup(addr *[16]byte, width int, out MatchSet) MatchSet {
	cur := int32(0)
	for i := 0; ; i++ {
		if s := t.nodes[cur].set; s != nil {
			out = out.Union(s)
		}
		if i >= width {
			return out
		}
		b := (addr[i/8] >> (7 - uint(i)%8)) & 1
		next := t.nodes[cur].children[b]
		if next == -1 {
			return out
		}
		cur = next
	}
}
