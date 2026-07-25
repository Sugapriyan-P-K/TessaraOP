package matcher

import (
	"strings"

	"github.com/suga/tessaraop/internal/bitset"
)

// DomainIndex answers "which policies have a DNS-suffix condition that
// accepts this host" via a trie over reversed labels.
//
// Labels are walked right to left, so api.admin.acme.com visits
// com -> acme -> admin -> api and collects a policy set at every terminal it
// passes. That structure enforces label alignment for free: evilacme.com
// walks com -> evilacme and never reaches the acme node, so it cannot match a
// policy scoped to acme.com. A plain strings.HasSuffix check would match it —
// that is a real and frequently exploited authorization bypass, so the index
// and the validation path in model.MatchDNSSuffix both align on labels.
//
// Hosts are expected already lowercased by the ingest layer, as any gateway
// or proxy normalizes them; the hot path does not allocate to case-fold.
type DomainIndex struct {
	root *domainNode
	n    int
}

type domainNode struct {
	children map[string]*domainNode
	builder  *bitset.Builder
	set      *bitset.Set
}

// NewDomainIndex returns an empty index over a shard of `universe` policies.
func NewDomainIndex(universe int) *DomainIndex {
	return &DomainIndex{root: &domainNode{}, n: universe}
}

// Insert records that the policy at policyIdx accepts `suffix` and anything
// under it.
func (d *DomainIndex) Insert(suffix string, policyIdx int) {
	cur := d.root
	forEachLabelRTL(suffix, func(label string) {
		if cur.children == nil {
			cur.children = make(map[string]*domainNode, 2)
		}
		next, ok := cur.children[label]
		if !ok {
			next = &domainNode{}
			cur.children[label] = next
		}
		cur = next
	})
	if cur.builder == nil {
		cur.builder = bitset.NewBuilder(d.n)
	}
	cur.builder.Add(policyIdx)
}

// Freeze finalizes every terminal set. Call once after all Inserts.
func (d *DomainIndex) Freeze() { freezeDomain(d.root) }

func freezeDomain(n *domainNode) {
	if n.builder != nil {
		n.set = n.builder.Build()
		n.builder = nil
	}
	for _, c := range n.children {
		freezeDomain(c)
	}
}

// Lookup unions into base the policy set of every suffix that accepts host.
func (d *DomainIndex) Lookup(host string, base MatchSet) MatchSet {
	cur := d.root
	if cur.set != nil {
		base = base.Union(cur.set)
	}
	stopped := false
	forEachLabelRTL(host, func(label string) {
		if stopped || cur.children == nil {
			stopped = true
			return
		}
		next, ok := cur.children[label]
		if !ok {
			stopped = true
			return
		}
		cur = next
		if cur.set != nil {
			base = base.Union(cur.set)
		}
	})
	return base
}

// forEachLabelRTL yields the dot-separated labels of name from right to left.
// The callback receives substrings of name, which share its backing array, so
// iteration does not allocate.
func forEachLabelRTL(name string, fn func(label string)) {
	end := len(name)
	for end > 0 {
		dot := strings.LastIndexByte(name[:end], '.')
		fn(name[dot+1 : end])
		if dot < 0 {
			return
		}
		end = dot
	}
}
