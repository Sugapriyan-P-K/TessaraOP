package engine

import (
	"math"
	"net/netip"
	"sync"

	"github.com/suga/tessaraop/internal/model"
)

// Cache is a striped, direct-mapped decision cache.
//
// Every hit is verified by comparing the full request against the stored key,
// never by trusting the hash alone. That matters more here than in an ordinary
// cache: a hash collision in an authorization path would silently hand one
// subject another subject's decision, so the hash is used only to pick a slot
// and the comparison decides the hit. Replacement is direct-mapped overwrite
// rather than LRU, which keeps lookups to a single striped read lock with no
// list bookkeeping on the hot path.
//
// Requests are hashed order-independently, since Go map iteration order is
// randomized and the same logical request must always land in the same slot.
type Cache struct {
	stripes []stripe
	mask    uint64
}

type stripe struct {
	mu      sync.RWMutex
	entries []cacheEntry
}

type cacheEntry struct {
	valid bool
	key   cachedRequest
	dec   model.Decision
}

// cachedRequest is an owned copy of a request's identifying fields. The
// engine must not alias caller maps, which callers are free to mutate or
// reuse after Evaluate returns.
type cachedRequest struct {
	tenant  string
	scope   string
	attrs   map[string]string
	numeric map[string]float64
	ips     map[string]netip.Addr
}

const stripeCount = 64

// NewCache returns a cache holding approximately size entries.
func NewCache(size int) *Cache {
	perStripe := size / stripeCount
	if perStripe < 1 {
		perStripe = 1
	}
	// Round up to a power of two so slot selection is a mask, not a modulo.
	pow := 1
	for pow < perStripe {
		pow <<= 1
	}
	c := &Cache{
		stripes: make([]stripe, stripeCount),
		mask:    uint64(pow - 1),
	}
	for i := range c.stripes {
		c.stripes[i].entries = make([]cacheEntry, pow)
	}
	return c
}

// Get returns a cached decision for req, if one is present and verified.
func (c *Cache) Get(req model.Request) (model.Decision, bool) {
	h := hashRequest(req)
	s := &c.stripes[h%stripeCount]
	slot := (h >> 6) & c.mask

	s.mu.RLock()
	e := &s.entries[slot]
	if e.valid && e.key.matches(req) {
		d := e.dec
		s.mu.RUnlock()
		return d, true
	}
	s.mu.RUnlock()
	return model.Decision{}, false
}

// Put stores a decision, overwriting whatever occupied the slot.
func (c *Cache) Put(req model.Request, d model.Decision) {
	h := hashRequest(req)
	s := &c.stripes[h%stripeCount]
	slot := (h >> 6) & c.mask

	key := cachedRequest{tenant: req.TenantID, scope: req.Scope}
	if len(req.Attributes) > 0 {
		key.attrs = make(map[string]string, len(req.Attributes))
		for k, v := range req.Attributes {
			key.attrs[k] = v
		}
	}
	if len(req.Numeric) > 0 {
		key.numeric = make(map[string]float64, len(req.Numeric))
		for k, v := range req.Numeric {
			key.numeric[k] = v
		}
	}
	if len(req.IPs) > 0 {
		key.ips = make(map[string]netip.Addr, len(req.IPs))
		for k, v := range req.IPs {
			key.ips[k] = v
		}
	}

	s.mu.Lock()
	s.entries[slot] = cacheEntry{valid: true, key: key, dec: d}
	s.mu.Unlock()
}

// matches reports exact equality with req.
func (k cachedRequest) matches(req model.Request) bool {
	if k.tenant != req.TenantID ||
		k.scope != req.Scope ||
		len(k.attrs) != len(req.Attributes) ||
		len(k.numeric) != len(req.Numeric) ||
		len(k.ips) != len(req.IPs) {
		return false
	}
	for key, v := range req.Attributes {
		if kv, ok := k.attrs[key]; !ok || kv != v {
			return false
		}
	}
	for key, v := range req.Numeric {
		if kv, ok := k.numeric[key]; !ok || kv != v {
			return false
		}
	}
	for key, v := range req.IPs {
		if kv, ok := k.ips[key]; !ok || kv != v {
			return false
		}
	}
	return true
}

// hashRequest computes an order-independent 64-bit hash. Per-entry hashes are
// summed rather than chained, so Go's randomized map iteration order cannot
// change the result for a given logical request.
func hashRequest(req model.Request) uint64 {
	h := fnv64(fnv64(offset64, req.TenantID), req.Scope)
	var acc uint64
	for k, v := range req.Attributes {
		acc += mix(fnv64(fnv64(offset64, k), v))
	}
	for k, v := range req.Numeric {
		e := fnv64(offset64, k)
		e = fnv64Uint(e, floatBits(v))
		acc += mix(e)
	}
	for k, v := range req.IPs {
		e := fnv64(offset64, k)
		b := v.As16()
		for _, c := range b {
			e = (e ^ uint64(c)) * prime64
		}
		acc += mix(e)
	}
	return mix(h + acc)
}

const (
	offset64 = 14695981039346656037
	prime64  = 1099511628211
)

func fnv64(h uint64, s string) uint64 {
	for i := 0; i < len(s); i++ {
		h = (h ^ uint64(s[i])) * prime64
	}
	return h
}

func fnv64Uint(h, v uint64) uint64 {
	for i := 0; i < 8; i++ {
		h = (h ^ (v>>(8*uint(i)))&0xff) * prime64
	}
	return h
}

// mix is a finalizer that spreads entropy across all bits, so both the stripe
// selection (low bits) and the slot selection (higher bits) are well
// distributed from one hash value.
func mix(h uint64) uint64 {
	h ^= h >> 33
	h *= 0xff51afd7ed558ccd
	h ^= h >> 33
	h *= 0xc4ceb9fe1a85ec53
	h ^= h >> 33
	return h
}

func floatBits(f float64) uint64 {
	// Normalize negative zero so +0 and -0 hash identically, matching ==.
	if f == 0 {
		return 0
	}
	return math.Float64bits(f)
}
