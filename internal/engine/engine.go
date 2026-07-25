// Package engine is the top-level policy decision point.
//
// It composes three ideas, in descending order of how much each contributes
// to the latency target:
//
//  1. Sharding. No request is ever evaluated against the whole corpus. A
//     request carries a tenant, and only that tenant's shard plus the global
//     shard are in scope. Ten million policies spread over ten thousand
//     tenants means roughly a thousand policies per request — that ratio, not
//     any bit-twiddling, is what puts microsecond evaluation in reach.
//
//  2. Indexing. Within a shard, per-attribute indexes narrow those policies
//     to a handful of candidates before any exact matching runs.
//
//  3. Caching. Real authorization traffic repeats heavily: the same subject
//     hitting the same resource over and over. A verified decision cache
//     turns those into a hash lookup.
//
// Global policies are evaluated first, because platform-wide denies (IP
// blocklists, kill switches) are both the smallest set and the most likely to
// terminate evaluation immediately under deny-overrides.
package engine

import (
	"sync"

	"github.com/suga/tessaraop/internal/index"
	"github.com/suga/tessaraop/internal/model"
)

// Engine evaluates requests against a sharded, indexed policy corpus.
// It is safe for concurrent use: shards are immutable after construction,
// per-goroutine scratch comes from a pool, and the cache is internally striped.
type Engine struct {
	// scoped is keyed by tenant + scope; tenantWide by tenant alone and holds
	// policies applying across every scope in that tenant.
	scoped     map[shardKey]*index.Shard
	tenantWide map[string]*index.Shard
	global     *index.Shard

	alg   model.Algorithm
	cache *Cache

	scratch sync.Pool
	total   int
	tenants int
}

type shardKey struct {
	tenant string
	scope  string
}

// Config controls engine construction.
type Config struct {
	// Algorithm selects how matching policies combine. Defaults to
	// DenyOverrides, the only order-independent choice and therefore the only
	// one that needs no sorting pass over index output.
	Algorithm model.Algorithm

	// CacheSize is the number of decision cache entries. Zero disables the
	// cache entirely, which is what the benchmarks use when measuring raw
	// index performance rather than traffic locality.
	CacheSize int
}

// New builds an engine over the given policies, partitioning them into shards
// by TenantID. Policies in model.GlobalTenant form the global shard evaluated
// for every request.
func New(policies []model.Policy, cfg Config) *Engine {
	alg := cfg.Algorithm
	if alg == "" {
		alg = model.DenyOverrides
	}

	var (
		globals    []model.Policy
		wide       = map[string][]model.Policy{}
		byScope    = map[shardKey][]model.Policy{}
		tenantSeen = map[string]struct{}{}
	)
	for _, p := range policies {
		switch {
		case p.TenantID == model.GlobalTenant || p.TenantID == "":
			globals = append(globals, p)
		case p.Scope == model.TenantWideScope:
			wide[p.TenantID] = append(wide[p.TenantID], p)
			tenantSeen[p.TenantID] = struct{}{}
		default:
			k := shardKey{p.TenantID, p.Scope}
			byScope[k] = append(byScope[k], p)
			tenantSeen[p.TenantID] = struct{}{}
		}
	}

	e := &Engine{
		scoped:     make(map[shardKey]*index.Shard, len(byScope)),
		tenantWide: make(map[string]*index.Shard, len(wide)),
		alg:        alg,
		total:      len(policies),
	}
	if len(globals) > 0 {
		e.global = index.BuildShard(globals)
	}
	for t, ps := range wide {
		e.tenantWide[t] = index.BuildShard(ps)
	}
	for k, ps := range byScope {
		e.scoped[k] = index.BuildShard(ps)
	}
	e.tenants = len(tenantSeen)

	if cfg.CacheSize > 0 {
		e.cache = NewCache(cfg.CacheSize)
	}
	e.scratch.New = func() any { return index.NewScratch() }
	return e
}

// TotalPolicies reports the corpus size across every shard.
func (e *Engine) TotalPolicies() int { return e.total }

// TenantCount reports how many distinct tenants hold policies.
func (e *Engine) TenantCount() int { return e.tenants }

// ShardCount reports how many shards the corpus partitions into.
func (e *Engine) ShardCount() int {
	n := len(e.scoped) + len(e.tenantWide)
	if e.global != nil {
		n++
	}
	return n
}

// InScope reports how many policies a request can reach: the global shard,
// its tenant-wide shard, and its own scope's shard. This is the number that
// governs per-request cost, as opposed to the corpus total.
func (e *Engine) InScope(tenantID, scope string) int {
	n := 0
	if e.global != nil {
		n += e.global.Size()
	}
	if s, ok := e.tenantWide[tenantID]; ok {
		n += s.Size()
	}
	if s, ok := e.scoped[shardKey{tenantID, scope}]; ok {
		n += s.Size()
	}
	return n
}

// Evaluate renders a decision for req.
func (e *Engine) Evaluate(req model.Request) model.Decision {
	if e.cache != nil {
		if d, ok := e.cache.Get(req); ok {
			d.CacheHit = true
			return d
		}
	}

	sc := e.scratch.Get().(*index.Scratch)
	defer e.scratch.Put(sc)

	acc := model.NewAccumulator(e.alg)
	scanned := 0

	// Global first: it is the smallest shard and the most likely to end
	// evaluation outright under deny-overrides, so paying for it up front is
	// usually cheaper than reaching it last.
	if e.global != nil {
		scanned += evalShard(e.global, req, acc, sc)
	}
	if !acc.CanShortCircuit() {
		if s, ok := e.tenantWide[req.TenantID]; ok {
			scanned += evalShard(s, req, acc, sc)
		}
	}
	if !acc.CanShortCircuit() {
		if s, ok := e.scoped[shardKey{req.TenantID, req.Scope}]; ok {
			scanned += evalShard(s, req, acc, sc)
		}
	}

	acc.SetScanned(scanned)
	d := acc.Resolve()

	if e.cache != nil {
		e.cache.Put(req, d)
	}
	return d
}

// evalShard narrows the shard to candidates and validates them, feeding
// matches into the shared accumulator. It returns how many policies reached
// validation, which is the metric proving the index is doing work.
func evalShard(s *index.Shard, req model.Request, acc *model.Accumulator, sc *index.Scratch) int {
	cands := s.Candidates(req, sc)
	for _, idx := range cands {
		if s.Policies[idx].Matches(req) {
			acc.Consider(&s.Policies[idx])
			if acc.CanShortCircuit() {
				break
			}
		}
	}
	return len(cands)
}
