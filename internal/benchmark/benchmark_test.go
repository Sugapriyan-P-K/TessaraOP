// Package benchmark measures the engine against the naive baseline.
//
// The benchmarks are deliberately layered so each optimization can be
// attributed rather than blended into one headline number:
//
//	BenchmarkNaiveFlat     linear scan over an unsharded corpus
//	BenchmarkIndexedFlat   indexing over the same unsharded corpus
//	BenchmarkNaiveSharded  linear scan over the multi-tenant corpus
//	BenchmarkEngine        indexing plus sharding
//	BenchmarkEngineCached  indexing, sharding, and decision caching
//	BenchmarkEngineParallel throughput across cores
//	BenchmarkWorstCaseShard tail latency on the largest tenant
//
// Flat and sharded runs are kept separate so each comparison holds everything
// but one variable constant.
//
// The "validated" metric counts rules, not policies. A rule is the atomic
// indexed unit, so it is the number that tracks per-request cost; the policy
// count would understate the work by whatever the average rules-per-policy
// happens to be. The corpus sizes below are still stated in policies, since that
// is the unit a customer counts their own policy set in.
package benchmark

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/suga/tessaraop/internal/engine"
	"github.com/suga/tessaraop/internal/genutil"
	"github.com/suga/tessaraop/internal/indexed"
	"github.com/suga/tessaraop/internal/model"
	"github.com/suga/tessaraop/internal/naive"
)

// scales are the corpus sizes under test. Tenant counts track corpus size the
// way a real platform grows: more customers, not just more policies each.
var scales = []struct {
	policies int
	tenants  int
}{
	{10_000, 100},
	{100_000, 1_000},
	{1_000_000, 10_000},
}

const globalPolicies = 50

// flatten collapses a corpus onto a single tenant at tenant-wide scope.
//
// The naive evaluator gets tenant scoping almost free — a string compare skips
// a policy before any condition runs — while the single-shard indexed
// evaluator does no scoping at all. Comparing them on a multi-tenant corpus
// would therefore measure sharding, not indexing, and would flatter naive for
// a reason unrelated to the structure under test. Flattening removes tenancy
// from the comparison so the naive-versus-indexed rows isolate the index.
func flatten(c *genutil.Corpus) *genutil.Corpus {
	const tenant = "flat"
	out := make([]model.Policy, len(c.Policies))
	copy(out, c.Policies)
	for i := range out {
		out[i].TenantID = tenant
		out[i].Scope = model.TenantWideScope
	}
	return &genutil.Corpus{Policies: out, Tenants: []string{tenant}, Scopes: c.Scopes}
}

// flatRequests targets the flattened corpus's single tenant.
func flatRequests(c *genutil.Corpus, rng *rand.Rand, n int) []model.Request {
	out := requestPool(c, rng, n)
	for i := range out {
		out[i].TenantID = "flat"
		out[i].Scope = model.TenantWideScope
	}
	return out
}

// requestPool builds a fixed set of requests up front so the measured loop
// contains only evaluation, never generation.
func requestPool(c *genutil.Corpus, rng *rand.Rand, n int) []model.Request {
	out := make([]model.Request, n)
	for i := range out {
		out[i] = c.GenerateRequest(rng)
	}
	return out
}

// BenchmarkNaiveFlat is the O(N) baseline on an unsharded corpus. It pairs
// with BenchmarkIndexedFlat to isolate what indexing alone buys.
//
// Both run only at the smaller scales: a linear scan of a million policies
// takes tens of milliseconds per request, so the top scale would add minutes to
// the run to reconfirm what the 100k row already shows.
func BenchmarkNaiveFlat(b *testing.B) {
	for _, s := range scales[:2] {
		b.Run(fmt.Sprintf("N=%d", s.policies), func(b *testing.B) {
			rng := rand.New(rand.NewSource(42))
			c := flatten(genutil.Generate(genutil.Options{
				Policies: s.policies, Tenants: s.tenants, Global: globalPolicies}, rng))
			e := naive.New(c.Policies)
			reqs := flatRequests(c, rng, 64)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				e.Evaluate(reqs[i&63])
			}
		})
	}
}

func BenchmarkIndexedFlat(b *testing.B) {
	for _, s := range scales[:2] {
		b.Run(fmt.Sprintf("N=%d", s.policies), func(b *testing.B) {
			rng := rand.New(rand.NewSource(42))
			c := flatten(genutil.Generate(genutil.Options{
				Policies: s.policies, Tenants: s.tenants, Global: globalPolicies}, rng))
			e := indexed.New(c.Policies)
			reqs := flatRequests(c, rng, 64)

			var scanned int
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				scanned = e.Evaluate(reqs[i&63]).RulesScanned
			}
			b.ReportMetric(float64(scanned), "validated")
		})
	}
}

// BenchmarkNaiveSharded is the baseline the full engine is measured against:
// same multi-tenant corpus, same scoping rules, linear scan.
func BenchmarkNaiveSharded(b *testing.B) {
	for _, s := range scales {
		b.Run(fmt.Sprintf("N=%d", s.policies), func(b *testing.B) {
			rng := rand.New(rand.NewSource(42))
			c := genutil.Generate(genutil.Options{
				Policies: s.policies, Tenants: s.tenants, Global: globalPolicies}, rng)
			e := naive.New(c.Policies)
			reqs := requestPool(c, rng, 64)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				e.Evaluate(reqs[i&63])
			}
		})
	}
}

func BenchmarkEngine(b *testing.B) {
	for _, s := range scales {
		b.Run(fmt.Sprintf("N=%d", s.policies), func(b *testing.B) {
			rng := rand.New(rand.NewSource(42))
			c := genutil.Generate(genutil.Options{
				Policies: s.policies, Tenants: s.tenants, Global: globalPolicies}, rng)
			e := engine.New(c.Policies, engine.Config{})
			reqs := requestPool(c, rng, 64)

			var scanned int
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				scanned = e.Evaluate(reqs[i&63]).RulesScanned
			}
			b.ReportMetric(float64(scanned), "validated")
		})
	}
}

func BenchmarkEngineCached(b *testing.B) {
	for _, s := range scales {
		b.Run(fmt.Sprintf("N=%d", s.policies), func(b *testing.B) {
			rng := rand.New(rand.NewSource(42))
			c := genutil.Generate(genutil.Options{
				Policies: s.policies, Tenants: s.tenants, Global: globalPolicies}, rng)
			e := engine.New(c.Policies, engine.Config{CacheSize: 8192})
			// A 64-request working set against an 8k cache models traffic with
			// strong locality, which is what an authorization hot path sees.
			reqs := requestPool(c, rng, 64)
			for i := range reqs {
				e.Evaluate(reqs[i])
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				e.Evaluate(reqs[i&63])
			}
		})
	}
}

// BenchmarkEngineParallel measures throughput across cores, which is the
// number that matters for a millions-of-requests-per-second target. One engine
// serves every goroutine.
func BenchmarkEngineParallel(b *testing.B) {
	for _, s := range scales {
		b.Run(fmt.Sprintf("N=%d", s.policies), func(b *testing.B) {
			rng := rand.New(rand.NewSource(42))
			c := genutil.Generate(genutil.Options{
				Policies: s.policies, Tenants: s.tenants, Global: globalPolicies}, rng)
			e := engine.New(c.Policies, engine.Config{})
			reqs := requestPool(c, rng, 256)

			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				i := 0
				for pb.Next() {
					e.Evaluate(reqs[i&255])
					i++
				}
			})
		})
	}
}

// BenchmarkWorstCaseShard targets the largest tenant rather than a random one.
// The skewed corpus means an average request lands on a small shard; this
// reports the tail latency a whale customer actually experiences.
func BenchmarkWorstCaseShard(b *testing.B) {
	for _, s := range scales {
		b.Run(fmt.Sprintf("N=%d", s.policies), func(b *testing.B) {
			rng := rand.New(rand.NewSource(42))
			c := genutil.Generate(genutil.Options{
				Policies: s.policies, Tenants: s.tenants, Global: globalPolicies}, rng)
			e := engine.New(c.Policies, engine.Config{})

			whale := c.Tenants[0]
			reqs := make([]model.Request, 64)
			for i := range reqs {
				reqs[i] = c.GenerateRequestFor(whale, rng)
			}
			worst := 0
			for _, sc := range c.Scopes {
				if n := e.InScope(whale, sc); n > worst {
					worst = n
				}
			}

			var scanned int
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				scanned = e.Evaluate(reqs[i&63]).RulesScanned
			}
			b.ReportMetric(float64(scanned), "validated")
			b.ReportMetric(float64(worst), "in-scope")
		})
	}
}

func BenchmarkIndexBuild(b *testing.B) {
	for _, s := range scales {
		b.Run(fmt.Sprintf("N=%d", s.policies), func(b *testing.B) {
			rng := rand.New(rand.NewSource(42))
			c := genutil.Generate(genutil.Options{
				Policies: s.policies, Tenants: s.tenants, Global: globalPolicies}, rng)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				engine.New(c.Policies, engine.Config{})
			}
		})
	}
}
