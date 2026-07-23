package benchmark

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/suga/tessaraop/internal/genutil"
	"github.com/suga/tessaraop/internal/indexed"
	"github.com/suga/tessaraop/internal/model"
	"github.com/suga/tessaraop/internal/naive"
)

func BenchmarkNaive(b *testing.B) {
	for _, n := range []int{1_000, 10_000, 100_000} {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			rng := rand.New(rand.NewSource(42))
			policies := genutil.GeneratePolicies(n, rng)
			e := naive.New(policies)
			req := genutil.GenerateRequest(rng)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				e.Evaluate(req)
			}
		})
	}
}

func BenchmarkIndexed(b *testing.B) {
	for _, n := range []int{1_000, 10_000, 100_000} {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			rng := rand.New(rand.NewSource(42))
			policies := genutil.GeneratePolicies(n, rng)
			e := indexed.New(policies)
			req := genutil.GenerateRequest(rng)

			b.ResetTimer()
			var d model.Decision
			for i := 0; i < b.N; i++ {
				d = e.Evaluate(req)
			}
			b.ReportMetric(float64(d.PoliciesScanned), "candidates")
		})
	}
}

func BenchmarkIndexBuild(b *testing.B) {
	for _, n := range []int{1_000, 10_000, 100_000} {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			rng := rand.New(rand.NewSource(42))
			policies := genutil.GeneratePolicies(n, rng)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				indexed.New(policies)
			}
		})
	}
}
