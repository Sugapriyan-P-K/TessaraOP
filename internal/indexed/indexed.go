// Package indexed is a single-shard indexed evaluator.
//
// It applies indexing without sharding, which makes it the control in the
// benchmarks: comparing naive to indexed isolates what the index alone buys,
// and comparing indexed to the sharded engine isolates what partitioning
// buys on top. Keeping the two effects separable is what lets the results
// table attribute the speedup honestly instead of reporting one blended
// number.
package indexed

import (
	"github.com/suga/tessaraop/internal/index"
	"github.com/suga/tessaraop/internal/model"
)

// Evaluator indexes one flat policy set with no tenant partitioning.
type Evaluator struct {
	shard     *index.Shard
	scratch   *index.Scratch
	Algorithm model.Algorithm
}

// New builds an indexed evaluator over the policies using deny-overrides.
func New(policies []model.Policy) *Evaluator {
	return NewWith(policies, model.DenyOverrides)
}

// NewWith builds an indexed evaluator with an explicit combining algorithm.
func NewWith(policies []model.Policy, alg model.Algorithm) *Evaluator {
	return &Evaluator{
		shard:     index.BuildShard(policies),
		scratch:   index.NewScratch(),
		Algorithm: alg,
	}
}

// Evaluate narrows the rule set via the index, then applies exact match logic
// to the survivors under both combining tiers.
//
// Not safe for concurrent use: the scratch buffer is owned by this evaluator.
// The sharded engine pools scratch per goroutine and is the concurrent path.
func (e *Evaluator) Evaluate(req model.Request) model.Decision {
	var acc model.Accumulator
	acc.Reset(e.Algorithm)
	policies, rules := e.shard.Evaluate(req, e.scratch, &acc)
	acc.SetScanned(policies, rules)
	return acc.Resolve()
}

// TotalRules reports the size of the indexed universe.
func (e *Evaluator) TotalRules() int { return e.shard.Size() }
