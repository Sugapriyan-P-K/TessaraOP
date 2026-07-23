package indexed

import (
	"github.com/suga/tessaraop/internal/index"
	"github.com/suga/tessaraop/internal/model"
)

type Evaluator struct {
	policies []model.Policy
	index    *index.IndexSet
}

func New(policies []model.Policy) *Evaluator {
	return &Evaluator{
		policies: policies,
		index:    index.Build(policies),
	}
}

func (e *Evaluator) Evaluate(req model.Request) model.Decision {
	candidates := e.index.Candidates(req)
	return model.EvaluateIndices(e.policies, candidates, req)
}
