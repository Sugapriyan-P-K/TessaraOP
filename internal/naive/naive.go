package naive

import "github.com/suga/tessaraop/internal/model"

type Evaluator struct {
	Policies []model.Policy
}

func New(policies []model.Policy) *Evaluator {
	return &Evaluator{Policies: policies}
}

func (e *Evaluator) Evaluate(req model.Request) model.Decision {
	return model.Evaluate(e.Policies, req)
}
