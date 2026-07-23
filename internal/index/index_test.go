package index

import (
	"testing"

	"github.com/suga/tessaraop/internal/model"
)

func TestBuild_BasicFieldIndex(t *testing.T) {
	policies := []model.Policy{
		{
			ID:     "p0",
			Effect: model.Allow,
			Conditions: []model.Condition{
				{Attribute: "department", Operator: model.OpEquals, Values: []string{"engineering"}},
			},
		},
		{
			ID:     "p1",
			Effect: model.Allow,
			Conditions: []model.Condition{
				{Attribute: "department", Operator: model.OpEquals, Values: []string{"sales"}},
			},
		},
	}
	idx := Build(policies)
	if len(idx.fields) != 1 {
		t.Fatalf("expected 1 field index, got %d", len(idx.fields))
	}
	if _, ok := idx.fields["department"]; !ok {
		t.Fatal("expected field index for 'department'")
	}
}

func TestCandidates_SingleAttribute(t *testing.T) {
	policies := []model.Policy{
		{ID: "p0", Effect: model.Allow, Conditions: []model.Condition{
			{Attribute: "department", Operator: model.OpEquals, Values: []string{"engineering"}},
		}},
		{ID: "p1", Effect: model.Allow, Conditions: []model.Condition{
			{Attribute: "department", Operator: model.OpEquals, Values: []string{"sales"}},
		}},
		{ID: "p2", Effect: model.Deny, Conditions: []model.Condition{
			{Attribute: "department", Operator: model.OpEquals, Values: []string{"engineering"}},
		}},
	}
	idx := Build(policies)

	req := model.Request{Attributes: map[string]string{"department": "engineering"}}
	candidates := idx.Candidates(req)

	has := make(map[int]bool)
	for _, c := range candidates {
		has[c] = true
	}
	if !has[0] || !has[2] {
		t.Fatalf("expected p0 and p2 in candidates, got %v", candidates)
	}
	if has[1] {
		t.Fatalf("p1 (sales) should not be a candidate for engineering, got %v", candidates)
	}
}

func TestCandidates_MultipleAttributes(t *testing.T) {
	policies := []model.Policy{
		{ID: "p0", Effect: model.Allow, Conditions: []model.Condition{
			{Attribute: "department", Operator: model.OpEquals, Values: []string{"engineering"}},
			{Attribute: "resource.sensitivity", Operator: model.OpIn, Values: []string{"high", "critical"}},
		}},
		{ID: "p1", Effect: model.Allow, Conditions: []model.Condition{
			{Attribute: "department", Operator: model.OpEquals, Values: []string{"engineering"}},
			{Attribute: "resource.sensitivity", Operator: model.OpEquals, Values: []string{"low"}},
		}},
	}
	idx := Build(policies)

	req := model.Request{Attributes: map[string]string{
		"department":           "engineering",
		"resource.sensitivity": "high",
	}}
	candidates := idx.Candidates(req)

	has := make(map[int]bool)
	for _, c := range candidates {
		has[c] = true
	}
	if !has[0] {
		t.Fatalf("expected p0 in candidates, got %v", candidates)
	}
	if has[1] {
		t.Fatalf("p1 should be eliminated (sensitivity=low vs high), got %v", candidates)
	}
}

func TestCandidates_PolicyWithNoConditionAlwaysSurvives(t *testing.T) {
	policies := []model.Policy{
		{ID: "p0", Effect: model.Allow, Conditions: []model.Condition{
			{Attribute: "department", Operator: model.OpEquals, Values: []string{"engineering"}},
		}},
		{ID: "catch-all", Effect: model.Deny, Conditions: []model.Condition{}},
	}
	idx := Build(policies)

	req := model.Request{Attributes: map[string]string{"department": "sales"}}
	candidates := idx.Candidates(req)

	has := make(map[int]bool)
	for _, c := range candidates {
		has[c] = true
	}
	if !has[1] {
		t.Fatal("conditionless policy must always survive as a candidate")
	}
	if has[0] {
		t.Fatal("p0 (engineering) should be eliminated for department=sales")
	}
}

func TestCandidates_RangeConditionsAreNotIndexed(t *testing.T) {
	policies := []model.Policy{
		{ID: "time-policy", Effect: model.Allow, Conditions: []model.Condition{
			{Attribute: "time.hour", Operator: model.OpRange, Min: 9, Max: 17},
		}},
	}
	idx := Build(policies)

	if len(idx.fields) != 0 {
		t.Fatalf("range conditions should not produce field indexes, got %d", len(idx.fields))
	}

	req := model.Request{
		Attributes: map[string]string{},
		Numeric:    map[string]float64{"time.hour": 14},
	}
	candidates := idx.Candidates(req)
	if len(candidates) != 1 || candidates[0] != 0 {
		t.Fatalf("range-only policy must survive as candidate (no index to eliminate it), got %v", candidates)
	}
}

func TestCandidates_UnknownValue(t *testing.T) {
	policies := []model.Policy{
		{ID: "p0", Effect: model.Allow, Conditions: []model.Condition{
			{Attribute: "department", Operator: model.OpEquals, Values: []string{"engineering"}},
		}},
	}
	idx := Build(policies)

	req := model.Request{Attributes: map[string]string{"department": "nonexistent"}}
	candidates := idx.Candidates(req)
	if len(candidates) != 0 {
		t.Fatalf("no policy should match unknown value, got %v", candidates)
	}
}
