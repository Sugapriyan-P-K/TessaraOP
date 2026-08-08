package model

import "testing"

// TestSetOperators_WholeElementMatching is the reason these operators exist.
//
// A principal holding only "readwrite" satisfies `subject.roles contains "read"`,
// because contains is a substring test. For a role check that is a privilege
// escalation: the policy author wrote "read" meaning the read role, and got
// anything whose name happens to contain those four letters.
func TestSetOperators_WholeElementMatching(t *testing.T) {
	holder := req(map[string]string{"subject.roles": "readwrite,billing-admin"})

	substring := Condition{Attribute: "subject.roles", Operator: OpContains,
		Values: []string{"read"}}
	if !substring.Matches(holder) {
		t.Fatal("sanity: contains is a substring test and does match here")
	}

	whole := Condition{Attribute: "subject.roles", Operator: OpHasAny,
		Values: []string{"read"}}
	if whole.Matches(holder) {
		t.Error("has_any must compare whole elements: \"readwrite\" is not \"read\"")
	}

	// And it does match the element it actually holds.
	real := Condition{Attribute: "subject.roles", Operator: OpHasAny,
		Values: []string{"readwrite"}}
	if !real.Matches(holder) {
		t.Error("has_any must match an element the set really contains")
	}
}

func TestSetOperators_Semantics(t *testing.T) {
	r := req(map[string]string{"roles": "admin,editor,viewer"})

	cases := []struct {
		name string
		cond Condition
		want bool
	}{
		{"has_any one present", Condition{Attribute: "roles", Operator: OpHasAny,
			Values: []string{"editor"}}, true},
		{"has_any several, one present", Condition{Attribute: "roles", Operator: OpHasAny,
			Values: []string{"nobody", "viewer"}}, true},
		{"has_any none present", Condition{Attribute: "roles", Operator: OpHasAny,
			Values: []string{"nobody", "auditor"}}, false},

		{"has_all subset", Condition{Attribute: "roles", Operator: OpHasAll,
			Values: []string{"admin", "viewer"}}, true},
		{"has_all exact", Condition{Attribute: "roles", Operator: OpHasAll,
			Values: []string{"admin", "editor", "viewer"}}, true},
		{"has_all missing one", Condition{Attribute: "roles", Operator: OpHasAll,
			Values: []string{"admin", "auditor"}}, false},

		{"has_none absent", Condition{Attribute: "roles", Operator: OpHasNone,
			Values: []string{"auditor", "service-account"}}, true},
		{"has_none present", Condition{Attribute: "roles", Operator: OpHasNone,
			Values: []string{"auditor", "admin"}}, false},
	}
	for _, tc := range cases {
		if got := tc.cond.Matches(r); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

// TestSetOperators_FailClosedOnAbsence keeps the set operators consistent with
// every other operator here: a missing attribute matches nothing, negations
// included. `has_none` is the interesting one — it is tempting to treat "no
// attribute" as "holds none of them", which would let a request with no roles at
// all satisfy a rule guarding against a forbidden role.
func TestSetOperators_FailClosedOnAbsence(t *testing.T) {
	empty := Request{Attributes: map[string]string{}}
	for _, op := range []Operator{OpHasAny, OpHasAll, OpHasNone} {
		c := Condition{Attribute: "roles", Operator: op, Values: []string{"admin"}}
		if c.Matches(empty) {
			t.Errorf("operator %s matched an absent attribute", op)
		}
	}
}

func TestSetOperators_ToleratesUntidyInput(t *testing.T) {
	// Producers vary: some join with ", ", some leave a trailing comma.
	for _, value := range []string{
		"admin,editor",
		"admin, editor",
		" admin , editor ",
		"admin,,editor,",
		",admin,editor",
	} {
		r := req(map[string]string{"roles": value})
		c := Condition{Attribute: "roles", Operator: OpHasAll,
			Values: []string{"admin", "editor"}}
		if !c.Matches(r) {
			t.Errorf("value %q should hold both elements", value)
		}
		none := Condition{Attribute: "roles", Operator: OpHasNone,
			Values: []string{"viewer"}}
		if !none.Matches(r) {
			t.Errorf("value %q should not hold viewer", value)
		}
	}
}

func TestSetOperators_EmptySetValue(t *testing.T) {
	// Present but empty is distinguishable from absent, and holds no elements.
	r := req(map[string]string{"roles": ""})
	if (&Condition{Attribute: "roles", Operator: OpHasAny, Values: []string{"admin"}}).Matches(r) {
		t.Error("an empty set holds nothing")
	}
	if !(&Condition{Attribute: "roles", Operator: OpHasNone, Values: []string{"admin"}}).Matches(r) {
		t.Error("an empty set holds none of anything")
	}
}

// TestHasAll_EmptyValuesIsVacuouslyTrue documents the edge case rather than
// leaving it to chance. The linter rejects an empty value list, so this is only
// reachable through the Go API.
func TestHasAll_EmptyValuesIsVacuouslyTrue(t *testing.T) {
	r := req(map[string]string{"roles": "admin"})
	c := Condition{Attribute: "roles", Operator: OpHasAll}
	if !c.Matches(r) {
		t.Error("has_all with no required elements is vacuously satisfied")
	}
}

func TestForEachSetMember(t *testing.T) {
	var got []string
	ForEachSetMember(" a , b ,, c ", func(e string) bool {
		got = append(got, e)
		return true
	})
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("got %v", got)
	}

	// Early termination.
	var count int
	ForEachSetMember("a,b,c", func(string) bool {
		count++
		return false
	})
	if count != 1 {
		t.Errorf("returning false should stop iteration, visited %d", count)
	}
}

func TestSetOperators_AreRegistered(t *testing.T) {
	for _, op := range []Operator{OpHasAny, OpHasAll, OpHasNone} {
		if op.Family() != FamilyString {
			t.Errorf("%s should be in the string family", op)
		}
		found := false
		for _, listed := range AllOperators {
			if listed == op {
				found = true
			}
		}
		if !found {
			t.Errorf("%s is missing from AllOperators", op)
		}
	}
	if !OpHasNone.Negated() {
		t.Error("has_none is a negation")
	}
	if OpHasAny.Negated() || OpHasAll.Negated() {
		t.Error("has_any and has_all are not negations")
	}
}
