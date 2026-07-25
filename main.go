package main

import (
	"bufio"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/suga/tessaraop/internal/genutil"
	"github.com/suga/tessaraop/internal/indexed"
	"github.com/suga/tessaraop/internal/model"
	"github.com/suga/tessaraop/internal/naive"
)

func main() {
	n := flag.Int("n", 1000, "number of policies to generate")
	requests := flag.Int("requests", 10, "number of random requests to evaluate (bench mode)")
	seed := flag.Int64("seed", 42, "random seed for reproducibility")
	interactive := flag.Bool("interactive", false, "interactive mode: type requests, see results")
	demo := flag.Bool("demo", false, "demo mode: small hand-crafted policy set with walkthrough")
	flag.Parse()

	if *demo {
		runDemo()
		return
	}

	fmt.Printf("Generating %d policies (seed=%d)...\n", *n, *seed)
	rng := rand.New(rand.NewSource(*seed))
	policies := genutil.GeneratePolicies(*n, rng)

	fmt.Print("Building indexes...\n")
	buildStart := time.Now()
	indexedEval := indexed.New(policies)
	buildTime := time.Since(buildStart)
	naiveEval := naive.New(policies)

	fmt.Printf("Index built in %v\n\n", buildTime)

	printPolicySummary(policies)
	fmt.Println()

	if *interactive {
		runInteractive(naiveEval, indexedEval, *n)
		return
	}

	runBench(naiveEval, indexedEval, rng, *n, *requests)
}

func printPolicySummary(policies []model.Policy) {
	var allowCount, denyCount int
	condCounts := make(map[int]int)
	attrCounts := make(map[string]int)

	for _, p := range policies {
		if p.Effect == model.Allow {
			allowCount++
		} else {
			denyCount++
		}
		condCounts[len(p.Conditions)]++
		for _, c := range p.Conditions {
			attrCounts[c.Attribute]++
		}
	}

	fmt.Printf("Policy summary:\n")
	fmt.Printf("  Total: %d (Allow: %d, Deny: %d)\n", len(policies), allowCount, denyCount)
	fmt.Printf("  Conditions per policy:\n")
	for i := 0; i <= 5; i++ {
		if c, ok := condCounts[i]; ok {
			fmt.Printf("    %d conditions: %d policies\n", i, c)
		}
	}
	fmt.Printf("  Attributes indexed:\n")
	for attr, count := range attrCounts {
		fmt.Printf("    %s: %d conditions\n", attr, count)
	}
}

func runBench(naiveEval *naive.Evaluator, indexedEval *indexed.Evaluator, rng *rand.Rand, n, numRequests int) {
	fmt.Printf("Running %d requests through both evaluators...\n\n", numRequests)
	fmt.Printf("%-4s  %-8s  %-10s  %-10s  %-12s  %-12s  %-10s  %s\n",
		"#", "Result", "NaiveTime", "IndexTime", "NaiveScanned", "IdxScanned", "Speedup", "Match")

	var totalNaive, totalIndexed time.Duration
	mismatches := 0

	for i := 0; i < numRequests; i++ {
		req := genutil.GenerateRequest(rng)

		start := time.Now()
		naiveD := naiveEval.Evaluate(req)
		naiveDur := time.Since(start)

		start = time.Now()
		indexedD := indexedEval.Evaluate(req)
		indexedDur := time.Since(start)

		totalNaive += naiveDur
		totalIndexed += indexedDur

		match := "OK"
		if naiveD.Allowed != indexedD.Allowed || naiveD.MatchedPolicyID != indexedD.MatchedPolicyID {
			match = "MISMATCH"
			mismatches++
		}

		result := "DENY"
		if indexedD.Allowed {
			result = "ALLOW"
		}

		speedup := float64(naiveDur) / float64(indexedDur)

		fmt.Printf("%-4d  %-8s  %-10v  %-10v  %-12d  %-12d  %-10.1fx  %s\n",
			i+1, result, naiveDur.Round(time.Microsecond), indexedDur.Round(time.Microsecond),
			naiveD.PoliciesScanned, indexedD.PoliciesScanned, speedup, match)
	}

	fmt.Printf("\n--- Summary ---\n")
	fmt.Printf("Total naive:   %v\n", totalNaive.Round(time.Microsecond))
	fmt.Printf("Total indexed: %v\n", totalIndexed.Round(time.Microsecond))
	fmt.Printf("Avg speedup:   %.1fx\n", float64(totalNaive)/float64(totalIndexed))
	fmt.Printf("Mismatches:    %d/%d\n", mismatches, numRequests)
	if mismatches == 0 {
		fmt.Println("Correctness:   VERIFIED (naive and indexed agree on every request)")
	}
}

func runInteractive(naiveEval *naive.Evaluator, indexedEval *indexed.Evaluator, n int) {
	fmt.Println("Interactive mode. Type request attributes, get evaluation results.")
	fmt.Println("Format: department=engineering resource.sensitivity=high action=read time.hour=14.5")
	fmt.Println("Type 'quit' to exit.")
	fmt.Println()

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("request> ")
		if !scanner.Scan() {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "quit" || line == "exit" {
			break
		}
		if line == "" {
			continue
		}

		req := parseRequest(line)

		start := time.Now()
		naiveD := naiveEval.Evaluate(req)
		naiveDur := time.Since(start)

		start = time.Now()
		indexedD := indexedEval.Evaluate(req)
		indexedDur := time.Since(start)

		fmt.Printf("\n  Request:  %v %v\n", req.Attributes, req.Numeric)
		fmt.Printf("  Result:   %s\n", resultStr(indexedD))
		if indexedD.MatchedPolicyID != "" {
			fmt.Printf("  Matched:  %s (%s)\n", indexedD.MatchedPolicyID, indexedD.Effect)
		}
		fmt.Printf("  Naive:    scanned %d/%d policies in %v\n", naiveD.PoliciesScanned, n, naiveDur.Round(time.Microsecond))
		fmt.Printf("  Indexed:  scanned %d/%d policies in %v (%.1fx faster)\n",
			indexedD.PoliciesScanned, n, indexedDur.Round(time.Microsecond),
			float64(naiveDur)/float64(indexedDur))

		if naiveD.Allowed != indexedD.Allowed {
			fmt.Println("  WARNING: naive and indexed disagree!")
		}
		fmt.Println()
	}
}

func parseRequest(line string) model.Request {
	req := model.Request{
		Attributes: make(map[string]string),
		Numeric:    make(map[string]float64),
	}
	for _, part := range strings.Fields(line) {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key, val := kv[0], kv[1]
		if f, err := strconv.ParseFloat(val, 64); err == nil && key == "time.hour" {
			req.Numeric[key] = f
		} else {
			req.Attributes[key] = val
		}
	}
	return req
}

func resultStr(d model.Decision) string {
	if d.Allowed {
		return "ALLOWED"
	}
	return "DENIED"
}

func runDemo() {
	fmt.Println("=== TessaraOP Demo ===")
	fmt.Println()

	policies := []model.Policy{
		{
			ID: "allow-eng-read", Effect: model.Allow,
			Conditions: []model.Condition{
				{Attribute: "department", Operator: model.OpEquals, Values: []string{"engineering"}},
				{Attribute: "action", Operator: model.OpIn, Values: []string{"read", "write"}},
			},
		},
		{
			ID: "allow-sales-read", Effect: model.Allow,
			Conditions: []model.Condition{
				{Attribute: "department", Operator: model.OpEquals, Values: []string{"sales"}},
				{Attribute: "action", Operator: model.OpEquals, Values: []string{"read"}},
			},
		},
		{
			ID: "deny-critical-delete", Effect: model.Deny,
			Conditions: []model.Condition{
				{Attribute: "resource.sensitivity", Operator: model.OpIn, Values: []string{"critical"}},
				{Attribute: "action", Operator: model.OpEquals, Values: []string{"delete"}},
			},
		},
		{
			ID: "business-hours", Effect: model.Allow,
			Conditions: []model.Condition{
				{Attribute: "department", Operator: model.OpEquals, Values: []string{"engineering"}},
				{Attribute: "time.hour", Operator: model.OpRange, Min: 9, Max: 17},
			},
		},
		{
			ID: "catch-all-deny", Effect: model.Deny,
			Conditions: []model.Condition{},
		},
	}

	fmt.Println("Policies loaded:")
	for _, p := range policies {
		fmt.Printf("  [%s] %s — %d conditions\n", p.Effect, p.ID, len(p.Conditions))
		for _, c := range p.Conditions {
			switch c.Operator {
			case model.OpRange:
				fmt.Printf("      %s %s [%.0f, %.0f]\n", c.Attribute, c.Operator, c.Min, c.Max)
			default:
				fmt.Printf("      %s %s %v\n", c.Attribute, c.Operator, c.Values)
			}
		}
	}

	naiveEval := naive.New(policies)
	indexedEval := indexed.New(policies)

	testCases := []struct {
		name string
		req  model.Request
	}{
		{
			"Engineer reads a resource",
			model.Request{
				Attributes: map[string]string{"department": "engineering", "action": "read"},
			},
		},
		{
			"Sales tries to delete critical resource",
			model.Request{
				Attributes: map[string]string{
					"department":           "sales",
					"action":               "delete",
					"resource.sensitivity": "critical",
				},
			},
		},
		{
			"Engineer during business hours",
			model.Request{
				Attributes: map[string]string{"department": "engineering"},
				Numeric:    map[string]float64{"time.hour": 14.5},
			},
		},
		{
			"Unknown department tries to read",
			model.Request{
				Attributes: map[string]string{"department": "marketing", "action": "read"},
			},
		},
	}

	fmt.Printf("\n%-45s  %-8s  %-20s  %-6s  %s\n",
		"Scenario", "Result", "Matched", "Naive", "Indexed")
	fmt.Println(strings.Repeat("-", 100))

	for _, tc := range testCases {
		nd := naiveEval.Evaluate(tc.req)
		id := indexedEval.Evaluate(tc.req)

		result := "DENIED"
		if id.Allowed {
			result = "ALLOWED"
		}

		fmt.Printf("%-45s  %-8s  %-20s  %-6d  %d\n",
			tc.name, result, id.MatchedPolicyID,
			nd.PoliciesScanned, id.PoliciesScanned)
	}

	fmt.Print("\nNaive always scans all 5 policies. Indexed narrows via index first.\n")
}
