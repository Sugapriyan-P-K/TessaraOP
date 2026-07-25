// Package model defines the core ABAC/Zero-Trust data types shared by every
// evaluator implementation. Every matching decision in the system routes
// through Condition.Matches / Policy.Matches here, so the indexed fast path
// and the naive reference oracle can never disagree on semantics.
package model

import (
	"fmt"
	"net/netip"
	"strings"
)

// Effect is the outcome a policy grants if all its conditions match.
type Effect string

const (
	Allow Effect = "ALLOW"
	Deny  Effect = "DENY"
)

// Operator is the comparison a Condition applies to a request attribute.
//
// Operators fall into three families, which matters because each family
// needs a different index structure:
//
//	Set family    (eq, ne, in, nin, exists, nexists) -> hash map index
//	Numeric family(range, gt, lt)                    -> interval segment index
//	Network family(cidr, ncidr)                      -> radix trie index
//	Name family   (dnssuffix, prefix)                -> label/prefix trie index
type Operator string

const (
	// Set family — operate on Request.Attributes (string values).
	OpEquals    Operator = "eq"      // Attributes[Attr] == Values[0]
	OpNotEquals Operator = "ne"      // Attributes[Attr] != Values[0]
	OpIn        Operator = "in"      // Attributes[Attr] ∈ Values
	OpNotIn     Operator = "nin"     // Attributes[Attr] ∉ Values
	OpExists    Operator = "exists"  // Attributes[Attr] is present
	OpNotExists Operator = "nexists" // Attributes[Attr] is absent

	// Numeric family — operate on Request.Numeric (float64 values).
	OpRange       Operator = "range" // Min <= Numeric[Attr] <= Max
	OpGreaterThan Operator = "gt"    // Numeric[Attr] > Min
	OpLessThan    Operator = "lt"    // Numeric[Attr] < Max

	// Network family — operate on Request.IPs (netip.Addr values).
	OpCIDR    Operator = "cidr"  // IPs[Attr] ∈ any prefix in Prefixes
	OpNotCIDR Operator = "ncidr" // IPs[Attr] ∉ every prefix in Prefixes

	// Name family — operate on Request.Attributes (string values).
	OpDNSSuffix Operator = "dnssuffix" // host is, or is under, any domain in Values
	OpPrefix    Operator = "prefix"    // path has any of Values as a prefix
)

// Condition is a single predicate within a policy.
//
// Absent-attribute semantics (fail closed): a condition whose attribute is
// not present on the request does NOT match — including negations. So
// `source_ip NOT IN 203.0.113.0/24` requires source_ip to be present AND
// outside the block. OpNotExists is the sole operator that matches on
// absence, by definition. The index layer mirrors this exactly.
type Condition struct {
	Attribute string
	Operator  Operator

	Values   []string       // set family, name family
	Min, Max float64        // numeric family
	Prefixes []netip.Prefix // network family
}

// Matches evaluates this single condition against a request. This is the
// ground truth for the entire engine: the naive evaluator calls it directly,
// and the indexed evaluator calls it in its final validation pass. The index
// is only ever a pre-filter over this function, never a replacement for it.
func (c Condition) Matches(req Request) bool {
	switch c.Operator {

	case OpEquals:
		val, ok := req.Attributes[c.Attribute]
		return ok && len(c.Values) > 0 && val == c.Values[0]

	case OpNotEquals:
		val, ok := req.Attributes[c.Attribute]
		return ok && len(c.Values) > 0 && val != c.Values[0]

	case OpIn:
		val, ok := req.Attributes[c.Attribute]
		if !ok {
			return false
		}
		for _, v := range c.Values {
			if val == v {
				return true
			}
		}
		return false

	case OpNotIn:
		val, ok := req.Attributes[c.Attribute]
		if !ok {
			return false
		}
		for _, v := range c.Values {
			if val == v {
				return false
			}
		}
		return true

	case OpExists:
		_, ok := req.Attributes[c.Attribute]
		return ok

	case OpNotExists:
		_, ok := req.Attributes[c.Attribute]
		return !ok

	case OpRange:
		val, ok := req.Numeric[c.Attribute]
		return ok && val >= c.Min && val <= c.Max

	case OpGreaterThan:
		val, ok := req.Numeric[c.Attribute]
		return ok && val > c.Min

	case OpLessThan:
		val, ok := req.Numeric[c.Attribute]
		return ok && val < c.Max

	case OpCIDR:
		addr, ok := req.IPs[c.Attribute]
		if !ok {
			return false
		}
		for _, p := range c.Prefixes {
			if p.Contains(addr) {
				return true
			}
		}
		return false

	case OpNotCIDR:
		addr, ok := req.IPs[c.Attribute]
		if !ok {
			return false
		}
		for _, p := range c.Prefixes {
			if p.Contains(addr) {
				return false
			}
		}
		return true

	case OpDNSSuffix:
		host, ok := req.Attributes[c.Attribute]
		if !ok {
			return false
		}
		for _, suffix := range c.Values {
			if MatchDNSSuffix(host, suffix) {
				return true
			}
		}
		return false

	case OpPrefix:
		path, ok := req.Attributes[c.Attribute]
		if !ok {
			return false
		}
		for _, p := range c.Values {
			if strings.HasPrefix(path, p) {
				return true
			}
		}
		return false

	default:
		return false
	}
}

// MatchDNSSuffix reports whether host equals suffix or is a subdomain of it.
// Matching is label-aligned, so "evilexample.com" does NOT match "example.com"
// — a plain strings.HasSuffix here would be a real security bug.
func MatchDNSSuffix(host, suffix string) bool {
	if host == suffix {
		return true
	}
	if len(host) > len(suffix) &&
		strings.HasSuffix(host, suffix) &&
		host[len(host)-len(suffix)-1] == '.' {
		return true
	}
	return false
}

// Policy is a single rule: if every condition matches, Effect applies.
//
// TenantID and Scope together form the shard key, and that pairing is what
// makes a multi-million policy corpus tractable: the working set per request
// is one shard, not the corpus.
//
// Scope subdivides a tenant, typically by resource type or application. It
// exists because tenant alone is not a fine enough partition — real corpora
// are heavily skewed, and a single large customer can hold a six-figure policy
// count that no amount of indexing makes fast on its own. Production systems
// partition the same way: Zanzibar by namespace, IAM by principal and
// resource, Envoy RBAC per listener. A policy with an empty Scope applies
// across its whole tenant.
type Policy struct {
	ID          string
	TenantID    string
	Scope       string
	Effect      Effect
	Priority    int // higher wins under FirstApplicable; ignored by DenyOverrides
	Conditions  []Condition
	Obligations []string // e.g. require_mfa, audit_log — carried into the Decision
}

// GlobalTenant holds platform-wide policies evaluated for every request
// regardless of the request's own tenant (blocklists, kill switches).
const GlobalTenant = "__global__"

// TenantWideScope is the scope of policies applying across an entire tenant,
// evaluated alongside whichever scope a request names.
const TenantWideScope = ""

// Matches reports whether every condition matches. An empty condition list
// matches everything (catch-all), which is how default-deny backstops and
// blanket grants are expressed.
func (p Policy) Matches(req Request) bool {
	for i := range p.Conditions {
		if !p.Conditions[i].Matches(req) {
			return false
		}
	}
	return true
}

// Request is a single access check. Attributes are split by type so the hot
// path never parses or casts: string attributes, numeric attributes and IP
// attributes each land in the map their operators read directly.
type Request struct {
	TenantID   string
	Scope      string
	Attributes map[string]string
	Numeric    map[string]float64
	IPs        map[string]netip.Addr
}

// InScope reports whether a policy is reachable by this request: it must
// belong to the global tenant, or to the request's tenant at either
// tenant-wide scope or the request's own scope.
func (r Request) InScope(p *Policy) bool {
	if p.TenantID == GlobalTenant {
		return true
	}
	if p.TenantID != r.TenantID {
		return false
	}
	return p.Scope == TenantWideScope || p.Scope == r.Scope
}

// Decision is the result of evaluating a request against a policy set.
//
// PoliciesScanned is the core instrumentation metric: it counts policies that
// reached exact validation. Naive always scans the whole in-scope set; the
// indexed engine should scan a small fraction.
//
// MatchedPolicyID names *a* policy that matched and carries the winning
// effect, not necessarily a canonical one. Under DenyOverrides and
// PermitOverrides several policies can match with the same effect, and the
// algorithms say nothing about which of them to credit — so the engine reports
// whichever it reached first and stops, since scanning the remainder to pick a
// canonical winner would forfeit short-circuiting for no change in the
// decision. FirstApplicable is the exception: it must examine every candidate
// anyway, and its priority-then-ID ordering makes the reported policy fully
// deterministic. Audit trails that need a stable attribution should use
// FirstApplicable.
type Decision struct {
	Allowed         bool
	Effect          Effect
	MatchedPolicyID string
	Obligations     []string
	PoliciesScanned int
	CacheHit        bool
}

func (d Decision) String() string {
	return fmt.Sprintf("Decision{Allowed:%v Effect:%s Matched:%s Obligations:%v Scanned:%d}",
		d.Allowed, d.Effect, d.MatchedPolicyID, d.Obligations, d.PoliciesScanned)
}

// Evaluator is implemented by every evaluation strategy. Benchmarks and the
// differential test depend only on this interface.
type Evaluator interface {
	Evaluate(req Request) Decision
}

// Algorithm selects how multiple matching policies combine into one decision.
type Algorithm string

const (
	// DenyOverrides: any matching Deny wins; else any matching Allow wins;
	// else default-deny.
	//
	// This is the default and the only order-independent algorithm here,
	// which is exactly what makes indexing sound — the index yields
	// candidates in arbitrary order, and the result must not depend on that
	// order. Every other algorithm below requires an explicit ordering pass.
	DenyOverrides Algorithm = "deny-overrides"

	// PermitOverrides: any matching Allow wins; else any matching Deny; else
	// default-deny. Also order-independent. Used for opt-in grant models.
	PermitOverrides Algorithm = "permit-overrides"

	// FirstApplicable: the matching policy with the highest Priority wins
	// (ties broken by policy ID for determinism). Order-dependent, so the
	// engine must sort candidates before resolving — strictly more expensive
	// than DenyOverrides. Needed for exception rules ("deny all except X").
	FirstApplicable Algorithm = "first-applicable"
)

// Accumulator collects matching policies during a scan and resolves them into
// a Decision under the chosen Algorithm. Both the naive and indexed evaluators
// drive this same type, so combining semantics cannot drift between them.
type Accumulator struct {
	Algorithm Algorithm

	foundDeny  bool
	denyPolicy *Policy

	foundAllow  bool
	allowPolicy *Policy

	// FirstApplicable tracking
	bestPolicy *Policy

	scanned int
}

func NewAccumulator(alg Algorithm) *Accumulator {
	if alg == "" {
		alg = DenyOverrides
	}
	return &Accumulator{Algorithm: alg}
}

// Consider feeds one policy that has already been confirmed to match.
func (a *Accumulator) Consider(p *Policy) {
	switch a.Algorithm {
	case FirstApplicable:
		if a.bestPolicy == nil ||
			p.Priority > a.bestPolicy.Priority ||
			(p.Priority == a.bestPolicy.Priority && p.ID < a.bestPolicy.ID) {
			a.bestPolicy = p
		}
	default:
		if p.Effect == Deny {
			if !a.foundDeny {
				a.foundDeny = true
				a.denyPolicy = p
			}
		} else {
			if !a.foundAllow {
				a.foundAllow = true
				a.allowPolicy = p
			}
		}
	}
}

// CanShortCircuit reports whether the outcome is already decided, so the
// caller may stop scanning. Only DenyOverrides can short-circuit (on the
// first Deny) — the others must see every candidate.
func (a *Accumulator) CanShortCircuit() bool {
	return a.Algorithm == DenyOverrides && a.foundDeny
}

// SetScanned records how many policies reached exact validation.
func (a *Accumulator) SetScanned(n int) { a.scanned = n }

// Resolve produces the final decision under the configured algorithm.
func (a *Accumulator) Resolve() Decision {
	var winner *Policy
	switch a.Algorithm {
	case FirstApplicable:
		winner = a.bestPolicy
	case PermitOverrides:
		if a.foundAllow {
			winner = a.allowPolicy
		} else if a.foundDeny {
			winner = a.denyPolicy
		}
	default: // DenyOverrides
		if a.foundDeny {
			winner = a.denyPolicy
		} else if a.foundAllow {
			winner = a.allowPolicy
		}
	}

	if winner == nil {
		// Default deny: no policy matched at all.
		return Decision{
			Allowed:         false,
			Effect:          Deny,
			PoliciesScanned: a.scanned,
		}
	}
	return Decision{
		Allowed:         winner.Effect == Allow,
		Effect:          winner.Effect,
		MatchedPolicyID: winner.ID,
		Obligations:     winner.Obligations,
		PoliciesScanned: a.scanned,
	}
}

// Evaluate scans every policy in the slice. This is the reference
// implementation used by the naive evaluator and by differential tests.
func Evaluate(policies []Policy, req Request, alg Algorithm) Decision {
	acc := NewAccumulator(alg)
	for i := range policies {
		if policies[i].Matches(req) {
			acc.Consider(&policies[i])
			if acc.CanShortCircuit() {
				break
			}
		}
	}
	acc.SetScanned(len(policies))
	return acc.Resolve()
}

// EvaluateIndices validates only the candidate positions the index produced,
// indexing into the original slice rather than copying policies into a new
// one. The copy version allocated proportionally to candidate-set size and
// showed up directly in benchmark allocs/op.
func EvaluateIndices(policies []Policy, positions []int, req Request, alg Algorithm) Decision {
	acc := NewAccumulator(alg)
	for _, idx := range positions {
		if policies[idx].Matches(req) {
			acc.Consider(&policies[idx])
			if acc.CanShortCircuit() {
				break
			}
		}
	}
	acc.SetScanned(len(positions))
	return acc.Resolve()
}
