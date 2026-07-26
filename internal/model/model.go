// Package model defines the core ABAC/Zero-Trust data types shared by every
// evaluator implementation. Every matching decision in the system routes
// through Condition.Matches / ConditionExpr.Matches here, so the indexed fast
// path and the naive reference oracle can never disagree on semantics.
//
// The shape is three levels deep:
//
//	Policy  — the unit of tenancy, sharding and distribution
//	  └─ Rule    — the unit that carries an Effect and Obligations
//	       └─ When: ConditionExpr — an AND/OR/NOT tree over Conditions
//
// A Policy holds many Rules; a Rule holds one boolean expression over many
// Conditions. That is the structure real security policy takes — one document
// ("production database access") containing several rules, each granting or
// denying under its own compound predicate.
package model

import (
	"math"
	"net/netip"
	"regexp"
	"strings"
	"sync"
)

// Effect is the outcome a rule grants if its condition tree matches.
type Effect string

const (
	Allow Effect = "ALLOW"
	Deny  Effect = "DENY"
)

// Operator is the comparison a Condition applies to a request attribute.
//
// Operators fall into families, which matters because each family needs a
// different index structure and reads a different map on the Request:
//
//	String   -> Request.Attributes — hash map, prefix table, suffix table, label trie
//	Numeric  -> Request.Numeric    — interval table, numeric hash map
//	Network  -> Request.IPs        — binary radix trie over address bits
//	Presence -> any of the three   — plain participation bitsets
//
// Some operators are deliberately not indexable: substring and regular
// expression matching have no structure a pre-filter can exploit. Those still
// narrow the candidate set through attribute presence, then resolve in the
// exact validation pass. That is the same over-inclusive-never-under-inclusive
// contract every other index here honours.
type Operator string

const (
	// -- String family — operate on Request.Attributes (string values). --

	OpEquals      Operator = "eq"        // Attributes[Attr] == Values[0]
	OpNotEquals   Operator = "ne"        // Attributes[Attr] != Values[0]
	OpIn          Operator = "in"        // Attributes[Attr] ∈ Values
	OpNotIn       Operator = "nin"       // Attributes[Attr] ∉ Values
	OpContains    Operator = "contains"  // any of Values is a substring
	OpNotContains Operator = "ncontains" // no Value is a substring
	OpPrefix      Operator = "prefix"    // starts with any of Values (byte-wise)
	OpNotPrefix   Operator = "nprefix"   // starts with none of Values
	OpSuffix      Operator = "suffix"    // ends with any of Values (byte-wise)
	OpNotSuffix   Operator = "nsuffix"   // ends with none of Values
	OpRegex       Operator = "regex"     // matches any pattern in Values
	OpNotRegex    Operator = "nregex"    // matches no pattern in Values

	// OpDNSSuffix is label-aligned, unlike OpSuffix. Use it for every host,
	// domain and SNI comparison: OpSuffix would accept evilacme.com for
	// acme.com, which is a live authorization-bypass class.
	OpDNSSuffix    Operator = "dnssuffix"  // host is, or is under, any domain in Values
	OpNotDNSSuffix Operator = "ndnssuffix" // host is under none of Values

	// -- Presence family — read whichever map carries the attribute. --

	OpExists    Operator = "exists"  // the attribute is present
	OpNotExists Operator = "nexists" // the attribute is absent

	// -- Numeric family — operate on Request.Numeric (float64 values). --

	OpRange       Operator = "range"   // Min <= v <= Max
	OpNotRange    Operator = "nrange"  // v < Min or v > Max
	OpGreaterThan Operator = "gt"      // v > Min
	OpGreaterEq   Operator = "gte"     // v >= Min
	OpLessThan    Operator = "lt"      // v < Max
	OpLessEq      Operator = "lte"     // v <= Max
	OpNumEquals   Operator = "num_eq"  // v == Min
	OpNumNotEq    Operator = "num_ne"  // v != Min
	OpNumIn       Operator = "num_in"  // v ∈ Numbers
	OpNumNotIn    Operator = "num_nin" // v ∉ Numbers

	// -- Network family — operate on Request.IPs (netip.Addr values). --

	OpCIDR    Operator = "cidr"  // IPs[Attr] ∈ any prefix in Prefixes
	OpNotCIDR Operator = "ncidr" // IPs[Attr] ∉ every prefix in Prefixes
)

// Family classifies an operator by which Request map it reads.
type Family uint8

const (
	FamilyString Family = iota
	FamilyNumeric
	FamilyNetwork
	FamilyPresence
	FamilyUnknown
)

// Family reports which Request map this operator reads. The attribute registry
// uses it to reject a policy that applies a numeric comparison to a string
// attribute — a mistake that would otherwise fail closed at runtime and look
// like a policy that simply never matches.
func (op Operator) Family() Family {
	switch op {
	case OpEquals, OpNotEquals, OpIn, OpNotIn,
		OpContains, OpNotContains, OpPrefix, OpNotPrefix,
		OpSuffix, OpNotSuffix, OpRegex, OpNotRegex,
		OpDNSSuffix, OpNotDNSSuffix:
		return FamilyString
	case OpRange, OpNotRange, OpGreaterThan, OpGreaterEq,
		OpLessThan, OpLessEq, OpNumEquals, OpNumNotEq,
		OpNumIn, OpNumNotIn:
		return FamilyNumeric
	case OpCIDR, OpNotCIDR:
		return FamilyNetwork
	case OpExists, OpNotExists:
		return FamilyPresence
	default:
		return FamilyUnknown
	}
}

// Negated reports whether the operator succeeds on absence of a match rather
// than presence of one. The index layer needs this because a negated operator
// can only ever reject candidates, never enumerate them.
func (op Operator) Negated() bool {
	switch op {
	case OpNotEquals, OpNotIn, OpNotContains, OpNotPrefix, OpNotSuffix,
		OpNotRegex, OpNotDNSSuffix, OpNotExists, OpNotRange, OpNumNotEq,
		OpNumNotIn, OpNotCIDR:
		return true
	}
	return false
}

// AllOperators lists every operator the engine implements, in catalog order.
// The linter and the generated documentation both read it, so a new operator
// added to the const block above must be added here too.
var AllOperators = []Operator{
	OpEquals, OpNotEquals, OpIn, OpNotIn,
	OpContains, OpNotContains, OpPrefix, OpNotPrefix,
	OpSuffix, OpNotSuffix, OpRegex, OpNotRegex,
	OpDNSSuffix, OpNotDNSSuffix,
	OpExists, OpNotExists,
	OpRange, OpNotRange, OpGreaterThan, OpGreaterEq,
	OpLessThan, OpLessEq, OpNumEquals, OpNumNotEq,
	OpNumIn, OpNumNotIn,
	OpCIDR, OpNotCIDR,
}

// Condition is a single predicate over one request attribute.
//
// Absent-attribute semantics (fail closed): a condition whose attribute is not
// present on the request does NOT match — including negations. So
// `source_ip NOT IN 203.0.113.0/24` requires source_ip to be present AND
// outside the block. OpNotExists is the sole operator that matches on absence,
// by definition. The index layer mirrors this exactly.
type Condition struct {
	Attribute string
	Operator  Operator

	Values   []string       // string family
	Min, Max float64        // numeric family: range bounds and scalar comparand
	Numbers  []float64      // numeric set family (num_in, num_nin)
	Prefixes []netip.Prefix // network family

	// re holds the compiled patterns for OpRegex / OpNotRegex, populated by
	// Prepare. Matches falls back to a process-wide compile cache when it is
	// nil, so a hand-built policy still evaluates correctly without Prepare —
	// it just pays a map lookup per evaluation instead of none.
	re []*regexp.Regexp
}

// Matches evaluates this single condition against a request. This is the
// ground truth for the entire engine: the naive evaluator reaches it through
// the condition tree, and the indexed evaluator reaches it in its final
// validation pass. The index is only ever a pre-filter over this function,
// never a replacement for it.
func (c *Condition) Matches(req Request) bool {
	switch c.Operator.Family() {
	case FamilyString:
		val, ok := req.Attributes[c.Attribute]
		if !ok {
			return false
		}
		return c.matchString(val)
	case FamilyNumeric:
		val, ok := req.Numeric[c.Attribute]
		if !ok {
			return false
		}
		return c.matchNumeric(val)
	case FamilyNetwork:
		addr, ok := req.IPs[c.Attribute]
		if !ok {
			return false
		}
		return c.matchNetwork(addr)
	case FamilyPresence:
		present := req.Has(c.Attribute)
		if c.Operator == OpNotExists {
			return !present
		}
		return present
	default:
		return false
	}
}

func (c *Condition) matchString(val string) bool {
	switch c.Operator {
	case OpEquals:
		return len(c.Values) > 0 && val == c.Values[0]
	case OpNotEquals:
		return len(c.Values) > 0 && val != c.Values[0]

	case OpIn:
		return containsString(c.Values, val)
	case OpNotIn:
		return !containsString(c.Values, val)

	case OpContains:
		return anyString(c.Values, func(v string) bool { return strings.Contains(val, v) })
	case OpNotContains:
		return !anyString(c.Values, func(v string) bool { return strings.Contains(val, v) })

	case OpPrefix:
		return anyString(c.Values, func(v string) bool { return strings.HasPrefix(val, v) })
	case OpNotPrefix:
		return !anyString(c.Values, func(v string) bool { return strings.HasPrefix(val, v) })

	case OpSuffix:
		return anyString(c.Values, func(v string) bool { return strings.HasSuffix(val, v) })
	case OpNotSuffix:
		return !anyString(c.Values, func(v string) bool { return strings.HasSuffix(val, v) })

	case OpDNSSuffix:
		return anyString(c.Values, func(v string) bool { return MatchDNSSuffix(val, v) })
	case OpNotDNSSuffix:
		return !anyString(c.Values, func(v string) bool { return MatchDNSSuffix(val, v) })

	case OpRegex:
		return c.anyRegex(val)
	case OpNotRegex:
		return !c.anyRegex(val)
	}
	return false
}

func (c *Condition) matchNumeric(val float64) bool {
	// A NaN attribute value satisfies no comparison, including negated ones.
	// Every IEEE comparison against NaN is false, so `num_ne` would otherwise
	// return true for it and turn a malformed measurement into a match.
	if math.IsNaN(val) {
		return false
	}
	switch c.Operator {
	case OpRange:
		return val >= c.Min && val <= c.Max
	case OpNotRange:
		return val < c.Min || val > c.Max
	case OpGreaterThan:
		return val > c.Min
	case OpGreaterEq:
		return val >= c.Min
	case OpLessThan:
		return val < c.Max
	case OpLessEq:
		return val <= c.Max
	case OpNumEquals:
		return val == c.Min
	case OpNumNotEq:
		return val != c.Min
	case OpNumIn:
		return containsFloat(c.Numbers, val)
	case OpNumNotIn:
		return !containsFloat(c.Numbers, val)
	}
	return false
}

func (c *Condition) matchNetwork(addr netip.Addr) bool {
	hit := false
	for _, p := range c.Prefixes {
		if p.Contains(addr) {
			hit = true
			break
		}
	}
	if c.Operator == OpNotCIDR {
		return !hit
	}
	return hit
}

// anyRegex reports whether val matches any of this condition's patterns,
// preferring the patterns compiled by Prepare.
func (c *Condition) anyRegex(val string) bool {
	if c.re != nil {
		for _, re := range c.re {
			if re != nil && re.MatchString(val) {
				return true
			}
		}
		return false
	}
	for _, pat := range c.Values {
		re, err := compileCached(pat)
		if err != nil {
			// An unparsable pattern matches nothing, so a positive regex
			// condition fails and a negated one passes. Prepare surfaces the
			// error properly; this path only keeps evaluation deterministic.
			continue
		}
		if re.MatchString(val) {
			return true
		}
	}
	return false
}

func containsString(vals []string, v string) bool {
	for _, x := range vals {
		if x == v {
			return true
		}
	}
	return false
}

func containsFloat(vals []float64, v float64) bool {
	for _, x := range vals {
		if x == v {
			return true
		}
	}
	return false
}

func anyString(vals []string, pred func(string) bool) bool {
	for _, v := range vals {
		if pred(v) {
			return true
		}
	}
	return false
}

// regexCache memoizes compiled patterns for conditions that were never passed
// through Prepare. Policy corpora reuse a small number of attack signatures
// across many rules, so the cache stays small and hit rates are high.
var regexCache sync.Map // string -> *regexp.Regexp or error

func compileCached(pat string) (*regexp.Regexp, error) {
	if v, ok := regexCache.Load(pat); ok {
		if re, ok := v.(*regexp.Regexp); ok {
			return re, nil
		}
		return nil, v.(error)
	}
	re, err := regexp.Compile(pat)
	if err != nil {
		regexCache.Store(pat, err)
		return nil, err
	}
	regexCache.Store(pat, re)
	return re, nil
}

// Prepare compiles this condition's regular expressions so evaluation needs no
// cache lookup. It is idempotent and reports the first pattern that fails to
// compile.
func (c *Condition) Prepare() error {
	if c.Operator != OpRegex && c.Operator != OpNotRegex {
		return nil
	}
	if len(c.re) == len(c.Values) {
		return nil
	}
	compiled := make([]*regexp.Regexp, 0, len(c.Values))
	for _, pat := range c.Values {
		re, err := regexp.Compile(pat)
		if err != nil {
			return &ConditionError{Attribute: c.Attribute, Operator: c.Operator, Err: err}
		}
		compiled = append(compiled, re)
	}
	c.re = compiled
	return nil
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

// Request is a single access check. Attributes are split by type so the hot
// path never parses or casts: string attributes, numeric attributes and IP
// attributes each land in the map their operators read directly.
//
// The engine consumes named, already-parsed attributes and never decodes raw
// packets or raw HTTP bytes itself. Package ingest builds a Request from a
// net.Conn, an *http.Request or a *tls.ConnectionState using the standard
// library's audited parsers — a hand-rolled TCP/IP or HTTP decoder inside an
// authorization hot path is exactly where parser-differential bypasses live.
type Request struct {
	TenantID   string
	Scope      string
	Attributes map[string]string
	Numeric    map[string]float64
	IPs        map[string]netip.Addr
}

// Has reports whether the request carries the named attribute in any of its
// three typed maps.
func (r Request) Has(name string) bool {
	if _, ok := r.Attributes[name]; ok {
		return true
	}
	if _, ok := r.Numeric[name]; ok {
		return true
	}
	_, ok := r.IPs[name]
	return ok
}

// InScope reports whether a policy is reachable by this request: it must
// belong to the global tenant, or to the request's tenant at either
// tenant-wide scope or the request's own scope.
func (r Request) InScope(p *Policy) bool {
	if p.TenantID == GlobalTenant || p.TenantID == "" {
		return true
	}
	if p.TenantID != r.TenantID {
		return false
	}
	return p.Scope == TenantWideScope || p.Scope == r.Scope
}

// Decision is the result of evaluating a request against a policy set.
//
// RulesScanned and PoliciesScanned are the core instrumentation metrics: they
// count what reached exact validation. Naive always validates every in-scope
// rule; the indexed engine should reach a small fraction.
//
// MatchedPolicyID and MatchedRuleID name *a* rule that matched and carries the
// winning effect, not necessarily a canonical one. Under DenyOverrides and
// PermitOverrides several rules can match with the same effect, and the
// algorithms say nothing about which to credit — so the engine reports
// whichever it reached first and stops, since scanning the remainder to pick a
// canonical winner would forfeit short-circuiting for no change in the
// decision. FirstApplicable is the exception: it must examine every candidate
// anyway, and its priority-then-ID ordering makes the reported rule fully
// deterministic. Audit trails needing stable attribution should use it.
type Decision struct {
	Allowed         bool
	Effect          Effect
	MatchedPolicyID string
	MatchedRuleID   string
	Obligations     []string
	PoliciesScanned int
	RulesScanned    int
	CacheHit        bool
}

func (d Decision) String() string {
	return "Decision{Allowed:" + boolString(d.Allowed) +
		" Effect:" + string(d.Effect) +
		" Policy:" + d.MatchedPolicyID +
		" Rule:" + d.MatchedRuleID +
		" Obligations:" + strings.Join(d.Obligations, ",") +
		" Rules:" + itoa(d.RulesScanned) + "}"
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// Evaluator is implemented by every evaluation strategy. Benchmarks and the
// differential test depend only on this interface.
type Evaluator interface {
	Evaluate(req Request) Decision
}

// ConditionError reports a condition that cannot be compiled or validated.
type ConditionError struct {
	Attribute string
	Operator  Operator
	Err       error
}

func (e *ConditionError) Error() string {
	return "condition " + e.Attribute + " " + string(e.Operator) + ": " + e.Err.Error()
}

func (e *ConditionError) Unwrap() error { return e.Err }
