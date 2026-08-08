// Package bundle is the declarative, on-the-wire policy format.
//
// Customers do not author Go structs. They author files, review them, diff them,
// and ship them through the same pipeline as the rest of their configuration. So
// the engine needs a serialized form that is stable, reviewable, and validated
// before it ever reaches a decision path — this package is that form plus its
// linter.
//
// # Why JSON and not YAML
//
// The engine has no external dependencies, and that is a deliberate property: an
// authorization component sitting in a request path is a supply-chain surface,
// and every dependency widens it. Go's standard library ships a JSON codec and
// no YAML codec, so JSON is what this reads. Teams that prefer YAML for
// authoring can convert at build time; the format below is a direct structural
// match either way.
//
// # Shape
//
//	{
//	  "version": 1,
//	  "policies": [{
//	    "id": "acme-admin-console",
//	    "tenant": "acme",
//	    "scope": "identity",
//	    "priority": 100,
//	    "rule_algorithm": "first-applicable",
//	    "rules": [{
//	      "id": "grant-admin",
//	      "effect": "ALLOW",
//	      "priority": 100,
//	      "obligations": ["require_mfa"],
//	      "when": {
//	        "all": [
//	          {"any": [
//	            {"attr": "subject.role", "op": "eq", "values": ["admin"]},
//	            {"attr": "subject.role", "op": "eq", "values": ["security-admin"]}
//	          ]},
//	          {"not": {"attr": "subject.groups", "op": "has_any", "values": ["contractor"]}},
//	          {"attr": "subject.risk_score", "op": "range", "min": 0, "max": 30},
//	          {"attr": "network.source_ip", "op": "cidr", "prefixes": ["10.0.0.0/8"]}
//	        ]
//	      }
//	    }]
//	  }]
//	}
//
// A condition node is exactly one of "all", "any", "not", or a leaf carrying
// "attr" and "op". Nesting is unrestricted up to the linter's depth cap.
package bundle

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"

	"github.com/suga/tessaraop/internal/model"
)

// FormatVersion is the bundle schema version this package reads and writes.
// A bundle omitting the field is assumed to be version 1.
const FormatVersion = 1

// Bundle is a complete, self-contained policy set.
type Bundle struct {
	Version  int      `json:"version"`
	Policies []Policy `json:"policies"`

	// Metadata is free-form and carried through untouched. Deployment pipelines
	// use it for provenance: the commit that produced the bundle, who approved
	// it, when it was built.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Policy is the serialized form of model.Policy.
type Policy struct {
	ID       string `json:"id"`
	Tenant   string `json:"tenant,omitempty"`
	Scope    string `json:"scope,omitempty"`
	Priority int    `json:"priority,omitempty"`

	// RuleAlgorithm combines this policy's matching rules. Empty means
	// deny-overrides.
	RuleAlgorithm string `json:"rule_algorithm,omitempty"`

	Rules []Rule `json:"rules"`

	Description string `json:"description,omitempty"`
}

// Rule is the serialized form of model.Rule.
type Rule struct {
	ID          string   `json:"id"`
	Effect      string   `json:"effect"`
	Priority    int      `json:"priority,omitempty"`
	When        *Node    `json:"when,omitempty"`
	Obligations []string `json:"obligations,omitempty"`
	Description string   `json:"description,omitempty"`
}

// Node is one node of a condition tree: a boolean combinator or a leaf.
//
// It is a single struct with a discriminating shape rather than a tagged union,
// because that is what makes the JSON readable to a human reviewer. The cost is
// custom marshalling and a validity check that exactly one form is populated,
// which the linter reports as a diagnostic rather than a parse failure — a
// malformed node should tell the author which rule is wrong, not abort the file.
type Node struct {
	All []*Node `json:"all,omitempty"`
	Any []*Node `json:"any,omitempty"`
	Not *Node   `json:"not,omitempty"`

	// Leaf fields.
	Attr string `json:"attr,omitempty"`
	Op   string `json:"op,omitempty"`

	Values   []string  `json:"values,omitempty"`
	Min      *float64  `json:"min,omitempty"`
	Max      *float64  `json:"max,omitempty"`
	Numbers  []float64 `json:"numbers,omitempty"`
	Prefixes []string  `json:"prefixes,omitempty"`
}

// Kind reports which form this node takes, and whether it is unambiguous.
type NodeKind uint8

const (
	NodeInvalid NodeKind = iota // zero, or more than one, form populated
	NodeAll
	NodeAny
	NodeNot
	NodeLeaf
)

func (k NodeKind) String() string {
	switch k {
	case NodeAll:
		return "all"
	case NodeAny:
		return "any"
	case NodeNot:
		return "not"
	case NodeLeaf:
		return "leaf"
	}
	return "invalid"
}

// Kind classifies the node. A node with no form and a node with several are both
// invalid: the first says nothing, and the second would let the reader and the
// engine disagree about what the rule means.
func (n *Node) Kind() NodeKind {
	if n == nil {
		return NodeInvalid
	}
	forms := 0
	kind := NodeInvalid
	if n.All != nil {
		forms++
		kind = NodeAll
	}
	if n.Any != nil {
		forms++
		kind = NodeAny
	}
	if n.Not != nil {
		forms++
		kind = NodeNot
	}
	if n.Attr != "" || n.Op != "" {
		forms++
		kind = NodeLeaf
	}
	if forms != 1 {
		return NodeInvalid
	}
	return kind
}

// MarshalJSON writes exactly the one form this node takes.
//
// The struct tags alone cannot do this. With `omitempty`, an empty "all" — which
// means "match everything", the catch-all rule — serializes to {} and reloads as
// a node with no form at all, which the linter then rejects. Without
// `omitempty`, every leaf sprouts "all": null. So the form is selected here and
// an empty combinator is written as an explicit [].
func (n *Node) MarshalJSON() ([]byte, error) {
	switch n.Kind() {
	case NodeAll:
		return json.Marshal(struct {
			All []*Node `json:"all"`
		}{nonNilNodes(n.All)})

	case NodeAny:
		return json.Marshal(struct {
			Any []*Node `json:"any"`
		}{nonNilNodes(n.Any)})

	case NodeNot:
		return json.Marshal(struct {
			Not *Node `json:"not"`
		}{n.Not})

	case NodeLeaf:
		return json.Marshal(leafWire{
			Attr: n.Attr, Op: n.Op,
			Values: n.Values, Min: n.Min, Max: n.Max,
			Numbers: n.Numbers, Prefixes: n.Prefixes,
		})
	}

	// An invalid node is written as {} rather than raising an error: Write must
	// not fail on an in-memory tree, and the linter reports the shape properly
	// with a path the author can act on.
	return []byte("{}"), nil
}

// leafWire is the serialized form of a leaf. It is a separate type rather than an
// alias of Node so that marshalling it cannot recurse back into MarshalJSON.
type leafWire struct {
	Attr     string    `json:"attr"`
	Op       string    `json:"op"`
	Values   []string  `json:"values,omitempty"`
	Min      *float64  `json:"min,omitempty"`
	Max      *float64  `json:"max,omitempty"`
	Numbers  []float64 `json:"numbers,omitempty"`
	Prefixes []string  `json:"prefixes,omitempty"`
}

func nonNilNodes(in []*Node) []*Node {
	if in == nil {
		return []*Node{}
	}
	return in
}

// Read parses a bundle from r without validating it. Use Lint, or Compile, to
// find problems; Read only reports malformed JSON.
//
// Unknown fields are rejected. A typo'd key would otherwise be silently ignored,
// and "polices" instead of "policies" yields an empty bundle that denies every
// request — an outage presented as a successful load.
func Read(r io.Reader) (*Bundle, error) {
	dec := json.NewDecoder(skipBOM(r))
	dec.DisallowUnknownFields()

	var b Bundle
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	if b.Version == 0 {
		b.Version = FormatVersion
	}
	return &b, nil
}

// skipBOM discards a leading UTF-8 byte-order mark.
//
// JSON has no BOM in its grammar, so encoding/json rejects one with "invalid
// character 'ï'" — an error that says nothing about the actual problem. Plenty of
// Windows editors and shell redirections emit a BOM by default, so a policy
// author's very first bundle can arrive with one. Failing on it would be
// technically defensible and a genuinely bad onboarding experience, so it is
// simply skipped.
func skipBOM(r io.Reader) io.Reader {
	br := bufio.NewReader(r)
	if prefix, err := br.Peek(3); err == nil &&
		prefix[0] == 0xEF && prefix[1] == 0xBB && prefix[2] == 0xBF {
		_, _ = br.Discard(3)
	}
	return br
}

// ReadFile parses a bundle from a path.
func ReadFile(path string) (*Bundle, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Read(f)
}

// Write serializes a bundle as indented JSON.
func (b *Bundle) Write(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(b)
}

// ErrInvalidBundle is returned by Compile when the bundle holds errors.
var ErrInvalidBundle = errors.New("bundle: validation failed")

// Compile validates a bundle and converts it to engine policies.
//
// It refuses to produce policies when any diagnostic is an error, and that
// refusal is the point: a bundle with an unparsable regex or a numeric operator
// on a string attribute would otherwise load cleanly and fail closed at runtime,
// which looks exactly like a rule the author wrote wrong on purpose. Warnings do
// not block, and are returned so a deployment pipeline can surface them.
func (b *Bundle) Compile(opt LintOptions) ([]model.Policy, []Diagnostic, error) {
	diags := b.Lint(opt)
	if HasErrors(diags) {
		return nil, diags, ErrInvalidBundle
	}

	out := make([]model.Policy, 0, len(b.Policies))
	for i := range b.Policies {
		p, err := b.Policies[i].compile()
		if err != nil {
			// Lint should have caught anything reachable here; treat a
			// disagreement between the two as a bug rather than swallowing it.
			return nil, diags, fmt.Errorf("bundle: policy %q passed lint but failed to compile: %w",
				b.Policies[i].ID, err)
		}
		out = append(out, p)
	}
	return out, diags, nil
}

func (p *Policy) compile() (model.Policy, error) {
	tenant := p.Tenant
	if tenant == "" {
		tenant = model.GlobalTenant
	}
	out := model.Policy{
		ID:            p.ID,
		TenantID:      tenant,
		Scope:         p.Scope,
		Priority:      p.Priority,
		RuleAlgorithm: model.Algorithm(p.RuleAlgorithm),
		Rules:         make([]model.Rule, 0, len(p.Rules)),
	}
	for i := range p.Rules {
		r, err := p.Rules[i].compile()
		if err != nil {
			return model.Policy{}, err
		}
		out.Rules = append(out.Rules, r)
	}
	if err := out.Prepare(); err != nil {
		return model.Policy{}, err
	}
	return out, nil
}

func (r *Rule) compile() (model.Rule, error) {
	when, err := r.When.compile()
	if err != nil {
		return model.Rule{}, fmt.Errorf("rule %q: %w", r.ID, err)
	}
	return model.Rule{
		ID:          r.ID,
		Effect:      model.Effect(r.Effect),
		Priority:    r.Priority,
		When:        when,
		Obligations: r.Obligations,
	}, nil
}

// compile converts a node tree to a model expression. A nil node compiles to a
// nil expression, which matches everything — the catch-all rule.
func (n *Node) compile() (*model.ConditionExpr, error) {
	if n == nil {
		return nil, nil
	}
	switch n.Kind() {
	case NodeAll:
		sub, err := compileAll(n.All)
		if err != nil {
			return nil, err
		}
		return model.And(sub...), nil

	case NodeAny:
		sub, err := compileAll(n.Any)
		if err != nil {
			return nil, err
		}
		return model.Or(sub...), nil

	case NodeNot:
		inner, err := n.Not.compile()
		if err != nil {
			return nil, err
		}
		return model.Not(inner), nil

	case NodeLeaf:
		c, err := n.compileLeaf()
		if err != nil {
			return nil, err
		}
		return model.Cond(c), nil

	default:
		return nil, fmt.Errorf("condition node must be exactly one of all, any, not, or a leaf")
	}
}

func compileAll(nodes []*Node) ([]*model.ConditionExpr, error) {
	out := make([]*model.ConditionExpr, 0, len(nodes))
	for _, c := range nodes {
		e, err := c.compile()
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

func (n *Node) compileLeaf() (model.Condition, error) {
	c := model.Condition{
		Attribute: n.Attr,
		Operator:  model.Operator(n.Op),
		Values:    n.Values,
		Numbers:   n.Numbers,
	}
	if n.Min != nil {
		c.Min = *n.Min
	}
	if n.Max != nil {
		c.Max = *n.Max
	}
	for _, p := range n.Prefixes {
		prefix, err := netip.ParsePrefix(p)
		if err != nil {
			return model.Condition{}, fmt.Errorf("attribute %q: bad prefix %q: %w", n.Attr, p, err)
		}
		c.Prefixes = append(c.Prefixes, prefix)
	}
	return c, nil
}

// FromPolicies converts engine policies back to a bundle. Round-tripping matters
// for two reasons: it lets the CLI emit a starter bundle from the built-in demo
// set, and it gives the linter's tests a way to assert that compiling loses
// nothing.
func FromPolicies(policies []model.Policy) *Bundle {
	b := &Bundle{Version: FormatVersion, Policies: make([]Policy, 0, len(policies))}
	for i := range policies {
		p := &policies[i]
		bp := Policy{
			ID:            p.ID,
			Tenant:        p.TenantID,
			Scope:         p.Scope,
			Priority:      p.Priority,
			RuleAlgorithm: string(p.RuleAlgorithm),
			Rules:         make([]Rule, 0, len(p.Rules)),
		}
		for ri := range p.Rules {
			r := &p.Rules[ri]
			bp.Rules = append(bp.Rules, Rule{
				ID:          r.ID,
				Effect:      string(r.Effect),
				Priority:    r.Priority,
				When:        nodeFrom(r.When),
				Obligations: r.Obligations,
			})
		}
		b.Policies = append(b.Policies, bp)
	}
	return b
}

func nodeFrom(e *model.ConditionExpr) *Node {
	if e == nil {
		return nil
	}
	switch e.Kind {
	case model.ExprLeaf:
		c := e.Cond
		n := &Node{
			Attr:    c.Attribute,
			Op:      string(c.Operator),
			Values:  c.Values,
			Numbers: c.Numbers,
		}
		// Bounds are emitted only for the operators that read them, so a
		// round-tripped bundle does not sprout "min": 0 on every equality.
		switch c.Operator {
		case model.OpRange, model.OpNotRange:
			n.Min, n.Max = ptr(c.Min), ptr(c.Max)
		case model.OpGreaterThan, model.OpGreaterEq, model.OpNumEquals, model.OpNumNotEq:
			n.Min = ptr(c.Min)
		case model.OpLessThan, model.OpLessEq:
			n.Max = ptr(c.Max)
		}
		for _, p := range c.Prefixes {
			n.Prefixes = append(n.Prefixes, p.String())
		}
		return n

	case model.ExprAnd:
		return &Node{All: nodesFrom(e.Sub)}
	case model.ExprOr:
		return &Node{Any: nodesFrom(e.Sub)}
	case model.ExprNot:
		if len(e.Sub) != 1 {
			return &Node{}
		}
		return &Node{Not: nodeFrom(e.Sub[0])}
	}
	return &Node{}
}

func nodesFrom(sub []*model.ConditionExpr) []*Node {
	// Non-nil even when empty: an empty "all" is a meaningful catch-all, and
	// emitting null would change it to a leaf-less invalid node on reload.
	out := make([]*Node, 0, len(sub))
	for _, c := range sub {
		out = append(out, nodeFrom(c))
	}
	return out
}

func ptr(f float64) *float64 { return &f }

// Stats summarizes a bundle for a deployment log or an onboarding report.
type Stats struct {
	Policies       int
	Rules          int
	Conditions     int
	IndexableConds int
	RulesWithOrNot int
	Tenants        int
	Attributes     []string
	Operators      map[string]int
}

// Summarize walks the bundle and reports what it contains, including how much of
// it the index will actually be able to prune on. That last number is the one an
// operator wants before shipping a bundle: a policy set written mostly as
// disjunctions will be correct but will not be fast.
func (b *Bundle) Summarize() Stats {
	s := Stats{Operators: map[string]int{}}
	tenants := map[string]bool{}
	attrs := map[string]bool{}

	for i := range b.Policies {
		p := &b.Policies[i]
		s.Policies++
		tenants[p.Tenant] = true
		for ri := range p.Rules {
			s.Rules++
			when := p.Rules[ri].When
			total := countLeaves(when)
			spine := countSpineLeaves(when)
			s.Conditions += total
			s.IndexableConds += spine
			if spine < total {
				s.RulesWithOrNot++
			}
			walkNodes(when, func(n *Node) {
				if n.Kind() == NodeLeaf {
					s.Operators[n.Op]++
					attrs[n.Attr] = true
				}
			})
		}
	}

	s.Tenants = len(tenants)
	s.Attributes = make([]string, 0, len(attrs))
	for a := range attrs {
		s.Attributes = append(s.Attributes, a)
	}
	sort.Strings(s.Attributes)
	return s
}

func walkNodes(n *Node, fn func(*Node)) {
	if n == nil {
		return
	}
	fn(n)
	for _, c := range n.All {
		walkNodes(c, fn)
	}
	for _, c := range n.Any {
		walkNodes(c, fn)
	}
	walkNodes(n.Not, fn)
}

func countLeaves(n *Node) int {
	count := 0
	walkNodes(n, func(x *Node) {
		if x.Kind() == NodeLeaf {
			count++
		}
	})
	return count
}

// countSpineLeaves mirrors model.ConditionExpr.ANDSpineLeaves on the serialized
// form, so a bundle can be reported on before it is compiled.
func countSpineLeaves(n *Node) int {
	if n == nil {
		return 0
	}
	switch n.Kind() {
	case NodeLeaf:
		return 1
	case NodeAll:
		count := 0
		for _, c := range n.All {
			count += countSpineLeaves(c)
		}
		return count
	default: // any, not, invalid — off the spine
		return 0
	}
}
