package bundle

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"github.com/suga/tessaraop/internal/attr"
	"github.com/suga/tessaraop/internal/model"
)

// Severity ranks a diagnostic.
type Severity uint8

const (
	// Warning: the bundle will load and behave as written, but the author
	// probably did not mean it.
	Warning Severity = iota
	// Error: the bundle is rejected. Loading it would produce a policy set that
	// silently never matches, or that the engine cannot evaluate at all.
	Error
)

func (s Severity) String() string {
	if s == Error {
		return "error"
	}
	return "warning"
}

// Diagnostic is one finding, located by a path into the bundle.
type Diagnostic struct {
	Severity Severity
	Path     string // e.g. policies[2].rules[0].when.all[1]
	Message  string
}

func (d Diagnostic) String() string {
	return fmt.Sprintf("%s: %s: %s", d.Severity, d.Path, d.Message)
}

// HasErrors reports whether any diagnostic blocks loading.
func HasErrors(diags []Diagnostic) bool {
	for _, d := range diags {
		if d.Severity == Error {
			return true
		}
	}
	return false
}

// Errors returns only the blocking diagnostics.
func Errors(diags []Diagnostic) []Diagnostic {
	var out []Diagnostic
	for _, d := range diags {
		if d.Severity == Error {
			out = append(out, d)
		}
	}
	return out
}

// LintOptions tunes what the linter enforces.
//
// The defaults are what a customer's first bundle should be held to. The knobs
// exist because two things vary legitimately between deployments: whether the
// customer has extended the attribute vocabulary beyond the built-in registry,
// and how large a tree their authoring tool emits.
type LintOptions struct {
	// StrictAttributes makes an unregistered attribute name an error rather than
	// a warning.
	//
	// It defaults off, and that is deliberate. The registry covers the protocol
	// and identity surface, but customers legitimately carry their own
	// attributes — an internal risk signal, a bespoke resource label — and
	// refusing those at load time would force every integration to fork the
	// registry. The warning still fires, so a typo in a registry name is visible
	// rather than silent. Turn this on once the vocabulary is settled.
	StrictAttributes bool

	// MaxDepth caps condition-tree height. Zero means DefaultMaxDepth.
	//
	// An unbounded tree submitted by a tenant is a denial-of-service vector
	// against every request that reaches its shard: evaluation is linear in tree
	// size and the index cannot prune inside a disjunction.
	MaxDepth int

	// MaxConditionsPerRule caps leaves in one rule. Zero means
	// DefaultMaxConditionsPerRule.
	MaxConditionsPerRule int

	// MaxRegexLength caps a single pattern's source length. Zero means
	// DefaultMaxRegexLength. Go's regexp is RE2 and has no catastrophic
	// backtracking, so this is a cost bound rather than a safety one.
	MaxRegexLength int

	// AllowEmptyRuleSet permits a policy with no rules. Off by default: such a
	// policy can never produce a verdict, so it is almost always an editing
	// mistake rather than an intent.
	AllowEmptyRuleSet bool
}

// Linter defaults.
const (
	DefaultMaxDepth             = 16
	DefaultMaxConditionsPerRule = 64
	DefaultMaxRegexLength       = 512
)

func (o LintOptions) maxDepth() int {
	if o.MaxDepth <= 0 {
		return DefaultMaxDepth
	}
	return o.MaxDepth
}

func (o LintOptions) maxConds() int {
	if o.MaxConditionsPerRule <= 0 {
		return DefaultMaxConditionsPerRule
	}
	return o.MaxConditionsPerRule
}

func (o LintOptions) maxRegex() int {
	if o.MaxRegexLength <= 0 {
		return DefaultMaxRegexLength
	}
	return o.MaxRegexLength
}

// Lint validates a bundle and returns every finding, errors and warnings
// together, in bundle order.
//
// The linter exists because of a specific failure mode this engine has by
// design: absent attributes and unsatisfiable conditions fail closed. A rule
// comparing a string attribute with a numeric operator does not error — it simply
// never matches, which is indistinguishable from a rule the author meant to be
// narrow. Catching that at load time is the only place it can be caught.
func (b *Bundle) Lint(opt LintOptions) []Diagnostic {
	var diags []Diagnostic
	add := func(sev Severity, path, format string, args ...any) {
		diags = append(diags, Diagnostic{sev, path, fmt.Sprintf(format, args...)})
	}

	if b.Version != FormatVersion {
		add(Error, "version", "unsupported bundle version %d; this build reads version %d",
			b.Version, FormatVersion)
	}
	if len(b.Policies) == 0 {
		add(Warning, "policies", "bundle contains no policies, so every request will default-deny")
	}

	seenPolicy := map[string]int{}
	for i := range b.Policies {
		p := &b.Policies[i]
		path := fmt.Sprintf("policies[%d]", i)

		if p.ID == "" {
			add(Error, path, "policy has no id; ids appear in decisions and audit trails")
		} else if prev, dup := seenPolicy[p.ID]; dup {
			add(Error, path, "duplicate policy id %q, first seen at policies[%d]", p.ID, prev)
		} else {
			seenPolicy[p.ID] = i
		}

		if p.RuleAlgorithm != "" && !validAlgorithm(p.RuleAlgorithm) {
			add(Error, path+".rule_algorithm", "unknown algorithm %q; valid values are %s",
				p.RuleAlgorithm, strings.Join(algorithmNames(), ", "))
		}

		if len(p.Rules) == 0 && !opt.AllowEmptyRuleSet {
			add(Error, path+".rules", "policy has no rules and can never produce a verdict")
		}

		// A policy relying on rule priorities must say so: Rule.Priority is
		// ignored by the overrides algorithms, so setting it under the default
		// looks like it orders the rules when it does nothing at all.
		if p.RuleAlgorithm != string(model.FirstApplicable) && rulePrioritiesDiffer(p.Rules) {
			add(Warning, path, "rules carry different priorities but rule_algorithm is %s, "+
				"which ignores them; use first-applicable to order rules by priority",
				algorithmOrDefault(p.RuleAlgorithm))
		}

		seenRule := map[string]int{}
		for ri := range p.Rules {
			r := &p.Rules[ri]
			rpath := fmt.Sprintf("%s.rules[%d]", path, ri)

			if r.ID == "" {
				add(Error, rpath, "rule has no id")
			} else if prev, dup := seenRule[r.ID]; dup {
				add(Error, rpath, "duplicate rule id %q within policy %q, first seen at rules[%d]",
					r.ID, p.ID, prev)
			} else {
				seenRule[r.ID] = ri
			}

			switch model.Effect(r.Effect) {
			case model.Allow, model.Deny:
			case "":
				add(Error, rpath+".effect", "rule has no effect; must be ALLOW or DENY")
			default:
				add(Error, rpath+".effect", "unknown effect %q; must be ALLOW or DENY", r.Effect)
			}

			if r.When == nil {
				add(Warning, rpath+".when",
					"rule has no conditions and matches every request in scope; "+
						"intended only for a catch-all backstop")
			}

			if d := nodeDepth(r.When); d > opt.maxDepth() {
				add(Error, rpath+".when", "condition tree is %d deep, limit is %d", d, opt.maxDepth())
			}
			if n := countLeaves(r.When); n > opt.maxConds() {
				add(Error, rpath+".when", "rule has %d conditions, limit is %d", n, opt.maxConds())
			}

			diags = append(diags, lintNode(r.When, rpath+".when", opt)...)
		}
	}

	return diags
}

// lintNode validates one condition subtree.
func lintNode(n *Node, path string, opt LintOptions) []Diagnostic {
	if n == nil {
		return nil
	}
	var diags []Diagnostic
	add := func(sev Severity, p, format string, args ...any) {
		diags = append(diags, Diagnostic{sev, p, fmt.Sprintf(format, args...)})
	}

	switch n.Kind() {
	case NodeInvalid:
		add(Error, path, "condition node must be exactly one of all, any, not, or a leaf "+
			"with attr and op")
		return diags

	case NodeAll:
		if len(n.All) == 0 {
			add(Warning, path, `empty "all" matches every request; write it as an absent `+
				`"when" if that is the intent`)
		}
		for i, c := range n.All {
			diags = append(diags, lintNode(c, fmt.Sprintf("%s.all[%d]", path, i), opt)...)
		}
		return diags

	case NodeAny:
		if len(n.Any) == 0 {
			// Not merely useless: it silently makes the whole rule dead.
			add(Error, path, `empty "any" matches nothing, so this rule can never fire`)
		}
		if len(n.Any) == 1 {
			add(Warning, path, `"any" with one branch is just that branch, and it costs the `+
				`index: nothing under an "any" can be used as a pre-filter`)
		}
		for i, c := range n.Any {
			diags = append(diags, lintNode(c, fmt.Sprintf("%s.any[%d]", path, i), opt)...)
		}
		return diags

	case NodeNot:
		return append(diags, lintNode(n.Not, path+".not", opt)...)
	}

	// Leaf.
	if n.Attr == "" {
		add(Error, path, "leaf condition has an operator but no attribute")
		return diags
	}
	op := model.Operator(n.Op)
	family := op.Family()
	if family == model.FamilyUnknown {
		add(Error, path, "unknown operator %q on %q; valid operators are %s",
			n.Op, n.Attr, strings.Join(operatorNames(), " "))
		return diags
	}

	// Attribute must exist, and must be of a type the operator can read.
	registered, known := attr.Lookup(n.Attr)
	switch {
	case !known && opt.StrictAttributes:
		add(Error, path, "attribute %q is not in the registry", n.Attr)
	case !known:
		add(Warning, path, "attribute %q is not in the registry; the request must supply it "+
			"in the %s map or this condition can never match", n.Attr, mapNameFor(family))
	case !registered.Accepts(op):
		// The headline check. This is the mistake that would otherwise load fine
		// and produce a rule that never fires.
		add(Error, path, "operator %q reads %s values but %q is registered as %s, "+
			"so this condition can never match; valid operators here are %s",
			n.Op, mapNameFor(family), n.Attr, registered.Kind,
			operatorList(registered.Operators()))
	}

	diags = append(diags, lintLeafOperands(n, path, op)...)
	return diags
}

// lintLeafOperands checks that a leaf carries the operands its operator reads,
// and none that it ignores. A silently ignored operand is worth a warning: an
// author who wrote both "values" and "numbers" believes one of them is doing
// something.
func lintLeafOperands(n *Node, path string, op model.Operator) []Diagnostic {
	var diags []Diagnostic
	add := func(sev Severity, format string, args ...any) {
		diags = append(diags, Diagnostic{sev, path, fmt.Sprintf(format, args...)})
	}

	switch op {
	case model.OpExists, model.OpNotExists:
		if len(n.Values) > 0 || len(n.Numbers) > 0 || len(n.Prefixes) > 0 ||
			n.Min != nil || n.Max != nil {
			add(Warning, "operator %q tests only presence; the operands here are ignored", op)
		}
		return diags

	case model.OpEquals, model.OpNotEquals:
		switch {
		case len(n.Values) == 0:
			add(Error, "operator %q needs one value", op)
		case len(n.Values) > 1:
			// Real trap: eq/ne read Values[0] only, so extra values are silently
			// dropped and the rule is narrower than it looks.
			add(Error, "operator %q reads only the first value, but %d were given; "+
				"use %q for set membership", op, len(n.Values), setFormOf(op))
		}

	case model.OpIn, model.OpNotIn, model.OpContains, model.OpNotContains,
		model.OpPrefix, model.OpNotPrefix, model.OpSuffix, model.OpNotSuffix,
		model.OpDNSSuffix, model.OpNotDNSSuffix,
		model.OpHasAny, model.OpHasAll, model.OpHasNone:
		if len(n.Values) == 0 {
			add(Error, "operator %q needs at least one value", op)
		}
		// A value containing the set delimiter can never match a single element,
		// because the attribute is split on it before comparison.
		if op == model.OpHasAny || op == model.OpHasAll || op == model.OpHasNone {
			for i, v := range n.Values {
				if strings.ContainsRune(v, model.SetDelimiter) {
					add(Error, "value %d (%q) contains the set delimiter %q; "+
						"list elements separately instead, since %q compares whole elements",
						i, v, string(model.SetDelimiter), op)
				}
			}
		}
		// An empty string as the *only* value is almost always an editing
		// mistake. Among several it is often deliberate and correct: a NULL TCP
		// scan really does present no flags, so matching
		// `transport.tcp_flags in ["fin,syn", "", "fin,psh,urg"]` is how the
		// three classic invalid-flag scans are expressed. So this warns only on
		// the unambiguous case.
		if len(n.Values) == 1 && n.Values[0] == "" {
			add(Warning, "the only value is an empty string; %q against \"\" matches "+
				"just the present-and-empty case, which is rarely the intent", op)
		}
		// Using contains on an attribute the registry documents as a set is the
		// privilege-escalation trap the has_* operators exist to close: a
		// principal holding only "readwrite" satisfies `contains "read"`.
		if op == model.OpContains || op == model.OpNotContains {
			if isSetAttribute(n.Attr) {
				add(Error, "%q is a comma-delimited set, and %q is a substring test: "+
					"a principal holding only \"readwrite\" would satisfy contains \"read\". "+
					"Use has_any / has_all / has_none.", n.Attr, op)
			}
		}
		if op == model.OpSuffix || op == model.OpNotSuffix {
			for _, v := range n.Values {
				if looksLikeHostname(v) {
					add(Warning, "value %q looks like a domain, but %q is a raw byte test: "+
						"it would accept evil%s. Use dnssuffix for hostnames.", v, op, v)
				}
			}
		}

	case model.OpRegex, model.OpNotRegex:
		if len(n.Values) == 0 {
			add(Error, "operator %q needs at least one pattern", op)
		}
		for i, pat := range n.Values {
			if _, err := regexp.Compile(pat); err != nil {
				add(Error, "pattern %d does not compile: %v", i, err)
			}
			if len(pat) > DefaultMaxRegexLength {
				add(Warning, "pattern %d is %d bytes; long patterns cost time on every "+
					"request whose shard is reached, since regex cannot be indexed",
					i, len(pat))
			}
		}

	case model.OpRange, model.OpNotRange:
		switch {
		case n.Min == nil || n.Max == nil:
			add(Error, "operator %q needs both min and max", op)
		case *n.Min > *n.Max:
			add(Error, "min %g is greater than max %g, so %q can never match",
				*n.Min, *n.Max, op)
		}

	case model.OpGreaterThan, model.OpGreaterEq, model.OpNumEquals, model.OpNumNotEq:
		if n.Min == nil {
			add(Error, "operator %q needs min", op)
		}
		if n.Max != nil {
			add(Warning, "operator %q ignores max", op)
		}

	case model.OpLessThan, model.OpLessEq:
		if n.Max == nil {
			add(Error, "operator %q needs max", op)
		}
		if n.Min != nil {
			add(Warning, "operator %q ignores min", op)
		}

	case model.OpNumIn, model.OpNumNotIn:
		if len(n.Numbers) == 0 {
			add(Error, "operator %q needs at least one number", op)
		}

	case model.OpCIDR, model.OpNotCIDR:
		if len(n.Prefixes) == 0 {
			add(Error, "operator %q needs at least one prefix", op)
		}
		for i, p := range n.Prefixes {
			prefix, err := netip.ParsePrefix(p)
			if err != nil {
				add(Error, "prefix %d (%q) is not valid CIDR: %v", i, p, err)
				continue
			}
			if prefix.Addr() != prefix.Masked().Addr() {
				add(Warning, "prefix %q has bits set below its mask; it will be treated as %s",
					p, prefix.Masked())
			}
		}
	}

	// Operands the operator does not read at all.
	if op.Family() != model.FamilyNumeric && (n.Min != nil || n.Max != nil) &&
		op != model.OpExists && op != model.OpNotExists {
		add(Warning, "operator %q does not read min or max", op)
	}
	if op.Family() != model.FamilyNetwork && len(n.Prefixes) > 0 &&
		op != model.OpExists && op != model.OpNotExists {
		add(Warning, "operator %q does not read prefixes", op)
	}
	if op.Family() != model.FamilyString && len(n.Values) > 0 &&
		op != model.OpExists && op != model.OpNotExists {
		add(Warning, "operator %q does not read values", op)
	}
	if op != model.OpNumIn && op != model.OpNumNotIn && len(n.Numbers) > 0 {
		add(Warning, "operator %q does not read numbers", op)
	}

	return diags
}

// setFormOf names the set-membership operator corresponding to a scalar one, for
// the "you gave several values to eq" diagnostic.
func setFormOf(op model.Operator) model.Operator {
	if op == model.OpNotEquals {
		return model.OpNotIn
	}
	return model.OpIn
}

// setAttributes are the registry attributes documented as comma-delimited sets.
// Applying a substring operator to one of them is an error, not a style problem —
// see the diagnostic in lintLeafOperands.
var setAttributes = map[string]bool{
	"subject.roles":          true,
	"subject.groups":         true,
	"token.scopes":           true,
	"token.audience":         true,
	"transport.tcp_flags":    true,
	"network.ip_options":     true,
	"network.fragment_flags": true,
	"threat.categories":      true,
	"payload.dlp_categories": true,
	"payload.schema_errors":  true,
	"resource.ancestors":     true,
}

func isSetAttribute(name string) bool { return setAttributes[name] }

// looksLikeHostname is a heuristic for the suffix/dnssuffix confusion warning. It
// only needs to be right often enough to catch the mistake; a false positive
// costs one warning.
func looksLikeHostname(v string) bool {
	if strings.HasPrefix(v, ".") || !strings.Contains(v, ".") {
		return false
	}
	tld := v[strings.LastIndexByte(v, '.')+1:]
	if len(tld) < 2 {
		return false
	}
	for i := 0; i < len(tld); i++ {
		if tld[i] < 'a' || tld[i] > 'z' {
			return false
		}
	}
	return true
}

func mapNameFor(f model.Family) string {
	switch f {
	case model.FamilyString:
		return "string"
	case model.FamilyNumeric:
		return "numeric"
	case model.FamilyNetwork:
		return "ip"
	case model.FamilyPresence:
		return "any"
	}
	return "unknown"
}

func nodeDepth(n *Node) int {
	if n == nil {
		return 0
	}
	deepest := 0
	for _, c := range n.All {
		if d := nodeDepth(c); d > deepest {
			deepest = d
		}
	}
	for _, c := range n.Any {
		if d := nodeDepth(c); d > deepest {
			deepest = d
		}
	}
	if d := nodeDepth(n.Not); d > deepest {
		deepest = d
	}
	return deepest + 1
}

func rulePrioritiesDiffer(rules []Rule) bool {
	if len(rules) < 2 {
		return false
	}
	first := rules[0].Priority
	for i := 1; i < len(rules); i++ {
		if rules[i].Priority != first {
			return true
		}
	}
	return false
}

func validAlgorithm(s string) bool {
	for _, a := range model.AllAlgorithms {
		if string(a) == s {
			return true
		}
	}
	return false
}

func algorithmOrDefault(s string) string {
	if s == "" {
		return string(model.DenyOverrides)
	}
	return s
}

func algorithmNames() []string {
	out := make([]string, 0, len(model.AllAlgorithms))
	for _, a := range model.AllAlgorithms {
		out = append(out, string(a))
	}
	return out
}

func operatorNames() []string {
	out := make([]string, 0, len(model.AllOperators))
	for _, op := range model.AllOperators {
		out = append(out, string(op))
	}
	sort.Strings(out)
	return out
}

func operatorList(ops []model.Operator) string {
	out := make([]string, 0, len(ops))
	for _, op := range ops {
		out = append(out, string(op))
	}
	return strings.Join(out, " ")
}
