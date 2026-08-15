// Package importer translates policies from other engines into TessaraOP bundles.
//
// # The failure mode this package is built around
//
// A translator that cannot express a construct has two options: drop it, or
// refuse. Dropping is almost always wrong here, and the reason is asymmetric.
//
// Most policy languages express constraints as *restrictions* on a grant. An AWS
// IAM statement that allows `s3:GetObject` only when `aws:SourceIp` is inside
// 10.0.0.0/8 becomes, if the condition is dropped, a statement that allows
// `s3:GetObject` from anywhere. The translation succeeded, the bundle lints
// clean, and access is now broader than the policy it replaced. Nobody notices
// until it matters.
//
// The reverse — dropping something that would have *granted* access — produces a
// policy that denies too much. That is a visible outage, someone files a ticket,
// and it gets fixed.
//
// So every note this package emits carries a Widens flag, and by default an
// import **fails** if any construct would widen access. Options.AllowWidening
// exists for the case where an operator has read the notes and accepted them, and
// it is deliberately not the default.
//
// # What "fidelity" means here
//
//	Exact         semantics preserved; the translated rule accepts exactly what
//	              the source accepted
//	Approximated  preserved with a caveat the operator must read — usually
//	              because the source referred to something only its own runtime
//	              can resolve, and the translation depends on the request
//	              supplying an equivalent attribute
//	Dropped       not translated at all
//
// # Formats
//
// All three importers read JSON, because this module has no dependencies and the
// standard library ships no YAML codec. Every source format has a JSON form
// reachable from its own tooling:
//
//	AWS IAM              aws iam get-policy-version --output json
//	Kubernetes NetPol    kubectl get networkpolicy -o json
//	Envoy RBAC           the rbac filter config from a config dump
//
// # What is deliberately not attempted
//
// Rego is a general-purpose language with negation-as-failure, comprehensions and
// arbitrary built-ins. Only a recognizable subset could be translated, and
// shipping a partial Rego translator invites exactly the silent-widening failure
// above on the cases it does not understand. The OPA-compatible *endpoint* in
// package pdpserver is the better migration path: it keeps the caller's client
// code and lets policies be rewritten deliberately rather than machine-guessed.
package importer

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/suga/tessaraop/internal/model"
)

// Fidelity records how faithfully one source construct was translated.
type Fidelity uint8

const (
	// Exact: the translated rule accepts exactly what the source accepted.
	Exact Fidelity = iota
	// Approximated: preserved, but the operator must read the note.
	Approximated
	// Dropped: not translated.
	Dropped
)

func (f Fidelity) String() string {
	switch f {
	case Exact:
		return "exact"
	case Approximated:
		return "approximated"
	case Dropped:
		return "dropped"
	}
	return "unknown"
}

// Note is one observation about the translation of one source construct.
type Note struct {
	Fidelity Fidelity
	// Path locates the construct in the source document, e.g.
	// Statement[2].Condition.StringLike.
	Path string
	// Source names the construct, e.g. "NotAction" or "podSelector".
	Source string
	// Message explains what happened and, when relevant, what the operator
	// should do about it.
	Message string
	// Widens reports whether this translation makes the resulting policy accept
	// something the source policy would have refused. These are the notes that
	// matter: see the package documentation.
	Widens bool
}

func (n Note) String() string {
	prefix := n.Fidelity.String()
	if n.Widens {
		prefix = "WIDENS ACCESS (" + prefix + ")"
	}
	if n.Path == "" {
		return fmt.Sprintf("%s: %s: %s", prefix, n.Source, n.Message)
	}
	return fmt.Sprintf("%s: %s (%s): %s", prefix, n.Path, n.Source, n.Message)
}

// Report summarizes an import.
type Report struct {
	Format   string
	Source   string // a name for the document, e.g. its filename
	Policies int
	Rules    int
	Notes    []Note
}

// Widening returns the notes whose translation broadens access. An operator
// should read these before shipping the result, and by default the import
// refuses to produce policies while any exist.
func (r *Report) Widening() []Note {
	var out []Note
	for _, n := range r.Notes {
		if n.Widens {
			out = append(out, n)
		}
	}
	return out
}

// ByFidelity counts notes at each fidelity level.
func (r *Report) ByFidelity() map[Fidelity]int {
	out := map[Fidelity]int{}
	for _, n := range r.Notes {
		out[n.Fidelity]++
	}
	return out
}

// String renders the report for a terminal or a CI log, widening notes first.
func (r *Report) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s import of %s: %d policies, %d rules\n",
		r.Format, r.Source, r.Policies, r.Rules)

	counts := r.ByFidelity()
	fmt.Fprintf(&b, "  %d exact, %d approximated, %d dropped",
		counts[Exact], counts[Approximated], counts[Dropped])
	if w := r.Widening(); len(w) > 0 {
		fmt.Fprintf(&b, ", %d WIDENING ACCESS", len(w))
	}
	b.WriteString("\n")

	for _, n := range r.Widening() {
		fmt.Fprintf(&b, "  %s\n", n)
	}
	for _, n := range r.Notes {
		if !n.Widens {
			fmt.Fprintf(&b, "  %s\n", n)
		}
	}
	return b.String()
}

// Result is a completed import.
type Result struct {
	Policies []model.Policy
	Report   Report
}

// Options controls an import.
type Options struct {
	// Tenant is the tenant the imported policies belong to. Required: an
	// imported policy with no tenant would land in the global shard and apply to
	// every request in the deployment, which is never what a translation of one
	// customer's policy means.
	Tenant string

	// Scope subdivides the tenant. Each importer supplies a sensible default
	// when this is empty — "network" for NetworkPolicy, for instance — because
	// leaving everything at tenant-wide scope forfeits the partitioning that
	// makes evaluation fast.
	Scope string

	// IDPrefix is prepended to generated policy and rule IDs, so several imports
	// into one bundle cannot collide.
	IDPrefix string

	// AllowWidening permits an import whose result accepts more than the source.
	// Off by default. Turn it on only after reading Report.Widening().
	AllowWidening bool

	// Strict additionally refuses an import with any Approximated note, for a
	// pipeline that wants byte-for-byte semantics or nothing.
	Strict bool
}

func (o Options) scopeOr(def string) string {
	if o.Scope != "" {
		return o.Scope
	}
	return def
}

func (o Options) id(parts ...string) string {
	joined := strings.Join(parts, "/")
	if o.IDPrefix == "" {
		return joined
	}
	return o.IDPrefix + "/" + joined
}

// Errors returned when a translation cannot be delivered safely.
var (
	// ErrWidensAccess means the translation would accept something the source
	// policy refused. See Report.Widening() for what and why.
	ErrWidensAccess = errors.New("importer: translation would widen access")

	// ErrApproximated is returned under Options.Strict when any construct could
	// only be approximated.
	ErrApproximated = errors.New("importer: translation is approximate")

	// ErrNoTenant means Options.Tenant was empty.
	ErrNoTenant = errors.New("importer: Options.Tenant is required")
)

// builder accumulates policies and notes during one import.
type builder struct {
	opt    Options
	report Report
}

func newBuilder(format, source string, opt Options) *builder {
	return &builder{opt: opt, report: Report{Format: format, Source: source}}
}

func (b *builder) note(f Fidelity, widens bool, path, source, format string, args ...any) {
	b.report.Notes = append(b.report.Notes, Note{
		Fidelity: f, Widens: widens, Path: path, Source: source,
		Message: fmt.Sprintf(format, args...),
	})
}

func (b *builder) exact(path, source, format string, args ...any) {
	b.note(Exact, false, path, source, format, args...)
}

func (b *builder) approx(path, source, format string, args ...any) {
	b.note(Approximated, false, path, source, format, args...)
}

// approxWidening records an approximation that broadens access. Separate from
// approx because the distinction is the whole point of this package.
func (b *builder) approxWidening(path, source, format string, args ...any) {
	b.note(Approximated, true, path, source, format, args...)
}

func (b *builder) dropped(path, source, format string, args ...any) {
	b.note(Dropped, true, path, source, format, args...)
}

// droppedSafely records a construct that was not translated but whose absence
// cannot broaden access — typically because it only ever narrowed a deny, or
// because it was redundant.
func (b *builder) droppedSafely(path, source, format string, args ...any) {
	b.note(Dropped, false, path, source, format, args...)
}

// finish validates the accumulated result against the options.
func (b *builder) finish(policies []model.Policy) (*Result, error) {
	for i := range policies {
		b.report.Rules += len(policies[i].Rules)
	}
	b.report.Policies = len(policies)

	res := &Result{Policies: policies, Report: b.report}

	if w := b.report.Widening(); len(w) > 0 && !b.opt.AllowWidening {
		// The report is still returned, because the operator needs to read it in
		// order to decide whether to set AllowWidening.
		return res, fmt.Errorf("%w: %d construct(s); review Report.Widening()",
			ErrWidensAccess, len(w))
	}
	if b.opt.Strict {
		if n := b.report.ByFidelity()[Approximated]; n > 0 {
			return res, fmt.Errorf("%w: %d construct(s)", ErrApproximated, n)
		}
	}
	return res, nil
}

// --- Wildcard translation ---------------------------------------------------

// wildcardKind classifies a glob pattern by the cheapest TessaraOP operator that
// can express it exactly.
type wildcardKind uint8

const (
	globExact  wildcardKind = iota // no metacharacters
	globPrefix                     // trailing * only
	globAll                        // "*" alone: matches everything
	globRegex                      // anything else
)

func classifyGlob(pattern string) wildcardKind {
	switch {
	case pattern == "*":
		return globAll
	case !strings.ContainsAny(pattern, "*?"):
		return globExact
	case strings.HasSuffix(pattern, "*") &&
		!strings.ContainsAny(strings.TrimSuffix(pattern, "*"), "*?"):
		return globPrefix
	default:
		return globRegex
	}
}

// globToRegex converts an IAM/Envoy-style glob to an anchored regular expression.
//
// Escaping the literal segments is not optional. An action like "s3:Get*" is
// harmless, but a resource ARN contains dots and colons, and a pattern such as
// "arn:aws:s3:::my.bucket/*" translated without escaping would let "." match any
// character — so "my-bucket" would satisfy a rule written for "my.bucket". That
// is a widening bug hiding in a metacharacter.
func globToRegex(pattern string) string {
	var b strings.Builder
	b.WriteString("^")
	for _, part := range splitKeepingSeparators(pattern) {
		switch part {
		case "*":
			b.WriteString(".*")
		case "?":
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(part))
		}
	}
	b.WriteString("$")
	return b.String()
}

// splitKeepingSeparators splits a pattern into literal runs and single
// metacharacters.
func splitKeepingSeparators(pattern string) []string {
	var out []string
	start := 0
	for i := 0; i < len(pattern); i++ {
		if pattern[i] != '*' && pattern[i] != '?' {
			continue
		}
		if i > start {
			out = append(out, pattern[start:i])
		}
		out = append(out, pattern[i:i+1])
		start = i + 1
	}
	if start < len(pattern) {
		out = append(out, pattern[start:])
	}
	return out
}

// globConditions builds an expression matching attr against any of the patterns.
//
// Patterns are grouped by the operator that can express them, so a list of plain
// strings becomes one indexable `in` rather than a disjunction of regexes. That
// matters for performance: `in` is a hash lookup on the AND-spine, while a regex
// is not indexable at all.
//
// It returns nil when the patterns match everything, which the caller should read
// as "no condition needed".
func globConditions(attr string, patterns []string) *model.ConditionExpr {
	var exact, prefixes, regexes []string
	for _, p := range patterns {
		switch classifyGlob(p) {
		case globAll:
			return nil // "*" subsumes everything else in the list
		case globExact:
			exact = append(exact, p)
		case globPrefix:
			prefixes = append(prefixes, strings.TrimSuffix(p, "*"))
		default:
			regexes = append(regexes, globToRegex(p))
		}
	}

	var branches []*model.ConditionExpr
	if len(exact) > 0 {
		sort.Strings(exact)
		branches = append(branches, model.Cond(model.Condition{
			Attribute: attr, Operator: model.OpIn, Values: exact}))
	}
	if len(prefixes) > 0 {
		sort.Strings(prefixes)
		branches = append(branches, model.Cond(model.Condition{
			Attribute: attr, Operator: model.OpPrefix, Values: prefixes}))
	}
	if len(regexes) > 0 {
		sort.Strings(regexes)
		branches = append(branches, model.Cond(model.Condition{
			Attribute: attr, Operator: model.OpRegex, Values: regexes}))
	}

	switch len(branches) {
	case 0:
		return nil
	case 1:
		return branches[0]
	default:
		return model.Or(branches...)
	}
}

// appendNonNil adds e to dst when it carries a constraint. Importers build
// conjunctions incrementally and a nil child would mean "matches everything",
// which is exactly what should be omitted rather than inserted.
func appendNonNil(dst []*model.ConditionExpr, e *model.ConditionExpr) []*model.ConditionExpr {
	if e == nil {
		return dst
	}
	return append(dst, e)
}

// denyAll is the catch-all DENY rule used to materialize an implicit default.
//
// Several source formats deny by default once a policy selects a subject:
// Kubernetes NetworkPolicy for a selected pod, and Envoy RBAC under an ALLOW
// action. TessaraOP's shard-level default-deny is not equivalent, because
// another policy in the same shard could grant what the source would have
// refused. Making the default explicit as a lowest-priority rule preserves the
// source's meaning under first-applicable.
func denyAll(id, reason string) model.Rule {
	return model.Rule{
		ID:       id,
		Effect:   model.Deny,
		Priority: -1 << 30, // below any plausible authored priority
		When:     nil,      // matches everything
		Obligations: []string{
			// Not a real obligation so much as a breadcrumb: if this rule ever
			// fires, an operator reading the decision should see why it exists.
			"audit_log",
		},
	}
}
