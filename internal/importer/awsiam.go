package importer

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/suga/tessaraop/internal/attr"
	"github.com/suga/tessaraop/internal/model"
)

// AWS IAM policy documents.
//
// # Why this is the closest fit
//
// An IAM statement is already an effect plus a predicate: Effect, Action,
// Resource and a Condition block, all conjoined. That maps onto a Rule almost
// directly. And IAM's evaluation rule — an explicit Deny beats any Allow — is
// exactly deny-overrides, so the combining algorithm needs no translation either.
//
// # Where it stops being a clean fit
//
// Three things do not survive, and all three widen access if dropped silently:
//
//   - **Policy variables** (${aws:username}). They resolve against request
//     context at evaluation time; a literal translation matches the wrong thing
//     or nothing at all.
//   - **Set operators** (ForAnyValue:, ForAllValues:). They quantify over a
//     multi-valued context key, and the quantifier is the whole meaning.
//   - **Unrecognised condition operators or keys.** Dropping a condition turns a
//     narrow grant into a broad one.
//
// Each is reported as widening, so by default the import refuses rather than
// producing something more permissive than the source.
//
// # Actions and resources
//
// Actions arrive as IAM strings ("s3:GetObject") and are mapped onto the `action`
// attribute verbatim rather than being translated into read/write/delete. An
// invented mapping would be a guess, and a wrong guess about what an action means
// is an authorization bug. The request must supply the same vocabulary.
// Resources map to `resource.id` as full ARNs, for the same reason.

// ImportAWSIAM translates an IAM policy document.
func ImportAWSIAM(r io.Reader, source string, opt Options) (*Result, error) {
	if opt.Tenant == "" {
		return nil, ErrNoTenant
	}
	raw, err := io.ReadAll(io.LimitReader(r, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("importer: reading %s: %w", source, err)
	}

	var doc iamDocument
	if err := json.Unmarshal(skipBOMBytes(raw), &doc); err != nil {
		return nil, fmt.Errorf("importer: %s is not a valid IAM policy document: %w", source, err)
	}

	statements, err := doc.statements()
	if err != nil {
		return nil, fmt.Errorf("importer: %s: %w", source, err)
	}

	b := newBuilder("aws-iam", source, opt)

	policyID := opt.id(firstNonEmptyString(doc.ID, strings.TrimSuffix(source, ".json"), "iam-policy"))
	policy := model.Policy{
		ID:       policyID,
		TenantID: opt.Tenant,
		Scope:    opt.scopeOr("iam"),
		// IAM's explicit-deny-wins is deny-overrides exactly.
		RuleAlgorithm: model.DenyOverrides,
	}

	for i := range statements {
		st := &statements[i]
		path := fmt.Sprintf("Statement[%d]", i)

		rule, ok := b.iamStatement(st, path, i)
		if !ok {
			continue
		}
		policy.Rules = append(policy.Rules, rule)
	}

	if len(policy.Rules) == 0 {
		b.dropped("Statement", "document",
			"no statement could be translated, so the resulting policy would grant "+
				"and deny nothing")
		return b.finish(nil)
	}
	return b.finish([]model.Policy{policy})
}

func (b *builder) iamStatement(st *iamStatement, path string, index int) (model.Rule, bool) {
	rule := model.Rule{ID: b.opt.id(firstNonEmptyString(st.Sid, fmt.Sprintf("statement-%d", index)))}

	switch strings.ToLower(st.Effect) {
	case "allow":
		rule.Effect = model.Allow
	case "deny":
		rule.Effect = model.Deny
	default:
		b.dropped(path+".Effect", "Effect",
			"unknown effect %q; the statement was skipped entirely", st.Effect)
		return model.Rule{}, false
	}

	var conjuncts []*model.ConditionExpr

	// Action / NotAction.
	switch {
	case len(st.Action) > 0 && len(st.NotAction) > 0:
		b.dropped(path, "Action",
			"both Action and NotAction are present, which IAM does not permit; "+
				"the statement was skipped")
		return model.Rule{}, false
	case len(st.Action) > 0:
		if node, ok := b.globNode(path+".Action", "Action", attr.Action, st.Action); ok {
			conjuncts = appendNonNil(conjuncts, node)
		} else {
			return model.Rule{}, false
		}
	case len(st.NotAction) > 0:
		node, ok := b.globNode(path+".NotAction", "NotAction", attr.Action, st.NotAction)
		if !ok {
			return model.Rule{}, false
		}
		if node == nil {
			// NotAction ["*"] excludes everything, so the statement is dead.
			b.droppedSafely(path+".NotAction", "NotAction",
				`NotAction is "*", which excludes every action, so the statement can `+
					"never apply")
			return model.Rule{}, false
		}
		conjuncts = append(conjuncts, model.Not(node))
		if rule.Effect == model.Deny {
			// Worth flagging even though it translates exactly: NotAction with
			// Deny denies everything *except* the listed actions, which is a
			// well-known way to lock an account out by accident.
			b.exact(path+".NotAction", "NotAction",
				"NotAction with Effect Deny denies every action except those listed; "+
					"translated faithfully, but confirm that is the intent")
		}
	}

	// Resource / NotResource.
	switch {
	case len(st.Resource) > 0 && len(st.NotResource) > 0:
		b.dropped(path, "Resource",
			"both Resource and NotResource are present, which IAM does not permit; "+
				"the statement was skipped")
		return model.Rule{}, false
	case len(st.Resource) > 0:
		if node, ok := b.globNode(path+".Resource", "Resource", "resource.id", st.Resource); ok {
			conjuncts = appendNonNil(conjuncts, node)
		} else {
			return model.Rule{}, false
		}
	case len(st.NotResource) > 0:
		node, ok := b.globNode(path+".NotResource", "NotResource", "resource.id", st.NotResource)
		if !ok {
			return model.Rule{}, false
		}
		if node != nil {
			conjuncts = append(conjuncts, model.Not(node))
		}
	}

	// Principal only appears in resource-based policies, where it says *who* the
	// policy is about. TessaraOP takes the principal from the request, so this is
	// mapped onto subject.id.
	if len(st.Principal) > 0 {
		if node, ok := b.iamPrincipal(st.Principal, path+".Principal"); ok && node != nil {
			conjuncts = append(conjuncts, node)
		}
	}
	if len(st.NotPrincipal) > 0 {
		b.dropped(path+".NotPrincipal", "NotPrincipal",
			"NotPrincipal has no equivalent and was dropped; the rule now applies to "+
				"principals the source excluded")
	}

	// Condition block.
	for _, node := range b.iamConditions(st.Condition, path+".Condition") {
		conjuncts = appendNonNil(conjuncts, node)
	}

	if len(conjuncts) == 0 {
		b.exact(path, "Statement",
			"statement constrains nothing, so the rule matches every request in scope")
	}
	rule.When = model.And(conjuncts...)
	return rule, true
}

// globNode builds a condition from IAM glob patterns. It reports false when the
// statement must be abandoned, and a nil node when the patterns match everything.
func (b *builder) globNode(path, source, attribute string, patterns []string) (*model.ConditionExpr, bool) {
	for _, p := range patterns {
		if strings.Contains(p, "${") {
			// A policy variable resolves against request context at evaluation
			// time. Translating it literally would match the string "${aws:username}",
			// which matches nothing — turning a grant into a silent denial — or, in
			// a Deny, removing a restriction.
			b.dropped(path, source,
				"value %q contains a policy variable, which resolves at evaluation "+
					"time and cannot be translated statically", p)
			return nil, false
		}
	}
	node := globConditions(attribute, patterns)
	if node == nil {
		b.exact(path, source, `"*" matches everything, so no condition was emitted`)
	}
	return node, true
}

func (b *builder) iamPrincipal(raw json.RawMessage, path string) (*model.ConditionExpr, bool) {
	// "*" means anyone.
	var star string
	if err := json.Unmarshal(raw, &star); err == nil {
		if star == "*" {
			b.exact(path, "Principal", `Principal "*" matches every principal`)
			return nil, true
		}
		return model.Cond(model.Condition{
			Attribute: attr.SubjectID, Operator: model.OpEquals, Values: []string{star},
		}), true
	}

	var byType map[string]stringOrSlice
	if err := json.Unmarshal(raw, &byType); err != nil {
		b.dropped(path, "Principal", "unrecognised Principal shape; it was dropped, so "+
			"the rule now applies to principals the source did not name")
		return nil, false
	}

	var values []string
	for _, principals := range byType {
		values = append(values, principals...)
	}
	if len(values) == 0 {
		return nil, true
	}
	sort.Strings(values)
	b.approx(path, "Principal",
		"Principal was mapped onto %s; the request must identify principals with the "+
			"same ARNs or identifiers", attr.SubjectID)
	return model.Cond(model.Condition{
		Attribute: attr.SubjectID, Operator: model.OpIn, Values: values,
	}), true
}

// iamConditions translates the Condition block.
func (b *builder) iamConditions(block map[string]map[string]stringOrSlice, path string) []*model.ConditionExpr {
	if len(block) == 0 {
		return nil
	}
	// Sorted so a translation is reproducible.
	operators := make([]string, 0, len(block))
	for op := range block {
		operators = append(operators, op)
	}
	sort.Strings(operators)

	var out []*model.ConditionExpr
	for _, rawOp := range operators {
		opPath := path + "." + rawOp
		entries := block[rawOp]

		op, ifExists, setOperator := parseIAMOperator(rawOp)
		if setOperator != "" {
			// ForAnyValue / ForAllValues quantify over a multi-valued context key,
			// and the quantifier carries the meaning. There is no way to express
			// "every value of this key satisfies X" against a single attribute.
			b.dropped(opPath, rawOp,
				"%s quantifies over a multi-valued context key and has no equivalent; "+
					"the condition was dropped", setOperator)
			continue
		}

		keys := make([]string, 0, len(entries))
		for k := range entries {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, key := range keys {
			values := entries[key]
			node := b.iamCondition(opPath+"."+key, rawOp, op, key, values, ifExists)
			out = appendNonNil(out, node)
		}
	}
	return out
}

// iamCondition translates one operator/key/values triple.
func (b *builder) iamCondition(path, rawOp, op, key string, values []string, ifExists bool) *model.ConditionExpr {
	for _, v := range values {
		if strings.Contains(v, "${") {
			b.dropped(path, rawOp,
				"value %q contains a policy variable and cannot be translated statically; "+
					"the condition was dropped, which broadens the statement", v)
			return nil
		}
	}

	attribute, kind, known := iamContextKey(key)
	if !known {
		b.approxWidening(path, rawOp,
			"condition key %q is not in the attribute registry; it was mapped to %q, "+
				"and the rule is broader than the source unless the request supplies it",
			key, attribute)
	}

	cond, ok := b.iamOperator(path, rawOp, op, attribute, kind, values)
	if !ok {
		return nil
	}

	if !ifExists {
		return cond
	}
	// ...IfExists means "apply this only when the key is present". TessaraOP
	// fails closed on absent attributes, so the equivalent is an explicit
	// disjunction with absence — which translates the semantics exactly.
	b.exact(path, rawOp,
		"IfExists was translated as (attribute absent OR condition), which matches "+
			"its semantics exactly")
	return model.Or(
		model.Not(model.Cond(model.Condition{
			Attribute: attribute, Operator: model.OpExists,
		})),
		cond,
	)
}

// iamOperator builds the condition for a base operator.
func (b *builder) iamOperator(path, rawOp, op, attribute string, kind attr.Kind, values []string) (*model.ConditionExpr, bool) {
	str := func(operator model.Operator) *model.ConditionExpr {
		return model.Cond(model.Condition{
			Attribute: attribute, Operator: operator, Values: values,
		})
	}

	switch op {
	case "stringequals", "arnequals", "arnlike":
		// ArnLike permits wildcards; ArnEquals does not. Both are handled by the
		// glob translator, which emits an exact set when no metacharacter appears.
		if op == "arnlike" {
			return globConditions(attribute, values), true
		}
		return str(model.OpIn), true
	case "stringnotequals", "arnnotequals", "arnnotlike":
		if op == "arnnotlike" {
			node := globConditions(attribute, values)
			if node == nil {
				return nil, false
			}
			return model.Not(node), true
		}
		return str(model.OpNotIn), true

	case "stringlike":
		return globConditions(attribute, values), true
	case "stringnotlike":
		node := globConditions(attribute, values)
		if node == nil {
			b.dropped(path, rawOp, `StringNotLike "*" excludes everything`)
			return nil, false
		}
		return model.Not(node), true

	case "stringequalsignorecase", "stringnotequalsignorecase":
		// No case-insensitive comparison operator exists, but an anchored
		// case-insensitive regex is exactly equivalent.
		patterns := make([]string, 0, len(values))
		for _, v := range values {
			patterns = append(patterns, "(?i)^"+quoteRegex(v)+"$")
		}
		cond := model.Cond(model.Condition{
			Attribute: attribute, Operator: model.OpRegex, Values: patterns,
		})
		b.exact(path, rawOp,
			"translated to a case-insensitive anchored regex, which is equivalent; "+
				"note that regex conditions are not indexable")
		if strings.HasPrefix(op, "stringnot") {
			return model.Not(cond), true
		}
		return cond, true

	case "bool":
		// IAM booleans are the strings "true"/"false", which is also how the
		// registry represents boolean attributes.
		normalized := make([]string, 0, len(values))
		for _, v := range values {
			normalized = append(normalized, strings.ToLower(strings.TrimSpace(v)))
		}
		return model.Cond(model.Condition{
			Attribute: attribute, Operator: model.OpIn, Values: normalized,
		}), true

	case "null":
		// Null:true means the key must be absent; false means it must be present.
		absent := len(values) > 0 && strings.EqualFold(strings.TrimSpace(values[0]), "true")
		operator := model.OpExists
		if absent {
			operator = model.OpNotExists
		}
		b.exact(path, rawOp, "Null translates exactly to a presence check")
		return model.Cond(model.Condition{Attribute: attribute, Operator: operator}), true

	case "ipaddress", "notipaddress":
		prefixes, ok := b.parsePrefixes(path, rawOp, values)
		if !ok {
			return nil, false
		}
		operator := model.OpCIDR
		if op == "notipaddress" {
			operator = model.OpNotCIDR
		}
		return model.Cond(model.Condition{
			Attribute: attribute, Operator: operator, Prefixes: prefixes,
		}), true

	case "numericequals", "numericnotequals", "numericlessthan",
		"numericlessthanequals", "numericgreaterthan", "numericgreaterthanequals":
		return b.iamNumeric(path, rawOp, op, attribute, values, false)

	case "dateequals", "datenotequals", "datelessthan",
		"datelessthanequals", "dategreaterthan", "dategreaterthanequals":
		return b.iamNumeric(path, rawOp, op, attribute, values, true)
	}

	b.dropped(path, rawOp,
		"condition operator %q has no equivalent and was dropped, which makes the "+
			"statement broader than the source", rawOp)
	return nil, false
}

func (b *builder) iamNumeric(path, rawOp, op, attribute string, values []string, isDate bool) (*model.ConditionExpr, bool) {
	nums := make([]float64, 0, len(values))
	for _, v := range values {
		n, err := parseIAMNumber(v, isDate)
		if err != nil {
			b.dropped(path, rawOp, "value %q is not a %s: %v", v, numberKind(isDate), err)
			return nil, false
		}
		nums = append(nums, n)
	}
	if len(nums) == 0 {
		return nil, false
	}
	if isDate {
		b.approx(path, rawOp,
			"dates were converted to Unix seconds on %s; the request must supply the "+
				"same representation", attribute)
	}

	base := strings.TrimPrefix(strings.TrimPrefix(op, "numeric"), "date")
	switch base {
	case "equals":
		return model.Cond(model.Condition{
			Attribute: attribute, Operator: model.OpNumIn, Numbers: nums}), true
	case "notequals":
		return model.Cond(model.Condition{
			Attribute: attribute, Operator: model.OpNumNotIn, Numbers: nums}), true
	}

	// The ordered comparisons take a single operand in practice. Several values
	// mean "any of", so they become a disjunction.
	var branches []*model.ConditionExpr
	for _, n := range nums {
		c := model.Condition{Attribute: attribute}
		switch base {
		case "lessthan":
			c.Operator, c.Max = model.OpLessThan, n
		case "lessthanequals":
			c.Operator, c.Max = model.OpLessEq, n
		case "greaterthan":
			c.Operator, c.Min = model.OpGreaterThan, n
		case "greaterthanequals":
			c.Operator, c.Min = model.OpGreaterEq, n
		default:
			return nil, false
		}
		branches = append(branches, model.Cond(c))
	}
	if len(branches) == 1 {
		return branches[0], true
	}
	return model.Or(branches...), true
}

func (b *builder) parsePrefixes(path, rawOp string, values []string) ([]netip.Prefix, bool) {
	out := make([]netip.Prefix, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if p, err := netip.ParsePrefix(v); err == nil {
			out = append(out, p.Masked())
			continue
		}
		// A bare address is a /32 or /128.
		if a, err := netip.ParseAddr(v); err == nil {
			bits := a.BitLen()
			out = append(out, netip.PrefixFrom(a, bits))
			continue
		}
		b.dropped(path, rawOp, "value %q is not an IP address or CIDR block", v)
		return nil, false
	}
	return out, true
}

// --- Parsing helpers ---------------------------------------------------------

type iamDocument struct {
	Version   string          `json:"Version"`
	ID        string          `json:"Id"`
	Statement json.RawMessage `json:"Statement"`
}

// statements accepts both a single object and an array, which IAM permits.
func (d *iamDocument) statements() ([]iamStatement, error) {
	if len(d.Statement) == 0 {
		return nil, fmt.Errorf("document has no Statement")
	}
	var many []iamStatement
	if err := json.Unmarshal(d.Statement, &many); err == nil {
		return many, nil
	}
	var one iamStatement
	if err := json.Unmarshal(d.Statement, &one); err != nil {
		return nil, fmt.Errorf("Statement is neither an object nor an array: %w", err)
	}
	return []iamStatement{one}, nil
}

type iamStatement struct {
	Sid          string          `json:"Sid"`
	Effect       string          `json:"Effect"`
	Action       stringOrSlice   `json:"Action"`
	NotAction    stringOrSlice   `json:"NotAction"`
	Resource     stringOrSlice   `json:"Resource"`
	NotResource  stringOrSlice   `json:"NotResource"`
	Principal    json.RawMessage `json:"Principal"`
	NotPrincipal json.RawMessage `json:"NotPrincipal"`

	Condition map[string]map[string]stringOrSlice `json:"Condition"`
}

// stringOrSlice accepts either form, which IAM uses interchangeably.
type stringOrSlice []string

func (s *stringOrSlice) UnmarshalJSON(data []byte) error {
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		*s = []string{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err == nil {
		*s = many
		return nil
	}
	// Numbers and booleans appear in condition values; accept them as strings so
	// a document does not fail to parse over a JSON type.
	var scalar json.RawMessage
	if err := json.Unmarshal(data, &scalar); err == nil {
		*s = []string{strings.Trim(string(scalar), `"`)}
		return nil
	}
	return fmt.Errorf("value is neither a string nor an array of strings")
}

// parseIAMOperator splits an operator into its base form, the IfExists suffix and
// any set-operator prefix.
func parseIAMOperator(raw string) (base string, ifExists bool, setOperator string) {
	base = raw
	if i := strings.Index(base, ":"); i >= 0 {
		setOperator = base[:i]
		base = base[i+1:]
	}
	if strings.HasSuffix(strings.ToLower(base), "ifexists") {
		ifExists = true
		base = base[:len(base)-len("IfExists")]
	}
	return strings.ToLower(base), ifExists, setOperator
}

func parseIAMNumber(v string, isDate bool) (float64, error) {
	v = strings.TrimSpace(v)
	if !isDate {
		return strconv.ParseFloat(v, 64)
	}
	// Epoch seconds are also accepted for date operators.
	if n, err := strconv.ParseFloat(v, 64); err == nil {
		return n, nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05Z", "2006-01-02"} {
		if t, err := time.Parse(layout, v); err == nil {
			return float64(t.Unix()), nil
		}
	}
	return 0, fmt.Errorf("not an RFC 3339 timestamp or epoch value")
}

func numberKind(isDate bool) string {
	if isDate {
		return "date"
	}
	return "number"
}

// iamContextKey maps an IAM condition key onto a registry attribute.
//
// Unmapped keys fall through to an "aws." namespace and are reported as widening,
// because a condition on an attribute the request never supplies fails closed —
// which for a Deny statement means the restriction silently disappears.
func iamContextKey(key string) (attribute string, kind attr.Kind, known bool) {
	lower := strings.ToLower(key)

	// Tag and claim keys carry a suffix.
	for _, prefix := range []string{"aws:principaltag/", "aws:requesttag/", "aws:resourcetag/"} {
		if strings.HasPrefix(lower, prefix) {
			name := key[len(prefix):]
			return attr.Claim(strings.ToLower(name)), attr.KindString, true
		}
	}

	switch lower {
	case "aws:sourceip", "aws:vpcsourceip":
		return attr.SourceIP, attr.KindIP, true
	case "aws:multifactorauthpresent":
		return attr.MFAVerified, attr.KindString, true
	case "aws:multifactorauthage":
		return "subject.auth_age_seconds", attr.KindNumeric, true
	case "aws:currenttime", "aws:epochtime":
		return "time.unix", attr.KindNumeric, true
	case "aws:username", "aws:userid", "aws:principalarn", "aws:principalid":
		return attr.SubjectID, attr.KindString, true
	case "aws:principaltype":
		return "subject.type", attr.KindString, true
	case "aws:securetransport":
		return "tls.client_cert_verified", attr.KindString, false
	case "aws:referer":
		return "http.referer", attr.KindString, true
	case "aws:useragent":
		return attr.UserAgent, attr.KindString, true
	case "aws:requestedregion":
		return attr.GeoCountry, attr.KindString, false
	case "aws:principalorgid", "aws:principalaccount":
		return attr.Claim("org"), attr.KindString, false
	}

	// Anything else keeps its key under an aws. namespace so it is at least
	// addressable, and is flagged.
	return "aws." + strings.ReplaceAll(strings.TrimPrefix(lower, "aws:"), ":", "."),
		attr.KindString, false
}

func quoteRegex(s string) string {
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune(`\.+*?()|[]{}^$`, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

func firstNonEmptyString(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// skipBOMBytes drops a leading UTF-8 byte-order mark, which Windows editors emit
// and JSON's grammar has no place for.
func skipBOMBytes(b []byte) []byte {
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		return b[3:]
	}
	return b
}
