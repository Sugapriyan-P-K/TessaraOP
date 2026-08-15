package importer

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"

	"github.com/suga/tessaraop/internal/attr"
	"github.com/suga/tessaraop/internal/model"
)

// Envoy RBAC filter configuration.
//
// # The best structural fit of the three
//
// Envoy RBAC already expresses permissions and principals as boolean trees:
// and_rules, or_rules, not_rule, any. Those map one-to-one onto And, Or, Not and
// the empty conjunction, so the shape survives translation intact rather than
// being flattened.
//
// # The default that must be materialized
//
// With `action: ALLOW`, traffic matching no policy is denied. As with
// NetworkPolicy, the shard-level default-deny is not equivalent — another policy
// in the shard could grant it — so an explicit lowest-priority DENY is added.
// With `action: DENY` the default is to permit, which needs no rule.
//
// # shadow_rules
//
// Deliberately not merged into the output. shadow_rules are evaluated for
// metrics without being enforced — Envoy's own dry-run mechanism — so folding
// them into enforcement would turn an observation into a denial.
//
// # Input
//
// JSON, as it appears in a config dump or a filter configuration: either the
// filter object with a `rules` field, or the RBAC message itself.

// ImportEnvoyRBAC translates an Envoy RBAC configuration.
func ImportEnvoyRBAC(r io.Reader, source string, opt Options) (*Result, error) {
	if opt.Tenant == "" {
		return nil, ErrNoTenant
	}
	raw, err := io.ReadAll(io.LimitReader(r, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("importer: reading %s: %w", source, err)
	}

	var filter envoyFilter
	if err := json.Unmarshal(skipBOMBytes(raw), &filter); err != nil {
		return nil, fmt.Errorf("importer: %s is not a valid Envoy RBAC config: %w", source, err)
	}

	rules := filter.Rules
	if rules == nil {
		// The RBAC message itself rather than the filter wrapper.
		var direct envoyRBAC
		if err := json.Unmarshal(skipBOMBytes(raw), &direct); err == nil && len(direct.Policies) > 0 {
			rules = &direct
		}
	}

	b := newBuilder("envoy-rbac", source, opt)

	if filter.ShadowRules != nil {
		b.droppedSafely("shadow_rules", "shadow_rules",
			"shadow_rules are evaluated for metrics without being enforced, so they "+
				"were not translated; folding them in would turn an observation into "+
				"a denial")
	}

	if rules == nil || len(rules.Policies) == 0 {
		b.droppedSafely("rules", "rules", "configuration contains no policies")
		return b.finish(nil)
	}

	// ALLOW means "permit what matches, deny the rest"; DENY means the inverse.
	action := strings.ToUpper(strings.TrimSpace(rules.Action))
	if action == "" {
		action = "ALLOW"
		b.exact("rules.action", "action", "action was absent; defaulted to ALLOW")
	}
	var effect model.Effect
	switch action {
	case "ALLOW":
		effect = model.Allow
	case "DENY":
		effect = model.Deny
	case "LOG":
		b.droppedSafely("rules.action", "action",
			"action LOG only annotates the request and enforces nothing, so no rules "+
				"were produced")
		return b.finish(nil)
	default:
		return nil, fmt.Errorf("importer: %s: unknown RBAC action %q", source, action)
	}

	policy := model.Policy{
		ID:            b.opt.id(firstNonEmptyString(filter.Name, "envoy-rbac")),
		TenantID:      opt.Tenant,
		Scope:         opt.scopeOr("network"),
		RuleAlgorithm: model.FirstApplicable,
	}

	// Sorted so the translation is reproducible; Go map order is randomized.
	names := make([]string, 0, len(rules.Policies))
	for name := range rules.Policies {
		names = append(names, name)
	}
	sort.Strings(names)

	for i, name := range names {
		p := rules.Policies[name]
		path := fmt.Sprintf("rules.policies[%q]", name)

		var conjuncts []*model.ConditionExpr

		// permissions and principals are each OR-ed, and the two are AND-ed.
		if node := b.envoyAnyOf(p.Permissions, path+".permissions", b.envoyPermission); node != nil {
			conjuncts = append(conjuncts, node)
		} else if len(p.Permissions) > 0 {
			b.dropped(path+".permissions", "permissions",
				"no permission could be translated, so the rule now matches every request")
		}
		if node := b.envoyAnyOf(p.Principals, path+".principals", b.envoyPrincipal); node != nil {
			conjuncts = append(conjuncts, node)
		} else if len(p.Principals) > 0 {
			b.dropped(path+".principals", "principals",
				"no principal could be translated, so the rule now matches every principal")
		}

		if p.Condition != nil || p.CheckedCondition != nil {
			b.dropped(path+".condition", "condition",
				"CEL conditions are not translated; the rule is broader than the source")
		}

		policy.Rules = append(policy.Rules, model.Rule{
			ID:       b.opt.id(name),
			Effect:   effect,
			Priority: len(names) - i, // stable, above the default
			When:     model.And(conjuncts...),
		})
	}

	if effect == model.Allow {
		policy.Rules = append(policy.Rules, model.Rule{
			ID:          b.opt.id("default-deny"),
			Effect:      model.Deny,
			Priority:    -1 << 30,
			Obligations: []string{"audit_log"},
		})
		b.exact("rules.action", "action",
			"action ALLOW denies traffic matching no policy, so an explicit "+
				"lowest-priority DENY was added; without it the import would permit "+
				"traffic the source refused")
	}

	return b.finish([]model.Policy{policy})
}

// envoyAnyOf translates a list of matchers into a disjunction.
func (b *builder) envoyAnyOf(items []json.RawMessage, path string,
	translate func(json.RawMessage, string) *model.ConditionExpr) *model.ConditionExpr {

	var branches []*model.ConditionExpr
	for i, item := range items {
		if node := translate(item, fmt.Sprintf("%s[%d]", path, i)); node != nil {
			branches = append(branches, node)
		}
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

// envoyPermission translates a Permission matcher.
func (b *builder) envoyPermission(raw json.RawMessage, path string) *model.ConditionExpr {
	var p envoyPermission
	if err := json.Unmarshal(raw, &p); err != nil {
		b.dropped(path, "permission", "unrecognised permission shape: %v", err)
		return nil
	}

	switch {
	case p.Any:
		// `any: true` matches everything. An empty conjunction is exactly that in
		// this engine, so it is returned rather than nil — nil is reserved for
		// "could not translate", and conflating the two turned a faithful
		// translation into a spurious widening report.
		return model.And()

	case len(p.AndRules.Rules) > 0:
		var parts []*model.ConditionExpr
		for i, sub := range p.AndRules.Rules {
			subPath := fmt.Sprintf("%s.and_rules[%d]", path, i)
			node := b.envoyPermission(sub, subPath)
			if node == nil {
				// A lost conjunct removes a restriction, so the rule matches more
				// than the source did.
				b.dropped(subPath, "and_rules",
					"a conjunct could not be translated, so this rule is broader than "+
						"the source")
				continue
			}
			parts = append(parts, node)
		}
		return model.And(parts...)

	case len(p.OrRules.Rules) > 0:
		return b.envoyAnyOf(p.OrRules.Rules, path+".or_rules", b.envoyPermission)

	case len(p.NotRule) > 0:
		inner := b.envoyPermission(p.NotRule, path+".not_rule")
		if inner == nil {
			b.dropped(path+".not_rule", "not_rule",
				"the negated matcher could not be translated, so the negation was "+
					"dropped and the rule is broader than the source")
			return nil
		}
		return model.Not(inner)

	case p.URLPath != nil:
		return b.envoyStringMatch(p.URLPath.Path, attr.HTTPPath, path+".url_path")

	case p.Header != nil:
		attribute := attr.Header(p.Header.Name)
		// Envoy's pseudo-headers name the method and path.
		switch strings.ToLower(p.Header.Name) {
		case ":method":
			attribute = attr.HTTPMethod
		case ":path":
			attribute = attr.HTTPPath
		case ":authority", "host":
			attribute = attr.HTTPHost
		}
		return b.envoyHeaderMatch(p.Header, attribute, path+".header")

	case p.DestinationPort > 0:
		return model.Cond(model.Condition{
			Attribute: attr.DestPort, Operator: model.OpNumIn,
			Numbers: []float64{float64(p.DestinationPort)},
		})

	case p.DestinationPortRange != nil:
		// Envoy port ranges are half-open: [start, end).
		return model.Cond(model.Condition{
			Attribute: attr.DestPort, Operator: model.OpRange,
			Min: float64(p.DestinationPortRange.Start),
			Max: float64(p.DestinationPortRange.End - 1),
		})

	case p.DestinationIP != nil:
		return b.envoyCIDR(p.DestinationIP, attr.DestIP, path+".destination_ip")

	case p.RequestedServerName != nil:
		return b.envoyStringMatch(p.RequestedServerName, attr.SNI, path+".requested_server_name")

	case p.Metadata != nil:
		b.dropped(path+".metadata", "metadata",
			"metadata matchers read Envoy's per-filter state, which has no equivalent; "+
				"the matcher was dropped and the rule is broader than the source")
		return nil
	}

	b.dropped(path, "permission",
		"no recognised matcher in this permission; it was dropped, which broadens "+
			"the rule")
	return nil
}

// envoyPrincipal translates a Principal matcher.
func (b *builder) envoyPrincipal(raw json.RawMessage, path string) *model.ConditionExpr {
	var p envoyPrincipal
	if err := json.Unmarshal(raw, &p); err != nil {
		b.dropped(path, "principal", "unrecognised principal shape: %v", err)
		return nil
	}

	switch {
	case p.Any:
		// As above: the empty conjunction means "any principal", which is exact.
		return model.And()

	case len(p.AndIDs.IDs) > 0:
		var parts []*model.ConditionExpr
		for i, sub := range p.AndIDs.IDs {
			subPath := fmt.Sprintf("%s.and_ids[%d]", path, i)
			node := b.envoyPrincipal(sub, subPath)
			if node == nil {
				b.dropped(subPath, "and_ids",
					"a conjunct could not be translated, so this rule is broader than "+
						"the source")
				continue
			}
			parts = append(parts, node)
		}
		return model.And(parts...)

	case len(p.OrIDs.IDs) > 0:
		return b.envoyAnyOf(p.OrIDs.IDs, path+".or_ids", b.envoyPrincipal)

	case len(p.NotID) > 0:
		inner := b.envoyPrincipal(p.NotID, path+".not_id")
		if inner == nil {
			b.dropped(path+".not_id", "not_id",
				"the negated principal could not be translated, so the negation was "+
					"dropped and the rule is broader than the source")
			return nil
		}
		return model.Not(inner)

	case p.Authenticated != nil:
		if p.Authenticated.PrincipalName == nil {
			// `authenticated: {}` means "any authenticated peer", which mTLS
			// establishes.
			b.approx(path+".authenticated", "authenticated",
				"translated as a verified client certificate; the request must supply "+
					"tls.client_cert_verified")
			return model.Cond(model.Condition{
				Attribute: "tls.client_cert_verified", Operator: model.OpEquals,
				Values: []string{"true"},
			})
		}
		return b.envoyStringMatch(p.Authenticated.PrincipalName,
			"tls.client_cert_cn", path+".authenticated.principal_name")

	case p.DirectRemoteIP != nil:
		return b.envoyCIDR(p.DirectRemoteIP, attr.SourceIP, path+".direct_remote_ip")
	case p.RemoteIP != nil:
		return b.envoyCIDR(p.RemoteIP, attr.SourceIP, path+".remote_ip")
	case p.SourceIP != nil:
		return b.envoyCIDR(p.SourceIP, attr.SourceIP, path+".source_ip")

	case p.Header != nil:
		return b.envoyHeaderMatch(p.Header, attr.Header(p.Header.Name), path+".header")

	case p.URLPath != nil:
		return b.envoyStringMatch(p.URLPath.Path, attr.HTTPPath, path+".url_path")

	case p.Metadata != nil:
		b.dropped(path+".metadata", "metadata",
			"metadata matchers have no equivalent; the matcher was dropped and the "+
				"rule is broader than the source")
		return nil
	}

	b.dropped(path, "principal",
		"no recognised matcher in this principal; it was dropped, which broadens "+
			"the rule")
	return nil
}

// envoyStringMatch translates Envoy's StringMatcher, whose variants map onto the
// string operators directly.
func (b *builder) envoyStringMatch(m *envoyStringMatcher, attribute, path string) *model.ConditionExpr {
	if m == nil {
		return nil
	}
	values := func(v string) []string { return []string{v} }

	switch {
	case m.Exact != "":
		return model.Cond(model.Condition{
			Attribute: attribute, Operator: model.OpEquals, Values: values(m.Exact)})
	case m.Prefix != "":
		return model.Cond(model.Condition{
			Attribute: attribute, Operator: model.OpPrefix, Values: values(m.Prefix)})
	case m.Suffix != "":
		return model.Cond(model.Condition{
			Attribute: attribute, Operator: model.OpSuffix, Values: values(m.Suffix)})
	case m.Contains != "":
		return model.Cond(model.Condition{
			Attribute: attribute, Operator: model.OpContains, Values: values(m.Contains)})
	case m.SafeRegex != nil && m.SafeRegex.Regex != "":
		// Envoy's safe_regex is RE2, which is the same engine Go's regexp uses,
		// so the pattern transfers unchanged.
		b.exact(path, "safe_regex",
			"Envoy safe_regex is RE2, the same engine used here, so the pattern "+
				"transfers unchanged")
		return model.Cond(model.Condition{
			Attribute: attribute, Operator: model.OpRegex,
			Values: values("^(?:" + m.SafeRegex.Regex + ")$")})
	}
	b.dropped(path, "string_matcher",
		"no recognised variant in this string matcher; it was dropped, which "+
			"broadens the rule")
	return nil
}

func (b *builder) envoyHeaderMatch(h *envoyHeaderMatcher, attribute, path string) *model.ConditionExpr {
	var node *model.ConditionExpr

	switch {
	case h.ExactMatch != "":
		node = model.Cond(model.Condition{
			Attribute: attribute, Operator: model.OpEquals, Values: []string{h.ExactMatch}})
	case h.PrefixMatch != "":
		node = model.Cond(model.Condition{
			Attribute: attribute, Operator: model.OpPrefix, Values: []string{h.PrefixMatch}})
	case h.SuffixMatch != "":
		node = model.Cond(model.Condition{
			Attribute: attribute, Operator: model.OpSuffix, Values: []string{h.SuffixMatch}})
	case h.ContainsMatch != "":
		node = model.Cond(model.Condition{
			Attribute: attribute, Operator: model.OpContains, Values: []string{h.ContainsMatch}})
	case h.PresentMatch:
		node = model.Cond(model.Condition{Attribute: attribute, Operator: model.OpExists})
	case h.StringMatch != nil:
		node = b.envoyStringMatch(h.StringMatch, attribute, path+".string_match")
	case h.RangeMatch != nil:
		node = model.Cond(model.Condition{
			Attribute: attribute, Operator: model.OpRange,
			Min: float64(h.RangeMatch.Start), Max: float64(h.RangeMatch.End - 1)})
		b.approx(path+".range_match", "range_match",
			"a numeric header range requires %s in the numeric map", attribute)
	default:
		b.dropped(path, "header",
			"no recognised variant in this header matcher; it was dropped, which "+
				"broadens the rule")
		return nil
	}

	if node != nil && h.InvertMatch {
		return model.Not(node)
	}
	return node
}

func (b *builder) envoyCIDR(c *envoyCIDRRange, attribute, path string) *model.ConditionExpr {
	if c == nil || c.AddressPrefix == "" {
		return nil
	}
	spec := fmt.Sprintf("%s/%d", c.AddressPrefix, c.PrefixLen)
	prefix, err := netip.ParsePrefix(spec)
	if err != nil {
		b.dropped(path, "cidr_range", "%q is not a CIDR block: %v", spec, err)
		return nil
	}
	return model.Cond(model.Condition{
		Attribute: attribute, Operator: model.OpCIDR,
		Prefixes: []netip.Prefix{prefix.Masked()},
	})
}

// --- Parsing -----------------------------------------------------------------

type envoyFilter struct {
	Name        string     `json:"name"`
	Rules       *envoyRBAC `json:"rules"`
	ShadowRules *envoyRBAC `json:"shadow_rules"`
}

type envoyRBAC struct {
	Action   string                  `json:"action"`
	Policies map[string]envoyPolicyV `json:"policies"`
}

type envoyPolicyV struct {
	Permissions      []json.RawMessage `json:"permissions"`
	Principals       []json.RawMessage `json:"principals"`
	Condition        json.RawMessage   `json:"condition"`
	CheckedCondition json.RawMessage   `json:"checked_condition"`
}

type envoyPermission struct {
	Any      bool `json:"any"`
	AndRules struct {
		Rules []json.RawMessage `json:"rules"`
	} `json:"and_rules"`
	OrRules struct {
		Rules []json.RawMessage `json:"rules"`
	} `json:"or_rules"`
	NotRule json.RawMessage `json:"not_rule"`

	Header  *envoyHeaderMatcher `json:"header"`
	URLPath *struct {
		Path *envoyStringMatcher `json:"path"`
	} `json:"url_path"`
	DestinationIP        *envoyCIDRRange     `json:"destination_ip"`
	DestinationPort      int                 `json:"destination_port"`
	DestinationPortRange *envoyInt32Range    `json:"destination_port_range"`
	RequestedServerName  *envoyStringMatcher `json:"requested_server_name"`
	Metadata             json.RawMessage     `json:"metadata"`
}

type envoyPrincipal struct {
	Any    bool `json:"any"`
	AndIDs struct {
		IDs []json.RawMessage `json:"ids"`
	} `json:"and_ids"`
	OrIDs struct {
		IDs []json.RawMessage `json:"ids"`
	} `json:"or_ids"`
	NotID json.RawMessage `json:"not_id"`

	Authenticated *struct {
		PrincipalName *envoyStringMatcher `json:"principal_name"`
	} `json:"authenticated"`
	SourceIP       *envoyCIDRRange     `json:"source_ip"`
	DirectRemoteIP *envoyCIDRRange     `json:"direct_remote_ip"`
	RemoteIP       *envoyCIDRRange     `json:"remote_ip"`
	Header         *envoyHeaderMatcher `json:"header"`
	URLPath        *struct {
		Path *envoyStringMatcher `json:"path"`
	} `json:"url_path"`
	Metadata json.RawMessage `json:"metadata"`
}

type envoyStringMatcher struct {
	Exact     string `json:"exact"`
	Prefix    string `json:"prefix"`
	Suffix    string `json:"suffix"`
	Contains  string `json:"contains"`
	SafeRegex *struct {
		Regex string `json:"regex"`
	} `json:"safe_regex"`
}

type envoyHeaderMatcher struct {
	Name          string              `json:"name"`
	ExactMatch    string              `json:"exact_match"`
	PrefixMatch   string              `json:"prefix_match"`
	SuffixMatch   string              `json:"suffix_match"`
	ContainsMatch string              `json:"contains_match"`
	PresentMatch  bool                `json:"present_match"`
	InvertMatch   bool                `json:"invert_match"`
	StringMatch   *envoyStringMatcher `json:"string_match"`
	RangeMatch    *envoyInt32Range    `json:"range_match"`
}

type envoyCIDRRange struct {
	AddressPrefix string `json:"address_prefix"`
	PrefixLen     int    `json:"prefix_len"`
}

type envoyInt32Range struct {
	Start int `json:"start"`
	End   int `json:"end"`
}
