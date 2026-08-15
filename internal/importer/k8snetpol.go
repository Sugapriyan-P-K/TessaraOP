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

// Kubernetes NetworkPolicy.
//
// # The thing that must not be got wrong
//
// NetworkPolicy is **default-deny once a pod is selected**. A pod with no policy
// selecting it accepts everything; the moment any policy selects it for Ingress,
// all ingress traffic not explicitly permitted is denied.
//
// TessaraOP's shard-level default-deny is *not* equivalent, because another
// policy in the same shard could grant what the source refused. So the implicit
// deny is materialized as an explicit lowest-priority DENY rule under
// first-applicable. Without that, an imported NetworkPolicy would be dramatically
// more permissive than the original — the exact silent-widening failure this
// package exists to prevent.
//
// # Selectors need the cluster
//
// podSelector and namespaceSelector are label queries resolved against live
// cluster state. A Request has no pod identity and this package performs no I/O,
// so they are translated onto a documented label attribute and reported as
// widening: the rule is broader than the source unless the caller supplies those
// labels.
//
// # Input
//
// JSON, as produced by `kubectl get networkpolicy -o json`. Both a single object
// and a List are accepted.

// K8sLabelAttribute is where a pod's labels are expected, as comma-joined
// "key=value" pairs. Match with has_all.
const K8sLabelAttribute = "k8s.pod_labels"

// K8sNamespaceAttribute is where the workload's namespace is expected.
const K8sNamespaceAttribute = "k8s.namespace"

// ImportK8sNetworkPolicy translates one or more NetworkPolicy objects.
//
// The namespace becomes the tenant unless Options.Tenant overrides it, because in
// multi-tenant Kubernetes the namespace *is* the tenant boundary. A policy
// imported into the wrong tenant would apply to traffic it was never written for.
func ImportK8sNetworkPolicy(r io.Reader, source string, opt Options) (*Result, error) {
	raw, err := io.ReadAll(io.LimitReader(r, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("importer: reading %s: %w", source, err)
	}

	objects, err := decodeK8sObjects(skipBOMBytes(raw))
	if err != nil {
		return nil, fmt.Errorf("importer: %s: %w", source, err)
	}

	b := newBuilder("k8s-networkpolicy", source, opt)
	var policies []model.Policy

	for i := range objects {
		obj := &objects[i]
		path := fmt.Sprintf("items[%d]", i)

		if obj.Kind != "" && obj.Kind != "NetworkPolicy" {
			b.droppedSafely(path, "kind",
				"object is a %s, not a NetworkPolicy; it was skipped", obj.Kind)
			continue
		}

		tenant := opt.Tenant
		if tenant == "" {
			tenant = obj.Metadata.Namespace
		}
		if tenant == "" {
			return nil, fmt.Errorf("importer: %s: %w (the object has no namespace either)",
				source, ErrNoTenant)
		}

		p := b.k8sPolicy(obj, tenant, path)
		if len(p.Rules) > 0 {
			policies = append(policies, p)
		}
	}

	if len(policies) == 0 {
		b.droppedSafely("items", "document", "no NetworkPolicy object was translated")
	}
	return b.finish(policies)
}

func (b *builder) k8sPolicy(obj *k8sNetworkPolicy, tenant, path string) model.Policy {
	name := firstNonEmptyString(obj.Metadata.Name, "networkpolicy")
	policy := model.Policy{
		ID:       b.opt.id(name),
		TenantID: tenant,
		Scope:    b.opt.scopeOr("network"),
		// first-applicable, because the materialized default-deny must sit below
		// the permits by priority rather than override them.
		RuleAlgorithm: model.FirstApplicable,
	}

	// The pods this policy applies to. An empty selector means every pod in the
	// namespace, which is expressible; a non-empty one is not, without the
	// cluster.
	selector := b.k8sSelector(obj.Spec.PodSelector, path+".spec.podSelector", "podSelector")

	types := obj.Spec.PolicyTypes
	if len(types) == 0 {
		// The default per the API: Ingress, plus Egress if any egress rule exists.
		types = []string{"Ingress"}
		if len(obj.Spec.Egress) > 0 {
			types = append(types, "Egress")
		}
		b.exact(path+".spec.policyTypes", "policyTypes",
			"policyTypes was absent; defaulted to %s per the API", strings.Join(types, ", "))
	}

	for _, t := range types {
		switch strings.ToLower(t) {
		case "ingress":
			for i, rule := range obj.Spec.Ingress {
				rulePath := fmt.Sprintf("%s.spec.ingress[%d]", path, i)
				policy.Rules = append(policy.Rules,
					b.k8sTrafficRule(name, "ingress", i, rule.From, rule.Ports, selector, rulePath))
			}
		case "egress":
			for i, rule := range obj.Spec.Egress {
				rulePath := fmt.Sprintf("%s.spec.egress[%d]", path, i)
				policy.Rules = append(policy.Rules,
					b.k8sTrafficRule(name, "egress", i, rule.To, rule.Ports, selector, rulePath))
			}
		default:
			b.dropped(path+".spec.policyTypes", "policyTypes",
				"unknown policy type %q was ignored", t)
		}
	}

	// The materialized default-deny. See the package documentation: without it
	// the import is far more permissive than the source.
	if len(policy.Rules) > 0 || len(types) > 0 {
		policy.Rules = append(policy.Rules, model.Rule{
			ID:     b.opt.id(name, "default-deny"),
			Effect: model.Deny,
			// Below every permit, so it applies only when none matched.
			Priority:    -1 << 30,
			When:        selectorExpr(selector),
			Obligations: []string{"audit_log"},
		})
		b.exact(path, "policyTypes",
			"NetworkPolicy denies by default once it selects a pod, so an explicit "+
				"lowest-priority DENY was added for %s; without it the import would "+
				"permit traffic the source refused", strings.Join(types, "+"))
	}

	return policy
}

// k8sTrafficRule builds one ALLOW rule from an ingress or egress entry.
func (b *builder) k8sTrafficRule(name, direction string, index int,
	peers []k8sPeer, ports []k8sPort, selector []*model.ConditionExpr, path string) model.Rule {

	rule := model.Rule{
		ID:     b.opt.id(name, fmt.Sprintf("%s-%d", direction, index)),
		Effect: model.Allow,
		// Above the materialized default-deny, which sits at the minimum.
		Priority: index + 1,
	}

	conjuncts := append([]*model.ConditionExpr(nil), selector...)

	// Peers within one rule are OR-ed; an empty list means "from anywhere".
	if len(peers) > 0 {
		var branches []*model.ConditionExpr
		for i, peer := range peers {
			if node := b.k8sPeer(peer, direction, fmt.Sprintf("%s.from[%d]", path, i)); node != nil {
				branches = append(branches, node)
			}
		}
		switch len(branches) {
		case 0:
			// Every peer was untranslatable, so the rule now permits any source.
			b.dropped(path, direction,
				"no peer in this rule could be translated, so it now permits traffic "+
					"from anywhere")
		case 1:
			conjuncts = append(conjuncts, branches[0])
		default:
			conjuncts = append(conjuncts, model.Or(branches...))
		}
	} else {
		b.exact(path, direction, "no peer restriction, so traffic from anywhere is permitted")
	}

	// Ports within one rule are also OR-ed.
	if len(ports) > 0 {
		var branches []*model.ConditionExpr
		for i, port := range ports {
			if node := b.k8sPort(port, fmt.Sprintf("%s.ports[%d]", path, i)); node != nil {
				branches = append(branches, node)
			}
		}
		if len(branches) == 1 {
			conjuncts = append(conjuncts, branches[0])
		} else if len(branches) > 1 {
			conjuncts = append(conjuncts, model.Or(branches...))
		}
	}

	rule.When = model.And(conjuncts...)
	return rule
}

func (b *builder) k8sPeer(peer k8sPeer, direction, path string) *model.ConditionExpr {
	ipAttribute := attr.SourceIP
	if direction == "egress" {
		ipAttribute = attr.DestIP
	}

	if peer.IPBlock != nil {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(peer.IPBlock.CIDR))
		if err != nil {
			b.dropped(path+".ipBlock.cidr", "ipBlock",
				"%q is not a CIDR block: %v", peer.IPBlock.CIDR, err)
			return nil
		}
		node := model.Cond(model.Condition{
			Attribute: ipAttribute, Operator: model.OpCIDR,
			Prefixes: []netip.Prefix{prefix.Masked()},
		})

		// `except` carves holes out of the block, which is a conjunction with a
		// negated CIDR — expressible exactly.
		var excepts []netip.Prefix
		for _, e := range peer.IPBlock.Except {
			p, err := netip.ParsePrefix(strings.TrimSpace(e))
			if err != nil {
				b.dropped(path+".ipBlock.except", "ipBlock",
					"%q is not a CIDR block, so an exclusion was lost and the rule "+
						"permits more than the source: %v", e, err)
				continue
			}
			excepts = append(excepts, p.Masked())
		}
		if len(excepts) > 0 {
			node = model.And(node, model.Not(model.Cond(model.Condition{
				Attribute: ipAttribute, Operator: model.OpCIDR, Prefixes: excepts,
			})))
			b.exact(path+".ipBlock.except", "ipBlock",
				"except was translated as a negated CIDR, which is exact")
		}
		return node
	}

	var parts []*model.ConditionExpr
	if peer.NamespaceSelector != nil {
		if node := b.k8sNamespaceSelector(*peer.NamespaceSelector, path+".namespaceSelector"); node != nil {
			parts = append(parts, node)
		}
	}
	if peer.PodSelector != nil {
		sel := b.k8sSelector(peer.PodSelector, path+".podSelector", "podSelector")
		parts = append(parts, sel...)
	}

	switch len(parts) {
	case 0:
		return nil
	case 1:
		return parts[0]
	default:
		return model.And(parts...)
	}
}

// k8sSelector translates a label selector.
//
// An empty selector means "every pod in the namespace" and is expressible as no
// condition. A non-empty one needs cluster state, so it is mapped onto a label
// attribute the caller must supply, and reported as widening.
func (b *builder) k8sSelector(sel *k8sLabelSelector, path, source string) []*model.ConditionExpr {
	if sel == nil || (len(sel.MatchLabels) == 0 && len(sel.MatchExpressions) == 0) {
		if sel != nil {
			b.exact(path, source, "empty selector matches every pod in the namespace")
		}
		return nil
	}

	if len(sel.MatchExpressions) > 0 {
		b.dropped(path+".matchExpressions", source,
			"matchExpressions (set-based selectors) are not translated; the rule is "+
				"broader than the source")
	}
	if len(sel.MatchLabels) == 0 {
		return nil
	}

	labels := make([]string, 0, len(sel.MatchLabels))
	for k, v := range sel.MatchLabels {
		labels = append(labels, k+"="+v)
	}
	sort.Strings(labels)

	b.approxWidening(path, source,
		"label selector %v requires cluster state to resolve; it was translated as "+
			"%s has_all %v, so the rule is broader than the source unless the request "+
			"supplies those labels", labels, K8sLabelAttribute, labels)

	return []*model.ConditionExpr{model.Cond(model.Condition{
		Attribute: K8sLabelAttribute, Operator: model.OpHasAll, Values: labels,
	})}
}

func (b *builder) k8sNamespaceSelector(sel k8sLabelSelector, path string) *model.ConditionExpr {
	// The common case by far is matching a namespace by its name label.
	for _, key := range []string{
		"kubernetes.io/metadata.name", "name", "namespace",
	} {
		if v, ok := sel.MatchLabels[key]; ok {
			b.approx(path, "namespaceSelector",
				"matched on the %q label and translated to %s == %q",
				key, K8sNamespaceAttribute, v)
			return model.Cond(model.Condition{
				Attribute: K8sNamespaceAttribute, Operator: model.OpEquals,
				Values: []string{v},
			})
		}
	}
	if len(sel.MatchLabels) == 0 && len(sel.MatchExpressions) == 0 {
		b.exact(path, "namespaceSelector", "empty selector matches every namespace")
		return nil
	}
	b.dropped(path, "namespaceSelector",
		"namespace label selectors other than the name label need cluster state; "+
			"this one was dropped, so the rule permits traffic from namespaces the "+
			"source excluded")
	return nil
}

func (b *builder) k8sPort(port k8sPort, path string) *model.ConditionExpr {
	var parts []*model.ConditionExpr

	if port.Protocol != "" {
		parts = append(parts, model.Cond(model.Condition{
			Attribute: "network.protocol_name", Operator: model.OpEquals,
			Values: []string{strings.ToLower(port.Protocol)},
		}))
	}

	switch {
	case port.Port == nil:
		// No port means every port on the given protocol.
	case port.Port.IsName:
		// A named port resolves through the pod spec, which needs cluster state.
		b.dropped(path+".port", "port",
			"named port %q resolves through the pod spec and needs cluster state; "+
				"the port restriction was dropped, so the rule permits every port",
			port.Port.Name)
	case port.EndPort > 0 && port.EndPort > port.Port.Number:
		parts = append(parts, model.Cond(model.Condition{
			Attribute: attr.DestPort, Operator: model.OpRange,
			Min: float64(port.Port.Number), Max: float64(port.EndPort),
		}))
	default:
		parts = append(parts, model.Cond(model.Condition{
			Attribute: attr.DestPort, Operator: model.OpNumIn,
			Numbers: []float64{float64(port.Port.Number)},
		}))
	}

	switch len(parts) {
	case 0:
		return nil
	case 1:
		return parts[0]
	default:
		return model.And(parts...)
	}
}

// selectorExpr wraps the pod selector for the default-deny rule.
func selectorExpr(selector []*model.ConditionExpr) *model.ConditionExpr {
	if len(selector) == 0 {
		return nil // selects every pod in the namespace
	}
	return model.And(selector...)
}

// --- Parsing -----------------------------------------------------------------

type k8sNetworkPolicy struct {
	Kind     string `json:"kind"`
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Spec struct {
		PodSelector *k8sLabelSelector `json:"podSelector"`
		PolicyTypes []string          `json:"policyTypes"`
		Ingress     []k8sIngressRule  `json:"ingress"`
		Egress      []k8sEgressRule   `json:"egress"`
	} `json:"spec"`
}

type k8sLabelSelector struct {
	MatchLabels      map[string]string `json:"matchLabels"`
	MatchExpressions []json.RawMessage `json:"matchExpressions"`
}

type k8sIngressRule struct {
	From  []k8sPeer `json:"from"`
	Ports []k8sPort `json:"ports"`
}

type k8sEgressRule struct {
	To    []k8sPeer `json:"to"`
	Ports []k8sPort `json:"ports"`
}

type k8sPeer struct {
	PodSelector       *k8sLabelSelector `json:"podSelector"`
	NamespaceSelector *k8sLabelSelector `json:"namespaceSelector"`
	IPBlock           *struct {
		CIDR   string   `json:"cidr"`
		Except []string `json:"except"`
	} `json:"ipBlock"`
}

type k8sPort struct {
	Protocol string          `json:"protocol"`
	Port     *k8sIntOrString `json:"port"`
	EndPort  int             `json:"endPort"`
}

// k8sIntOrString mirrors the API's IntOrString: a port is either a number or a
// name resolved through the pod spec.
type k8sIntOrString struct {
	Number int
	Name   string
	IsName bool
}

func (v *k8sIntOrString) UnmarshalJSON(data []byte) error {
	var n int
	if err := json.Unmarshal(data, &n); err == nil {
		v.Number = n
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		v.Name, v.IsName = s, true
		return nil
	}
	return fmt.Errorf("port is neither a number nor a name")
}

// decodeK8sObjects accepts a single object or a List.
func decodeK8sObjects(raw []byte) ([]k8sNetworkPolicy, error) {
	var list struct {
		Kind  string             `json:"kind"`
		Items []k8sNetworkPolicy `json:"items"`
	}
	if err := json.Unmarshal(raw, &list); err == nil && len(list.Items) > 0 {
		return list.Items, nil
	}

	var one k8sNetworkPolicy
	if err := json.Unmarshal(raw, &one); err != nil {
		return nil, fmt.Errorf("not a NetworkPolicy or a List: %w", err)
	}
	if one.Kind == "" && one.Metadata.Name == "" {
		return nil, fmt.Errorf("document has neither kind nor metadata.name")
	}
	return []k8sNetworkPolicy{one}, nil
}
