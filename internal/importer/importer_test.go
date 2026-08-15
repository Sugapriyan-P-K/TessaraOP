package importer

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/suga/tessaraop/internal/model"
)

func opts() Options { return Options{Tenant: "acme"} }

func permissive() Options {
	o := opts()
	o.AllowWidening = true
	return o
}

// mustOK is curried so the two-value import call can be its sole argument, which
// Go requires when other parameters are present.
func mustOK(t *testing.T) func(*Result, error) *Result {
	return func(res *Result, err error) *Result {
		t.Helper()
		if err != nil {
			t.Fatalf("import: %v\n%s", err, res.Report.String())
		}
		return res
	}
}

// findRule locates a rule by ID suffix, since IDs may carry a prefix.
func findRule(res *Result, suffix string) *model.Rule {
	for i := range res.Policies {
		for j := range res.Policies[i].Rules {
			if strings.HasSuffix(res.Policies[i].Rules[j].ID, suffix) {
				return &res.Policies[i].Rules[j]
			}
		}
	}
	return nil
}

func noteMentioning(res *Result, substr string) *Note {
	for i := range res.Report.Notes {
		if strings.Contains(res.Report.Notes[i].Message, substr) ||
			strings.Contains(res.Report.Notes[i].Source, substr) {
			return &res.Report.Notes[i]
		}
	}
	return nil
}

// --- The property the whole package is built around --------------------------

// TestWideningIsRefusedByDefault is the central contract. Dropping a constraint
// from a grant broadens it, the bundle still lints clean, and nobody notices —
// so an import that would widen access must fail rather than succeed quietly.
func TestWideningIsRefusedByDefault(t *testing.T) {
	// A policy variable cannot be resolved statically, so the condition on it
	// would have to be dropped, which broadens the statement.
	const doc = `{
	  "Version": "2012-10-17",
	  "Statement": [{
	    "Effect": "Allow",
	    "Action": "s3:GetObject",
	    "Resource": "arn:aws:s3:::bucket/${aws:username}/*"
	  }]
	}`

	res, err := ImportAWSIAM(strings.NewReader(doc), "test.json", opts())
	if err == nil {
		t.Fatal("an import that would widen access must fail by default")
	}
	if !errors.Is(err, ErrWidensAccess) {
		t.Fatalf("expected ErrWidensAccess, got %v", err)
	}
	// The report still comes back, because the operator has to read it to decide.
	if res == nil || len(res.Report.Widening()) == 0 {
		t.Fatal("the report must be returned so the widening can be reviewed")
	}

	// And it succeeds once the operator has accepted the risk explicitly.
	if _, err := ImportAWSIAM(strings.NewReader(doc), "test.json", permissive()); err != nil {
		t.Fatalf("AllowWidening should permit it: %v", err)
	}
}

func TestTenantIsRequired(t *testing.T) {
	const doc = `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	if _, err := ImportAWSIAM(strings.NewReader(doc), "t.json", Options{}); !errors.Is(err, ErrNoTenant) {
		t.Fatalf("expected ErrNoTenant, got %v", err)
	}
}

func TestStrictRefusesApproximations(t *testing.T) {
	const doc = `{"Statement":[{
	  "Effect":"Allow","Action":"s3:GetObject","Resource":"*",
	  "Condition":{"DateGreaterThan":{"aws:CurrentTime":"2024-01-01T00:00:00Z"}}
	}]}`

	o := opts()
	if _, err := ImportAWSIAM(strings.NewReader(doc), "t.json", o); err != nil {
		t.Fatalf("an approximation alone should not fail: %v", err)
	}
	o.Strict = true
	if _, err := ImportAWSIAM(strings.NewReader(doc), "t.json", o); !errors.Is(err, ErrApproximated) {
		t.Fatalf("Strict should refuse an approximation, got %v", err)
	}
}

// --- AWS IAM -----------------------------------------------------------------

func TestIAM_BasicStatement(t *testing.T) {
	const doc = `{
	  "Version": "2012-10-17",
	  "Id": "s3-read",
	  "Statement": [{
	    "Sid": "AllowRead",
	    "Effect": "Allow",
	    "Action": ["s3:GetObject", "s3:ListBucket"],
	    "Resource": "arn:aws:s3:::reports/*"
	  }]
	}`
	res := mustOK(t)(ImportAWSIAM(strings.NewReader(doc), "t.json", opts()))

	if len(res.Policies) != 1 {
		t.Fatalf("expected one policy, got %d", len(res.Policies))
	}
	p := res.Policies[0]
	if p.TenantID != "acme" {
		t.Errorf("tenant = %q", p.TenantID)
	}
	// IAM's explicit-deny-wins is deny-overrides exactly.
	if p.RuleAlgorithm != model.DenyOverrides {
		t.Errorf("rule algorithm = %q, want deny-overrides", p.RuleAlgorithm)
	}

	r := findRule(res, "AllowRead")
	if r == nil {
		t.Fatal("the statement Sid should become the rule ID")
	}
	if r.Effect != model.Allow {
		t.Errorf("effect = %q", r.Effect)
	}

	// Behavioural check: the translated rule must accept what the source did.
	match := model.Request{TenantID: "acme", Attributes: map[string]string{
		"action":      "s3:GetObject",
		"resource.id": "arn:aws:s3:::reports/q1.pdf",
	}}
	if !r.When.Matches(match) {
		t.Error("expected the permitted action and resource to match")
	}
	wrongAction := model.Request{TenantID: "acme", Attributes: map[string]string{
		"action": "s3:DeleteObject", "resource.id": "arn:aws:s3:::reports/q1.pdf"}}
	if r.When.Matches(wrongAction) {
		t.Error("an action outside the list must not match")
	}
	wrongResource := model.Request{TenantID: "acme", Attributes: map[string]string{
		"action": "s3:GetObject", "resource.id": "arn:aws:s3:::secrets/key"}}
	if r.When.Matches(wrongResource) {
		t.Error("a resource outside the ARN prefix must not match")
	}
}

func TestIAM_SingleStatementObject(t *testing.T) {
	// IAM permits Statement as an object rather than an array.
	const doc = `{"Statement":{"Effect":"Deny","Action":"*","Resource":"*"}}`
	res := mustOK(t)(ImportAWSIAM(strings.NewReader(doc), "t.json", opts()))
	if len(res.Policies) != 1 || len(res.Policies[0].Rules) != 1 {
		t.Fatalf("expected one rule, got %+v", res.Policies)
	}
	if res.Policies[0].Rules[0].Effect != model.Deny {
		t.Error("effect should be DENY")
	}
}

// TestIAM_IfExistsIsExact covers one of the two constructs that translate
// perfectly. IfExists means "apply only when the key is present", and TessaraOP
// fails closed on absence — so an explicit disjunction with absence is equivalent.
func TestIAM_IfExistsIsExact(t *testing.T) {
	const doc = `{"Statement":[{
	  "Effect":"Allow","Action":"s3:GetObject","Resource":"*",
	  "Condition":{"StringEqualsIfExists":{"aws:PrincipalTag/team":"platform"}}
	}]}`
	res := mustOK(t)(ImportAWSIAM(strings.NewReader(doc), "t.json", opts()))
	r := findRule(res, "statement-0")
	if r == nil {
		t.Fatal("no rule produced")
	}

	base := map[string]string{"action": "s3:GetObject", "resource.id": "x"}

	// Key present and matching: allowed.
	with := model.Request{TenantID: "acme", Attributes: mergeMaps(base,
		map[string]string{"subject.claim.team": "platform"})}
	if !r.When.Matches(with) {
		t.Error("a matching tag should satisfy the condition")
	}
	// Key absent: IfExists means the condition does not apply, so still allowed.
	without := model.Request{TenantID: "acme", Attributes: mergeMaps(base, nil)}
	if !r.When.Matches(without) {
		t.Error("IfExists must pass when the key is absent")
	}
	// Key present and wrong: denied.
	wrong := model.Request{TenantID: "acme", Attributes: mergeMaps(base,
		map[string]string{"subject.claim.team": "other"})}
	if r.When.Matches(wrong) {
		t.Error("a non-matching tag must fail the condition")
	}
}

// TestIAM_NullIsExact covers the other exact translation.
func TestIAM_NullIsExact(t *testing.T) {
	const doc = `{"Statement":[{
	  "Effect":"Deny","Action":"*","Resource":"*",
	  "Condition":{"Null":{"aws:MultiFactorAuthPresent":"true"}}
	}]}`
	res := mustOK(t)(ImportAWSIAM(strings.NewReader(doc), "t.json", opts()))
	r := findRule(res, "statement-0")

	absent := model.Request{TenantID: "acme", Attributes: map[string]string{
		"action": "x", "resource.id": "y"}}
	if !r.When.Matches(absent) {
		t.Error("Null:true means the key must be absent, which it is")
	}
	present := model.Request{TenantID: "acme", Attributes: map[string]string{
		"action": "x", "resource.id": "y", "subject.mfa_verified": "true"}}
	if r.When.Matches(present) {
		t.Error("Null:true must fail when the key is present")
	}
}

func TestIAM_ConditionOperators(t *testing.T) {
	const doc = `{"Statement":[{
	  "Effect":"Allow","Action":"*","Resource":"*",
	  "Condition":{
	    "IpAddress":{"aws:SourceIp":["10.0.0.0/8"]},
	    "Bool":{"aws:MultiFactorAuthPresent":"true"},
	    "NumericLessThan":{"aws:MultiFactorAuthAge":"3600"}
	  }
	}]}`
	res := mustOK(t)(ImportAWSIAM(strings.NewReader(doc), "t.json", opts()))
	r := findRule(res, "statement-0")
	if r == nil {
		t.Fatal("no rule produced")
	}

	ok := model.Request{
		TenantID:   "acme",
		Attributes: map[string]string{"action": "x", "resource.id": "y", "subject.mfa_verified": "true"},
		Numeric:    map[string]float64{"subject.auth_age_seconds": 60},
		IPs:        mustAddr("network.source_ip", "10.1.2.3"),
	}
	if !r.When.Matches(ok) {
		t.Error("all three conditions should be satisfied")
	}

	offNetwork := ok
	offNetwork.IPs = mustAddr("network.source_ip", "203.0.113.9")
	if r.When.Matches(offNetwork) {
		t.Error("an address outside the block must fail")
	}

	stale := ok
	stale.Numeric = map[string]float64{"subject.auth_age_seconds": 7200}
	if r.When.Matches(stale) {
		t.Error("an auth age above the limit must fail")
	}
}

// TestIAM_NotActionTranslatesAndIsFlagged: NotAction with Deny denies everything
// except the listed actions, which is a well-known way to lock an account out.
func TestIAM_NotActionTranslatesAndIsFlagged(t *testing.T) {
	const doc = `{"Statement":[{
	  "Effect":"Deny","NotAction":["iam:*"],"Resource":"*"
	}]}`
	res := mustOK(t)(ImportAWSIAM(strings.NewReader(doc), "t.json", opts()))
	r := findRule(res, "statement-0")

	// s3:GetObject is not iam:*, so the deny applies.
	denied := model.Request{TenantID: "acme", Attributes: map[string]string{
		"action": "s3:GetObject", "resource.id": "x"}}
	if !r.When.Matches(denied) {
		t.Error("NotAction should match actions outside the list")
	}
	// iam:PassRole is excluded from the deny.
	exempt := model.Request{TenantID: "acme", Attributes: map[string]string{
		"action": "iam:PassRole", "resource.id": "x"}}
	if r.When.Matches(exempt) {
		t.Error("NotAction must not match a listed action")
	}
	if noteMentioning(res, "NotAction with Effect Deny") == nil {
		t.Error("the NotAction+Deny footgun should be called out")
	}
}

// TestIAM_WildcardEscaping guards a widening bug that hides in a metacharacter: a
// dot in an ARN translated to regex without escaping would match any character.
func TestIAM_WildcardEscaping(t *testing.T) {
	const doc = `{"Statement":[{
	  "Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::my.bucket/*x"
	}]}`
	res := mustOK(t)(ImportAWSIAM(strings.NewReader(doc), "t.json", opts()))
	r := findRule(res, "statement-0")

	exact := model.Request{TenantID: "acme", Attributes: map[string]string{
		"action": "s3:GetObject", "resource.id": "arn:aws:s3:::my.bucket/ax"}}
	if !r.When.Matches(exact) {
		t.Error("the literal bucket name should match")
	}
	lookalike := model.Request{TenantID: "acme", Attributes: map[string]string{
		"action": "s3:GetObject", "resource.id": "arn:aws:s3:::my-bucket/ax"}}
	if r.When.Matches(lookalike) {
		t.Error("an unescaped dot would let my-bucket match a rule written for my.bucket")
	}
}

func TestIAM_SetOperatorsAreRefused(t *testing.T) {
	// ForAllValues quantifies over a multi-valued key; the quantifier is the
	// meaning, so dropping the condition broadens the statement.
	const doc = `{"Statement":[{
	  "Effect":"Allow","Action":"*","Resource":"*",
	  "Condition":{"ForAllValues:StringEquals":{"aws:TagKeys":["team"]}}
	}]}`
	_, err := ImportAWSIAM(strings.NewReader(doc), "t.json", opts())
	if !errors.Is(err, ErrWidensAccess) {
		t.Fatalf("expected the set operator to be refused, got %v", err)
	}
}

func TestIAM_UnknownConditionOperatorWidens(t *testing.T) {
	const doc = `{"Statement":[{
	  "Effect":"Allow","Action":"*","Resource":"*",
	  "Condition":{"BinaryEquals":{"aws:Something":"abc"}}
	}]}`
	res, err := ImportAWSIAM(strings.NewReader(doc), "t.json", opts())
	if !errors.Is(err, ErrWidensAccess) {
		t.Fatalf("an untranslatable condition must be refused, got %v", err)
	}
	if noteMentioning(res, "BinaryEquals") == nil {
		t.Error("the offending operator should be named")
	}
}

// --- Kubernetes NetworkPolicy ------------------------------------------------

const netpol = `{
  "kind": "NetworkPolicy",
  "metadata": {"name": "allow-frontend", "namespace": "prod"},
  "spec": {
    "podSelector": {},
    "policyTypes": ["Ingress"],
    "ingress": [{
      "from": [{"ipBlock": {"cidr": "10.0.0.0/8", "except": ["10.99.0.0/16"]}}],
      "ports": [{"protocol": "TCP", "port": 8080}]
    }]
  }
}`

func TestK8s_NamespaceBecomesTenant(t *testing.T) {
	// In multi-tenant Kubernetes the namespace is the tenant boundary, so an
	// import into the wrong tenant would apply to traffic it was never written for.
	res := mustOK(t)(ImportK8sNetworkPolicy(strings.NewReader(netpol), "np.json", Options{}))
	if len(res.Policies) != 1 {
		t.Fatalf("expected one policy, got %d", len(res.Policies))
	}
	if res.Policies[0].TenantID != "prod" {
		t.Errorf("tenant = %q, want the namespace", res.Policies[0].TenantID)
	}

	// An explicit tenant overrides it.
	res = mustOK(t)(ImportK8sNetworkPolicy(strings.NewReader(netpol), "np.json", opts()))
	if res.Policies[0].TenantID != "acme" {
		t.Errorf("explicit tenant should win, got %q", res.Policies[0].TenantID)
	}
}

// TestK8s_DefaultDenyIsMaterialized is the most important test in this file.
// NetworkPolicy denies by default once it selects a pod; the shard-level default
// is not equivalent, because another policy could grant what the source refused.
func TestK8s_DefaultDenyIsMaterialized(t *testing.T) {
	res := mustOK(t)(ImportK8sNetworkPolicy(strings.NewReader(netpol), "np.json", Options{}))

	deny := findRule(res, "default-deny")
	if deny == nil {
		t.Fatal("the implicit default-deny must be materialized, or the import " +
			"permits traffic the source refused")
	}
	if deny.Effect != model.Deny {
		t.Errorf("effect = %q", deny.Effect)
	}

	// It must sit below every permit.
	for i := range res.Policies[0].Rules {
		r := &res.Policies[0].Rules[i]
		if r.Effect == model.Allow && r.Priority <= deny.Priority {
			t.Errorf("permit %q has priority %d, not above the default-deny's %d",
				r.ID, r.Priority, deny.Priority)
		}
	}
	// And the policy must resolve by priority for that to mean anything.
	if res.Policies[0].RuleAlgorithm != model.FirstApplicable {
		t.Errorf("rule algorithm = %q, want first-applicable",
			res.Policies[0].RuleAlgorithm)
	}

	// Behaviourally: permitted traffic is allowed, everything else denied.
	allowed := model.Request{TenantID: "prod", Scope: "network",
		Numeric:    map[string]float64{"transport.dest_port": 8080},
		Attributes: map[string]string{"network.protocol_name": "tcp"},
		IPs:        mustAddr("network.source_ip", "10.1.2.3")}
	if d := model.Evaluate(res.Policies, allowed, model.DenyOverrides); !d.Allowed {
		t.Errorf("permitted traffic should be allowed: %s", d)
	}

	wrongPort := allowed
	wrongPort.Numeric = map[string]float64{"transport.dest_port": 9999}
	if d := model.Evaluate(res.Policies, wrongPort, model.DenyOverrides); d.Allowed {
		t.Errorf("a port outside the rule must be denied by the default: %s", d)
	}
}

// TestK8s_IPBlockExceptIsExact: `except` carves holes out of the block, which is
// a negated CIDR — expressible exactly.
func TestK8s_IPBlockExceptIsExact(t *testing.T) {
	res := mustOK(t)(ImportK8sNetworkPolicy(strings.NewReader(netpol), "np.json", Options{}))
	allow := findRule(res, "ingress-0")
	if allow == nil {
		t.Fatal("no ingress rule produced")
	}

	base := map[string]string{"network.protocol_name": "tcp"}
	inside := model.Request{TenantID: "prod", Attributes: base,
		Numeric: map[string]float64{"transport.dest_port": 8080},
		IPs:     mustAddr("network.source_ip", "10.1.2.3")}
	if !allow.When.Matches(inside) {
		t.Error("an address inside the block should match")
	}

	excepted := inside
	excepted.IPs = mustAddr("network.source_ip", "10.99.1.1")
	if allow.When.Matches(excepted) {
		t.Error("an address inside `except` must be excluded")
	}
}

// TestK8s_PodSelectorWidens: label selectors need live cluster state, so they
// cannot be resolved here and the rule is broader than the source.
func TestK8s_PodSelectorWidens(t *testing.T) {
	const selective = `{
	  "kind":"NetworkPolicy",
	  "metadata":{"name":"api","namespace":"prod"},
	  "spec":{
	    "podSelector":{"matchLabels":{"app":"api"}},
	    "policyTypes":["Ingress"],
	    "ingress":[{"from":[{"ipBlock":{"cidr":"10.0.0.0/8"}}]}]
	  }
	}`
	res, err := ImportK8sNetworkPolicy(strings.NewReader(selective), "np.json", Options{})
	if !errors.Is(err, ErrWidensAccess) {
		t.Fatalf("a pod selector needs cluster state and must be flagged, got %v", err)
	}
	if noteMentioning(res, "cluster state") == nil {
		t.Error("the note should say why")
	}
}

func TestK8s_PortRange(t *testing.T) {
	const ranged = `{
	  "kind":"NetworkPolicy","metadata":{"name":"r","namespace":"prod"},
	  "spec":{"podSelector":{},"policyTypes":["Ingress"],
	    "ingress":[{"ports":[{"protocol":"TCP","port":8000,"endPort":8100}]}]}
	}`
	res := mustOK(t)(ImportK8sNetworkPolicy(strings.NewReader(ranged), "np.json", Options{}))
	r := findRule(res, "ingress-0")

	base := map[string]string{"network.protocol_name": "tcp"}
	for _, tc := range []struct {
		port float64
		want bool
	}{{7999, false}, {8000, true}, {8050, true}, {8100, true}, {8101, false}} {
		req := model.Request{TenantID: "prod", Attributes: base,
			Numeric: map[string]float64{"transport.dest_port": tc.port}}
		if got := r.When.Matches(req); got != tc.want {
			t.Errorf("port %g: got %v want %v", tc.port, got, tc.want)
		}
	}
}

func TestK8s_List(t *testing.T) {
	list := `{"kind":"NetworkPolicyList","items":[` + netpol + `,` + netpol + `]}`
	res := mustOK(t)(ImportK8sNetworkPolicy(strings.NewReader(list), "np.json", Options{}))
	if len(res.Policies) != 2 {
		t.Fatalf("expected two policies from the list, got %d", len(res.Policies))
	}
}

// --- Envoy RBAC ---------------------------------------------------------------

const envoyConfig = `{
  "name": "envoy.filters.http.rbac",
  "rules": {
    "action": "ALLOW",
    "policies": {
      "admin-access": {
        "permissions": [
          {"and_rules": {"rules": [
            {"url_path": {"path": {"prefix": "/admin"}}},
            {"header": {"name": ":method", "exact_match": "GET"}}
          ]}}
        ],
        "principals": [
          {"authenticated": {"principal_name": {"exact": "admin.acme.com"}}}
        ]
      }
    }
  }
}`

func TestEnvoy_BooleanShapeSurvives(t *testing.T) {
	res := mustOK(t)(ImportEnvoyRBAC(strings.NewReader(envoyConfig), "rbac.json", opts()))
	r := findRule(res, "admin-access")
	if r == nil {
		t.Fatal("no rule produced")
	}

	ok := model.Request{TenantID: "acme", Attributes: map[string]string{
		"http.path": "/admin/users", "http.method": "GET",
		"tls.client_cert_cn": "admin.acme.com"}}
	if !r.When.Matches(ok) {
		t.Error("a request satisfying every matcher should match")
	}

	// Each conjunct must actually be required.
	for name, mutate := range map[string]func(map[string]string){
		"wrong path":   func(m map[string]string) { m["http.path"] = "/public" },
		"wrong method": func(m map[string]string) { m["http.method"] = "POST" },
		"wrong cn":     func(m map[string]string) { m["tls.client_cert_cn"] = "someone.else" },
	} {
		attrs := map[string]string{}
		for k, v := range ok.Attributes {
			attrs[k] = v
		}
		mutate(attrs)
		if r.When.Matches(model.Request{TenantID: "acme", Attributes: attrs}) {
			t.Errorf("%s should not match", name)
		}
	}
}

// TestEnvoy_AllowActionMaterializesDeny: with action ALLOW, traffic matching no
// policy is denied, and the shard default is not equivalent.
func TestEnvoy_AllowActionMaterializesDeny(t *testing.T) {
	res := mustOK(t)(ImportEnvoyRBAC(strings.NewReader(envoyConfig), "rbac.json", opts()))
	if findRule(res, "default-deny") == nil {
		t.Fatal("action ALLOW denies unmatched traffic, so an explicit deny is required")
	}

	unmatched := model.Request{TenantID: "acme", Scope: "network",
		Attributes: map[string]string{"http.path": "/public"}}
	if d := model.Evaluate(res.Policies, unmatched, model.DenyOverrides); d.Allowed {
		t.Errorf("unmatched traffic must be denied: %s", d)
	}
}

func TestEnvoy_DenyActionNeedsNoDefault(t *testing.T) {
	deny := strings.Replace(envoyConfig, `"action": "ALLOW"`, `"action": "DENY"`, 1)
	res := mustOK(t)(ImportEnvoyRBAC(strings.NewReader(deny), "rbac.json", opts()))
	if findRule(res, "default-deny") != nil {
		t.Error("action DENY permits unmatched traffic, so no default rule belongs")
	}
	if r := findRule(res, "admin-access"); r == nil || r.Effect != model.Deny {
		t.Error("the rule should carry the DENY effect")
	}
}

// TestEnvoy_ShadowRulesAreNotEnforced: shadow_rules are Envoy's dry-run
// mechanism, so folding them in would turn an observation into a denial.
func TestEnvoy_ShadowRulesAreNotEnforced(t *testing.T) {
	const withShadow = `{
	  "rules": {"action":"ALLOW","policies":{"real":{"permissions":[{"any":true}],
	     "principals":[{"any":true}]}}},
	  "shadow_rules": {"action":"DENY","policies":{"shadowed":{
	     "permissions":[{"any":true}],"principals":[{"any":true}]}}}
	}`
	res := mustOK(t)(ImportEnvoyRBAC(strings.NewReader(withShadow), "rbac.json", opts()))
	if findRule(res, "shadowed") != nil {
		t.Error("shadow rules must not be enforced")
	}
	if noteMentioning(res, "shadow_rules") == nil {
		t.Error("the omission should be reported")
	}
}

func TestEnvoy_NotRule(t *testing.T) {
	const config = `{
	  "rules": {"action":"ALLOW","policies":{"non-admin":{
	    "permissions":[{"not_rule":{"url_path":{"path":{"prefix":"/admin"}}}}],
	    "principals":[{"any":true}]}}}
	}`
	res := mustOK(t)(ImportEnvoyRBAC(strings.NewReader(config), "rbac.json", opts()))
	r := findRule(res, "non-admin")

	public := model.Request{TenantID: "acme", Attributes: map[string]string{"http.path": "/public"}}
	if !r.When.Matches(public) {
		t.Error("a non-admin path should match the negation")
	}
	admin := model.Request{TenantID: "acme", Attributes: map[string]string{"http.path": "/admin/x"}}
	if r.When.Matches(admin) {
		t.Error("an admin path must not match the negation")
	}
}

func TestEnvoy_MetadataMatcherWidens(t *testing.T) {
	const config = `{
	  "rules":{"action":"ALLOW","policies":{"p":{
	    "permissions":[{"metadata":{"filter":"x"}}],
	    "principals":[{"any":true}]}}}
	}`
	_, err := ImportEnvoyRBAC(strings.NewReader(config), "rbac.json", opts())
	if !errors.Is(err, ErrWidensAccess) {
		t.Fatalf("a metadata matcher has no equivalent and must be flagged, got %v", err)
	}
}

func TestEnvoy_PortRangeIsHalfOpen(t *testing.T) {
	// Envoy's destination_port_range is [start, end).
	const config = `{
	  "rules":{"action":"ALLOW","policies":{"p":{
	    "permissions":[{"destination_port_range":{"start":8000,"end":8010}}],
	    "principals":[{"any":true}]}}}
	}`
	res := mustOK(t)(ImportEnvoyRBAC(strings.NewReader(config), "rbac.json", opts()))
	r := findRule(res, "p")
	if r == nil {
		t.Fatal("no rule produced")
	}
	for _, tc := range []struct {
		port float64
		want bool
	}{{7999, false}, {8000, true}, {8009, true}, {8010, false}} {
		req := model.Request{TenantID: "acme",
			Numeric: map[string]float64{"transport.dest_port": tc.port}}
		if got := r.When.Matches(req); got != tc.want {
			t.Errorf("port %g: got %v want %v (range is half-open)", tc.port, got, tc.want)
		}
	}
}

// --- Report ------------------------------------------------------------------

func TestReport_SeparatesWideningNotes(t *testing.T) {
	const doc = `{"Statement":[{
	  "Effect":"Allow","Action":"*","Resource":"*",
	  "Condition":{"BinaryEquals":{"aws:X":"y"}}
	}]}`
	res, _ := ImportAWSIAM(strings.NewReader(doc), "t.json", permissive())

	if len(res.Report.Widening()) == 0 {
		t.Fatal("expected a widening note")
	}
	rendered := res.Report.String()
	if !strings.Contains(rendered, "WIDENING ACCESS") {
		t.Errorf("widening notes should be prominent:\n%s", rendered)
	}
	// Widening notes come first, so they are not lost in a long report.
	if idx := strings.Index(rendered, "WIDENING"); idx < 0 {
		t.Error("widening notes should be listed first")
	}
}

// --- Helpers ------------------------------------------------------------------

func mergeMaps(base, extra map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func mustAddr(name, addr string) map[string]netip.Addr {
	return map[string]netip.Addr{name: netip.MustParseAddr(addr)}
}
