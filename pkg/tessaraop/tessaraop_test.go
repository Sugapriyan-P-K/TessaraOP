package tessaraop_test

import (
	"strings"
	"sync"
	"testing"

	"github.com/suga/tessaraop/pkg/tessaraop"
)

const bundleV1 = `{
  "version": 1,
  "policies": [{
    "id": "acme-grant",
    "tenant": "acme",
    "rules": [{
      "id": "allow-admin",
      "effect": "ALLOW",
      "obligations": ["audit_log"],
      "when": {"attr": "subject.role", "op": "eq", "values": ["admin"]}
    }]
  }]
}`

// bundleV2 grants the auditor role instead, so a reload is observable.
const bundleV2 = `{
  "version": 1,
  "policies": [{
    "id": "acme-grant",
    "tenant": "acme",
    "rules": [{
      "id": "allow-auditor",
      "effect": "ALLOW",
      "when": {"attr": "subject.role", "op": "eq", "values": ["auditor"]}
    }]
  }]
}`

func adminReq() tessaraop.Request {
	return tessaraop.NewRequest("acme", "").
		Str(tessaraop.AttrSubjectRole, "admin").Build()
}

func newPDP(t *testing.T, src string) *tessaraop.PDP {
	t.Helper()
	pdp, diags, err := tessaraop.ReadBundle(strings.NewReader(src), tessaraop.Config{})
	if err != nil {
		t.Fatalf("ReadBundle: %v\n%s", err, tessaraop.FormatDiagnostics(diags))
	}
	return pdp
}

func TestReadBundle_AndEvaluate(t *testing.T) {
	pdp := newPDP(t, bundleV1)

	d := pdp.Evaluate(adminReq())
	if !d.Allowed {
		t.Fatalf("expected admin to be allowed, got %s", d)
	}
	if d.MatchedRuleID != "allow-admin" {
		t.Errorf("credited rule = %q", d.MatchedRuleID)
	}
	if len(d.Obligations) != 1 || d.Obligations[0] != "audit_log" {
		t.Errorf("obligations = %v", d.Obligations)
	}

	viewer := tessaraop.NewRequest("acme", "").
		Str(tessaraop.AttrSubjectRole, "viewer").Build()
	if pdp.Evaluate(viewer).Allowed {
		t.Error("a viewer must not be allowed")
	}
}

func TestAllowed_Shorthand(t *testing.T) {
	pdp := newPDP(t, bundleV1)
	if !pdp.Allowed(adminReq()) {
		t.Error("expected admin to be allowed")
	}
}

// TestReload_IsObservableAndAtomic checks the property that lets policy ship on a
// different cadence from the binary.
func TestReload_IsObservableAndAtomic(t *testing.T) {
	pdp := newPDP(t, bundleV1)
	gen1 := pdp.Generation()

	if !pdp.Allowed(adminReq()) {
		t.Fatal("admin should be allowed before the reload")
	}

	if _, err := pdp.LoadBundle(strings.NewReader(bundleV2)); err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	if pdp.Generation() <= gen1 {
		t.Errorf("generation should advance on reload: %d then %d", gen1, pdp.Generation())
	}
	if pdp.Allowed(adminReq()) {
		t.Error("after the reload admin should no longer be granted")
	}
	auditor := tessaraop.NewRequest("acme", "").
		Str(tessaraop.AttrSubjectRole, "auditor").Build()
	if !pdp.Allowed(auditor) {
		t.Error("after the reload auditor should be granted")
	}
}

// TestReload_FailureKeepsThePreviousPolicySet is the property that turns a bad
// policy deploy into stale rules rather than an outage. An engine that emptied
// itself on a parse error would deny every request.
func TestReload_FailureKeepsThePreviousPolicySet(t *testing.T) {
	pdp := newPDP(t, bundleV1)
	before := pdp.Generation()

	bad := `{"version":1,"policies":[{"id":"p","tenant":"t","rules":[{"id":"r",
	  "effect":"ALLOW","when":{"attr":"subject.role","op":"gt","min":1}}]}]}`
	diags, err := pdp.LoadBundle(strings.NewReader(bad))
	if err == nil {
		t.Fatal("expected the bad bundle to be rejected")
	}
	if !tessaraop.HasErrors(diags) {
		t.Error("expected diagnostics explaining the rejection")
	}
	if pdp.Generation() != before {
		t.Errorf("a rejected reload must not advance the generation: %d then %d",
			before, pdp.Generation())
	}
	if !pdp.Allowed(adminReq()) {
		t.Error("the previous policy set must remain in effect after a failed reload")
	}
}

func TestReload_MalformedJSONKeepsPreviousSet(t *testing.T) {
	pdp := newPDP(t, bundleV1)
	if _, err := pdp.LoadBundle(strings.NewReader(`{not json`)); err == nil {
		t.Fatal("expected a parse error")
	}
	if !pdp.Allowed(adminReq()) {
		t.Error("malformed JSON must leave the previous set in place")
	}
}

func TestReload_EmptyPolicySetIsRejected(t *testing.T) {
	// An empty set denies everything. As a silent outcome of a mis-pathed file
	// that is an outage, so it must be an explicit error.
	pdp := newPDP(t, bundleV1)
	if err := pdp.Reload(nil); err == nil {
		t.Fatal("expected ErrNoPolicies")
	}
	if !pdp.Allowed(adminReq()) {
		t.Error("the previous set must survive a rejected empty reload")
	}
}

// TestReload_DoesNotAliasCallerSlice guards against a caller reusing or appending
// to the slice they passed in and mutating a live policy set underneath the
// engine.
func TestReload_DoesNotAliasCallerSlice(t *testing.T) {
	policies := []tessaraop.Policy{
		tessaraop.SimplePolicy("p", "acme", "", tessaraop.Allow, 0,
			[]tessaraop.Condition{{
				Attribute: tessaraop.AttrSubjectRole,
				Operator:  tessaraop.OpEquals,
				Values:    []string{"admin"},
			}}),
	}
	pdp, err := tessaraop.New(policies, tessaraop.Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !pdp.Allowed(adminReq()) {
		t.Fatal("expected admin to be allowed")
	}

	// Overwrite the caller's slice element entirely.
	policies[0] = tessaraop.SimplePolicy("p", "acme", "", tessaraop.Deny, 0, nil)

	if !pdp.Allowed(adminReq()) {
		t.Error("mutating the caller's slice must not change the installed policy set")
	}
}

// TestConcurrentEvaluateDuringReload is the concurrency claim under -race: a
// request in flight must see one complete policy set, never a mixture.
func TestConcurrentEvaluateDuringReload(t *testing.T) {
	pdp := newPDP(t, bundleV1)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// Whichever set is installed, the decision must be internally
				// consistent: allowed implies a credited rule and vice versa.
				d := pdp.Evaluate(adminReq())
				if d.Allowed != (d.MatchedRuleID != "") {
					t.Errorf("inconsistent decision during reload: %s", d)
					return
				}
			}
		}()
	}

	for i := 0; i < 30; i++ {
		src := bundleV1
		if i%2 == 1 {
			src = bundleV2
		}
		if _, err := pdp.LoadBundle(strings.NewReader(src)); err != nil {
			t.Errorf("reload %d: %v", i, err)
			break
		}
	}
	close(stop)
	wg.Wait()
}

func TestMetricsAndInfo(t *testing.T) {
	pdp, _, err := tessaraop.ReadBundle(strings.NewReader(bundleV1),
		tessaraop.Config{CacheSize: 256})
	if err != nil {
		t.Fatalf("ReadBundle: %v", err)
	}

	req := adminReq()
	pdp.Evaluate(req)
	pdp.Evaluate(req) // should hit the cache
	viewer := tessaraop.NewRequest("acme", "").
		Str(tessaraop.AttrSubjectRole, "viewer").Build()
	pdp.Evaluate(viewer)

	m := pdp.Metrics()
	if m.Evaluations != 3 {
		t.Errorf("evaluations = %d want 3", m.Evaluations)
	}
	if m.Allowed != 2 || m.Denied != 1 {
		t.Errorf("allowed/denied = %d/%d want 2/1", m.Allowed, m.Denied)
	}
	if m.CacheHits != 1 {
		t.Errorf("cache hits = %d want 1", m.CacheHits)
	}
	if m.Reloads != 1 {
		t.Errorf("reloads = %d want 1 (the initial load)", m.Reloads)
	}

	info := pdp.Info()
	if info.Policies != 1 || info.Rules != 1 {
		t.Errorf("info policies/rules = %d/%d want 1/1", info.Policies, info.Rules)
	}
	if !info.CacheEnabled {
		t.Error("cache should be reported as enabled")
	}
	if info.Algorithm != string(tessaraop.DenyOverrides) {
		t.Errorf("algorithm = %q, should default to deny-overrides", info.Algorithm)
	}
	if info.Generation == 0 {
		t.Error("generation should be non-zero after a load")
	}
}

func TestReachableRules(t *testing.T) {
	pdp := newPDP(t, bundleV1)
	if n := pdp.ReachableRules("acme", ""); n != 1 {
		t.Errorf("acme should reach 1 rule, got %d", n)
	}
	if n := pdp.ReachableRules("someone-else", ""); n != 0 {
		t.Errorf("an unrelated tenant should reach 0 rules, got %d", n)
	}
}

// --- RequestBuilder ---------------------------------------------------------

// TestRequestBuilder_ErrCatchesWrongMap covers the single most common integration
// mistake. A port supplied as a string is invisible to every numeric operator, so
// the rule guarding it silently never fires — there is no runtime symptom to
// notice, which is why the builder cross-checks against the registry.
func TestRequestBuilder_ErrCatchesWrongMap(t *testing.T) {
	b := tessaraop.NewRequest("acme", "").
		Str(tessaraop.AttrDestPort, "443") // registered numeric, supplied as string
	b.Build()

	err := b.Err()
	if err == nil {
		t.Fatal("expected an error for a numeric attribute supplied as a string")
	}
	if !strings.Contains(err.Error(), tessaraop.AttrDestPort) {
		t.Errorf("error should name the attribute, got %v", err)
	}

	// And the correct form is clean.
	ok := tessaraop.NewRequest("acme", "").Num(tessaraop.AttrDestPort, 443)
	ok.Build()
	if err := ok.Err(); err != nil {
		t.Errorf("correctly typed request reported: %v", err)
	}
}

func TestRequestBuilder_UnregisteredNamesAreAllowed(t *testing.T) {
	// Customers legitimately carry their own vocabulary; the builder must not
	// reject it.
	b := tessaraop.NewRequest("acme", "").
		Str("custom.internal_signal", "x").
		Num("custom.score", 5)
	b.Build()
	if err := b.Err(); err != nil {
		t.Errorf("unregistered attributes must be permitted, got %v", err)
	}
}

func TestRequestBuilder_IPString(t *testing.T) {
	b := tessaraop.NewRequest("acme", "").IPString(tessaraop.AttrSourceIP, "10.1.2.3")
	req := b.Build()
	if err := b.Err(); err != nil {
		t.Fatalf("Err: %v", err)
	}
	if !req.IPs[tessaraop.AttrSourceIP].IsValid() {
		t.Fatal("expected the address to be set")
	}

	// host:port is what net.Conn.RemoteAddr().String() yields, so it must work.
	withPort := tessaraop.NewRequest("acme", "").
		IPString(tessaraop.AttrSourceIP, "10.1.2.3:44444")
	r2 := withPort.Build()
	if err := withPort.Err(); err != nil {
		t.Errorf("host:port should parse, got %v", err)
	}
	if got := r2.IPs[tessaraop.AttrSourceIP].String(); got != "10.1.2.3" {
		t.Errorf("expected the port to be stripped, got %q", got)
	}

	// An unparsable address is dropped and reported, never guessed at: a zero
	// address would make a CIDR condition match a block it should not.
	bad := tessaraop.NewRequest("acme", "").IPString(tessaraop.AttrSourceIP, "not-an-ip")
	r3 := bad.Build()
	if _, ok := r3.IPs[tessaraop.AttrSourceIP]; ok {
		t.Error("an unparsable address must not be set")
	}
	if bad.Err() == nil {
		t.Error("an unparsable address must be reported")
	}
}

func TestRequestBuilder_BoolAndStrs(t *testing.T) {
	req := tessaraop.NewRequest("acme", "").
		Bool(tessaraop.AttrMFAVerified, true).
		Strs("subject.groups", "platform", "oncall").
		Build()

	if req.Attributes[tessaraop.AttrMFAVerified] != "true" {
		t.Errorf("bool = %q", req.Attributes[tessaraop.AttrMFAVerified])
	}
	if req.Attributes["subject.groups"] != "platform,oncall" {
		t.Errorf("groups = %q", req.Attributes["subject.groups"])
	}
}

// TestRequestBuilder_BuildDropsEmptyMaps matters for the decision cache: the same
// logical request must hash identically however it was built, and an empty map is
// not the same value as a nil one.
func TestRequestBuilder_BuildDropsEmptyMaps(t *testing.T) {
	req := tessaraop.NewRequest("acme", "billing").Build()
	if req.Attributes != nil || req.Numeric != nil || req.IPs != nil {
		t.Fatalf("empty maps should be dropped, got %+v", req)
	}
}

// --- Linting and export -----------------------------------------------------

func TestLintBundle(t *testing.T) {
	diags, err := tessaraop.LintBundle(strings.NewReader(bundleV1), tessaraop.LintOptions{})
	if err != nil {
		t.Fatalf("LintBundle: %v", err)
	}
	if tessaraop.HasErrors(diags) {
		t.Errorf("a good bundle should lint clean:\n%s", tessaraop.FormatDiagnostics(diags))
	}

	bad := `{"version":1,"policies":[{"id":"p","tenant":"t","rules":[{"id":"r",
	  "effect":"ALLOW","when":{"attr":"subject.role","op":"gt","min":1}}]}]}`
	diags, err = tessaraop.LintBundle(strings.NewReader(bad), tessaraop.LintOptions{})
	if err != nil {
		t.Fatalf("LintBundle: %v", err)
	}
	if !tessaraop.HasErrors(diags) {
		t.Error("expected the type mismatch to be an error")
	}
	if len(tessaraop.Errors(diags)) == 0 {
		t.Error("Errors should return the blocking diagnostics")
	}
}

func TestValidatePolicies(t *testing.T) {
	// The linter must be available to SDK callers who build policies in Go, not
	// only to bundle authors.
	policies := []tessaraop.Policy{
		tessaraop.SimplePolicy("p", "acme", "", tessaraop.Allow, 0,
			[]tessaraop.Condition{{
				Attribute: tessaraop.AttrSubjectRole,
				Operator:  tessaraop.OpGreaterThan, // numeric operator on a string attribute
				Min:       5,
			}}),
	}
	diags := tessaraop.ValidatePolicies(policies, tessaraop.LintOptions{})
	if !tessaraop.HasErrors(diags) {
		t.Fatalf("expected the type mismatch to be caught:\n%s",
			tessaraop.FormatDiagnostics(diags))
	}
}

func TestExportBundle_RoundTrips(t *testing.T) {
	pdp := newPDP(t, bundleV1)
	_ = pdp

	policies := []tessaraop.Policy{
		tessaraop.SimplePolicy("p", "acme", "billing", tessaraop.Allow, 7,
			[]tessaraop.Condition{{
				Attribute: tessaraop.AttrSubjectRole,
				Operator:  tessaraop.OpIn,
				Values:    []string{"admin", "auditor"},
			}}),
	}
	var out strings.Builder
	if err := tessaraop.ExportBundle(policies, &out); err != nil {
		t.Fatalf("ExportBundle: %v", err)
	}

	back, diags, err := tessaraop.ReadBundle(strings.NewReader(out.String()), tessaraop.Config{})
	if err != nil {
		t.Fatalf("reimport: %v\n%s", err, tessaraop.FormatDiagnostics(diags))
	}
	req := tessaraop.NewRequest("acme", "billing").
		Str(tessaraop.AttrSubjectRole, "auditor").Build()
	if !back.Allowed(req) {
		t.Error("an exported and reimported policy must behave the same")
	}
}

func TestFormatDiagnostics_ErrorsFirst(t *testing.T) {
	src := `{"version":1,"policies":[{"id":"p","tenant":"t","rules":[{"id":"r",
	  "effect":"ALLOW","when":{"attr":"subject.role","op":"gt","min":1}}]}]}`
	diags, err := tessaraop.LintBundle(strings.NewReader(src), tessaraop.LintOptions{})
	if err != nil {
		t.Fatalf("LintBundle: %v", err)
	}
	out := tessaraop.FormatDiagnostics(diags)
	if !strings.HasPrefix(out, "error:") {
		t.Errorf("errors should be listed first, got:\n%s", out)
	}
	if tessaraop.FormatDiagnostics(nil) != "no findings" {
		t.Error("empty diagnostics should render a readable message")
	}
}

// --- Registry ---------------------------------------------------------------

func TestAttributesAreExposed(t *testing.T) {
	if len(tessaraop.Attributes()) == 0 {
		t.Fatal("the registry should be reachable from the public API")
	}
	a, ok := tessaraop.LookupAttribute(tessaraop.AttrSourceIP)
	if !ok {
		t.Fatalf("%s should resolve", tessaraop.AttrSourceIP)
	}
	if !a.Accepts(tessaraop.OpCIDR) {
		t.Error("source ip should accept the cidr operator")
	}
	if a.Accepts(tessaraop.OpEquals) {
		t.Error("an ip attribute should not accept string equality")
	}
}

func TestAttributeNameHelpers(t *testing.T) {
	cases := map[string]string{
		tessaraop.Header("X-Real-IP"): "http.header.x-real-ip",
		tessaraop.QueryParam("id"):    "http.query.id",
		tessaraop.Cookie("locale"):    "http.cookie.locale",
		tessaraop.Claim("tenant"):     "subject.claim.tenant",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("got %q want %q", got, want)
		}
		if _, ok := tessaraop.LookupAttribute(got); !ok {
			t.Errorf("%q should resolve through its namespace", got)
		}
	}
}

// TestZeroValuePDPFailsClosed covers misuse: a caller who constructs a PDP
// directly instead of through New. Denying is the only acceptable answer; a panic
// in a request path is not.
func TestZeroValuePDPFailsClosed(t *testing.T) {
	var pdp tessaraop.PDP
	d := pdp.Evaluate(adminReq())
	if d.Allowed {
		t.Fatal("a PDP with no policy set must deny")
	}
	if d.Effect != tessaraop.Deny {
		t.Errorf("effect = %q want DENY", d.Effect)
	}
}
