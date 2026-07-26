package pdpserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/suga/tessaraop/pkg/tessaraop"
)

// The test bundle exercises one rule per surface the handlers touch: a role
// check, a source-address check, a numeric port check, and a global deny.
const testBundle = `{
  "version": 1,
  "policies": [
    {
      "id": "global-baseline",
      "rules": [{
        "id": "block-listed",
        "effect": "DENY",
        "when": {"attr": "network.source_ip", "op": "cidr", "prefixes": ["203.0.113.0/24"]}
      }]
    },
    {
      "id": "acme-grant",
      "tenant": "acme",
      "rules": [{
        "id": "allow-admin-read",
        "effect": "ALLOW",
        "obligations": ["audit_log"],
        "when": {"all": [
          {"attr": "subject.role", "op": "eq", "values": ["admin"]},
          {"attr": "action", "op": "in", "values": ["read", "write"]}
        ]}
      }]
    },
    {
      "id": "acme-ports",
      "tenant": "acme",
      "scope": "network",
      "rules": [{
        "id": "allow-https",
        "effect": "ALLOW",
        "when": {"attr": "transport.dest_port", "op": "num_in", "numbers": [443, 8443]}
      }]
    }
  ]
}`

func newServer(t *testing.T, cfg Config) *Server {
	t.Helper()
	if cfg.PDP == nil {
		pdp, diags, err := tessaraop.ReadBundle(strings.NewReader(testBundle), tessaraop.Config{})
		if err != nil {
			t.Fatalf("bundle: %v\n%s", err, tessaraop.FormatDiagnostics(diags))
		}
		cfg.PDP = pdp
	}
	srv, _, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv
}

func do(t *testing.T, srv *Server, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	return w
}

func postJSON(t *testing.T, srv *Server, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return do(t, srv, r)
}

func TestNew_RequiresPDP(t *testing.T) {
	if _, _, err := New(Config{}); err == nil {
		t.Fatal("expected ErrNoPDP")
	}
}

// TestNew_WarnsAboutFootguns checks that the two dangerous defaults are surfaced
// at startup rather than discovered in an incident.
func TestNew_WarnsAboutFootguns(t *testing.T) {
	pdp, _, err := tessaraop.ReadBundle(strings.NewReader(testBundle), tessaraop.Config{})
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	_, warnings, err := New(Config{PDP: pdp, BundlePath: "x.json"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	joined := strings.Join(warnings, "\n")
	if !strings.Contains(joined, "/v1/reload is unauthenticated") {
		t.Errorf("expected a reload-auth warning, got:\n%s", joined)
	}
	if !strings.Contains(joined, "TrustedProxyHops is 0") {
		t.Errorf("expected a forwarded-header warning, got:\n%s", joined)
	}
}

// --- Native JSON API --------------------------------------------------------

func TestDecision_Allow(t *testing.T) {
	srv := newServer(t, Config{})
	w := postJSON(t, srv, "/v1/decision", `{
	  "tenant": "acme",
	  "attributes": {"subject.role": "admin", "action": "read"}
	}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", w.Code, w.Body)
	}

	var got DecisionResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !got.Allowed || got.Effect != "ALLOW" {
		t.Fatalf("expected allow, got %+v", got)
	}
	if got.RuleID != "allow-admin-read" {
		t.Errorf("rule = %q", got.RuleID)
	}
	if len(got.Obligations) != 1 || got.Obligations[0] != "audit_log" {
		t.Errorf("obligations = %v", got.Obligations)
	}
	if got.Generation == 0 {
		t.Error("generation should be reported so an audit record can be tied to a policy set")
	}
}

func TestDecision_GlobalDenyWins(t *testing.T) {
	srv := newServer(t, Config{})
	w := postJSON(t, srv, "/v1/decision", `{
	  "tenant": "acme",
	  "attributes": {"subject.role": "admin", "action": "read"},
	  "ips": {"network.source_ip": "203.0.113.9"}
	}`)
	var got DecisionResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Allowed {
		t.Fatalf("a blocklisted source must be denied, got %+v", got)
	}
	if got.PolicyID != "global-baseline" {
		t.Errorf("expected the global policy to be credited, got %q", got.PolicyID)
	}
}

func TestDecision_NumericAttribute(t *testing.T) {
	srv := newServer(t, Config{})
	w := postJSON(t, srv, "/v1/decision", `{
	  "tenant": "acme", "scope": "network",
	  "numeric": {"transport.dest_port": 443}
	}`)
	var got DecisionResponse
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if !got.Allowed {
		t.Fatalf("port 443 should be allowed, got %+v", got)
	}
}

// TestDecision_WrongMapIsWarned surfaces the mistake rather than letting a rule
// silently never fire.
func TestDecision_WrongMapIsWarned(t *testing.T) {
	srv := newServer(t, Config{})
	w := postJSON(t, srv, "/v1/decision", `{
	  "tenant": "acme", "scope": "network",
	  "attributes": {"transport.dest_port": "443"}
	}`)
	var got DecisionResponse
	_ = json.Unmarshal(w.Body.Bytes(), &got)

	if got.Allowed {
		t.Error("a numeric attribute sent as a string cannot match a numeric operator")
	}
	if len(got.Warnings) == 0 {
		t.Fatal("expected a warning about the wrong map")
	}
	if !strings.Contains(strings.Join(got.Warnings, " "), "transport.dest_port") {
		t.Errorf("warning should name the attribute: %v", got.Warnings)
	}
}

func TestDecision_BadIPIsWarned(t *testing.T) {
	srv := newServer(t, Config{})
	w := postJSON(t, srv, "/v1/decision",
		`{"tenant":"acme","ips":{"network.source_ip":"not-an-ip"}}`)
	var got DecisionResponse
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if len(got.Warnings) == 0 {
		t.Fatal("expected a warning for an unparsable address")
	}
}

func TestDecision_DefaultTenant(t *testing.T) {
	srv := newServer(t, Config{DefaultTenant: "acme"})
	w := postJSON(t, srv, "/v1/decision",
		`{"attributes":{"subject.role":"admin","action":"read"}}`)
	var got DecisionResponse
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if !got.Allowed {
		t.Fatalf("the default tenant should apply, got %+v", got)
	}
}

func TestDecision_MalformedJSON(t *testing.T) {
	srv := newServer(t, Config{})
	w := postJSON(t, srv, "/v1/decision", `{not json`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d want 400", w.Code)
	}
}

func TestDecision_MethodNotAllowed(t *testing.T) {
	srv := newServer(t, Config{})
	w := do(t, srv, httptest.NewRequest(http.MethodGet, "/v1/decision", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d want 405", w.Code)
	}
	if w.Header().Get("Allow") != http.MethodPost {
		t.Errorf("Allow header = %q", w.Header().Get("Allow"))
	}
}

func TestDecision_OnDecisionHookFires(t *testing.T) {
	var seen int
	srv := newServer(t, Config{
		OnDecision: func(req tessaraop.Request, d tessaraop.Decision) { seen++ },
	})
	postJSON(t, srv, "/v1/decision", `{"tenant":"acme"}`)
	if seen != 1 {
		t.Fatalf("audit hook fired %d times, want 1", seen)
	}
}

// --- Forward-auth / ext_authz ----------------------------------------------

// TestForwardAuth_StatusCodesOnly pins the contract every proxy in this family
// relies on: 200 allows, 403 denies.
func TestForwardAuth_StatusCodesOnly(t *testing.T) {
	srv := newServer(t, Config{})

	allow := httptest.NewRequest(http.MethodGet, "/v1/authz", nil)
	allow.Header.Set(HeaderTenant, "acme")
	allow.Header.Set(HeaderSubjectRole, "admin")
	w := do(t, srv, allow)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for an allowed request, got %d", w.Code)
	}
	if w.Header().Get(HeaderDecision) != "ALLOW" {
		t.Errorf("decision header = %q", w.Header().Get(HeaderDecision))
	}
	if w.Header().Get(HeaderObligations) != "audit_log" {
		t.Errorf("obligations header = %q; a proxy copies this upstream so the "+
			"application can enforce it", w.Header().Get(HeaderObligations))
	}
	if w.Header().Get(HeaderRule) != "allow-admin-read" {
		t.Errorf("rule header = %q", w.Header().Get(HeaderRule))
	}

	deny := httptest.NewRequest(http.MethodGet, "/v1/authz", nil)
	deny.Header.Set(HeaderTenant, "acme")
	deny.Header.Set(HeaderSubjectRole, "viewer")
	w = do(t, srv, deny)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for a denied request, got %d", w.Code)
	}
}

// TestForwardAuth_NeverReturns5xx is a security property specific to this
// protocol shape. Every proxy in the family treats 5xx as a failure of the
// authorizer rather than a denial, and most are configured to fail open on it. So
// a request this handler cannot make sense of must still be a 403.
func TestForwardAuth_NeverReturns5xx(t *testing.T) {
	srv := newServer(t, Config{})

	awkward := []*http.Request{
		httptest.NewRequest(http.MethodGet, "/v1/authz", nil),
		httptest.NewRequest("BREW", "/v1/authz/deeply/nested/path", nil),
		httptest.NewRequest(http.MethodPost, "/v1/authz", strings.NewReader("garbage")),
	}
	awkward[2].Header.Set(HeaderRiskScore, "not-a-number")
	awkward[1].Header.Set("X-Forwarded-Uri", "/%zz%zz")

	for i, r := range awkward {
		w := do(t, srv, r)
		if w.Code >= 500 {
			t.Errorf("request %d returned %d; a 5xx here makes fail-open proxies grant access",
				i, w.Code)
		}
		if w.Code != http.StatusOK && w.Code != http.StatusForbidden {
			t.Errorf("request %d returned %d, want 200 or 403", i, w.Code)
		}
	}
}

// TestForwardAuth_UsesOriginalMethodAndPath covers the header conventions the
// different proxies use to convey the request being authorized.
func TestForwardAuth_UsesOriginalMethodAndPath(t *testing.T) {
	srv := newServer(t, Config{})

	// Traefik-style: the original method and URI arrive in headers.
	r := httptest.NewRequest(http.MethodGet, "/v1/authz", nil)
	r.Header.Set(HeaderTenant, "acme")
	r.Header.Set(HeaderSubjectRole, "admin")
	r.Header.Set("X-Forwarded-Method", "POST")
	r.Header.Set("X-Forwarded-Uri", "/api/v2/docs?draft=1")

	w := do(t, srv, r)
	// POST maps to the write action, which the policy allows.
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// DELETE maps to delete, which the policy does not allow.
	r2 := httptest.NewRequest(http.MethodGet, "/v1/authz", nil)
	r2.Header.Set(HeaderTenant, "acme")
	r2.Header.Set(HeaderSubjectRole, "admin")
	r2.Header.Set("X-Forwarded-Method", "DELETE")
	if w := do(t, srv, r2); w.Code != http.StatusForbidden {
		t.Fatalf("DELETE should not be allowed, got %d", w.Code)
	}
}

func TestForwardAuth_ExplicitActionOverridesMethod(t *testing.T) {
	srv := newServer(t, Config{})
	r := httptest.NewRequest(http.MethodDelete, "/v1/authz", nil)
	r.Header.Set(HeaderTenant, "acme")
	r.Header.Set(HeaderSubjectRole, "admin")
	r.Header.Set(HeaderAction, "read")
	if w := do(t, srv, r); w.Code != http.StatusOK {
		t.Fatalf("an explicit action header should override the method, got %d", w.Code)
	}
}

// TestForwardAuth_ForwardedForNotTrustedByDefault is the same security property
// the ingest package enforces, checked through the server's configuration.
func TestForwardAuth_ForwardedForNotTrustedByDefault(t *testing.T) {
	// The blocklisted address arrives only in the client-controlled header.
	build := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/v1/authz", nil)
		r.Header.Set(HeaderTenant, "acme")
		r.Header.Set(HeaderSubjectRole, "admin")
		r.Header.Set("X-Forwarded-For", "203.0.113.9")
		r.RemoteAddr = "10.0.0.5:5555"
		return r
	}

	// With no trusted hops the header is ignored, so the global blocklist — which
	// matches on source address — does not fire.
	srv := newServer(t, Config{})
	if w := do(t, srv, build()); w.Code != http.StatusOK {
		t.Fatalf("untrusted header should be ignored, got %d", w.Code)
	}

	// With one trusted hop the header is authoritative and the deny applies.
	srvTrust := newServer(t, Config{TrustedProxyHops: 1})
	if w := do(t, srvTrust, build()); w.Code != http.StatusForbidden {
		t.Fatalf("a trusted forwarded address should reach the blocklist, got %d", w.Code)
	}
}

func TestForwardAuth_MFAHeaderFailsClosed(t *testing.T) {
	// Only affirmative spellings count, so a malformed header does not assert MFA.
	for _, v := range []string{"", "maybe", "0", "false", "no"} {
		if parseBoolHeader(v) {
			t.Errorf("%q must not be read as true", v)
		}
	}
	for _, v := range []string{"1", "true", "TRUE", "yes", "on"} {
		if !parseBoolHeader(v) {
			t.Errorf("%q should be read as true", v)
		}
	}
}

// --- OPA-compatible endpoint -----------------------------------------------

func TestOPA_SplitInput(t *testing.T) {
	srv := newServer(t, Config{})
	w := postJSON(t, srv, "/v1/data/tessaraop", `{
	  "input": {
	    "tenant": "acme",
	    "attributes": {"subject.role": "admin", "action": "read"}
	  }
	}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body %s", w.Code, w.Body)
	}

	var got opaResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !got.Result.Allow {
		t.Fatalf("expected allow, got %+v", got.Result)
	}
	if got.Result.RuleID != "allow-admin-read" {
		t.Errorf("rule = %q", got.Result.RuleID)
	}
}

// TestOPA_FlatInputIsTypedByTheRegistry is the interesting part of OPA
// compatibility. An existing OPA policy's input is one flat object, and the JSON
// type is not a reliable guide: a port sent as "443" by one client and 443 by
// another must reach the same numeric map, or the same policy behaves differently
// per caller.
func TestOPA_FlatInputIsTypedByTheRegistry(t *testing.T) {
	srv := newServer(t, Config{})

	// dest_port as a JSON number.
	w := postJSON(t, srv, "/v1/data/tessaraop", `{
	  "input": {"tenant": "acme", "scope": "network", "transport.dest_port": 443}
	}`)
	var got opaResponse
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if !got.Result.Allow {
		t.Errorf("numeric port should be allowed, got %+v", got.Result)
	}

	// The same value as a JSON string must behave identically, because the
	// registry — not the JSON type — decides the map.
	w = postJSON(t, srv, "/v1/data/tessaraop", `{
	  "input": {"tenant": "acme", "scope": "network", "transport.dest_port": "443"}
	}`)
	got = opaResponse{}
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if !got.Result.Allow {
		t.Errorf("string-encoded port should behave the same, got %+v", got.Result)
	}
}

func TestOPA_FlatInputIP(t *testing.T) {
	srv := newServer(t, Config{})
	w := postJSON(t, srv, "/v1/data/tessaraop", `{
	  "input": {
	    "tenant": "acme",
	    "subject.role": "admin",
	    "action": "read",
	    "network.source_ip": "203.0.113.9"
	  }
	}`)
	var got opaResponse
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got.Result.Allow {
		t.Fatalf("the blocklisted address should deny, got %+v", got.Result)
	}
	if got.Result.PolicyID != "global-baseline" {
		t.Errorf("expected the global policy, got %q", got.Result.PolicyID)
	}
}

func TestOPA_FlatInputBoolAndArray(t *testing.T) {
	srv := newServer(t, Config{})
	w := postJSON(t, srv, "/v1/data/tessaraop", `{
	  "input": {
	    "tenant": "acme",
	    "subject.mfa_verified": true,
	    "subject.groups": ["platform", "oncall"],
	    "subject.role": "admin",
	    "action": "read"
	  }
	}`)
	var got opaResponse
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if !got.Result.Allow {
		t.Fatalf("expected allow, got %+v", got.Result)
	}
}

func TestJSONToString(t *testing.T) {
	cases := map[string]string{
		`"admin"`:            "admin",
		`true`:               "true",
		`false`:              "false",
		`443`:                "443",
		`1.5`:                "1.5",
		`["a","b"]`:          "a,b",
		`[1,2]`:              "1,2",
		`{"nested":"thing"}`: `{"nested":"thing"}`,
	}
	for raw, want := range cases {
		if got := jsonToString(json.RawMessage(raw)); got != want {
			t.Errorf("%s -> %q want %q", raw, got, want)
		}
	}
}

func TestOPA_UnregisteredKeyIsWarned(t *testing.T) {
	srv := newServer(t, Config{})
	w := postJSON(t, srv, "/v1/data/tessaraop",
		`{"input":{"tenant":"acme","custom.thing":"x"}}`)
	var got opaResponse
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if len(got.Result.Warnings) == 0 {
		t.Fatal("an unregistered key should be flagged, since a typo lands here")
	}
}

func TestOPA_MalformedJSON(t *testing.T) {
	srv := newServer(t, Config{})
	if w := postJSON(t, srv, "/v1/data/tessaraop", `{oops`); w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d want 400", w.Code)
	}
}

// --- Operational endpoints --------------------------------------------------

func TestHealthzAndReadyz(t *testing.T) {
	srv := newServer(t, Config{})
	if w := do(t, srv, httptest.NewRequest(http.MethodGet, "/healthz", nil)); w.Code != 200 {
		t.Errorf("healthz = %d", w.Code)
	}
	if w := do(t, srv, httptest.NewRequest(http.MethodGet, "/readyz", nil)); w.Code != 200 {
		t.Errorf("readyz = %d", w.Code)
	}
}

// TestReadyz_UnreadyWithoutPolicy separates liveness from readiness. A process
// that is alive but holds no policy denies every request, so it must be pulled
// from the load balancer rather than restarted.
func TestReadyz_UnreadyWithoutPolicy(t *testing.T) {
	var empty tessaraop.PDP
	srv := newServer(t, Config{PDP: &empty})

	if w := do(t, srv, httptest.NewRequest(http.MethodGet, "/healthz", nil)); w.Code != 200 {
		t.Errorf("healthz should still be 200: %d", w.Code)
	}
	w := do(t, srv, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz = %d want 503 before any policy is installed", w.Code)
	}
}

func TestMetrics_PrometheusFormat(t *testing.T) {
	srv := newServer(t, Config{})
	postJSON(t, srv, "/v1/decision", `{"tenant":"acme","attributes":{"subject.role":"admin","action":"read"}}`)
	postJSON(t, srv, "/v1/decision", `{"tenant":"acme","attributes":{"subject.role":"viewer"}}`)

	w := do(t, srv, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if w.Code != 200 {
		t.Fatalf("metrics = %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Errorf("content type = %q", ct)
	}

	body := w.Body.String()
	for _, want := range []string{
		"tessaraop_evaluations_total 2",
		"tessaraop_allowed_total 1",
		"tessaraop_denied_total 1",
		"# TYPE tessaraop_evaluations_total counter",
		"# TYPE tessaraop_policy_generation gauge",
		"tessaraop_rules 3",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q:\n%s", want, body)
		}
	}
	// Every metric must carry HELP and TYPE, or a scrape treats it as untyped.
	helps := strings.Count(body, "# HELP ")
	types := strings.Count(body, "# TYPE ")
	if helps != types || helps == 0 {
		t.Errorf("HELP/TYPE counts mismatched: %d and %d", helps, types)
	}
}

func TestInfo(t *testing.T) {
	srv := newServer(t, Config{})
	w := do(t, srv, httptest.NewRequest(http.MethodGet, "/v1/info", nil))
	if w.Code != 200 {
		t.Fatalf("info = %d", w.Code)
	}
	var got struct {
		Info struct {
			Policies int `json:"policies"`
			Rules    int `json:"rules"`
		} `json:"info"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Info.Policies != 3 || got.Info.Rules != 3 {
		t.Errorf("info = %+v", got.Info)
	}
}

func TestAttributes_Endpoint(t *testing.T) {
	srv := newServer(t, Config{})
	w := do(t, srv, httptest.NewRequest(http.MethodGet, "/v1/attributes", nil))
	if w.Code != 200 {
		t.Fatalf("attributes = %d", w.Code)
	}
	var got struct {
		Attributes []struct {
			Name      string   `json:"name"`
			Kind      string   `json:"kind"`
			Operators []string `json:"operators"`
		} `json:"attributes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Attributes) < 50 {
		t.Fatalf("expected the full registry, got %d entries", len(got.Attributes))
	}
	for _, a := range got.Attributes {
		if a.Name == "" || a.Kind == "" || len(a.Operators) == 0 {
			t.Fatalf("incomplete entry: %+v", a)
		}
	}
}

// --- Reload -----------------------------------------------------------------

func TestReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policies.json")
	if err := os.WriteFile(path, []byte(testBundle), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	pdp, _, err := tessaraop.OpenBundle(path, tessaraop.Config{})
	if err != nil {
		t.Fatalf("OpenBundle: %v", err)
	}
	srv := newServer(t, Config{PDP: pdp, BundlePath: path})
	gen := pdp.Generation()

	// Swap in a bundle that grants auditor instead of admin.
	updated := strings.Replace(testBundle, `"admin"`, `"auditor"`, 1)
	if err := os.WriteFile(path, []byte(updated), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	w := postJSON(t, srv, "/v1/reload", ``)
	if w.Code != http.StatusOK {
		t.Fatalf("reload = %d body %s", w.Code, w.Body)
	}
	if pdp.Generation() <= gen {
		t.Error("generation should advance")
	}

	adminNow := postJSON(t, srv, "/v1/decision",
		`{"tenant":"acme","attributes":{"subject.role":"admin","action":"read"}}`)
	var got DecisionResponse
	_ = json.Unmarshal(adminNow.Body.Bytes(), &got)
	if got.Allowed {
		t.Error("after the reload admin should no longer be granted")
	}
}

// TestReload_RejectedBundleKeepsServing is the operationally important case: a
// failed reload must leave the previous policy in effect, and must say so.
func TestReload_RejectedBundleKeepsServing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policies.json")
	if err := os.WriteFile(path, []byte(testBundle), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	pdp, _, err := tessaraop.OpenBundle(path, tessaraop.Config{})
	if err != nil {
		t.Fatalf("OpenBundle: %v", err)
	}
	srv := newServer(t, Config{PDP: pdp, BundlePath: path})

	broken := `{"version":1,"policies":[{"id":"p","tenant":"t","rules":[{"id":"r",
	  "effect":"ALLOW","when":{"attr":"subject.role","op":"gt","min":1}}]}]}`
	if err := os.WriteFile(path, []byte(broken), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	w := postJSON(t, srv, "/v1/reload", ``)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("reload = %d want 422", w.Code)
	}
	if !strings.Contains(w.Body.String(), "remains in effect") {
		t.Errorf("the response must tell an operator the old policy is still serving:\n%s", w.Body)
	}

	// And it really is still serving.
	allow := postJSON(t, srv, "/v1/decision",
		`{"tenant":"acme","attributes":{"subject.role":"admin","action":"read"}}`)
	var got DecisionResponse
	_ = json.Unmarshal(allow.Body.Bytes(), &got)
	if !got.Allowed {
		t.Error("the previous policy set must still be answering")
	}
}

func TestReload_TokenRequired(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policies.json")
	if err := os.WriteFile(path, []byte(testBundle), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	pdp, _, err := tessaraop.OpenBundle(path, tessaraop.Config{})
	if err != nil {
		t.Fatalf("OpenBundle: %v", err)
	}
	srv := newServer(t, Config{PDP: pdp, BundlePath: path, ReloadToken: "s3cret"})

	if w := postJSON(t, srv, "/v1/reload", ``); w.Code != http.StatusUnauthorized {
		t.Fatalf("without a token: %d want 401", w.Code)
	}

	r := httptest.NewRequest(http.MethodPost, "/v1/reload", nil)
	r.Header.Set("X-Tessaraop-Token", "wrong")
	if w := do(t, srv, r); w.Code != http.StatusUnauthorized {
		t.Fatalf("with a wrong token: %d want 401", w.Code)
	}

	r = httptest.NewRequest(http.MethodPost, "/v1/reload", nil)
	r.Header.Set("X-Tessaraop-Token", "s3cret")
	if w := do(t, srv, r); w.Code != http.StatusOK {
		t.Fatalf("with the right token: %d want 200", w.Code)
	}
}

func TestReload_NotConfigured(t *testing.T) {
	srv := newServer(t, Config{})
	if w := postJSON(t, srv, "/v1/reload", ``); w.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d want 501 when no bundle path is configured", w.Code)
	}
}

func TestConstantTimeEqual(t *testing.T) {
	if !constantTimeEqual("abc", "abc") {
		t.Error("equal strings should compare equal")
	}
	if constantTimeEqual("abc", "abd") || constantTimeEqual("abc", "abcd") ||
		constantTimeEqual("", "a") {
		t.Error("unequal strings must not compare equal")
	}
	if !constantTimeEqual("", "") {
		t.Error("two empty strings are equal")
	}
}

// --- Body limit -------------------------------------------------------------

func TestMaxBodyBytes(t *testing.T) {
	srv := newServer(t, Config{MaxBodyBytes: 64})
	huge := `{"tenant":"acme","attributes":{"x":"` + strings.Repeat("a", 500) + `"}}`
	if w := postJSON(t, srv, "/v1/decision", huge); w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d want 400 for an oversized body", w.Code)
	}
	if w := postJSON(t, srv, "/v1/data/tessaraop", huge); w.Code != http.StatusBadRequest {
		t.Fatalf("OPA endpoint status = %d want 400", w.Code)
	}
}
