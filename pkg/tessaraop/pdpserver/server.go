// Package pdpserver exposes a PDP over HTTP so stacks that are not Go can use it.
//
// # Why several endpoint shapes rather than one
//
// An authorization engine only gets adopted if it speaks the protocol the
// customer's proxy already speaks. Asking a platform team to write a new sidecar
// is how a pilot stalls. So this serves four shapes over the same policy set:
//
//	POST /v1/decision          native JSON: full request in, full decision out
//	ANY  /v1/authz             forward-auth: 200 or 403, headers describe the request
//	POST /v1/data/tessaraop    OPA-compatible: {"input": …} -> {"result": …}
//	GET  /v1/attributes        the registry, as onboarding documentation
//
// /v1/authz is the important one for breadth. Envoy's ext_authz HTTP service,
// NGINX auth_request, Traefik ForwardAuth, HAProxy, Istio's ext_authz and
// Caddy's forward_auth all work the same way: forward the original request's
// headers to a URL and act on the status code. One handler covers all of them,
// with no protobuf dependency and no per-proxy adapter.
//
// The OPA-shaped endpoint exists because a team already calling OPA has the
// client code, the retry behaviour and the dashboards; matching the request and
// response envelope turns migration into a URL change.
//
// # Operational endpoints
//
//	GET  /healthz    process is up
//	GET  /readyz     a policy set is installed; 503 before the first load
//	GET  /metrics    Prometheus text format
//	POST /v1/reload  re-read the bundle from disk, atomically
//	GET  /v1/info    what is installed right now
//
// Metrics are emitted in Prometheus' text exposition format by hand rather than
// through a client library, keeping the zero-dependency property. The format is
// stable and simple enough that this is a better trade than a dependency in a
// request path.
package pdpserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/suga/tessaraop/internal/attr"
	"github.com/suga/tessaraop/internal/ingest"
	"github.com/suga/tessaraop/pkg/tessaraop"
)

// Config controls a Server.
type Config struct {
	// PDP is the decision point to serve. Required.
	PDP *tessaraop.PDP

	// BundlePath, when set, is what POST /v1/reload re-reads.
	BundlePath string

	// DefaultTenant is used when a request names no tenant. Empty means a
	// request without a tenant reaches only global policies.
	DefaultTenant string

	// TrustedProxyHops is how many proxies you operate in front of this server,
	// counted from the right of X-Forwarded-For.
	//
	// It defaults to 0, meaning the header is ignored and the transport-level
	// peer address is used. That default is the safe one: X-Forwarded-For is
	// attacker-controlled on its left, so trusting its first entry lets any
	// client claim any source address and walk through a CIDR allowlist. Set it
	// to the actual number of hops you control, never higher.
	TrustedProxyHops int

	// MaxBodyBytes caps a decode. Zero means DefaultMaxBodyBytes.
	MaxBodyBytes int64

	// Now supplies the clock, for tests and for replaying audited requests.
	Now func() time.Time

	// OnDecision, if set, is called after every decision. Use it for audit
	// logging. It runs on the request goroutine, so it must not block.
	OnDecision func(req tessaraop.Request, d tessaraop.Decision)

	// ReloadToken, when set, is required in the X-Tessaraop-Token header on
	// /v1/reload.
	//
	// Reload changes what every subsequent request is authorized against, so it
	// is the one mutating endpoint here and the one worth protecting. Leaving it
	// empty is only appropriate when the listener is not reachable from outside
	// the pod; the server logs a warning at construction either way.
	ReloadToken string
}

// DefaultMaxBodyBytes bounds request decoding.
const DefaultMaxBodyBytes = 1 << 20

// Server is an http.Handler serving a PDP.
type Server struct {
	cfg Config
	mux *http.ServeMux

	// Counters for the metrics endpoint that the PDP itself does not track,
	// because they are transport concerns rather than policy ones.
	badRequests  atomic.Uint64
	reloadOK     atomic.Uint64
	reloadFailed atomic.Uint64
	started      time.Time
}

// ErrNoPDP is returned when Config.PDP is nil.
var ErrNoPDP = errors.New("pdpserver: Config.PDP is required")

// New builds a server. It returns a warning string when the configuration is
// usable but has a footgun worth surfacing in a startup log.
func New(cfg Config) (*Server, []string, error) {
	if cfg.PDP == nil {
		return nil, nil, ErrNoPDP
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	var warnings []string
	if cfg.BundlePath != "" && cfg.ReloadToken == "" {
		warnings = append(warnings,
			"/v1/reload is unauthenticated; bind to a private interface or set ReloadToken, "+
				"since reload changes what every later request is authorized against")
	}
	if cfg.TrustedProxyHops == 0 {
		warnings = append(warnings,
			"TrustedProxyHops is 0, so X-Forwarded-For is ignored and the peer address is "+
				"used; set it to the number of proxies you operate if this server is behind one")
	}

	s := &Server{cfg: cfg, mux: http.NewServeMux(), started: time.Now()}
	s.routes()
	return s, warnings, nil
}

func (s *Server) routes() {
	s.mux.HandleFunc("/v1/decision", s.handleDecision)
	s.mux.HandleFunc("/v1/authz", s.handleForwardAuth)
	s.mux.HandleFunc("/v1/authz/", s.handleForwardAuth)
	s.mux.HandleFunc("/v1/data/tessaraop", s.handleOPA)
	s.mux.HandleFunc("/v1/data/tessaraop/", s.handleOPA)
	s.mux.HandleFunc("/v1/attributes", s.handleAttributes)
	s.mux.HandleFunc("/v1/info", s.handleInfo)
	s.mux.HandleFunc("/v1/reload", s.handleReload)
	s.mux.HandleFunc("/healthz", s.handleHealthz)
	s.mux.HandleFunc("/readyz", s.handleReadyz)
	s.mux.HandleFunc("/metrics", s.handleMetrics)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

// --- Native JSON API --------------------------------------------------------

// DecisionRequest is the native request envelope.
//
// Attributes are split by type on the wire exactly as they are in memory, rather
// than being inferred from JSON types. Inference would be ambiguous in the way
// that matters: a port arriving as "443" and one arriving as 443 would land in
// different maps, and the string one is invisible to every numeric operator — a
// rule that silently never fires. Making the caller choose the map makes the
// mistake impossible to express.
type DecisionRequest struct {
	Tenant string `json:"tenant"`
	Scope  string `json:"scope"`

	Attributes map[string]string  `json:"attributes,omitempty"`
	Numeric    map[string]float64 `json:"numeric,omitempty"`
	IPs        map[string]string  `json:"ips,omitempty"`
}

// DecisionResponse is the native response envelope.
type DecisionResponse struct {
	Allowed     bool     `json:"allowed"`
	Effect      string   `json:"effect"`
	PolicyID    string   `json:"policy_id,omitempty"`
	RuleID      string   `json:"rule_id,omitempty"`
	Obligations []string `json:"obligations,omitempty"`

	RulesScanned    int  `json:"rules_scanned"`
	PoliciesScanned int  `json:"policies_scanned"`
	CacheHit        bool `json:"cache_hit"`

	// Generation identifies the policy set that produced this answer, so an
	// audit record can be tied back to what was installed at the time.
	Generation uint64 `json:"generation"`

	// Warnings reports attributes the registry declares under a different type
	// than the one they arrived in. Advisory, not fatal: unregistered names are a
	// customer's own vocabulary and must keep working.
	Warnings []string `json:"warnings,omitempty"`
}

func (s *Server) handleDecision(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.methodNotAllowed(w, http.MethodPost)
		return
	}
	var in DecisionRequest
	if !s.decode(w, r, &in) {
		return
	}
	req, warnings := s.buildRequest(in)
	d := s.evaluate(req)
	s.writeJSON(w, http.StatusOK, s.response(d, warnings))
}

// buildRequest converts the wire envelope to an engine request, reporting
// type mismatches against the registry.
func (s *Server) buildRequest(in DecisionRequest) (tessaraop.Request, []string) {
	tenant := in.Tenant
	if tenant == "" {
		tenant = s.cfg.DefaultTenant
	}
	b := tessaraop.NewRequest(tenant, in.Scope)
	for k, v := range in.Attributes {
		b.Str(k, v)
	}
	for k, v := range in.Numeric {
		b.Num(k, v)
	}
	var warnings []string
	for k, v := range in.IPs {
		addr, err := netip.ParseAddr(v)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("ips[%q]: %q is not an IP address", k, v))
			continue
		}
		b.IP(k, addr)
	}
	req := b.Build()
	if err := b.Err(); err != nil {
		warnings = append(warnings, err.Error())
	}
	return req, warnings
}

func (s *Server) response(d tessaraop.Decision, warnings []string) DecisionResponse {
	return DecisionResponse{
		Allowed:         d.Allowed,
		Effect:          string(d.Effect),
		PolicyID:        d.MatchedPolicyID,
		RuleID:          d.MatchedRuleID,
		Obligations:     d.Obligations,
		RulesScanned:    d.RulesScanned,
		PoliciesScanned: d.PoliciesScanned,
		CacheHit:        d.CacheHit,
		Generation:      s.cfg.PDP.Generation(),
		Warnings:        warnings,
	}
}

func (s *Server) evaluate(req tessaraop.Request) tessaraop.Decision {
	d := s.cfg.PDP.Evaluate(req)
	if s.cfg.OnDecision != nil {
		s.cfg.OnDecision(req, d)
	}
	return d
}

// --- Forward-auth / ext_authz ----------------------------------------------

// Forward-auth request and response headers.
//
// These are read from and written to the proxy's own header plumbing, which is
// the only channel available in that protocol shape. The names are namespaced so
// they cannot collide with a customer's headers.
const (
	// HeaderTenant and HeaderScope override what the request would otherwise
	// infer. A proxy typically sets them per listener or per route.
	HeaderTenant = "X-Tessaraop-Tenant"
	HeaderScope  = "X-Tessaraop-Scope"

	// HeaderSubject and friends carry the authenticated principal, which the
	// proxy or an upstream auth filter has already established.
	HeaderSubject     = "X-Tessaraop-Subject"
	HeaderSubjectRole = "X-Tessaraop-Role"
	HeaderGroups      = "X-Tessaraop-Groups"
	HeaderMFA         = "X-Tessaraop-Mfa"
	HeaderRiskScore   = "X-Tessaraop-Risk-Score"

	// HeaderAction and HeaderResource override the defaults derived from the
	// HTTP method and path.
	HeaderAction      = "X-Tessaraop-Action"
	HeaderResource    = "X-Tessaraop-Resource"
	HeaderSensitivity = "X-Tessaraop-Sensitivity"

	// Response headers. Envoy, Traefik and NGINX can all copy selected response
	// headers onto the upstream request, which is how obligations reach the
	// application that has to enforce them.
	HeaderDecision    = "X-Tessaraop-Decision"
	HeaderPolicy      = "X-Tessaraop-Policy"
	HeaderRule        = "X-Tessaraop-Rule"
	HeaderObligations = "X-Tessaraop-Obligations"
	HeaderGeneration  = "X-Tessaraop-Generation"
)

// handleForwardAuth implements the shape Envoy ext_authz (HTTP), NGINX
// auth_request, Traefik ForwardAuth, HAProxy and Caddy forward_auth all use: the
// original request's method, path and headers arrive here, and the status code is
// the answer.
//
// 200 allows. 403 denies. Nothing else is returned for a well-formed request,
// because every one of those proxies treats a 5xx as a failure of the authorizer
// rather than a denial, and most are configured to fail open on it. Returning
// 500 on a malformed request would therefore be the one response that could
// grant access by accident, so a request this handler cannot understand is
// denied with 403 and the reason is put in a header.
func (s *Server) handleForwardAuth(w http.ResponseWriter, r *http.Request) {
	tenant := r.Header.Get(HeaderTenant)
	if tenant == "" {
		tenant = s.cfg.DefaultTenant
	}
	scope := r.Header.Get(HeaderScope)

	b := ingest.New(tenant, scope).FromHTTPRequest(r).AtTime(s.cfg.Now())

	// Order matters here, and getting it backwards is a security bug rather than
	// a cosmetic one. The transport peer address goes in first; the forwarded
	// headers are applied second so that a *trusted* chain overrides it. Done the
	// other way round, the peer — which behind a proxy is the proxy — would
	// overwrite the real client address, and a blocklist written against the
	// client would never fire.
	//
	// When TrustedProxyHops is 0, FromForwardedHeaders is a no-op and the peer
	// address stands, which is the correct posture for a directly exposed server.
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		if addr, perr := netip.ParseAddr(host); perr == nil {
			if addr.Is4In6() {
				addr = addr.Unmap()
			}
			b.SetIP(attr.SourceIP, addr)
		}
	}
	b.FromForwardedHeaders(r, s.cfg.TrustedProxyHops)

	// The original request's method and path, which the proxy rewrote onto this
	// one. Envoy and NGINX both preserve them; Traefik forwards them as
	// X-Forwarded-Method and X-Forwarded-Uri.
	method := firstNonEmpty(r.Header.Get("X-Forwarded-Method"), r.Method)
	origPath := firstNonEmpty(
		r.Header.Get("X-Forwarded-Uri"),
		r.Header.Get("X-Original-Uri"),
		strings.TrimPrefix(r.URL.Path, "/v1/authz"),
	)
	b.Set(attr.HTTPMethod, strings.ToUpper(method))
	if origPath != "" {
		if i := strings.IndexByte(origPath, '?'); i >= 0 {
			b.Set(attr.HTTPQuery, origPath[i+1:])
			origPath = origPath[:i]
		}
		b.Set(attr.HTTPPath, origPath)
		b.Set(attr.ResourcePath, origPath)
	}
	if host := r.Header.Get("X-Forwarded-Host"); host != "" {
		b.Set(attr.HTTPHost, strings.ToLower(host))
	}

	// Identity and intent, as asserted by headers.
	subject := &ingest.SubjectInfo{
		ID:          r.Header.Get(HeaderSubject),
		Role:        r.Header.Get(HeaderSubjectRole),
		MFAVerified: parseBoolHeader(r.Header.Get(HeaderMFA)),
	}
	if g := r.Header.Get(HeaderGroups); g != "" {
		subject.Groups = splitAndTrim(g)
	}
	if v := r.Header.Get(HeaderRiskScore); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			subject.RiskScore = f
		}
	}
	b.FromSubject(subject)

	if a := r.Header.Get(HeaderAction); a != "" {
		b.Action(a)
	} else {
		b.Action(methodAction(method))
	}
	if res := r.Header.Get(HeaderResource); res != "" {
		b.Set(attr.ResourceType, res)
	}
	if sens := r.Header.Get(HeaderSensitivity); sens != "" {
		b.Set(attr.Sensitivity, strings.ToLower(sens))
	}

	d := s.evaluate(b.Build())

	h := w.Header()
	h.Set(HeaderGeneration, strconv.FormatUint(s.cfg.PDP.Generation(), 10))
	h.Set(HeaderDecision, string(d.Effect))
	if d.MatchedPolicyID != "" {
		h.Set(HeaderPolicy, d.MatchedPolicyID)
	}
	if d.MatchedRuleID != "" {
		h.Set(HeaderRule, d.MatchedRuleID)
	}
	if len(d.Obligations) > 0 {
		h.Set(HeaderObligations, strings.Join(d.Obligations, ","))
	}

	if d.Allowed {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusForbidden)
}

// --- OPA-compatible endpoint -----------------------------------------------

// opaRequest matches OPA's data API envelope.
type opaRequest struct {
	Input struct {
		Tenant string `json:"tenant"`
		Scope  string `json:"scope"`

		// Attributes may arrive either pre-split, matching the native API, or as
		// one flat object. The flat form is what an existing OPA policy's input
		// looks like, so it has to work — and the ambiguity it creates is
		// resolved by the registry rather than by guessing from the JSON type.
		Attributes map[string]string  `json:"attributes,omitempty"`
		Numeric    map[string]float64 `json:"numeric,omitempty"`
		IPs        map[string]string  `json:"ips,omitempty"`

		Flat map[string]json.RawMessage `json:"-"`
	} `json:"input"`
}

// opaResponse matches OPA's data API response envelope.
type opaResponse struct {
	Result opaResult `json:"result"`
}

type opaResult struct {
	Allow       bool     `json:"allow"`
	Effect      string   `json:"effect"`
	PolicyID    string   `json:"policy_id,omitempty"`
	RuleID      string   `json:"rule_id,omitempty"`
	Obligations []string `json:"obligations,omitempty"`
	Generation  uint64   `json:"generation"`
	Warnings    []string `json:"warnings,omitempty"`
}

func (s *Server) handleOPA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.methodNotAllowed(w, http.MethodPost)
		return
	}

	// Decode twice: once into the typed envelope, once loosely to recover any
	// flat input keys. Two passes over a bounded body is cheap next to the
	// alternative of a hand-written decoder.
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes))
	if err != nil {
		s.badRequests.Add(1)
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body too large or unreadable"})
		return
	}

	var in opaRequest
	if err := json.Unmarshal(body, &in); err != nil {
		s.badRequests.Add(1)
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed JSON: " + err.Error()})
		return
	}

	dr := DecisionRequest{
		Tenant:     in.Input.Tenant,
		Scope:      in.Input.Scope,
		Attributes: in.Input.Attributes,
		Numeric:    in.Input.Numeric,
		IPs:        in.Input.IPs,
	}
	warnings := mergeFlatInput(body, &dr)

	req, moreWarnings := s.buildRequest(dr)
	warnings = append(warnings, moreWarnings...)
	d := s.evaluate(req)

	s.writeJSON(w, http.StatusOK, opaResponse{Result: opaResult{
		Allow:       d.Allowed,
		Effect:      string(d.Effect),
		PolicyID:    d.MatchedPolicyID,
		RuleID:      d.MatchedRuleID,
		Obligations: d.Obligations,
		Generation:  s.cfg.PDP.Generation(),
		Warnings:    warnings,
	}})
}

// mergeFlatInput folds flat "input" keys into the split maps, choosing the map
// from the attribute registry rather than from the JSON type.
//
// The registry is the right authority here because the JSON type is not
// trustworthy: a port serialized as "443" by one client and 443 by another must
// reach the same numeric map, or the same policy would behave differently per
// caller. An unregistered key falls back to its JSON type, and says so.
func mergeFlatInput(body []byte, dr *DecisionRequest) []string {
	var envelope struct {
		Input map[string]json.RawMessage `json:"input"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil
	}

	var warnings []string
	for key, raw := range envelope.Input {
		switch key {
		case "tenant", "scope", "attributes", "numeric", "ips":
			continue
		}

		kind, registered := attr.KindFor(key)
		if !registered {
			// Fall back to the JSON type, and flag it: a typo'd registry name
			// lands here and would otherwise be silently unmatched.
			kind = guessKind(raw)
			warnings = append(warnings, fmt.Sprintf(
				"input[%q] is not in the registry; treated as %s by its JSON type", key, kind))
		}

		switch kind {
		case attr.KindNumeric:
			var f float64
			if err := json.Unmarshal(raw, &f); err == nil {
				setNum(dr, key, f)
				continue
			}
			var str string
			if err := json.Unmarshal(raw, &str); err == nil {
				if f, err := strconv.ParseFloat(str, 64); err == nil {
					setNum(dr, key, f)
					continue
				}
			}
			warnings = append(warnings, fmt.Sprintf(
				"input[%q] is registered as numeric but is not a number", key))

		case attr.KindIP:
			var str string
			if err := json.Unmarshal(raw, &str); err == nil {
				setIP(dr, key, str)
				continue
			}
			warnings = append(warnings, fmt.Sprintf(
				"input[%q] is registered as an ip but is not a string", key))

		default:
			setStr(dr, key, jsonToString(raw))
		}
	}
	return warnings
}

func guessKind(raw json.RawMessage) attr.Kind {
	var f float64
	if err := json.Unmarshal(raw, &f); err == nil {
		return attr.KindNumeric
	}
	return attr.KindString
}

// jsonToString renders a JSON value as the string a policy would compare against:
// a bare string unquoted, a bool as true/false, a number in its shortest form,
// and anything structured as its raw JSON.
func jsonToString(raw json.RawMessage) string {
	var str string
	if err := json.Unmarshal(raw, &str); err == nil {
		return str
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err == nil {
		if b {
			return "true"
		}
		return "false"
	}
	var f float64
	if err := json.Unmarshal(raw, &f); err == nil {
		return strconv.FormatFloat(f, 'f', -1, 64)
	}
	// Arrays become comma-joined, matching the convention the registry documents
	// for multi-valued string attributes such as subject.groups.
	var list []json.RawMessage
	if err := json.Unmarshal(raw, &list); err == nil {
		parts := make([]string, 0, len(list))
		for _, item := range list {
			parts = append(parts, jsonToString(item))
		}
		return strings.Join(parts, ",")
	}
	return string(raw)
}

func setStr(dr *DecisionRequest, k, v string) {
	if dr.Attributes == nil {
		dr.Attributes = map[string]string{}
	}
	dr.Attributes[k] = v
}

func setNum(dr *DecisionRequest, k string, v float64) {
	if dr.Numeric == nil {
		dr.Numeric = map[string]float64{}
	}
	dr.Numeric[k] = v
}

func setIP(dr *DecisionRequest, k, v string) {
	if dr.IPs == nil {
		dr.IPs = map[string]string{}
	}
	dr.IPs[k] = v
}

// --- Introspection and operations ------------------------------------------

func (s *Server) handleAttributes(w http.ResponseWriter, r *http.Request) {
	type entry struct {
		Name      string   `json:"name"`
		Kind      string   `json:"kind"`
		Layer     string   `json:"layer"`
		Doc       string   `json:"doc"`
		Namespace bool     `json:"namespace,omitempty"`
		Operators []string `json:"operators"`
	}
	out := make([]entry, 0, len(tessaraop.Attributes()))
	for _, a := range tessaraop.Attributes() {
		ops := make([]string, 0, 8)
		for _, op := range a.Operators() {
			ops = append(ops, string(op))
		}
		out = append(out, entry{
			Name: a.Name, Kind: a.Kind.String(), Layer: a.Layer.String(),
			Doc: a.Doc, Namespace: a.Dynamic, Operators: ops,
		})
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"attributes": out})
}

func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]any{
		"info":       s.cfg.PDP.Info(),
		"metrics":    s.cfg.PDP.Metrics(),
		"uptime_sec": int64(time.Since(s.started).Seconds()),
	})
}

func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.methodNotAllowed(w, http.MethodPost)
		return
	}
	if s.cfg.BundlePath == "" {
		s.writeJSON(w, http.StatusNotImplemented,
			map[string]string{"error": "server was not configured with a bundle path"})
		return
	}
	if s.cfg.ReloadToken != "" {
		// Constant-time compare: this is a shared secret, and a timing oracle on
		// it would be a real if slow leak.
		if !constantTimeEqual(r.Header.Get("X-Tessaraop-Token"), s.cfg.ReloadToken) {
			s.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
			return
		}
	}

	diags, err := s.cfg.PDP.LoadBundleFile(s.cfg.BundlePath)
	msgs := make([]string, 0, len(diags))
	for _, d := range diags {
		msgs = append(msgs, d.String())
	}
	if err != nil {
		s.reloadFailed.Add(1)
		// The previous policy set is still installed. Say so explicitly: an
		// operator seeing a failed reload needs to know whether the service is
		// now denying everything or still serving the old rules.
		s.writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"error":       err.Error(),
			"diagnostics": msgs,
			"installed":   s.cfg.PDP.Info(),
			"note":        "reload rejected; the previously loaded policy set remains in effect",
		})
		return
	}
	s.reloadOK.Add(1)
	s.writeJSON(w, http.StatusOK, map[string]any{
		"reloaded":    true,
		"diagnostics": msgs,
		"installed":   s.cfg.PDP.Info(),
	})
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok\n")
}

// handleReadyz reports whether a policy set is installed.
//
// Separate from healthz because they answer different questions and drive
// different orchestrator behaviour: a process that is alive but has no policy
// would deny every request, so it must be pulled from the load balancer rather
// than restarted.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if s.cfg.PDP.Generation() == 0 {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "no policy set installed\n")
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ready\n")
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	m := s.cfg.PDP.Metrics()
	info := s.cfg.PDP.Info()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	var b strings.Builder
	metric := func(name, help, typ string, value uint64) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n%s %d\n", name, help, name, typ, name, value)
	}
	metric("tessaraop_evaluations_total", "Decisions rendered.", "counter", m.Evaluations)
	metric("tessaraop_allowed_total", "Decisions that allowed.", "counter", m.Allowed)
	metric("tessaraop_denied_total", "Decisions that denied.", "counter", m.Denied)
	metric("tessaraop_cache_hits_total", "Decisions served from the cache.", "counter", m.CacheHits)
	metric("tessaraop_rules_validated_total",
		"Rules that reached exact validation. Divided by evaluations, this is the index's selectivity.",
		"counter", m.RulesTested)
	metric("tessaraop_reloads_total", "Policy sets installed.", "counter", m.Reloads)
	metric("tessaraop_reload_failures_total", "Rejected reload attempts.", "counter", s.reloadFailed.Load())
	metric("tessaraop_bad_requests_total", "Requests that could not be decoded.", "counter", s.badRequests.Load())
	metric("tessaraop_policy_generation", "Installed policy set generation.", "gauge", info.Generation)
	metric("tessaraop_policies", "Policies installed.", "gauge", uint64(info.Policies))
	metric("tessaraop_rules", "Rules installed; the indexed universe size.", "gauge", uint64(info.Rules))
	metric("tessaraop_tenants", "Tenants holding policy.", "gauge", uint64(info.Tenants))
	metric("tessaraop_shards", "Shards the corpus partitions into.", "gauge", uint64(info.Shards))

	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, b.String())
}

// --- Helpers ----------------------------------------------------------------

func (s *Server) decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes))
	if err := dec.Decode(dst); err != nil {
		s.badRequests.Add(1)
		s.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed JSON: " + err.Error()})
		return false
	}
	return true
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (s *Server) methodNotAllowed(w http.ResponseWriter, allowed ...string) {
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	s.writeJSON(w, http.StatusMethodNotAllowed,
		map[string]string{"error": "method not allowed"})
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func splitAndTrim(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// parseBoolHeader treats only affirmative spellings as true, so a missing or
// malformed header fails closed.
func parseBoolHeader(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func methodAction(method string) string {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return "read"
	case http.MethodDelete:
		return "delete"
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		return "write"
	}
	return "unknown"
}

// constantTimeEqual compares two strings without leaking their contents through
// timing. It compares lengths first, which does leak the length — acceptable for
// a configured token, and unavoidable without padding.
func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
