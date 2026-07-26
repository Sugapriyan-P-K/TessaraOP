package ingest

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/suga/tessaraop/internal/attr"
)

func get(t *testing.T, target string) *http.Request {
	t.Helper()
	return httptest.NewRequest(http.MethodGet, target, nil)
}

// --- HTTP -------------------------------------------------------------------

func TestFromHTTPRequest_CoreFields(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/v2/admin/users?page=2&sort=name", strings.NewReader("{}"))
	r.Host = "API.Admin.Acme.com:8443"
	r.Header.Set("Content-Type", "application/json; charset=utf-8")
	r.Header.Set("User-Agent", "curl/8.4.0")
	r.Header.Set("Referer", "https://acme.com/console")
	r.Header.Set("X-Request-Id", "abc123")

	got := New("acme", "identity").FromHTTPRequest(r).Build()

	checks := map[string]string{
		attr.HTTPMethod:             "POST",
		attr.HTTPPath:               "/api/v2/admin/users",
		attr.HTTPQuery:              "page=2&sort=name",
		attr.HTTPHost:               "api.admin.acme.com",
		attr.UserAgent:              "curl/8.4.0",
		"http.referer":              "https://acme.com/console",
		attr.ContentType:            "application/json",
		attr.Header("X-Request-Id"): "abc123",
		attr.QueryParam("page"):     "2",
		attr.QueryParam("sort"):     "name",
	}
	for name, want := range checks {
		if got.Attributes[name] != want {
			t.Errorf("%s = %q want %q", name, got.Attributes[name], want)
		}
	}
	if got.TenantID != "acme" || got.Scope != "identity" {
		t.Errorf("tenant/scope lost: %q/%q", got.TenantID, got.Scope)
	}
}

// TestFromHTTPRequest_HostIsNormalized matters for correctness, not tidiness. A
// dnssuffix condition on "admin.acme.com" is a byte-level label comparison, so an
// unnormalized "Admin.Acme.com:8443" would not match it and the rule would
// silently not apply.
func TestFromHTTPRequest_HostIsNormalized(t *testing.T) {
	cases := map[string]string{
		"API.Acme.com:8443":  "api.acme.com",
		"acme.com":           "acme.com",
		"[2001:db8::1]:8443": "2001:db8::1",
		"[2001:db8::1]":      "2001:db8::1",
	}
	for host, want := range cases {
		r := get(t, "/")
		r.Host = host
		got := New("t", "").FromHTTPRequest(r).Build()
		if got.Attributes[attr.HTTPHost] != want {
			t.Errorf("host %q normalized to %q, want %q",
				host, got.Attributes[attr.HTTPHost], want)
		}
	}
}

// TestFromHTTPRequest_ExposesBothPaths is what lets a policy detect traversal.
// Only the cleaned path would hide "/api/../admin"; only the raw path would make
// every ordinary rule fragile. Both are needed, and comparing them is the signal.
func TestFromHTTPRequest_ExposesBothPaths(t *testing.T) {
	r := get(t, "/api/v2/../../admin/config")
	got := New("t", "").FromHTTPRequest(r).Build()

	if got.Attributes[attr.HTTPPath] != "/admin/config" {
		t.Errorf("cleaned path = %q want /admin/config", got.Attributes[attr.HTTPPath])
	}
	if raw := got.Attributes["http.raw_path"]; !strings.Contains(raw, "..") {
		t.Errorf("raw path should preserve the traversal, got %q", raw)
	}
}

// TestFromHTTPRequest_SkipsCredentialHeaders is a security property. Attributes
// reach the decision cache, audit logs and whatever an integration does with a
// Request afterwards, so a bearer token copied into one is a credential leak
// waiting for a debug log line.
func TestFromHTTPRequest_SkipsCredentialHeaders(t *testing.T) {
	r := get(t, "/")
	r.Header.Set("Authorization", "Bearer super-secret-token")
	r.Header.Set("Cookie", "session=secret-session-value")
	r.Header.Set("Proxy-Authorization", "Basic secret")

	got := New("t", "").FromHTTPRequest(r).Build()

	for name, value := range got.Attributes {
		if strings.Contains(value, "super-secret-token") ||
			strings.Contains(value, "secret-session-value") {
			t.Errorf("attribute %q leaked a credential: %q", name, value)
		}
	}
	if _, ok := got.Attributes[attr.Header("Authorization")]; ok {
		t.Error("the Authorization header must not become an attribute")
	}
	if _, ok := got.Attributes[attr.Header("Cookie")]; ok {
		t.Error("the Cookie header must not become an attribute")
	}
	// The scheme is still available, which is what a policy actually needs.
	if got.Attributes["http.authorization_scheme"] != "bearer" {
		t.Errorf("expected the auth scheme to be recorded, got %q",
			got.Attributes["http.authorization_scheme"])
	}
	// And no cookie value appears, because none was allowlisted.
	if _, ok := got.Attributes[attr.Cookie("session")]; ok {
		t.Error("cookie values must not be populated without an explicit allowlist")
	}
}

// TestWithCookies_AllowlistIsRequired pins the default. Populating every cookie
// would put session credentials in the decision cache and in audit records, so a
// cookie's value becomes an attribute only when an integrator names it.
func TestWithCookies_AllowlistIsRequired(t *testing.T) {
	r := get(t, "/")
	r.Header.Set("Cookie", "session=secret-value; locale=en-GB; flag=beta")

	// Default: nothing.
	plain := New("t", "").FromHTTPRequest(r).Build()
	for _, name := range []string{"session", "locale", "flag"} {
		if _, ok := plain.Attributes[attr.Cookie(name)]; ok {
			t.Errorf("cookie %q should not be populated by default", name)
		}
	}

	// Allowlisted: only the named ones, and the secret stays out.
	allowed := New("t", "").WithCookies("locale", "flag").FromHTTPRequest(r).Build()
	if allowed.Attributes[attr.Cookie("locale")] != "en-GB" {
		t.Errorf("allowlisted cookie missing, got %q", allowed.Attributes[attr.Cookie("locale")])
	}
	if allowed.Attributes[attr.Cookie("flag")] != "beta" {
		t.Errorf("allowlisted cookie missing, got %q", allowed.Attributes[attr.Cookie("flag")])
	}
	if _, ok := allowed.Attributes[attr.Cookie("session")]; ok {
		t.Error("a cookie outside the allowlist must stay out")
	}
}

func TestFromHTTPRequest_WebSocketUpgrade(t *testing.T) {
	r := get(t, "/ws")
	r.Header.Set("Upgrade", "WebSocket")
	r.Header.Set("Sec-WebSocket-Protocol", "chat")
	got := New("t", "").FromHTTPRequest(r).Build()

	if got.Attributes["ws.upgrade_requested"] != "true" {
		t.Error("expected the upgrade to be detected case-insensitively")
	}
	if got.Attributes["ws.protocol"] != "chat" {
		t.Error("expected the subprotocol to be recorded")
	}

	plain := New("t", "").FromHTTPRequest(get(t, "/")).Build()
	if plain.Attributes["ws.upgrade_requested"] != "false" {
		t.Error("a plain request must report false, not absent")
	}
}

func TestFromHTTPRequest_MultipartBoundary(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/upload", nil)
	r.Header.Set("Content-Type", "multipart/form-data; boundary=----xyz789")
	got := New("t", "").FromHTTPRequest(r).Build()

	if got.Attributes[attr.ContentType] != "multipart/form-data" {
		t.Errorf("media type should have parameters stripped, got %q",
			got.Attributes[attr.ContentType])
	}
	if got.Attributes["http.multipart_boundary"] != "----xyz789" {
		t.Errorf("boundary = %q", got.Attributes["http.multipart_boundary"])
	}
}

func TestFromHTTPRequest_UnparsableContentTypeIsKept(t *testing.T) {
	// A malformed Content-Type is itself worth matching on, so it must not vanish.
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("Content-Type", "application/json;;;charset")
	got := New("t", "").FromHTTPRequest(r).Build()
	if got.Attributes[attr.ContentType] == "" {
		t.Error("an unparsable Content-Type must still be recorded")
	}
}

// --- X-Forwarded-For, the security-critical part ----------------------------

// TestFromForwardedHeaders_HopCounting is the test that matters most in this
// package. X-Forwarded-For is attacker-controlled on its left: a client can send
// any value it likes. Taking the leftmost entry — the common implementation — lets
// anyone claim a corporate source address and walk through a CIDR allowlist.
func TestFromForwardedHeaders_HopCounting(t *testing.T) {
	// Client claims 10.0.0.1; two proxies we operate appended the truth.
	r := get(t, "/")
	r.Header.Add("X-Forwarded-For", "10.0.0.1, 203.0.113.7")
	r.Header.Add("X-Forwarded-For", "192.168.1.1")

	// With two trusted hops, the real client is the third entry from the right.
	got := New("t", "").FromForwardedHeaders(r, 2).Build()
	if want := netip.MustParseAddr("203.0.113.7"); got.IPs[attr.SourceIP] != want {
		t.Errorf("with 2 trusted hops: got %v want %v", got.IPs[attr.SourceIP], want)
	}

	// With one, it is the second from the right.
	got = New("t", "").FromForwardedHeaders(r, 1).Build()
	if want := netip.MustParseAddr("192.168.1.1"); got.IPs[attr.SourceIP] != want {
		t.Errorf("with 1 trusted hop: got %v want %v", got.IPs[attr.SourceIP], want)
	}

	// With none, the header is ignored entirely — the safe default.
	got = New("t", "").FromForwardedHeaders(r, 0).Build()
	if _, ok := got.IPs[attr.SourceIP]; ok {
		t.Error("with 0 trusted hops the header must be ignored")
	}
}

// TestFromForwardedHeaders_ClaimedAddressIsNotTrusted covers the case where fewer
// hops arrived than configured. The leftmost value is still client-controlled, so
// it must not be promoted to the verified source address.
func TestFromForwardedHeaders_ClaimedAddressIsNotTrusted(t *testing.T) {
	r := get(t, "/")
	r.Header.Set("X-Forwarded-For", "10.0.0.1")

	got := New("t", "").FromForwardedHeaders(r, 3).Build()
	if _, ok := got.IPs[attr.SourceIP]; ok {
		t.Error("an under-length forwarded chain must not set the source address")
	}
	if got.Attributes["http.header.x-forwarded-for-claimed"] != "10.0.0.1" {
		t.Error("the claimed address should be recorded separately for visibility")
	}
}

func TestFromForwardedHeaders_Unmaps4In6(t *testing.T) {
	r := get(t, "/")
	r.Header.Set("X-Forwarded-For", "::ffff:10.1.2.3")
	got := New("t", "").FromForwardedHeaders(r, 1).Build()

	addr := got.IPs[attr.SourceIP]
	if !addr.Is4() {
		t.Fatalf("expected an unmapped IPv4 address, got %v", addr)
	}
	// A policy written against 10.0.0.0/8 must match it.
	if !netip.MustParsePrefix("10.0.0.0/8").Contains(addr) {
		t.Errorf("%v should fall inside 10.0.0.0/8", addr)
	}
}

// --- TLS --------------------------------------------------------------------

func TestFromTLS(t *testing.T) {
	cs := &tls.ConnectionState{
		Version:            tls.VersionTLS13,
		CipherSuite:        tls.TLS_AES_128_GCM_SHA256,
		ServerName:         "API.Acme.com",
		NegotiatedProtocol: "h2",
	}
	got := New("t", "").FromTLS(cs).Build()

	if got.Attributes[attr.TLSVersion] != "TLS1.3" {
		t.Errorf("version = %q", got.Attributes[attr.TLSVersion])
	}
	if got.Numeric[attr.TLSVersionNo] != 13 {
		t.Errorf("numeric version = %v want 13", got.Numeric[attr.TLSVersionNo])
	}
	if got.Attributes[attr.SNI] != "api.acme.com" {
		t.Errorf("SNI should be lowercased, got %q", got.Attributes[attr.SNI])
	}
	if got.Attributes["tls.alpn"] != "h2" {
		t.Errorf("alpn = %q", got.Attributes["tls.alpn"])
	}
}

// TestTLSVersionNumbering_SortsSSLv3Lowest checks the encoding that makes a
// version floor expressible. If SSLv3 mapped above TLS1.3, "at least 12" would
// accept SSLv3 — the exact connection the rule exists to reject.
func TestTLSVersionNumbering_SortsSSLv3Lowest(t *testing.T) {
	floors := []struct {
		version uint16
		name    string
	}{
		{tls.VersionTLS10, "TLS1.0"},
		{tls.VersionTLS11, "TLS1.1"},
		{tls.VersionTLS12, "TLS1.2"},
		{tls.VersionTLS13, "TLS1.3"},
	}
	for _, f := range floors {
		n := tlsVersionNumber(f.version)
		if f.version >= tls.VersionTLS12 && n < 12 {
			t.Errorf("%s numbered %v, should satisfy a >=12 floor", f.name, n)
		}
		if f.version < tls.VersionTLS12 && n >= 12 {
			t.Errorf("%s numbered %v, should fail a >=12 floor", f.name, n)
		}
	}
	// SSLv3 must sort below every TLS version, not above them. Encoding it as its
	// version number, 30, would place it past TLS 1.3's 13, so a >=12 floor would
	// accept exactly the protocol the rule exists to reject.
	sslv3 := tlsVersionNumber(tls.VersionSSL30)
	if sslv3 >= 12 {
		t.Errorf("SSLv3 numbered %v, which satisfies a >=12 floor", sslv3)
	}
	if sslv3 >= tlsVersionNumber(tls.VersionTLS10) {
		t.Errorf("SSLv3 (%v) must sort below TLS 1.0 (%v)",
			sslv3, tlsVersionNumber(tls.VersionTLS10))
	}
	// An unrecognized version must fail every floor a policy can express.
	if unknown := tlsVersionNumber(0x9999); unknown != 0 {
		t.Errorf("an unknown version numbered %v, want 0", unknown)
	}
}

func TestFromTLS_ClientCertificate(t *testing.T) {
	leaf := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "svc.acme.com"},
		Issuer:       pkix.Name{CommonName: "Acme Internal CA"},
		SerialNumber: big.NewInt(4242),
		NotAfter:     time.Now().Add(30 * 24 * time.Hour),
	}
	cs := &tls.ConnectionState{
		Version:          tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{leaf},
		VerifiedChains:   [][]*x509.Certificate{{leaf}},
	}
	got := New("t", "").FromTLS(cs).Build()

	if got.Attributes["tls.client_cert_cn"] != "svc.acme.com" {
		t.Errorf("cn = %q", got.Attributes["tls.client_cert_cn"])
	}
	if got.Attributes["tls.client_cert_serial"] != "4242" {
		t.Errorf("serial = %q", got.Attributes["tls.client_cert_serial"])
	}
	if got.Attributes["tls.client_cert_verified"] != "true" {
		t.Error("a verified chain must report true")
	}
	if d := got.Numeric["tls.client_cert_expires_in_days"]; d < 29 || d > 31 {
		t.Errorf("expiry days = %v, want about 30", d)
	}

	// A presented but unverified certificate must not report as verified.
	unverified := &tls.ConnectionState{
		Version:          tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{leaf},
	}
	got = New("t", "").FromTLS(unverified).Build()
	if got.Attributes["tls.client_cert_verified"] != "false" {
		t.Error("an unverified chain must report false")
	}
}

// --- Identity ---------------------------------------------------------------

func TestFromSubjectAndToken(t *testing.T) {
	got := New("t", "").
		FromSubject(&SubjectInfo{
			ID: "u-1", Role: "admin", Groups: []string{"platform", "oncall"},
			MFAVerified: true, RiskScore: 12, AuthAge: 5 * time.Minute,
		}).
		FromToken(&TokenInfo{
			Valid: true, SignatureValid: true, Algorithm: "RS256",
			Issuer: "https://idp.acme.com", Scopes: []string{"read", "write"},
			ExpiresIn:       10 * time.Minute,
			AdditionalClaim: map[string]string{"tenant": "acme"},
		}).
		Build()

	if got.Attributes[attr.SubjectRole] != "admin" ||
		got.Attributes[attr.MFAVerified] != "true" ||
		got.Numeric[attr.RiskScore] != 12 {
		t.Errorf("subject attributes wrong: %+v", got.Attributes)
	}
	if got.Attributes["subject.groups"] != "platform,oncall" {
		t.Errorf("groups should be comma-joined for contains matching, got %q",
			got.Attributes["subject.groups"])
	}
	if got.Attributes[attr.TokenScopes] != "read,write" {
		t.Errorf("scopes = %q", got.Attributes[attr.TokenScopes])
	}
	if got.Attributes[attr.Claim("tenant")] != "acme" {
		t.Errorf("additional claim missing: %+v", got.Attributes)
	}
	if got.Numeric["token.expires_in_seconds"] != 600 {
		t.Errorf("expiry = %v want 600", got.Numeric["token.expires_in_seconds"])
	}
}

func TestNilArgumentsAreNoOps(t *testing.T) {
	// Callers should not have to branch on whether TLS was negotiated or a token
	// was presented.
	got := New("t", "s").
		FromHTTPRequest(nil).
		FromTLS(nil).
		FromToken(nil).
		FromSubject(nil).
		FromConn(nil).
		FromForwardedHeaders(nil, 2).
		Build()

	if got.TenantID != "t" || got.Scope != "s" {
		t.Fatal("tenant and scope should survive")
	}
	if len(got.Attributes) != 0 || len(got.Numeric) != 0 || len(got.IPs) != 0 {
		t.Fatalf("nil inputs should contribute nothing, got %+v", got)
	}
}

// --- Payload ----------------------------------------------------------------

func TestFromFileName(t *testing.T) {
	cases := map[string]string{
		"shell.php":      ".php",
		"archive.tar.gz": ".gz",
		"Report.PDF":     ".pdf",
		"noextension":    "",
	}
	for name, wantExt := range cases {
		got := New("t", "").FromFileName(name).Build()
		if got.Attributes[attr.FileExt] != wantExt {
			t.Errorf("%q -> ext %q want %q", name, got.Attributes[attr.FileExt], wantExt)
		}
		if got.Attributes["payload.file_name"] != name {
			t.Errorf("%q: file name not recorded", name)
		}
	}
}

func TestFromBody(t *testing.T) {
	// A PNG signature, so magic-number detection has something real to find.
	body := []byte("\x89PNG\r\n\x1a\n" + strings.Repeat("x", 100))
	got := New("t", "").FromBody(body).Build()

	if !strings.HasPrefix(got.Attributes["payload.file_magic"], "89504e47") {
		t.Errorf("magic = %q, want a PNG signature", got.Attributes["payload.file_magic"])
	}
	if got.Attributes["payload.detected_mime"] != "image/png" {
		t.Errorf("detected mime = %q", got.Attributes["payload.detected_mime"])
	}
	if got.Attributes[attr.PayloadBody] == "" {
		t.Error("body should be recorded for regex and DLP matching")
	}
}

// TestFromBody_RespectsLimit checks the bound. An unbounded copy in an
// authorization path is a memory-exhaustion vector reachable by anyone who can
// send a request.
func TestFromBody_RespectsLimit(t *testing.T) {
	body := []byte(strings.Repeat("a", 10000))
	got := New("t", "").WithBodyLimit(100).FromBody(body).Build()
	if n := len(got.Attributes[attr.PayloadBody]); n != 100 {
		t.Fatalf("body limit not applied: recorded %d bytes", n)
	}
}

// --- Time -------------------------------------------------------------------

// TestAtTime_UsesTheSuppliedClock is why the clock is a parameter. Reading
// time.Now here would make an audited request unreplayable: the same input could
// produce a different decision.
func TestAtTime_UsesTheSuppliedClock(t *testing.T) {
	when := time.Date(2026, 7, 26, 14, 30, 0, 0, time.UTC)
	got := New("t", "").AtTime(when).Build()

	if h := got.Numeric[attr.TimeHour]; h < 14.49 || h > 14.51 {
		t.Errorf("time.hour = %v want about 14.5", h)
	}
	if got.Numeric["time.day_of_week"] != float64(time.Sunday) {
		t.Errorf("day_of_week = %v, 2026-07-26 is a Sunday", got.Numeric["time.day_of_week"])
	}
	if got.Numeric["time.unix"] != float64(when.Unix()) {
		t.Errorf("unix = %v want %v", got.Numeric["time.unix"], when.Unix())
	}
}

// --- Registry agreement -----------------------------------------------------

// TestBuiltAttributesMatchTheRegistry is the contract test between this package
// and package attr. Every value this adapter produces must land in the map the
// registry declares, or the operators for that attribute cannot see it and the
// rule silently never fires.
func TestBuiltAttributesMatchTheRegistry(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/v2/x?a=1", strings.NewReader("{}"))
	r.Host = "api.acme.com"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Custom", "v")
	r.Header.Set("Upgrade", "websocket")
	r.RemoteAddr = "10.1.2.3:44444"
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, ServerName: "api.acme.com"}

	got := New("acme", "identity").
		FromHTTPRequest(r).
		FromSubject(&SubjectInfo{ID: "u", Role: "admin", RiskScore: 5}).
		FromToken(&TokenInfo{Valid: true, Scopes: []string{"read"}}).
		FromResource("document", "d-1", "/docs/1", "high").
		Action("read").
		AtTime(time.Now()).
		FromFileName("a.pdf").
		Build()

	check := func(name string, want attr.Kind) {
		a, ok := attr.Lookup(name)
		if !ok {
			t.Errorf("ingest produced unregistered attribute %q", name)
			return
		}
		if a.Kind != want {
			t.Errorf("%q is registered as %s but ingest put it in the %s map",
				name, a.Kind, want)
		}
	}
	for name := range got.Attributes {
		check(name, attr.KindString)
	}
	for name := range got.Numeric {
		check(name, attr.KindNumeric)
	}
	for name := range got.IPs {
		check(name, attr.KindIP)
	}
}

func TestHTTPRequest_Convenience(t *testing.T) {
	r := httptest.NewRequest(http.MethodDelete, "/api/v2/docs/7", nil)
	r.Host = "api.acme.com"
	r.RemoteAddr = "10.4.5.6:33333"

	got := HTTPRequest("acme", "identity", r,
		&SubjectInfo{ID: "u-9", Role: "admin"}, 0, time.Now())

	if got.Attributes[attr.Action] != "delete" {
		t.Errorf("DELETE should map to the delete action, got %q", got.Attributes[attr.Action])
	}
	if got.IPs[attr.SourceIP] != netip.MustParseAddr("10.4.5.6") {
		t.Errorf("source ip = %v", got.IPs[attr.SourceIP])
	}
	if got.Numeric[attr.SourcePort] != 33333 {
		t.Errorf("source port = %v", got.Numeric[attr.SourcePort])
	}
	if got.Attributes[attr.ResourcePath] != "/api/v2/docs/7" {
		t.Errorf("resource path = %q", got.Attributes[attr.ResourcePath])
	}
}

// TestHTTPRequest_ForwardedAddressWins checks precedence: when a trusted
// forwarded chain resolved a client address, the transport peer (which is the
// proxy) must not overwrite it.
func TestHTTPRequest_ForwardedAddressWins(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "192.168.1.1:5555" // the proxy
	r.Header.Set("X-Forwarded-For", "203.0.113.9")

	got := HTTPRequest("acme", "", r, nil, 1, time.Now())
	if want := netip.MustParseAddr("203.0.113.9"); got.IPs[attr.SourceIP] != want {
		t.Fatalf("source ip = %v want %v (the forwarded client, not the proxy)",
			got.IPs[attr.SourceIP], want)
	}
}

func TestMethodActionMapping(t *testing.T) {
	cases := map[string]string{
		http.MethodGet: "read", http.MethodHead: "read", http.MethodOptions: "read",
		http.MethodPost: "write", http.MethodPut: "write", http.MethodPatch: "write",
		http.MethodDelete: "delete",
		"WEIRD":           "unknown",
	}
	for method, want := range cases {
		if got := httpMethodAction(method); got != want {
			t.Errorf("%s -> %q want %q", method, got, want)
		}
	}
}

func TestSplitHostPort_ToleratesMissingPort(t *testing.T) {
	cases := []struct {
		in   string
		host string
		port int
	}{
		{"10.0.0.1:443", "10.0.0.1", 443},
		{"10.0.0.1", "10.0.0.1", 0},
		{"[2001:db8::1]:8443", "2001:db8::1", 8443},
		{"[2001:db8::1]", "2001:db8::1", 0},
	}
	for _, tc := range cases {
		host, port := splitHostPort(tc.in)
		if host != tc.host || port != tc.port {
			t.Errorf("%q -> (%q, %d) want (%q, %d)", tc.in, host, port, tc.host, tc.port)
		}
	}
}
