// Package ingest builds a model.Request from real traffic.
//
// # Why this is a separate package, and why it uses only the standard library
//
// The policy core evaluates named, already-typed attributes. It does not decode
// packets or HTTP bytes, and that boundary is deliberate rather than incidental.
// Parser-differential bugs are one of the most productive sources of
// authorization bypasses in real systems: when the component making the decision
// parses a request differently from the component serving it, an attacker crafts
// input the two disagree about. A hand-rolled TCP/IP or HTTP decoder sitting
// inside an authorization hot path is exactly that shape of mistake.
//
// So everything here delegates to code that already has to be right:
// net/http for requests, net/netip for addresses, crypto/tls for handshake state,
// mime for media types. This package's whole job is mapping their output onto the
// names in the attribute registry, and normalizing it the way policy authors
// expect — lowercased hosts, port-stripped, media-type parameters removed.
//
// # What it does not do
//
// It performs no I/O, no DNS lookup, no threat-intelligence enrichment, and no
// body reading unless explicitly asked. Geo-IP, IP reputation, ASN, session
// validity and token verification all require a store or a network call, so they
// arrive through Enrich rather than being inferred here. Layer 3 and 4 header
// fields beyond what a net.Conn exposes — TTL, TCP flags, fragmentation, DSCP —
// are not reachable from Go's socket abstraction at all; they come from whatever
// dataplane sits in front of the application, via the same Enrich seam.
//
// That split is honest about where the data comes from. An adapter that
// fabricated a TTL would be worse than one that omits it, because a policy on a
// fabricated attribute reads as enforced when it is not.
package ingest

import (
	"crypto/tls"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"path"
	"strings"
	"time"

	"github.com/suga/tessaraop/internal/attr"
	"github.com/suga/tessaraop/internal/model"
)

// Builder accumulates attributes and produces a model.Request.
//
// Every From* method is additive and may be chained in any order; later calls
// overwrite earlier values for the same attribute. A nil argument is a no-op, so
// a caller need not branch on whether TLS was negotiated or a token was present.
type Builder struct {
	tenant string
	scope  string

	strs map[string]string
	nums map[string]float64
	ips  map[string]netip.Addr

	// bodyLimit caps how much of a request body FromBody will read.
	bodyLimit int64

	// cookies is the set of cookie names whose values may become attributes.
	// Nil means none, which is the default; see WithCookies.
	cookies map[string]bool
}

// DefaultBodyLimit bounds payload inspection. Bodies are only read when a caller
// explicitly asks, and even then a bound is required: an unbounded read in an
// authorization path is a memory-exhaustion vector reachable by anyone who can
// send a request.
const DefaultBodyLimit = 64 << 10

// New starts a builder for a tenant and scope.
//
// Scope is the second half of the shard key and the single most effective lever
// on per-request cost. Pick something stable and reasonably narrow — a resource
// family, an application, a listener — not something request-specific.
func New(tenantID, scope string) *Builder {
	return &Builder{
		tenant:    tenantID,
		scope:     scope,
		strs:      make(map[string]string, 24),
		nums:      make(map[string]float64, 8),
		ips:       make(map[string]netip.Addr, 2),
		bodyLimit: DefaultBodyLimit,
	}
}

// WithBodyLimit changes how much body FromBody will read.
func (b *Builder) WithBodyLimit(n int64) *Builder {
	if n > 0 {
		b.bodyLimit = n
	}
	return b
}

// WithCookies allowlists the cookie names whose values may become attributes.
//
// No cookie is populated unless named here, and that default is the point. A
// session cookie is a credential; copying every cookie into the attribute map
// would put it in the decision cache, in whatever an integration logs, and in any
// audit record — the same leak this package refuses for the raw Cookie header,
// arriving through a different door.
//
// So the caller names the cookies their policies actually reference. Those are
// almost never the secret ones: a locale, a feature flag, a consent marker. If a
// policy genuinely needs to test a session cookie, prefer resolving it upstream
// and passing the result through FromSubject or session.valid, so the engine sees
// a verdict rather than the credential.
func (b *Builder) WithCookies(names ...string) *Builder {
	if b.cookies == nil {
		b.cookies = make(map[string]bool, len(names))
	}
	for _, n := range names {
		if n != "" {
			b.cookies[n] = true
		}
	}
	return b
}

// Set stores a string attribute directly, for values this package cannot derive.
func (b *Builder) Set(name, value string) *Builder {
	if name != "" {
		b.strs[name] = value
	}
	return b
}

// SetNum stores a numeric attribute directly.
func (b *Builder) SetNum(name string, value float64) *Builder {
	if name != "" {
		b.nums[name] = value
	}
	return b
}

// SetIP stores an IP attribute directly.
func (b *Builder) SetIP(name string, addr netip.Addr) *Builder {
	if name != "" && addr.IsValid() {
		b.ips[name] = addr
	}
	return b
}

// SetBool stores a string attribute as "true" or "false".
func (b *Builder) SetBool(name string, value bool) *Builder {
	if value {
		return b.Set(name, "true")
	}
	return b.Set(name, "false")
}

// Build returns the assembled request. Empty maps are dropped so the decision
// cache hashes the same logical request identically however it was assembled.
func (b *Builder) Build() model.Request {
	r := model.Request{TenantID: b.tenant, Scope: b.scope}
	if len(b.strs) > 0 {
		r.Attributes = b.strs
	}
	if len(b.nums) > 0 {
		r.Numeric = b.nums
	}
	if len(b.ips) > 0 {
		r.IPs = b.ips
	}
	return r
}

// --- Layer 3 and 4 ----------------------------------------------------------

// FromConn populates what a net.Conn actually exposes: the peer and local
// address and port, and the transport protocol.
//
// It does not populate TTL, TCP flags, window size, fragmentation or DSCP.
// Go's net.Conn does not surface them, and inventing values would make policies
// on those attributes look enforced while matching nothing. Supply them through
// Set/SetNum from whatever dataplane can actually see the headers.
func (b *Builder) FromConn(c net.Conn) *Builder {
	if c == nil {
		return b
	}
	if remote := c.RemoteAddr(); remote != nil {
		b.addrPort(remote, attr.SourceIP, attr.SourcePort)
		b.protocolFrom(remote)
	}
	if local := c.LocalAddr(); local != nil {
		b.addrPort(local, attr.DestIP, attr.DestPort)
	}
	return b
}

// FromAddrPort sets the source address and port from a parsed pair.
func (b *Builder) FromAddrPort(src netip.AddrPort) *Builder {
	if src.Addr().IsValid() {
		b.SetIP(attr.SourceIP, src.Addr())
		b.SetNum(attr.SourcePort, float64(src.Port()))
		b.SetNum("network.ip_version", ipVersion(src.Addr()))
	}
	return b
}

func (b *Builder) addrPort(a net.Addr, ipName, portName string) {
	host, port := splitHostPort(a.String())
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return
	}
	// Unwrap 4-in-6 so a policy written against 10.0.0.0/8 matches a connection
	// reported as ::ffff:10.0.0.1, which is what a dual-stack listener yields.
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	b.SetIP(ipName, addr)
	if port > 0 {
		b.SetNum(portName, float64(port))
	}
	if ipName == attr.SourceIP {
		b.SetNum("network.ip_version", ipVersion(addr))
	}
}

func (b *Builder) protocolFrom(a net.Addr) {
	switch a.Network() {
	case "tcp", "tcp4", "tcp6":
		b.Set("network.protocol_name", "tcp")
		b.SetNum(attr.IPProtocol, 6)
	case "udp", "udp4", "udp6":
		b.Set("network.protocol_name", "udp")
		b.SetNum(attr.IPProtocol, 17)
	case "ip", "ip4", "ip6":
		b.Set("network.protocol_name", "ip")
	}
}

func ipVersion(a netip.Addr) float64 {
	if a.Is4() || a.Is4In6() {
		return 4
	}
	return 6
}

// splitHostPort tolerates an address with no port, which net.SplitHostPort
// rejects.
func splitHostPort(s string) (host string, port int) {
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return strings.Trim(s, "[]"), 0
	}
	n := 0
	for i := 0; i < len(p); i++ {
		if p[i] < '0' || p[i] > '9' {
			return h, 0
		}
		n = n*10 + int(p[i]-'0')
	}
	return h, n
}

// --- Layer 7: HTTP ----------------------------------------------------------

// FromHTTPRequest populates the http.* namespace from a parsed request.
//
// The request is not modified and the body is not read; call FromBody for that.
//
// Two normalizations matter for policy correctness. The host is lowercased and
// port-stripped, so a dnssuffix condition on "admin.acme.com" matches
// "Admin.Acme.com:8443". And both the cleaned path and the raw path are exposed:
// comparing them is how a policy detects traversal and encoding tricks, which a
// single normalized value would hide.
func (b *Builder) FromHTTPRequest(r *http.Request) *Builder {
	if r == nil {
		return b
	}

	b.Set(attr.HTTPMethod, strings.ToUpper(r.Method))
	b.Set(attr.HTTPVersion, r.Proto)

	rawPath := r.URL.EscapedPath()
	b.Set("http.raw_path", rawPath)
	b.Set(attr.HTTPPath, path.Clean("/"+strings.TrimPrefix(r.URL.Path, "/")))
	b.Set(attr.HTTPQuery, r.URL.RawQuery)
	b.SetNum("http.uri_length", float64(len(r.URL.RequestURI())))

	host := r.Host
	if host == "" && r.URL != nil {
		host = r.URL.Host
	}
	b.Set(attr.HTTPHost, normalizeHost(host))

	b.Set(attr.UserAgent, r.UserAgent())
	b.Set("http.referer", r.Referer())
	b.SetNum("http.header_count", float64(len(r.Header)))

	if ct := r.Header.Get("Content-Type"); ct != "" {
		media, params, err := mime.ParseMediaType(ct)
		if err == nil {
			b.Set(attr.ContentType, strings.ToLower(media))
			if boundary := params["boundary"]; boundary != "" {
				b.Set("http.multipart_boundary", boundary)
			}
		} else {
			// Unparsable Content-Type is itself worth being able to match on, so
			// record it verbatim rather than dropping the attribute.
			b.Set(attr.ContentType, strings.ToLower(ct))
		}
	}
	if r.ContentLength >= 0 {
		b.SetNum(attr.ContentLen, float64(r.ContentLength))
	}

	if authz := r.Header.Get("Authorization"); authz != "" {
		scheme := authz
		if i := strings.IndexByte(authz, ' '); i > 0 {
			scheme = authz[:i]
		}
		// The scheme only. The credential itself must never become an attribute:
		// attributes reach logs, caches and audit trails.
		b.Set("http.authorization_scheme", strings.ToLower(scheme))
	}

	// Every header, under its lowercased name. Multi-valued headers are joined
	// with ", " as RFC 9110 permits, so a contains condition sees all values.
	for name, values := range r.Header {
		if isSensitiveHeader(name) {
			continue
		}
		b.Set(attr.Header(name), strings.Join(values, ", "))
	}

	// Query parameters, first value each.
	if q := r.URL.Query(); len(q) > 0 {
		for name, values := range q {
			if len(values) > 0 {
				b.Set(attr.QueryParam(name), values[0])
			}
		}
	}

	// Cookies, but only those explicitly allowlisted. See WithCookies.
	if len(b.cookies) > 0 {
		for _, c := range r.Cookies() {
			if b.cookies[c.Name] {
				b.Set(attr.Cookie(c.Name), c.Value)
			}
		}
	}

	// WebSocket upgrade attempts.
	upgrade := strings.ToLower(r.Header.Get("Upgrade"))
	b.SetBool("ws.upgrade_requested", upgrade == "websocket")
	if proto := r.Header.Get("Sec-WebSocket-Protocol"); proto != "" {
		b.Set("ws.protocol", proto)
	}

	if r.TLS != nil {
		b.FromTLS(r.TLS)
	}
	return b
}

// isSensitiveHeader lists headers whose values must not become attributes.
//
// Attributes flow into the decision cache, into logs, and into whatever an
// integration does with a Request afterwards. A bearer token or a cookie jar
// copied into that path is a credential-leak waiting for a debug log line, and no
// policy needs the secret itself — the parsed results (token.valid, token.scopes,
// api.key_id, and the individual cookies) carry everything a rule can use.
func isSensitiveHeader(name string) bool {
	switch http.CanonicalHeaderKey(name) {
	case "Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie":
		return true
	}
	return false
}

// normalizeHost lowercases and strips any port, so hostname conditions compare
// against a canonical form.
func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if h == "" {
		return ""
	}
	if strings.HasPrefix(h, "[") {
		if i := strings.IndexByte(h, ']'); i > 0 {
			return h[1:i]
		}
		return h
	}
	// Only strip a trailing :port, never a colon inside a bare IPv6 literal.
	if i := strings.LastIndexByte(h, ':'); i > 0 && !strings.Contains(h[:i], ":") {
		return h[:i]
	}
	return h
}

// FromResponse populates the response-phase attributes, for policies that act on
// what a downstream server returned.
func (b *Builder) FromResponse(statusCode int, header http.Header) *Builder {
	if statusCode > 0 {
		b.SetNum(attr.HTTPStatus, float64(statusCode))
	}
	if ct := header.Get("Content-Type"); ct != "" {
		if media, _, err := mime.ParseMediaType(ct); err == nil {
			b.Set("payload.detected_mime", strings.ToLower(media))
		}
	}
	return b
}

// FromForwardedHeaders resolves the client address from proxy headers.
//
// trustedHops is the number of proxies you operate, counted from the right. This
// argument has no safe default, which is why it is required: X-Forwarded-For is
// attacker-controlled on its left, so taking the leftmost entry — the common
// mistake — lets a client claim any source address it likes and walk straight
// through a CIDR allowlist. With trustedHops = n, the (n+1)-th entry from the
// right is the last one your own infrastructure wrote, and everything left of it
// is discarded.
//
// Pass 0 when nothing is in front of you; the header is then ignored entirely and
// the transport-level address stands.
func (b *Builder) FromForwardedHeaders(r *http.Request, trustedHops int) *Builder {
	if r == nil || trustedHops <= 0 {
		return b
	}
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		for _, part := range strings.Split(v, ",") {
			if p := strings.TrimSpace(part); p != "" {
				hops = append(hops, p)
			}
		}
	}
	if len(hops) == 0 {
		return b
	}
	idx := len(hops) - trustedHops
	if idx < 0 {
		// Fewer hops than expected: the leftmost is the most trustworthy entry
		// available, but it is still client-controlled, so it is recorded
		// separately rather than overwriting the verified source address.
		b.Set("http.header.x-forwarded-for-claimed", hops[0])
		return b
	}
	if addr, err := netip.ParseAddr(hops[idx]); err == nil {
		if addr.Is4In6() {
			addr = addr.Unmap()
		}
		b.SetIP(attr.SourceIP, addr)
		b.SetNum("network.ip_version", ipVersion(addr))
	}
	return b
}

// --- TLS --------------------------------------------------------------------

// FromTLS populates the tls.* namespace from a completed handshake.
func (b *Builder) FromTLS(cs *tls.ConnectionState) *Builder {
	if cs == nil {
		return b
	}
	b.Set(attr.TLSVersion, tlsVersionName(cs.Version))
	b.SetNum(attr.TLSVersionNo, tlsVersionNumber(cs.Version))
	b.Set(attr.CipherSuite, tls.CipherSuiteName(cs.CipherSuite))
	b.Set(attr.SNI, strings.ToLower(cs.ServerName))
	if cs.NegotiatedProtocol != "" {
		b.Set("tls.alpn", cs.NegotiatedProtocol)
	}

	if len(cs.PeerCertificates) > 0 {
		leaf := cs.PeerCertificates[0]
		b.Set("tls.client_cert_cn", leaf.Subject.CommonName)
		b.Set("tls.client_cert_issuer", leaf.Issuer.String())
		if leaf.SerialNumber != nil {
			b.Set("tls.client_cert_serial", leaf.SerialNumber.String())
		}
		days := time.Until(leaf.NotAfter).Hours() / 24
		b.SetNum("tls.client_cert_expires_in_days", days)
		// VerifiedChains is non-empty only when the handshake verified the chain
		// against the configured roots, so this reflects what crypto/tls actually
		// established rather than merely that a certificate was presented.
		b.SetBool("tls.client_cert_verified", len(cs.VerifiedChains) > 0)
	}
	return b
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	}
	return "unknown"
}

// tlsVersionNumber encodes a version for numeric comparison, so a policy can say
// "at least 1.2" once instead of enumerating every acceptable version and needing
// an edit when a new one ships.
//
// The scale must be monotonic in protocol age, and that is the whole subtlety.
// Encoding SSLv3 as its version number, 30, would place it above TLS 1.3's 13, so
// a `tls.version_num >= 12` floor would accept SSLv3 — precisely the connection
// the rule exists to reject. So SSLv3 is 3, and an unrecognized version is 0,
// which fails every floor a policy can express.
func tlsVersionNumber(v uint16) float64 {
	switch v {
	case tls.VersionSSL30:
		return 3
	case tls.VersionTLS10:
		return 10
	case tls.VersionTLS11:
		return 11
	case tls.VersionTLS12:
		return 12
	case tls.VersionTLS13:
		return 13
	}
	return 0
}

// --- Identity ---------------------------------------------------------------

// TokenInfo is the outcome of validating a bearer token, as decided by the
// caller's own verifier.
//
// This package deliberately does not verify signatures. Doing so requires key
// material, key rotation, clock policy and an audience list, all of which belong
// to the integration; a token library that quietly accepted alg=none inside an
// authorization engine would be a critical vulnerability. What arrives here is a
// verdict the caller already reached, mapped onto attributes so policies can
// require it.
type TokenInfo struct {
	Valid           bool
	SignatureValid  bool
	Algorithm       string
	Issuer          string
	Subject         string
	Audience        []string
	Scopes          []string
	ExpiresIn       time.Duration
	AdditionalClaim map[string]string
}

// FromToken populates the token.* namespace and any extra claims.
func (b *Builder) FromToken(t *TokenInfo) *Builder {
	if t == nil {
		return b
	}
	b.SetBool(attr.TokenValid, t.Valid)
	b.SetBool("token.signature_valid", t.SignatureValid)
	if t.Algorithm != "" {
		b.Set("token.algorithm", t.Algorithm)
	}
	if t.Issuer != "" {
		b.Set("token.issuer", t.Issuer)
	}
	if t.Subject != "" {
		b.Set("token.subject", t.Subject)
	}
	if len(t.Audience) > 0 {
		b.Set("token.audience", strings.Join(t.Audience, ","))
	}
	if len(t.Scopes) > 0 {
		b.Set(attr.TokenScopes, strings.Join(t.Scopes, ","))
	}
	b.SetNum("token.expires_in_seconds", t.ExpiresIn.Seconds())
	for name, value := range t.AdditionalClaim {
		b.Set(attr.Claim(name), value)
	}
	return b
}

// SubjectInfo is the authenticated principal, as resolved by the caller.
type SubjectInfo struct {
	ID            string
	Type          string
	Role          string
	Roles         []string
	Department    string
	Groups        []string
	MFAVerified   bool
	DeviceManaged bool
	RiskScore     float64
	AuthAge       time.Duration
}

// FromSubject populates the subject.* namespace.
func (b *Builder) FromSubject(s *SubjectInfo) *Builder {
	if s == nil {
		return b
	}
	if s.ID != "" {
		b.Set(attr.SubjectID, s.ID)
	}
	if s.Type != "" {
		b.Set("subject.type", s.Type)
	}
	if s.Role != "" {
		b.Set(attr.SubjectRole, s.Role)
	}
	if len(s.Roles) > 0 {
		b.Set("subject.roles", strings.Join(s.Roles, ","))
	}
	if s.Department != "" {
		b.Set("subject.department", s.Department)
	}
	if len(s.Groups) > 0 {
		b.Set("subject.groups", strings.Join(s.Groups, ","))
	}
	b.SetBool(attr.MFAVerified, s.MFAVerified)
	b.SetBool("subject.device_managed", s.DeviceManaged)
	b.SetNum(attr.RiskScore, s.RiskScore)
	if s.AuthAge > 0 {
		b.SetNum("subject.auth_age_seconds", s.AuthAge.Seconds())
	}
	return b
}

// --- Resource, action, time -------------------------------------------------

// FromResource names what is being acted on.
func (b *Builder) FromResource(resourceType, id, resourcePath, sensitivity string) *Builder {
	if resourceType != "" {
		b.Set(attr.ResourceType, resourceType)
	}
	if id != "" {
		b.Set("resource.id", id)
	}
	if resourcePath != "" {
		b.Set(attr.ResourcePath, resourcePath)
	}
	if sensitivity != "" {
		b.Set(attr.Sensitivity, strings.ToLower(sensitivity))
	}
	return b
}

// Action names the operation requested.
func (b *Builder) Action(action string) *Builder {
	return b.Set(attr.Action, strings.ToLower(action))
}

// AtTime populates the time.* namespace.
//
// The clock is passed in rather than read here so that a decision is
// reproducible: replaying an audited request must yield the same answer, which it
// cannot if the engine consults the wall clock itself. time.hour carries a
// fractional part so a window like [9, 17.5] means what it looks like.
func (b *Builder) AtTime(t time.Time) *Builder {
	b.SetNum(attr.TimeHour, float64(t.Hour())+float64(t.Minute())/60+float64(t.Second())/3600)
	b.SetNum("time.day_of_week", float64(t.Weekday()))
	b.SetNum("time.unix", float64(t.Unix()))
	return b
}

// --- Payload ----------------------------------------------------------------

// FromFileName populates the payload.* attributes derivable from a name alone.
func (b *Builder) FromFileName(name string) *Builder {
	if name == "" {
		return b
	}
	b.Set("payload.file_name", name)
	// The final extension only. "archive.tar.gz" reports ".gz", matching what
	// path.Ext yields and what a suffix condition on ".gz" expects.
	if ext := strings.ToLower(path.Ext(name)); ext != "" {
		b.Set(attr.FileExt, ext)
	}
	return b
}

// FromBody records an already-read body for regex, DLP and magic-number matching.
//
// It takes bytes rather than a reader, because consuming an http.Request.Body
// inside an authorization check would leave the handler with nothing to read.
// Callers that need body inspection should tee the body once at the edge and pass
// the buffer both here and downstream. Content is truncated to the builder's body
// limit.
func (b *Builder) FromBody(body []byte) *Builder {
	if len(body) == 0 {
		return b
	}
	if int64(len(body)) > b.bodyLimit {
		body = body[:b.bodyLimit]
	}
	b.Set(attr.PayloadBody, string(body))

	// Leading bytes as lowercase hex, for true-type detection against a declared
	// extension. Sixteen bytes covers every common magic number.
	n := len(body)
	if n > 16 {
		n = 16
	}
	const hexDigits = "0123456789abcdef"
	buf := make([]byte, 0, n*2)
	for _, c := range body[:n] {
		buf = append(buf, hexDigits[c>>4], hexDigits[c&0xf])
	}
	b.Set("payload.file_magic", string(buf))

	if sniffed := http.DetectContentType(body); sniffed != "" {
		if media, _, err := mime.ParseMediaType(sniffed); err == nil {
			b.Set("payload.detected_mime", strings.ToLower(media))
		}
	}
	return b
}

// --- Convenience ------------------------------------------------------------

// HTTPRequest is the common case in one call: an HTTP request plus its
// authenticated principal, at a given time.
//
// trustedHops is passed through to FromForwardedHeaders; pass 0 unless you
// operate proxies in front of this service, and read that method's documentation
// before passing anything else.
func HTTPRequest(tenantID, scope string, r *http.Request, subject *SubjectInfo,
	trustedHops int, now time.Time) model.Request {

	b := New(tenantID, scope).
		FromHTTPRequest(r).
		FromForwardedHeaders(r, trustedHops).
		FromSubject(subject).
		AtTime(now)

	if r != nil {
		// Method and path are the natural action and resource for an HTTP API, so
		// a policy can be written without the caller mapping them by hand. An
		// integration with richer semantics should override with FromResource.
		b.Action(httpMethodAction(r.Method))
		b.FromResource("http_endpoint", "", r.URL.Path, "")
		if remote := r.RemoteAddr; remote != "" {
			host, port := splitHostPort(remote)
			if addr, err := netip.ParseAddr(host); err == nil {
				if addr.Is4In6() {
					addr = addr.Unmap()
				}
				// Only if forwarded-header resolution did not already set it.
				if _, ok := b.ips[attr.SourceIP]; !ok {
					b.SetIP(attr.SourceIP, addr)
					b.SetNum("network.ip_version", ipVersion(addr))
				}
				if port > 0 {
					b.SetNum(attr.SourcePort, float64(port))
				}
			}
		}
	}
	return b.Build()
}

// httpMethodAction maps a verb onto the read/write/delete vocabulary policies use
// for actions, so an HTTP integration needs no mapping table of its own.
func httpMethodAction(method string) string {
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
