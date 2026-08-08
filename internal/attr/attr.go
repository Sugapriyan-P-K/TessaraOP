// Package attr is the canonical registry of attributes a request can carry.
//
// The engine evaluates named, already-typed attributes; it never decodes raw
// packets or raw HTTP bytes. This package is the contract between the two
// halves of that split: an ingestion adapter promises to populate these names
// with these types, and a policy author promises to reference only these names.
// Package ingest implements the adapter side using the standard library's
// audited parsers.
//
// Having the contract be data rather than convention buys three things a
// product needs. A policy that compares a numeric attribute with a string
// operator is rejected at load time instead of failing closed at runtime and
// looking like a rule that simply never fires. A customer onboarding against
// TessaraOP can be handed the list of attributes to supply rather than reading
// the evaluator. And the operator surface for each attribute is documented in
// one place that cannot drift from the code, since the linter reads it.
//
// # Naming
//
// Names are dotted and namespaced by protocol layer or by subject area:
//
//	network.*    layer 3, IP header
//	transport.*  layer 4, TCP/UDP/ICMP header
//	conn.*       connection state and volumetric counters
//	geo.*        geographic resolution of an address
//	threat.*     threat-intelligence enrichment
//	iface.*      ingress and egress interface
//	http.*       layer 7, HTTP request and response structure
//	payload.*    decoded body content and signature results
//	tls.*        TLS handshake and client certificate metadata
//	subject.*    the authenticated principal
//	token.*      bearer token / JWT claim validation results
//	session.*    server-side session state
//	api.*        API key presence and identity
//	bot.*        bot-detection and challenge outcome
//	graphql.*    GraphQL operation shape
//	ws.*         WebSocket upgrade attempts
//	resource.*   the object being acted on
//	action       the operation requested
//	time.*       evaluation-time clock attributes
//
// Four namespaces are open-ended, because their key space belongs to the
// customer's traffic rather than to this registry: http.header.*, http.query.*,
// http.cookie.* and subject.claim.*.
package attr

import (
	"sort"
	"strings"

	"github.com/suga/tessaraop/internal/model"
)

// Kind is the value type an attribute carries, and therefore which map on
// model.Request holds it.
type Kind uint8

const (
	KindString  Kind = iota // model.Request.Attributes
	KindNumeric             // model.Request.Numeric
	KindIP                  // model.Request.IPs
)

func (k Kind) String() string {
	switch k {
	case KindString:
		return "string"
	case KindNumeric:
		return "numeric"
	case KindIP:
		return "ip"
	}
	return "unknown"
}

// Layer groups attributes for documentation and for the onboarding checklist an
// integrator works through.
type Layer uint8

const (
	LayerNetwork   Layer = iota // L3
	LayerTransport              // L4
	LayerConn                   // connection state, rate and volume
	LayerInfra                  // geo, threat intel, interfaces
	LayerHTTP                   // L7 structure
	LayerPayload                // decoded content
	LayerTLS                    // handshake and certificates
	LayerIdentity               // principal, token, session
	LayerResource               // resource, action, time
)

var layerNames = [...]string{
	"network(L3)", "transport(L4)", "connection", "infrastructure",
	"http(L7)", "payload", "tls", "identity", "resource",
}

func (l Layer) String() string {
	if int(l) < len(layerNames) {
		return layerNames[l]
	}
	return "unknown"
}

// Attribute is one registry entry.
type Attribute struct {
	Name  string
	Kind  Kind
	Layer Layer
	Doc   string

	// Dynamic marks an open-ended namespace rather than a single attribute.
	// Name then ends in a dot and matches any attribute under it.
	Dynamic bool
}

// s, n and ip are terse constructors so the table below reads as a table.
func s(name string, l Layer, doc string) Attribute {
	return Attribute{Name: name, Kind: KindString, Layer: l, Doc: doc}
}
func n(name string, l Layer, doc string) Attribute {
	return Attribute{Name: name, Kind: KindNumeric, Layer: l, Doc: doc}
}
func ip(name string, l Layer, doc string) Attribute {
	return Attribute{Name: name, Kind: KindIP, Layer: l, Doc: doc}
}
func dyn(prefix string, k Kind, l Layer, doc string) Attribute {
	return Attribute{Name: prefix, Kind: k, Layer: l, Doc: doc, Dynamic: true}
}

// Catalog is every registered attribute, in layer order.
//
// Several protocol fields are registered twice under different types, because
// policies ask two different questions of them. tls.version is a string for
// exact-set membership ("reject SSLv3, TLS1.0, TLS1.1") while tls.version_num
// is numeric for a floor ("require at least 1.2") — expressing the floor as a
// string set means editing every policy when a new version ships. The same
// reasoning applies to network.protocol / protocol_name.
var Catalog = []Attribute{
	// -- Layer 3: IP header --
	ip("network.source_ip", LayerNetwork, "Address originating the packet."),
	ip("network.dest_ip", LayerNetwork, "Address receiving the packet."),
	n("network.ip_version", LayerNetwork, "4 or 6."),
	n("network.protocol", LayerNetwork, "IP protocol number: 1 ICMP, 2 IGMP, 6 TCP, 17 UDP, 47 GRE, 50 ESP."),
	s("network.protocol_name", LayerNetwork, "Lowercased protocol name, for set membership instead of numbers."),
	n("network.ttl", LayerNetwork, "TTL / hop limit. Low or unusual values indicate traceroute and OS fingerprinting."),
	s("network.ip_options", LayerNetwork, "Comma-joined IP option names present, e.g. lsrr,ssrr,rr. Empty when none."),
	s("network.fragment_flags", LayerNetwork, "Comma-joined fragmentation flags set: df, mf."),
	n("network.fragment_offset", LayerNetwork, "Fragment offset in 8-byte units. Non-zero on a non-first fragment."),
	n("network.dscp", LayerNetwork, "DSCP code point, 0-63."),
	n("network.tos", LayerNetwork, "Legacy ToS byte."),

	// -- Layer 4: transport header --
	n("transport.source_port", LayerTransport, "Originating port, typically ephemeral."),
	n("transport.dest_port", LayerTransport, "Target service port."),
	s("transport.tcp_flags", LayerTransport, "Comma-joined flags set, ascending: ack,cwr,ece,fin,psh,rst,syn,urg."),
	n("transport.tcp_seq", LayerTransport, "TCP sequence number."),
	n("transport.tcp_window", LayerTransport, "TCP receive window size."),
	n("transport.icmp_type", LayerTransport, "ICMP type, e.g. 8 echo request, 3 destination unreachable."),
	n("transport.icmp_code", LayerTransport, "ICMP code within the type."),

	// -- Connection state and volumetrics --
	s("conn.state", LayerConn, "Firewall state table verdict: new, established, related, invalid."),
	n("conn.rate_per_sec", LayerConn, "New connections per second from this source."),
	n("conn.concurrent", LayerConn, "Currently open connections from this source."),
	n("conn.packets_per_sec", LayerConn, "Packets per second on this flow or source."),
	n("conn.bytes_per_sec", LayerConn, "Bytes per second on this flow or source."),
	n("conn.idle_seconds", LayerConn, "Seconds this connection has been idle."),
	n("conn.duration_seconds", LayerConn, "Seconds since the connection opened."),

	// -- Infrastructure and threat intelligence --
	s("geo.country", LayerInfra, "ISO 3166-1 alpha-2 country code, uppercase."),
	s("geo.continent", LayerInfra, "Two-letter continent code."),
	s("geo.city", LayerInfra, "Resolved city name."),
	n("threat.ip_reputation", LayerInfra, "Reputation score, 0 clean to 100 known-malicious."),
	s("threat.proxy_type", LayerInfra, "Anonymizer classification: none, tor, vpn, proxy, hosting, relay."),
	n("threat.asn", LayerInfra, "Autonomous system number of the source address."),
	s("threat.as_org", LayerInfra, "Autonomous system organisation name."),
	s("threat.categories", LayerInfra, "Comma-joined feed categories, e.g. botnet,scanner,spam."),
	s("iface.inbound", LayerInfra, "Ingress interface, e.g. eth0, wan1, vlan10."),
	s("iface.outbound", LayerInfra, "Egress interface."),

	// -- Layer 7: HTTP structure --
	s("http.method", LayerHTTP, "Uppercase verb: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, TRACE, CONNECT."),
	s("http.path", LayerHTTP, "Decoded request path, no query string. Normalize before populating."),
	s("http.raw_path", LayerHTTP, "Path exactly as received, before normalization. Compare the two to detect traversal."),
	s("http.query", LayerHTTP, "Raw query string, without the leading question mark."),
	s("http.host", LayerHTTP, "Host header, lowercased, port stripped."),
	s("http.version", LayerHTTP, "Protocol version string: HTTP/1.0, HTTP/1.1, HTTP/2, HTTP/3."),
	s("http.user_agent", LayerHTTP, "User-Agent header verbatim."),
	s("http.referer", LayerHTTP, "Referer header verbatim."),
	s("http.content_type", LayerHTTP, "Content-Type media type, parameters stripped and lowercased."),
	n("http.content_length", LayerHTTP, "Declared or observed body length in bytes."),
	s("http.authorization_scheme", LayerHTTP, "Lowercased auth scheme: bearer, basic, negotiate."),
	s("http.multipart_boundary", LayerHTTP, "Multipart boundary token, for structural inspection of uploads."),
	n("http.status", LayerHTTP, "Downstream response status. Response-phase rules only."),
	n("http.header_count", LayerHTTP, "Number of headers received."),
	n("http.uri_length", LayerHTTP, "Length of the full request URI in bytes."),
	dyn("http.header.", KindString, LayerHTTP, "Any request header by lowercased name, e.g. http.header.x-forwarded-for."),
	dyn("http.query.", KindString, LayerHTTP, "Any query parameter by name, e.g. http.query.id. First value wins."),
	dyn("http.cookie.", KindString, LayerHTTP, "A cookie by name, e.g. http.cookie.locale. The ingest adapter populates only cookies an integrator allowlists, since cookie values are frequently credentials."),

	// -- Payload content and signature results --
	s("payload.body", LayerPayload, "Decoded body, for regex and DLP scanning. Populate only when inspection is enabled."),
	s("payload.file_name", LayerPayload, "Uploaded file name as declared."),
	s("payload.file_ext", LayerPayload, "Lowercased extension including the dot, e.g. .exe, .php."),
	s("payload.file_magic", LayerPayload, "Leading body bytes as lowercase hex, for true-type detection."),
	s("payload.declared_mime", LayerPayload, "MIME type the client claimed."),
	s("payload.detected_mime", LayerPayload, "MIME type sniffed from content. Disagreement with declared_mime is the signal."),
	s("payload.schema_valid", LayerPayload, "\"true\" or \"false\": JSON/XML body validated against the endpoint schema."),
	s("payload.schema_errors", LayerPayload, "Comma-joined schema violation names."),
	n("payload.dlp_matches", LayerPayload, "Count of DLP pattern hits in the inspected content."),
	s("payload.dlp_categories", LayerPayload, "Comma-joined DLP categories hit, e.g. pan,ssn,api_key."),
	n("payload.entropy", LayerPayload, "Shannon entropy of the body, for packed or encrypted payload detection."),

	// -- TLS handshake and certificates --
	s("tls.version", LayerTLS, "Negotiated version string: SSLv3, TLS1.0, TLS1.1, TLS1.2, TLS1.3."),
	n("tls.version_num", LayerTLS, "Negotiated version on a monotonic scale: SSLv3 -> 3, TLS 1.0-1.3 -> 10, 11, 12, 13, unknown -> 0. Ordered by age so a floor like >=12 rejects everything older."),
	s("tls.cipher_suite", LayerTLS, "IANA cipher suite name, e.g. TLS_AES_128_GCM_SHA256."),
	s("tls.sni", LayerTLS, "Server Name Indication from the handshake, lowercased."),
	s("tls.alpn", LayerTLS, "Negotiated ALPN protocol, e.g. h2, http/1.1."),
	s("tls.client_cert_cn", LayerTLS, "Client certificate subject common name."),
	s("tls.client_cert_issuer", LayerTLS, "Client certificate issuer distinguished name."),
	s("tls.client_cert_serial", LayerTLS, "Client certificate serial number."),
	s("tls.client_cert_verified", LayerTLS, "\"true\" or \"false\": chain verified against the trusted CA set."),
	s("tls.client_cert_revoked", LayerTLS, "\"true\", \"false\" or \"unknown\" from CRL/OCSP."),
	n("tls.client_cert_expires_in_days", LayerTLS, "Days until the client certificate expires; negative when already expired."),
	s("tls.ja3", LayerTLS, "JA3 client hello fingerprint, for stack identification."),

	// -- Identity, token and session --
	s("subject.id", LayerIdentity, "Stable principal identifier."),
	s("subject.type", LayerIdentity, "Principal class: user, service, device."),
	s("subject.role", LayerIdentity, "Primary role."),
	s("subject.roles", LayerIdentity, "Comma-joined roles. Carries the transitive closure when a role hierarchy is configured, so it is a superset of subject.role. Match with has_any / has_all / has_none, never contains."),
	s("subject.department", LayerIdentity, "Organisational unit."),
	s("subject.groups", LayerIdentity, "Comma-joined group memberships, transitively closed when a group hierarchy is configured. Match with has_any / has_all / has_none, never contains."),
	s("subject.mfa_verified", LayerIdentity, "\"true\" or \"false\"."),
	s("subject.device_managed", LayerIdentity, "\"true\" or \"false\": device is enrolled and compliant."),
	n("subject.risk_score", LayerIdentity, "Continuous risk assessment, 0 to 100."),
	n("subject.auth_age_seconds", LayerIdentity, "Seconds since the principal last authenticated."),
	s("token.valid", LayerIdentity, "\"true\" or \"false\": signature, expiry and audience all checked."),
	s("token.signature_valid", LayerIdentity, "\"true\" or \"false\": cryptographic signature alone."),
	s("token.algorithm", LayerIdentity, "JWS algorithm from the header, e.g. RS256. Reject \"none\"."),
	s("token.issuer", LayerIdentity, "iss claim."),
	s("token.subject", LayerIdentity, "sub claim."),
	s("token.audience", LayerIdentity, "Comma-joined aud claim."),
	s("token.scopes", LayerIdentity, "Comma-joined scope or scp claim."),
	n("token.expires_in_seconds", LayerIdentity, "Seconds until exp; negative when already expired."),
	dyn("subject.claim.", KindString, LayerIdentity, "Any additional token claim by name, e.g. subject.claim.tenant."),
	s("session.id", LayerIdentity, "Server-side session identifier."),
	s("session.valid", LayerIdentity, "\"true\" or \"false\": session found and active in the backing store."),
	n("session.age_seconds", LayerIdentity, "Seconds since the session was created."),
	s("api.key_present", LayerIdentity, "\"true\" or \"false\"."),
	s("api.key_id", LayerIdentity, "Identifier of the presented API key. Never the key itself."),
	s("bot.challenge_passed", LayerIdentity, "\"true\" or \"false\": CAPTCHA or silent browser challenge cleared."),
	n("bot.score", LayerIdentity, "Automation likelihood, 0 human to 100 bot."),

	// -- Resource, action and time --
	s("resource.id", LayerResource, "Identifier of the object acted on."),
	s("resource.type", LayerResource, "Object class, e.g. document, bucket, endpoint."),
	s("resource.domain", LayerResource, "Fully qualified host of the resource. Use dnssuffix, never suffix."),
	s("resource.path", LayerResource, "Hierarchical path of the resource."),
	s("resource.sensitivity", LayerResource, "Classification: low, medium, high, critical."),
	s("resource.owner", LayerResource, "Principal owning the resource, for relationship checks."),
	s("resource.ancestors", LayerResource, "Comma-joined containment ancestors of the resource, closest first, including the resource itself. Match with has_any so a policy scoped to a folder or project covers everything beneath it."),
	s("action", LayerResource, "Operation requested, e.g. read, write, delete, admin."),
	n("graphql.depth", LayerResource, "Maximum nesting depth of the incoming query."),
	n("graphql.complexity", LayerResource, "Computed cost score of the incoming query."),
	s("graphql.operation", LayerResource, "Named GraphQL operation."),
	s("ws.upgrade_requested", LayerResource, "\"true\" or \"false\": the request asks to become a WebSocket."),
	s("ws.protocol", LayerResource, "Requested WebSocket subprotocol."),
	n("time.hour", LayerResource, "Hour of day in the evaluating zone, 0 to 24 with a fractional part."),
	n("time.day_of_week", LayerResource, "0 Sunday through 6 Saturday."),
	n("time.unix", LayerResource, "Evaluation timestamp in Unix seconds."),
}

// Well-known attribute names, so Go callers get a compile-time check rather
// than discovering a typo as a rule that silently never matches. The registry
// covers far more names than this; these are the ones integrations touch most.
const (
	SourceIP     = "network.source_ip"
	DestIP       = "network.dest_ip"
	IPProtocol   = "network.protocol"
	SourcePort   = "transport.source_port"
	DestPort     = "transport.dest_port"
	TCPFlags     = "transport.tcp_flags"
	ConnState    = "conn.state"
	GeoCountry   = "geo.country"
	ThreatRep    = "threat.ip_reputation"
	ProxyType    = "threat.proxy_type"
	ASN          = "threat.asn"
	HTTPMethod   = "http.method"
	HTTPPath     = "http.path"
	HTTPHost     = "http.host"
	HTTPQuery    = "http.query"
	UserAgent    = "http.user_agent"
	ContentType  = "http.content_type"
	ContentLen   = "http.content_length"
	HTTPStatus   = "http.status"
	HTTPVersion  = "http.version"
	PayloadBody  = "payload.body"
	FileExt      = "payload.file_ext"
	TLSVersion   = "tls.version"
	TLSVersionNo = "tls.version_num"
	CipherSuite  = "tls.cipher_suite"
	SNI          = "tls.sni"
	SubjectID    = "subject.id"
	SubjectRole  = "subject.role"
	MFAVerified  = "subject.mfa_verified"
	RiskScore    = "subject.risk_score"
	TokenValid   = "token.valid"
	TokenScopes  = "token.scopes"
	ResourceType = "resource.type"
	ResourcePath = "resource.path"
	Sensitivity  = "resource.sensitivity"
	Action       = "action"
	TimeHour     = "time.hour"

	// HeaderPrefix and friends build names in the open-ended namespaces.
	HeaderPrefix = "http.header."
	QueryPrefix  = "http.query."
	CookiePrefix = "http.cookie."
	ClaimPrefix  = "subject.claim."
)

// Header returns the attribute name for an HTTP request header. The name is
// lowercased, matching what the ingest adapter populates.
func Header(name string) string { return HeaderPrefix + strings.ToLower(name) }

// QueryParam returns the attribute name for a query parameter.
func QueryParam(name string) string { return QueryPrefix + name }

// Cookie returns the attribute name for a cookie.
func Cookie(name string) string { return CookiePrefix + name }

// Claim returns the attribute name for a token claim.
func Claim(name string) string { return ClaimPrefix + name }

var (
	exact   map[string]Attribute
	dynamic []Attribute
)

func init() {
	exact = make(map[string]Attribute, len(Catalog))
	for _, a := range Catalog {
		if a.Dynamic {
			dynamic = append(dynamic, a)
			continue
		}
		exact[a.Name] = a
	}
	// Longest prefix first, so a more specific namespace added later still
	// wins over a broader one.
	sort.Slice(dynamic, func(i, j int) bool {
		return len(dynamic[i].Name) > len(dynamic[j].Name)
	})
}

// Lookup resolves an attribute name, matching exact entries first and then
// open-ended namespaces by prefix.
func Lookup(name string) (Attribute, bool) {
	if a, ok := exact[name]; ok {
		return a, true
	}
	for _, d := range dynamic {
		if strings.HasPrefix(name, d.Name) && len(name) > len(d.Name) {
			a := d
			a.Name = name
			return a, true
		}
	}
	return Attribute{}, false
}

// Names returns every non-dynamic attribute name, sorted.
func Names() []string {
	out := make([]string, 0, len(exact))
	for k := range exact {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ByLayer returns every attribute in a layer, in catalog order.
func ByLayer(l Layer) []Attribute {
	var out []Attribute
	for _, a := range Catalog {
		if a.Layer == l {
			out = append(out, a)
		}
	}
	return out
}

// KindFor reports the registered type of an attribute.
func KindFor(name string) (Kind, bool) {
	a, ok := Lookup(name)
	return a.Kind, ok
}

// Accepts reports whether an operator can be applied to this attribute's type.
// Presence operators apply to every kind; the rest must match the family.
func (a Attribute) Accepts(op model.Operator) bool {
	f := op.Family()
	if f == model.FamilyPresence {
		return true
	}
	switch a.Kind {
	case KindString:
		return f == model.FamilyString
	case KindNumeric:
		return f == model.FamilyNumeric
	case KindIP:
		return f == model.FamilyNetwork
	}
	return false
}

// Operators lists every operator valid on this attribute, for documentation and
// for authoring tools that offer completions.
func (a Attribute) Operators() []model.Operator {
	var out []model.Operator
	for _, op := range model.AllOperators {
		if a.Accepts(op) {
			out = append(out, op)
		}
	}
	return out
}
