package attr

import (
	"strings"
	"testing"

	"github.com/suga/tessaraop/internal/model"
)

func TestCatalog_NoDuplicateNames(t *testing.T) {
	seen := map[string]bool{}
	for _, a := range Catalog {
		if seen[a.Name] {
			t.Errorf("duplicate registry entry %q", a.Name)
		}
		seen[a.Name] = true
	}
}

func TestCatalog_EveryEntryIsDocumented(t *testing.T) {
	// The registry is the onboarding checklist an integrator reads, so an
	// undocumented entry is a real gap rather than a style nit.
	for _, a := range Catalog {
		if a.Doc == "" {
			t.Errorf("attribute %q has no documentation", a.Name)
		}
		if !strings.Contains(a.Name, ".") && a.Name != "action" {
			t.Errorf("attribute %q is not namespaced", a.Name)
		}
	}
}

func TestCatalog_DynamicEntriesEndInADot(t *testing.T) {
	for _, a := range Catalog {
		if a.Dynamic && !strings.HasSuffix(a.Name, ".") {
			t.Errorf("dynamic namespace %q must end in a dot", a.Name)
		}
		if !a.Dynamic && strings.HasSuffix(a.Name, ".") {
			t.Errorf("non-dynamic attribute %q must not end in a dot", a.Name)
		}
	}
}

func TestLookup_Exact(t *testing.T) {
	a, ok := Lookup(SourceIP)
	if !ok {
		t.Fatalf("%s must be registered", SourceIP)
	}
	if a.Kind != KindIP {
		t.Errorf("%s should be an IP attribute, got %s", SourceIP, a.Kind)
	}
	if a.Layer != LayerNetwork {
		t.Errorf("%s should be layer 3, got %s", SourceIP, a.Layer)
	}
}

func TestLookup_DynamicNamespaces(t *testing.T) {
	cases := []struct {
		name string
		kind Kind
	}{
		{Header("X-Forwarded-For"), KindString},
		{QueryParam("id"), KindString},
		{Cookie("session"), KindString},
		{Claim("tenant"), KindString},
	}
	for _, tc := range cases {
		a, ok := Lookup(tc.name)
		if !ok {
			t.Errorf("%q should resolve through a dynamic namespace", tc.name)
			continue
		}
		if a.Kind != tc.kind {
			t.Errorf("%q resolved to kind %s, want %s", tc.name, a.Kind, tc.kind)
		}
		if a.Name != tc.name {
			t.Errorf("resolved entry should carry the full name, got %q", a.Name)
		}
	}
}

// TestLookup_BareNamespaceIsNotAnAttribute checks that the prefix itself does not
// resolve. "http.header." names a namespace, not a value a request can carry.
func TestLookup_BareNamespaceIsNotAnAttribute(t *testing.T) {
	for _, p := range []string{HeaderPrefix, QueryPrefix, CookiePrefix, ClaimPrefix} {
		if _, ok := Lookup(p); ok {
			t.Errorf("bare namespace %q must not resolve to an attribute", p)
		}
	}
}

func TestLookup_UnknownName(t *testing.T) {
	if _, ok := Lookup("not.a.real.attribute"); ok {
		t.Fatal("an unregistered name must not resolve")
	}
}

func TestHeader_LowercasesTheName(t *testing.T) {
	// The ingest adapter populates lowercased header names, so the constructor
	// must agree or a policy referencing X-Real-IP would never match.
	if got, want := Header("X-Real-IP"), "http.header.x-real-ip"; got != want {
		t.Fatalf("Header = %q want %q", got, want)
	}
}

// TestAccepts_MatchesOperatorFamilies is the check that gives the registry its
// value: applying a numeric comparison to a string attribute must be rejectable
// at load time, because at runtime it fails closed and looks exactly like a rule
// that simply never fires.
func TestAccepts_MatchesOperatorFamilies(t *testing.T) {
	str, _ := Lookup(SubjectRole)
	num, _ := Lookup(RiskScore)
	ip, _ := Lookup(SourceIP)

	cases := []struct {
		attr Attribute
		op   model.Operator
		want bool
	}{
		{str, model.OpEquals, true},
		{str, model.OpRegex, true},
		{str, model.OpGreaterThan, false},
		{str, model.OpCIDR, false},

		{num, model.OpRange, true},
		{num, model.OpNumIn, true},
		{num, model.OpEquals, false},
		{num, model.OpCIDR, false},

		{ip, model.OpCIDR, true},
		{ip, model.OpNotCIDR, true},
		{ip, model.OpEquals, false},
		{ip, model.OpRange, false},

		// Presence operators read whichever map holds the attribute, so they
		// apply to every kind.
		{str, model.OpExists, true},
		{num, model.OpExists, true},
		{ip, model.OpNotExists, true},
	}
	for _, tc := range cases {
		if got := tc.attr.Accepts(tc.op); got != tc.want {
			t.Errorf("%s (%s).Accepts(%s) = %v want %v",
				tc.attr.Name, tc.attr.Kind, tc.op, got, tc.want)
		}
	}
}

func TestOperators_ListsOnlyValidOnes(t *testing.T) {
	num, _ := Lookup(DestPort)
	ops := num.Operators()
	if len(ops) == 0 {
		t.Fatal("a numeric attribute must accept some operators")
	}
	for _, op := range ops {
		if !num.Accepts(op) {
			t.Errorf("Operators() listed %s, which Accepts rejects", op)
		}
	}
	for _, op := range model.AllOperators {
		if num.Accepts(op) {
			continue
		}
		for _, listed := range ops {
			if listed == op {
				t.Errorf("Operators() listed the invalid operator %s", op)
			}
		}
	}
}

func TestByLayer_CoversTheWholeCatalog(t *testing.T) {
	total := 0
	for _, l := range []Layer{
		LayerNetwork, LayerTransport, LayerConn, LayerInfra,
		LayerHTTP, LayerPayload, LayerTLS, LayerIdentity, LayerResource,
	} {
		in := ByLayer(l)
		if len(in) == 0 {
			t.Errorf("layer %s has no attributes", l)
		}
		total += len(in)
	}
	if total != len(Catalog) {
		t.Fatalf("layers cover %d attributes but the catalog holds %d", total, len(Catalog))
	}
}

func TestNames_IsSortedAndExcludesNamespaces(t *testing.T) {
	names := Names()
	for i := 1; i < len(names); i++ {
		if names[i-1] >= names[i] {
			t.Fatalf("Names() is not sorted at %d: %q then %q", i, names[i-1], names[i])
		}
	}
	for _, n := range names {
		if strings.HasSuffix(n, ".") {
			t.Errorf("Names() should not include the namespace %q", n)
		}
	}
}

// TestWellKnownConstantsAreRegistered guards against a constant drifting from the
// catalog entry it names. The constants exist so a typo is a compile error; that
// only helps if they resolve.
func TestWellKnownConstantsAreRegistered(t *testing.T) {
	for _, name := range []string{
		SourceIP, DestIP, IPProtocol, SourcePort, DestPort, TCPFlags,
		ConnState, GeoCountry, ThreatRep, ProxyType, ASN,
		HTTPMethod, HTTPPath, HTTPHost, HTTPQuery, UserAgent,
		ContentType, ContentLen, HTTPStatus, HTTPVersion,
		PayloadBody, FileExt,
		TLSVersion, TLSVersionNo, CipherSuite, SNI,
		SubjectID, SubjectRole, MFAVerified, RiskScore,
		TokenValid, TokenScopes,
		ResourceType, ResourcePath, Sensitivity, Action, TimeHour,
	} {
		if _, ok := Lookup(name); !ok {
			t.Errorf("well-known constant %q is not in the catalog", name)
		}
	}
}

// TestVersionAttributesComeInBothTypes documents why some protocol fields are
// registered twice. A version floor ("at least TLS 1.2") needs a numeric
// comparison; an exclusion list ("reject SSLv3, TLS1.0, TLS1.1") needs string set
// membership. Expressing the floor as a string set means editing every policy
// whenever a new version ships.
func TestVersionAttributesComeInBothTypes(t *testing.T) {
	str, ok := Lookup(TLSVersion)
	if !ok || str.Kind != KindString {
		t.Fatalf("%s should be a string attribute", TLSVersion)
	}
	num, ok := Lookup(TLSVersionNo)
	if !ok || num.Kind != KindNumeric {
		t.Fatalf("%s should be a numeric attribute", TLSVersionNo)
	}

	if !num.Accepts(model.OpGreaterEq) {
		t.Error("the numeric form must support a version floor")
	}
	if !str.Accepts(model.OpIn) {
		t.Error("the string form must support set membership")
	}
}
