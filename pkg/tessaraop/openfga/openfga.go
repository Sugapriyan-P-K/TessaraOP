// Package openfga resolves relationships from an OpenFGA server.
//
// # Why this exists as an adapter rather than as storage
//
// TessaraOP does not store relationship tuples. That decision is recorded in
// COMPARISON.md §7.1: a tuple store needs a database, which would turn a
// stateless drop-in component into a stateful service and end the
// zero-dependency property. Relationships are consumed instead, and this is the
// consumer for the most widely deployed open implementation of the Zanzibar
// model.
//
// # Why it uses net/http rather than the OpenFGA SDK
//
// The SDK would be the first external dependency in the module, in the package
// closest to the request path. OpenFGA's Check API is a small JSON POST, so the
// standard library covers it, and the dependency count stays at zero.
//
// # What it does
//
// One Check call per relation named in your policies. OpenFGA answers
// "does this user hold this relation on this object" and does the graph
// traversal — group nesting, folder containment, userset rewrites — server-side,
// which is exactly the work this package deliberately does not reimplement.
//
// The relations to check must be listed, because there is no cheap way to
// enumerate "every relation this user holds" in the Check API and checking every
// relation in the model would be round trips you do not need. The set that
// appears in a policy bundle is small and known at load time.
//
//	resolver := openfga.New(openfga.Config{
//	    Endpoint:  "http://localhost:8080",
//	    StoreID:   storeID,
//	    Relations: []string{"owner", "editor", "viewer"},
//	})
//	req := tessaraop.NewRequest("acme", "docs").Build()
//	err := tessaraop.ResolveRelations(ctx, resolver, &req, "user:anne", "document:budget")
//
// # Failure handling
//
// A failed check fails the whole resolution rather than returning the relations
// gathered so far. A truncated relation set narrows access silently, which in an
// authorization path is an outage disguised as a decision. Wrap this in
// tessaraop.RelationTimeout, and put a tessaraop.NewStaticRelations in front of it
// through a Chain if you need a locally-known subset to survive an outage.
package openfga

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Config describes the server and what to ask it.
type Config struct {
	// Endpoint is the OpenFGA HTTP base URL, e.g. http://localhost:8080.
	Endpoint string

	// StoreID identifies the store. Required.
	StoreID string

	// AuthorizationModelID pins the model version.
	//
	// Leaving it empty makes OpenFGA use the latest model, which means a model
	// change silently changes authorization decisions. Pin it in production and
	// roll it forward deliberately, the same way the policy bundle generation is
	// rolled forward.
	AuthorizationModelID string

	// Relations to check. Required: this is the set your policies name.
	Relations []string

	// Token, when set, is sent as a Bearer credential.
	Token string

	// HTTPClient overrides the default. The default sets a timeout, because an
	// unbounded call to a relationship store sits in the request path.
	HTTPClient *http.Client
}

// Resolver implements tessaraop.RelationResolver against an OpenFGA server.
type Resolver struct {
	cfg    Config
	client *http.Client
}

// DefaultTimeout bounds a single Check call.
const DefaultTimeout = 3 * time.Second

// New builds a resolver. It does not contact the server; the first Relations call
// does.
func New(cfg Config) *Resolver {
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: DefaultTimeout}
	}
	cfg.Endpoint = strings.TrimSuffix(cfg.Endpoint, "/")
	return &Resolver{cfg: cfg, client: client}
}

// Validate reports a configuration that cannot work, so a caller finds out at
// startup rather than on the first request.
func (r *Resolver) Validate() error {
	switch {
	case r.cfg.Endpoint == "":
		return fmt.Errorf("openfga: Endpoint is required")
	case r.cfg.StoreID == "":
		return fmt.Errorf("openfga: StoreID is required")
	case len(r.cfg.Relations) == 0:
		return fmt.Errorf("openfga: Relations is required; list the relations your " +
			"policies name, since Check answers one relation at a time")
	}
	if _, err := url.Parse(r.cfg.Endpoint); err != nil {
		return fmt.Errorf("openfga: Endpoint is not a URL: %w", err)
	}
	return nil
}

// Relations implements tessaraop.RelationResolver.
//
// Checks run sequentially rather than in parallel. The relation list is short —
// the handful a policy set names — and firing concurrent requests per
// authorization decision multiplies load on the relationship store by that
// factor, which is the wrong trade for a component already in the request path.
func (r *Resolver) Relations(ctx context.Context, subject, object string) ([]string, error) {
	if subject == "" || object == "" {
		return nil, nil
	}
	var held []string
	for _, relation := range r.cfg.Relations {
		ok, err := r.check(ctx, subject, relation, object)
		if err != nil {
			// Never a partial answer. See the package documentation.
			return nil, fmt.Errorf("openfga: checking %q on %q for %q: %w",
				relation, object, subject, err)
		}
		if ok {
			held = append(held, relation)
		}
	}
	return held, nil
}

type checkRequest struct {
	TupleKey             tupleKey `json:"tuple_key"`
	AuthorizationModelID string   `json:"authorization_model_id,omitempty"`
}

type tupleKey struct {
	User     string `json:"user"`
	Relation string `json:"relation"`
	Object   string `json:"object"`
}

type checkResponse struct {
	Allowed bool `json:"allowed"`
}

func (r *Resolver) check(ctx context.Context, subject, relation, object string) (bool, error) {
	body, err := json.Marshal(checkRequest{
		TupleKey:             tupleKey{User: subject, Relation: relation, Object: object},
		AuthorizationModelID: r.cfg.AuthorizationModelID,
	})
	if err != nil {
		return false, err
	}

	endpoint := fmt.Sprintf("%s/stores/%s/check", r.cfg.Endpoint, url.PathEscape(r.cfg.StoreID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	if r.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+r.cfg.Token)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	// The body is bounded before reading: this is a network peer, and an
	// unbounded read from one in a request path is a memory-exhaustion vector.
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return false, err
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("status %d: %s", resp.StatusCode,
			strings.TrimSpace(string(payload)))
	}

	var out checkResponse
	if err := json.Unmarshal(payload, &out); err != nil {
		return false, fmt.Errorf("malformed response: %w", err)
	}
	return out.Allowed, nil
}
