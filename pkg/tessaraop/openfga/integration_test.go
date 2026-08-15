package openfga_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/suga/tessaraop/pkg/tessaraop"
	"github.com/suga/tessaraop/pkg/tessaraop/openfga"
)

// This exercises the adapter against a real OpenFGA server rather than a mock of
// it. A mock would only confirm the adapter matches my reading of the API, which
// is precisely the thing worth doubting — the whole reason COMPARISON.md said no
// adapter would ship until one could be verified.
//
// The server is started in-process with in-memory storage. If the binary is not
// installed the test skips, so the suite still passes on a machine without it:
//
//	go install github.com/openfga/openfga/cmd/openfga@latest

// server is a running OpenFGA instance.
type server struct {
	baseURL string
	cmd     *exec.Cmd
	client  *http.Client
}

func openfgaBinary() string {
	name := "openfga"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	candidate := filepath.Join(home, "go", "bin", name)
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	return ""
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func startServer(t *testing.T) *server {
	t.Helper()
	bin := openfgaBinary()
	if bin == "" {
		t.Skip("openfga binary not found; " +
			"install with: go install github.com/openfga/openfga/cmd/openfga@latest")
	}

	httpPort := freePort(t)
	grpcPort := freePort(t)

	cmd := exec.Command(bin, "run",
		"--http-addr", fmt.Sprintf("127.0.0.1:%d", httpPort),
		"--grpc-addr", fmt.Sprintf("127.0.0.1:%d", grpcPort),
		"--datastore-engine", "memory",
		"--log-level", "error",
	)
	if err := cmd.Start(); err != nil {
		t.Skipf("could not start openfga: %v", err)
	}

	s := &server{
		baseURL: fmt.Sprintf("http://127.0.0.1:%d", httpPort),
		cmd:     cmd,
		client:  &http.Client{Timeout: 5 * time.Second},
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	// Wait for it to accept connections.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := s.client.Get(s.baseURL + "/healthz")
		if err == nil {
			resp.Body.Close()
			return s
		}
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			t.Skipf("openfga exited during startup")
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Skip("openfga did not become ready within 30s")
	return nil
}

func (s *server) post(t *testing.T, path string, body any, out any) {
	t.Helper()
	blob, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp, err := s.client.Post(s.baseURL+path, "application/json", bytes.NewReader(blob))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()

	payload, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST %s: status %d: %s", path, resp.StatusCode, payload)
	}
	if out != nil {
		if err := json.Unmarshal(payload, out); err != nil {
			t.Fatalf("decode %s: %v (body %s)", path, err, payload)
		}
	}
}

// setup creates a store, writes an authorization model, and loads tuples.
//
// The model is the canonical Zanzibar shape: documents live in folders, viewers
// are inherited from editors, editors from owners, and folder viewers see the
// documents inside. That nesting is exactly the work TessaraOP does not do
// itself, so it is what the adapter needs to prove it can consume.
func setup(t *testing.T, s *server) (storeID, modelID string) {
	t.Helper()

	var store struct {
		ID string `json:"id"`
	}
	s.post(t, "/stores", map[string]string{"name": "tessaraop-test"}, &store)
	if store.ID == "" {
		t.Fatal("no store id returned")
	}

	model := map[string]any{
		"schema_version": "1.1",
		"type_definitions": []any{
			map[string]any{"type": "user", "relations": map[string]any{}},
			map[string]any{
				"type": "folder",
				"relations": map[string]any{
					"viewer": map[string]any{"this": map[string]any{}},
				},
				"metadata": map[string]any{
					"relations": map[string]any{
						"viewer": map[string]any{
							"directly_related_user_types": []any{
								map[string]string{"type": "user"},
							},
						},
					},
				},
			},
			map[string]any{
				"type": "document",
				"relations": map[string]any{
					"parent": map[string]any{"this": map[string]any{}},
					"owner":  map[string]any{"this": map[string]any{}},
					"editor": map[string]any{
						"union": map[string]any{"child": []any{
							map[string]any{"this": map[string]any{}},
							map[string]any{"computedUserset": map[string]any{"relation": "owner"}},
						}},
					},
					"viewer": map[string]any{
						"union": map[string]any{"child": []any{
							map[string]any{"this": map[string]any{}},
							map[string]any{"computedUserset": map[string]any{"relation": "editor"}},
							map[string]any{"tupleToUserset": map[string]any{
								"tupleset":        map[string]any{"relation": "parent"},
								"computedUserset": map[string]any{"relation": "viewer"},
							}},
						}},
					},
				},
				"metadata": map[string]any{
					"relations": map[string]any{
						"parent": map[string]any{"directly_related_user_types": []any{
							map[string]string{"type": "folder"}}},
						"owner": map[string]any{"directly_related_user_types": []any{
							map[string]string{"type": "user"}}},
						"editor": map[string]any{"directly_related_user_types": []any{
							map[string]string{"type": "user"}}},
						"viewer": map[string]any{"directly_related_user_types": []any{
							map[string]string{"type": "user"}}},
					},
				},
			},
		},
	}

	var written struct {
		AuthorizationModelID string `json:"authorization_model_id"`
	}
	s.post(t, "/stores/"+store.ID+"/authorization-models", model, &written)
	if written.AuthorizationModelID == "" {
		t.Fatal("no authorization model id returned")
	}

	tuples := []map[string]string{
		{"user": "user:anne", "relation": "owner", "object": "document:budget"},
		{"user": "user:bob", "relation": "editor", "object": "document:budget"},
		{"user": "user:carol", "relation": "viewer", "object": "folder:finance"},
		{"user": "folder:finance", "relation": "parent", "object": "document:budget"},
	}
	s.post(t, "/stores/"+store.ID+"/write", map[string]any{
		"writes":                 map[string]any{"tuple_keys": tuples},
		"authorization_model_id": written.AuthorizationModelID,
	}, nil)

	return store.ID, written.AuthorizationModelID
}

func newResolver(storeID, modelID, baseURL string) *openfga.Resolver {
	return openfga.New(openfga.Config{
		Endpoint:             baseURL,
		StoreID:              storeID,
		AuthorizationModelID: modelID,
		Relations:            []string{"owner", "editor", "viewer"},
	})
}

// TestAgainstRealServer is the point of the file: the adapter's understanding of
// the Check API is confirmed by a server that implements it.
func TestAgainstRealServer(t *testing.T) {
	s := startServer(t)
	storeID, modelID := setup(t, s)
	r := newResolver(storeID, modelID, s.baseURL)

	if err := r.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cases := []struct {
		user string
		want string
	}{
		// Direct owner. The model unions owner into editor and editor into
		// viewer, so all three hold — resolved by OpenFGA, not by us.
		{"user:anne", "owner,editor,viewer"},
		// Direct editor, which implies viewer.
		{"user:bob", "editor,viewer"},
		// Viewer on the parent folder only. Reaching the document requires the
		// tuple-to-userset rewrite, which is exactly the graph traversal this
		// adapter exists to delegate.
		{"user:carol", "viewer"},
		// No relationship at all.
		{"user:dave", ""},
	}

	for _, tc := range cases {
		rels, err := r.Relations(ctx, tc.user, "document:budget")
		if err != nil {
			t.Fatalf("%s: Relations: %v", tc.user, err)
		}
		if got := strings.Join(rels, ","); got != tc.want {
			t.Errorf("%s: got %q want %q", tc.user, got, tc.want)
		}
	}
}

// TestEndToEndPolicy is the whole point of ReBAC support: a policy written
// against relations, decided by the ordinary engine, with the relationship graph
// living in OpenFGA.
func TestEndToEndPolicy(t *testing.T) {
	s := startServer(t)
	storeID, modelID := setup(t, s)
	resolver := newResolver(storeID, modelID, s.baseURL)

	const bundle = `{
	  "version": 1,
	  "policies": [{
	    "id": "docs",
	    "tenant": "acme",
	    "rules": [
	      {
	        "id": "editors-may-write",
	        "effect": "ALLOW",
	        "when": {"all": [
	          {"attr": "subject.relations", "op": "has_any", "values": ["owner", "editor"]},
	          {"attr": "action", "op": "eq", "values": ["write"]}
	        ]}
	      },
	      {
	        "id": "viewers-may-read",
	        "effect": "ALLOW",
	        "when": {"all": [
	          {"attr": "subject.relations", "op": "has_any", "values": ["viewer"]},
	          {"attr": "action", "op": "eq", "values": ["read"]}
	        ]}
	      }
	    ]
	  }]
	}`

	pdp, diags, err := tessaraop.ReadBundle(strings.NewReader(bundle), tessaraop.Config{})
	if err != nil {
		t.Fatalf("bundle: %v\n%s", err, tessaraop.FormatDiagnostics(diags))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	decide := func(user, action string) bool {
		t.Helper()
		req := tessaraop.NewRequest("acme", "").Str(tessaraop.AttrAction, action).Build()
		if err := tessaraop.ResolveRelations(ctx, resolver, &req, user, "document:budget"); err != nil {
			t.Fatalf("resolving relations for %s: %v", user, err)
		}
		return pdp.Evaluate(req).Allowed
	}

	cases := []struct {
		user, action string
		want         bool
		why          string
	}{
		{"user:anne", "write", true, "owner implies editor"},
		{"user:anne", "read", true, "owner implies viewer"},
		{"user:bob", "write", true, "direct editor"},
		{"user:carol", "write", false, "viewer on the folder is not an editor"},
		{"user:carol", "read", true, "folder viewer reaches the document"},
		{"user:dave", "read", false, "no relationship, so the attribute is absent and it fails closed"},
	}

	for _, tc := range cases {
		if got := decide(tc.user, tc.action); got != tc.want {
			t.Errorf("%s %s: got allowed=%v want %v (%s)",
				tc.user, tc.action, got, tc.want, tc.why)
		}
	}
}

// TestErrorsAreNotPartial pins the choice that matters most operationally: a
// failed check must fail the resolution, not return what it managed to gather.
func TestErrorsAreNotPartial(t *testing.T) {
	s := startServer(t)
	storeID, modelID := setup(t, s)

	// A store that does not exist, so every check errors.
	bad := openfga.New(openfga.Config{
		Endpoint:             s.baseURL,
		StoreID:              "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		AuthorizationModelID: modelID,
		Relations:            []string{"owner", "viewer"},
	})
	_ = storeID

	rels, err := bad.Relations(context.Background(), "user:anne", "document:budget")
	if err == nil {
		t.Fatal("expected an error against a missing store")
	}
	if rels != nil {
		t.Fatalf("a failed resolution must return no relations, got %v", rels)
	}
}

func TestValidate(t *testing.T) {
	cases := map[string]openfga.Config{
		"no endpoint":  {StoreID: "s", Relations: []string{"viewer"}},
		"no store":     {Endpoint: "http://x", Relations: []string{"viewer"}},
		"no relations": {Endpoint: "http://x", StoreID: "s"},
	}
	for name, cfg := range cases {
		if err := openfga.New(cfg).Validate(); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
	ok := openfga.Config{Endpoint: "http://x", StoreID: "s", Relations: []string{"viewer"}}
	if err := openfga.New(ok).Validate(); err != nil {
		t.Errorf("a complete config should validate, got %v", err)
	}
}
