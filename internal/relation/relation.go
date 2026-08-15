// Package relation resolves what a subject is to an object, so relationship-based
// policy can be expressed without the engine growing a graph database.
//
// # The decision this package encodes
//
// ReBAC — "Anne can view this document because she is in the group that owns the
// parent folder" — is the largest functional gap against Cedar and OpenFGA. There
// were two ways to close it, and COMPARISON.md §7.1 records why this one was
// chosen.
//
// Building a Zanzibar-style tuple store natively would mean adding a database:
// durability, migrations, replication, snapshot consistency. That turns TessaraOP
// from a stateless drop-in compute component into a stateful service, with a
// different operational burden and the loss of the zero-dependency property the
// moment a driver is added. It would also mean competing on OpenFGA's strongest
// axis while the actual differentiator stagnated.
//
// So relationships are *consumed*, not stored. A Resolver answers "what is this
// subject to this object", the answer is materialized into an ordinary attribute
// before evaluation, and an indexed operator (has_any) matches it. The engine
// gains no new concept and the evaluation path is untouched — the same division
// of labour that keeps parsing and I/O outside the hot path.
//
// # Why the interface is defined here rather than importing a client
//
// Defining it natively means TessaraOP is not coupled to any one store. An
// adapter for OpenFGA, SpiceDB or an in-house service is an implementation of one
// method, and a native tuple store later would be a drop-in third implementation
// rather than a rewrite. That hedge costs almost nothing now and preserves the
// option.
//
// # What this handles, and what it does not
//
// This serves Check-shaped questions: "what is Anne to document:123", asked about
// one named object. That is what an authorization decision needs.
//
// It does not serve ListObjects — "which documents can Anne view" — which is a
// reverse query over the relationship graph and a genuinely different problem. If
// you need it, ask your ReBAC store directly; this package is not a substitute
// for one.
package relation

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/suga/tessaraop/internal/hierarchy"
	"github.com/suga/tessaraop/internal/model"
)

// Resolver answers what relations a subject holds to an object.
//
// Implementations are called once per request, before evaluation, from whatever
// goroutine is assembling the request — never from the evaluation path. They may
// block and may perform I/O; the context carries the caller's deadline.
//
// An implementation must be safe for concurrent use.
type Resolver interface {
	// Relations returns the relation names the subject holds to the object, in
	// any order. An empty result is not an error: it means no relationship,
	// which is a perfectly ordinary answer.
	Relations(ctx context.Context, subject, object string) ([]string, error)
}

// ResolverFunc adapts a function to the Resolver interface.
type ResolverFunc func(ctx context.Context, subject, object string) ([]string, error)

// Relations implements Resolver.
func (f ResolverFunc) Relations(ctx context.Context, subject, object string) ([]string, error) {
	return f(ctx, subject, object)
}

// Materialize resolves the relations and renders them in the delimited form the
// engine's set operators read.
//
// This is the whole integration surface: call it while building a request, put
// the result in subject.relations, and write policy against
// `subject.relations has_any ["owner", "editor"]`.
func Materialize(ctx context.Context, r Resolver, subject, object string) (string, error) {
	if r == nil || subject == "" || object == "" {
		return "", nil
	}
	rels, err := r.Relations(ctx, subject, object)
	if err != nil {
		return "", err
	}
	return hierarchy.Join(normalize(rels)), nil
}

// normalize sorts and deduplicates, so the same logical answer always renders
// identically. That matters because the value becomes an attribute and the
// decision cache keys on attribute values — an unstable order would turn one
// logical request into several cache entries.
func normalize(rels []string) []string {
	if len(rels) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(rels))
	out := make([]string, 0, len(rels))
	for _, r := range rels {
		r = strings.TrimSpace(r)
		if r == "" || seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// --- Static: an in-memory tuple store ---------------------------------------

// Tuple is one relationship fact: subject holds relation on object.
type Tuple struct {
	Subject  string
	Relation string
	Object   string
}

// Static is an in-memory Resolver over a fixed set of tuples.
//
// It is not a substitute for a real ReBAC store — there is no persistence, no
// consistency model, and no reverse index. It exists for three things a product
// needs anyway: tests, local development, and deployments whose relationship set
// is genuinely small and static (a handful of service accounts and owners), where
// running a separate store would be absurd.
//
// Two expansions are applied, and together they cover most of what a real ReBAC
// model is asked for:
//
//   - **Object containment.** With a resource hierarchy, a relation held on a
//     folder is also held on everything inside it. This is what makes "Anne can
//     view the doc because she can view its folder" work.
//   - **Subject groups.** With a group hierarchy, a relation held by a group is
//     also held by its members, transitively.
//
// What it deliberately does not implement is Zanzibar's full userset rewrite
// algebra — computed usersets, tuple-to-userset indirection. Those need a real
// engine, and pretending otherwise would be the dishonest half-implementation
// this package's documentation warns against.
type Static struct {
	mu sync.RWMutex
	// byPair maps subject -> object -> relations.
	byPair map[string]map[string]map[string]bool

	objects *hierarchy.Graph
	groups  *hierarchy.Graph
}

// NewStatic returns an empty in-memory resolver.
func NewStatic() *Static {
	return &Static{byPair: make(map[string]map[string]map[string]bool)}
}

// Add records a relationship. Safe to call concurrently with reads.
func (s *Static) Add(tuples ...Tuple) *Static {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range tuples {
		if t.Subject == "" || t.Relation == "" || t.Object == "" {
			continue
		}
		objs, ok := s.byPair[t.Subject]
		if !ok {
			objs = make(map[string]map[string]bool)
			s.byPair[t.Subject] = objs
		}
		rels, ok := objs[t.Object]
		if !ok {
			rels = make(map[string]bool)
			objs[t.Object] = rels
		}
		rels[t.Relation] = true
	}
	return s
}

// WithObjectHierarchy makes a relation held on a container also hold on
// everything it contains. The graph must be frozen.
func (s *Static) WithObjectHierarchy(g *hierarchy.Graph) *Static {
	if g != nil && g.Frozen() {
		s.mu.Lock()
		s.objects = g
		s.mu.Unlock()
	}
	return s
}

// WithGroupHierarchy makes a relation held by a group also hold for its members,
// transitively. The graph must be frozen, and its edges run member -> group.
func (s *Static) WithGroupHierarchy(g *hierarchy.Graph) *Static {
	if g != nil && g.Frozen() {
		s.mu.Lock()
		s.groups = g
		s.mu.Unlock()
	}
	return s
}

// Relations implements Resolver.
func (s *Static) Relations(_ context.Context, subject, object string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Every identity the subject effectively acts as: itself plus every group it
	// belongs to, transitively.
	subjects := []string{subject}
	if s.groups != nil {
		subjects = s.groups.Closure(subject)
	}

	// Every object a relation could be held on to cover this one: itself plus
	// every container it sits inside.
	objects := []string{object}
	if s.objects != nil {
		objects = s.objects.Closure(object)
	}

	found := map[string]bool{}
	for _, subj := range subjects {
		objs, ok := s.byPair[subj]
		if !ok {
			continue
		}
		for _, obj := range objects {
			for rel := range objs[obj] {
				found[rel] = true
			}
		}
	}

	out := make([]string, 0, len(found))
	for rel := range found {
		out = append(out, rel)
	}
	sort.Strings(out)
	return out, nil
}

// Size reports how many (subject, object) pairs hold at least one relation.
func (s *Static) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, objs := range s.byPair {
		n += len(objs)
	}
	return n
}

// --- Composition -------------------------------------------------------------

// Chain queries several resolvers and unions their answers.
//
// The common shape is a Static holding locally-known relationships in front of a
// remote store, so an outage in the remote one degrades to the local subset
// rather than to no relationships at all.
type Chain []Resolver

// Relations implements Resolver. An error from any member fails the whole chain:
// silently returning a partial relation set would narrow access without saying
// so, which in an authorization path is an outage disguised as a decision.
func (c Chain) Relations(ctx context.Context, subject, object string) ([]string, error) {
	var all []string
	for _, r := range c {
		if r == nil {
			continue
		}
		rels, err := r.Relations(ctx, subject, object)
		if err != nil {
			return nil, err
		}
		all = append(all, rels...)
	}
	return normalize(all), nil
}

// ErrResolverTimeout is returned when a resolver exceeds its deadline.
var ErrResolverTimeout = errors.New("relation: resolver timed out")

// WithTimeout bounds how long a resolver may take.
//
// A remote relationship store sits in the request path, so an unbounded call
// there is an availability risk for everything behind it. This does not decide
// what to do on timeout — that is a policy question, and the caller answers it by
// choosing whether to fail the request or to proceed with no relations, which
// fails closed at the engine.
func WithTimeout(r Resolver, d time.Duration) Resolver {
	return ResolverFunc(func(ctx context.Context, subject, object string) ([]string, error) {
		ctx, cancel := context.WithTimeout(ctx, d)
		defer cancel()

		type result struct {
			rels []string
			err  error
		}
		ch := make(chan result, 1)
		go func() {
			rels, err := r.Relations(ctx, subject, object)
			ch <- result{rels, err}
		}()

		select {
		case res := <-ch:
			return res.rels, res.err
		case <-ctx.Done():
			return nil, ErrResolverTimeout
		}
	})
}

// Cache memoizes resolutions for a bounded time.
//
// Relationship data changes, and a cached answer is a stale authorization
// decision — so the TTL is required rather than optional, and there is no
// invalidation hook. If your relationships change in ways that must take effect
// immediately, do not cache them here; cache them where the writes are, so an
// invalidation can accompany them.
type Cache struct {
	inner Resolver
	ttl   time.Duration
	now   func() time.Time

	mu      sync.RWMutex
	entries map[string]cacheEntry
}

type cacheEntry struct {
	rels    []string
	expires time.Time
}

// NewCache wraps a resolver with a time-bounded cache.
func NewCache(inner Resolver, ttl time.Duration) *Cache {
	return &Cache{
		inner: inner, ttl: ttl, now: time.Now,
		entries: make(map[string]cacheEntry),
	}
}

// Relations implements Resolver.
func (c *Cache) Relations(ctx context.Context, subject, object string) ([]string, error) {
	key := subject + "\x00" + object

	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if ok && c.now().Before(entry.expires) {
		return entry.rels, nil
	}

	rels, err := c.inner.Relations(ctx, subject, object)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.entries[key] = cacheEntry{rels: rels, expires: c.now().Add(c.ttl)}
	c.mu.Unlock()
	return rels, nil
}

// Len reports how many entries are held, expired or not.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// --- Attribute names ---------------------------------------------------------

// SubjectRelations is the attribute Materialize's output belongs in. Match it
// with has_any / has_all / has_none.
const SubjectRelations = "subject.relations"

// Apply resolves the subject's relations to the object and writes them into a
// request's attribute map, ready for evaluation.
//
// It is a convenience over Materialize for callers assembling a request by hand
// rather than through package ingest.
func Apply(ctx context.Context, r Resolver, req *model.Request, subject, object string) error {
	value, err := Materialize(ctx, r, subject, object)
	if err != nil {
		return err
	}
	if value == "" {
		return nil
	}
	if req.Attributes == nil {
		req.Attributes = map[string]string{}
	}
	req.Attributes[SubjectRelations] = value
	return nil
}

// --- Writing an adapter ------------------------------------------------------

// The adapter contract, stated here because no adapter ships with this module.
//
// OpenFGA and SpiceDB adapters are not included, and that is deliberate rather
// than an oversight: both require a live server to verify against, and shipping
// unexercised network code as a "supported adapter" would be exactly the kind of
// claim COMPARISON.md §8 forbids. Writing one is small, and this is all it has to
// do.
//
// For OpenFGA, one Check call per candidate relation, or one ListRelations call
// where the server supports it:
//
//	type openFGA struct {
//	    client *http.Client
//	    url, store, model string
//	    relations []string // the relations your policies actually name
//	}
//
//	func (o *openFGA) Relations(ctx context.Context, subject, object string) ([]string, error) {
//	    var held []string
//	    for _, rel := range o.relations {
//	        ok, err := o.check(ctx, subject, rel, object)
//	        if err != nil {
//	            return nil, err // never a partial answer; see Chain
//	        }
//	        if ok {
//	            held = append(held, rel)
//	        }
//	    }
//	    return held, nil
//	}
//
// Three things an adapter must get right:
//
//  1. **Never return a partial answer on error.** A truncated relation set
//     narrows access silently, which is an outage that looks like a decision.
//     Return the error and let the caller decide.
//  2. **Bound the call.** Wrap it in WithTimeout. It sits in the request path.
//  3. **Enumerate only the relations your policies name.** Checking every
//     relation in the model is a round trip you do not need; the set of
//     relations that appear in your bundle is small and known at load time.
