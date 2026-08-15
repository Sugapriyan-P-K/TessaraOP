// Package audit records decisions for compliance, incident review and debugging.
//
// # Why this is not just a log line
//
// An authorization decision is a compliance artifact. "Who was allowed to do what,
// when, and under which policy" is the question an auditor asks, and answering it
// six months later requires that the record be structured, complete, and tied to
// the exact policy set that produced it. A printf in a handler does not survive
// that conversation.
//
// So a Record carries the decision, the rule credited, the generation of the
// policy set that was installed at the time, and a bounded, redacted view of the
// request.
//
// # Two things this refuses to do
//
// **It does not log attribute values by default.** A request carries whatever the
// integration put in it, and package ingest works hard to keep credentials out of
// attributes — an audit sink that echoed them wholesale would undo that at the
// worst possible place, since audit logs are retained for years and shipped to
// third-party systems. Attribute *names* are recorded; values only for attributes
// explicitly allowlisted.
//
// **It does not block the request path.** Writes go through a bounded buffer and a
// background goroutine. If the sink cannot keep up the buffer fills and records
// are dropped, with the drop counted — because an authorization decision that
// cannot be logged must still be *made*. Blocking a decision on a slow log
// shipper turns an observability problem into an availability one.
//
// That last choice has a consequence worth stating plainly: this sink is
// lossy under pressure. If your compliance regime requires that no decision go
// unrecorded, you need a durable queue, and this is the wrong component.
package audit

import (
	"context"
	"encoding/json"
	"io"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/suga/tessaraop/pkg/tessaraop"
)

// Record is one audited decision.
type Record struct {
	Time time.Time `json:"time"`

	TenantID string `json:"tenant_id,omitempty"`
	Scope    string `json:"scope,omitempty"`

	Allowed     bool     `json:"allowed"`
	Effect      string   `json:"effect"`
	PolicyID    string   `json:"policy_id,omitempty"`
	RuleID      string   `json:"rule_id,omitempty"`
	Obligations []string `json:"obligations,omitempty"`

	// Generation identifies the policy set that produced this decision, so a
	// record can be tied back to exactly what was installed at the time. Without
	// it a six-month-old audit record cannot be reproduced.
	Generation uint64 `json:"generation"`

	// CacheHit reports that the decision was served from cache. Worth recording:
	// a cached decision was computed against the generation stored with the
	// cache entry, not necessarily the current one.
	CacheHit bool `json:"cache_hit,omitempty"`

	RulesScanned int `json:"rules_scanned,omitempty"`

	// Attributes names what the request carried. Values appear only for
	// allowlisted attributes; see Options.RecordValues.
	Attributes map[string]string `json:"attributes,omitempty"`
	// AttributeNames lists the attributes present but not recorded by value,
	// so an investigator knows what was available without seeing it.
	AttributeNames []string `json:"attribute_names,omitempty"`
}

// Sink consumes audit records. Implementations must be safe for concurrent use.
type Sink interface {
	Write(Record) error
}

// SinkFunc adapts a function to Sink.
type SinkFunc func(Record) error

// Write implements Sink.
func (f SinkFunc) Write(r Record) error { return f(r) }

// JSONLines writes one JSON object per line, which is what every log shipper
// already understands.
type JSONLines struct {
	mu  sync.Mutex
	enc *json.Encoder
}

// NewJSONLines returns a sink writing newline-delimited JSON to w.
func NewJSONLines(w io.Writer) *JSONLines {
	return &JSONLines{enc: json.NewEncoder(w)}
}

// Write implements Sink.
func (j *JSONLines) Write(r Record) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.enc.Encode(r)
}

// Options configures a Logger.
type Options struct {
	// RecordValues names attributes whose values may be written. Everything else
	// is recorded by name only.
	//
	// The allowlist is the whole design. Audit logs are retained for years and
	// shipped to systems outside the trust boundary of the service that produced
	// them, so "record everything and redact later" is not a posture that
	// survives contact with a real incident.
	RecordValues map[string]bool

	// RecordAllValues writes every attribute value. Intended for a local debug
	// session; it is a deliberate footgun and Logger warns when it is set.
	RecordAllValues bool

	// Buffer is how many records may be queued before writes are dropped. Zero
	// means DefaultBuffer.
	Buffer int

	// SampleAllowed records only every Nth allowed decision. Denials are always
	// recorded in full, because they are what an investigation starts from and
	// they are far rarer.
	//
	// Zero or one records everything.
	SampleAllowed int

	// Now supplies the clock, for tests.
	Now func() time.Time

	// OnError is called when the sink returns an error. It must not block. A nil
	// OnError discards the error, which is the right default: an audit write
	// failing must not take down the decision path.
	OnError func(error)
}

// DefaultBuffer bounds the queue.
const DefaultBuffer = 4096

// Logger turns decisions into records and hands them to a Sink without blocking
// the caller.
type Logger struct {
	sink Sink
	opt  Options

	ch     chan Record
	done   chan struct{}
	closed atomic.Bool

	written atomic.Uint64
	dropped atomic.Uint64
	failed  atomic.Uint64
	seen    atomic.Uint64
}

// New starts a logger. Close it to flush.
//
// It returns warnings for configurations that are legal but worth seeing in a
// startup log, in the same spirit as pdpserver.New.
func New(sink Sink, opt Options) (*Logger, []string) {
	if opt.Buffer <= 0 {
		opt.Buffer = DefaultBuffer
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}

	var warnings []string
	if opt.RecordAllValues {
		warnings = append(warnings,
			"audit: RecordAllValues is set, so every attribute value will be written to "+
				"the audit log, including any credential an integration placed in a "+
				"request; use RecordValues to allowlist instead")
	}

	l := &Logger{
		sink: sink, opt: opt,
		ch:   make(chan Record, opt.Buffer),
		done: make(chan struct{}),
	}
	go l.run()
	return l, warnings
}

func (l *Logger) run() {
	defer close(l.done)
	for rec := range l.ch {
		if err := l.sink.Write(rec); err != nil {
			l.failed.Add(1)
			if l.opt.OnError != nil {
				l.opt.OnError(err)
			}
			continue
		}
		l.written.Add(1)
	}
}

// Record queues a decision. It never blocks.
//
// This is the signature pdpserver.Config.OnDecision expects, so wiring it up is
// one line.
func (l *Logger) Record(req tessaraop.Request, d tessaraop.Decision) {
	l.RecordAt(req, d, 0)
}

// RecordAt is Record with the policy generation, which the caller knows and the
// decision does not carry.
func (l *Logger) RecordAt(req tessaraop.Request, d tessaraop.Decision, generation uint64) {
	if l.closed.Load() {
		return
	}
	n := l.seen.Add(1)

	// Denials are always recorded: they are what an investigation starts from,
	// and they are far rarer than grants, so sampling them saves little and
	// costs a great deal.
	if d.Allowed && l.opt.SampleAllowed > 1 {
		if n%uint64(l.opt.SampleAllowed) != 0 {
			return
		}
	}

	rec := Record{
		Time:         l.opt.Now(),
		TenantID:     req.TenantID,
		Scope:        req.Scope,
		Allowed:      d.Allowed,
		Effect:       string(d.Effect),
		PolicyID:     d.MatchedPolicyID,
		RuleID:       d.MatchedRuleID,
		Obligations:  d.Obligations,
		Generation:   generation,
		CacheHit:     d.CacheHit,
		RulesScanned: d.RulesScanned,
	}
	l.attachAttributes(&rec, req)

	select {
	case l.ch <- rec:
	default:
		// The buffer is full. Drop rather than block: a decision that cannot be
		// logged must still be made, and blocking here would turn a slow log
		// shipper into a request-path outage.
		l.dropped.Add(1)
	}
}

func (l *Logger) attachAttributes(rec *Record, req tessaraop.Request) {
	var names []string
	add := func(name, value string) {
		if l.opt.RecordAllValues || l.opt.RecordValues[name] {
			if rec.Attributes == nil {
				rec.Attributes = map[string]string{}
			}
			rec.Attributes[name] = value
			return
		}
		names = append(names, name)
	}

	for name, value := range req.Attributes {
		add(name, value)
	}
	for name, value := range req.Numeric {
		add(name, formatFloat(value))
	}
	for name, value := range req.IPs {
		add(name, value.String())
	}

	sort.Strings(names)
	rec.AttributeNames = names
}

func formatFloat(f float64) string {
	b, _ := json.Marshal(f)
	return string(b)
}

// Close stops the logger and waits for queued records to be written.
//
// It is safe to call more than once. Records submitted after Close are dropped
// silently rather than panicking on a closed channel, because shutdown races with
// in-flight requests by nature.
func (l *Logger) Close(ctx context.Context) error {
	if l.closed.Swap(true) {
		return nil
	}
	close(l.ch)
	select {
	case <-l.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Stats reports what the logger has done. Dropped is the number worth alerting
// on: it means the sink could not keep up and decisions went unrecorded.
type Stats struct {
	Seen    uint64 `json:"seen"`
	Written uint64 `json:"written"`
	Dropped uint64 `json:"dropped"`
	Failed  uint64 `json:"failed"`
}

// Stats returns a snapshot.
func (l *Logger) Stats() Stats {
	return Stats{
		Seen:    l.seen.Load(),
		Written: l.written.Load(),
		Dropped: l.dropped.Load(),
		Failed:  l.failed.Load(),
	}
}
