package audit

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/suga/tessaraop/pkg/tessaraop"
)

// collector is a Sink that keeps records for inspection.
type collector struct {
	mu      sync.Mutex
	records []Record
	err     error
}

func (c *collector) Write(r Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	c.records = append(c.records, r)
	return nil
}

func (c *collector) all() []Record {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Record, len(c.records))
	copy(out, c.records)
	return out
}

func closeLogger(t *testing.T, l *Logger) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := l.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func sampleRequest() tessaraop.Request {
	return tessaraop.NewRequest("acme", "identity").
		Str(tessaraop.AttrSubjectRole, "admin").
		Str("session.id", "super-secret-session").
		Num(tessaraop.AttrRiskScore, 12).
		IPString(tessaraop.AttrSourceIP, "10.1.2.3").
		Build()
}

func sampleDecision(allowed bool) tessaraop.Decision {
	d := tessaraop.Decision{
		Allowed: allowed, Effect: tessaraop.Deny,
		MatchedPolicyID: "acme-grant", MatchedRuleID: "allow-admin",
		Obligations: []string{"audit_log"}, RulesScanned: 3,
	}
	if allowed {
		d.Effect = tessaraop.Allow
	}
	return d
}

func TestRecord_CapturesTheDecision(t *testing.T) {
	c := &collector{}
	l, _ := New(c, Options{})
	l.RecordAt(sampleRequest(), sampleDecision(true), 7)
	closeLogger(t, l)

	recs := c.all()
	if len(recs) != 1 {
		t.Fatalf("expected one record, got %d", len(recs))
	}
	r := recs[0]
	if !r.Allowed || r.Effect != "ALLOW" {
		t.Errorf("decision not captured: %+v", r)
	}
	if r.PolicyID != "acme-grant" || r.RuleID != "allow-admin" {
		t.Errorf("attribution not captured: %+v", r)
	}
	if r.TenantID != "acme" || r.Scope != "identity" {
		t.Errorf("tenancy not captured: %+v", r)
	}
	// The generation is what ties a six-month-old record back to the policy set
	// that produced it.
	if r.Generation != 7 {
		t.Errorf("generation = %d want 7", r.Generation)
	}
	if r.Time.IsZero() {
		t.Error("expected a timestamp")
	}
}

// TestRecord_DoesNotLogValuesByDefault is the security property. Audit logs are
// retained for years and shipped outside the trust boundary of the service that
// produced them, so "record everything and redact later" is not a posture that
// survives an incident.
func TestRecord_DoesNotLogValuesByDefault(t *testing.T) {
	c := &collector{}
	l, _ := New(c, Options{})
	l.Record(sampleRequest(), sampleDecision(false))
	closeLogger(t, l)

	blob, err := json.Marshal(c.all()[0])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(blob), "super-secret-session") {
		t.Fatal("attribute values must not be logged by default")
	}

	// But the names are, so an investigator knows what was available.
	r := c.all()[0]
	var found bool
	for _, name := range r.AttributeNames {
		if name == "session.id" {
			found = true
		}
	}
	if !found {
		t.Errorf("attribute names should be recorded, got %v", r.AttributeNames)
	}
	if len(r.Attributes) != 0 {
		t.Errorf("no values should be recorded, got %v", r.Attributes)
	}
}

func TestRecord_AllowlistedValuesAreLogged(t *testing.T) {
	c := &collector{}
	l, _ := New(c, Options{
		RecordValues: map[string]bool{tessaraop.AttrSubjectRole: true},
	})
	l.Record(sampleRequest(), sampleDecision(true))
	closeLogger(t, l)

	r := c.all()[0]
	if r.Attributes[tessaraop.AttrSubjectRole] != "admin" {
		t.Errorf("allowlisted value should be recorded, got %v", r.Attributes)
	}
	if _, ok := r.Attributes["session.id"]; ok {
		t.Error("a non-allowlisted value must stay out")
	}
}

func TestNew_WarnsAboutRecordAllValues(t *testing.T) {
	_, warnings := New(&collector{}, Options{RecordAllValues: true})
	if len(warnings) == 0 || !strings.Contains(warnings[0], "credential") {
		t.Fatalf("expected a warning about logging every value, got %v", warnings)
	}
}

func TestRecord_TypedAttributesAreRendered(t *testing.T) {
	c := &collector{}
	l, _ := New(c, Options{RecordAllValues: true})
	l.Record(sampleRequest(), sampleDecision(true))
	closeLogger(t, l)

	r := c.all()[0]
	if r.Attributes[tessaraop.AttrRiskScore] != "12" {
		t.Errorf("numeric attribute = %q", r.Attributes[tessaraop.AttrRiskScore])
	}
	if r.Attributes[tessaraop.AttrSourceIP] != "10.1.2.3" {
		t.Errorf("ip attribute = %q", r.Attributes[tessaraop.AttrSourceIP])
	}
}

// TestSampling_NeverSamplesDenials pins the asymmetry. Denials are what an
// investigation starts from and are far rarer than grants, so sampling them saves
// little and costs a great deal.
func TestSampling_NeverSamplesDenials(t *testing.T) {
	c := &collector{}
	l, _ := New(c, Options{SampleAllowed: 10})

	for i := 0; i < 50; i++ {
		l.Record(sampleRequest(), sampleDecision(false))
	}
	closeLogger(t, l)

	if got := len(c.all()); got != 50 {
		t.Fatalf("every denial must be recorded, got %d of 50", got)
	}
}

func TestSampling_ReducesAllowedRecords(t *testing.T) {
	c := &collector{}
	l, _ := New(c, Options{SampleAllowed: 10})
	for i := 0; i < 100; i++ {
		l.Record(sampleRequest(), sampleDecision(true))
	}
	closeLogger(t, l)

	got := len(c.all())
	if got == 0 || got > 20 {
		t.Fatalf("expected roughly a tenth of 100 allowed records, got %d", got)
	}
	if l.Stats().Seen != 100 {
		t.Errorf("Seen should count everything offered, got %d", l.Stats().Seen)
	}
}

// TestRecord_DropsRatherThanBlocks is the availability property: a decision that
// cannot be logged must still be made. Blocking here would turn a slow log
// shipper into a request-path outage.
func TestRecord_DropsRatherThanBlocks(t *testing.T) {
	block := make(chan struct{})
	slow := SinkFunc(func(Record) error {
		<-block // never returns until released
		return nil
	})

	l, _ := New(slow, Options{Buffer: 2})

	// Far more than the buffer can hold, while the sink is stuck.
	done := make(chan struct{})
	go func() {
		for i := 0; i < 500; i++ {
			l.Record(sampleRequest(), sampleDecision(true))
		}
		close(done)
	}()

	select {
	case <-done:
		// Good: recording never blocked.
	case <-time.After(5 * time.Second):
		t.Fatal("Record blocked when the sink was stuck")
	}

	if l.Stats().Dropped == 0 {
		t.Error("expected drops to be counted when the buffer filled")
	}

	close(block)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = l.Close(ctx)
}

func TestSinkErrorsAreCountedNotFatal(t *testing.T) {
	c := &collector{err: errors.New("shipper down")}
	var seen error
	l, _ := New(c, Options{OnError: func(err error) { seen = err }})

	l.Record(sampleRequest(), sampleDecision(true))
	closeLogger(t, l)

	if l.Stats().Failed != 1 {
		t.Errorf("expected the failure to be counted, got %+v", l.Stats())
	}
	if seen == nil {
		t.Error("OnError should have been called")
	}
	if l.Stats().Written != 0 {
		t.Error("a failed write must not count as written")
	}
}

func TestJSONLines(t *testing.T) {
	var buf strings.Builder
	l, _ := New(NewJSONLines(&buf), Options{})
	l.Record(sampleRequest(), sampleDecision(true))
	l.Record(sampleRequest(), sampleDecision(false))
	closeLogger(t, l)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected two lines, got %d:\n%s", len(lines), buf.String())
	}
	for i, line := range lines {
		var r Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("line %d is not valid JSON: %v", i, err)
		}
	}
}

// TestCloseIsIdempotentAndSafeAfterwards covers shutdown, which races with
// in-flight requests by nature.
func TestCloseIsIdempotentAndSafeAfterwards(t *testing.T) {
	c := &collector{}
	l, _ := New(c, Options{})
	closeLogger(t, l)
	closeLogger(t, l) // second close is a no-op

	// Recording after Close must not panic on a closed channel.
	l.Record(sampleRequest(), sampleDecision(true))
	if len(c.all()) != 0 {
		t.Error("records after Close should be dropped")
	}
}

func TestConcurrentRecording(t *testing.T) {
	c := &collector{}
	l, _ := New(c, Options{Buffer: 8192})

	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				l.Record(sampleRequest(), sampleDecision(i%2 == 0))
			}
		}()
	}
	wg.Wait()
	closeLogger(t, l)

	s := l.Stats()
	if s.Seen != 800 {
		t.Errorf("Seen = %d want 800", s.Seen)
	}
	if s.Written+s.Dropped != 800 {
		t.Errorf("every record should be written or counted as dropped: %+v", s)
	}
}
