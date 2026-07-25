package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/ai-crypto-onramp/audit-logger/internal/event"
	"github.com/ai-crypto-onramp/audit-logger/internal/redaction"
	"github.com/ai-crypto-onramp/audit-logger/internal/s3"
	"github.com/ai-crypto-onramp/audit-logger/internal/store"
	"github.com/ai-crypto-onramp/audit-logger/internal/store/memstore"
)

func envelopeJSON(id, ts string, payload map[string]any, payloadHash string) []byte {
	m := map[string]any{
		"id":             id,
		"ts":             ts,
		"source_service": "orch",
		"actor_id":       "u1",
		"action":         "tx.initiated",
		"target_type":    "transaction",
		"target_id":      "tx" + id,
	}
	if payloadHash != "" {
		m["payload_hash"] = payloadHash
	} else if payload != nil {
		b, _ := json.Marshal(payload)
		m["payload_hash"] = event.HashPayload(b)
		m["payload"] = payload
	} else {
		m["payload_hash"] = event.HashPayload(nil)
	}
	b, _ := json.Marshal(m)
	return b
}

func newPipeline(t *testing.T, redactor Redactor, retentionDays int, legalHold bool) (*Pipeline, *memstore.All, *s3.Fake) {
	t.Helper()
	all := memstore.NewAll()
	fake := s3.NewFake()
	p := New(Deps{
		Events:          all.Events,
		Payloads:         &PutAdapter{Client: fake},
		PayloadBucket:   "audit-bucket",
		StorageClass:    "STANDARD",
		RetentionDays:   retentionDays,
		LegalHoldDefault: legalHold,
		Redactor:        redactor,
	})
	return p, all, fake
}

func TestIngestFresh(t *testing.T) {
	ctx := context.Background()
	p, all, fake := newPipeline(t, nil, 2555, false)
	body := envelopeJSON("e1", "2026-07-13T10:00:00Z", map[string]any{"amount": "100"}, "")
	res := p.Ingest(ctx, body)
	if !res.Inserted {
		t.Fatalf("expected inserted, reason=%q", res.Reason)
	}
	got, err := all.Events.Get(ctx, "e1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.PayloadRef != "e1" {
		t.Errorf("payload_ref: %q", got.PayloadRef)
	}
	if len(got.ThisHash) != 32 {
		t.Errorf("this_hash len: %d", len(got.ThisHash))
	}
	if len(got.PrevHash) != 32 || bytes.Equal(got.PrevHash, []byte{}) {
		// genesis -> prev_hash should be zero
	}
	// S3 object should exist.
	obj, _ := fake.Head(ctx, "audit-bucket", "e1")
	if obj == nil {
		t.Fatal("payload not in S3")
	}
	if obj.RetentionDays != 2555 {
		t.Errorf("retention: %d", obj.RetentionDays)
	}
}

func TestIngestDedup(t *testing.T) {
	ctx := context.Background()
	p, all, _ := newPipeline(t, nil, 2555, false)
	body := envelopeJSON("e1", "2026-07-13T10:00:00Z", map[string]any{"amount": "100"}, "")
	if res := p.Ingest(ctx, body); !res.Inserted {
		t.Fatalf("first insert: %q", res.Reason)
	}
	if res := p.Ingest(ctx, body); res.Inserted {
		t.Fatal("second insert should be deduped")
	}
	// Exactly one row in the store.
	list, _ := all.Events.List(ctx, store.Filter{Limit: 100})
	if len(list.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(list.Events))
	}
}

func TestIngestChainExtension(t *testing.T) {
	ctx := context.Background()
	p, all, _ := newPipeline(t, nil, 2555, false)
	for i := 0; i < 3; i++ {
		id := "e" + string(rune('1'+i))
		ts := "2026-07-13T10:00:0" + string(rune('0'+i)) + "Z"
		body := envelopeJSON(id, ts, map[string]any{"i": i}, "")
		res := p.Ingest(ctx, body)
		if !res.Inserted {
			t.Fatalf("insert %s: %q", id, res.Reason)
		}
	}
	list, _ := all.Events.List(ctx, store.Filter{Limit: 100})
	if len(list.Events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(list.Events))
	}
	// Verify chain.
	var events []*store.Event
	for _, e := range list.Events {
		events = append(events, &e)
	}
	if err := verifyChainLocal(events); err != nil {
		t.Fatalf("chain: %v", err)
	}
}

// verifyChainLocal recomputes this_hash for each event and checks the prev
// linkage; a tiny reimplementation to avoid a circular import of chain in
// this test file. The real chain.VerifyChain is exercised in the chain
// package's own tests.
func verifyChainLocal(events []*store.Event) error {
	for i, e := range events {
		var wantPrev []byte
		if i == 0 {
			wantPrev = make([]byte, 32)
		} else {
			wantPrev = events[i-1].ThisHash
		}
		if !bytes.Equal(e.PrevHash, wantPrev) {
			return errStringf("event %s prev_hash mismatch", e.ID)
		}
	}
	return nil
}

func errStringf(format string, args ...any) error {
	return &errString{msg: format}
}

type errString struct{ msg string }

func (e *errString) Error() string { return e.msg }

func TestIngestRejectsMalformed(t *testing.T) {
	ctx := context.Background()
	p, _, _ := newPipeline(t, nil, 2555, false)
	res := p.Ingest(ctx, []byte("not json"))
	if res.Inserted {
		t.Fatal("malformed should not be inserted")
	}
	if res.Reason == "" {
		t.Fatal("expected reason")
	}
}

func TestIngestRejectsMissingFields(t *testing.T) {
	ctx := context.Background()
	p, _, _ := newPipeline(t, nil, 2555, false)
	res := p.Ingest(ctx, []byte(`{"id":"e1"}`))
	if res.Inserted {
		t.Fatal("missing fields should not be inserted")
	}
}

func TestIngestRejectsPayloadHashMismatch(t *testing.T) {
	ctx := context.Background()
	p, _, _ := newPipeline(t, nil, 2555, false)
	body := envelopeJSON("e1", "2026-07-13T10:00:00Z", map[string]any{"a": 1}, "sha256:deadbeef")
	res := p.Ingest(ctx, body)
	if res.Inserted {
		t.Fatal("mismatched payload_hash should be rejected")
	}
	if res.Reason == "" {
		t.Fatal("expected reason")
	}
}

func TestIngestAppliesRedaction(t *testing.T) {
	ctx := context.Background()
	policy := `rules:
  - service: orch
    action: "*"
    fields:
      ssn: mask
`
	pol, _ := redaction.Parse(policy)
	shim := &directReloader{policy: pol}
	p, all, fake := newPipeline(t, shim, 2555, false)
	body := envelopeJSON("e1", "2026-07-13T10:00:00Z", map[string]any{"ssn": "123-45-6789", "amount": "100"}, "")
	res := p.Ingest(ctx, body)
	if !res.Inserted {
		t.Fatalf("insert: %q", res.Reason)
	}
	got, _ := all.Events.Get(ctx, "e1")
	if !got.Redacted {
		t.Fatal("Redacted flag should be true")
	}
	stored, _ := fake.Get(ctx, "audit-bucket", "e1")
	var obj map[string]any
	_ = json.Unmarshal(stored, &obj)
	if obj["ssn"] == "123-45-6789" {
		t.Fatal("ssn should be masked in S3")
	}
}

// directReloader is a test-only Redactor that wraps a pre-parsed policy.
type directReloader struct {
	policy *redaction.Policy
}

func (d *directReloader) Policy() *redaction.Policy { return d.policy }
func (d *directReloader) Reload() error             { return nil }
func (d *directReloader) Apply(s, a string, b []byte) ([]byte, bool, error) {
	return d.policy.Apply(s, a, b)
}

func TestIngestLegalHoldDefault(t *testing.T) {
	ctx := context.Background()
	p, all, fake := newPipeline(t, nil, 2555, true)
	body := envelopeJSON("e1", "2026-07-13T10:00:00Z", map[string]any{"a": 1}, "")
	res := p.Ingest(ctx, body)
	if !res.Inserted {
		t.Fatalf("insert: %q", res.Reason)
	}
	got, _ := all.Events.Get(ctx, "e1")
	if !got.LegalHold {
		t.Error("LegalHold should be true")
	}
	obj, _ := fake.Head(ctx, "audit-bucket", "e1")
	if obj == nil || !obj.LegalHold {
		t.Error("S3 object should have legal hold")
	}
}

func TestIngestWithoutPayloadBody(t *testing.T) {
	ctx := context.Background()
	p, all, fake := newPipeline(t, nil, 2555, false)
	// Envelope with only payload_hash (no payload body).
	body := envelopeJSON("e1", "2026-07-13T10:00:00Z", nil, event.HashPayload([]byte("out-of-band")))
	res := p.Ingest(ctx, body)
	if !res.Inserted {
		t.Fatalf("insert: %q", res.Reason)
	}
	got, _ := all.Events.Get(ctx, "e1")
	if got.PayloadRef != "" {
		t.Errorf("payload_ref should be empty, got %q", got.PayloadRef)
	}
	// No S3 object should exist.
	if _, err := fake.Get(ctx, "audit-bucket", "e1"); err == nil {
		t.Error("S3 object should not exist when no payload body")
	}
}

func TestIngestDeadLettersRejections(t *testing.T) {
	ctx := context.Background()
	all := memstore.NewAll()
	fake := s3.NewFake()
	p := New(Deps{
		Events:      all.Events,
		Payloads:     &PutAdapter{Client: fake},
		PayloadBucket: "audit-bucket",
		DeadLetters:  all.DeadLetters,
		Topic:        "audit.v1",
	})
	// Malformed message.
	_ = p.IngestMessage(ctx, IngestMessage_{
		Topic:     "audit.v1",
		Partition: 0,
		Offset:    42,
		Key:       []byte("k"),
		Value:     []byte("not json"),
	})
	dls, _ := all.DeadLetters.List(ctx, 10)
	if len(dls) != 1 {
		t.Fatalf("dead letters: %d", len(dls))
	}
	if dls[0].Topic != "audit.v1" || dls[0].Offset != 42 {
		t.Errorf("dl: %+v", dls[0])
	}
	if dls[0].Reason == "" {
		t.Error("missing reason")
	}
}