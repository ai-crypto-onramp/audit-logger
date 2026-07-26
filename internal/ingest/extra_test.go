package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/ai-crypto-onramp/audit-logger/internal/event"
	"github.com/ai-crypto-onramp/audit-logger/internal/s3"
	"github.com/ai-crypto-onramp/audit-logger/internal/store"
	"github.com/ai-crypto-onramp/audit-logger/internal/store/memstore"
)

// errRedactor is a Redactor that always returns an error.
type errRedactor struct{}

func (errRedactor) Apply(service, action string, body []byte) ([]byte, bool, error) {
	return nil, false, errors.New("redact boom")
}

func TestIngestRedactionError(t *testing.T) {
	ctx := context.Background()
	all := memstore.NewAll()
	fake := s3.NewFake()
	p := New(Deps{
		Events:        all.Events,
		Payloads:      &PutAdapter{Client: fake},
		PayloadBucket: "audit-bucket",
		Redactor:      errRedactor{},
	})
	body := envelopeJSON("e1", "2026-07-13T10:00:00Z", map[string]any{"a": 1}, "")
	res := p.Ingest(ctx, body)
	if res.Inserted {
		t.Fatal("should not be inserted on redaction error")
	}
	if res.Reason == "" {
		t.Fatal("expected reason")
	}
}

// errInsertChainedStore is an EventStore whose InsertChained always
// errors. This simulates a failure of the atomic chain-extension path
// (the tx begin, advisory lock, chain-head read, or insert).
type errInsertChainedStore struct {
	*memstore.EventStore
}

func (s *errInsertChainedStore) InsertChained(context.Context, *store.Event, func(prevHash []byte) []byte) (bool, error) {
	return false, errors.New("insert chained boom")
}

func TestIngestInsertChainedError(t *testing.T) {
	ctx := context.Background()
	all := memstore.NewAll()
	fake := s3.NewFake()
	es := &errInsertChainedStore{EventStore: all.Events}
	p := New(Deps{
		Events:        es,
		Payloads:      &PutAdapter{Client: fake},
		PayloadBucket: "audit-bucket",
	})
	body := envelopeJSON("e1", "2026-07-13T10:00:00Z", map[string]any{"a": 1}, "")
	res := p.Ingest(ctx, body)
	if res.Inserted {
		t.Fatal("should not be inserted on chain-extension error")
	}
	if res.Reason == "" {
		t.Fatal("expected reason")
	}
}

func TestIngestDedupWithNoRetention(t *testing.T) {
	ctx := context.Background()
	// Use RetentionDays=0 so the S3 overwrite on the second ingest
	// succeeds; the dedup then happens at the Insert layer.
	all := memstore.NewAll()
	fake := s3.NewFake()
	p := New(Deps{
		Events:        all.Events,
		Payloads:      &PutAdapter{Client: fake},
		PayloadBucket: "audit-bucket",
		RetentionDays: 0,
	})
	body := envelopeJSON("e1", "2026-07-13T10:00:00Z", map[string]any{"a": 1}, "")
	if res := p.Ingest(ctx, body); !res.Inserted {
		t.Fatalf("first insert: %q", res.Reason)
	}
	res := p.Ingest(ctx, body)
	if res.Inserted {
		t.Fatal("second insert should be deduped")
	}
	if res.Reason != "" {
		t.Errorf("dedup should have empty reason, got %q", res.Reason)
	}
}

func TestIngestPayloadHashMismatchWithBody(t *testing.T) {
	ctx := context.Background()
	all := memstore.NewAll()
	fake := s3.NewFake()
	p := New(Deps{
		Events:        all.Events,
		Payloads:      &PutAdapter{Client: fake},
		PayloadBucket: "audit-bucket",
	})
	// Build an envelope with a payload body AND a mismatched but
	// well-formed payload_hash (valid 32-byte sha256 hex of different
	// data) so the mismatch branch is exercised.
	payload := map[string]any{"a": 1}
	otherHash := event.HashPayload([]byte("different"))
	m := map[string]any{
		"id":             "e1",
		"ts":             "2026-07-13T10:00:00Z",
		"source_service": "orch",
		"actor_id":       "u1",
		"action":         "tx.initiated",
		"target_type":    "transaction",
		"target_id":      "tx1",
		"payload":        payload,
		"payload_hash":   otherHash,
	}
	body, _ := json.Marshal(m)
	res := p.Ingest(ctx, body)
	if res.Inserted {
		t.Fatal("mismatched payload_hash should be rejected")
	}
	if res.Reason == "" {
		t.Fatal("expected reason")
	}
}

func TestIngestS3PutError(t *testing.T) {
	ctx := context.Background()
	all := memstore.NewAll()
	p := New(Deps{
		Events:        all.Events,
		Payloads:      errPayloadStore{},
		PayloadBucket: "audit-bucket",
	})
	body := envelopeJSON("e1", "2026-07-13T10:00:00Z", map[string]any{"a": 1}, "")
	res := p.Ingest(ctx, body)
	if res.Inserted {
		t.Fatal("should not be inserted on s3 put error")
	}
	if res.Reason == "" {
		t.Fatal("expected reason")
	}
}

type errPayloadStore struct{}

func (errPayloadStore) Put(context.Context, string, s3.PutOptions, []byte) ([]byte, error) {
	return nil, errors.New("s3 boom")
}