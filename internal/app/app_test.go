package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ai-crypto-onramp/audit-logger/internal/auth"
	"github.com/ai-crypto-onramp/audit-logger/internal/config"
	"github.com/ai-crypto-onramp/audit-logger/internal/event"
	"github.com/ai-crypto-onramp/audit-logger/internal/kafka"
	"github.com/ai-crypto-onramp/audit-logger/internal/store"
)

// WithDefaults returns cfg with safe test defaults applied.
func WithDefaults(cfg config.Config) config.Config {
	if cfg.Port == "" {
		cfg.Port = "0"
	}
	if cfg.KafkaTopic == "" {
		cfg.KafkaTopic = "audit.v1"
	}
	if cfg.KafkaConsumerGroup == "" {
		cfg.KafkaConsumerGroup = "audit-event-log"
	}
	if cfg.RetentionDays == 0 {
		cfg.RetentionDays = 2555
	}
	if cfg.ChainAnchorInterval == 0 {
		cfg.ChainAnchorInterval = time.Hour
	}
	if cfg.PayloadStorageClass == "" {
		cfg.PayloadStorageClass = "STANDARD"
	}
	return cfg
}

func TestBuildDefault(t *testing.T) {
	cfg := WithDefaults(config.Config{})
	srv, err := Build(cfg)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer func() { _ = srv.Shutdown() }()
	if srv.HTTPHandler() == nil {
		t.Fatal("nil handler")
	}
	if srv.Pipeline() == nil {
		t.Fatal("nil pipeline")
	}
	if srv.Consumer() == nil {
		t.Fatal("nil consumer")
	}
}

func TestHealthzSmoke(t *testing.T) {
	cfg := WithDefaults(config.Config{})
	srv, err := Build(cfg)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer func() { _ = srv.Shutdown() }()
	ts := httptest.NewServer(srv.HTTPHandler())
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
}

func TestIngestAndQueryEndToEnd(t *testing.T) {
	cfg := WithDefaults(config.Config{
		PayloadBucket: "audit-bucket",
	})
	srv, err := Build(cfg)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer func() { _ = srv.Shutdown() }()
	ts := httptest.NewServer(srv.HTTPHandler())
	defer ts.Close()

	// Enqueue an event via the Kafka fake.
	fake, ok := srv.Consumer().(*kafka.Fake)
	if !ok {
		t.Fatalf("expected *kafka.Fake, got %T", srv.Consumer())
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Consumer().Run(ctx, func(ctx context.Context, msg kafka.Message) error {
		_ = srv.Pipeline().Ingest(ctx, msg.Value)
		return nil
	}) }()
	payload := map[string]any{"amount": "100"}
	body, _ := json.Marshal(map[string]any{
		"id":             "evt1",
		"ts":             "2026-07-13T10:00:00Z",
		"source_service": "orch",
		"actor_id":       "u1",
		"action":         "tx.initiated",
		"target_type":    "transaction",
		"target_id":      "tx1",
		"payload":        payload,
		"payload_hash":   event.HashPayload(mustJSON(payload)),
	})
	if err := fake.Enqueue(kafka.Message{Topic: "audit.v1", Offset: 1, Value: body}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	// Wait for the event to be ingested.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := srv.Stores().Events.Get(ctx, "evt1"); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := srv.Stores().Events.Get(ctx, "evt1"); err != nil {
		t.Fatalf("event not ingested: %v", err)
	}

	// Query via the API.
	req, _ := http.NewRequest("GET", ts.URL+"/v1/events?service=orch", nil)
	req.Header.Set(auth.RolesHeader, string(auth.RoleReader))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	events := out["events"].([]any)
	if len(events) != 1 {
		t.Fatalf("events: %d", len(events))
	}
}

func TestBuildWithRedactionPolicyPath(t *testing.T) {
	cfg := WithDefaults(config.Config{
		RedactionPolicyPath: "/no/such/path/redaction.yaml",
	})
	srv, err := Build(cfg)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer func() { _ = srv.Shutdown() }()
	if srv.Redactor() == nil {
		t.Fatal("nil redactor")
	}
}

func TestBuildWithPostgresFallback(t *testing.T) {
	cfg := WithDefaults(config.Config{
		DBURL: "postgres://invalid:5432/audit",
	})
	srv, err := Build(cfg)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer func() { _ = srv.Shutdown() }()
	// Should fall back to in-memory stores; verify by inserting an event.
	ctx := context.Background()
	_, err = srv.Stores().Events.Insert(ctx, &store.Event{ID: "e1", TS: time.Now()})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}