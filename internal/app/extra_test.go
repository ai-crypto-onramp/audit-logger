package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/ai-crypto-onramp/audit-logger/internal/auth"
	"github.com/ai-crypto-onramp/audit-logger/internal/chain"
	"github.com/ai-crypto-onramp/audit-logger/internal/config"
	"github.com/ai-crypto-onramp/audit-logger/internal/event"
	"github.com/ai-crypto-onramp/audit-logger/internal/kms"
	"github.com/ai-crypto-onramp/audit-logger/internal/s3"
	"github.com/ai-crypto-onramp/audit-logger/internal/store"
)

func TestExportPutAdapterPut(t *testing.T) {
	fake := s3.NewFake()
	a := &exportPutAdapter{client: fake}
	body := bytes.NewReader([]byte("hello"))
	key, err := a.Put(context.Background(), "bkt", s3.PutOptions{Key: "k"}, body)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if key != "k" {
		t.Errorf("key: %q", key)
	}
}

func TestSweepVerifierVerifyWindowOK(t *testing.T) {
	cfg := WithDefaults(config.Config{})
	srv, err := Build(cfg)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer func() { _ = srv.Shutdown() }()
	ctx := context.Background()
	// Insert a single event with a computed hash.
	e := &store.Event{ID: "v1", TS: time.Now(), SourceService: "s", PayloadHash: []byte("p")}
	e.ThisHash = chain.EventHash(e)
	_, _ = srv.Stores().Events.Insert(ctx, e)
	v := &sweepVerifier{events: srv.Stores().Events, anchors: srv.Stores().Anchors, signer: kms.NewFake("k").Sign}
	rep, err := v.VerifyWindow(ctx, time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if rep.EventCount != 1 {
		t.Errorf("event count: %d", rep.EventCount)
	}
}

func TestBuildWithRedactionPolicyFile(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/policy.yaml"
	policy := `rules:
  - service: "*"
    action: "*"
    fields:
      password: drop
`
	if err := os.WriteFile(path, []byte(policy), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg := WithDefaults(config.Config{RedactionPolicyPath: path})
	srv, err := Build(cfg)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer func() { _ = srv.Shutdown() }()
	if srv.Redactor() == nil {
		t.Fatal("nil redactor")
	}
	// Reload should succeed (same file).
	if err := srv.Redactor().Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
}

func TestBuildWithS3AndKMSCredsButNoAWSRegion(t *testing.T) {
	cfg := WithDefaults(config.Config{
		PayloadBucket: "audit-bucket",
		KMSKeyID:      "alias/test",
	})
	os.Unsetenv("AWS_REGION")
	srv, err := Build(cfg)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer func() { _ = srv.Shutdown() }()
	// Should fall back to fakes since AWS_REGION unset; ensure no panic.
	if srv.signer == nil {
		t.Fatal("nil signer")
	}
}

func TestBuildWithKafkaBrokers(t *testing.T) {
	cfg := WithDefaults(config.Config{
		KafkaBrokers: []string{"invalid:9999"},
	})
	srv, err := Build(cfg)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer func() { _ = srv.Shutdown() }()
	if srv.Consumer() == nil {
		t.Fatal("nil consumer")
	}
}

func TestStartLoopsAndShutdown(t *testing.T) {
	cfg := WithDefaults(config.Config{
		ChainAnchorInterval: 50 * time.Millisecond,
	})
	srv, err := Build(cfg)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancelled so loops exit immediately
	srv.startLoops(ctx)
	// Wait briefly for goroutines to finish.
	done := make(chan struct{})
	go func() {
		srv.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("loops did not exit")
	}
}

func TestStartLoopsAnchorRunsWithEvents(t *testing.T) {
	cfg := WithDefaults(config.Config{
		ChainAnchorInterval: 20 * time.Millisecond,
	})
	srv, err := Build(cfg)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer func() { _ = srv.Shutdown() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Insert an event so the anchor job has work to do.
	e := &store.Event{ID: "a1", TS: time.Now(), SourceService: "s", PayloadHash: []byte("p")}
	e.ThisHash = chain.EventHash(e)
	_, _ = srv.Stores().Events.Insert(ctx, e)
	srv.startLoops(ctx)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		head, _ := srv.Stores().Events.ChainHead(ctx)
		if head != nil && head.Anchored {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	head, _ := srv.Stores().Events.ChainHead(ctx)
	if head == nil || !head.Anchored {
		t.Fatalf("event not anchored")
	}
}

func TestRunShutdownViaSignal(t *testing.T) {
	cfg := WithDefaults(config.Config{Port: "0"})
	srv, err := Build(cfg)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Run()
	}()
	// Give the server a moment to start, then send SIGINT.
	time.Sleep(100 * time.Millisecond)
	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("find process: %v", err)
	}
	_ = p.Signal(os.Interrupt)
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			// http.ErrServerClosed is the expected graceful shutdown return.
			t.Fatalf("run: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not shut down")
	}
}

func TestHealthzAndMetricsEndpoints(t *testing.T) {
	cfg := WithDefaults(config.Config{})
	srv, err := Build(cfg)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer func() { _ = srv.Shutdown() }()
	ts := httptest.NewServer(srv.HTTPHandler())
	defer ts.Close()
	for _, path := range []string{"/healthz", "/metrics"} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("get %s: %v", path, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s: %d", path, resp.StatusCode)
		}
		resp.Body.Close()
	}
}

func TestSignerReturnsFake(t *testing.T) {
	cfg := WithDefaults(config.Config{KMSKeyID: "alias/x"})
	os.Unsetenv("AWS_REGION")
	srv, err := Build(cfg)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer func() { _ = srv.Shutdown() }()
	if srv.signer == nil {
		t.Fatal("nil signer")
	}
	if srv.signer.KeyID() != "alias/x" {
		t.Errorf("key id: %q", srv.signer.KeyID())
	}
}

func TestIngestViaKafkaFakeWithPayloadHash(t *testing.T) {
	cfg := WithDefaults(config.Config{PayloadBucket: "bkt"})
	srv, err := Build(cfg)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer func() { _ = srv.Shutdown() }()
	ts := httptest.NewServer(srv.HTTPHandler())
	defer ts.Close()
	ctx := context.Background()
	payload := map[string]any{"amount": "100"}
	body, _ := json.Marshal(map[string]any{
		"id":             "11111111-1111-4111-8111-111111111111",
		"ts":             "2026-07-13T10:00:00Z",
		"source_service": "orch",
		"actor_id":       "u1",
		"action":         "tx.initiated",
		"target_type":    "transaction",
		"target_id":      "tx1",
		"payload":        payload,
		"payload_hash":   event.HashPayload(mustJSON(payload)),
	})
	if res := srv.Pipeline().Ingest(ctx, body); !res.Inserted {
		t.Fatalf("ingest: %q", res.Reason)
	}
	// Query with reader role.
	req, _ := http.NewRequest("GET", ts.URL+"/v1/events/11111111-1111-4111-8111-111111111111", nil)
	req.Header.Set(auth.RolesHeader, string(auth.RoleReader))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
}
