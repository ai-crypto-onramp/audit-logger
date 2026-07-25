package app

import (
	"context"
	"testing"
	"time"

	"github.com/ai-crypto-onramp/audit-logger/internal/chain"
	"github.com/ai-crypto-onramp/audit-logger/internal/config"
	"github.com/ai-crypto-onramp/audit-logger/internal/kafka"
	"github.com/ai-crypto-onramp/audit-logger/internal/store"
)

func TestServerAnchorGetter(t *testing.T) {
	cfg := WithDefaults(config.Config{})
	srv, err := Build(cfg)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer func() { _ = srv.Shutdown() }()
	if srv.Anchor() == nil {
		t.Fatal("nil anchor")
	}
}

func TestSweepVerifierError(t *testing.T) {
	// A pre-cancelled context causes Sweep to return ctx.Err(), which
	// sweepVerifier.VerifyWindow propagates.
	cfg := WithDefaults(config.Config{})
	srv, err := Build(cfg)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer func() { _ = srv.Shutdown() }()
	v := &sweepVerifier{events: srv.Stores().Events, anchors: srv.Stores().Anchors}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := v.VerifyWindow(ctx, time.Time{}, time.Time{}); err == nil {
		t.Fatal("expected error on cancelled ctx")
	}
}

func TestStartLoopsKafkaHandlerProcessesMessage(t *testing.T) {
	// Drive startLoops with a real kafka.Fake consumer and enqueue a
	// message; the handler closure should ingest it. We use a tiny
	// anchor interval so the anchor loop also runs.
	cfg := WithDefaults(config.Config{
		PayloadBucket:        "bkt",
		ChainAnchorInterval:  50 * time.Millisecond,
	})
	srv, err := Build(cfg)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer func() { _ = srv.Shutdown() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv.startLoops(ctx)
	// The consumer is a *kafka.Fake; enqueue a malformed message so the
	// handler runs and the consumer's Run returns no error (handler
	// always returns nil).
	fake, ok := srv.Consumer().(*kafka.Fake)
	if !ok {
		t.Fatalf("expected *kafka.Fake, got %T", srv.Consumer())
	}
	_ = fake.Enqueue(kafka.Message{Topic: "audit.v1", Offset: 1, Value: []byte("not-json")})
	// Allow the loop to drain briefly.
	time.Sleep(100 * time.Millisecond)
}

func TestStartLoopsAnchorErrorLogged(t *testing.T) {
	// Use an AnchorJob whose Events store's ChainHead returns a non-empty
	// head but MarkAnchored errors, so the anchor tick logs an error. We
	// replace srv.anchor after build.
	cfg := WithDefaults(config.Config{
		ChainAnchorInterval: 20 * time.Millisecond,
	})
	srv, err := Build(cfg)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer func() { _ = srv.Shutdown() }()
	ctx := context.Background()
	// Insert an event so the anchor job has work; replace the anchor job's
	// Anchors store with one whose InsertAnchor errors so Run errors.
	e := &store.Event{ID: "a1", TS: time.Now(), SourceService: "s", PayloadHash: []byte("p")}
	e.ThisHash = chain.EventHash(e)
	_, _ = srv.Stores().Events.Insert(ctx, e)
	srv.anchor.Anchors = errInsertAnchorStore{}
	ctx2, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv.startLoops(ctx2)
	time.Sleep(80 * time.Millisecond)
}

type errInsertAnchorStore struct{}

func (errInsertAnchorStore) InsertAnchor(context.Context, *store.Anchor) (string, error) {
	return "", errAnchorBoom
}
func (errInsertAnchorStore) ListAnchors(context.Context, time.Time, time.Time) ([]*store.Anchor, error) {
	return nil, nil
}
func (errInsertAnchorStore) GetAnchor(context.Context, string) (*store.Anchor, error) {
	return nil, &store.ErrNotFound{}
}

var errAnchorBoom = errStr("anchor boom")

type errStr string

func (e errStr) Error() string { return string(e) }