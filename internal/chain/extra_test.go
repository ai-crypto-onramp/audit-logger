package chain

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ai-crypto-onramp/audit-logger/internal/event"
	"github.com/ai-crypto-onramp/audit-logger/internal/store"
	"github.com/ai-crypto-onramp/audit-logger/internal/store/memstore"
)

func TestEventHashFromEnvelopeError(t *testing.T) {
	// A malformed payload_hash triggers the error branch.
	ev := &event.Envelope{
		ID:            "e1",
		TS:            mustTime(t, "2026-07-13T10:00:00Z"),
		SourceService: "orch",
		ActorID:       "u1",
		Action:        "act",
		TargetType:    "tt",
		TargetID:      "tid",
		PayloadHash:   "sha256:bad",
	}
	if _, err := EventHashFromEnvelope(ev, ZeroHash); err == nil {
		t.Fatal("expected error for bad payload_hash")
	}
}

// errChainHeadStore is an EventStore whose ChainHead always errors.
type errChainHeadStore struct {
	*memstore.EventStore
}

func (s *errChainHeadStore) ChainHead(context.Context) (*store.Event, error) {
	return nil, errors.New("chain head boom")
}

func TestAnchorJobChainHeadError(t *testing.T) {
	all := memstore.NewAll()
	job := &AnchorJob{
		Events:  &errChainHeadStore{EventStore: all.Events},
		Anchors: all.Anchors,
		Signer:  func([]byte) ([]byte, string, error) { return nil, "", nil },
	}
	if _, err := job.Run(context.Background()); err == nil {
		t.Fatal("expected chain head error")
	}
}

func TestAnchorJobBadRootHash(t *testing.T) {
	all := memstore.NewAll()
	ctx := context.Background()
	// Insert an event whose ThisHash is not 32 bytes.
	e := &store.Event{
		ID:            "e1",
		TS:            mustTime(t, "2026-07-13T10:00:00Z"),
		SourceService: "s",
		PayloadHash:   []byte("p"),
		ThisHash:      []byte("short"),
	}
	_, _ = all.Events.Insert(ctx, e)
	job := &AnchorJob{
		Events:  all.Events,
		Anchors: all.Anchors,
		Signer:  func([]byte) ([]byte, string, error) { return nil, "", nil },
	}
	if _, err := job.Run(ctx); err == nil {
		t.Fatal("expected bad root hash error")
	}
}

func TestAnchorJobSignerError(t *testing.T) {
	all := memstore.NewAll()
	ctx := context.Background()
	events := makeChain(1)
	for _, e := range events {
		_, _ = all.Events.Insert(ctx, e)
	}
	job := &AnchorJob{
		Events:  all.Events,
		Anchors: all.Anchors,
		Signer:  func([]byte) ([]byte, string, error) { return nil, "", errors.New("sign boom") },
	}
	if _, err := job.Run(ctx); err == nil {
		t.Fatal("expected signer error")
	}
}

// errAnchorStore is an AnchorStore whose InsertAnchor always errors.
type errAnchorStore struct {
	*memstore.AnchorStore
}

func (s *errAnchorStore) InsertAnchor(context.Context, *store.Anchor) (string, error) {
	return "", errors.New("anchor insert boom")
}

func TestAnchorJobInsertAnchorError(t *testing.T) {
	all := memstore.NewAll()
	ctx := context.Background()
	events := makeChain(1)
	for _, e := range events {
		_, _ = all.Events.Insert(ctx, e)
	}
	job := &AnchorJob{
		Events:  all.Events,
		Anchors: &errAnchorStore{AnchorStore: all.Anchors},
		Signer:  func([]byte) ([]byte, string, error) { return []byte("sig"), "k", nil },
	}
	if _, err := job.Run(ctx); err == nil {
		t.Fatal("expected insert anchor error")
	}
}

// errMarkAnchoredStore is an EventStore whose MarkAnchored always errors.
type errMarkAnchoredStore struct {
	*memstore.EventStore
}

func (s *errMarkAnchoredStore) MarkAnchored(context.Context, time.Time, string) (int64, error) {
	return 0, errors.New("mark anchored boom")
}

func TestAnchorJobMarkAnchoredError(t *testing.T) {
	all := memstore.NewAll()
	ctx := context.Background()
	events := makeChain(1)
	for _, e := range events {
		_, _ = all.Events.Insert(ctx, e)
	}
	job := &AnchorJob{
		Events:  &errMarkAnchoredStore{EventStore: all.Events},
		Anchors: all.Anchors,
		Signer:  func([]byte) ([]byte, string, error) { return []byte("sig"), "k", nil },
	}
	if _, err := job.Run(ctx); err == nil {
		t.Fatal("expected mark anchored error")
	}
}

func TestAnchorJobEventCountCallback(t *testing.T) {
	all := memstore.NewAll()
	ctx := context.Background()
	events := makeChain(2)
	for _, e := range events {
		_, _ = all.Events.Insert(ctx, e)
	}
	job := &AnchorJob{
		Events:     all.Events,
		Anchors:    all.Anchors,
		Signer:     func([]byte) ([]byte, string, error) { return []byte("sig"), "k", nil },
		EventCount: func(context.Context) (int64, error) { return 42, nil },
	}
	anchor, err := job.Run(ctx)
	if err != nil {
		t.Fatalf("anchor: %v", err)
	}
	if anchor.EventCount != 42 {
		t.Errorf("event count: %d", anchor.EventCount)
	}
}

func TestSweepContextCancelled(t *testing.T) {
	all := memstore.NewAll()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Sweep(ctx, all.Events, all.Anchors, time.Time{}, time.Time{}, nil); err == nil {
		t.Fatal("expected ctx error")
	}
}

func TestSweepAnchorCountAndSignerError(t *testing.T) {
	ctx := context.Background()
	all, events := buildChain(t, 3)
	_ = events
	// Insert an anchor so AnchorCount > 0 (exercises the int64 cast).
	signer := NewFakeSigner()
	job := &AnchorJob{Events: all.Events, Anchors: all.Anchors, Signer: signer.Sign}
	if _, err := job.Run(ctx); err != nil {
		t.Fatalf("anchor: %v", err)
	}
	// Now run Sweep with a signer that errors; the report should still
	// complete (signer error is swallowed) and AnchorCount should be set.
	rep, err := Sweep(ctx, all.Events, all.Anchors, time.Time{}, time.Time{}, errSignerFn)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if rep.AnchorCount == 0 {
		t.Error("expected anchor count > 0")
	}
	// Signer error means no signature is embedded.
	if rep.Signature != "" {
		t.Errorf("signature should be empty on signer error, got %q", rep.Signature)
	}
}

// NewFakeSigner returns a real kms.Fake-based signer; defined here to avoid
// importing kms in this test file (re-using the buildChain helper which
// already imports store/memstore).
func NewFakeSigner() *fakeSigner { return &fakeSigner{} }

type fakeSigner struct{}

func (f *fakeSigner) Sign(digest []byte) ([]byte, string, error) {
	// Return a deterministic non-empty signature.
	return append([]byte(nil), digest...), "fake-key", nil
}

func errSignerFn([]byte) ([]byte, string, error) { return nil, "", errors.New("sign boom") }