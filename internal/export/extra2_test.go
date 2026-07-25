package export

import (
	"context"
	"testing"
	"time"

	"github.com/ai-crypto-onramp/audit-logger/internal/chain"
	"github.com/ai-crypto-onramp/audit-logger/internal/s3"
	"github.com/ai-crypto-onramp/audit-logger/internal/store"
	"github.com/ai-crypto-onramp/audit-logger/internal/store/memstore"
)

func TestRunJobBrokenChainRootFallback(t *testing.T) {
	// A tampered event makes VerifyChain return a nil root, so RunJob
	// falls back to chain.ZeroHash for chainRoot (the `len != 32` branch).
	ctx := context.Background()
	all := memstore.NewAll()
	base := mustTime("2026-07-13T10:00:00Z")
	// Insert two events; tamper the second's this_hash so the chain is
	// broken and VerifyChain returns (broken, nil).
	e1 := &store.Event{
		ID:            "e1",
		TS:            base,
		SourceService: "s",
		ActorID:       "u",
		Action:        "a",
		TargetType:    "t",
		TargetID:      "ti",
		PayloadHash:   []byte("p"),
		PrevHash:      chain.ZeroHash,
	}
	e1.ThisHash = chain.EventHash(e1)
	_, _ = all.Events.Insert(ctx, e1)
	e2 := &store.Event{
		ID:            "e2",
		TS:            base.Add(time.Second),
		SourceService: "s",
		ActorID:       "u",
		Action:        "a",
		TargetType:    "t",
		TargetID:      "ti",
		PayloadHash:   []byte("p"),
		PrevHash:      append([]byte(nil), e1.ThisHash...),
	}
	e2.ThisHash = chain.EventHash(e2)
	_, _ = all.Events.Insert(ctx, e2)
	// Tamper e2's actor so this_hash no longer matches.
	all.Events.TamperForTest("e2", func(e *store.Event) {
		e.ActorID = "tampered"
	})
	r := New(Deps{
		Events:        all.Events,
		Jobs:          all.Exports,
		Payloads:      &s3PutAdapter{s3.NewFake()},
		PayloadBucket: "bkt",
	})
	job := &store.ExportJob{ID: "exp-broken", Format: "JSON", RetentionDays: 30, Status: "PENDING"}
	_ = all.Exports.CreateJob(ctx, job)
	if err := r.RunJob(ctx, job); err != nil {
		t.Fatalf("run: %v", err)
	}
	got, _ := all.Exports.GetJob(ctx, "exp-broken")
	// The chain root should be ZeroHash (32 zero bytes) due to the fallback.
	if len(got.ChainRoot) != 32 {
		t.Errorf("chain root len: %d", len(got.ChainRoot))
	}
	for _, b := range got.ChainRoot {
		if b != 0 {
			t.Fatal("expected zero chain root")
		}
	}
}

func TestRunJobPaginates(t *testing.T) {
	// Insert more than 1000 events so RunJob's List pagination
	// continuation (filter.Cursor = res.NextCursor) is exercised.
	ctx := context.Background()
	all := memstore.NewAll()
	base := mustTime("2026-07-13T10:00:00Z")
	var prev []byte = chain.ZeroHash
	for i := 0; i < 1001; i++ {
		id := padID(i)
		e := &store.Event{
			ID:            id,
			TS:            base.Add(time.Duration(i) * time.Millisecond),
			SourceService: "s",
			ActorID:       "u",
			Action:        "a",
			TargetType:    "t",
			TargetID:      "ti",
			PayloadHash:   []byte("p"),
			PrevHash:      append([]byte(nil), prev...),
		}
		e.ThisHash = chain.EventHash(e)
		prev = e.ThisHash
		_, _ = all.Events.Insert(ctx, e)
	}
	r := New(Deps{
		Events:        all.Events,
		Jobs:          all.Exports,
		Payloads:      &s3PutAdapter{s3.NewFake()},
		PayloadBucket: "bkt",
	})
	job := &store.ExportJob{ID: "exp-page", Format: "JSON", RetentionDays: 30, Status: "PENDING"}
	_ = all.Exports.CreateJob(ctx, job)
	if err := r.RunJob(ctx, job); err != nil {
		t.Fatalf("run: %v", err)
	}
	got, _ := all.Exports.GetJob(ctx, "exp-page")
	if got.RowCount != 1001 {
		t.Errorf("row count: %d", got.RowCount)
	}
}

func padID(n int) string {
	const digits = "0123456789"
	s := make([]byte, 4)
	for i := 3; i >= 0; i-- {
		s[i] = digits[n%10]
		n /= 10
	}
	return "e" + string(s)
}