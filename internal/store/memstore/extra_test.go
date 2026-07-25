package memstore

import (
	"context"
	"testing"
	"time"

	"github.com/ai-crypto-onramp/audit-logger/internal/store"
)

func TestListFilterSkipBranches(t *testing.T) {
	s := NewEventStore()
	ctx := context.Background()
	t1 := mustParseTime(t, "2026-07-13T10:00:00Z")
	t2 := mustParseTime(t, "2026-07-13T10:00:01Z")
	t3 := mustParseTime(t, "2026-07-13T10:00:02Z")
	_, _ = s.Insert(ctx, sampleEvent("e1", t1, nil))
	e2 := sampleEvent("e2", t2, nil)
	e2.SourceService = "pay"
	e2.Action = "different"
	e2.TargetType = "other"
	_, _ = s.Insert(ctx, e2)
	_, _ = s.Insert(ctx, sampleEvent("e3", t3, nil))

	// From filter skips events before t2.
	res, _ := s.List(ctx, store.Filter{From: t2, Limit: 10})
	if len(res.Events) != 2 {
		t.Errorf("from: %d", len(res.Events))
	}
	// To filter skips events >= t2 (exclusive).
	res, _ = s.List(ctx, store.Filter{To: t2, Limit: 10})
	if len(res.Events) != 1 {
		t.Errorf("to: %d", len(res.Events))
	}
	// Service filter skips non-matching.
	res, _ = s.List(ctx, store.Filter{Service: "pay", Limit: 10})
	if len(res.Events) != 1 {
		t.Errorf("service: %d", len(res.Events))
	}
	// Action filter skips non-matching.
	res, _ = s.List(ctx, store.Filter{Action: "different", Limit: 10})
	if len(res.Events) != 1 {
		t.Errorf("action: %d", len(res.Events))
	}
	// TargetType filter skips non-matching.
	res, _ = s.List(ctx, store.Filter{TargetType: "other", Limit: 10})
	if len(res.Events) != 1 {
		t.Errorf("target_type: %d", len(res.Events))
	}
	// Cursor filter skips events <= cursor.
	res, _ = s.List(ctx, store.Filter{Cursor: store.Cursor{TS: t2, ID: "e2"}, Limit: 10})
	if len(res.Events) != 1 {
		t.Errorf("cursor: %d", len(res.Events))
	}
}

func TestChainHeadCopy(t *testing.T) {
	s := NewEventStore()
	ctx := context.Background()
	t1 := mustParseTime(t, "2026-07-13T10:00:00Z")
	_, _ = s.Insert(ctx, sampleEvent("e1", t1, nil))
	h, err := s.ChainHead(ctx)
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	if h == nil || h.ID != "e1" {
		t.Fatalf("head: %+v", h)
	}
}

func TestAnchorStoreListAnchorsFilters(t *testing.T) {
	s := NewAnchorStore()
	ctx := context.Background()
	from := mustParseTime(t, "2026-07-13T10:00:00Z")
	// Insert two anchors; the second has AnchoredAt = from + 30m.
	a1 := &store.Anchor{RootHash: []byte("r1")}
	_, _ = s.InsertAnchor(ctx, a1)
	// Manually set AnchoredAt on the stored anchor.
	s.mu.Lock()
	a := s.anchors[0]
	a.AnchoredAt = from.Add(15 * time.Minute)
	s.mu.Unlock()

	a2 := &store.Anchor{RootHash: []byte("r2")}
	_, _ = s.InsertAnchor(ctx, a2)
	s.mu.Lock()
	s.anchors[1].AnchoredAt = from.Add(45 * time.Minute)
	s.mu.Unlock()

	// from filter: skip anchors before from.
	res, _ := s.ListAnchors(ctx, from.Add(20*time.Minute), time.Time{})
	if len(res) != 1 {
		t.Errorf("from filter: %d", len(res))
	}
	// to filter: skip anchors after to.
	res, _ = s.ListAnchors(ctx, time.Time{}, from.Add(40*time.Minute))
	if len(res) != 1 {
		t.Errorf("to filter: %d", len(res))
	}
}

func TestAnchorStoreGetAnchorLoop(t *testing.T) {
	s := NewAnchorStore()
	ctx := context.Background()
	id, _ := s.InsertAnchor(ctx, &store.Anchor{RootHash: []byte("r")})
	// Insert a second anchor so the loop visits both.
	_, _ = s.InsertAnchor(ctx, &store.Anchor{RootHash: []byte("r2")})
	got, err := s.GetAnchor(ctx, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil || string(got.RootHash) != "r" {
		t.Errorf("got: %+v", got)
	}
	if _, err := s.GetAnchor(ctx, "nope"); !store.IsNotFound(err) {
		t.Errorf("expected not found, got %v", err)
	}
}

func TestCreateJobDuplicateReturnsNil(t *testing.T) {
	s := NewExportJobStore()
	ctx := context.Background()
	j := &store.ExportJob{ID: "dup", Format: "JSON"}
	if err := s.CreateJob(ctx, j); err != nil {
		t.Fatalf("create: %v", err)
	}
	// Re-create the same id; should be a no-op (return nil) without error.
	if err := s.CreateJob(ctx, &store.ExportJob{ID: "dup", Format: "JSON"}); err != nil {
		t.Fatalf("duplicate create: %v", err)
	}
}

func TestGetJobCopy(t *testing.T) {
	s := NewExportJobStore()
	ctx := context.Background()
	_ = s.CreateJob(ctx, &store.ExportJob{ID: "g1", Format: "JSON"})
	got, err := s.GetJob(ctx, "g1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil || got.ID != "g1" {
		t.Errorf("got: %+v", got)
	}
}

func TestUpdateJobCopy(t *testing.T) {
	s := NewExportJobStore()
	ctx := context.Background()
	_ = s.CreateJob(ctx, &store.ExportJob{ID: "u1", Format: "JSON"})
	if err := s.UpdateJob(ctx, "u1", "COMPLETE", 5, "ref", []byte("root"), "anc", time.Now()); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, _ := s.GetJob(ctx, "u1")
	if got.Status != "COMPLETE" || got.RowCount != 5 || got.AnchorID != "anc" {
		t.Errorf("got: %+v", got)
	}
	if err := s.UpdateJob(ctx, "nope", "x", 0, "", nil, "", time.Time{}); !store.IsNotFound(err) {
		t.Errorf("expected not found, got %v", err)
	}
}

func TestListJobsLimitTruncation(t *testing.T) {
	s := NewExportJobStore()
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		_ = s.CreateJob(ctx, &store.ExportJob{ID: "j" + string(rune('1'+i)), Format: "JSON"})
	}
	all, _ := s.ListJobs(ctx, 3)
	if len(all) != 3 {
		t.Errorf("limit: %d", len(all))
	}
	// limit <= 0 returns all.
	all, _ = s.ListJobs(ctx, 0)
	if len(all) != 5 {
		t.Errorf("no limit: %d", len(all))
	}
}

func TestInsertSortTiebreakByID(t *testing.T) {
	// Two events with the same TS exercise the sort comparator's
	// tiebreak branch (return a.ID < b.ID).
	s := NewEventStore()
	ctx := context.Background()
	ts := mustParseTime(t, "2026-07-13T10:00:00Z")
	_, _ = s.Insert(ctx, sampleEvent("zzz", ts, nil))
	_, _ = s.Insert(ctx, sampleEvent("aaa", ts, nil))
	res, _ := s.List(ctx, store.Filter{Limit: 10})
	if len(res.Events) != 2 {
		t.Fatalf("events: %d", len(res.Events))
	}
	if res.Events[0].ID != "aaa" || res.Events[1].ID != "zzz" {
		t.Errorf("order: %s %s", res.Events[0].ID, res.Events[1].ID)
	}
}

func TestTamperForTestMissingID(t *testing.T) {
	s := NewEventStore()
	// Tampering a non-existent id should be a silent no-op.
	s.TamperForTest("nope", func(e *store.Event) {
		t.Error("should not call fn for missing id")
	})
}

func TestListActorMismatchSkip(t *testing.T) {
	s := NewEventStore()
	ctx := context.Background()
	ts := mustParseTime(t, "2026-07-13T10:00:00Z")
	_, _ = s.Insert(ctx, sampleEvent("e1", ts, nil))
	// Filter by an actor that doesn't match -> skip branch.
	res, _ := s.List(ctx, store.Filter{Actor: "no-such-actor", Limit: 10})
	if len(res.Events) != 0 {
		t.Errorf("expected 0 for mismatched actor, got %d", len(res.Events))
	}
}