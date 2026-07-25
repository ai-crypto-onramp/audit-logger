package memstore

import (
	"context"
	"testing"
	"time"

	"github.com/ai-crypto-onramp/audit-logger/internal/store"
)

func mustParseTime(t *testing.T, s string) time.Time {
	ts, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return ts.UTC()
}

func sampleEvent(id string, ts time.Time, prev []byte) *store.Event {
	return &store.Event{
		ID:            id,
		TS:            ts,
		SourceService: "orch",
		ActorID:       "u1",
		Action:        "tx.initiated",
		TargetType:    "transaction",
		TargetID:      "tx" + id,
		PayloadHash:   []byte("hash-" + id),
		PayloadRef:    "s3://bucket/" + id,
		PrevHash:      prev,
		ThisHash:      []byte("this-" + id),
	}
}

func TestInsertAndGet(t *testing.T) {
	s := NewEventStore()
	ctx := context.Background()
	ts := mustParseTime(t, "2026-07-13T10:00:00Z")
	e := sampleEvent("e1", ts, nil)
	if ok, err := s.Insert(ctx, e); err != nil || !ok {
		t.Fatalf("insert: ok=%v err=%v", ok, err)
	}
	got, err := s.Get(ctx, "e1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ID != "e1" {
		t.Errorf("id: %q", got.ID)
	}
}

func TestInsertIdempotent(t *testing.T) {
	s := NewEventStore()
	ctx := context.Background()
	ts := mustParseTime(t, "2026-07-13T10:00:00Z")
	e := sampleEvent("e1", ts, nil)
	if ok, _ := s.Insert(ctx, e); !ok {
		t.Fatal("first insert should be new")
	}
	if ok, _ := s.Insert(ctx, e); ok {
		t.Fatal("second insert should be no-op")
	}
	if len(s.events) != 1 {
		t.Errorf("events: %d", len(s.events))
	}
}

func TestGetNotFound(t *testing.T) {
	s := NewEventStore()
	_, err := s.Get(context.Background(), "nope")
	if !store.IsNotFound(err) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestListFilter(t *testing.T) {
	s := NewEventStore()
	ctx := context.Background()
	t1 := mustParseTime(t, "2026-07-13T10:00:00Z")
	t2 := mustParseTime(t, "2026-07-13T10:00:01Z")
	t3 := mustParseTime(t, "2026-07-13T10:00:02Z")
	_ = sampleEvent("e1", t1, nil)
	_ = sampleEvent("e2", t2, nil)
	e3 := sampleEvent("e3", t3, nil)
	e3.SourceService = "pay"
	_, _ = s.Insert(ctx, sampleEvent("e1", t1, nil))
	_, _ = s.Insert(ctx, sampleEvent("e2", t2, nil))
	_, _ = s.Insert(ctx, e3)

	// All
	res, err := s.List(ctx, store.Filter{Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(res.Events) != 3 {
		t.Fatalf("all: %d", len(res.Events))
	}

	// By service
	res, _ = s.List(ctx, store.Filter{Service: "orch", Limit: 10})
	if len(res.Events) != 2 {
		t.Errorf("orch: %d", len(res.Events))
	}
	res, _ = s.List(ctx, store.Filter{Service: "pay", Limit: 10})
	if len(res.Events) != 1 {
		t.Errorf("pay: %d", len(res.Events))
	}

	// By time window [t1, t3)
	res, _ = s.List(ctx, store.Filter{From: t1, To: t3, Limit: 10})
	if len(res.Events) != 2 {
		t.Errorf("window: %d", len(res.Events))
	}

	// By actor / action / target
	res, _ = s.List(ctx, store.Filter{Actor: "u1", Limit: 10})
	if len(res.Events) != 3 {
		t.Errorf("actor: %d", len(res.Events))
	}
	res, _ = s.List(ctx, store.Filter{TargetType: "transaction", TargetID: "txe2", Limit: 10})
	if len(res.Events) != 1 {
		t.Errorf("target: %d", len(res.Events))
	}
}

func TestListPagination(t *testing.T) {
	s := NewEventStore()
	ctx := context.Background()
	base := mustParseTime(t, "2026-07-13T10:00:00Z")
	for i := 0; i < 5; i++ {
		_, _ = s.Insert(ctx, sampleEvent("e"+string(rune('1'+i)), base.Add(time.Duration(i)*time.Second), nil))
	}
	res, _ := s.List(ctx, store.Filter{Limit: 2})
	if len(res.Events) != 2 {
		t.Fatalf("page1: %d", len(res.Events))
	}
	if res.Events[0].ID != "e1" || res.Events[1].ID != "e2" {
		t.Errorf("page1 order: %s %s", res.Events[0].ID, res.Events[1].ID)
	}
	if res.NextCursor.ID != "e2" {
		t.Errorf("cursor: %s", res.NextCursor.ID)
	}
	res2, _ := s.List(ctx, store.Filter{Limit: 2, Cursor: res.NextCursor})
	if len(res2.Events) != 2 {
		t.Fatalf("page2: %d", len(res2.Events))
	}
	if res2.Events[0].ID != "e3" || res2.Events[1].ID != "e4" {
		t.Errorf("page2 order: %s %s", res2.Events[0].ID, res2.Events[1].ID)
	}
	res3, _ := s.List(ctx, store.Filter{Limit: 2, Cursor: res2.NextCursor})
	if len(res3.Events) != 1 {
		t.Fatalf("page3: %d", len(res3.Events))
	}
	if res3.Events[0].ID != "e5" {
		t.Errorf("page3 order: %s", res3.Events[0].ID)
	}
	if !res3.NextCursor.TS.IsZero() {
		t.Errorf("expected empty cursor, got %v", res3.NextCursor)
	}
}

func TestChainHead(t *testing.T) {
	s := NewEventStore()
	ctx := context.Background()
	if h, _ := s.ChainHead(ctx); h != nil {
		t.Fatal("empty chain head should be nil")
	}
	t1 := mustParseTime(t, "2026-07-13T10:00:00Z")
	t2 := mustParseTime(t, "2026-07-13T10:00:01Z")
	_, _ = s.Insert(ctx, sampleEvent("e1", t1, nil))
	_, _ = s.Insert(ctx, sampleEvent("e2", t2, []byte("prev")))
	h, _ := s.ChainHead(ctx)
	if h.ID != "e2" {
		t.Errorf("head: %s", h.ID)
	}
}

func TestSetLegalHold(t *testing.T) {
	s := NewEventStore()
	ctx := context.Background()
	t1 := mustParseTime(t, "2026-07-13T10:00:00Z")
	_, _ = s.Insert(ctx, sampleEvent("e1", t1, nil))
	if err := s.SetLegalHold(ctx, "e1", true); err != nil {
		t.Fatalf("set hold: %v", err)
	}
	got, _ := s.Get(ctx, "e1")
	if !got.LegalHold {
		t.Error("LegalHold not set")
	}
	_ = s.SetLegalHold(ctx, "e1", false)
	got, _ = s.Get(ctx, "e1")
	if got.LegalHold {
		t.Error("LegalHold not cleared")
	}
	if err := s.SetLegalHold(ctx, "nope", true); !store.IsNotFound(err) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestMarkAnchored(t *testing.T) {
	s := NewEventStore()
	ctx := context.Background()
	t1 := mustParseTime(t, "2026-07-13T10:00:00Z")
	t2 := mustParseTime(t, "2026-07-13T10:00:01Z")
	t3 := mustParseTime(t, "2026-07-13T10:00:02Z")
	_, _ = s.Insert(ctx, sampleEvent("e1", t1, nil))
	_, _ = s.Insert(ctx, sampleEvent("e2", t2, nil))
	_, _ = s.Insert(ctx, sampleEvent("e3", t3, nil))
	n, err := s.MarkAnchored(ctx, t2, "e2")
	if err != nil {
		t.Fatalf("anchored: %v", err)
	}
	if n != 2 {
		t.Errorf("anchored count: %d", n)
	}
	// Re-anchoring same window -> 0 newly anchored.
	n, _ = s.MarkAnchored(ctx, t2, "e2")
	if n != 0 {
		t.Errorf("re-anchor count: %d", n)
	}
	// Anchor everything.
	n, _ = s.MarkAnchored(ctx, t3, "e3")
	if n != 1 {
		t.Errorf("final anchor count: %d", n)
	}
}

func TestAnchorStore(t *testing.T) {
	s := NewAnchorStore()
	ctx := context.Background()
	id, err := s.InsertAnchor(ctx, &store.Anchor{RootHash: []byte("root1"), EventCount: 10})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if id == "" {
		t.Errorf("id: %q", id)
	}
	id2, _ := s.InsertAnchor(ctx, &store.Anchor{RootHash: []byte("root2"), EventCount: 5})
	if id2 == "" {
		t.Errorf("id2: %q", id2)
	}
	all, _ := s.ListAnchors(ctx, time.Time{}, time.Time{})
	if len(all) != 2 {
		t.Errorf("list: %d", len(all))
	}
	got, _ := s.GetAnchor(ctx, id)
	if got == nil || string(got.RootHash) != "root1" {
		t.Errorf("get: %+v", got)
	}
}

func TestExportJobStore(t *testing.T) {
	s := NewExportJobStore()
	ctx := context.Background()
	j := &store.ExportJob{ID: "x1", Format: "JSON", Status: "PENDING"}
	if err := s.CreateJob(ctx, j); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.UpdateJob(ctx, "x1", "COMPLETE", 100, "s3://bucket/x1", []byte("root"), "anchor-1", time.Now()); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, _ := s.GetJob(ctx, "x1")
	if got.Status != "COMPLETE" || got.RowCount != 100 || got.AnchorID != "anchor-1" {
		t.Errorf("got: %+v", got)
	}
	// List
	j2 := &store.ExportJob{ID: "x2", Format: "CSV", Status: "PENDING"}
	_ = s.CreateJob(ctx, j2)
	all, _ := s.ListJobs(ctx, 10)
	if len(all) != 2 {
		t.Errorf("list: %d", len(all))
	}
}

func TestDeadLetterStore(t *testing.T) {
	s := NewDeadLetterStore()
	ctx := context.Background()
	_ = s.Append(ctx, &store.DeadLetter{Topic: "audit.v1", Payload: []byte("bad"), Reason: "missing id"})
	_ = s.Append(ctx, &store.DeadLetter{Topic: "audit.v1", Payload: []byte("worse"), Reason: "missing ts"})
	all, _ := s.List(ctx, 10)
	if len(all) != 2 {
		t.Fatalf("list: %d", len(all))
	}
	if all[0].Reason != "missing ts" {
		t.Errorf("newest first: %q", all[0].Reason)
	}
}

func TestCursorRoundtrip(t *testing.T) {
	ts := mustParseTime(t, "2026-07-13T10:00:00.123456789Z")
	c := store.Cursor{TS: ts, ID: "e1"}
	s := c.String()
	c2, err := store.ParseCursor(s)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !c2.TS.Equal(c.TS) || c2.ID != c.ID {
		t.Errorf("roundtrip: %+v", c2)
	}
	empty, _ := store.ParseCursor("")
	if !empty.TS.IsZero() || empty.ID != "" {
		t.Errorf("empty cursor: %+v", empty)
	}
	if _, err := store.ParseCursor("bad"); err == nil {
		t.Error("expected parse error")
	}
}

func TestNewAll(t *testing.T) {
	all := NewAll()
	if all.Events == nil || all.Anchors == nil || all.Exports == nil || all.DeadLetters == nil {
		t.Fatal("missing store")
	}
}