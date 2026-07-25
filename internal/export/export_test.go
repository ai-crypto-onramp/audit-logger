package export

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/ai-crypto-onramp/audit-logger/internal/chain"
	"github.com/ai-crypto-onramp/audit-logger/internal/kms"
	"github.com/ai-crypto-onramp/audit-logger/internal/s3"
	"github.com/ai-crypto-onramp/audit-logger/internal/store"
	"github.com/ai-crypto-onramp/audit-logger/internal/store/memstore"
)

func mustTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t.UTC()
}

func seed(t *testing.T, all *memstore.All) []*store.Event {
	t.Helper()
	ctx := context.Background()
	var prev []byte = chain.ZeroHash
	var events []*store.Event
	base := mustTime("2026-07-13T10:00:00Z")
	for i := 0; i < 4; i++ {
		e := &store.Event{
			ID:            "e" + string(rune('a'+i)),
			TS:            base.Add(time.Duration(i) * time.Second),
			SourceService: "orch",
			ActorID:       "u1",
			Action:        "tx.initiated",
			TargetType:    "transaction",
			TargetID:      "tx" + string(rune('a'+i)),
			PayloadHash:   []byte("ph"),
			PayloadRef:    "e" + string(rune('a'+i)),
			PrevHash:      append([]byte(nil), prev...),
		}
		e.ThisHash = chain.EventHash(e)
		prev = e.ThisHash
		events = append(events, e)
		_, _ = all.Events.Insert(ctx, e)
	}
	return events
}

func newRunner(t *testing.T, withSigner bool) (*Runner, *memstore.All, *s3.Fake) {
	t.Helper()
	all := memstore.NewAll()
	seed(t, all)
	fake := s3.NewFake()
	var signer kms.Signer
	if withSigner {
		signer = kms.NewFake("alias/test")
	}
	r := New(Deps{
		Events:              all.Events,
		Anchors:             all.Anchors,
		Jobs:                all.Exports,
		Payloads:            &s3PutAdapter{fake},
		PayloadBucket:       "audit-bucket",
		Signer:              signer,
		DefaultRetentionDays: 2555,
	})
	return r, all, fake
}

// s3PutAdapter adapts s3.Fake to the io.Reader-based PayloadStore.
type s3PutAdapter struct {
	f *s3.Fake
}

func (a *s3PutAdapter) Put(ctx context.Context, bucket string, opts s3.PutOptions, body io.Reader) (string, error) {
	key, err := a.f.Put(ctx, bucket, opts, body)
	if err != nil {
		return "", err
	}
	return key, nil
}

func TestRunJobJSON(t *testing.T) {
	ctx := context.Background()
	r, all, fake := newRunner(t, true)
	job := &store.ExportJob{
		ID:            "exp1",
		Format:        "JSON",
		RetentionDays: 100,
		Status:        "PENDING",
	}
	_ = all.Exports.CreateJob(ctx, job)
	if err := r.RunJob(ctx, job); err != nil {
		t.Fatalf("run: %v", err)
	}
	got, _ := all.Exports.GetJob(ctx, "exp1")
	if got.Status != "COMPLETE" {
		t.Errorf("status: %s", got.Status)
	}
	if got.RowCount != 4 {
		t.Errorf("row count: %d", got.RowCount)
	}
	if got.PayloadRef == "" {
		t.Error("missing payload ref")
	}
	if got.AnchorID == "" {
		t.Error("missing anchor id")
	}
	if len(got.ChainRoot) != 32 {
		t.Errorf("chain root len: %d", len(got.ChainRoot))
	}
	// S3 object should exist and be retained.
	obj, _ := fake.Head(ctx, "audit-bucket", "exports/exp1.json")
	if obj == nil {
		t.Fatal("export artifact not in S3")
	}
	if obj.RetentionDays != 100 {
		t.Errorf("retention: %d", obj.RetentionDays)
	}
}

func TestRunJobCSV(t *testing.T) {
	ctx := context.Background()
	r, all, fake := newRunner(t, false)
	job := &store.ExportJob{
		ID:            "exp2",
		Format:        "CSV",
		RetentionDays: 100,
		Status:        "PENDING",
	}
	_ = all.Exports.CreateJob(ctx, job)
	if err := r.RunJob(ctx, job); err != nil {
		t.Fatalf("run: %v", err)
	}
	got, _ := all.Exports.GetJob(ctx, "exp2")
	if got.Status != "COMPLETE" {
		t.Errorf("status: %s", got.Status)
	}
	if got.RowCount != 4 {
		t.Errorf("row count: %d", got.RowCount)
	}
	body, _ := fake.Get(ctx, "audit-bucket", "exports/exp2.csv")
	if !strings.HasPrefix(string(body), "{") {
		t.Fatal("expected manifest line first")
	}
	// Find the CSV header line after the manifest.
	if !strings.Contains(string(body), "id,ts,source_service") {
		t.Errorf("missing CSV header: %q", body[:200])
	}
	// 1 manifest JSON line + 1 header + 4 rows.
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) < 5 {
		t.Errorf("lines: %d", len(lines))
	}
}

func TestRunJobFilter(t *testing.T) {
	ctx := context.Background()
	r, all, _ := newRunner(t, false)
	query := map[string]any{"service": "pay"}
	qb, _ := json.Marshal(query)
	job := &store.ExportJob{
		ID:            "exp3",
		Format:        "JSON",
		RetentionDays: 100,
		Status:        "PENDING",
		Query:         qb,
	}
	_ = all.Exports.CreateJob(ctx, job)
	if err := r.RunJob(ctx, job); err != nil {
		t.Fatalf("run: %v", err)
	}
	got, _ := all.Exports.GetJob(ctx, "exp3")
	if got.RowCount != 0 {
		t.Errorf("expected 0 rows for pay, got %d", got.RowCount)
	}
}

func TestRunJobFailedMarksJob(t *testing.T) {
	ctx := context.Background()
	all := memstore.NewAll()
	// Use a List implementation that always errors.
	r := New(Deps{
		Events:        errStore{},
		Jobs:          all.Exports,
		PayloadBucket: "bkt",
		Payloads:      &s3PutAdapter{s3.NewFake()},
	})
	job := &store.ExportJob{ID: "exp4", Format: "JSON", Status: "PENDING"}
	_ = all.Exports.CreateJob(ctx, job)
	if err := r.RunJob(ctx, job); err == nil {
		t.Fatal("expected error")
	}
	got, _ := all.Exports.GetJob(ctx, "exp4")
	if got.Status != "FAILED" {
		t.Errorf("expected FAILED, got %s", got.Status)
	}
}

type errStore struct{}

func (errStore) Insert(context.Context, *store.Event) (bool, error) { return false, nil }
func (errStore) Get(context.Context, string) (*store.Event, error) { return nil, &store.ErrNotFound{} }
func (errStore) List(context.Context, store.Filter) (*store.ListResult, error) {
	return nil, errBoom
}
func (errStore) ChainHead(context.Context) (*store.Event, error) { return nil, nil }
func (errStore) SetLegalHold(context.Context, string, bool) error { return nil }
func (errStore) MarkAnchored(context.Context, time.Time, string) (int64, error) { return 0, nil }

var errBoom = &errStr{"boom"}

type errStr struct{ s string }

func (e *errStr) Error() string { return e.s }

func TestSerializeCSVHeader(t *testing.T) {
	out, err := serializeCSV(nil)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	if !strings.HasPrefix(string(out), "id,ts,") {
		t.Errorf("header: %q", out)
	}
}

func TestExtForFormat(t *testing.T) {
	if extForFormat("json") != "json" {
		t.Error("json ext")
	}
	if extForFormat("csv") != "csv" {
		t.Error("csv ext")
	}
	if extForFormat("xml") != "json" {
		t.Error("xml fallback to json")
	}
}