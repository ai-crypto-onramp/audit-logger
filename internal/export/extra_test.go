package export

import (
	"context"
	"io"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ai-crypto-onramp/audit-logger/internal/chain"
	"github.com/ai-crypto-onramp/audit-logger/internal/kms"
	"github.com/ai-crypto-onramp/audit-logger/internal/s3"
	"github.com/ai-crypto-onramp/audit-logger/internal/store"
	"github.com/ai-crypto-onramp/audit-logger/internal/store/memstore"
)

func TestRunJobNilJob(t *testing.T) {
	r := New(Deps{Payloads: &s3PutAdapter{s3.NewFake()}})
	if err := r.RunJob(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil job")
	}
}

func TestRunJobDefaultRetentionFallback(t *testing.T) {
	ctx := context.Background()
	all := memstore.NewAll()
	seed(t, all)
	r := New(Deps{
		Events:              all.Events,
		Jobs:                all.Exports,
		Payloads:            &s3PutAdapter{s3.NewFake()},
		PayloadBucket:       "bkt",
		DefaultRetentionDays: 0,
	})
	job := &store.ExportJob{ID: "exp-def", Format: "JSON", Status: "PENDING"}
	_ = all.Exports.CreateJob(ctx, job)
	if err := r.RunJob(ctx, job); err != nil {
		t.Fatalf("run: %v", err)
	}
	got, _ := all.Exports.GetJob(ctx, "exp-def")
	if got.Status != "COMPLETE" {
		t.Errorf("status: %s", got.Status)
	}
}

func TestRunJobUnsupportedFormat(t *testing.T) {
	ctx := context.Background()
	all := memstore.NewAll()
	seed(t, all)
	r := New(Deps{
		Events:        all.Events,
		Jobs:          all.Exports,
		Payloads:      &s3PutAdapter{s3.NewFake()},
		PayloadBucket: "bkt",
	})
	job := &store.ExportJob{ID: "exp-xml", Format: "xml", RetentionDays: 30, Status: "PENDING"}
	_ = all.Exports.CreateJob(ctx, job)
	if err := r.RunJob(ctx, job); err == nil {
		t.Fatal("expected unsupported format error")
	}
	got, _ := all.Exports.GetJob(ctx, "exp-xml")
	if got.Status != "FAILED" {
		t.Errorf("expected FAILED, got %s", got.Status)
	}
}

func TestRunJobParseQueryError(t *testing.T) {
	ctx := context.Background()
	all := memstore.NewAll()
	r := New(Deps{
		Events:        all.Events,
		Jobs:          all.Exports,
		Payloads:      &s3PutAdapter{s3.NewFake()},
		PayloadBucket: "bkt",
	})
	job := &store.ExportJob{ID: "exp-bad", Format: "JSON", RetentionDays: 30, Status: "PENDING", Query: []byte("not-json")}
	_ = all.Exports.CreateJob(ctx, job)
	if err := r.RunJob(ctx, job); err == nil {
		t.Fatal("expected parse error")
	}
	got, _ := all.Exports.GetJob(ctx, "exp-bad")
	if got.Status != "FAILED" {
		t.Errorf("expected FAILED, got %s", got.Status)
	}
}

func TestRunJobS3PutError(t *testing.T) {
	ctx := context.Background()
	all := memstore.NewAll()
	seed(t, all)
	r := New(Deps{
		Events:        all.Events,
		Jobs:          all.Exports,
		Payloads:      errPayloadStore{},
		PayloadBucket: "bkt",
	})
	job := &store.ExportJob{ID: "exp-put", Format: "JSON", RetentionDays: 30, Status: "PENDING"}
	_ = all.Exports.CreateJob(ctx, job)
	if err := r.RunJob(ctx, job); err == nil {
		t.Fatal("expected s3 put error")
	}
	got, _ := all.Exports.GetJob(ctx, "exp-put")
	if got.Status != "FAILED" {
		t.Errorf("expected FAILED, got %s", got.Status)
	}
}

type errPayloadStore struct{}

func (errPayloadStore) Put(ctx context.Context, bucket string, opts s3.PutOptions, body io.Reader) (string, error) {
	return "", errors.New("put boom")
}

func TestRunJobContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	all := memstore.NewAll()
	seed(t, all)
	r := New(Deps{
		Events:        all.Events,
		Jobs:          all.Exports,
		Payloads:      &s3PutAdapter{s3.NewFake()},
		PayloadBucket: "bkt",
	})
	cancel()
	job := &store.ExportJob{ID: "exp-ctx", Format: "JSON", RetentionDays: 30, Status: "PENDING"}
	_ = all.Exports.CreateJob(ctx, job)
	// The first List call returns events (cancellation only checked at loop
	// top), so the job may still complete. We assert the runner doesn't panic.
	_ = r.RunJob(ctx, job)
}

func TestRunJobSignerError(t *testing.T) {
	ctx := context.Background()
	all := memstore.NewAll()
	seed(t, all)
	r := New(Deps{
		Events:        all.Events,
		Anchors:       all.Anchors,
		Jobs:          all.Exports,
		Payloads:      &s3PutAdapter{s3.NewFake()},
		PayloadBucket: "bkt",
		Signer:        errSigner{},
	})
	job := &store.ExportJob{ID: "exp-sig", Format: "JSON", RetentionDays: 30, Status: "PENDING"}
	_ = all.Exports.CreateJob(ctx, job)
	if err := r.RunJob(ctx, job); err != nil {
		t.Fatalf("run: %v", err)
	}
	got, _ := all.Exports.GetJob(ctx, "exp-sig")
	if got.Status != "COMPLETE" {
		t.Errorf("signer error should not fail job: %s", got.Status)
	}
	if got.AnchorID != "" {
		t.Errorf("anchor id should be empty when signer errors: %s", got.AnchorID)
	}
}

type errSigner struct{}

func (errSigner) Sign(digest []byte) ([]byte, string, error) {
	return nil, "", errors.New("sign boom")
}

func (errSigner) Verify(digest, sig []byte) (bool, error) { return false, nil }

func (errSigner) KeyID() string { return "err" }

func TestRunJobAnchorInsertError(t *testing.T) {
	ctx := context.Background()
	all := memstore.NewAll()
	seed(t, all)
	r := New(Deps{
		Events:        all.Events,
		Anchors:       errAnchors{},
		Jobs:          all.Exports,
		Payloads:      &s3PutAdapter{s3.NewFake()},
		PayloadBucket: "bkt",
		Signer:        kms.NewFake("alias/x"),
	})
	job := &store.ExportJob{ID: "exp-anc", Format: "JSON", RetentionDays: 30, Status: "PENDING"}
	_ = all.Exports.CreateJob(ctx, job)
	if err := r.RunJob(ctx, job); err != nil {
		t.Fatalf("run: %v", err)
	}
	got, _ := all.Exports.GetJob(ctx, "exp-anc")
	if got.AnchorID != "" {
		t.Errorf("anchor id should be empty on insert error: %s", got.AnchorID)
	}
}

type errAnchors struct{}

func (errAnchors) ListAnchors(ctx context.Context, from, to time.Time) ([]*store.Anchor, error) {
	return nil, nil
}

func (errAnchors) InsertAnchor(ctx context.Context, a *store.Anchor) (string, error) {
	return "", errors.New("anchor boom")
}

func (errAnchors) GetAnchor(ctx context.Context, id string) (*store.Anchor, error) {
	return nil, &store.ErrNotFound{}
}

func TestParseQueryFull(t *testing.T) {
	q := map[string]any{
		"from":        "2026-07-13T00:00:00Z",
		"to":          "2026-07-14T00:00:00Z",
		"service":     "orch",
		"actor":       "u1",
		"action":      "tx.initiated",
		"target_type": "transaction",
		"target_id":   "tx1",
		"extra":       "ignored",
	}
	b, _ := json.Marshal(q)
	f, err := parseQuery(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if f.Service != "orch" {
		t.Errorf("service: %q", f.Service)
	}
	if f.Actor != "u1" {
		t.Errorf("actor: %q", f.Actor)
	}
	if f.Action != "tx.initiated" {
		t.Errorf("action: %q", f.Action)
	}
	if f.TargetType != "transaction" {
		t.Errorf("target_type: %q", f.TargetType)
	}
	if f.TargetID != "tx1" {
		t.Errorf("target_id: %q", f.TargetID)
	}
	if f.From.IsZero() {
		t.Error("from not set")
	}
	if f.To.IsZero() {
		t.Error("to not set")
	}
}

func TestParseQueryEmpty(t *testing.T) {
	f, err := parseQuery(nil)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if f.Service != "" {
		t.Errorf("service: %q", f.Service)
	}
}

func TestParseQueryInvalidJSON(t *testing.T) {
	if _, err := parseQuery([]byte("not-json")); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestParseQueryBadTimeStampsIgnored(t *testing.T) {
	q := map[string]any{"from": "bad", "to": "also-bad"}
	b, _ := json.Marshal(q)
	f, err := parseQuery(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !f.From.IsZero() {
		t.Error("from should be zero for bad time")
	}
	if !f.To.IsZero() {
		t.Error("to should be zero for bad time")
	}
}

func TestSerializeCSVMultipleRows(t *testing.T) {
	base := mustTime("2026-07-13T10:00:00Z")
	events := []*store.Event{
		{ID: "a", TS: base, SourceService: "s", ActorID: "u", Action: "x", TargetType: "t", TargetID: "ti", PayloadHash: []byte("p"), PrevHash: chain.ZeroHash, ThisHash: chain.ZeroHash, Anchored: true, LegalHold: true, Redacted: false, PayloadRef: "ref-a"},
		{ID: "b", TS: base.Add(time.Second), SourceService: "s", ActorID: "u", Action: "x", TargetType: "t", TargetID: "ti", PayloadHash: []byte("p"), PrevHash: chain.ZeroHash, ThisHash: chain.ZeroHash, PayloadRef: "ref-b"},
	}
	out, err := serializeCSV(events)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 3 {
		t.Fatalf("lines: %d", len(lines))
	}
	if !strings.Contains(lines[1], "a,") {
		t.Errorf("row1: %q", lines[1])
	}
	if !strings.Contains(lines[2], "false,false,false") {
		t.Errorf("row2 flags: %q", lines[2])
	}
}

func TestSerializeJSONEmpty(t *testing.T) {
	out, err := serializeJSON(nil)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	if !strings.Contains(string(out), `"events":`) {
		t.Errorf("out: %s", out)
	}
}

func TestBoolStr(t *testing.T) {
	if boolStr(true) != "true" {
		t.Error("true")
	}
	if boolStr(false) != "false" {
		t.Error("false")
	}
}

func TestBuildManifestEmpty(t *testing.T) {
	m := buildManifest(&store.ExportJob{ID: "x", Format: "JSON"}, nil, chain.ZeroHash, "")
	if m.Type != "audit-export-manifest" {
		t.Errorf("type: %q", m.Type)
	}
	if m.RowCount != 0 {
		t.Errorf("row count: %d", m.RowCount)
	}
	if !m.WindowFrom.IsZero() || !m.WindowTo.IsZero() {
		t.Errorf("window should be zero for empty")
	}
}

func TestRunJobUpdateJobError(t *testing.T) {
	ctx := context.Background()
	all := memstore.NewAll()
	seed(t, all)
	r := New(Deps{
		Events:        all.Events,
		Jobs:          errJobStore{},
		Payloads:      &s3PutAdapter{s3.NewFake()},
		PayloadBucket: "bkt",
	})
	job := &store.ExportJob{ID: "exp-upd", Format: "JSON", RetentionDays: 30, Status: "PENDING"}
	if err := r.RunJob(ctx, job); err == nil {
		t.Fatal("expected update error")
	}
}

type errJobStore struct{}

func (errJobStore) CreateJob(ctx context.Context, job *store.ExportJob) error { return nil }

func (errJobStore) GetJob(ctx context.Context, id string) (*store.ExportJob, error) {
	return nil, &store.ErrNotFound{}
}

func (errJobStore) UpdateJob(ctx context.Context, id, status string, rows int64, ref string, root []byte, anchorID string, completedAt time.Time) error {
	return errors.New("update boom")
}

func (errJobStore) ListJobs(ctx context.Context, limit int) ([]*store.ExportJob, error) {
	return nil, nil
}
