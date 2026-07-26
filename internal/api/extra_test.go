package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/ai-crypto-onramp/audit-logger/internal/auth"
	"github.com/ai-crypto-onramp/audit-logger/internal/chain"
	"github.com/ai-crypto-onramp/audit-logger/internal/store"
	"github.com/ai-crypto-onramp/audit-logger/internal/store/memstore"
)

func TestListEventsBadTo(t *testing.T) {
	h, _, _ := newRouter(t)
	rec := do(t, h, "GET", "/v1/events?to=bad", nil, auth.RoleReader)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestListEventsInvalidLimit(t *testing.T) {
	h, _, _ := newRouter(t)
	// limit=abc -> default; limit=-5 -> min; limit=99999 -> max
	rec := do(t, h, "GET", "/v1/events?limit=abc", nil, auth.RoleReader)
	if rec.Code != http.StatusOK {
		t.Fatalf("abc limit: %d", rec.Code)
	}
	rec = do(t, h, "GET", "/v1/events?limit=-5", nil, auth.RoleReader)
	if rec.Code != http.StatusOK {
		t.Fatalf("neg limit: %d", rec.Code)
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp["events"].([]any)) != 1 {
		t.Errorf("min limit should clamp to 1, got %d", len(resp["events"].([]any)))
	}
	rec = do(t, h, "GET", "/v1/events?limit=99999", nil, auth.RoleReader)
	if rec.Code != http.StatusOK {
		t.Fatalf("huge limit: %d", rec.Code)
	}
}

func TestListEventsListError(t *testing.T) {
	all := memstore.NewAll()
	seedChain(t, all)
	d := &Deps{
		Events:   errListStore{},
		Anchors:  all.Anchors,
		Exports:  all.Exports,
		Verifier: &chainVerifier{Events: all.Events, Anchors: all.Anchors},
	}
	h := NewRouter(d)
	rec := do(t, h, "GET", "/v1/events", nil, auth.RoleReader)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
}

type errListStore struct{}

func (errListStore) Insert(context.Context, *store.Event) (bool, error) { return false, nil }

func (errListStore) InsertChained(context.Context, *store.Event, func(prevHash []byte) []byte) (bool, error) {
	return false, nil
}

func (errListStore) Get(context.Context, string) (*store.Event, error) {
	return nil, &store.ErrNotFound{}
}

func (errListStore) List(context.Context, store.Filter) (*store.ListResult, error) {
	return nil, errors.New("list boom")
}

func (errListStore) ChainHead(context.Context) (*store.Event, error) { return nil, nil }

func (errListStore) SetLegalHold(context.Context, string, bool) error { return nil }

func (errListStore) MarkAnchored(context.Context, time.Time, string) (int64, error) {
	return 0, nil
}

func TestGetEventWithPayloadURL(t *testing.T) {
	all := memstore.NewAll()
	seedChain(t, all)
	d := &Deps{
		Events:        all.Events,
		Anchors:       all.Anchors,
		Exports:       all.Exports,
		Payloads:      fakePresigner{},
		PayloadBucket: "bkt",
		LegalHold:      all.Events,
		Verifier:       &chainVerifier{Events: all.Events, Anchors: all.Anchors},
	}
	h := NewRouter(d)
	rec := do(t, h, "GET", "/v1/events/00000000-0000-4000-8000-000000000001", nil, auth.RoleReader)
	if rec.Code != http.StatusOK {
		t.Fatalf("get: %d %s", rec.Code, rec.Body.String())
	}
	var ev map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &ev)
	if ev["payload_url"] != "https://presigned/00000000-0000-4000-8000-000000000001" {
		t.Errorf("payload_url: %v", ev["payload_url"])
	}
}

type fakePresigner struct{}

func (fakePresigner) PresignGet(ctx context.Context, bucket, key string, ttl time.Duration) (string, error) {
	return "https://presigned/" + key, nil
}

func TestGetEventPresignError(t *testing.T) {
	all := memstore.NewAll()
	seedChain(t, all)
	d := &Deps{
		Events:        all.Events,
		Anchors:       all.Anchors,
		Exports:       all.Exports,
		Payloads:      errPresigner{},
		PayloadBucket: "bkt",
		LegalHold:      all.Events,
		Verifier:       &chainVerifier{Events: all.Events, Anchors: all.Anchors},
	}
	h := NewRouter(d)
	rec := do(t, h, "GET", "/v1/events/00000000-0000-4000-8000-000000000001", nil, auth.RoleReader)
	if rec.Code != http.StatusOK {
		t.Fatalf("get: %d", rec.Code)
	}
	var ev map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &ev)
	if ev["payload_url"] != "" {
		t.Errorf("payload_url should be empty on presign error: %v", ev["payload_url"])
	}
}

type errPresigner struct{}

func (errPresigner) PresignGet(ctx context.Context, bucket, key string, ttl time.Duration) (string, error) {
	return "", errors.New("presign boom")
}

func TestGetEventInternalError(t *testing.T) {
	all := memstore.NewAll()
	seedChain(t, all)
	d := &Deps{
		Events:  errGetStore{},
		Anchors: all.Anchors,
		Exports: all.Exports,
	}
	h := NewRouter(d)
	rec := do(t, h, "GET", "/v1/events/00000000-0000-4000-8000-000000000001", nil, auth.RoleReader)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
}

type errGetStore struct{}

func (errGetStore) Insert(context.Context, *store.Event) (bool, error) { return false, nil }

func (errGetStore) InsertChained(context.Context, *store.Event, func(prevHash []byte) []byte) (bool, error) {
	return false, nil
}

func (errGetStore) Get(context.Context, string) (*store.Event, error) {
	return nil, errors.New("get boom")
}

func (errGetStore) List(context.Context, store.Filter) (*store.ListResult, error) {
	return &store.ListResult{Events: nil}, nil
}

func (errGetStore) ChainHead(context.Context) (*store.Event, error) { return nil, nil }

func (errGetStore) SetLegalHold(context.Context, string, bool) error { return nil }

func (errGetStore) MarkAnchored(context.Context, time.Time, string) (int64, error) { return 0, nil }

func TestVerifyEventFirstEventZeroPrev(t *testing.T) {
	h, _, _ := newRouter(t)
	// First event e1 should use ZeroHash as prev.
	rec := do(t, h, "GET", "/v1/events/00000000-0000-4000-8000-000000000001/verify-chain", nil, auth.RoleReader)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify: %d", rec.Code)
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out["status"] != "ok" {
		t.Errorf("status: %v", out["status"])
	}
	if out["prev_hash"] != chain.HashHex(chain.ZeroHash) {
		t.Errorf("prev_hash should be zero: %v", out["prev_hash"])
	}
}

func TestVerifyEventListError(t *testing.T) {
	all := memstore.NewAll()
	seedChain(t, all)
	d := &Deps{
		Events:  &listErrThenGetStore{events: all.Events},
		Anchors: all.Anchors,
		Exports: all.Exports,
	}
	h := NewRouter(d)
	rec := do(t, h, "GET", "/v1/events/00000000-0000-4000-8000-000000000003/verify-chain", nil, auth.RoleReader)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
}

type listErrThenGetStore struct {
	events store.EventStore
}

func (s *listErrThenGetStore) Insert(ctx context.Context, e *store.Event) (bool, error) {
	return s.events.Insert(ctx, e)
}

func (s *listErrThenGetStore) InsertChained(ctx context.Context, e *store.Event, hashFn func(prevHash []byte) []byte) (bool, error) {
	return s.events.InsertChained(ctx, e, hashFn)
}

func (s *listErrThenGetStore) Get(ctx context.Context, id string) (*store.Event, error) {
	return s.events.Get(ctx, id)
}

func (s *listErrThenGetStore) List(ctx context.Context, f store.Filter) (*store.ListResult, error) {
	return nil, errors.New("list boom")
}

func (s *listErrThenGetStore) ChainHead(ctx context.Context) (*store.Event, error) {
	return s.events.ChainHead(ctx)
}

func (s *listErrThenGetStore) SetLegalHold(ctx context.Context, id string, hold bool) error {
	return s.events.SetLegalHold(ctx, id, hold)
}

func (s *listErrThenGetStore) MarkAnchored(ctx context.Context, ts time.Time, id string) (int64, error) {
	return s.events.MarkAnchored(ctx, ts, id)
}

func TestCreateExportDefaultsFormatAndRetention(t *testing.T) {
	h, all, _ := newRouter(t)
	// Empty format -> defaults to JSON; missing retention -> 2555.
	body := []byte(`{"query":{}}`)
	rec := do(t, h, "POST", "/v1/exports", body, auth.RoleAdmin)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	id := resp["id"].(string)
	job, _ := all.Exports.GetJob(context.Background(), id)
	if job.Format != "JSON" {
		t.Errorf("format: %q", job.Format)
	}
	if job.RetentionDays != 2555 {
		t.Errorf("retention: %d", job.RetentionDays)
	}
}

func TestCreateExportCSVExplicit(t *testing.T) {
	h, all, _ := newRouter(t)
	body := []byte(`{"format":"csv","retention_days":30}`)
	rec := do(t, h, "POST", "/v1/exports", body, auth.RoleAdmin)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("create: %d", rec.Code)
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	id := resp["id"].(string)
	job, _ := all.Exports.GetJob(context.Background(), id)
	if job.Format != "CSV" {
		t.Errorf("format: %q", job.Format)
	}
	if job.RetentionDays != 30 {
		t.Errorf("retention: %d", job.RetentionDays)
	}
}

func TestCreateExportCreateJobError(t *testing.T) {
	all := memstore.NewAll()
	seedChain(t, all)
	d := &Deps{
		Events:  all.Events,
		Anchors: all.Anchors,
		Exports: errCreateJobStore{},
	}
	h := NewRouter(d)
	body := []byte(`{"format":"json"}`)
	rec := do(t, h, "POST", "/v1/exports", body, auth.RoleAdmin)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
}

type errCreateJobStore struct{}

func (errCreateJobStore) CreateJob(ctx context.Context, job *store.ExportJob) error {
	return errors.New("create boom")
}

func (errCreateJobStore) GetJob(ctx context.Context, id string) (*store.ExportJob, error) {
	return nil, &store.ErrNotFound{}
}

func (errCreateJobStore) UpdateJob(ctx context.Context, id, status string, rows int64, ref string, root []byte, anchorID string, completedAt time.Time) error {
	return nil
}

func (errCreateJobStore) ListJobs(ctx context.Context, limit int) ([]*store.ExportJob, error) {
	return nil, nil
}

func TestGetExportWithDownloadURL(t *testing.T) {
	h, all, _ := newRouter(t)
	body := []byte(`{"format":"json"}`)
	rec := do(t, h, "POST", "/v1/exports", body, auth.RoleAdmin)
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	id := resp["id"].(string)
	_ = all.Exports.UpdateJob(context.Background(), id, "complete", 3, "exports/"+id, []byte("rootbytes1234567890123456789012"), "anchor-7", time.Now())
	// Rebuild router with presigner.
	d := &Deps{
		Events:        all.Events,
		Anchors:       all.Anchors,
		Exports:       all.Exports,
		Payloads:      fakePresigner{},
		PayloadBucket: "bkt",
		LegalHold:      all.Events,
		Verifier:       &chainVerifier{Events: all.Events, Anchors: all.Anchors},
	}
	h2 := NewRouter(d)
	rec = do(t, h2, "GET", "/v1/exports/"+id, nil, auth.RoleReader)
	if rec.Code != http.StatusOK {
		t.Fatalf("poll: %d", rec.Code)
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out["download_url"] != "https://presigned/exports/"+id {
		t.Errorf("download_url: %v", out["download_url"])
	}
	if out["anchor_id"] != "anchor-7" {
		t.Errorf("anchor_id: %v", out["anchor_id"])
	}
}

func TestGetExportInternalError(t *testing.T) {
	all := memstore.NewAll()
	seedChain(t, all)
	d := &Deps{
		Events:  all.Events,
		Anchors: all.Anchors,
		Exports: errGetJobStore{},
	}
	h := NewRouter(d)
	rec := do(t, h, "GET", "/v1/exports/00000000-0000-0000-0000-000000000009", nil, auth.RoleReader)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
}

type errGetJobStore struct{}

func (errGetJobStore) CreateJob(ctx context.Context, job *store.ExportJob) error { return nil }

func (errGetJobStore) GetJob(ctx context.Context, id string) (*store.ExportJob, error) {
	return nil, errors.New("get boom")
}

func (errGetJobStore) UpdateJob(ctx context.Context, id, status string, rows int64, ref string, root []byte, anchorID string, completedAt time.Time) error {
	return nil
}

func (errGetJobStore) ListJobs(ctx context.Context, limit int) ([]*store.ExportJob, error) {
	return nil, nil
}

func TestAdminVerifyChainNoVerifier(t *testing.T) {
	all := memstore.NewAll()
	seedChain(t, all)
	d := &Deps{
		Events:  all.Events,
		Anchors: all.Anchors,
		Exports: all.Exports,
	}
	h := NewRouter(d)
	rec := do(t, h, "POST", "/v1/admin/verify-chain", nil, auth.RoleAdmin)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d", rec.Code)
	}
}

func TestAdminVerifyChainError(t *testing.T) {
	all := memstore.NewAll()
	seedChain(t, all)
	d := &Deps{
		Events:  all.Events,
		Anchors: all.Anchors,
		Exports: all.Exports,
		Verifier: errVerifier{},
	}
	h := NewRouter(d)
	rec := do(t, h, "POST", "/v1/admin/verify-chain", nil, auth.RoleAdmin)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
}

type errVerifier struct{}

func (errVerifier) VerifyWindow(ctx context.Context, from, to time.Time) (chain.Report, error) {
	return chain.Report{}, errors.New("verify boom")
}

func TestLegalHoldMalformedJSON(t *testing.T) {
	h, _, _ := newRouter(t)
	rec := do(t, h, "POST", "/v1/admin/legal-hold/00000000-0000-4000-8000-000000000001", []byte("not-json"), auth.RoleAdmin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestLegalHoldInternalError(t *testing.T) {
	all := memstore.NewAll()
	seedChain(t, all)
	d := &Deps{
		Events:   all.Events,
		Anchors:  all.Anchors,
		Exports:  all.Exports,
		LegalHold: errLegalHold{},
	}
	h := NewRouter(d)
	rec := do(t, h, "POST", "/v1/admin/legal-hold/00000000-0000-4000-8000-000000000001", []byte(`{"hold":true}`), auth.RoleAdmin)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
}

type errLegalHold struct{}

func (errLegalHold) SetLegalHold(ctx context.Context, id string, hold bool) error {
	return errors.New("legalhold boom")
}

func TestLegalHoldEmptyBody(t *testing.T) {
	h, _, _ := newRouter(t)
	// Empty body -> decode returns io.EOF, which we tolerate; hold defaults to false.
	rec := do(t, h, "POST", "/v1/admin/legal-hold/00000000-0000-4000-8000-000000000001", nil, auth.RoleAdmin)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestRedactionReloadError(t *testing.T) {
	all := memstore.NewAll()
	seedChain(t, all)
	d := &Deps{
		Events:         all.Events,
		Anchors:        all.Anchors,
		Exports:        all.Exports,
		LegalHold:      all.Events,
		Verifier:       &chainVerifier{Events: all.Events, Anchors: all.Anchors},
		RedactorReload: func() error { return errors.New("reload boom") },
	}
	h := NewRouter(d)
	rec := do(t, h, "POST", "/v1/admin/redaction/reload", nil, auth.RoleAdmin)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
}

func TestRedactionReloadNotConfigured(t *testing.T) {
	all := memstore.NewAll()
	seedChain(t, all)
	d := &Deps{
		Events:   all.Events,
		Anchors:  all.Anchors,
		Exports:  all.Exports,
		LegalHold: all.Events,
	}
	h := NewRouter(d)
	rec := do(t, h, "POST", "/v1/admin/redaction/reload", nil, auth.RoleAdmin)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d", rec.Code)
	}
}

func TestLegalHoldNotConfigured(t *testing.T) {
	all := memstore.NewAll()
	seedChain(t, all)
	d := &Deps{
		Events:  all.Events,
		Anchors: all.Anchors,
		Exports: all.Exports,
	}
	h := NewRouter(d)
	rec := do(t, h, "POST", "/v1/admin/legal-hold/00000000-0000-4000-8000-000000000001", []byte(`{"hold":true}`), auth.RoleAdmin)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d", rec.Code)
	}
}

func TestParseIntDefault(t *testing.T) {
	if parseIntDefault("", 50, 1, 100) != 50 {
		t.Error("empty default")
	}
	if parseIntDefault("abc", 50, 1, 100) != 50 {
		t.Error("invalid default")
	}
	if parseIntDefault("-1", 50, 1, 100) != 1 {
		t.Error("min clamp")
	}
	if parseIntDefault("1000", 50, 1, 100) != 100 {
		t.Error("max clamp")
	}
	if parseIntDefault("42", 50, 1, 100) != 42 {
		t.Error("exact value")
	}
}

func TestListEventsWithFromAndToFilters(t *testing.T) {
	h, _, _ := newRouter(t)
	from := "2026-07-13T10:00:01Z"
	to := "2026-07-13T10:00:04Z"
	rec := do(t, h, "GET", "/v1/events?from="+from+"&to="+to, nil, auth.RoleReader)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d", rec.Code)
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	events := resp["events"].([]any)
	if len(events) != 3 {
		t.Errorf("expected 3 events in window, got %d", len(events))
	}
}

func TestListEventsAllFilterParams(t *testing.T) {
	h, _, _ := newRouter(t)
	rec := do(t, h, "GET", "/v1/events?service=orch&actor=u1&action=tx.initiated&target_type=transaction&target_id=tx1", nil, auth.RoleReader)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d", rec.Code)
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	events := resp["events"].([]any)
	if len(events) != 1 {
		t.Errorf("expected 1 event for target_id=tx1, got %d", len(events))
	}
}

func TestVerifyEventNotFound(t *testing.T) {
	h, _, _ := newRouter(t)
	rec := do(t, h, "GET", "/v1/events/nope/verify-chain", nil, auth.RoleReader)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestVerifyEventGetInternalError(t *testing.T) {
	all := memstore.NewAll()
	seedChain(t, all)
	d := &Deps{
		Events:  errGetStore{},
		Anchors: all.Anchors,
		Exports: all.Exports,
	}
	h := NewRouter(d)
	rec := do(t, h, "GET", "/v1/events/00000000-0000-4000-8000-000000000001/verify-chain", nil, auth.RoleReader)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
}

func TestGetExportWithCompletedAt(t *testing.T) {
	h, all, _ := newRouter(t)
	body := []byte(`{"format":"json"}`)
	rec := do(t, h, "POST", "/v1/exports", body, auth.RoleAdmin)
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	id := resp["id"].(string)
	completed := time.Now()
	_ = all.Exports.UpdateJob(context.Background(), id, "complete", 3, "exports/"+id, make([]byte, 32), "", completed)
	rec = do(t, h, "GET", "/v1/exports/"+id, nil, auth.RoleReader)
	if rec.Code != http.StatusOK {
		t.Fatalf("poll: %d", rec.Code)
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out["completed_at"] == nil {
		t.Error("missing completed_at")
	}
	if out["chain_root"] == nil {
		t.Error("missing chain_root")
	}
}

func TestCreateExportRequiresRole(t *testing.T) {
	h, _, _ := newRouter(t)
	rec := do(t, h, "POST", "/v1/exports", []byte(`{}`), "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestNewExportIDUniqueness(t *testing.T) {
	ids := map[string]bool{}
	for i := 0; i < 100; i++ {
		id := newExportID()
		if ids[id] {
			t.Fatalf("duplicate id: %s", id)
		}
		ids[id] = true
	}
}

func TestToEventJSONWithHashes(t *testing.T) {
	e := &store.Event{
		ID:            "x",
		TS:            mustTime("2026-07-13T10:00:00Z"),
		SourceService: "s",
		ActorID:       "a",
		Action:        "act",
		TargetType:    "tt",
		TargetID:      "ti",
		PayloadHash:   []byte("ph"),
		PrevHash:      chain.ZeroHash,
		ThisHash:      chain.ZeroHash,
		PayloadRef:    "ref",
		Anchored:      true,
		LegalHold:     true,
		Redacted:      false,
	}
	m := toEventJSON(e, false)
	if m["id"] != "x" {
		t.Errorf("id: %v", m["id"])
	}
	if m["anchored"] != true {
		t.Errorf("anchored: %v", m["anchored"])
	}
	if m["payload_hash"] != "sha256:"+bytesHex("ph") {
		t.Errorf("payload_hash: %v", m["payload_hash"])
	}
}

func bytesHex(s string) string {
	return hexEncode([]byte(s))
}

func hexEncode(b []byte) string {
	const chars = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = chars[v>>4]
		out[i*2+1] = chars[v&0x0f]
	}
	return string(out)
}
