package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ai-crypto-onramp/audit-logger/internal/auth"
	"github.com/ai-crypto-onramp/audit-logger/internal/chain"
	"github.com/ai-crypto-onramp/audit-logger/internal/store"
	"github.com/ai-crypto-onramp/audit-logger/internal/store/memstore"
)

func mustTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t.UTC()
}

// testUUIDs are fixed UUIDs used as event IDs in tests so they pass the
// validID check in the API handlers.
var testUUIDs = []string{
	"00000000-0000-4000-8000-000000000001",
	"00000000-0000-4000-8000-000000000002",
	"00000000-0000-4000-8000-000000000003",
	"00000000-0000-4000-8000-000000000004",
	"00000000-0000-4000-8000-000000000005",
}

func seedChain(t *testing.T, all *memstore.All) []*store.Event {
	t.Helper()
	ctx := context.Background()
	var prev []byte = chain.ZeroHash
	var events []*store.Event
	base := mustTime("2026-07-13T10:00:00Z")
	for i := 0; i < 5; i++ {
		e := &store.Event{
			ID:            testUUIDs[i],
			TS:            base.Add(time.Duration(i) * time.Second),
			SourceService: "orch",
			ActorID:       "u1",
			Action:        "tx.initiated",
			TargetType:    "transaction",
			TargetID:      "tx" + string(rune('1'+i)),
			PayloadHash:   []byte("ph"),
			PayloadRef:    testUUIDs[i],
			PrevHash:      append([]byte(nil), prev...),
		}
		e.ThisHash = chain.EventHash(e)
		prev = e.ThisHash
		events = append(events, e)
		if _, err := all.Events.Insert(ctx, e); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	return events
}

func newRouter(t *testing.T) (http.Handler, *memstore.All, *chainVerifier) {
	t.Helper()
	all := memstore.NewAll()
	seedChain(t, all)
	v := &chainVerifier{Events: all.Events, Anchors: all.Anchors}
	d := &Deps{
		Events:          all.Events,
		Anchors:         all.Anchors,
		Exports:         all.Exports,
		DeadLetters:     all.DeadLetters,
		LegalHold:        all.Events,
		Verifier:        v,
		RedactorReload:  func() error { return nil },
	}
	return NewRouter(d), all, v
}

func do(t *testing.T, h http.Handler, method, path string, body []byte, role auth.Role) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if role != "" {
		sub := "audit-reader-svc"
		if role == auth.RoleAdmin {
			sub = "audit-admin"
		}
		tok, err := auth.Issue(sub, testSecret)
		if err != nil {
			t.Fatalf("auth.Issue: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHealthz(t *testing.T) {
	h, _, _ := newRouter(t)
	rec := do(t, h, "GET", "/healthz", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz: %d", rec.Code)
	}
}

func TestListEvents(t *testing.T) {
	h, _, _ := newRouter(t)
	rec := do(t, h, "GET", "/v1/events?limit=2", nil, auth.RoleReader)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	events := resp["events"].([]any)
	if len(events) != 2 {
		t.Fatalf("events: %d", len(events))
	}
	if resp["next_cursor"] == "" {
		t.Error("expected next cursor")
	}
}

func TestListEventsForbidsNoRole(t *testing.T) {
	h, _, _ := newRouter(t)
	rec := do(t, h, "GET", "/v1/events", nil, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestListEventsFilters(t *testing.T) {
	h, _, _ := newRouter(t)
	rec := do(t, h, "GET", "/v1/events?service=pay", nil, auth.RoleReader)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d", rec.Code)
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	events := resp["events"].([]any)
	if len(events) != 0 {
		t.Errorf("expected 0 pay events, got %d", len(events))
	}
	rec = do(t, h, "GET", "/v1/events?service=orch&actor=u1", nil, auth.RoleReader)
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	events = resp["events"].([]any)
	if len(events) != 5 {
		t.Errorf("expected 5 orch/u1 events, got %d", len(events))
	}
}

func TestListEventsPagination(t *testing.T) {
	h, _, _ := newRouter(t)
	rec := do(t, h, "GET", "/v1/events?limit=2", nil, auth.RoleReader)
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	cursor := resp["next_cursor"].(string)
	if cursor == "" {
		t.Fatal("expected cursor")
	}
	rec2 := do(t, h, "GET", "/v1/events?limit=2&cursor="+cursor, nil, auth.RoleReader)
	_ = json.Unmarshal(rec2.Body.Bytes(), &resp)
	events := resp["events"].([]any)
	if len(events) != 2 {
		t.Fatalf("page2 events: %d", len(events))
	}
}

func TestGetEvent(t *testing.T) {
	h, _, _ := newRouter(t)
	rec := do(t, h, "GET", "/v1/events/00000000-0000-4000-8000-000000000001", nil, auth.RoleReader)
	if rec.Code != http.StatusOK {
		t.Fatalf("get: %d %s", rec.Code, rec.Body.String())
	}
	var ev map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &ev)
	if ev["id"] != testUUIDs[0] {
		t.Errorf("id: %v", ev["id"])
	}
}

func TestGetEventNotFound(t *testing.T) {
	h, _, _ := newRouter(t)
	rec := do(t, h, "GET", "/v1/events/nope", nil, auth.RoleReader)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestVerifyEventOK(t *testing.T) {
	h, _, _ := newRouter(t)
	rec := do(t, h, "GET", "/v1/events/00000000-0000-4000-8000-000000000003/verify-chain", nil, auth.RoleReader)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify: %d %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out["status"] != "ok" {
		t.Errorf("status: %v", out["status"])
	}
}

func TestVerifyEventDetectsTamper(t *testing.T) {
	h, all, _ := newRouter(t)
	ctx := context.Background()
	// Tamper an event in-place via the store's internal map.
	all.Events.SetLegalHold(ctx, testUUIDs[1], false)
	// Mutate actor_id directly in the internal map. We use a small hack:
	// re-insert via Insert would be deduped, so we touch the map through
	// a helper exposed only for tests.
	tamperEvent(all, testUUIDs[1], func(e *store.Event) {
		e.ActorID = "tampered"
	})
	rec := do(t, h, "GET", "/v1/events/00000000-0000-4000-8000-000000000002/verify-chain", nil, auth.RoleReader)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify: %d %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out["status"] != "broken" {
		t.Errorf("expected broken, got %v", out["status"])
	}
}

func TestCreateExportAndPoll(t *testing.T) {
	h, all, _ := newRouter(t)
	body := []byte(`{"query":{"service":"orch"},"format":"csv","retention_days":100}`)
	rec := do(t, h, "POST", "/v1/exports", body, auth.RoleAdmin)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	id := resp["id"].(string)
	if id == "" {
		t.Fatal("empty export id")
	}
	// Simulate job completion.
	_ = all.Exports.UpdateJob(context.Background(), id, "complete", 5, "exports/"+id, []byte("root"), "anchor-1", time.Now())
	rec = do(t, h, "GET", "/v1/exports/"+id, nil, auth.RoleReader)
	if rec.Code != http.StatusOK {
		t.Fatalf("poll: %d %s", rec.Code, rec.Body.String())
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["status"] != "complete" {
		t.Errorf("status: %v", resp["status"])
	}
	if resp["row_count"].(float64) != 5 {
		t.Errorf("row count: %v", resp["row_count"])
	}
}

func TestCreateExportRequiresAdmin(t *testing.T) {
	h, _, _ := newRouter(t)
	body := []byte(`{"query":{},"format":"json"}`)
	rec := do(t, h, "POST", "/v1/exports", body, auth.RoleReader)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestAdminVerifyChain(t *testing.T) {
	h, _, _ := newRouter(t)
	rec := do(t, h, "POST", "/v1/admin/verify-chain?from=2026-07-13T00:00:00Z&to=2026-07-14T00:00:00Z", nil, auth.RoleAdmin)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify: %d %s", rec.Code, rec.Body.String())
	}
	var out chain.Report
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.Status != chain.StatusOK {
		t.Errorf("status: %v", out.Status)
	}
	if out.EventCount != 5 {
		t.Errorf("event count: %v", out.EventCount)
	}
}

func TestAdminVerifyChainRequiresAdmin(t *testing.T) {
	h, _, _ := newRouter(t)
	rec := do(t, h, "POST", "/v1/admin/verify-chain", nil, auth.RoleReader)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestLegalHold(t *testing.T) {
	h, all, _ := newRouter(t)
	body := []byte(`{"hold":true}`)
	rec := do(t, h, "POST", "/v1/admin/legal-hold/00000000-0000-4000-8000-000000000001", body, auth.RoleAdmin)
	if rec.Code != http.StatusOK {
		t.Fatalf("set hold: %d %s", rec.Code, rec.Body.String())
	}
	got, _ := all.Events.Get(context.Background(), testUUIDs[0])
	if !got.LegalHold {
		t.Error("legal hold not set")
	}
	body = []byte(`{"hold":false}`)
	rec = do(t, h, "POST", "/v1/admin/legal-hold/00000000-0000-4000-8000-000000000001", body, auth.RoleAdmin)
	if rec.Code != http.StatusOK {
		t.Fatalf("release hold: %d", rec.Code)
	}
	got, _ = all.Events.Get(context.Background(), testUUIDs[0])
	if got.LegalHold {
		t.Error("legal hold not released")
	}
}

func TestLegalHoldNotFound(t *testing.T) {
	h, _, _ := newRouter(t)
	body := []byte(`{"hold":true}`)
	rec := do(t, h, "POST", "/v1/admin/legal-hold/nope", body, auth.RoleAdmin)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	h, _, _ := newRouter(t)
	rec := do(t, h, "GET", "/metrics", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics: %d", rec.Code)
	}
	if rec.Body.Len() == 0 {
		t.Fatal("empty metrics body")
	}
}

func TestRedactionReload(t *testing.T) {
	h, _, _ := newRouter(t)
	rec := do(t, h, "POST", "/v1/admin/redaction/reload", nil, auth.RoleAdmin)
	if rec.Code != http.StatusOK {
		t.Fatalf("reload: %d %s", rec.Code, rec.Body.String())
	}
}

func TestRedactionReloadRequiresAdmin(t *testing.T) {
	h, _, _ := newRouter(t)
	rec := do(t, h, "POST", "/v1/admin/redaction/reload", nil, auth.RoleReader)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestListEventsBadCursor(t *testing.T) {
	h, _, _ := newRouter(t)
	rec := do(t, h, "GET", "/v1/events?cursor=bad", nil, auth.RoleReader)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestListEventsBadFrom(t *testing.T) {
	h, _, _ := newRouter(t)
	rec := do(t, h, "GET", "/v1/events?from=bad", nil, auth.RoleReader)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestExportPollNotFound(t *testing.T) {
	h, _, _ := newRouter(t)
	rec := do(t, h, "GET", "/v1/exports/nope", nil, auth.RoleReader)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestCreateExportMalformedJSON(t *testing.T) {
	h, _, _ := newRouter(t)
	rec := do(t, h, "POST", "/v1/exports", []byte("not-json"), auth.RoleAdmin)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

// chainVerifier implements api.Verifier by calling chain.Sweep.
type chainVerifier struct {
	Events  store.EventStore
	Anchors store.AnchorStore
}

func (v *chainVerifier) VerifyWindow(ctx context.Context, from, to time.Time) (chain.Report, error) {
	r, err := chain.Sweep(ctx, v.Events, v.Anchors, from, to, nil)
	if err != nil {
		return chain.Report{}, err
	}
	return *r, nil
}

// tamperEvent mutates an in-memory event in place. The memstore does not
// expose a mutator (by design), so we reach into the internal map via a
// type assertion.
func tamperEvent(all *memstore.All, id string, fn func(*store.Event)) {
	all.Events.TamperForTest(id, fn)
}