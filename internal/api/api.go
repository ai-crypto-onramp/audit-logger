// Package api implements the REST API for the Audit Event Log service using
// the std net/http ServeMux (Go 1.22+ pattern matching). Handlers are kept
// thin and depend only on the store / s3 / kms / redaction interfaces so
// they can be exercised in tests with in-memory fakes.
//
// Endpoints (see README for the full contract):
//
//	GET  /v1/events                      paginated filtered search (audit-reader)
//	GET  /v1/events/{id}                 fetch a single event (audit-reader)
//	GET  /v1/events/{id}/verify-chain    verify single-event linkage (audit-reader)
//	POST /v1/exports                     create export job (audit-admin)
//	GET  /v1/exports/{id}                poll export job (audit-reader)
//	POST /v1/admin/verify-chain          trigger full sweep (audit-admin)
//	POST /v1/admin/legal-hold/{id}        place / release legal hold (audit-admin)
//	POST /v1/admin/redaction/reload       reload redaction policy (audit-admin)
//	GET  /healthz                        liveness probe
//	GET  /metrics                        Prometheus scrape
package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/ai-crypto-onramp/audit-logger/internal/auth"
	"github.com/ai-crypto-onramp/audit-logger/internal/chain"
	"github.com/ai-crypto-onramp/audit-logger/internal/event"
	"github.com/ai-crypto-onramp/audit-logger/internal/metrics"
	"github.com/ai-crypto-onramp/audit-logger/internal/store"
)

// Presigner issues time-limited S3 download URLs.
type Presigner interface {
	PresignGet(ctx context.Context, bucket, key string, ttl time.Duration) (string, error)
}

// LegalHoldSetter exposes the legal-hold mutator.
type LegalHoldSetter interface {
	SetLegalHold(ctx context.Context, id string, hold bool) error
}

// Verifier walks a chain window and returns the outcome.
type Verifier interface {
	VerifyWindow(ctx context.Context, from, to time.Time) (chain.Report, error)
}

// Deps bundles the handler dependencies.
type Deps struct {
	Events       store.EventStore
	Anchors      store.AnchorStore
	Exports      store.ExportJobStore
	DeadLetters  store.DeadLetterStore
	Payloads      Presigner
	PayloadBucket string
	LegalHold      LegalHoldSetter
	Verifier       Verifier
	RedactorReload func() error
}

// NewRouter returns an http.Handler wired with all routes. Reader-protected
// routes are wrapped in auth.Require(RoleReader); admin routes in
// auth.Require(RoleAdmin).
func NewRouter(d *Deps) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", healthz)
	if d.RedactorReload != nil {
		mux.Handle("POST /v1/admin/redaction/reload", auth.Require(auth.RoleAdmin)(http.HandlerFunc(d.handleRedactionReload)))
	} else {
		mux.Handle("POST /v1/admin/redaction/reload", auth.Require(auth.RoleAdmin)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeError(w, http.StatusNotImplemented, "redaction reload not configured")
		})))
	}
	mux.Handle("GET /metrics", promhttp.Handler())

	// Reads (audit-reader).
	mux.Handle("GET /v1/events", auth.Require(auth.RoleReader)(http.HandlerFunc(d.handleListEvents)))
	mux.Handle("GET /v1/events/{id}", auth.Require(auth.RoleReader)(http.HandlerFunc(d.handleGetEvent)))
	mux.Handle("GET /v1/events/{id}/verify-chain", auth.Require(auth.RoleReader)(http.HandlerFunc(d.handleVerifyEvent)))

	// Exports (audit-admin for create, audit-reader for poll).
	mux.Handle("POST /v1/exports", auth.Require(auth.RoleAdmin)(http.HandlerFunc(d.handleCreateExport)))
	mux.Handle("GET /v1/exports/{id}", auth.Require(auth.RoleReader)(http.HandlerFunc(d.handleGetExport)))

	// Admin (audit-admin).
	mux.Handle("POST /v1/admin/verify-chain", auth.Require(auth.RoleAdmin)(http.HandlerFunc(d.handleAdminVerifyChain)))
	if d.LegalHold != nil {
		mux.Handle("POST /v1/admin/legal-hold/{id}", auth.Require(auth.RoleAdmin)(http.HandlerFunc(d.handleLegalHold)))
	} else {
		mux.Handle("POST /v1/admin/legal-hold/{id}", auth.Require(auth.RoleAdmin)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeError(w, http.StatusNotImplemented, "legal hold not configured")
		})))
	}
	secret, bypass := auth.SecretFromEnv()
	return auth.Middleware(secret, bypass)(mux)
}

func healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// --- GET /v1/events ---

func (d *Deps) handleListEvents(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() { metrics.QueryLatency.WithLabelValues("list").Observe(time.Since(start).Seconds()) }()

	f := store.Filter{
		Service:    r.URL.Query().Get("service"),
		Actor:      r.URL.Query().Get("actor"),
		Action:     r.URL.Query().Get("action"),
		TargetType: r.URL.Query().Get("target_type"),
		TargetID:   r.URL.Query().Get("target_id"),
		Limit:      parseIntDefault(r.URL.Query().Get("limit"), 100, 1, 1000),
	}
	if from := r.URL.Query().Get("from"); from != "" {
		ts, err := time.Parse(time.RFC3339Nano, from)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid from: "+err.Error())
			return
		}
		f.From = ts
	}
	if to := r.URL.Query().Get("to"); to != "" {
		ts, err := time.Parse(time.RFC3339Nano, to)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid to: "+err.Error())
			return
		}
		f.To = ts
	}
	if cursorStr := r.URL.Query().Get("cursor"); cursorStr != "" {
		c, err := store.ParseCursor(cursorStr)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid cursor: "+err.Error())
			return
		}
		f.Cursor = c
	}
	res, err := d.Events.List(r.Context(), f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list: "+err.Error())
		return
	}
	resp := map[string]any{
		"events":      toEventJSONs(res.Events, false),
		"next_cursor": res.NextCursor.String(),
	}
	if res.NextCursor.TS.IsZero() {
		resp["next_cursor"] = ""
	}
	writeJSON(w, http.StatusOK, resp)
}

// --- GET /v1/events/{id} ---

func (d *Deps) handleGetEvent(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() { metrics.QueryLatency.WithLabelValues("get").Observe(time.Since(start).Seconds()) }()
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing id")
		return
	}
	if !validID(id) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	e, err := d.Events.Get(r.Context(), id)
	if err != nil {
		if store.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "get: "+err.Error())
		return
	}
	payloadURL := ""
	if d.Payloads != nil && d.PayloadBucket != "" && e.PayloadRef != "" {
		u, err := d.Payloads.PresignGet(r.Context(), d.PayloadBucket, e.PayloadRef, 15*time.Minute)
		if err == nil {
			payloadURL = u
		}
	}
	out := toEventJSON(e, true)
	out["payload_url"] = payloadURL
	writeJSON(w, http.StatusOK, out)
}

// --- GET /v1/events/{id}/verify-chain ---

func (d *Deps) handleVerifyEvent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing id")
		return
	}
	if !validID(id) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	e, err := d.Events.Get(r.Context(), id)
	if err != nil {
		if store.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "get: "+err.Error())
		return
	}
	// Look up the preceding event to check prev_hash linkage.
	var prev []byte
	list, err := d.Events.List(r.Context(), store.Filter{To: e.TS, Limit: 1000})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list: "+err.Error())
		return
	}
	for i := len(list.Events) - 1; i >= 0; i-- {
		cand := list.Events[i]
		if cand.ID == id {
			continue
		}
		if cand.TS.Before(e.TS) || (cand.TS.Equal(e.TS) && cand.ID < e.ID) {
			prev = cand.ThisHash
			break
		}
	}
	if prev == nil {
		prev = chain.ZeroHash
	}
	res := chain.VerifyEvent(e, prev)
	metrics.ChainVerifyOutcomes.WithLabelValues(string(res.Status)).Inc()
	out := map[string]any{
		"id":        e.ID,
		"prev_hash": chain.HashHex(res.PrevHash),
		"this_hash": chain.HashHex(res.ThisHash),
		"computed":  chain.HashHex(res.Computed),
		"status":    string(res.Status),
	}
	if res.Reason != "" {
		out["reason"] = res.Reason
	}
	writeJSON(w, http.StatusOK, out)
}

// --- POST /v1/exports ---

type createExportReq struct {
	Query        json.RawMessage `json:"query"`
	Format       string          `json:"format"`
	RetentionDays int            `json:"retention_days"`
}

func (d *Deps) handleCreateExport(w http.ResponseWriter, r *http.Request) {
	var req createExportReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed json")
		return
	}
	// Normalize format to uppercase enum literal; default to JSON.
	req.Format = strings.ToUpper(req.Format)
	if req.Format != "JSON" && req.Format != "CSV" {
		req.Format = "JSON"
	}
	if req.RetentionDays <= 0 {
		req.RetentionDays = 2555
	}
	if len(req.Query) == 0 {
		req.Query = json.RawMessage(`{}`)
	}
	id := newExportID()
	job := &store.ExportJob{
		ID:            id,
		Query:         []byte(req.Query),
		Format:        req.Format,
		RetentionDays: req.RetentionDays,
		Status:        "PENDING",
	}
	if err := d.Exports.CreateJob(r.Context(), job); err != nil {
		writeError(w, http.StatusInternalServerError, "create: "+err.Error())
		return
	}
	metrics.ExportsCreated.WithLabelValues(req.Format).Inc()
	writeJSON(w, http.StatusAccepted, map[string]any{"id": id, "status": "PENDING"})
}

// --- GET /v1/exports/{id} ---

func (d *Deps) handleGetExport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing id")
		return
	}
	if !validID(id) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	j, err := d.Exports.GetJob(r.Context(), id)
	if err != nil {
		if store.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "get: "+err.Error())
		return
	}
	out := map[string]any{
		"id":            j.ID,
		"status":        j.Status,
		"format":        j.Format,
		"retention_days": j.RetentionDays,
		"row_count":     j.RowCount,
	}
	if j.PayloadRef != "" {
		out["payload_ref"] = j.PayloadRef
		if d.Payloads != nil && d.PayloadBucket != "" {
			u, err := d.Payloads.PresignGet(r.Context(), d.PayloadBucket, j.PayloadRef, 15*time.Minute)
			if err == nil {
				out["download_url"] = u
			}
		}
	}
	if len(j.ChainRoot) == 32 {
		out["chain_root"] = chain.HashHex(j.ChainRoot)
	}
	if j.AnchorID != "" {
		out["anchor_id"] = j.AnchorID
	}
	if !j.CompletedAt.IsZero() {
		out["completed_at"] = j.CompletedAt.UTC().Format(time.RFC3339Nano)
	}
	writeJSON(w, http.StatusOK, out)
}

// --- POST /v1/admin/verify-chain ---

func (d *Deps) handleAdminVerifyChain(w http.ResponseWriter, r *http.Request) {
	if d.Verifier == nil {
		writeError(w, http.StatusNotImplemented, "verifier not configured")
		return
	}
	from, _ := time.Parse(time.RFC3339Nano, r.URL.Query().Get("from"))
	to, _ := time.Parse(time.RFC3339Nano, r.URL.Query().Get("to"))
	report, err := d.Verifier.VerifyWindow(r.Context(), from, to)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "verify: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, report)
}

// --- POST /v1/admin/legal-hold/{id} ---

type legalHoldReq struct {
	Hold bool `json:"hold"`
}

func (d *Deps) handleLegalHold(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing id")
		return
	}
	if !validID(id) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	var req legalHoldReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
		writeError(w, http.StatusBadRequest, "malformed json")
		return
	}
	if err := d.LegalHold.SetLegalHold(r.Context(), id, req.Hold); err != nil {
		if store.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "set legal hold: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "legal_hold": req.Hold})
}

// --- POST /v1/admin/redaction/reload ---

func (d *Deps) handleRedactionReload(w http.ResponseWriter, r *http.Request) {
	if d.RedactorReload == nil {
		writeError(w, http.StatusNotImplemented, "redaction reload not configured")
		return
	}
	if err := d.RedactorReload(); err != nil {
		writeError(w, http.StatusInternalServerError, "reload: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "reloaded"})
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func parseIntDefault(s string, def, min, max int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	if n < min {
		return min
	}
	if n > max {
		return max
	}
	return n
}

func toEventJSON(e *store.Event, includeHashes bool) map[string]any {
	m := map[string]any{
		"id":             e.ID,
		"ts":             e.TS.UTC().Format(time.RFC3339Nano),
		"source_service": e.SourceService,
		"actor_id":       e.ActorID,
		"action":         e.Action,
		"target_type":    e.TargetType,
		"target_id":      e.TargetID,
		"anchored":       e.Anchored,
		"legal_hold":     e.LegalHold,
		"redacted":       e.Redacted,
		"payload_ref":    e.PayloadRef,
	}
	if includeHashes || true {
		m["payload_hash"] = "sha256:" + hex.EncodeToString(e.PayloadHash)
		m["prev_hash"] = chain.HashHex(e.PrevHash)
		m["this_hash"] = chain.HashHex(e.ThisHash)
	}
	return m
}

func toEventJSONs(events []store.Event, includeHashes bool) []map[string]any {
	out := make([]map[string]any, 0, len(events))
	for i := range events {
		out = append(out, toEventJSON(&events[i], includeHashes))
	}
	return out
}

// newExportID returns a UUIDv7 string for an export job.
var newExportID = func() string {
	id, _ := uuid.NewV7()
	return id.String()
}

// validID reports whether s is a parseable UUID. Used to reject non-UUID
// path params before they reach the UUID-keyed store, so malformed ids
// return 404 rather than a 500 from the DB driver.
func validID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil
}

// _ guards
var (
	_ = errors.New
	_ = strings.Split
	_ = url.QueryEscape
	_ = event.HashPrefix
)