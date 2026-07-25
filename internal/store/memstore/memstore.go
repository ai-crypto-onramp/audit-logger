// Package memstore is an in-memory implementation of the store interfaces,
// used by unit tests and the smoke harness so `go test ./...` passes
// without requiring Docker or a live Postgres. It is safe for concurrent
// use.
//
// The EventStore implementation enforces the append-only contract: no
// Update or Delete methods exist. Insert is idempotent on event id.
package memstore

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/ai-crypto-onramp/audit-logger/internal/store"
)

// All bundles the in-memory stores.
type All struct {
	Events      *EventStore
	Anchors     *AnchorStore
	Exports     *ExportJobStore
	DeadLetters *DeadLetterStore
}

// NewAll returns a fresh set of in-memory stores.
func NewAll() *All {
	return &All{
		Events:      NewEventStore(),
		Anchors:     NewAnchorStore(),
		Exports:     NewExportJobStore(),
		DeadLetters: NewDeadLetterStore(),
	}
}

// --- EventStore ---

// EventStore implements store.EventStore in memory.
type EventStore struct {
	mu     sync.Mutex
	events map[string]*store.Event
	// index of (ts, id) sorted on demand
	ordered []*store.Event
}

// NewEventStore returns an empty in-memory EventStore.
func NewEventStore() *EventStore { return &EventStore{events: map[string]*store.Event{}} }

// Insert persists an event idempotently. Returns true for a fresh insert.
func (s *EventStore) Insert(_ context.Context, e *store.Event) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.events[e.ID]; ok {
		return false, nil
	}
	c := *e
	s.events[e.ID] = &c
	s.ordered = append(s.ordered, &c)
	sort.SliceStable(s.ordered, func(i, j int) bool {
		a, b := s.ordered[i], s.ordered[j]
		if !a.TS.Equal(b.TS) {
			return a.TS.Before(b.TS)
		}
		return a.ID < b.ID
	})
	return true, nil
}

// Get returns a single event by id.
func (s *EventStore) Get(_ context.Context, id string) (*store.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.events[id]
	if !ok {
		return nil, &store.ErrNotFound{ID: id}
	}
	c := *e
	return &c, nil
}

// List returns events matching the filter, ordered by (ts ASC, id ASC).
//nolint:gocyclo // many filter fields to handle
func (s *EventStore) List(_ context.Context, f store.Filter) (*store.ListResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	var out []store.Event
	for _, e := range s.ordered {
		if !f.From.IsZero() && e.TS.Before(f.From) {
			continue
		}
		if !f.To.IsZero() && !e.TS.Before(f.To) {
			continue
		}
		if f.Service != "" && e.SourceService != f.Service {
			continue
		}
		if f.Actor != "" && e.ActorID != f.Actor {
			continue
		}
		if f.Action != "" && e.Action != f.Action {
			continue
		}
		if f.TargetType != "" && e.TargetType != f.TargetType {
			continue
		}
		if f.TargetID != "" && e.TargetID != f.TargetID {
			continue
		}
		if !f.Cursor.TS.IsZero() || f.Cursor.ID != "" {
			// keyset: row must be strictly after cursor.
			if !e.TS.After(f.Cursor.TS) && !(e.TS.Equal(f.Cursor.TS) && e.ID > f.Cursor.ID) {
				continue
			}
		}
		out = append(out, *e)
		if len(out) >= limit {
			break
		}
	}
	res := &store.ListResult{Events: out}
	if len(out) >= limit && len(out) > 0 {
		last := out[len(out)-1]
		res.NextCursor = store.Cursor{TS: last.TS, ID: last.ID}
	}
	return res, nil
}

// ChainHead returns the current tail of the chain.
func (s *EventStore) ChainHead(_ context.Context) (*store.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.ordered) == 0 {
		return nil, nil
	}
	c := *s.ordered[len(s.ordered)-1]
	return &c, nil
}

// SetLegalHold toggles the legal_hold flag.
func (s *EventStore) SetLegalHold(_ context.Context, id string, hold bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.events[id]
	if !ok {
		return &store.ErrNotFound{ID: id}
	}
	e.LegalHold = hold
	return nil
}

// MarkAnchored sets anchored=true for events with (ts, id) <= (toTS, toID).
func (s *EventStore) MarkAnchored(_ context.Context, toTS time.Time, toID string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for _, e := range s.ordered {
		if e.TS.Before(toTS) || (e.TS.Equal(toTS) && e.ID <= toID) {
			if !e.Anchored {
				e.Anchored = true
				n++
			}
		}
	}
	return n, nil
}

// TamperForTest mutates an in-memory event in place. It is exported only so
// tests can simulate tampering to exercise the chain verifier; it must
// never be called from production code (the EventStore contract is
// append-only).
func (s *EventStore) TamperForTest(id string, fn func(*store.Event)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.events[id]
	if !ok {
		return
	}
	fn(e)
}

// --- AnchorStore ---

// AnchorStore implements store.AnchorStore in memory.
type AnchorStore struct {
	mu      sync.Mutex
	anchors []*store.Anchor
}

// NewAnchorStore returns an empty in-memory AnchorStore.
func NewAnchorStore() *AnchorStore { return &AnchorStore{} }

// InsertAnchor persists a new anchor and returns its assigned id.
func (s *AnchorStore) InsertAnchor(_ context.Context, a *store.Anchor) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := *a
	id, _ := uuid.NewV7()
	c.ID = id.String()
	if c.AnchoredAt.IsZero() {
		c.AnchoredAt = time.Now().UTC()
	}
	s.anchors = append(s.anchors, &c)
	return c.ID, nil
}

// ListAnchors returns anchors ordered by anchored_at ASC within [from,to].
func (s *AnchorStore) ListAnchors(_ context.Context, from, to time.Time) ([]*store.Anchor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*store.Anchor
	for _, a := range s.anchors {
		if !from.IsZero() && a.AnchoredAt.Before(from) {
			continue
		}
		if !to.IsZero() && a.AnchoredAt.After(to) {
			continue
		}
		c := *a
		out = append(out, &c)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].AnchoredAt.Before(out[j].AnchoredAt) })
	return out, nil
}

// GetAnchor returns a single anchor by id.
func (s *AnchorStore) GetAnchor(_ context.Context, id string) (*store.Anchor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.anchors {
		if a.ID == id {
			c := *a
			return &c, nil
		}
	}
	return nil, &store.ErrNotFound{ID: id}
}

// --- ExportJobStore ---

// ExportJobStore implements store.ExportJobStore in memory.
type ExportJobStore struct {
	mu   sync.Mutex
	jobs map[string]*store.ExportJob
}

// NewExportJobStore returns an empty in-memory ExportJobStore.
func NewExportJobStore() *ExportJobStore { return &ExportJobStore{jobs: map[string]*store.ExportJob{}} }

// CreateJob inserts a new export job.
func (s *ExportJobStore) CreateJob(_ context.Context, j *store.ExportJob) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.jobs[j.ID]; ok {
		return nil
	}
	c := *j
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now().UTC()
	}
	s.jobs[j.ID] = &c
	return nil
}

// GetJob returns a single export job by id.
func (s *ExportJobStore) GetJob(_ context.Context, id string) (*store.ExportJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	if !ok {
		return nil, &store.ErrNotFound{ID: id}
	}
	c := *j
	return &c, nil
}

// UpdateJob updates an export job's status/result fields.
func (s *ExportJobStore) UpdateJob(_ context.Context, id string, status string, rowCount int64, payloadRef string, chainRoot []byte, anchorID string, completedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	if !ok {
		return &store.ErrNotFound{ID: id}
	}
	j.Status = status
	j.RowCount = rowCount
	j.PayloadRef = payloadRef
	j.ChainRoot = append([]byte(nil), chainRoot...)
	j.AnchorID = anchorID
	if !completedAt.IsZero() {
		j.CompletedAt = completedAt
	}
	return nil
}

// ListJobs returns all export jobs ordered by created_at DESC.
func (s *ExportJobStore) ListJobs(_ context.Context, limit int) ([]*store.ExportJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*store.ExportJob, 0, len(s.jobs))
	for _, j := range s.jobs {
		c := *j
		out = append(out, &c)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// --- DeadLetterStore ---

// DeadLetterStore implements store.DeadLetterStore in memory.
type DeadLetterStore struct {
	mu    sync.Mutex
	items []*store.DeadLetter
}

// NewDeadLetterStore returns an empty in-memory DeadLetterStore.
func NewDeadLetterStore() *DeadLetterStore { return &DeadLetterStore{} }

// Append persists a dead-letter record.
func (s *DeadLetterStore) Append(_ context.Context, dl *store.DeadLetter) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := *dl
	id, _ := uuid.NewV7()
	c.ID = id.String()
	if c.RejectedAt.IsZero() {
		c.RejectedAt = time.Now().UTC()
	}
	s.items = append(s.items, &c)
	return nil
}

// List returns dead-letter records newest-first.
func (s *DeadLetterStore) List(_ context.Context, limit int) ([]*store.DeadLetter, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 || limit > len(s.items) {
		limit = len(s.items)
	}
	out := make([]*store.DeadLetter, 0, limit)
	for i := len(s.items) - 1; i >= 0 && len(out) < limit; i-- {
		c := *s.items[i]
		out = append(out, &c)
	}
	return out, nil
}