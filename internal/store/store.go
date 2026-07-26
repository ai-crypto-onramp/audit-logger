// Package store defines the storage interfaces and record types for the
// Audit Event Log service. The package exposes interfaces (EventStore,
// AnchorStore, ExportJobStore, DeadLetterStore) so the service can run
// against either a real PostgreSQL backend (internal/store/postgres) or an
// in-memory mock (internal/store/memstore) used by tests and the smoke
// harness.
//
// The EventStore is intentionally append-only: it exposes Insert, Get,
// List, and chain navigation helpers, but no Update or Delete methods.
// Any code path that would modify an existing audit_events row must
// construct a new store record and call Insert, which dedups on id.
package store

import (
	"context"
	"errors"
	"time"
)

// Event is the persisted audit_events row. PayloadHash, PrevHash, and
// ThisHash are the raw 32-byte SHA-256 sums.
type Event struct {
	ID            string    `json:"id"`
	TS            time.Time `json:"ts"`
	SourceService string    `json:"source_service"`
	ActorID       string    `json:"actor_id"`
	Action        string    `json:"action"`
	TargetType    string    `json:"target_type"`
	TargetID      string    `json:"target_id"`
	PayloadHash   []byte    `json:"payload_hash"`
	PayloadRef    string    `json:"payload_ref"`
	PrevHash      []byte    `json:"prev_hash"`
	ThisHash      []byte    `json:"this_hash"`
	Anchored      bool      `json:"anchored"`
	LegalHold     bool      `json:"legal_hold"`
	Redacted      bool      `json:"redacted"`
}

// Filter is the search filter for List. Zero-value fields are ignored.
type Filter struct {
	From       time.Time // inclusive
	To         time.Time // exclusive (the row's ts must be < To)
	Service    string
	Actor      string
	Action     string
	TargetType string
	TargetID   string
	Limit      int
	// Cursor is the keyset pagination cursor: (ts, id) of the last row of the
	// previous page. Rows strictly after the cursor in (ts ASC, id ASC) order
	// are returned. An empty cursor returns from the beginning.
	Cursor Cursor
}

// Cursor is a keyset pagination cursor.
type Cursor struct {
	TS time.Time
	ID string
}

// String returns an opaque cursor string ("ts|id") suitable for use as a
// query parameter. Empty values return "".
func (c Cursor) String() string {
	if c.TS.IsZero() && c.ID == "" {
		return ""
	}
	return c.TS.UTC().Format(time.RFC3339Nano) + "|" + c.ID
}

// ParseCursor parses a cursor string produced by Cursor.String. Returns a
// zero Cursor for "".
func ParseCursor(s string) (Cursor, error) {
	if s == "" {
		return Cursor{}, nil
	}
	for i := 0; i < len(s); i++ {
		if s[i] == '|' {
			ts, err := time.Parse(time.RFC3339Nano, s[:i])
			if err != nil {
				return Cursor{}, err
			}
			return Cursor{TS: ts, ID: s[i+1:]}, nil
		}
	}
	return Cursor{}, errors.New("store: invalid cursor")
}

// ListResult is the paginated list response.
type ListResult struct {
	Events    []Event
	NextCursor Cursor
}

// ErrNotFound is returned by stores when a row lookup misses.
type ErrNotFound struct{ ID string }

func (e *ErrNotFound) Error() string { return "store: not found: " + e.ID }

// IsNotFound reports whether err is an ErrNotFound.
func IsNotFound(err error) bool {
	var n *ErrNotFound
	return errors.As(err, &n)
}

// EventStore persists and queries audit events. It is append-only: only
// Insert is exposed for writes. SetLegalHold and MarkAnchored are the
// sole mutators and only touch the legal_hold / anchored flags (the
// chain-relevant columns are never mutated after insert).
type EventStore interface {
	// Insert persists an event. It is idempotent on event id: re-inserting
	// the same id is a no-op. Returns (inserted=true, nil) for a fresh
	// insert, (false, nil) for a re-delivery.
	//
	// NOTE: Insert does NOT extend the hash chain atomically. Callers that
	// need to append a new link to the chain must use InsertChained, which
	// reads the chain tip (prev_hash) inside the insert transaction under
	// SERIALIZABLE isolation + an advisory lock so concurrent ingests
	// cannot fork the chain.
	Insert(ctx context.Context, e *Event) (bool, error)
	// InsertChained atomically reads the current chain head's this_hash,
	// computes the new event's prev_hash from it, computes this_hash via
	// hashFn(prev_hash), and inserts the event under SERIALIZABLE isolation
	// + a transaction-scoped advisory lock. The supplied hashFn MUST be the
	// canonical chain hash function (chain.EventHash bound to e). It is
	// invoked with the prev_hash read inside the locked transaction. The
	// caller must NOT pre-set e.PrevHash or e.ThisHash before calling;
	// InsertChained sets both. Returns (inserted=true, nil) for a fresh
	// insert, (false, nil) for an idempotent re-delivery (same event id).
	InsertChained(ctx context.Context, e *Event, hashFn func(prevHash []byte) []byte) (bool, error)
	// Get returns a single event by id.
	Get(ctx context.Context, id string) (*Event, error)
	// List returns events matching the filter, ordered by (ts ASC, id ASC).
	List(ctx context.Context, f Filter) (*ListResult, error)
	// ChainHead returns the current tail of the chain (the event with the
	// maximum (ts, id)) and its this_hash, used to set prev_hash for the
	// next insert. Returns (nil, ZeroHash) if the chain is empty.
	//
	// NOTE: ChainHead is safe for read-only consumers (verify, anchor),
	// but MUST NOT be used to extend the chain outside a transaction. Use
	// InsertChained for that.
	ChainHead(ctx context.Context) (*Event, error)
	// SetLegalHold toggles the legal_hold flag for an event.
	SetLegalHold(ctx context.Context, id string, hold bool) error
	// MarkAnchored sets anchored=true for events with (ts, id) <= (toTS, toID).
	MarkAnchored(ctx context.Context, toTS time.Time, toID string) (int64, error)
}

// Anchor is a persisted KMS-signed chain anchor.
type Anchor struct {
	ID          string
	AnchoredAt  time.Time
	RootHash    []byte
	LastEventID string
	LastEventTS time.Time
	Signature   []byte
	KMSKeyID    string
	NotaryURL   string
	EventCount  int64
}

// AnchorStore persists and reads chain anchors.
type AnchorStore interface {
	// InsertAnchor persists a new anchor and returns its assigned id.
	InsertAnchor(ctx context.Context, a *Anchor) (string, error)
	// ListAnchors returns anchors ordered by anchored_at ASC within [from,to].
	ListAnchors(ctx context.Context, from, to time.Time) ([]*Anchor, error)
	// GetAnchor returns a single anchor by id.
	GetAnchor(ctx context.Context, id string) (*Anchor, error)
}

// ExportJob is the persisted state of a regulator export request.
type ExportJob struct {
	ID           string
	Query        []byte // raw JSON of the query object
	Format       string // "JSON" or "CSV"
	RetentionDays int
	Status       string // PENDING, RUNNING, COMPLETE, FAILED
	RowCount     int64
	PayloadRef   string
	ChainRoot    []byte
	AnchorID     string
	CreatedAt    time.Time
	CompletedAt  time.Time
}

// ExportJobStore persists export jobs.
type ExportJobStore interface {
	// CreateJob inserts a new export job.
	CreateJob(ctx context.Context, j *ExportJob) error
	// GetJob returns a single export job by id.
	GetJob(ctx context.Context, id string) (*ExportJob, error)
	// UpdateJob marks an export job's status/result fields. Only status,
	// row_count, payload_ref, chain_root, anchor_id, and completed_at may
	// be set.
	UpdateJob(ctx context.Context, id string, status string, rowCount int64, payloadRef string, chainRoot []byte, anchorID string, completedAt time.Time) error
	// ListJobs returns all export jobs ordered by created_at DESC (admin view).
	ListJobs(ctx context.Context, limit int) ([]*ExportJob, error)
}

// DeadLetter is a rejected-event record.
type DeadLetter struct {
	ID         string
	Topic      string
	Partition  int
	Offset     int64
	Key        string
	Payload    []byte
	Reason     string
	RejectedAt  time.Time
}

// DeadLetterStore persists rejected events.
type DeadLetterStore interface {
	Append(ctx context.Context, dl *DeadLetter) error
	List(ctx context.Context, limit int) ([]*DeadLetter, error)
}

// All bundles the per-aggregate stores for convenient wiring.
type All struct {
	Events      EventStore
	Anchors     AnchorStore
	Exports     ExportJobStore
	DeadLetters DeadLetterStore
}