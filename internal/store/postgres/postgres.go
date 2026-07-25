// Package postgres implements the store interfaces against a real
// PostgreSQL database using pgx/v5. It is NOT used by unit tests (those
// use internal/store/memstore); it is exercised by the integration suite
// via docker-compose. The package is imported only when DB_URL is set.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ai-crypto-onramp/audit-logger/internal/store"
	"github.com/ai-crypto-onramp/audit-logger/internal/store/migrations"
)

// DB wraps a pgxpool.Pool and exposes the store implementations.
type DB struct {
	pool        *pgxpool.Pool
	events      *EventStore
	anchors     *AnchorStore
	exports     *ExportJobStore
	deadLetters *DeadLetterStore
}

// Open connects to dsn, pings, runs migrations, and returns a wired DB.
func Open(ctx context.Context, dsn string) (*DB, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres: open: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}
	d := &DB{pool: pool}
	if err := d.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	d.events = &EventStore{pool: pool}
	d.anchors = &AnchorStore{pool: pool}
	d.exports = &ExportJobStore{pool: pool}
	d.deadLetters = &DeadLetterStore{pool: pool}
	return d, nil
}

// Close releases the pool.
func (d *DB) Close() error {
	if d.pool != nil {
		d.pool.Close()
	}
	return nil
}

func (d *DB) migrate(ctx context.Context) error {
	runner := migrations.NewRunner(
		func(ctx context.Context, q string, args ...any) error {
			_, err := d.pool.Exec(ctx, q, args...)
			return err
		},
		func(ctx context.Context, version string) (bool, error) {
			var applied bool
			err := d.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)`, version).Scan(&applied)
			return applied, err
		},
	)
	return runner.Up(ctx)
}

// Events returns the EventStore.
func (d *DB) Events() store.EventStore { return d.events }

// Anchors returns the AnchorStore.
func (d *DB) Anchors() store.AnchorStore { return d.anchors }

// Exports returns the ExportJobStore.
func (d *DB) Exports() store.ExportJobStore { return d.exports }

// DeadLetters returns the DeadLetterStore.
func (d *DB) DeadLetters() store.DeadLetterStore { return d.deadLetters }

// All returns a store.All bundle.
func (d *DB) All() store.All {
	return store.All{
		Events:      d.events,
		Anchors:     d.anchors,
		Exports:     d.exports,
		DeadLetters: d.deadLetters,
	}
}

// --- EventStore ---

type EventStore struct{ pool *pgxpool.Pool }

func (s *EventStore) Insert(ctx context.Context, e *store.Event) (bool, error) {
	ct, err := s.pool.Exec(ctx, `
		INSERT INTO audit_events
		(id, ts, source_service, actor_id, action, target_type, target_id,
		 payload_hash, payload_ref, prev_hash, this_hash, anchored, legal_hold, redacted)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		ON CONFLICT (id) DO NOTHING`,
		e.ID, e.TS, e.SourceService, e.ActorID, e.Action, e.TargetType, e.TargetID,
		e.PayloadHash, e.PayloadRef, e.PrevHash, e.ThisHash, e.Anchored, e.LegalHold, e.Redacted)
	if err != nil {
		return false, err
	}
	return ct.RowsAffected() > 0, nil
}

func (s *EventStore) Get(ctx context.Context, id string) (*store.Event, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, ts, source_service, actor_id, action, target_type, target_id,
			payload_hash, payload_ref, prev_hash, this_hash, anchored, legal_hold, redacted
		FROM audit_events WHERE id=$1`, id)
	e, err := scanEvent(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &store.ErrNotFound{ID: id}
		}
		return nil, err
	}
	return e, nil
}

func (s *EventStore) List(ctx context.Context, f store.Filter) (*store.ListResult, error) {
	q := `SELECT id, ts, source_service, actor_id, action, target_type, target_id,
		payload_hash, payload_ref, prev_hash, this_hash, anchored, legal_hold, redacted
		FROM audit_events WHERE 1=1`
	args := []any{}
	n := 1
	if !f.From.IsZero() {
		q += fmt.Sprintf(" AND ts >= $%d", n)
		args = append(args, f.From)
		n++
	}
	if !f.To.IsZero() {
		q += fmt.Sprintf(" AND ts < $%d", n)
		args = append(args, f.To)
		n++
	}
	if f.Service != "" {
		q += fmt.Sprintf(" AND source_service = $%d", n)
		args = append(args, f.Service)
		n++
	}
	if f.Actor != "" {
		q += fmt.Sprintf(" AND actor_id = $%d", n)
		args = append(args, f.Actor)
		n++
	}
	if f.Action != "" {
		q += fmt.Sprintf(" AND action = $%d", n)
		args = append(args, f.Action)
		n++
	}
	if f.TargetType != "" {
		q += fmt.Sprintf(" AND target_type = $%d", n)
		args = append(args, f.TargetType)
		n++
	}
	if f.TargetID != "" {
		q += fmt.Sprintf(" AND target_id = $%d", n)
		args = append(args, f.TargetID)
		n++
	}
	if !f.Cursor.TS.IsZero() || f.Cursor.ID != "" {
		q += fmt.Sprintf(" AND (ts, id) > ($%d, $%d)", n, n+1)
		args = append(args, f.Cursor.TS, f.Cursor.ID)
	}
	q += " ORDER BY ts ASC, id ASC"
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	q += fmt.Sprintf(" LIMIT %d", limit+1)
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Event
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	res := &store.ListResult{Events: out}
	if len(out) > limit {
		res.Events = out[:limit]
		last := out[limit-1]
		res.NextCursor = store.Cursor{TS: last.TS, ID: last.ID}
	}
	return res, nil
}

func (s *EventStore) ChainHead(ctx context.Context) (*store.Event, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, ts, source_service, actor_id, action, target_type, target_id,
			payload_hash, payload_ref, prev_hash, this_hash, anchored, legal_hold, redacted
		FROM audit_events ORDER BY ts DESC, id DESC LIMIT 1`)
	e, err := scanEvent(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return e, nil
}

func (s *EventStore) SetLegalHold(ctx context.Context, id string, hold bool) error {
	ct, err := s.pool.Exec(ctx, `UPDATE audit_events SET legal_hold=$2, updated_at=now() WHERE id=$1`, id, hold)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return &store.ErrNotFound{ID: id}
	}
	return nil
}

func (s *EventStore) MarkAnchored(ctx context.Context, toTS time.Time, toID string) (int64, error) {
	ct, err := s.pool.Exec(ctx, `UPDATE audit_events SET anchored=true, updated_at=now() WHERE (ts, id) <= ($1, $2) AND anchored=false`, toTS, toID)
	if err != nil {
		return 0, err
	}
	return ct.RowsAffected(), nil
}

// scanner abstracts pgx.Row and pgx.Rows scan.
type scanner interface {
	Scan(dest ...any) error
}

func scanEvent(s scanner) (*store.Event, error) {
	var e store.Event
	err := s.Scan(&e.ID, &e.TS, &e.SourceService, &e.ActorID, &e.Action, &e.TargetType, &e.TargetID,
		&e.PayloadHash, &e.PayloadRef, &e.PrevHash, &e.ThisHash, &e.Anchored, &e.LegalHold, &e.Redacted)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// --- AnchorStore ---

type AnchorStore struct{ pool *pgxpool.Pool }

func (s *AnchorStore) InsertAnchor(ctx context.Context, a *store.Anchor) (string, error) {
	id, _ := uuid.NewV7()
	row := s.pool.QueryRow(ctx, `
		INSERT INTO chain_anchors (id, anchored_at, root_hash, last_event_id, last_event_ts, signature, kms_key_id, notary_url, event_count)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`,
		id, a.AnchoredAt, a.RootHash, a.LastEventID, a.LastEventTS, a.Signature, a.KMSKeyID, a.NotaryURL, a.EventCount)
	var returnedID string
	if err := row.Scan(&returnedID); err != nil {
		return "", err
	}
	return returnedID, nil
}

func (s *AnchorStore) ListAnchors(ctx context.Context, from, to time.Time) ([]*store.Anchor, error) {
	q := `SELECT id, anchored_at, root_hash, last_event_id, last_event_ts, signature, kms_key_id, notary_url, event_count
		FROM chain_anchors WHERE 1=1`
	args := []any{}
	n := 1
	if !from.IsZero() {
		q += fmt.Sprintf(" AND anchored_at >= $%d", n)
		args = append(args, from)
		n++
	}
	if !to.IsZero() {
		q += fmt.Sprintf(" AND anchored_at <= $%d", n)
		args = append(args, to)
	}
	q += " ORDER BY anchored_at ASC"
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.Anchor
	for rows.Next() {
		var a store.Anchor
		var lastID *string
		var lastTS *time.Time
		if err := rows.Scan(&a.ID, &a.AnchoredAt, &a.RootHash, &lastID, &lastTS, &a.Signature, &a.KMSKeyID, &a.NotaryURL, &a.EventCount); err != nil {
			return nil, err
		}
		if lastID != nil {
			a.LastEventID = *lastID
		}
		if lastTS != nil {
			a.LastEventTS = *lastTS
		}
		out = append(out, &a)
	}
	return out, rows.Err()
}

func (s *AnchorStore) GetAnchor(ctx context.Context, id string) (*store.Anchor, error) {
	row := s.pool.QueryRow(ctx, `SELECT id, anchored_at, root_hash, last_event_id, last_event_ts, signature, kms_key_id, notary_url, event_count FROM chain_anchors WHERE id=$1`, id)
	var a store.Anchor
	var lastID *string
	var lastTS *time.Time
	if err := row.Scan(&a.ID, &a.AnchoredAt, &a.RootHash, &lastID, &lastTS, &a.Signature, &a.KMSKeyID, &a.NotaryURL, &a.EventCount); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &store.ErrNotFound{ID: id}
		}
		return nil, err
	}
	if lastID != nil {
		a.LastEventID = *lastID
	}
	if lastTS != nil {
		a.LastEventTS = *lastTS
	}
	return &a, nil
}

// --- ExportJobStore ---

type ExportJobStore struct{ pool *pgxpool.Pool }

func (s *ExportJobStore) CreateJob(ctx context.Context, j *store.ExportJob) error {
	var createdAt any
	if !j.CreatedAt.IsZero() {
		createdAt = j.CreatedAt
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO export_jobs (id, query, format, retention_days, status, created_at)
		VALUES ($1,$2,$3,$4,$5,COALESCE($6,now()))
		ON CONFLICT (id) DO NOTHING`,
		j.ID, j.Query, j.Format, j.RetentionDays, j.Status, createdAt)
	return err
}

func (s *ExportJobStore) GetJob(ctx context.Context, id string) (*store.ExportJob, error) {
	row := s.pool.QueryRow(ctx, `SELECT id, query, format, retention_days, status, row_count, payload_ref, chain_root, anchor_id, created_at, completed_at FROM export_jobs WHERE id=$1`, id)
	var j store.ExportJob
	var completedAt *time.Time
	var uid pgtype.UUID
	var anchorID *string
	if err := row.Scan(&uid, &j.Query, &j.Format, &j.RetentionDays, &j.Status, &j.RowCount, &j.PayloadRef, &j.ChainRoot, &anchorID, &j.CreatedAt, &completedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &store.ErrNotFound{ID: id}
		}
		return nil, err
	}
	if uid.Valid {
		j.ID = uid.String()
	}
	if anchorID != nil {
		j.AnchorID = *anchorID
	}
	if completedAt != nil {
		j.CompletedAt = *completedAt
	}
	return &j, nil
}

func (s *ExportJobStore) UpdateJob(ctx context.Context, id string, status string, rowCount int64, payloadRef string, chainRoot []byte, anchorID string, completedAt time.Time) error {
	ct, err := s.pool.Exec(ctx, `
		UPDATE export_jobs SET status=$2, row_count=$3, payload_ref=$4, chain_root=$5, anchor_id=$6, completed_at=COALESCE($7, completed_at), updated_at=now()
		WHERE id=$1`,
		id, status, rowCount, payloadRef, chainRoot, anchorID, completedAt)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return &store.ErrNotFound{ID: id}
	}
	return nil
}

func (s *ExportJobStore) ListJobs(ctx context.Context, limit int) ([]*store.ExportJob, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `SELECT id, query, format, retention_days, status, row_count, payload_ref, chain_root, anchor_id, created_at, completed_at FROM export_jobs ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.ExportJob
	for rows.Next() {
		var j store.ExportJob
		var completedAt *time.Time
		var uid pgtype.UUID
		var anchorID *string
		if err := rows.Scan(&uid, &j.Query, &j.Format, &j.RetentionDays, &j.Status, &j.RowCount, &j.PayloadRef, &j.ChainRoot, &anchorID, &j.CreatedAt, &completedAt); err != nil {
			return nil, err
		}
		if uid.Valid {
			j.ID = uid.String()
		}
		if anchorID != nil {
			j.AnchorID = *anchorID
		}
		if completedAt != nil {
			j.CompletedAt = *completedAt
		}
		out = append(out, &j)
	}
	return out, rows.Err()
}

// --- DeadLetterStore ---

type DeadLetterStore struct{ pool *pgxpool.Pool }

func (s *DeadLetterStore) Append(ctx context.Context, dl *store.DeadLetter) error {
	id, _ := uuid.NewV7()
	_, err := s.pool.Exec(ctx, `
		INSERT INTO dead_letter (id, topic, partition_no, offset_no, key, payload, reason)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		id, dl.Topic, dl.Partition, dl.Offset, dl.Key, dl.Payload, dl.Reason)
	return err
}

func (s *DeadLetterStore) List(ctx context.Context, limit int) ([]*store.DeadLetter, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `SELECT id, topic, partition_no, offset_no, key, payload, reason, rejected_at FROM dead_letter ORDER BY rejected_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.DeadLetter
	for rows.Next() {
		var dl store.DeadLetter
		if err := rows.Scan(&dl.ID, &dl.Topic, &dl.Partition, &dl.Offset, &dl.Key, &dl.Payload, &dl.Reason, &dl.RejectedAt); err != nil {
			return nil, err
		}
		out = append(out, &dl)
	}
	return out, rows.Err()
}

// _ guards
var (
	_ = (*pgconn.PgConn)(nil)
)