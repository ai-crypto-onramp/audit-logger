// Package export implements the regulator export pipeline. A job serializes
// the matching events to JSON or CSV, writes the artifact to S3 with Object
// Lock for the configured retention period, records a manifest (row count,
// window, chain root, KMS anchor id), and updates the export job row.
package export

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/ai-crypto-onramp/audit-logger/internal/chain"
	"github.com/ai-crypto-onramp/audit-logger/internal/kms"
	"github.com/ai-crypto-onramp/audit-logger/internal/s3"
	"github.com/ai-crypto-onramp/audit-logger/internal/store"
)

// PayloadStore is the object-storage surface used by the export pipeline.
type PayloadStore interface {
	Put(ctx context.Context, bucket string, opts s3.PutOptions, body io.Reader) (string, error)
}

// Deps bundles export dependencies.
type Deps struct {
	Events        store.EventStore
	Anchors       store.AnchorStore
	Jobs          store.ExportJobStore
	Payloads       PayloadStore
	PayloadBucket  string
	Signer         kms.Signer
	// DefaultRetentionDays is applied when the job request omits a value.
	DefaultRetentionDays int
}

// Runner executes pending export jobs.
type Runner struct {
	deps Deps
}

// New returns a Runner wired to the supplied dependencies.
func New(deps Deps) *Runner { return &Runner{deps: deps} }

// RunJob executes a single export job: serialize matching events, write the
// artifact to S3, record a manifest, and update the job row.
func (r *Runner) RunJob(ctx context.Context, job *store.ExportJob) error {
	if job == nil {
		return fmt.Errorf("export: nil job")
	}
	retention := job.RetentionDays
	if retention <= 0 {
		retention = r.deps.DefaultRetentionDays
		if retention <= 0 {
			retention = 2555
		}
	}

	// Parse the query JSON to build a Filter.
	filter, err := parseQuery(job.Query)
	if err != nil {
		_ = r.deps.Jobs.UpdateJob(ctx, job.ID, "FAILED", 0, "", nil, "", time.Now())
		return fmt.Errorf("export: parse query: %w", err)
	}
	filter.Limit = 10000

	// Collect events.
	var all []*store.Event
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		res, err := r.deps.Events.List(ctx, filter)
		if err != nil {
			_ = r.deps.Jobs.UpdateJob(ctx, job.ID, "FAILED", 0, "", nil, "", time.Now())
			return fmt.Errorf("export: list: %w", err)
		}
		if len(res.Events) == 0 {
			break
		}
		for i := range res.Events {
			all = append(all, &res.Events[i])
		}
		if res.NextCursor.TS.IsZero() {
			break
		}
		filter.Cursor = res.NextCursor
	}

	// Serialize.
	var body []byte
	switch job.Format {
	case "JSON", "":
		body, err = serializeJSON(all)
	case "CSV":
		body, err = serializeCSV(all)
	default:
		err = fmt.Errorf("export: unsupported format %q", job.Format)
	}
	if err != nil {
		_ = r.deps.Jobs.UpdateJob(ctx, job.ID, "FAILED", 0, "", nil, "", time.Now())
		return err
	}

	// Compute chain root over the exported window.
	_, root := chain.VerifyChain(all)
	chainRoot := root
	if len(chainRoot) != 32 {
		chainRoot = chain.ZeroHash
	}

	// Sign the root if a signer is configured.
	var anchorID string
	if r.deps.Signer != nil && len(chainRoot) == 32 {
		sig, keyID, err := r.deps.Signer.Sign(chainRoot)
		if err == nil {
			anchor := &store.Anchor{
				RootHash:   append([]byte(nil), chainRoot...),
				Signature:  sig,
				KMSKeyID:   keyID,
				EventCount: int64(len(all)),
			}
			id, err := r.deps.Anchors.InsertAnchor(ctx, anchor)
			if err == nil {
				anchorID = id
			}
		}
	}

	// Build manifest + body.
	manifest := buildManifest(job, all, chainRoot, anchorID)
	manifestJSON, _ := json.MarshalIndent(manifest, "", "  ")
	full := append(manifestJSON, '\n')
	full = append(full, body...)
	full = append(full, '\n')

	// Write to S3 with Object Lock.
	key := "exports/" + job.ID + "." + extForFormat(job.Format)
	if _, err := r.deps.Payloads.Put(ctx, r.deps.PayloadBucket, s3.PutOptions{
		Key:           key,
		ContentType:   "application/octet-stream",
		StorageClass:  "STANDARD",
		RetentionDays: retention,
	}, bytes.NewReader(full)); err != nil {
		_ = r.deps.Jobs.UpdateJob(ctx, job.ID, "FAILED", 0, "", nil, "", time.Now())
		return fmt.Errorf("export: s3 put: %w", err)
	}

	return r.deps.Jobs.UpdateJob(ctx, job.ID, "COMPLETE", int64(len(all)), key, chainRoot, anchorID, time.Now())
}

// Manifest is the export artifact's header describing the window, count,
// chain root, and anchor id.
type Manifest struct {
	Type         string    `json:"type"`
	ExportID      string    `json:"export_id"`
	Format        string    `json:"format"`
	WindowFrom    time.Time `json:"window_from,omitempty"`
	WindowTo      time.Time `json:"window_to,omitempty"`
	RowCount      int64     `json:"row_count"`
	ChainRoot     string    `json:"chain_root"`
	AnchorID      string    `json:"anchor_id,omitempty"`
	KMSKeyID      string    `json:"kms_key_id,omitempty"`
	SignatureHex  string    `json:"signature_hex,omitempty"`
	GeneratedAt   time.Time `json:"generated_at"`
}

func buildManifest(job *store.ExportJob, events []*store.Event, root []byte, anchorID string) Manifest {
	m := Manifest{
		Type:        "audit-export-manifest",
		ExportID:     job.ID,
		Format:       job.Format,
		RowCount:     int64(len(events)),
		ChainRoot:    chain.HashHex(root),
		AnchorID:    anchorID,
		GeneratedAt: time.Now().UTC(),
	}
	if len(events) > 0 {
		m.WindowFrom = events[0].TS
		m.WindowTo = events[len(events)-1].TS
	}
	return m
}

func extForFormat(format string) string {
	if format == "CSV" || format == "csv" {
		return "csv"
	}
	return "json"
}

func serializeJSON(events []*store.Event) ([]byte, error) {
	out := map[string]any{
		"events": events,
	}
	return json.MarshalIndent(out, "", "  ")
}

func serializeCSV(events []*store.Event) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	header := []string{"id", "ts", "source_service", "actor_id", "action", "target_type", "target_id", "payload_hash", "prev_hash", "this_hash", "anchored", "legal_hold", "redacted", "payload_ref"}
	if err := w.Write(header); err != nil {
		return nil, err
	}
	for _, e := range events {
		row := []string{
			e.ID,
			e.TS.UTC().Format(time.RFC3339Nano),
			e.SourceService,
			e.ActorID,
			e.Action,
			e.TargetType,
			e.TargetID,
			"sha256:" + hex.EncodeToString(e.PayloadHash),
			chain.HashHex(e.PrevHash),
			chain.HashHex(e.ThisHash),
			boolStr(e.Anchored),
			boolStr(e.LegalHold),
			boolStr(e.Redacted),
			e.PayloadRef,
		}
		if err := w.Write(row); err != nil {
			return nil, err
		}
	}
	w.Flush()
	return buf.Bytes(), nil
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// parseQuery decodes a query JSON object into a Filter.
func parseQuery(raw []byte) (store.Filter, error) {
	var f store.Filter
	if len(raw) == 0 {
		return f, nil
	}
	var q map[string]any
	if err := json.Unmarshal(raw, &q); err != nil {
		return f, err
	}
	if v, ok := q["from"].(string); ok && v != "" {
		ts, err := time.Parse(time.RFC3339Nano, v)
		if err == nil {
			f.From = ts
		}
	}
	if v, ok := q["to"].(string); ok && v != "" {
		ts, err := time.Parse(time.RFC3339Nano, v)
		if err == nil {
			f.To = ts
		}
	}
	if v, ok := q["service"].(string); ok {
		f.Service = v
	}
	if v, ok := q["actor"].(string); ok {
		f.Actor = v
	}
	if v, ok := q["action"].(string); ok {
		f.Action = v
	}
	if v, ok := q["target_type"].(string); ok {
		f.TargetType = v
	}
	if v, ok := q["target_id"].(string); ok {
		f.TargetID = v
	}
	return f, nil
}