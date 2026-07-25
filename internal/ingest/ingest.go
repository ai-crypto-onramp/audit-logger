// Package ingest implements the append-only ingest pipeline: decode the
// Kafka wire envelope, validate it, compute payload_hash if a payload body
// is present, apply PII redaction to the payload, write the payload to S3
// with Object Lock, extend the SHA-256 hash chain by setting prev_hash to
// the current chain head and computing this_hash, and finally insert the
// event into the audit_events index with idempotency on event id.
//
// The pipeline is at-least-once: re-deliveries of the same event id are
// deduped at the repository layer (ON CONFLICT (id) DO NOTHING for
// Postgres, map lookup for the in-memory store). Updates and deletes are
// never exposed at the repository layer (see internal/store).
package ingest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ai-crypto-onramp/audit-logger/internal/chain"
	"github.com/ai-crypto-onramp/audit-logger/internal/event"
	"github.com/ai-crypto-onramp/audit-logger/internal/metrics"
	"github.com/ai-crypto-onramp/audit-logger/internal/s3"
	"github.com/ai-crypto-onramp/audit-logger/internal/store"
)

// PayloadStore is the object-storage surface used by ingest.
type PayloadStore interface {
	Put(ctx context.Context, bucket string, opts s3.PutOptions, body []byte) ([]byte, error)
}

// PutAdapter bridges s3.Client's io.Reader-based Put to a bytes-based Put
// for the ingest pipeline's convenience.
type PutAdapter struct {
	Client s3.Client
}

// Put writes the payload bytes to the bucket/key.
func (p *PutAdapter) Put(ctx context.Context, bucket string, opts s3.PutOptions, body []byte) ([]byte, error) {
	key, err := p.Client.Put(ctx, bucket, opts, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	return []byte(key), nil
}

// Redactor is the redaction surface used by ingest. *redaction.Reloader
// satisfies it; tests can supply a custom implementation.
type Redactor interface {
	Apply(service, action string, body []byte) ([]byte, bool, error)
}

// DeadLetterSink records rejected events. May be nil (rejections are still
// counted via metrics).
type DeadLetterSink interface {
	Append(ctx context.Context, dl *store.DeadLetter) error
}

// Deps bundles ingest dependencies.
type Deps struct {
	Events       store.EventStore
	Payloads      PayloadStore
	PayloadBucket string
	StorageClass  string
	RetentionDays int
	LegalHoldDefault bool
	// Redactor applies PII redaction to payloads before the S3 write. May
	// be nil (no redaction).
	Redactor Redactor
	// DeadLetters records rejected events. May be nil.
	DeadLetters DeadLetterSink
	// Topic is the Kafka topic the message arrived on; recorded on
	// dead-letter entries for traceability.
	Topic string
}

// Pipeline ingests a single Kafka message.
type Pipeline struct {
	deps Deps
}

// New returns a Pipeline wired to the supplied dependencies.
func New(deps Deps) *Pipeline { return &Pipeline{deps: deps} }

// Result is the outcome of processing a single message.
type Result struct {
	Inserted  bool
	EventID   string
	Event     *store.Event
	Reason    string
}

// Ingest decodes a Kafka message value into an envelope, validates it,
// computes payload_hash if needed, applies redaction, writes the payload
// to S3, extends the chain, and inserts the event into the index.
func (p *Pipeline) Ingest(ctx context.Context, value []byte) Result {
	return p.IngestMessage(ctx, IngestMessage_{Value: value})
}

// IngestMessage processes a message with metadata (topic, partition,
// offset) so rejected events can be recorded in the dead-letter sink.
func (p *Pipeline) IngestMessage(ctx context.Context, msg IngestMessage_) Result {
	start := time.Now()
	ev, err := event.DecodeAndValidate(msg.Value)
	if err != nil {
		metrics.IngestRejections.WithLabelValues("unknown", "decode").Inc()
		p.deadLetter(ctx, msg, msg.Value, "decode: "+err.Error())
		return Result{Reason: "decode: " + err.Error()}
	}
	defer func() {
		metrics.IngestLatency.WithLabelValues(ev.SourceService).Observe(time.Since(start).Seconds())
	}()

	// Compute / verify payload_hash.
	var payloadBody []byte
	if len(ev.Payload) > 0 {
		payloadBody = []byte(ev.Payload)
		computed := event.HashPayload(payloadBody)
		if ev.PayloadHash != "" && event.NormalizeHash(ev.PayloadHash) != computed {
			metrics.IngestRejections.WithLabelValues(ev.SourceService, "payload_hash").Inc()
			p.deadLetter(ctx, msg, msg.Value, "payload_hash mismatch")
			return Result{Reason: "payload_hash mismatch", EventID: ev.ID}
		}
		ev.PayloadHash = computed
	}

	// Apply redaction (does not affect payload_hash).
	redacted := false
	if p.deps.Redactor != nil && len(payloadBody) > 0 {
		out, changed, err := p.deps.Redactor.Apply(ev.SourceService, ev.Action, payloadBody)
		if err != nil {
			metrics.IngestRejections.WithLabelValues(ev.SourceService, "redaction").Inc()
			p.deadLetter(ctx, msg, msg.Value, "redaction: "+err.Error())
			return Result{Reason: "redaction: " + err.Error(), EventID: ev.ID}
		}
		if changed {
			payloadBody = out
			redacted = true
		}
	}

	// Compute payload_hash bytes for the chain.
	payloadHash, err := event.DecodeHashToBytes(ev.PayloadHash)
	if err != nil {
		metrics.IngestRejections.WithLabelValues(ev.SourceService, "payload_hash_format").Inc()
		p.deadLetter(ctx, msg, msg.Value, "payload_hash format: "+err.Error())
		return Result{Reason: "payload_hash format: " + err.Error(), EventID: ev.ID}
	}

	// Extend the chain: prev_hash = chain head's this_hash (or ZeroHash).
	head, err := p.deps.Events.ChainHead(ctx)
	if err != nil {
		metrics.IngestRejections.WithLabelValues(ev.SourceService, "chain_head").Inc()
		return Result{Reason: "chain head: " + err.Error(), EventID: ev.ID}
	}
	var prevHash []byte
	if head != nil && len(head.ThisHash) == 32 {
		prevHash = append([]byte(nil), head.ThisHash...)
	} else {
		prevHash = append([]byte(nil), chain.ZeroHash...)
	}

	thisHash := chain.CanonicalHash(ev.ID, ev.TS, ev.SourceService, ev.ActorID, ev.Action, ev.TargetType, ev.TargetID, payloadHash, prevHash)

	// Write payload to S3 BEFORE committing the index row.
	payloadRef := ""
	if p.deps.Payloads != nil && p.deps.PayloadBucket != "" && len(payloadBody) > 0 {
		key := ev.ID
		keyBytes, err := p.deps.Payloads.Put(ctx, p.deps.PayloadBucket, s3.PutOptions{
			Key:           key,
			ContentType:   "application/json",
			StorageClass:  p.deps.StorageClass,
			RetentionDays: p.deps.RetentionDays,
			LegalHold:     p.deps.LegalHoldDefault,
		}, payloadBody)
		if err != nil {
			metrics.IngestRejections.WithLabelValues(ev.SourceService, "s3_put").Inc()
			return Result{Reason: "s3 put: " + err.Error(), EventID: ev.ID}
		}
		payloadRef = string(keyBytes)
	}

	row := &store.Event{
		ID:            ev.ID,
		TS:            ev.TS,
		SourceService: ev.SourceService,
		ActorID:       ev.ActorID,
		Action:        ev.Action,
		TargetType:    ev.TargetType,
		TargetID:      ev.TargetID,
		PayloadHash:   payloadHash,
		PayloadRef:    payloadRef,
		PrevHash:      prevHash,
		ThisHash:      thisHash,
		Anchored:      false,
		LegalHold:     p.deps.LegalHoldDefault,
		Redacted:      redacted,
	}
	inserted, err := p.deps.Events.Insert(ctx, row)
	if err != nil {
		metrics.IngestRejections.WithLabelValues(ev.SourceService, "insert").Inc()
		return Result{Reason: "insert: " + err.Error(), EventID: ev.ID}
	}
	if !inserted {
		metrics.IngestDuplicates.WithLabelValues(ev.SourceService).Inc()
		return Result{Inserted: false, EventID: ev.ID}
	}
	metrics.EventsIngested.WithLabelValues(ev.SourceService).Inc()
	return Result{Inserted: true, EventID: ev.ID, Event: row}
}

// IngestMessage_ carries a Kafka message plus its partition metadata.
type IngestMessage_ struct {
	Topic     string
	Partition int
	Offset    int64
	Key       []byte
	Value     []byte
}

// deadLetter records a rejected event in the sink (if configured) and
// increments the dead-letter counter.
func (p *Pipeline) deadLetter(ctx context.Context, msg IngestMessage_, raw []byte, reason string) {
	metrics.DeadLettered.WithLabelValues(p.deps.Topic).Inc()
	if p.deps.DeadLetters == nil {
		return
	}
	_ = p.deps.DeadLetters.Append(ctx, &store.DeadLetter{
		Topic:     p.deps.Topic,
		Partition: msg.Partition,
		Offset:    msg.Offset,
		Key:       string(msg.Key),
		Payload:   append([]byte(nil), raw...),
		Reason:    reason,
	})
}

// ErrInvalidPayload is returned by helpers for invalid message bodies.
var ErrInvalidPayload = errors.New("ingest: invalid payload")

// _ guard
var _ = fmt.Sprintf