# Audit / Event Log

![CI](https://github.com/ai-crypto-onramp/audit-logger/actions/workflows/ci.yml/badge.svg)
[![codecov](https://codecov.io/gh/ai-crypto-onramp/audit-logger/branch/main/graph/badge.svg)](https://codecov.io/gh/ai-crypto-onramp/audit-logger)

Append-only audit trail for compliance and incident forensics; consumes the event bus.

## Overview / Responsibilities

The Audit / Event Log service is the centralized, append-only record of every
meaningful state change across the crypto on-ramp. It consumes events emitted by
upstream services over the event bus (Kafka) and persists them in a
tamper-evident, hash-chained, immutable store. It serves compliance teams,
regulators, security/forensics, and internal incident responders.

Core responsibilities:

- Ingest domain events from ORCH, PAY, MPC, POLICY, LEDGER and other services
  via the shared event bus.
- Normalize each event into a structured audit envelope with a fixed schema.
- Persist events in append-only (WORM) storage with cryptographic hash chaining
  so any after-the-fact modification is detectable.
- Provide searchable, indexed read access for incident response and compliance
  queries.
- Produce regulator-grade exports (JSON/CSV) with retention windows.
- Periodically anchor the hash chain to an external trust anchor (KMS / external
  notary) to prove chain integrity predating any alleged tampering.
- Run integrity verification tooling that recomputes the chain and detects gaps
  or modified records.

## Language & Tech Stack

- **Language:** Go
- **Transport in:** Kafka consumer (event bus)
- **Storage:** Append-only storage with hash chaining; PostgreSQL as the
  searchable index; S3 (with S3 Glacier lifecycle) for cold payload retention
- **Tamper-evidence:** SHA-256 hash chain where each event records the hash of
  the previous event; periodic root anchors to KMS / external notary
- **Retention:** WORM (Write-Once-Read-Many) retention with Object Lock; cold
  tier to S3 Glacier

## System Requirements

1. **Centralized audit trail:** Single append-only store for audit events across
   all services (ORCH, PAY, MPC, POLICY, LEDGER, KYC, KYT, WALLET, CHAIN, etc.).
2. **Structured event schema:** Every event must contain `actor`, `action`,
   `target` (type + id), `ts`, `source_service`, and `payload_hash`.
3. **Cryptographic chaining:** Each event stores `prev_hash` (hash of the
   preceding event) and `this_hash` (hash of its own canonical content including
   `prev_hash`), forming a tamper-evident chain.
4. **Tamper-evidence:** Any modification to a stored event must be detectable via
   chain recomputation or anchor verification.
5. **Immutability (WORM):** Storage must prevent overwrites/deletes for the
   retention period (Object Lock / WORM-tier storage).
6. **Long retention:** Financial records retained 7+ years (2555+ days) to
   satisfy SOX/AML record-keeping requirements.
7. **Searchable by attributes:** Events queryable by time range, source service,
   actor, action, and target.
8. **Regulator export:** On-demand export in JSON or CSV with explicit retention
   window, signed and immutable once produced.
9. **PII redaction policy:** Configurable redaction/transformation of PII fields
   at ingest so the audit store does not become a plaintext PII repository.
10. **Integrity verification tool:** A CLI/admin endpoint that walks the chain,
    recomputes hashes, and reports the first broken link and any gap.

## Non-Functional Requirements

| Attribute | Target |
|---|---|
| Ingest latency (event → persisted + indexed) | < 1s p99 |
| Storage durability | 99.999999999% (11 nines) via S3 + replication |
| Ingest delivery | At-least-once Kafka consume with idempotent dedup on event id |
| Query p99 (indexed lookups) | < 500ms |
| Tamper detection | Any single-bit modification detectable; chain recompute ≤ 30 min for full sweep |
| Availability | 99.9% (audit reads may degrade to read-only replica on primary loss) |
| Retention | 7+ years (2555 days default), legal-hold override |

## Technical Specifications

### API Surface

- **Write path:** Kafka consumer only — no public write API. Services publish
  domain events to the event bus; the audit service consumes and persists.
- **Read path:** REST (HTTPS) for queries and retrieval.
- **Admin path:** REST for exports, chain verification, legal hold, retention
  config (restricted to audit-admin role).

### Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/events?from=&to=&service=&actor=&action=&target_type=&target_id=&limit=&cursor=` | Paginated event search over indexed attributes |
| GET | `/v1/events/:id` | Fetch a single event by id (full envelope + payload ref) |
| GET | `/v1/events/:id/verify-chain` | Verify the chain linkage for a single event (returns prev/this hash, status) |
| POST | `/v1/exports` | Create an export job: body `{ "query": {...}, "format": "json|csv", "retention_days": N }`; returns export id + signed S3 location when complete |
| GET | `/v1/exports/:id` | Poll export job status / download link |
| POST | `/v1/admin/verify-chain` | Trigger a full-chain integrity sweep (admin only) |
| POST | `/v1/admin/legal-hold/:id` | Place / release legal hold on an event (admin only) |

### Data Model

Table `audit_events` (PostgreSQL — searchable index):

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | Deterministic id (hash of producer id + ts) for dedup |
| `ts` | TIMESTAMPTZ | Event occurrence time (producer-supplied) |
| `source_service` | TEXT | Emitting service (orch, pay, mpc, policy, ledger, ...) |
| `actor_id` | TEXT | User / service / API key that performed the action |
| `action` | TEXT | Verb (e.g. `tx.initiated`, `sign.approved`, `ledger.posted`) |
| `target_type` | TEXT | Resource kind (`transaction`, `wallet`, `signing_job`) |
| `target_id` | TEXT | Resource id |
| `payload_hash` | BYTEA | SHA-256 of the full original payload |
| `payload_ref` | TEXT | S3 object key holding the (possibly redacted) payload |
| `prev_hash` | BYTEA | `this_hash` of the preceding event (genesis = 0) |
| `this_hash` | BYTEA | SHA-256 over canonical (id, ts, source_service, actor_id, action, target_type, target_id, payload_hash, prev_hash) |
| `anchored` | BOOL | True once included in a KMS-anchored root |
| `legal_hold` | BOOL | True if under legal hold (exempt from lifecycle delete) |
| `redacted` | BOOL | True if PII redaction was applied to the stored payload |

The chain is materialized by `(ts ASC, id ASC)` ordering at write time. Reads
are served from PostgreSQL; full payloads are fetched from S3 on demand via
`payload_ref`.

### Event Schema

Wire format (Kafka value, JSON):

```json
{
  "id": "uuid",
  "ts": "2026-07-06T12:34:56.789Z",
  "source_service": "orch",
  "actor_id": "user_7f3a",
  "action": "tx.initiated",
  "target_type": "transaction",
  "target_id": "tx_01H...",
  "payload_hash": "sha256:9f86d0...",
  "payload": { "amount": "100.00", "currency": "USD", "chain": "ethereum" },
  "prev_hash": "sha256:2c26b4...",
  "this_hash": "sha256:b5a3ad...",
  "redaction": "none"
}
```

Required fields: `id`, `ts`, `source_service`, `actor_id`, `action`,
`target_type`, `target_id`, `payload_hash`, `prev_hash`, `this_hash`. `payload`
is optional on the wire (producer may send only `payload_hash` and out-of-band
the payload to S3); the audit service computes/validates `this_hash`.

### Integrations

- **Event bus (Kafka):** Consumes `audit.v1` topic (consumer group
  `audit-event-log`). Idempotent on event `id`.
- **S3 (payload bucket):** Stores full event payloads; lifecycle transitions to
  S3 Glacier after 90 days, Glacier Deep Archive after 1 year; Object Lock in
  compliance mode for the full retention period.
- **PostgreSQL:** Searchable index of audit_events; not the system of record for
  tamper-evidence (the chain + S3 payloads are).
- **KMS:** Signs periodic root anchors (`this_hash` of the last event in the
  window) so chain integrity can be proven against a third-party trust anchor.
- **Notification service (optional):** Signed webhooks for a configurable subset
  of critical events (e.g. `sign.approved`, `policy.override`) to a downstream
  SIEM / SOC pipeline.

### Tamper-Evidence

- Each event stores `prev_hash` = `this_hash` of the immediately preceding event.
- `this_hash` = `SHA-256` over the canonical concatenation of indexed fields and
  `prev_hash` (and `payload_hash`, not the payload itself, so payload redaction
  does not break the chain).
- Every `CHAIN_ANCHOR_INTERVAL_MINUTES` (default 60), the service writes a root
  anchor record containing the latest `this_hash`, signed by KMS. The signed
  anchor is itself stored in S3 + emitted to an external notary (configurable).
- Verification recomputes `this_hash` for every event, checks `prev_hash`
  linkage, and validates that each KMS-signed anchor matches the recomputed root
  at that point in the chain. First mismatch + position is reported.

## Dependencies

| Dependency | Purpose |
|---|---|
| Kafka | Event bus consumer (ingest) |
| PostgreSQL | Searchable index of audit events |
| S3 (Standard + Glacier) | Append-only payload storage with WORM Object Lock |
| KMS | Signs periodic chain root anchors |
| (Optional) External notary | Receives signed anchors for third-party proof |

## Configuration

| Env var | Required | Default | Description |
|---|---|---|---|
| `PORT` | yes | `8080` | REST listen port |
| `KAFKA_BROKERS` | yes | — | Comma-separated broker list |
| `KAFKA_TOPIC` | yes | `audit.v1` | Source event bus topic |
| `KAFKA_CONSUMER_GROUP` | no | `audit-event-log` | Consumer group id |
| `DB_URL` | yes | — | PostgreSQL DSN for the index |
| `PAYLOAD_BUCKET` | yes | — | S3 bucket for event payloads |
| `PAYLOAD_STORAGE_CLASS` | no | `STANDARD` | Initial S3 storage class |
| `GLACIER_TRANSITION_DAYS` | no | `90` | Days before Standard → Glacier |
| `DEEP_ARCHIVE_TRANSITION_DAYS` | no | `365` | Days before Glacier → Deep Archive |
| `RETENTION_DAYS` | no | `2555` | WORM retention (7 years) |
| `CHAIN_ANCHOR_INTERVAL_MINUTES` | no | `60` | How often to anchor chain root to KMS |
| `KMS_KEY_ID` | yes | — | KMS key for signing anchors |
| `EXTERNAL_NOTARY_URL` | no | — | Optional notary endpoint for signed anchors |
| `REDACTION_POLICY_PATH` | no | `/etc/audit/redaction.yaml` | PII redaction rules |
| `LOG_LEVEL` | no | `info` | Log level (debug/info/warn/error) |
| `LEGAL_HOLD_DEFAULT` | no | `false` | Whether new events start under legal hold |

## Local Development

```bash
# Build
go build -o bin/audit-event-log ./cmd/audit-event-log

# Run (requires local Kafka, Postgres, S3-compatible store, KMS mock)
go run ./cmd/audit-event-log

# Run tests
go test ./...

# Run chain verification tests specifically (these validate tamper detection)
go test ./internal/chain -run TestVerify

# Run integrity sweep CLI against a running instance
./bin/audit-event-log verify-chain --from=2026-01-01 --to=2026-07-06

# Produce a sample export
curl -X POST http://localhost:8080/v1/exports \
  -H 'content-type: application/json' \
  -d '{"query":{"from":"2026-01-01","to":"2026-07-06","service":"orch"},"format":"csv","retention_days":2555}'
```

## Compliance

- **SOX / AML retention:** Default retention 2555 days (7 years) satisfies
  financial record-keeping obligations; configurable per jurisdiction via
  `RETENTION_DAYS`.
- **Legal hold:** Any event may be placed under legal hold via
  `/v1/admin/legal-hold/:id`, which exempts it from lifecycle deletion until the
  hold is released. Legal-hold events remain queryable and exportable.
- **Regulator export format:** Exports are produced as JSON or CSV with a fixed
  envelope (the same schema as the stored event, plus `prev_hash` and
  `this_hash`). Each export is written to S3 with Object Lock and a signed
  download URL; the export artifact itself is immutable for `retention_days`.
- **PII redaction:** A redaction policy (`REDACTION_POLICY_PATH`) declares
  field-level transforms (hash, mask, drop) per `source_service` / `action`.
  Redaction is applied at ingest before the payload is written to S3; the
  `redacted` flag and `payload_hash` (of the original payload) are preserved so
  integrity is provable without retaining plaintext PII.
- **Integrity proof:** The verification tool produces a signed report attesting
  chain integrity over a given window, suitable for submission to auditors and
  regulators.
