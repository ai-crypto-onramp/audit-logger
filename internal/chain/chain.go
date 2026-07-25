// Package chain implements the SHA-256 hash chain that links audit events.
// this_hash = SHA-256 over the canonical concatenation of (id, ts,
// source_service, actor_id, action, target_type, target_id, payload_hash,
// prev_hash). The chain is materialized by (ts ASC, id ASC) ordering at
// write time; the genesis event's prev_hash is all-zero.
//
// The package also implements the periodic anchor job that signs the chain
// root with a KMS Signer, and the Verify tool that recomputes hashes and
// detects tampering.
package chain

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ai-crypto-onramp/audit-logger/internal/event"
	"github.com/ai-crypto-onramp/audit-logger/internal/store"
)

// ZeroHash is the genesis prev_hash sentinel (32 zero bytes).
var ZeroHash = make([]byte, 32)

// CanonicalHash computes this_hash for a pending event given its prev_hash.
// The hash covers the canonical byte encoding of (id, ts, source_service,
// actor_id, action, target_type, target_id, payload_hash, prev_hash). The
// payload body is NOT included; payload_hash is, so payload redaction does
// not invalidate the chain.
func CanonicalHash(id string, ts time.Time, sourceService, actorID, action, targetType, targetID string, payloadHash, prevHash []byte) []byte {
	h := sha256.New()
	writeStr(h, id)
	writeTime(h, ts)
	writeStr(h, sourceService)
	writeStr(h, actorID)
	writeStr(h, action)
	writeStr(h, targetType)
	writeStr(h, targetID)
	writeBytes(h, payloadHash)
	writeBytes(h, prevHash)
	return h.Sum(nil)
}

// EventHash computes this_hash for a store.Event (convenience wrapper).
func EventHash(e *store.Event) []byte {
	return CanonicalHash(e.ID, e.TS, e.SourceService, e.ActorID, e.Action, e.TargetType, e.TargetID, e.PayloadHash, e.PrevHash)
}

// EventHashFromEnvelope computes this_hash for a wire envelope given a
// prev_hash. The payload_hash field is parsed from the envelope's
// "sha256:<hex>" representation.
func EventHashFromEnvelope(ev *event.Envelope, prevHash []byte) ([]byte, error) {
	payloadHash, err := event.DecodeHashToBytes(ev.PayloadHash)
	if err != nil {
		return nil, fmt.Errorf("chain: payload_hash: %w", err)
	}
	return CanonicalHash(ev.ID, ev.TS, ev.SourceService, ev.ActorID, ev.Action, ev.TargetType, ev.TargetID, payloadHash, prevHash), nil
}

// HashHex returns the "sha256:<hex>" representation of a raw 32-byte hash.
func HashHex(b []byte) string {
	if len(b) != 32 {
		return ""
	}
	return event.HashPrefix + hex.EncodeToString(b)
}

// ParseHash parses a "sha256:<hex>" or bare-hex string into 32 raw bytes.
func ParseHash(s string) ([]byte, error) { return event.DecodeHashToBytes(s) }

// --- helpers ---

// writeStr writes a length-prefixed UTF-8 string. The length is a 4-byte
// big-endian uint32. This canonical encoding is independent of the JSON
// representation so we can recompute hashes deterministically.
func writeStr(h sha256Hasher, s string) {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(s)))
	_, _ = h.Write(lenBuf[:])
	_, _ = h.Write([]byte(s))
}

// writeBytes writes a length-prefixed byte slice. Empty slices are
// distinguished from nil by always emitting the 4-byte length prefix.
func writeBytes(h sha256Hasher, b []byte) {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(b)))
	_, _ = h.Write(lenBuf[:])
	_, _ = h.Write(b)
}

// writeTime writes ts as a UnixNano int64 in big-endian fixed-width encoding.
func writeTime(h sha256Hasher, ts time.Time) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(ts.UTC().UnixNano()))
	_, _ = h.Write(buf[:])
}

// sha256Hasher is the subset of hash.Hash used by the helpers.
type sha256Hasher interface {
	Write(p []byte) (n int, err error)
}

// --- Verify ---

// VerifyResult is the outcome of verifying a single link.
type VerifyResult struct {
	Event     *store.Event
	PrevHash  []byte
	ThisHash  []byte
	Computed  []byte
	Status    VerifyStatus
	Reason    string
}

// VerifyStatus enumerates verification outcomes for a single event.
type VerifyStatus string

const (
	StatusOK    VerifyStatus = "ok"
	StatusBroken VerifyStatus = "broken"   // computed this_hash != stored this_hash
	StatusGap   VerifyStatus = "gap"      // prev_hash linkage broken
)

// VerifyEvent recomputes this_hash for a single event and checks that
// prev_hash matches the supplied prev. Pass nil for prev to only check
// this_hash integrity.
func VerifyEvent(e *store.Event, prev []byte) VerifyResult {
	computed := EventHash(e)
	res := VerifyResult{Event: e, PrevHash: prev, ThisHash: e.ThisHash, Computed: computed}
	if !bytesEqual(computed, e.ThisHash) {
		res.Status = StatusBroken
		res.Reason = "stored this_hash does not match recomputed hash"
		return res
	}
	if prev != nil && !bytesEqual(prev, e.PrevHash) {
		res.Status = StatusGap
		res.Reason = "prev_hash linkage broken"
		return res
	}
	res.Status = StatusOK
	return res
}

// VerifyChain walks events in (ts ASC, id ASC) order and recomputes the
// hash chain. The first broken link or gap stops the walk and is returned.
// If the chain is intact the result's Status is StatusOK and the last
// event's this_hash is returned as Computed (root hash).
func VerifyChain(events []*store.Event) (VerifyResult, []byte) {
	var prev []byte = ZeroHash
	for i, e := range events {
		// Treat the first event's prev_hash as the genesis check.
		expectedPrev := prev
		if i == 0 {
			expectedPrev = nil // genesis only checks this_hash
		}
		res := VerifyEvent(e, expectedPrev)
		if res.Status != StatusOK {
			return res, nil
		}
		prev = e.ThisHash
	}
	if len(events) == 0 {
		return VerifyResult{Status: StatusOK}, ZeroHash
	}
	return VerifyResult{Status: StatusOK}, prev
}

// --- Anchor ---

// AnchorJob signs the current chain root (the this_hash of the chain head)
// and persists a chain_anchors row. It then marks all covered events
// anchored=true.
type AnchorJob struct {
	Events    store.EventStore
	Anchors   store.AnchorStore
	Signer    func(digest []byte) (signature []byte, keyID string, err error)
	NotaryURL string
	// EventCount, if non-nil, returns the number of events covered by this
	// anchor; otherwise the count of all currently-unanchored events is used.
	EventCount func(ctx context.Context) (int64, error)
}

// ErrEmptyChain is returned by AnchorJob.Run when there are no events to anchor.
var ErrEmptyChain = errors.New("chain: no events to anchor")

// Run computes the Merkle root over all unanchored events and persists a
// KMS-signed anchor record. For simplicity, the "Merkle root" is the
// this_hash of the current chain head; a future implementation can compute
// a binary-tree root over all unanchored event hashes. Either way the root
// uniquely identifies the chain prefix.
func (a *AnchorJob) Run(ctx context.Context) (*store.Anchor, error) {
	head, err := a.Events.ChainHead(ctx)
	if err != nil {
		return nil, fmt.Errorf("chain: anchor: chain head: %w", err)
	}
	if head == nil {
		return nil, ErrEmptyChain
	}
	root := head.ThisHash
	if len(root) != 32 {
		return nil, fmt.Errorf("chain: anchor: bad root hash %x", root)
	}
	var count int64
	if a.EventCount != nil {
		count, _ = a.EventCount(ctx)
	} else {
		count = 1
	}
	sig, keyID, err := a.Signer(root)
	if err != nil {
		return nil, fmt.Errorf("chain: anchor: sign: %w", err)
	}
	anchor := &store.Anchor{
		RootHash:    append([]byte(nil), root...),
		LastEventID: head.ID,
		LastEventTS: head.TS,
		Signature:   sig,
		KMSKeyID:    keyID,
		NotaryURL:   a.NotaryURL,
		EventCount:  count,
	}
	id, err := a.Anchors.InsertAnchor(ctx, anchor)
	if err != nil {
		return nil, fmt.Errorf("chain: anchor: insert: %w", err)
	}
	anchor.ID = id
	if _, err := a.Events.MarkAnchored(ctx, head.TS, head.ID); err != nil {
		return nil, fmt.Errorf("chain: anchor: mark anchored: %w", err)
	}
	return anchor, nil
}

// --- Sweep (full-chain verification over a window) ---

// Report is the signed integrity report produced by a full-chain sweep.
type Report struct {
	From        time.Time  `json:"from"`
	To          time.Time  `json:"to"`
	EventCount  int64      `json:"event_count"`
	Status      VerifyStatus `json:"status"`
	FirstBroken string      `json:"first_broken_id,omitempty"`
	Position    int         `json:"position,omitempty"`
	Reason      string      `json:"reason,omitempty"`
	RootHash    string      `json:"root_hash,omitempty"`
	AnchorCount int64      `json:"anchor_count"`
	CheckedAnchors int       `json:"anchors_checked"`
	AnchorMismatches int    `json:"anchor_mismatches"`
	Signature   string      `json:"signature,omitempty"`
	SignedAt    time.Time  `json:"signed_at,omitempty"`
	KeyID       string      `json:"key_id,omitempty"`
}

// Sweep walks all events in (ts ASC, id ASC) order within [from, to] and
// recomputes the hash chain. It returns a Report summarizing the outcome.
// If signer is non-nil the report's RootHash is signed and the signature
// is embedded in the report.
//nolint:gocyclo // sweep is inherently complex
func Sweep(ctx context.Context, events store.EventStore, anchors store.AnchorStore, from, to time.Time, signer func([]byte) ([]byte, string, error)) (*Report, error) {
	r := &Report{From: from, To: to, Status: StatusOK}
	var all []*store.Event
	cursor := store.Cursor{}
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		res, err := events.List(ctx, store.Filter{From: from, To: to, Limit: 1000, Cursor: cursor})
		if err != nil {
			return nil, fmt.Errorf("chain: sweep: list: %w", err)
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
		cursor = res.NextCursor
	}
	r.EventCount = int64(len(all))
	vres, root := VerifyChain(all)
	if vres.Status != StatusOK {
		r.Status = vres.Status
		r.Reason = vres.Reason
		if vres.Event != nil {
			r.FirstBroken = vres.Event.ID
			for i, e := range all {
				if e.ID == vres.Event.ID {
					r.Position = i + 1
					break
				}
			}
		}
	}
	if len(root) == 32 {
		r.RootHash = HashHex(root)
	}
	// Verify anchors within the window.
	if anchors != nil {
		anchs, err := anchors.ListAnchors(ctx, from, to)
		if err == nil {
			r.AnchorCount = int64(len(anchs))
			r.CheckedAnchors = len(anchs)
			for _, a := range anchs {
				// Recompute root at anchor's last event.
				head, err := events.Get(ctx, a.LastEventID)
				if err != nil || head == nil {
					r.AnchorMismatches++
					continue
				}
				if len(a.RootHash) == 32 && !bytesEqual(a.RootHash, head.ThisHash) {
					r.AnchorMismatches++
				}
			}
		}
	}
	if signer != nil && len(root) == 32 {
		sig, keyID, err := signer(root)
		if err == nil {
			r.Signature = "sig:" + hex.EncodeToString(sig)
			r.KeyID = keyID
			r.SignedAt = time.Now().UTC()
		}
	}
	return r, nil
}

// --- Merkle root (binary tree) ---

// MerkleRoot computes a binary Merkle root over a list of 32-byte event
// hashes, ordered in the supplied slice order. For empty input it returns
// ZeroHash. For a single input it returns that input. Otherwise it pairs
// hashes, SHA-256s each pair, and recurses. If the number of leaves is odd
// the last leaf is promoted as-is.
func MerkleRoot(hashes [][]byte) []byte {
	if len(hashes) == 0 {
		return append([]byte(nil), ZeroHash...)
	}
	if len(hashes) == 1 {
		return append([]byte(nil), hashes[0]...)
	}
	current := hashes
	for len(current) > 1 {
		var next [][]byte
		for i := 0; i < len(current); i += 2 {
			if i+1 >= len(current) {
				next = append(next, append([]byte(nil), current[i]...))
				continue
			}
			h := sha256.New()
			_, _ = h.Write(current[i])
			_, _ = h.Write(current[i+1])
			next = append(next, h.Sum(nil))
		}
		current = next
	}
	return current[0]
}

// --- bytesEqual ---

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// _ guards.
var _ = strings.HasPrefix