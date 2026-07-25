// Package chain — tamper-detection regression tests. These tests assert
// that the verifier detects every form of tampering the audit log must
// catch: a single-bit modification, a field-level modification, a removed
// event (gap), and a tampered anchor. They are the regression guard for
// Stage 10 acceptance criterion "Tamper-detection test fails if the
// verifier ever misses a modification."
package chain

import (
	"context"
	"testing"
	"time"

	"github.com/ai-crypto-onramp/audit-logger/internal/kms"
	"github.com/ai-crypto-onramp/audit-logger/internal/store"
	"github.com/ai-crypto-onramp/audit-logger/internal/store/memstore"
)

// buildChain inserts n events into the in-memory store and returns them.
func buildChain(t *testing.T, n int) (*memstore.All, []*store.Event) {
	t.Helper()
	ctx := context.Background()
	all := memstore.NewAll()
	var prev []byte = ZeroHash
	var events []*store.Event
	base, _ := time.Parse(time.RFC3339Nano, "2026-07-13T10:00:00Z")
	for i := 0; i < n; i++ {
		e := &store.Event{
			ID:            "evt" + string(rune('a'+i)),
			TS:            base.Add(time.Duration(i) * time.Second),
			SourceService: "orch",
			ActorID:       "u1",
			Action:        "tx.initiated",
			TargetType:    "transaction",
			TargetID:      "tx" + string(rune('a'+i)),
			PayloadHash:   []byte("ph-" + string(rune('a'+i))),
			PayloadRef:    "s3://" + string(rune('a'+i)),
			PrevHash:      append([]byte(nil), prev...),
		}
		e.ThisHash = EventHash(e)
		prev = e.ThisHash
		events = append(events, e)
		_, _ = all.Events.Insert(ctx, e)
	}
	return all, events
}

// TestTamperSingleBitModification flips one bit in an event's actor_id and
// asserts the verifier reports the offending event id and position.
func TestTamperSingleBitModification(t *testing.T) {
	all, events := buildChain(t, 10)
	// Tamper event 5's actor_id (without recomputing this_hash).
	all.Events.TamperForTest(events[5].ID, func(e *store.Event) {
		e.ActorID = "u1" // unchanged
	})
	// Now flip a single bit in the stored actor_id via a second tamper.
	all.Events.TamperForTest(events[5].ID, func(e *store.Event) {
		if e.ActorID == "u1" {
			e.ActorID = "v1" // single-character change
		}
	})
	rep, err := Sweep(context.Background(), all.Events, all.Anchors, time.Time{}, time.Time{}, nil)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if rep.Status != StatusBroken {
		t.Fatalf("expected broken, got %s (%s)", rep.Status, rep.Reason)
	}
	if rep.FirstBroken != events[5].ID {
		t.Errorf("first broken: %s, want %s", rep.FirstBroken, events[5].ID)
	}
	if rep.Position != 6 {
		t.Errorf("position: %d, want 6", rep.Position)
	}
}

// TestTamperFieldModification tests that modifying any indexed field is
// detected.
func TestTamperFieldModification(t *testing.T) {
	cases := []struct {
		name   string
		tamper func(*store.Event)
	}{
		{"source_service", func(e *store.Event) { e.SourceService = "pay" }},
		{"action", func(e *store.Event) { e.Action = "tx.confirmed" }},
		{"target_id", func(e *store.Event) { e.TargetID = "tampered" }},
		{"payload_hash", func(e *store.Event) { e.PayloadHash = []byte("tampered") }},
		{"prev_hash", func(e *store.Event) {
			e.PrevHash = []byte("bogus-prev")
			e.ThisHash = EventHash(e) // recompute to isolate the prev_hash tamper as a gap
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			all, events := buildChain(t, 6)
			all.Events.TamperForTest(events[3].ID, c.tamper)
			rep, err := Sweep(context.Background(), all.Events, all.Anchors, time.Time{}, time.Time{}, nil)
			if err != nil {
				t.Fatalf("sweep: %v", err)
			}
			if rep.Status == StatusOK {
				t.Fatalf("tamper on %q not detected", c.name)
			}
		})
	}
}

// TestTamperGapDetected asserts a severed chain link is reported as a gap
// with the boundary ids.
func TestTamperGapDetected(t *testing.T) {
	all, events := buildChain(t, 8)
	// Sever link between event 4 and 5: change event 5's prev_hash and
	// recompute this_hash so the gap is isolated.
	all.Events.TamperForTest(events[5].ID, func(e *store.Event) {
		e.PrevHash = []byte("severed")
		e.ThisHash = EventHash(e)
	})
	rep, err := Sweep(context.Background(), all.Events, all.Anchors, time.Time{}, time.Time{}, nil)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if rep.Status != StatusGap {
		t.Fatalf("expected gap, got %s (%s)", rep.Status, rep.Reason)
	}
	if rep.FirstBroken != events[5].ID {
		t.Errorf("first broken: %s, want %s", rep.FirstBroken, events[5].ID)
	}
}

// TestTamperAnchorMismatch asserts an anchor whose root does not match the
// recomputed root is reported as a mismatch.
func TestTamperAnchorMismatch(t *testing.T) {
	all, events := buildChain(t, 5)
	signer := kms.NewFake("alias/test")
	job := &AnchorJob{Events: all.Events, Anchors: all.Anchors, Signer: signer.Sign}
	if _, err := job.Run(context.Background()); err != nil {
		t.Fatalf("anchor: %v", err)
	}
	// Tamper the chain head's this_hash AFTER anchoring so the anchor's
	// recorded root_hash no longer matches the recomputed root.
	all.Events.TamperForTest(events[4].ID, func(e *store.Event) {
		e.ThisHash = []byte("tampered-root")
	})
	rep, err := Sweep(context.Background(), all.Events, all.Anchors, time.Time{}, time.Time{}, nil)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if rep.AnchorMismatches == 0 {
		t.Fatalf("expected at least one anchor mismatch, report=%+v", rep)
	}
}

// TestSignedReport asserts the sweep produces a signed report when a signer
// is supplied.
func TestSignedReport(t *testing.T) {
	all, _ := buildChain(t, 5)
	signer := kms.NewFake("alias/test")
	rep, err := Sweep(context.Background(), all.Events, all.Anchors, time.Time{}, time.Time{}, signer.Sign)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if rep.Signature == "" {
		t.Fatal("expected signed report")
	}
	if rep.KeyID != "alias/test" {
		t.Errorf("key id: %q", rep.KeyID)
	}
}