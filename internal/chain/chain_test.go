package chain

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/ai-crypto-onramp/audit-logger/internal/event"
	"github.com/ai-crypto-onramp/audit-logger/internal/kms"
	"github.com/ai-crypto-onramp/audit-logger/internal/store"
	"github.com/ai-crypto-onramp/audit-logger/internal/store/memstore"
)

func mustTime(t *testing.T, s string) time.Time {
	ts, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return ts.UTC()
}

func makeChain(n int) []*store.Event {
	var prev []byte = ZeroHash
	var out []*store.Event
	base, _ := time.Parse(time.RFC3339Nano, "2026-07-13T10:00:00Z")
	base = base.UTC()
	for i := 0; i < n; i++ {
		e := &store.Event{
			ID:            "e" + string(rune('a'+i)),
			TS:            base.Add(time.Duration(i) * time.Second),
			SourceService: "orch",
			ActorID:       "u1",
			Action:        "x",
			TargetType:    "t",
			TargetID:      "i",
			PayloadHash:   []byte("payload-hash"),
			PrevHash:      append([]byte(nil), prev...),
		}
		e.ThisHash = EventHash(e)
		prev = e.ThisHash
		out = append(out, e)
	}
	return out
}

func TestCanonicalHashDeterministic(t *testing.T) {
	ts := mustTime(t, "2026-07-13T10:00:00Z")
	h1 := CanonicalHash("e1", ts, "orch", "u1", "act", "tt", "tid", []byte("ph"), ZeroHash)
	h2 := CanonicalHash("e1", ts, "orch", "u1", "act", "tt", "tid", []byte("ph"), ZeroHash)
	if !bytesEqual(h1, h2) {
		t.Fatal("non-deterministic hash")
	}
	if len(h1) != 32 {
		t.Fatalf("len: %d", len(h1))
	}
}

func TestCanonicalHashChangesWithAnyField(t *testing.T) {
	ts := mustTime(t, "2026-07-13T10:00:00Z")
	base := CanonicalHash("e1", ts, "orch", "u1", "act", "tt", "tid", []byte("ph"), ZeroHash)
	cases := map[string]func() []byte{
		"id":       func() []byte { return CanonicalHash("e2", ts, "orch", "u1", "act", "tt", "tid", []byte("ph"), ZeroHash) },
		"ts":       func() []byte { return CanonicalHash("e1", ts.Add(time.Second), "orch", "u1", "act", "tt", "tid", []byte("ph"), ZeroHash) },
		"service":  func() []byte { return CanonicalHash("e1", ts, "pay", "u1", "act", "tt", "tid", []byte("ph"), ZeroHash) },
		"actor":    func() []byte { return CanonicalHash("e1", ts, "orch", "u2", "act", "tt", "tid", []byte("ph"), ZeroHash) },
		"action":   func() []byte { return CanonicalHash("e1", ts, "orch", "u1", "act2", "tt", "tid", []byte("ph"), ZeroHash) },
		"ttype":    func() []byte { return CanonicalHash("e1", ts, "orch", "u1", "act", "tt2", "tid", []byte("ph"), ZeroHash) },
		"tid":      func() []byte { return CanonicalHash("e1", ts, "orch", "u1", "act", "tt", "tid2", []byte("ph"), ZeroHash) },
		"phash":    func() []byte { return CanonicalHash("e1", ts, "orch", "u1", "act", "tt", "tid", []byte("ph2"), ZeroHash) },
		"prev":     func() []byte { return CanonicalHash("e1", ts, "orch", "u1", "act", "tt", "tid", []byte("ph"), []byte{1, 2, 3}) },
	}
	for name, fn := range cases {
		if bytesEqual(base, fn()) {
			t.Errorf("hash did not change when field %q changed", name)
		}
	}
}

func TestVerifyChainIntact(t *testing.T) {
	events := makeChain(5)
	res, root := VerifyChain(events)
	if res.Status != StatusOK {
		t.Fatalf("status: %s reason: %s", res.Status, res.Reason)
	}
	if len(root) != 32 {
		t.Fatalf("root len: %d", len(root))
	}
	if !bytesEqual(root, events[len(events)-1].ThisHash) {
		t.Error("root should equal last this_hash")
	}
}

func TestVerifyChainDetectsTamper(t *testing.T) {
	events := makeChain(5)
	// Flip a bit in the middle event's actor_id WITHOUT recomputing this_hash.
	events[2].ActorID = "u-tampered"
	res, _ := VerifyChain(events)
	if res.Status != StatusBroken {
		t.Fatalf("expected broken, got %s (%s)", res.Status, res.Reason)
	}
	if res.Event.ID != "ec" {
		t.Errorf("tampered event id: %s", res.Event.ID)
	}
}

func TestVerifyChainDetectsGap(t *testing.T) {
	events := makeChain(5)
	// Sever the link: change event 3's prev_hash to a bogus value and
	// recompute this_hash so the event is internally consistent but the
	// prev_hash linkage is broken (a gap).
	events[3].PrevHash = []byte("bogus-prev")
	events[3].ThisHash = EventHash(events[3])
	// Propagate the change forward so the tamper is isolated to the gap.
	for i := 4; i < len(events); i++ {
		events[i].PrevHash = append([]byte(nil), events[i-1].ThisHash...)
		events[i].ThisHash = EventHash(events[i])
	}
	res, _ := VerifyChain(events)
	if res.Status != StatusGap {
		t.Fatalf("expected gap, got %s (%s)", res.Status, res.Reason)
	}
	if res.Event.ID != "ed" {
		t.Errorf("gap event id: %s", res.Event.ID)
	}
}

func TestVerifyChainEmpty(t *testing.T) {
	res, root := VerifyChain(nil)
	if res.Status != StatusOK {
		t.Fatalf("status: %s", res.Status)
	}
	if !bytesEqual(root, ZeroHash) {
		t.Error("empty chain root should be ZeroHash")
	}
}

func TestVerifyEventSingle(t *testing.T) {
	events := makeChain(1)
	res := VerifyEvent(events[0], nil)
	if res.Status != StatusOK {
		t.Fatalf("status: %s", res.Status)
	}
}

func TestEventHashFromEnvelope(t *testing.T) {
	ph := sha256.Sum256([]byte("payload"))
	ev := &event.Envelope{
		ID:            "e1",
		TS:            mustTime(t, "2026-07-13T10:00:00Z"),
		SourceService: "orch",
		ActorID:       "u1",
		Action:        "act",
		TargetType:    "tt",
		TargetID:      "tid",
		PayloadHash:   event.HashPrefix + hex.EncodeToString(ph[:]),
	}
	prev := ZeroHash
	h, err := EventHashFromEnvelope(ev, prev)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if len(h) != 32 {
		t.Fatalf("len: %d", len(h))
	}
	// Should match computing directly from raw bytes.
	want := CanonicalHash(ev.ID, ev.TS, ev.SourceService, ev.ActorID, ev.Action, ev.TargetType, ev.TargetID, ph[:], prev)
	if !bytesEqual(h, want) {
		t.Fatal("mismatch")
	}
}

func TestHashHexRoundtrip(t *testing.T) {
	raw := []byte("0123456789abcdef0123456789abcdef")
	hexStr := HashHex(raw)
	if hexStr == "" {
		t.Fatal("HashHex empty for 32 bytes")
	}
	parsed, err := ParseHash(hexStr)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !bytesEqual(parsed, raw) {
		t.Fatal("roundtrip mismatch")
	}
	if HashHex([]byte("short")) != "" {
		t.Error("expected empty for short")
	}
}

func TestMerkleRoot(t *testing.T) {
	if !bytesEqual(MerkleRoot(nil), ZeroHash) {
		t.Error("empty merkle root should be ZeroHash")
	}
	one := []byte("0123456789abcdef0123456789abcdef")
	if !bytesEqual(MerkleRoot([][]byte{one}), one) {
		t.Error("single leaf root should be the leaf")
	}
	two := [][]byte{one, []byte("fedcba9876543210fedcba9876543210")}
	root := MerkleRoot(two)
	want := sha256.Sum256(append(append([]byte(nil), two[0]...), two[1]...))
	if !bytesEqual(root, want[:]) {
		t.Fatal("two-leaf merkle root mismatch")
	}
	// Odd leaf count: last leaf promoted.
	three := append([][]byte{one, []byte("fedcba9876543210fedcba9876543210")}, []byte("aaaabbbbccccddddeeeeffff00001111"))
	root = MerkleRoot(three)
	if len(root) != 32 {
		t.Fatalf("root len: %d", len(root))
	}
}

func TestAnchorJobRun(t *testing.T) {
	all := memstore.NewAll()
	ctx := context.Background()
	// Ingest a couple of events so the chain head exists.
	events := makeChain(2)
	for _, e := range events {
		_, _ = all.Events.Insert(ctx, e)
	}
	signer := kms.NewFake("alias/test")
	job := &AnchorJob{
		Events:  all.Events,
		Anchors: all.Anchors,
		Signer:  signer.Sign,
	}
	anchor, err := job.Run(ctx)
	if err != nil {
		t.Fatalf("anchor: %v", err)
	}
	if anchor.LastEventID != "eb" {
		t.Errorf("last event: %s", anchor.LastEventID)
	}
	if string(anchor.RootHash) != string(events[1].ThisHash) {
		t.Error("root mismatch")
	}
	if len(anchor.Signature) == 0 {
		t.Error("empty signature")
	}
	// Verify signature against the root.
	ok, err := signer.Verify(anchor.RootHash, anchor.Signature)
	if err != nil || !ok {
		t.Fatalf("verify anchor: ok=%v err=%v", ok, err)
	}
	// All events should be anchored now.
	head, _ := all.Events.ChainHead(ctx)
	if !head.Anchored {
		t.Error("chain head not anchored")
	}
}

func TestAnchorJobEmptyChain(t *testing.T) {
	all := memstore.NewAll()
	signer := kms.NewFake("k")
	job := &AnchorJob{Events: all.Events, Anchors: all.Anchors, Signer: signer.Sign}
	if _, err := job.Run(context.Background()); !errors.Is(err, ErrEmptyChain) {
		t.Fatalf("expected ErrEmptyChain, got %v", err)
	}
}

func TestAnchorJobRecordsAnchor(t *testing.T) {
	all := memstore.NewAll()
	ctx := context.Background()
	events := makeChain(1)
	for _, e := range events {
		_, _ = all.Events.Insert(ctx, e)
	}
	signer := kms.NewFake("k")
	job := &AnchorJob{Events: all.Events, Anchors: all.Anchors, Signer: signer.Sign}
	anchor, err := job.Run(ctx)
	if err != nil {
		t.Fatalf("anchor: %v", err)
	}
	anchors, _ := all.Anchors.ListAnchors(ctx, time.Time{}, time.Time{})
	if len(anchors) != 1 || anchors[0].ID != anchor.ID {
		t.Errorf("anchors: %v", anchors)
	}
	if anchors[0].KMSKeyID != "k" {
		t.Errorf("key id: %q", anchors[0].KMSKeyID)
	}
}