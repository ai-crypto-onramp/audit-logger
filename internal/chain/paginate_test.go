package chain

import (
	"context"
	"testing"
	"time"

	"github.com/ai-crypto-onramp/audit-logger/internal/store"
	"github.com/ai-crypto-onramp/audit-logger/internal/store/memstore"
)

func TestSweepAnchorMissingEvent(t *testing.T) {
	// Insert an anchor whose LastEventID does not exist in the event
	// store; Sweep should count it as an anchor mismatch (the
	// err != nil || head == nil branch).
	all := memstore.NewAll()
	ctx := context.Background()
	_, _ = all.Events.Insert(ctx, &store.Event{
		ID:            "e1",
		TS:            mustTime(t, "2026-07-13T10:00:00Z"),
		SourceService: "s",
		PayloadHash:   []byte("p"),
		ThisHash:      []byte("0123456789abcdef0123456789abcdef"),
	})
	// Manually insert an anchor pointing to a non-existent event id.
	_, _ = all.Anchors.InsertAnchor(ctx, &store.Anchor{
		RootHash:    make([]byte, 32),
		LastEventID: "does-not-exist",
		EventCount:  1,
	})
	rep, err := Sweep(ctx, all.Events, all.Anchors, time.Time{}, time.Time{}, nil)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if rep.AnchorMismatches == 0 {
		t.Fatal("expected anchor mismatch for missing event")
	}
}

func TestSweepPaginates(t *testing.T) {
	// Insert more than 1000 events so Sweep's List pagination
	// continuation (cursor = res.NextCursor) is exercised.
	all := memstore.NewAll()
	ctx := context.Background()
	base := mustTime(t, "2026-07-13T10:00:00Z")
	var prev []byte = ZeroHash
	for i := 0; i < 1001; i++ {
		id := "e" + zeroPad(i)
		e := &store.Event{
			ID:            id,
			TS:            base.Add(time.Duration(i) * time.Millisecond),
			SourceService: "s",
			ActorID:       "u",
			Action:        "a",
			TargetType:    "t",
			TargetID:      "ti",
			PayloadHash:   []byte("p"),
			PrevHash:      append([]byte(nil), prev...),
		}
		e.ThisHash = EventHash(e)
		prev = e.ThisHash
		_, _ = all.Events.Insert(ctx, e)
	}
	rep, err := Sweep(ctx, all.Events, nil, time.Time{}, time.Time{}, nil)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if rep.EventCount != 1001 {
		t.Errorf("event count: %d", rep.EventCount)
	}
}

func zeroPad(n int) string {
	// Produce a zero-padded 4-digit decimal string for stable sort order.
	const digits = "0123456789"
	s := make([]byte, 4)
	for i := 3; i >= 0; i-- {
		s[i] = digits[n%10]
		n /= 10
	}
	return string(s)
}