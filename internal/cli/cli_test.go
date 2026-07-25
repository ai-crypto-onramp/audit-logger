package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ai-crypto-onramp/audit-logger/internal/chain"
	"github.com/ai-crypto-onramp/audit-logger/internal/store"
	"github.com/ai-crypto-onramp/audit-logger/internal/store/memstore"
)

func mustTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t.UTC()
}

func seed(t *testing.T, all *memstore.All) []*store.Event {
	t.Helper()
	ctx := context.Background()
	var prev []byte = chain.ZeroHash
	var events []*store.Event
	base := mustTime("2026-07-13T10:00:00Z")
	for i := 0; i < 5; i++ {
		e := &store.Event{
			ID:            "e" + string(rune('a'+i)),
			TS:            base.Add(time.Duration(i) * time.Second),
			SourceService: "orch",
			ActorID:       "u1",
			Action:        "act",
			TargetType:    "tt",
			TargetID:      "tid",
			PayloadHash:   []byte("ph"),
			PrevHash:      append([]byte(nil), prev...),
		}
		e.ThisHash = chain.EventHash(e)
		prev = e.ThisHash
		events = append(events, e)
		_, _ = all.Events.Insert(ctx, e)
	}
	return events
}

func TestRunVerifyChainIntact(t *testing.T) {
	all := memstore.NewAll()
	seed(t, all)
	var buf bytes.Buffer
	rep, code, err := RunVerifyChain(context.Background(), all.Events, time.Time{}, time.Time{}, &buf)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if code != 0 {
		t.Errorf("exit code: %d", code)
	}
	if rep.Status != chain.StatusOK {
		t.Errorf("status: %s", rep.Status)
	}
	if !strings.Contains(buf.String(), "Status:  ok") {
		t.Errorf("output missing status: %q", buf.String())
	}
	if !strings.Contains(buf.String(), "Events:  5") {
		t.Errorf("output missing event count: %q", buf.String())
	}
}

func TestRunVerifyChainDetectsTamper(t *testing.T) {
	all := memstore.NewAll()
	events := seed(t, all)
	// Tamper event 2's actor_id in place.
	all.Events.TamperForTest(events[2].ID, func(e *store.Event) {
		e.ActorID = "tampered"
	})
	var buf bytes.Buffer
	rep, code, err := RunVerifyChain(context.Background(), all.Events, time.Time{}, time.Time{}, &buf)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if code != 1 {
		t.Errorf("exit code: %d", code)
	}
	if rep.Status != chain.StatusBroken {
		t.Errorf("status: %s", rep.Status)
	}
	if rep.FirstBroken != "ec" {
		t.Errorf("first broken: %s", rep.FirstBroken)
	}
	if !strings.Contains(buf.String(), "First broken event: ec") {
		t.Errorf("output missing broken event: %q", buf.String())
	}
}

func TestRunVerifyChainWindowFilter(t *testing.T) {
	all := memstore.NewAll()
	seed(t, all)
	var buf bytes.Buffer
	from := mustTime("2026-07-13T10:00:01Z")
	to := mustTime("2026-07-13T10:00:03Z")
	rep, _, err := RunVerifyChain(context.Background(), all.Events, from, to, &buf)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	// 2 events in [01, 03): e1 (ts=01), e2 (ts=02). e3 (ts=03) excluded by To exclusive.
	if rep.EventCount != 2 {
		t.Errorf("event count: %d", rep.EventCount)
	}
}

func TestParseVerifyChainFlags(t *testing.T) {
	args := []string{"-from", "2026-01-01T00:00:00Z", "-to", "2026-07-13T00:00:00Z", "-db", "postgres://localhost/audit"}
	f, err := ParseVerifyChainFlags(args)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if f.From != "2026-01-01T00:00:00Z" {
		t.Errorf("from: %q", f.From)
	}
	if f.DBURL != "postgres://localhost/audit" {
		t.Errorf("db: %q", f.DBURL)
	}
}