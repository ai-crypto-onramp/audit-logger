package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ai-crypto-onramp/audit-logger/internal/store"
)

func TestListOnlyStoreInsertError(t *testing.T) {
	s := &listOnlyStore{op: nil}
	if _, err := s.Insert(context.Background(), &store.Event{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestListOnlyStoreChainHeadError(t *testing.T) {
	s := &listOnlyStore{op: nil}
	if _, err := s.ChainHead(context.Background()); err == nil {
		t.Fatal("expected error")
	}
}

func TestListOnlyStoreSetLegalHoldError(t *testing.T) {
	s := &listOnlyStore{op: nil}
	if err := s.SetLegalHold(context.Background(), "x", true); err == nil {
		t.Fatal("expected error")
	}
}

func TestListOnlyStoreMarkAnchoredError(t *testing.T) {
	s := &listOnlyStore{op: nil}
	if _, err := s.MarkAnchored(context.Background(), time.Now(), "x"); err == nil {
		t.Fatal("expected error")
	}
}

func TestListOnlyStoreGetDelegates(t *testing.T) {
	s := &listOnlyStore{op: errOp{}}
	if _, err := s.Get(context.Background(), "x"); err == nil {
		t.Fatal("expected error from delegate")
	}
}

func TestListOnlyStoreListDelegates(t *testing.T) {
	s := &listOnlyStore{op: errOp{}}
	if _, err := s.List(context.Background(), store.Filter{}); err == nil {
		t.Fatal("expected error from delegate")
	}
}

type errOp struct{}

func (errOp) List(ctx context.Context, f store.Filter) (*store.ListResult, error) {
	return nil, errors.New("list boom")
}

func (errOp) Get(ctx context.Context, id string) (*store.Event, error) {
	return nil, errors.New("get boom")
}

func TestRunVerifyChainEmptyStore(t *testing.T) {
	all := newEmptyEvents()
	var buf bytes.Buffer
	rep, code, err := RunVerifyChain(context.Background(), all, time.Time{}, time.Time{}, &buf)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if code != 0 {
		t.Errorf("exit code: %d", code)
	}
	if rep.EventCount != 0 {
		t.Errorf("event count: %d", rep.EventCount)
	}
	if !strings.Contains(buf.String(), "Status:  ok") {
		t.Errorf("output: %q", buf.String())
	}
}

func TestParseVerifyChainFlagsAllFlags(t *testing.T) {
	args := []string{
		"-from", "2026-01-01T00:00:00Z",
		"-to", "2026-07-13T00:00:00Z",
		"-db", "postgres://localhost/audit",
		"-out", "/tmp/report.txt",
		"-sign",
		"-kms-key", "alias/foo",
	}
	f, err := ParseVerifyChainFlags(args)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if f.From != "2026-01-01T00:00:00Z" {
		t.Errorf("from: %q", f.From)
	}
	if f.To != "2026-07-13T00:00:00Z" {
		t.Errorf("to: %q", f.To)
	}
	if f.DBURL != "postgres://localhost/audit" {
		t.Errorf("db: %q", f.DBURL)
	}
	if f.Output != "/tmp/report.txt" {
		t.Errorf("out: %q", f.Output)
	}
	if !f.Sign {
		t.Error("sign should be true")
	}
	if f.KMSKeyID != "alias/foo" {
		t.Errorf("kms: %q", f.KMSKeyID)
	}
}

func TestParseVerifyChainFlagsInvalid(t *testing.T) {
	if _, err := ParseVerifyChainFlags([]string{"-not-a-flag"}); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestParseVerifyChainFlagsDefaultsFromEnv(t *testing.T) {
	os.Setenv("DB_URL", "postgres://env/audit")
	defer os.Unsetenv("DB_URL")
	os.Setenv("KMS_KEY_ID", "alias/env")
	defer os.Unsetenv("KMS_KEY_ID")
	f, err := ParseVerifyChainFlags(nil)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if f.DBURL != "postgres://env/audit" {
		t.Errorf("db: %q", f.DBURL)
	}
	if f.KMSKeyID != "alias/env" {
		t.Errorf("kms: %q", f.KMSKeyID)
	}
}

func TestRunVerifyChainSweepError(t *testing.T) {
	op := errOp{}
	var buf bytes.Buffer
	_, code, err := RunVerifyChain(context.Background(), op, time.Time{}, time.Time{}, &buf)
	if err == nil {
		t.Fatal("expected error")
	}
	if code != 2 {
		t.Errorf("code: %d", code)
	}
}

func newEmptyEvents() *emptyEvents { return &emptyEvents{} }

type emptyEvents struct{}

func (emptyEvents) List(ctx context.Context, f store.Filter) (*store.ListResult, error) {
	return &store.ListResult{Events: nil}, nil
}

func (emptyEvents) Get(ctx context.Context, id string) (*store.Event, error) {
	return nil, &store.ErrNotFound{}
}
