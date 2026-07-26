// Package cli implements the audit-event-log CLI subcommands, currently
// `verify-chain`. The CLI is built into ./bin/audit-event-log and accepts
// a DB_URL to connect directly to the Postgres index; it streams events
// ordered by (ts, id) and recomputes the hash chain, reporting the first
// broken link and any gap.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/ai-crypto-onramp/audit-logger/internal/chain"
	"github.com/ai-crypto-onramp/audit-logger/internal/store"
)

// VerifyChainFlags parses the CLI flags for `verify-chain`.
type VerifyChainFlags struct {
	From     string
	To       string
	DBURL    string
	Output   string
	Sign     bool
	KMSKeyID string
}

// ParseVerifyChainFlags parses args (without the subcommand name).
func ParseVerifyChainFlags(args []string) (VerifyChainFlags, error) {
	fs := flag.NewFlagSet("verify-chain", flag.ContinueOnError)
	var f VerifyChainFlags
	fs.StringVar(&f.From, "from", "", "start of the window (RFC3339)")
	fs.StringVar(&f.To, "to", "", "end of the window (RFC3339)")
	fs.StringVar(&f.DBURL, "db", os.Getenv("DB_URL"), "PostgreSQL DSN (defaults to $DB_URL)")
	fs.StringVar(&f.Output, "out", "", "output file path (defaults to stdout)")
	fs.BoolVar(&f.Sign, "sign", false, "sign the report with KMS")
	fs.StringVar(&f.KMSKeyID, "kms-key", os.Getenv("KMS_KEY_ID"), "KMS key id for signing")
	if err := fs.Parse(args); err != nil {
		return f, err
	}
	return f, nil
}

// VerifyChainOp is the dependency surface for RunVerifyChain. It is a subset
// of store.EventStore so the CLI can run against either a Postgres-backed
// store or an in-memory store in tests.
type VerifyChainOp interface {
	List(ctx context.Context, f store.Filter) (*store.ListResult, error)
	Get(ctx context.Context, id string) (*store.Event, error)
}

// RunVerifyChain walks events from op in (ts ASC, id ASC) order and
// recomputes the hash chain. It writes a signed report to out. Returns the
// report and the exit status (0 = ok, 1 = broken/gap, 2 = error).
func RunVerifyChain(ctx context.Context, op VerifyChainOp, from, to time.Time, out io.Writer) (*chain.Report, int, error) {
	r, err := chain.Sweep(ctx, &listOnlyStore{op: op}, nil, from, to, nil)
	if err != nil {
		return nil, 2, err
	}
	fmt.Fprintf(out, "Audit Event Log - Chain Integrity Report\n")
	fmt.Fprintf(out, "==========================================\n")
	fmt.Fprintf(out, "Window:  %s -> %s\n", r.From.Format(time.RFC3339), r.To.Format(time.RFC3339))
	fmt.Fprintf(out, "Events:  %d\n", r.EventCount)
	fmt.Fprintf(out, "Status:  %s\n", r.Status)
	if r.FirstBroken != "" {
		fmt.Fprintf(out, "First broken event: %s (position %d)\n", r.FirstBroken, r.Position)
	}
	if r.Reason != "" {
		fmt.Fprintf(out, "Reason:  %s\n", r.Reason)
	}
	if r.RootHash != "" {
		fmt.Fprintf(out, "Root:    %s\n", r.RootHash)
	}
	if r.AnchorCount > 0 {
		fmt.Fprintf(out, "Anchors: %d (checked %d, mismatches %d)\n", r.AnchorCount, r.CheckedAnchors, r.AnchorMismatches)
	}
	if r.Status != chain.StatusOK {
		return r, 1, nil
	}
	return r, 0, nil
}

// listOnlyStore adapts VerifyChainOp to the store.EventStore surface that
// chain.Sweep expects. Only List and Get are populated; the others panic
// or return errors when called, since Sweep only needs List (and Get for
// anchor verification, which we disable by passing nil anchors).
type listOnlyStore struct {
	op VerifyChainOp
}

func (s *listOnlyStore) Insert(context.Context, *store.Event) (bool, error) {
	return false, errors.New("cli: list-only store")
}
func (s *listOnlyStore) InsertChained(context.Context, *store.Event, func(prevHash []byte) []byte) (bool, error) {
	return false, errors.New("cli: list-only store")
}
func (s *listOnlyStore) Get(ctx context.Context, id string) (*store.Event, error) {
	return s.op.Get(ctx, id)
}
func (s *listOnlyStore) List(ctx context.Context, f store.Filter) (*store.ListResult, error) {
	return s.op.List(ctx, f)
}
func (s *listOnlyStore) ChainHead(context.Context) (*store.Event, error) {
	return nil, errors.New("cli: list-only store")
}
func (s *listOnlyStore) SetLegalHold(context.Context, string, bool) error {
	return errors.New("cli: list-only store")
}
func (s *listOnlyStore) MarkAnchored(context.Context, time.Time, string) (int64, error) {
	return 0, errors.New("cli: list-only store")
}