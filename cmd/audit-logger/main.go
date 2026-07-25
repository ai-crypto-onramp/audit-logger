// Command audit-event-log is the entrypoint for the Audit Event Log
// service. It loads configuration, builds the wired server, and runs it.
// Subcommand `verify-chain` runs the standalone chain integrity CLI.
//
// Run with `go run ./cmd/audit-event-log` (local dev) or `make run`. See
// README.md for the full configuration surface.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/ai-crypto-onramp/audit-logger/internal/app"
	"github.com/ai-crypto-onramp/audit-logger/internal/cli"
	"github.com/ai-crypto-onramp/audit-logger/internal/config"
	"github.com/ai-crypto-onramp/audit-logger/internal/otel"
	"github.com/ai-crypto-onramp/audit-logger/internal/store/postgres"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "verify-chain" {
		os.Exit(runVerifyChain(os.Args[2:]))
	}
	shutdown, err := otel.Init("audit-event-log")
	if err != nil {
		log.Fatalf("otel init: %v", err)
	}
	defer func() { _ = shutdown(context.Background()) }()

	cfg := config.Load()
	srv, err := app.Build(cfg)
	if err != nil {
		log.Fatalf("build: %v", err)
	}
	if err := srv.Run(); err != nil {
		log.Fatalf("run: %v", err)
	}
}

// runVerifyChain runs the verify-chain CLI. When --db is set (or $DB_URL is
// set) it connects to Postgres; otherwise it reports that no source is
// configured and exits 2.
func runVerifyChain(args []string) int {
	flags, err := cli.ParseVerifyChainFlags(args)
	if err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		fmt.Fprintln(os.Stderr, "verify-chain:", err)
		return 2
	}
	if flags.DBURL == "" {
		fmt.Fprintln(os.Stderr, "verify-chain: --db or $DB_URL is required")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	db, err := postgres.Open(ctx, flags.DBURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify-chain: open db:", err)
		return 2
	}
	defer db.Close()
	var from, to time.Time
	if flags.From != "" {
		ts, err := time.Parse(time.RFC3339Nano, flags.From)
		if err != nil {
			fmt.Fprintln(os.Stderr, "verify-chain: invalid --from:", err)
			return 2
		}
		from = ts
	}
	if flags.To != "" {
		ts, err := time.Parse(time.RFC3339Nano, flags.To)
		if err != nil {
			fmt.Fprintln(os.Stderr, "verify-chain: invalid --to:", err)
			return 2
		}
		to = ts
	}
	out := os.Stdout
	if flags.Output != "" {
		f, err := os.Create(flags.Output)
		if err != nil {
			fmt.Fprintln(os.Stderr, "verify-chain: open output:", err)
			return 2
		}
		defer f.Close()
		out = f
	}
	_, code, err := cli.RunVerifyChain(ctx, db.Events(), from, to, out)
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify-chain:", err)
		return 2
	}
	return code
}