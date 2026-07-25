// Command migrate applies or reverts the embedded database migrations for
// audit-event-log. It reuses internal/store/migrations.Runner.
//
// Usage:
//
//	migrate --up     apply all pending up-migrations (reads DB_URL)
//	migrate --down   revert all applied migrations in reverse order (reads DB_URL)
//
// Run with `go run ./cmd/migrate --up` (local dev) or `make migrate-up`.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ai-crypto-onramp/audit-logger/internal/store/migrations"
)

func main() {
	up := flag.Bool("up", false, "apply all pending up-migrations")
	down := flag.Bool("down", false, "revert all applied migrations in reverse order")
	flag.Parse()
	if !*up && !*down {
		fmt.Fprintln(os.Stderr, "usage: migrate [--up|--down]")
		os.Exit(2)
	}

	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		fmt.Fprintln(os.Stderr, "DB_URL is required")
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open db:", err)
		os.Exit(1)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "ping db:", err)
		os.Exit(1)
	}

	runner := migrations.NewRunner(
		func(ctx context.Context, q string, args ...any) error {
			_, err := pool.Exec(ctx, q, args...)
			return err
		},
		func(ctx context.Context, version string) (bool, error) {
			var applied bool
			err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)`, version).Scan(&applied)
			return applied, err
		},
	)

	switch {
	case *up:
		if err := runner.Up(ctx); err != nil {
			fmt.Fprintln(os.Stderr, "migrate up:", err)
			os.Exit(1)
		}
		fmt.Println("migrations applied")
	case *down:
		if err := runner.Down(ctx); err != nil {
			fmt.Fprintln(os.Stderr, "migrate down:", err)
			os.Exit(1)
		}
		fmt.Println("migrations reverted")
	}
}