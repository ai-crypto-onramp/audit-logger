package app

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ai-crypto-onramp/audit-logger/internal/config"
	"github.com/ai-crypto-onramp/audit-logger/internal/kafka"
)

// errConsumer is a kafka.ConsumerGroup whose Run always returns a non-ctx error.
type errConsumer struct{}

func (errConsumer) Run(context.Context, kafka.Handler) error {
	return errors.New("consumer boom")
}
func (errConsumer) Stop() error { return nil }

func TestStartLoopsConsumerErrorLogged(t *testing.T) {
	cfg := WithDefaults(config.Config{ChainAnchorInterval: 0})
	srv, err := Build(cfg)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer func() { _ = srv.Shutdown() }()
	// Replace the consumer with one that errors on Run.
	srv.consumer = errConsumer{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv.startLoops(ctx)
	// Wait briefly for the goroutine to call Run and log.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv.wg.Wait()
	}()
	select {
	case <-time.After(200 * time.Millisecond):
	case <-func() chan struct{} { c := make(chan struct{}); close(c); return c }():
	}
}