// Package app is the composition root for the Audit Event Log service. It
// loads config, opens stores (in-memory by default, Postgres when DB_URL
// is set), constructs the ingest pipeline / chain anchor job / export
// runner / REST handlers, and starts the HTTP server plus the Kafka
// consumer and the anchor background loop.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/ai-crypto-onramp/audit-logger/internal/api"
	"github.com/ai-crypto-onramp/audit-logger/internal/chain"
	"github.com/ai-crypto-onramp/audit-logger/internal/config"
	"github.com/ai-crypto-onramp/audit-logger/internal/export"
	"github.com/ai-crypto-onramp/audit-logger/internal/ingest"
	"github.com/ai-crypto-onramp/audit-logger/internal/kafka"
	"github.com/ai-crypto-onramp/audit-logger/internal/kms"
	"github.com/ai-crypto-onramp/audit-logger/internal/metrics"
	"github.com/ai-crypto-onramp/audit-logger/internal/redaction"
	"github.com/ai-crypto-onramp/audit-logger/internal/s3"
	"github.com/ai-crypto-onramp/audit-logger/internal/store"
	"github.com/ai-crypto-onramp/audit-logger/internal/store/memstore"
)

// Server bundles the wired service.
type Server struct {
	cfg         config.Config
	http        *http.Server
	handler     http.Handler
	anchor      *chain.AnchorJob
	signer      kms.Signer
	redactor    *redaction.Reloader
	stores      store.All
	consumer    kafka.ConsumerGroup
	pipeline    *ingest.Pipeline
	cancel      context.CancelFunc
	wg          sync.WaitGroup
}

// Build constructs the server from config. When DB_URL is empty it uses
// in-memory stores; when set it opens Postgres and runs migrations. The
// Kafka consumer, S3 payload store, and KMS signer default to in-memory
// fakes only when DEV_MODE=1 (or running under a test binary); in
// production missing creds are fatal.
func Build(cfg config.Config) (*Server, error) {
	// Register Prometheus collectors (idempotent).
	metrics.Register(nil)

	devMode := os.Getenv("DEV_MODE") == "1" || testing.Testing()
	if devMode {
		log.Printf("DEV_MODE=1: stub/fake clients in use — NOT FOR PRODUCTION")
	}

	// Stores: Postgres if DB_URL, else in-memory.
	var all store.All
	if cfg.DBURL != "" {
		// Postgres adapter is in internal/store/postgres; imported lazily
		// via the build tag-free path. We attempt to open it here; if the
		// import fails (e.g. driver missing) we fall back to in-memory.
		all = openPostgresOrFallback(context.Background(), cfg.DBURL)
	} else {
		mem := memstore.NewAll()
		all = store.All{Events: mem.Events, Anchors: mem.Anchors, Exports: mem.Exports, DeadLetters: mem.DeadLetters}
	}

	// S3 payload store: real adapter if PAYLOAD_BUCKET+AWS configured; in
	// DEV_MODE fall back to fake with a warning, otherwise fatal.
	payloadStore, err := buildS3(cfg, devMode)
	if err != nil {
		return nil, err
	}

	// KMS signer: real adapter if KMS_KEY_ID+AWS configured; in DEV_MODE
	// fall back to fake with a warning, otherwise fatal.
	signer, err := buildKMS(cfg, devMode)
	if err != nil {
		return nil, err
	}

	// Redaction policy.
	redactor, err := redaction.NewReloader(cfg.RedactionPolicyPath)
	if err != nil {
		return nil, err
	}

	// Ingest pipeline.
	pipeline := ingest.New(ingest.Deps{
		Events:           all.Events,
		Payloads:          &ingest.PutAdapter{Client: payloadStore},
		PayloadBucket:     cfg.PayloadBucket,
		StorageClass:      cfg.PayloadStorageClass,
		RetentionDays:     cfg.RetentionDays,
		LegalHoldDefault:  cfg.LegalHoldDefault,
		Redactor:          redactor,
		DeadLetters:       all.DeadLetters,
		Topic:             cfg.KafkaTopic,
	})

	// Anchor job.
	anchor := &chain.AnchorJob{
		Events:   all.Events,
		Anchors:  all.Anchors,
		Signer:   signer.Sign,
		NotaryURL: cfg.ExternalNotaryURL,
	}

	// Export runner.
	_ = export.New(export.Deps{
		Events:              all.Events,
		Anchors:             all.Anchors,
		Jobs:                all.Exports,
		Payloads:            &exportPutAdapter{client: payloadStore},
		PayloadBucket:       cfg.PayloadBucket,
		Signer:              signer,
		DefaultRetentionDays: cfg.RetentionDays,
	})

	// Kafka consumer: real adapter if KAFKA_BROKERS set; in DEV_MODE fall
	// back to fake with a warning, otherwise fatal.
	consumer, err := buildKafka(cfg, devMode)
	if err != nil {
		return nil, err
	}

	// Verifier backed by chain.Sweep.
	verifier := &sweepVerifier{events: all.Events, anchors: all.Anchors, signer: signer.Sign}

	// REST router.
	d := &api.Deps{
		Events:          all.Events,
		Anchors:         all.Anchors,
		Exports:         all.Exports,
		DeadLetters:     all.DeadLetters,
		Payloads:        payloadStore,
		PayloadBucket:   cfg.PayloadBucket,
		LegalHold:        all.Events,
		Verifier:        verifier,
		RedactorReload:  redactor.Reload,
	}
	router := api.NewRouter(d)

	wrapped := otelhttp.NewHandler(router, "audit-event-log")
	srv := &Server{
		cfg:      cfg,
		handler:  wrapped,
		anchor:   anchor,
		signer:   signer,
		redactor: redactor,
		stores:   all,
		consumer: consumer,
		pipeline: pipeline,
		http: &http.Server{
			Addr:              ":" + cfg.Port,
			Handler:           wrapped,
			ReadHeaderTimeout: 5 * time.Second,
		},
	}
	return srv, nil
}

// Run starts the HTTP server, the Kafka consumer loop, and the anchor
// background loop. It blocks until SIGINT/SIGTERM.
func (s *Server) Run() error {
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.startLoops(ctx)
	log.Printf("audit-event-log listening on :%s", s.cfg.Port)
	errCh := make(chan error, 1)
	go func() { errCh <- s.http.ListenAndServe() }()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-errCh:
		return err
	case <-sig:
		return s.Shutdown()
	}
}

func (s *Server) startLoops(ctx context.Context) {
	// Kafka consumer loop.
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		handler := func(ctx context.Context, msg kafka.Message) error {
			_ = s.pipeline.IngestMessage(ctx, ingest.IngestMessage_{
				Topic:     msg.Topic,
				Partition: msg.Partition,
				Offset:    msg.Offset,
				Key:       msg.Key,
				Value:     msg.Value,
			})
			return nil
		}
		if err := s.consumer.Run(ctx, handler); err != nil && ctx.Err() == nil {
			log.Printf("consumer: %v", err)
		}
	}()

	// Anchor loop.
	if s.cfg.ChainAnchorInterval > 0 {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			t := time.NewTicker(s.cfg.ChainAnchorInterval)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					if _, err := s.anchor.Run(ctx); err != nil && err != chain.ErrEmptyChain {
						log.Printf("anchor: %v", err)
					}
				}
			}
		}()
	}
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown() error {
	if s.cancel != nil {
		s.cancel()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var err error
	if s.http != nil {
		err = s.http.Shutdown(ctx)
	}
	s.wg.Wait()
	return err
}

// HTTPHandler returns the wired HTTP handler (test helper).
func (s *Server) HTTPHandler() http.Handler { return s.handler }

// Pipeline returns the ingest pipeline (test helper).
func (s *Server) Pipeline() *ingest.Pipeline { return s.pipeline }

// Consumer returns the Kafka consumer (test helper).
func (s *Server) Consumer() kafka.ConsumerGroup { return s.consumer }

// Anchor returns the anchor job (test helper).
func (s *Server) Anchor() *chain.AnchorJob { return s.anchor }

// Redactor returns the redaction reloader (test helper).
func (s *Server) Redactor() *redaction.Reloader { return s.redactor }

// Stores returns the wired store.All bundle (test helper).
func (s *Server) Stores() store.All { return s.stores }

// sweepVerifier implements api.Verifier.
type sweepVerifier struct {
	events  store.EventStore
	anchors store.AnchorStore
	signer  func([]byte) ([]byte, string, error)
}

func (v *sweepVerifier) VerifyWindow(ctx context.Context, from, to time.Time) (chain.Report, error) {
	r, err := chain.Sweep(ctx, v.events, v.anchors, from, to, v.signer)
	if err != nil {
		return chain.Report{}, err
	}
	return *r, nil
}

// exportPutAdapter adapts s3.Client to the export.PayloadStore interface
// (io.Reader-based).
type exportPutAdapter struct {
	client s3.Client
}

func (a *exportPutAdapter) Put(ctx context.Context, bucket string, opts s3.PutOptions, body io.Reader) (string, error) {
	return a.client.Put(ctx, bucket, opts, body)
}

// _ guard
var _ = promhttp.Handler

// buildS3 wires the S3 payload store. When PAYLOAD_BUCKET and AWS_REGION
// are set it constructs the real adapter. In DEV_MODE any missing cred or
// init error falls back to the fake with a warning; in prod it is fatal.
func buildS3(cfg config.Config, devMode bool) (s3.Client, error) {
	if cfg.PayloadBucket != "" && os.Getenv("AWS_REGION") != "" {
		ps, err := newS3Client(cfg)
		if err != nil {
			if devMode {
				log.Printf("app: s3 client init failed, using fake (DEV_MODE): %v", err)
				return s3.NewFake(), nil
			}
			return nil, fmt.Errorf("S3 client init failed and DEV_MODE!=1; refusing to start in production mode: %w", err)
		}
		return ps, nil
	}
	if devMode {
		log.Printf("app: PAYLOAD_BUCKET or AWS_REGION unset and DEV_MODE=1; using fake S3 payload store (NOT FOR PRODUCTION)")
		return s3.NewFake(), nil
	}
	return nil, errors.New("PAYLOAD_BUCKET/AWS_REGION unset and DEV_MODE!=1; refusing to start in production mode")
}

// buildKMS wires the KMS signer. When KMS_KEY_ID and AWS_REGION are set it
// constructs the real adapter. In DEV_MODE any missing cred or init error
// falls back to the fake with a warning; in prod it is fatal.
func buildKMS(cfg config.Config, devMode bool) (kms.Signer, error) {
	if cfg.KMSKeyID != "" && os.Getenv("AWS_REGION") != "" {
		s, err := newKMSClient(cfg.KMSKeyID)
		if err != nil {
			if devMode {
				log.Printf("app: kms client init failed, using fake (DEV_MODE): %v", err)
				return kms.NewFake(cfg.KMSKeyID), nil
			}
			return nil, fmt.Errorf("KMS client init failed and DEV_MODE!=1; refusing to start in production mode: %w", err)
		}
		return s, nil
	}
	if devMode {
		log.Printf("app: KMS_KEY_ID or AWS_REGION unset and DEV_MODE=1; using fake KMS signer (NOT FOR PRODUCTION)")
		return kms.NewFake(cfg.KMSKeyID), nil
	}
	return nil, errors.New("KMS_KEY_ID/AWS_REGION unset and DEV_MODE!=1; refusing to start in production mode")
}

// buildKafka wires the Kafka consumer group. When KAFKA_BROKERS is set it
// constructs the real adapter. In DEV_MODE any missing cred or init error
// falls back to the fake with a warning; in prod it is fatal.
func buildKafka(cfg config.Config, devMode bool) (kafka.ConsumerGroup, error) {
	if len(cfg.KafkaBrokers) > 0 {
		c, err := newKafkaConsumer(cfg)
		if err != nil {
			if devMode {
				log.Printf("app: kafka consumer init failed, using fake (DEV_MODE): %v", err)
				return kafka.NewFake(256), nil
			}
			return nil, fmt.Errorf("kafka consumer init failed and DEV_MODE!=1; refusing to start in production mode: %w", err)
		}
		return c, nil
	}
	if devMode {
		log.Printf("app: KAFKA_BROKERS unset and DEV_MODE=1; using fake kafka consumer (NOT FOR PRODUCTION)")
		return kafka.NewFake(256), nil
	}
	return nil, errors.New("KAFKA_BROKERS unset and DEV_MODE!=1; refusing to start in production mode")
}