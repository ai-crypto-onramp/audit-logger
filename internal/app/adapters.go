// Package app — adapter factories. These functions construct real Postgres
// / S3 / KMS / Kafka adapters from config; they are only invoked when the
// relevant env vars are set. On any init error they fall back to in-memory
// fakes so the binary still boots (mirroring the sibling services).
package app

import (
	"context"
	"log"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/ai-crypto-onramp/audit-logger/internal/config"
	"github.com/ai-crypto-onramp/audit-logger/internal/kafka"
	"github.com/ai-crypto-onramp/audit-logger/internal/kafka/kafkaadapter"
	"github.com/ai-crypto-onramp/audit-logger/internal/kms"
	"github.com/ai-crypto-onramp/audit-logger/internal/kms/kmsadapter"
	"github.com/ai-crypto-onramp/audit-logger/internal/s3"
	"github.com/ai-crypto-onramp/audit-logger/internal/s3/s3adapter"
	"github.com/ai-crypto-onramp/audit-logger/internal/store"
	"github.com/ai-crypto-onramp/audit-logger/internal/store/memstore"
	"github.com/ai-crypto-onramp/audit-logger/internal/store/postgres"
)

// openPostgresOrFallback opens a Postgres-backed store.All bundle. On error
// it logs and falls back to in-memory stores so the binary still boots.
func openPostgresOrFallback(ctx context.Context, dsn string) store.All {
	db, err := postgres.Open(ctx, dsn)
	if err != nil {
		log.Printf("app: postgres open failed (%v), using in-memory stores", err)
		mem := memstore.NewAll()
		return store.All{Events: mem.Events, Anchors: mem.Anchors, Exports: mem.Exports, DeadLetters: mem.DeadLetters}
	}
	return db.All()
}

// newS3Client returns a real S3 client backed by aws-sdk-go-v2.
func newS3Client(cfg config.Config) (s3.Client, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, err
	}
	svc := awss3.NewFromConfig(awsCfg)
	return s3adapter.New(svc), nil
}

// newKMSClient returns a real KMS signer backed by aws-sdk-go-v2.
func newKMSClient(keyID string) (kms.Signer, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, err
	}
	svc := awskms.NewFromConfig(awsCfg)
	return kmsadapter.New(svc, keyID), nil
}

// newKafkaConsumer returns a real Kafka consumer group.
func newKafkaConsumer(cfg config.Config) (kafka.ConsumerGroup, error) {
	return kafkaadapter.New(cfg.KafkaBrokers, cfg.KafkaTopic, cfg.KafkaConsumerGroup)
}