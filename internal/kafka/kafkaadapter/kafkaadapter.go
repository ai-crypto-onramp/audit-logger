// Package kafkaadapter provides a real Kafka consumer-group implementation
// of the kafka.ConsumerGroup interface using github.com/segmentio/kafka-go.
// It is only imported when KAFKA_BROKERS is set; unit tests use kafka.Fake.
package kafkaadapter

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/segmentio/kafka-go"

	kafkac "github.com/ai-crypto-onramp/audit-logger/internal/kafka"
)

// Consumer wraps a kafka-go Reader and implements kafkac.ConsumerGroup.
type Consumer struct {
	r       *kafka.Reader
	stopped bool
}

// New returns a Consumer backed by a kafka-go Reader configured for the
// given group id.
func New(brokers []string, topic, groupID string) (*Consumer, error) {
	if len(brokers) == 0 {
		return nil, &kafkac.ErrInvalid{Reason: "brokers empty"}
	}
	if topic == "" {
		return nil, &kafkac.ErrInvalid{Reason: "topic empty"}
	}
	if groupID == "" {
		groupID = "audit-event-log"
	}
	r := kafka.NewReader(kafka.ReaderConfig{
		Brokers:  brokers,
		Topic:    topic,
		GroupID:  groupID,
		MinBytes: 1,
		MaxBytes: 10e6,
	})
	return &Consumer{r: r}, nil
}

// Run drains messages from the broker and calls handler. On success it
// commits the offset (kafka-go group consumers commit offsets on read).
func (c *Consumer) Run(ctx context.Context, handler kafkac.Handler) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		m, err := c.r.ReadMessage(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return fmt.Errorf("kafkaadapter: read: %w", err)
		}
		headers := map[string]string{}
		for _, h := range m.Headers {
			headers[h.Key] = string(h.Value)
		}
		msg := kafkac.Message{
			Topic:     m.Topic,
			Partition: m.Partition,
			Offset:    m.Offset,
			Key:       m.Key,
			Value:     m.Value,
			Headers:   headers,
		}
		if err := handler(ctx, msg); err != nil {
			log.Printf("kafkaadapter: handler error (offset=%d): %v", m.Offset, err)
			// At-least-once: do not commit; the broker will redeliver.
			continue
		}
		if err := c.r.CommitMessages(ctx, m); err != nil {
			log.Printf("kafkaadapter: commit (offset=%d): %v", m.Offset, err)
		}
	}
}

// Stop closes the underlying reader.
func (c *Consumer) Stop() error {
	if c.stopped {
		return nil
	}
	c.stopped = true
	return c.r.Close()
}