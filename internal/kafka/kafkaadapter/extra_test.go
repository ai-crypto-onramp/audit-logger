package kafkaadapter

import (
	"errors"
	"testing"

	"github.com/ai-crypto-onramp/audit-logger/internal/kafka"
)

func TestNewBrokersEmpty(t *testing.T) {
	if _, err := New(nil, "topic", "group"); err == nil {
		t.Fatal("expected error for empty brokers")
	}
	if _, err := New([]string{}, "topic", "group"); err == nil {
		t.Fatal("expected error for empty brokers slice")
	}
}

func TestNewTopicEmpty(t *testing.T) {
	if _, err := New([]string{"b:9092"}, "", "group"); err == nil {
		t.Fatal("expected error for empty topic")
	}
}

func TestNewDefaultGroupID(t *testing.T) {
	c, err := New([]string{"b:9092"}, "topic", "")
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if c == nil {
		t.Fatal("nil consumer")
	}
}

func TestNewReturnsErrInvalid(t *testing.T) {
	_, err := New(nil, "topic", "group")
	var invalid *kafka.ErrInvalid
	if !errors.As(err, &invalid) {
		t.Fatalf("expected *kafka.ErrInvalid, got %T", err)
	}
}