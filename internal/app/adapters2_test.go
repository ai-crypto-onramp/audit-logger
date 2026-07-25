package app

import (
	"testing"

	"github.com/ai-crypto-onramp/audit-logger/internal/config"
)

// withAWSProfileNonexistent sets AWS env so that
// awsconfig.LoadDefaultConfig fails (profile not found), while keeping
// AWS_REGION set so the Build path attempts to construct a real adapter.
func withAWSProfileNonexistent(t *testing.T) {
	t.Helper()
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_PROFILE", "nonexistent-profile-xyz-for-tests")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
}

func TestBuildS3ClientInitFailsFallsBack(t *testing.T) {
	withAWSProfileNonexistent(t)
	cfg := WithDefaults(config.Config{PayloadBucket: "audit-bucket"})
	srv, err := Build(cfg)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer func() { _ = srv.Shutdown() }()
	// Should fall back to the in-memory fake; no panic.
}

func TestBuildKMSClientInitFailsFallsBack(t *testing.T) {
	withAWSProfileNonexistent(t)
	cfg := WithDefaults(config.Config{KMSKeyID: "alias/x"})
	srv, err := Build(cfg)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer func() { _ = srv.Shutdown() }()
	if srv.signer == nil {
		t.Fatal("nil signer")
	}
}

func TestNewS3ClientLoadConfigError(t *testing.T) {
	withAWSProfileNonexistent(t)
	if _, err := newS3Client(config.Config{PayloadBucket: "bkt"}); err == nil {
		t.Fatal("expected LoadDefaultConfig error")
	}
}

func TestNewKMSClientLoadConfigError(t *testing.T) {
	withAWSProfileNonexistent(t)
	if _, err := newKMSClient("alias/x"); err == nil {
		t.Fatal("expected LoadDefaultConfig error")
	}
}