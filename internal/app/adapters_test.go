package app

import (
	"os"
	"testing"

	"github.com/ai-crypto-onramp/audit-logger/internal/config"
)

func TestNewS3ClientWithRegion(t *testing.T) {
	os.Setenv("AWS_REGION", "us-east-1")
	os.Setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
	os.Setenv("AWS_SECRET_ACCESS_KEY", "secrettest")
	os.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	defer os.Unsetenv("AWS_REGION")
	defer os.Unsetenv("AWS_ACCESS_KEY_ID")
	defer os.Unsetenv("AWS_SECRET_ACCESS_KEY")
	defer os.Unsetenv("AWS_EC2_METADATA_DISABLED")
	c, err := newS3Client(config.Config{PayloadBucket: "bkt"})
	if err != nil {
		t.Fatalf("newS3Client: %v", err)
	}
	if c == nil {
		t.Fatal("nil client")
	}
}

func TestNewKMSClientWithRegion(t *testing.T) {
	os.Setenv("AWS_REGION", "us-east-1")
	os.Setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
	os.Setenv("AWS_SECRET_ACCESS_KEY", "secrettest")
	os.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	defer os.Unsetenv("AWS_REGION")
	defer os.Unsetenv("AWS_ACCESS_KEY_ID")
	defer os.Unsetenv("AWS_SECRET_ACCESS_KEY")
	defer os.Unsetenv("AWS_EC2_METADATA_DISABLED")
	c, err := newKMSClient("alias/x")
	if err != nil {
		t.Fatalf("newKMSClient: %v", err)
	}
	if c == nil {
		t.Fatal("nil signer")
	}
}

func TestBuildWithAWSRegionUsesRealAdapters(t *testing.T) {
	os.Setenv("AWS_REGION", "us-east-1")
	os.Setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
	os.Setenv("AWS_SECRET_ACCESS_KEY", "secrettest")
	os.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	defer os.Unsetenv("AWS_REGION")
	defer os.Unsetenv("AWS_ACCESS_KEY_ID")
	defer os.Unsetenv("AWS_SECRET_ACCESS_KEY")
	defer os.Unsetenv("AWS_EC2_METADATA_DISABLED")
	cfg := WithDefaults(config.Config{
		PayloadBucket: "audit-bucket",
		KMSKeyID:      "alias/test",
	})
	srv, err := Build(cfg)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer func() { _ = srv.Shutdown() }()
	if srv.signer == nil {
		t.Fatal("nil signer")
	}
}
