// Package kmsadapter provides a real AWS KMS implementation of the kms.Signer
// interface. It is only imported when KMS_KEY_ID is set and AWS credentials
// are configured; unit tests use kms.Fake.
package kmsadapter

import (
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	kmssigner "github.com/ai-crypto-onramp/audit-logger/internal/kms"
)

// Client wraps an aws-sdk-go-v2 KMS client and implements kms.Signer.
type Client struct {
	svc   *kms.Client
	keyID string
}

// New returns a Client backed by the supplied KMS service client and key id.
func New(svc *kms.Client, keyID string) *Client { return &Client{svc: svc, keyID: keyID} }

// KeyID returns the configured key id.
func (c *Client) KeyID() string { return c.keyID }

// Sign signs a 32-byte SHA-256 digest with the configured KMS key.
func (c *Client) Sign(digest []byte) ([]byte, string, error) {
	if len(digest) != 32 {
		return nil, "", fmt.Errorf("kmsadapter: digest must be 32 bytes, got %d", len(digest))
	}
	out, err := c.svc.Sign(nil, &kms.SignInput{
		KeyId:            aws.String(c.keyID),
		Message:          digest,
		MessageType:      kmstypes.MessageTypeDigest,
		SigningAlgorithm: kmstypes.SigningAlgorithmSpecRsassaPssSha256,
	})
	if err != nil {
		return nil, "", fmt.Errorf("kmsadapter: sign: %w", err)
	}
	if out.Signature == nil {
		return nil, "", errors.New("kmsadapter: empty signature")
	}
	return out.Signature, c.keyID, nil
}

// Verify verifies a KMS-produced signature over digest.
func (c *Client) Verify(digest, signature []byte) (bool, error) {
	out, err := c.svc.Verify(nil, &kms.VerifyInput{
		KeyId:            aws.String(c.keyID),
		Message:          digest,
		MessageType:      kmstypes.MessageTypeDigest,
		Signature:        signature,
		SigningAlgorithm: kmstypes.SigningAlgorithmSpecRsassaPssSha256,
	})
	if err != nil {
		return false, fmt.Errorf("kmsadapter: verify: %w", err)
	}
	return out.KeyId != nil && *out.KeyId == c.keyID && out.SignatureValid, nil
}

// _ guard ensures the interface is satisfied.
var _ kmssigner.Signer = (*Client)(nil)