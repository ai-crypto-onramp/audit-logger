// Package s3adapter provides a thin real-S3 implementation of the s3.Client
// interface using aws-sdk-go-v2. It is only imported when PAYLOAD_BUCKET is
// set and AWS credentials are configured; unit tests use s3.Fake instead.
package s3adapter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	s3store "github.com/ai-crypto-onramp/audit-logger/internal/s3"
)

// Client wraps an aws-sdk-go-v2 S3 client and implements s3store.Client.
type Client struct {
	svc        *s3.Client
}

// New returns a Client backed by the supplied S3 service client.
func New(svc *s3.Client) *Client { return &Client{svc: svc} }

// Put writes an object. Retention and legal hold are applied via Object Lock
// metadata when configured.
func (c *Client) Put(ctx context.Context, bucket string, opts s3store.PutOptions, body io.Reader) (string, error) {
	buf, err := io.ReadAll(body)
	if err != nil {
		return "", err
	}
	put := &s3.PutObjectInput{
		Bucket:       aws.String(bucket),
		Key:          aws.String(opts.Key),
		Body:         bytes.NewReader(buf),
		StorageClass: s3types.StorageClass(opts.StorageClass),
	}
	if put.StorageClass == "" {
		put.StorageClass = s3types.StorageClassStandard
	}
	if opts.ContentType != "" {
		put.ContentType = aws.String(opts.ContentType)
	}
	if opts.RetentionDays > 0 {
		put.ObjectLockRetainUntilDate = aws.Time(time.Now().UTC().Add(time.Duration(opts.RetentionDays) * 24 * time.Hour))
		put.ObjectLockMode = s3types.ObjectLockModeCompliance
	}
	if opts.LegalHold {
		put.ObjectLockLegalHoldStatus = s3types.ObjectLockLegalHoldStatusOn
	}
	if _, err := c.svc.PutObject(ctx, put); err != nil {
		return "", fmt.Errorf("s3adapter: put %s/%s: %w", bucket, opts.Key, err)
	}
	return opts.Key, nil
}

// Get downloads an object's bytes.
func (c *Client) Get(ctx context.Context, bucket, key string) ([]byte, error) {
	out, err := c.svc.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		var nsk *s3types.NoSuchKey
		if errors.As(err, &nsk) {
			return nil, &s3store.ErrNotFound{Key: key}
		}
		return nil, fmt.Errorf("s3adapter: get %s/%s: %w", bucket, key, err)
	}
	defer out.Body.Close()
	return io.ReadAll(out.Body)
}

// PresignGet returns a time-limited download URL.
func (c *Client) PresignGet(ctx context.Context, bucket, key string, ttl time.Duration) (string, error) {
	presignClient := s3.NewPresignClient(c.svc)
	req, err := presignClient.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}, s3.WithPresignExpires(ttl))
	if err != nil {
		return "", fmt.Errorf("s3adapter: presign: %w", err)
	}
	return req.URL, nil
}

// Head returns object metadata.
func (c *Client) Head(ctx context.Context, bucket, key string) (*s3store.Object, error) {
	out, err := c.svc.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		var nsk *s3types.NotFound
		if errors.As(err, &nsk) {
			return nil, &s3store.ErrNotFound{Key: key}
		}
		return nil, fmt.Errorf("s3adapter: head %s/%s: %w", bucket, key, err)
	}
	o := &s3store.Object{
		Key:          key,
		Bucket:       bucket,
		StorageClass: string(out.StorageClass),
	}
	if out.ContentLength != nil {
		o.Size = *out.ContentLength
	}
	return o, nil
}

// Delete attempts to delete an object. Under Object Lock retention this
// returns an error from S3.
func (c *Client) Delete(ctx context.Context, bucket, key string) error {
	_, err := c.svc.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("s3adapter: delete %s/%s: %w", bucket, key, err)
	}
	return nil
}