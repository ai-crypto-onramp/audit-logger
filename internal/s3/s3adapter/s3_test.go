package s3adapter

import (
	"bytes"
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"

	s3store "github.com/ai-crypto-onramp/audit-logger/internal/s3"
)

// fakeS3Server is a minimal S3-like HTTP server for unit-testing the
// s3adapter without a real AWS account. It implements just enough of the
// S3 REST API (PutObject, GetObject, HeadObject, DeleteObject) for the
// adapter's methods.
type fakeS3Server struct {
	*httptest.Server
	mu       map[string][]byte
	content  map[string]string
}

type s3ErrorXML struct {
	XMLName xml.Name `xml:"Error"`
	Code    string   `xml:"Code"`
	Message string   `xml:"Message"`
}

func newFakeS3Server() *fakeS3Server {
	f := &fakeS3Server{
		mu:      map[string][]byte{},
		content: map[string]string{},
	}
	f.Server = httptest.NewServer(http.HandlerFunc(f.handle))
	return f
}

func (f *fakeS3Server) key(r *http.Request) string {
	return r.Host + r.URL.Path
}

func (f *fakeS3Server) writeError(w http.ResponseWriter, code int, s3Code string) {
	w.WriteHeader(code)
	b, _ := xml.Marshal(s3ErrorXML{Code: s3Code, Message: s3Code})
	_, _ = w.Write(b)
}

func (f *fakeS3Server) handle(w http.ResponseWriter, r *http.Request) {
	k := f.key(r)
	switch r.Method {
	case http.MethodPut:
		if _, ok := f.mu[k]; ok {
			// Mimic Object Lock retention block.
			f.writeError(w, http.StatusLocked, "ObjectLockRetention")
			return
		}
		b, _ := io.ReadAll(r.Body)
		f.mu[k] = b
		f.content[k] = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	case http.MethodGet:
		b, ok := f.mu[k]
		if !ok {
			f.writeError(w, http.StatusNotFound, "NoSuchKey")
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(b)))
		w.Header().Set("Content-Type", f.content[k])
		w.Header().Set("X-Amz-Storage-Class", "STANDARD")
		_, _ = w.Write(b)
	case http.MethodHead:
		b, ok := f.mu[k]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(b)))
		w.Header().Set("X-Amz-Storage-Class", "STANDARD")
		w.WriteHeader(http.StatusOK)
	case http.MethodDelete:
		if _, ok := f.mu[k]; !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		delete(f.mu, k)
		delete(f.content, k)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func newAdapter(t *testing.T, serverURL string) *Client {
	t.Helper()
	svc := awss3.NewFromConfig(aws.Config{Region: "us-east-1"}, func(o *awss3.Options) {
		o.BaseEndpoint = aws.String(serverURL)
		o.UsePathStyle = true
		o.Credentials = aws.AnonymousCredentials{}
	})
	return New(svc)
}

func TestPutAndGet(t *testing.T) {
	srv := newFakeS3Server()
	defer srv.Close()
	c := newAdapter(t, srv.URL)
	ctx := context.Background()
	body := []byte("hello world")
	key, err := c.Put(ctx, "bkt", s3store.PutOptions{Key: "obj1", ContentType: "text/plain"}, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if key != "obj1" {
		t.Errorf("key: %q", key)
	}
	got, err := c.Get(ctx, "bkt", "obj1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("body: %q", got)
	}
}

func TestPutDefaultStorageClass(t *testing.T) {
	srv := newFakeS3Server()
	defer srv.Close()
	c := newAdapter(t, srv.URL)
	if _, err := c.Put(context.Background(), "bkt", s3store.PutOptions{Key: "k"}, bytes.NewReader([]byte("x"))); err != nil {
		t.Fatalf("put: %v", err)
	}
}

func TestPutWithRetentionAndLegalHold(t *testing.T) {
	srv := newFakeS3Server()
	defer srv.Close()
	c := newAdapter(t, srv.URL)
	if _, err := c.Put(context.Background(), "bkt", s3store.PutOptions{Key: "k", RetentionDays: 10, LegalHold: true}, bytes.NewReader([]byte("x"))); err != nil {
		t.Fatalf("put: %v", err)
	}
}

func TestGetNotFound(t *testing.T) {
	srv := newFakeS3Server()
	defer srv.Close()
	c := newAdapter(t, srv.URL)
	if _, err := c.Get(context.Background(), "bkt", "nope"); err == nil {
		t.Fatal("expected not found")
	}
}

func TestGetError(t *testing.T) {
	// Point the client at a dead URL to force a transport error.
	svc := awss3.NewFromConfig(aws.Config{Region: "us-east-1"}, func(o *awss3.Options) {
		o.BaseEndpoint = aws.String("http://127.0.0.1:0")
		o.UsePathStyle = true
		o.Credentials = aws.AnonymousCredentials{}
	})
	deadClient := New(svc)
	if _, err := deadClient.Get(context.Background(), "bkt", "k"); err == nil {
		t.Fatal("expected transport error")
	}
}

func TestPutError(t *testing.T) {
	// Point the client at a dead URL to force a transport error.
	svc := awss3.NewFromConfig(aws.Config{Region: "us-east-1"}, func(o *awss3.Options) {
		o.BaseEndpoint = aws.String("http://127.0.0.1:0")
		o.UsePathStyle = true
		o.Credentials = aws.AnonymousCredentials{}
	})
	deadClient := New(svc)
	if _, err := deadClient.Put(context.Background(), "bkt", s3store.PutOptions{Key: "k"}, bytes.NewReader([]byte("x"))); err == nil {
		t.Fatal("expected transport error")
	}
}

func TestHead(t *testing.T) {
	srv := newFakeS3Server()
	defer srv.Close()
	c := newAdapter(t, srv.URL)
	ctx := context.Background()
	if _, err := c.Put(ctx, "bkt", s3store.PutOptions{Key: "obj", ContentType: "text/plain"}, bytes.NewReader([]byte("data"))); err != nil {
		t.Fatalf("put: %v", err)
	}
	obj, err := c.Head(ctx, "bkt", "obj")
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	if obj.Key != "obj" || obj.Size != 4 {
		t.Errorf("obj: %+v", obj)
	}
}

func TestHeadNotFound(t *testing.T) {
	srv := newFakeS3Server()
	defer srv.Close()
	c := newAdapter(t, srv.URL)
	if _, err := c.Head(context.Background(), "bkt", "nope"); err == nil {
		t.Fatal("expected not found")
	}
}

func TestHeadError(t *testing.T) {
	svc := awss3.NewFromConfig(aws.Config{Region: "us-east-1"}, func(o *awss3.Options) {
		o.BaseEndpoint = aws.String("http://127.0.0.1:0")
		o.UsePathStyle = true
		o.Credentials = aws.AnonymousCredentials{}
	})
	deadClient := New(svc)
	if _, err := deadClient.Head(context.Background(), "bkt", "k"); err == nil {
		t.Fatal("expected transport error")
	}
}

func TestDelete(t *testing.T) {
	srv := newFakeS3Server()
	defer srv.Close()
	c := newAdapter(t, srv.URL)
	ctx := context.Background()
	_, _ = c.Put(ctx, "bkt", s3store.PutOptions{Key: "obj"}, bytes.NewReader([]byte("x")))
	if err := c.Delete(ctx, "bkt", "obj"); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

func TestDeleteError(t *testing.T) {
	svc := awss3.NewFromConfig(aws.Config{Region: "us-east-1"}, func(o *awss3.Options) {
		o.BaseEndpoint = aws.String("http://127.0.0.1:0")
		o.UsePathStyle = true
		o.Credentials = aws.AnonymousCredentials{}
	})
	deadClient := New(svc)
	if err := deadClient.Delete(context.Background(), "bkt", "k"); err == nil {
		t.Fatal("expected transport error")
	}
}

func TestPresignGet(t *testing.T) {
	srv := newFakeS3Server()
	defer srv.Close()
	svc := awss3.NewFromConfig(aws.Config{Region: "us-east-1", Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "AKIA", SecretAccessKey: "secret", Source: "test"}, nil
	})}, func(o *awss3.Options) {
		o.BaseEndpoint = aws.String(srv.URL)
		o.UsePathStyle = true
	})
	c := New(svc)
	ctx := context.Background()
	_, _ = c.Put(ctx, "bkt", s3store.PutOptions{Key: "obj"}, bytes.NewReader([]byte("x")))
	url, err := c.PresignGet(ctx, "bkt", "obj", 5*time.Minute)
	if err != nil {
		t.Fatalf("presign: %v", err)
	}
	if url == "" {
		t.Fatal("empty presigned url")
	}
}

func TestPresignGetError(t *testing.T) {
	svc := awss3.NewFromConfig(aws.Config{Region: "us-east-1"}, func(o *awss3.Options) {
		o.BaseEndpoint = aws.String("http://127.0.0.1:0")
		o.UsePathStyle = true
		o.Credentials = aws.AnonymousCredentials{}
	})
	deadClient := New(svc)
	if _, err := deadClient.PresignGet(context.Background(), "bkt", "k", time.Minute); err == nil {
		t.Fatal("expected presign error")
	}
}