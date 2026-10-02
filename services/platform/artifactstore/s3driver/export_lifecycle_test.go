package s3driver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
)

type cleanupHTTP struct {
	mode    string
	methods []string
	t       *testing.T
}

func (h *cleanupHTTP) RoundTrip(r *http.Request) (*http.Response, error) {
	h.methods = append(h.methods, r.Method)
	if r.URL.Query().Get("versionId") != "version-1" || r.Header.Get("X-Amz-Expected-Bucket-Owner") != "123456789012" {
		h.t.Fatal("cleanup escaped exact version/owner")
	}
	status := 404
	body := ""
	header := http.Header{}
	if r.Method == "DELETE" {
		if h.mode == "lost_delete" {
			return nil, errors.New("response lost")
		}
		status = 204
		header.Set("X-Amz-Version-Id", "version-1")
	}
	if r.Method == "GET" {
		if r.Header.Get("Range") != "bytes=0-0" {
			h.t.Fatal("absence read unbounded")
		}
		if h.mode == "deleted" || h.mode == "lost_delete" {
			body = `<Error><Code>NoSuchVersion</Code><Message>Missing exact version</Message></Error>`
		} else if h.mode == "denied" {
			status = 403
			body = `<Error><Code>AccessDenied</Code></Error>`
		}
	}
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
}
func TestExportCleanupSDKExactVersionAbsence(t *testing.T) {
	for _, mode := range []string{"deleted", "lost_delete", "ambiguous404", "denied"} {
		t.Run(mode, func(t *testing.T) {
			transport := &cleanupHTTP{mode: mode, t: t}
			client := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String("https://cleanup.invalid"), UsePathStyle: true, Credentials: aws.AnonymousCredentials{}, HTTPClient: &http.Client{Transport: transport}})
			c, err := NewExportCleanup(client, validConfig())
			if err != nil {
				t.Fatal(err)
			}
			object := fixtureObject(t)
			object.Key = exportFixtureKey
			object.VersionID = "version-1"
			err = c.DeleteExact(context.Background(), object.DriverLocator)
			if (err == nil) != (mode == "deleted" || mode == "lost_delete") {
				t.Fatalf("mode=%s err=%v requests=%v", mode, err, transport.methods)
			}
			if len(transport.methods) != 2 || transport.methods[0] != "DELETE" || transport.methods[1] != "GET" {
				t.Fatalf("absence did not use exact GET, or retried: %v", transport.methods)
			}
		})
	}
}

func TestExportReadOnlyReconciliation(t *testing.T) {
	transport := &exportSDKTransport{t: t, losePut: true}
	client := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String("https://export.invalid"), UsePathStyle: true, Credentials: aws.AnonymousCredentials{}, HTTPClient: &http.Client{Transport: transport}})
	d, _ := NewExport(client, validConfig())
	store, _ := artifactstore.NewExport(d, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 1024})
	object := fixtureObject(t)
	object.Key = exportFixtureKey
	if _, err := store.Put(context.Background(), artifactstore.PutRequest{Locator: artifactstore.Locator{Scope: object.Scope, Reference: object.Reference}, MediaType: object.MediaType, Body: object.Body}); err != nil {
		t.Fatal(err)
	}
	verifier, err := NewExportVerifier(client, validConfig())
	if err != nil {
		t.Fatal(err)
	}
	before := transport.puts
	got, err := verifier.Verify(context.Background(), object)
	if err != nil || got.VersionID != "version-1" || transport.puts != before {
		t.Fatalf("read-only receipt failed: %+v %v puts=%d", got, err, transport.puts)
	}
	object.Body = []byte("different")
	object.Size = int64(len(object.Body))
	object.SHA256 = sha256.Sum256(object.Body)
	if _, err = verifier.Verify(context.Background(), object); err == nil || transport.puts != before {
		t.Fatal("changed intent accepted or verifier wrote")
	}
}

type reconcileFaultHTTP struct {
	base  *exportSDKTransport
	fault string
}

func (h *reconcileFaultHTTP) RoundTrip(r *http.Request) (*http.Response, error) {
	if h.fault == "timeout" {
		<-r.Context().Done()
		return nil, r.Context().Err()
	}
	if h.fault == "owner_denied" || h.fault == "missing" {
		code := 403
		if h.fault == "missing" {
			code = 404
		}
		return &http.Response{StatusCode: code, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	}
	response, err := h.base.RoundTrip(r)
	if err != nil {
		return response, err
	}
	if r.Method == "GET" {
		switch h.fault {
		case "wrong_version":
			response.Header.Set("X-Amz-Version-Id", "foreign-version")
		case "wrong_kms":
			response.Header.Set("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id", "arn:aws:kms:us-east-1:123456789012:key/22222222-2222-4222-8222-222222222222")
		case "wrong_checksum":
			response.Header.Set("X-Amz-Checksum-Sha256", base64.StdEncoding.EncodeToString(make([]byte, 32)))
		case "wrong_scope":
			response.Header.Set("X-Amz-Meta-Organization_id", "pid_00000000-0000-4000-8000-000000000099")
		}
	}
	return response, nil
}
func TestExportReadOnlyReconciliationSDKFaults(t *testing.T) {
	for _, fault := range []string{"wrong_version", "wrong_kms", "wrong_checksum", "wrong_scope", "owner_denied", "missing", "timeout", "different_bytes"} {
		t.Run(fault, func(t *testing.T) {
			base := &exportSDKTransport{t: t}
			httpBoundary := &reconcileFaultHTTP{base: base}
			client := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String("https://export.invalid"), UsePathStyle: true, Credentials: aws.AnonymousCredentials{}, HTTPClient: &http.Client{Transport: httpBoundary}})
			driver, _ := NewExport(client, validConfig())
			store, _ := artifactstore.NewExport(driver, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 1024})
			object := fixtureObject(t)
			object.Key = exportFixtureKey
			if _, err := store.Put(context.Background(), artifactstore.PutRequest{Locator: artifactstore.Locator{Scope: object.Scope, Reference: object.Reference}, MediaType: object.MediaType, Body: object.Body}); err != nil {
				t.Fatal(err)
			}
			verifier, _ := NewExportVerifier(client, validConfig())
			httpBoundary.fault = fault
			if fault == "different_bytes" {
				object.Body = []byte("same intent key, different bytes")
				object.Size = int64(len(object.Body))
				object.SHA256 = sha256.Sum256(object.Body)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			if _, err := verifier.Verify(ctx, object); err == nil {
				t.Fatal("unverified immutable receipt accepted")
			}
			if base.puts != 1 || base.writes != 1 {
				t.Fatal("reconciler issued write")
			}
		})
	}
}

type exactCleanupAPI struct {
	calls                  int
	denied, locked, absent bool
	version, owner         string
}

func (f *exactCleanupAPI) DeleteObject(ctx context.Context, in *s3.DeleteObjectInput, options ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	f.calls++
	f.version = aws.ToString(in.VersionId)
	f.owner = aws.ToString(in.ExpectedBucketOwner)
	var opts s3.Options
	for _, o := range options {
		o(&opts)
	}
	if opts.Retryer == nil || opts.Retryer.MaxAttempts() != 1 {
		return nil, errors.New("unbounded retries")
	}
	if f.denied {
		return nil, errors.New("denied")
	}
	if !f.locked {
		f.absent = true
	}
	return &s3.DeleteObjectOutput{VersionId: in.VersionId}, nil
}
func (f *exactCleanupAPI) GetObject(ctx context.Context, in *s3.GetObjectInput, options ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	if aws.ToString(in.VersionId) != f.version || aws.ToString(in.ExpectedBucketOwner) != f.owner {
		return nil, errors.New("wrong pin")
	}
	if f.absent {
		return nil, &smithy.GenericAPIError{Code: "NoSuchVersion", Message: "gone"}
	}
	return &s3.GetObjectOutput{VersionId: in.VersionId}, nil
}
func TestExportCleanupRequiresVerifiedExactVersionAbsence(t *testing.T) {
	for _, mode := range []string{"deleted", "denied", "locked", "missing_version"} {
		t.Run(mode, func(t *testing.T) {
			api := &exactCleanupAPI{denied: mode == "denied", locked: mode == "locked"}
			c, err := NewExportCleanup(api, validConfig())
			if err != nil {
				t.Fatal(err)
			}
			object := fixtureObject(t)
			object.Key = exportFixtureKey
			object.VersionID = "version-1"
			if mode == "missing_version" {
				object.VersionID = ""
			}
			err = c.DeleteExact(context.Background(), object.DriverLocator)
			if (err == nil) != (mode == "deleted") {
				t.Fatalf("mode=%s error=%v", mode, err)
			}
			if mode == "missing_version" && api.calls != 0 {
				t.Fatal("versionless delete reached provider")
			}
			if mode == "deleted" && (api.version != "version-1" || api.owner != "123456789012") {
				t.Fatalf("wrong authority %v", api)
			}
		})
	}
}
