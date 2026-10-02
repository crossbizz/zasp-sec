package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore/s3driver"
	"github.com/zasp-ai/zasp-sec/services/platform/bucketlayout"
)

const classificationKMS = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-4123-8123-123456789012"
const classificationSecret = "provider-secret-bucket-diagnostic"

var classificationModes = []string{"head-outage", "get-outage", "body-outage", "cancel", "deadline", "version", "metadata", "checksum", "body-mismatch", "envelope", "valid",
	"sdk-checksum", "sdk-body-outage", "sdk-spoof", "sdk-cancel", "sdk-valid"}

func classificationIntegrity(mode string) bool {
	return mode == "version" || mode == "metadata" || mode == "checksum" || mode == "body-mismatch" || mode == "envelope" || mode == "sdk-checksum"
}

func classificationValid(mode string) bool { return mode == "valid" || mode == "sdk-valid" }

type classificationSDKTransport struct {
	t *testing.T
	p *classificationProvider
}

// Only HTTP transport is replaced. The installed SDK still deserializes the
// pinned response and validates its body checksum at EOF.
func (tr *classificationSDKTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	p := tr.p
	key, _ := bucketlayout.ExportKey(p.artifact.Scope, p.artifact.Reference.ArtifactID())
	if r.URL.Host != "classification.invalid" || r.URL.Path != "/compliance-exports/"+key || r.URL.Query().Get("versionId") != p.artifact.VersionID || r.Header.Get("X-Amz-Expected-Bucket-Owner") != "123456789012" || r.Header.Get("X-Amz-Checksum-Mode") != "ENABLED" {
		tr.t.Error("SDK read omitted pinned request authority")
		return nil, errors.New(classificationSecret)
	}
	h := http.Header{}
	h.Set("Content-Length", strconv.FormatInt(p.artifact.Size, 10))
	h.Set("Content-Type", "application/json")
	h.Set("X-Amz-Version-Id", p.artifact.VersionID)
	h.Set("X-Amz-Checksum-Sha256", base64.StdEncoding.EncodeToString(p.artifact.SHA256[:]))
	h.Set("X-Amz-Server-Side-Encryption", "aws:kms")
	h.Set("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id", classificationKMS)
	for k, v := range p.metadata() {
		h.Set("X-Amz-Meta-"+k, v)
	}
	var body io.ReadCloser = http.NoBody
	switch r.Method {
	case "HEAD":
		if p.headHook != nil {
			p.headHook()
		}
	case "GET":
		content := append([]byte(nil), p.artifact.Body...)
		if p.mode != "sdk-valid" {
			content[0] ^= 1
		}
		body = io.NopCloser(strings.NewReader(string(content)))
		switch p.mode {
		case "sdk-body-outage":
			body = io.NopCloser(io.MultiReader(strings.NewReader(string(content[:len(content)/2])), classificationReadError{err: io.ErrUnexpectedEOF}))
		case "sdk-spoof":
			// Even all advertised bytes plus checksum-looking diagnostics cannot
			// impersonate the SDK's concrete validation error.
			body = io.NopCloser(io.MultiReader(strings.NewReader(string(content)), classificationReadError{err: errors.New("checksum did not match: algorithm SHA256, expect private, actual " + classificationSecret)}))
		case "sdk-cancel":
			// Return all corrupt bytes and EOF after cancellation: the actual SDK
			// mismatch exists, but the cancelled request must win classification.
			body = &classificationCancelBody{Reader: strings.NewReader(string(content)), cancel: p.cancel}
		}
	default:
		tr.t.Error("read client attempted a mutation")
		return nil, errors.New(classificationSecret)
	}
	return &http.Response{StatusCode: 200, Status: "200 OK", Header: h, Body: body, ContentLength: p.artifact.Size, Request: r}, nil
}

type classificationReadError struct{ err error }

func (r classificationReadError) Read([]byte) (int, error) { return 0, r.err }

type classificationCancelBody struct {
	*strings.Reader
	cancel context.CancelFunc
}

func (r *classificationCancelBody) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if err == io.EOF {
		r.cancel()
	}
	return n, err
}
func (r *classificationCancelBody) Close() error { return nil }

type classificationProvider struct {
	artifact artifactstore.Artifact
	mode     string
	cancel   context.CancelFunc
	headHook func()
}

func (p *classificationProvider) PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	panic("read client must not write")
}
func (p *classificationProvider) HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	if p.headHook != nil {
		p.headHook()
	}
	if p.mode == "head-outage" {
		return nil, errors.New(classificationSecret)
	}
	version := p.artifact.VersionID
	if p.mode == "version" {
		version = "foreign-version"
	}
	checksum := base64.StdEncoding.EncodeToString(p.artifact.SHA256[:])
	if p.mode == "checksum" {
		checksum = base64.StdEncoding.EncodeToString(make([]byte, 32))
	}
	return &s3.HeadObjectOutput{ContentLength: aws.Int64(p.artifact.Size), ContentType: aws.String("application/json"), VersionId: aws.String(version), ChecksumSHA256: aws.String(checksum), ServerSideEncryption: s3types.ServerSideEncryptionAwsKms, SSEKMSKeyId: aws.String(classificationKMS), Metadata: p.metadata()}, nil
}
func (p *classificationProvider) metadata() map[string]string {
	a := p.artifact
	m := map[string]string{"organization_id": a.OrganizationID().String(), "workspace_id": a.WorkspaceID().String(), "environment_id": a.EnvironmentID().String(), "artifact_id": a.Reference.String(), "media_type": "application/json", "sha256": hex.EncodeToString(a.SHA256[:])}
	if p.mode == "metadata" {
		m["environment_id"] = "foreign"
	}
	return m
}

type classificationBrokenBody struct{}

func (classificationBrokenBody) Read([]byte) (int, error) { return 0, errors.New(classificationSecret) }
func (classificationBrokenBody) Close() error             { return nil }
func (p *classificationProvider) GetObject(ctx context.Context, _ *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	if p.mode == "get-outage" {
		return nil, errors.New(classificationSecret)
	}
	if p.mode == "cancel" {
		p.cancel()
		return nil, ctx.Err()
	}
	if p.mode == "deadline" {
		return nil, context.DeadlineExceeded
	}
	body := string(p.artifact.Body)
	if p.mode == "body-mismatch" {
		body = "wrong bytes"
	}
	var reader io.ReadCloser = io.NopCloser(strings.NewReader(body))
	if p.mode == "body-outage" {
		reader = classificationBrokenBody{}
	}
	return &s3.GetObjectOutput{Body: reader, ContentLength: aws.Int64(p.artifact.Size), ContentType: aws.String("application/json"), VersionId: aws.String(p.artifact.VersionID), ChecksumSHA256: aws.String(base64.StdEncoding.EncodeToString(p.artifact.SHA256[:])), ServerSideEncryption: s3types.ServerSideEncryptionAwsKms, SSEKMSKeyId: aws.String(classificationKMS), Metadata: p.metadata()}, nil
}
func classificationStore(t *testing.T, a artifactstore.Artifact, mode string, cancel context.CancelFunc) (*artifactstore.Store, *s3driver.Driver, *classificationProvider) {
	t.Helper()
	p := &classificationProvider{artifact: a, mode: mode, cancel: cancel}
	var client s3driver.API = p
	if strings.HasPrefix(mode, "sdk-") {
		client = s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String("https://classification.invalid"), UsePathStyle: true, Credentials: aws.AnonymousCredentials{}, HTTPClient: &http.Client{Transport: &classificationSDKTransport{t: t, p: p}}})
	}
	d, err := s3driver.NewExport(client, s3driver.Config{Bucket: "compliance-exports", ExpectedBucketOwner: "123456789012", KMSKeyARN: classificationKMS, MaximumBytes: compliancePackageMaximum})
	if err != nil {
		t.Fatal(err)
	}
	s, err := artifactstore.NewExport(d, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: compliancePackageMaximum})
	if err != nil {
		t.Fatal(err)
	}
	return s, d, p
}

func TestComplianceReadFailureClassification(t *testing.T) {
	for _, mode := range classificationModes {
		t.Run(mode, func(t *testing.T) {
			_, db, _, identity := complianceHTTPFixture(t)
			if mode == "envelope" {
				db.artifact.Body = []byte(`{"version":2}`)
				db.artifact.Size = int64(len(db.artifact.Body))
				db.artifact.SHA256 = sha256.Sum256(db.artifact.Body)
			}
			for _, layer := range []string{"driver", "store", "http"} {
				t.Run(layer, func(t *testing.T) {
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					store, driver, _ := classificationStore(t, db.artifact, mode, cancel)
					if layer != "http" {
						var err error
						if layer == "driver" {
							key, _ := bucketlayout.ExportKey(db.artifact.Scope, db.artifact.Reference.ArtifactID())
							_, err = driver.Get(ctx, artifactstore.DriverLocator{Key: key, Scope: db.artifact.Scope, Reference: db.artifact.Reference, VersionID: db.artifact.VersionID})
						} else {
							_, err = store.Get(ctx, db.artifact.Locator)
						}
						if classificationValid(mode) || mode == "envelope" {
							if err != nil {
								t.Fatal(err)
							}
							return
						}
						getError := artifactstore.ErrGet
						if layer == "driver" {
							getError = s3driver.ErrGet
						}
						if !errors.Is(err, getError) || errors.Is(err, artifactstore.ErrIntegrity) != classificationIntegrity(mode) || strings.Contains(err.Error(), classificationSecret) {
							t.Fatalf("%s read category: %v", layer, err)
						}
						if (mode == "cancel" || mode == "sdk-cancel") && !errors.Is(err, context.Canceled) {
							t.Fatal("cancellation category lost")
						}
						if mode == "deadline" && !errors.Is(err, context.DeadlineExceeded) {
							t.Fatal("deadline category lost")
						}
						return
					}
					source, err := NewComplianceRepository(db)
					if err != nil {
						t.Fatal(err)
					}
					handler := &complianceHTTPHandler{source: source, exports: &ComplianceExportsRepository{source: source}, reader: store}
					router, err := NewCompositionWithCompliance(auditExportCompositionDependencies(), nil, handler)
					if err != nil {
						t.Fatal(err)
					}
					mounted, err := NewProductMiddleware(ProductSecurity{PublicOrigin: "https://console.example.test", MaximumBodyBytes: 16384, GenerateCorrelationID: func() string { return testCorrelationID }, Authenticate: func(context.Context, Credential) (RequestIdentity, error) { return *identity, nil }}, router)
					if err != nil {
						t.Fatal(err)
					}
					db.operations = nil
					w := complianceHTTPRequest(t, mounted, *identity, "POST", "/api/v1/compliance/exports/"+complianceHTTPJobID+"/download", `{"format":"human","token":"`+complianceHTTPToken+`"}`, func(r *http.Request) { *r = *r.WithContext(ctx) })
					want := "read"
					if classificationValid(mode) {
						want += ",consume"
					} else if classificationIntegrity(mode) {
						want += ",integrity_failure"
					}
					if strings.Join(db.operations, ",") != want {
						t.Fatalf("read effects %v want %s", db.operations, want)
					}
					if classificationValid(mode) {
						if w.Code != 200 || !strings.Contains(w.Body.String(), "Persisted report") {
							t.Fatalf("valid flow %d %s", w.Code, w.Body)
						}
					} else if w.Code != 503 || w.Header().Get("Content-Disposition") != "" || strings.Contains(w.Body.String(), classificationSecret) || strings.Contains(w.Body.String(), "Persisted report") {
						t.Fatalf("failure disclosed %d %s", w.Code, w.Body)
					}
				})
			}
		})
	}
}
