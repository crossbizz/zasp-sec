package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore/s3driver"
	"github.com/zasp-ai/zasp-sec/services/platform/audit"
)

const auditExportSDKKMS = "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111"

type auditExportSDKObject struct {
	body    []byte
	headers http.Header
}
type auditExportSDKTransport struct {
	objects           map[string]auditExportSDKObject
	puts, gets, heads int
	corrupt           string
}

func (transport *auditExportSDKTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Host != "audit-export.invalid" || !strings.HasPrefix(request.URL.Path, "/owned-export-fixture/organizations/") || !strings.Contains(request.URL.Path, "/exports/") || request.Header.Get("X-Amz-Expected-Bucket-Owner") != "123456789012" {
		return nil, errors.New("unexpected provider request")
	}
	key := request.URL.Path
	object, exists := transport.objects[key]
	status := http.StatusOK
	var body []byte
	if request.Method == http.MethodPut {
		transport.puts++
		if request.Header.Get("If-None-Match") != "*" || request.Header.Get("X-Amz-Server-Side-Encryption") != "aws:kms" || request.Header.Get("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id") != auditExportSDKKMS {
			return nil, errors.New("missing immutable KMS contract")
		}
		if exists {
			status = http.StatusPreconditionFailed
		} else {
			encoded, err := io.ReadAll(io.LimitReader(request.Body, audit.ExportMaximumChunkBytes+1))
			if err != nil {
				return nil, err
			}
			if len(encoded) > audit.ExportMaximumChunkBytes {
				return nil, errors.New("oversized artifact")
			}
			object = auditExportSDKObject{body: encoded, headers: request.Header.Clone()}
			object.headers.Set("X-Amz-Version-Id", "owned-version-1")
			object.headers.Set("Content-Length", strconv.Itoa(len(encoded)))
			transport.objects[key] = object
		}
	} else {
		if !exists {
			return &http.Response{StatusCode: http.StatusNotFound, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
		}
		if request.URL.Query().Get("versionId") != "owned-version-1" || request.Header.Get("X-Amz-Checksum-Mode") != "ENABLED" {
			return nil, errors.New("unpinned artifact read")
		}
		switch request.Method {
		case http.MethodHead:
			transport.heads++
		case http.MethodGet:
			transport.gets++
			body = bytes.Clone(object.body)
			if transport.corrupt == "body" || transport.corrupt == "chunk body" && strings.HasSuffix(key, "pid_73000008-0000-4000-8000-000000000008") {
				body[0] = '!'
			}
		default:
			return nil, errors.New("unexpected mutation")
		}
	}
	headers := object.headers.Clone()
	switch transport.corrupt {
	case "version":
		headers.Set("X-Amz-Version-Id", "wrong-version")
	case "kms":
		headers.Set("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id", "wrong-key")
	case "tenant metadata":
		headers.Set("X-Amz-Meta-Organization_id", "pid_73000009-0000-4000-8000-000000000009")
	}
	return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(bytes.NewReader(body)), Request: request}, nil
}

// The AWS SDK, typed store and export driver are real. The transport is owned,
// in-process and anonymous; this is not a cloud-bucket or deployment claim.
func TestAuditExportContentsThroughActualSDK(t *testing.T) {
	transport := &auditExportSDKTransport{objects: map[string]auditExportSDKObject{}}
	client := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String("https://audit-export.invalid"), UsePathStyle: true, Credentials: aws.AnonymousCredentials{}, HTTPClient: &http.Client{Transport: transport}, RetryMaxAttempts: 1})
	driver, err := s3driver.NewExport(client, s3driver.Config{Bucket: "owned-export-fixture", ExpectedBucketOwner: "123456789012", KMSKeyARN: auditExportSDKKMS, MaximumBytes: audit.ExportMaximumChunkBytes})
	if err != nil {
		t.Fatal(err)
	}
	store, err := artifactstore.NewExport(driver, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: audit.ExportMaximumChunkBytes})
	if err != nil {
		t.Fatal(err)
	}
	fixtures, result, last := auditExportTwoChunkContentsFixture(t)
	for _, fixture := range fixtures {
		locator := fixture.object.Locator
		locator.VersionID = ""
		created, err := store.Put(context.Background(), artifactstore.PutRequest{Locator: locator, MediaType: "application/json", Body: fixture.object.Body})
		if err != nil {
			t.Fatal("SDK artifact put", err)
		}
		if created.VersionID != "owned-version-1" {
			t.Fatal("missing version receipt")
		}
	}
	result.authority.Manifest.VersionID = "owned-version-1"
	// Put verifies its saved receipt by reading the pinned version back.
	if transport.puts != 3 || transport.heads != 3 || transport.gets != 3 {
		t.Fatal("saved receipts were not verified")
	}
	result.authority.Chunk.VersionID = "owned-version-1"
	last.VersionID = "owned-version-1"
	firstAuthority := *result.authority
	firstPage := result
	firstPage.authority = &firstAuthority
	first, err := verifyAuditExportContents(context.Background(), store, result)
	if err != nil || first.chunk == nil || first.chunk.Ordinal != 1 {
		t.Fatal("SDK first page", err)
	}
	result.authority.Chunk = last
	second, err := verifyAuditExportContents(context.Background(), store, result)
	if err != nil || second.chunk == nil || second.chunk.Ordinal != 2 || second.chunk.PreviousDigest != first.chunkSHA256 {
		t.Fatal("SDK second page", err)
	}
	if transport.puts != 3 || transport.gets != 7 || transport.heads != 7 {
		t.Fatalf("unexpected SDK traversal puts=%d heads=%d gets=%d", transport.puts, transport.heads, transport.gets)
	}
	// Traverse the production factory, actual repository decoder and HTTP cursor.
	// SQL wire responses use a fixture; this is not a PostgreSQL lifecycle proof.
	_, database, identity, _ := auditExportRepositoryFixture(t)
	config, _ := auditExportPolicyFixture(t)
	handler, err := NewAuditExportProductionHandler(context.Background(), database, AuditExportHandlerConfiguration{Storage: []AuditExportStorageConfiguration{{Policy: config, Client: client}}, CursorSigningKey: []byte(strings.Repeat("k", 32)), ProviderTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	identity.FreshAuthenticated = false
	cursor := ""
	for ordinal := int64(1); ordinal <= 2; ordinal++ {
		authorityPage := firstPage
		if ordinal == 2 {
			authorityPage = result
		}
		database.responses[postgresAuditExportGetSQL] = auditExportReadEnvelope(t, authorityPage.export, authorityPage.authority)
		path := "/api/v1/audit-exports/" + result.export.ID
		if cursor != "" {
			path += "?cursor=" + cursor
		}
		request := workflowRequest(t, identity, testCorrelationID, "getAuditExport", map[string]string{"id": result.export.ID}, http.MethodGet, path, "")
		request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "owned-cookie"})
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		var page struct {
			Contents struct {
				Chunk    audit.ExportChunk `json:"chunk"`
				PageInfo struct {
					HasMore    bool    `json:"has_more"`
					NextCursor *string `json:"next_cursor"`
				} `json:"page_info"`
			} `json:"contents"`
		}
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &page) != nil || page.Contents.Chunk.Ordinal != ordinal || len(page.Contents.Chunk.Events) != 1 {
			t.Fatalf("HTTP SDK traversal ordinal%d status%d %s", ordinal, response.Code, response.Body.String())
		}
		if database.query != postgresAuditExportGetSQL || len(database.args) != 11 || database.args[7] != ordinal {
			t.Fatal("factory retrieval bypassed scoped SQL authority")
		}
		if ordinal == 1 {
			if !page.Contents.PageInfo.HasMore || page.Contents.PageInfo.NextCursor == nil {
				t.Fatal("HTTP SDK next cursor missing")
			}
			cursor = *page.Contents.PageInfo.NextCursor
		} else if page.Contents.PageInfo.HasMore || page.Contents.PageInfo.NextCursor != nil {
			t.Fatal("HTTP SDK terminal page invalid")
		}
	}
	if transport.puts != 3 || transport.gets != 11 || transport.heads != 11 {
		t.Fatal("HTTP retrieval did not use exact pinned SDK reads")
	}
	for _, kind := range []string{"body", "chunk body", "version", "kms", "tenant metadata"} {
		transport.corrupt = kind
		if _, err := verifyAuditExportContents(context.Background(), store, result); !errors.Is(err, ErrRepositoryUnavailable) {
			t.Fatal("SDK corruption accepted", kind, err)
		}
		request := workflowRequest(t, identity, testCorrelationID, "getAuditExport", map[string]string{"id": result.export.ID}, http.MethodGet, "/api/v1/audit-exports/"+result.export.ID+"?cursor="+cursor, "")
		request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "owned-cookie"})
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		var publicError struct {
			Code string `json:"code"`
		}
		if response.Code != http.StatusServiceUnavailable || json.Unmarshal(response.Body.Bytes(), &publicError) != nil || publicError.Code != "provider_unavailable" || strings.Contains(response.Body.String(), "contents") || strings.Contains(response.Body.String(), "s3://") {
			t.Fatal("HTTP returned corrupt artifact contents", kind, response.Body.String())
		}
	}
}
