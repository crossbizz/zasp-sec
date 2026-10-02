package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type auditExportHTTPStub struct {
	create         AuditExportCreate
	identity       RequestIdentity
	descriptor     AuditExportDescriptor
	creates, reads int
	read           AuditExportRead
	pages          map[int64]auditExportReadResult
	failure        error
	cancel         context.CancelFunc
}

// HTTP unit fixtures replace only external storage I/O. The SDK integration
// constructs the registry through its production constructor.
func auditExportHTTPStorageFixture(t *testing.T, store auditExportArtifactReader) *auditExportStorageRegistry {
	t.Helper()
	_, policy := auditExportPolicyFixture(t)
	return &auditExportStorageRegistry{entries: map[string]auditExportTrustedStorage{policy.PolicyID: {policy: policy, reader: store}}}
}

func TestAuditExportHTTPRejectsUntrustedStoragePolicyBeforeIO(t *testing.T) {
	for _, kind := range []string{"unknown", "missing", "digest", "owner", "kms", "quota"} {
		t.Run(kind, func(t *testing.T) {
			store, result := auditExportEmptyContentsFixture(t)
			_, policy := auditExportPolicyFixture(t)
			result.authority.StoragePolicy = policy
			switch kind {
			case "unknown":
				result.authority.StoragePolicy.PolicyID = "pid_74000009-0000-4000-8000-000000000009"
			case "missing":
				result.authority.StoragePolicy = auditExportStoragePolicy{}
			case "digest":
				result.authority.StoragePolicy.PolicyDigest = strings.Repeat("a", 64)
			case "owner":
				result.authority.StoragePolicy.ExpectedBucketOwner = "987654321098"
			case "kms":
				result.authority.StoragePolicy.KMSKeyARN = strings.Replace(policy.KMSKeyARN, "us-east-1", "us-west-2", 1)
			case "quota":
				result.authority.StoragePolicy.MaximumExportBytes--
			}
			repository := &auditExportHTTPStub{pages: map[int64]auditExportReadResult{1: result}}
			handler, err := newAuditExportHTTPHandler(repository, auditExportHTTPStorageFixture(t, store), []byte(strings.Repeat("k", 32)), newWorkflowProductID)
			if err != nil {
				t.Fatal(err)
			}
			_, _, identity, _ := auditExportRepositoryFixture(t)
			request := workflowRequest(t, identity, testCorrelationID, "getAuditExport", map[string]string{"id": result.export.ID}, http.MethodGet, "/api/v1/audit-exports/"+result.export.ID, "")
			request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "owned-cookie"})
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusServiceUnavailable || store.gets != 0 || store.references != 0 || strings.Contains(response.Body.String(), "storage_policy") || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("untrusted policy reached storage: status=%d gets=%d", response.Code, store.gets)
			}
		})
	}
}

func (repository *auditExportHTTPStub) Create(_ context.Context, identity RequestIdentity, input AuditExportCreate) (AuditExportDescriptor, error) {
	repository.creates++
	repository.identity = identity
	repository.create = input
	if repository.cancel != nil {
		repository.cancel()
	}
	if repository.failure != nil {
		return AuditExportDescriptor{}, repository.failure
	}
	return repository.descriptor, nil
}
func (repository *auditExportHTTPStub) Get(_ context.Context, identity RequestIdentity, input AuditExportRead) (auditExportReadResult, error) {
	repository.reads++
	repository.identity = identity
	repository.read = input
	if repository.cancel != nil {
		repository.cancel()
	}
	if repository.failure != nil {
		return auditExportReadResult{}, repository.failure
	}
	if page, ok := repository.pages[input.ChunkOrdinal]; ok {
		return page, nil
	}
	return auditExportReadResult{}, ErrRepositoryUnavailable
}

func TestAuditExportHTTPGetTraversesVerifiedChunks(t *testing.T) {
	store, first, last := auditExportTwoChunkContentsFixture(t)
	second := first
	secondAuthority := *first.authority
	secondAuthority.Chunk = last
	second.authority = &secondAuthority
	repository := &auditExportHTTPStub{pages: map[int64]auditExportReadResult{1: first, 2: second}}
	_, _, identity, _ := auditExportRepositoryFixture(t)
	identity.FreshAuthenticated = false
	handler, err := newAuditExportHTTPHandler(repository, auditExportHTTPStorageFixture(t, store), []byte(strings.Repeat("k", 32)), newWorkflowProductID)
	if err != nil {
		t.Fatal(err)
	}
	cursor := ""
	for ordinal := int64(1); ordinal <= 2; ordinal++ {
		path := "/api/v1/audit-exports/" + first.export.ID
		if cursor != "" {
			path += "?cursor=" + cursor
		}
		request := workflowRequest(t, identity, testCorrelationID, "getAuditExport", map[string]string{"id": first.export.ID}, http.MethodGet, path, "")
		request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "owned-cookie"})
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		var page struct {
			Export   AuditExportDescriptor `json:"export"`
			Contents struct {
				Chunk struct {
					Ordinal int64 `json:"ordinal"`
				} `json:"chunk"`
				PageInfo struct {
					NextCursor *string `json:"next_cursor"`
					HasMore    bool    `json:"has_more"`
				} `json:"page_info"`
			} `json:"contents"`
		}
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &page) != nil || page.Export.ID != first.export.ID || page.Contents.Chunk.Ordinal != ordinal || repository.read.ChunkOrdinal != ordinal {
			t.Fatalf("GET traversal failed ordinal%d status%d %s", ordinal, response.Code, response.Body.String())
		}
		if strings.Contains(response.Body.String(), "object_reference") || strings.Contains(response.Body.String(), "version_id") || strings.Contains(response.Body.String(), "s3://") {
			t.Fatal("provider coordinates escaped")
		}
		if ordinal == 1 {
			if !page.Contents.PageInfo.HasMore || page.Contents.PageInfo.NextCursor == nil {
				t.Fatal("missing next cursor")
			}
			cursor = *page.Contents.PageInfo.NextCursor
		} else if page.Contents.PageInfo.HasMore || page.Contents.PageInfo.NextCursor != nil || len(repository.read.ManifestSHA256) != 32 {
			t.Fatal("invalid terminal page/cursor pin")
		}
	}
}

func TestAuditExportHTTPCreateUsesActualRepositoryContract(t *testing.T) {
	_, database, identity, input := auditExportRepositoryFixture(t)
	repository := &auditExportHTTPStub{}
	if err := json.Unmarshal(database.responses[postgresAuditExportCreateSQL], &repository.descriptor); err != nil {
		t.Fatal(err)
	}
	store, _, _ := auditExportArtifactFixtureForTest(t)
	ids := []string{input.ExportID, input.AuditID, input.OutboxID}
	handler, err := newAuditExportHTTPHandler(repository, auditExportHTTPStorageFixture(t, store), []byte(strings.Repeat("k", 32)), func() (string, error) { id := ids[0]; ids = ids[1:]; return id, nil })
	if err != nil {
		t.Fatal(err)
	}
	request := workflowRequest(t, identity, testCorrelationID, "createAuditExport", nil, http.MethodPost, "/api/v1/audit-exports", "{}")
	request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "owned-session-cookie"})
	request.Header.Set("X-CSRF-Token", identity.CSRFToken)
	request.Header.Set("Idempotency-Key", input.IdempotencyKey)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	digest := sha256.Sum256([]byte("owned-session-cookie"))
	if response.Code != http.StatusCreated || repository.creates != 1 || !bytes.Equal(repository.create.SessionDigest, digest[:]) || repository.create.ExportID != input.ExportID || repository.create.AuditID != input.AuditID || repository.create.OutboxID != input.OutboxID || repository.create.IdempotencyKey != input.IdempotencyKey {
		t.Fatalf("create did not bind generated IDs/current cookie: status=%d body=%s", response.Code, response.Body.String())
	}
	var descriptor AuditExportDescriptor
	if json.Unmarshal(response.Body.Bytes(), &descriptor) != nil || descriptor.ID != input.ExportID || descriptor.Status != "queued" || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("invalid create response")
	}
}

func TestAuditExportHTTPCreateRejectsBeforeSideEffects(t *testing.T) {
	for _, kind := range []string{"missing cookie", "duplicate cookie", "bearer", "stale", "permission", "csrf", "duplicate csrf", "key", "duplicate key", "query", "body", "oversize", "media"} {
		t.Run(kind, func(t *testing.T) {
			_, _, identity, input := auditExportRepositoryFixture(t)
			if kind == "stale" {
				identity.FreshAuthenticated = false
			}
			if kind == "permission" {
				identity.Permissions = []string{"view"}
			}
			repository := &auditExportHTTPStub{}
			store, _, _ := auditExportArtifactFixtureForTest(t)
			generated := 0
			handler, err := newAuditExportHTTPHandler(repository, auditExportHTTPStorageFixture(t, store), []byte(strings.Repeat("k", 32)), func() (string, error) { generated++; return input.ExportID, nil })
			if err != nil {
				t.Fatal(err)
			}
			body := "{}"
			if kind == "body" {
				body = `{"organization_id":"caller"}`
			}
			if kind == "oversize" {
				body = strings.Repeat(" ", 1025) + "{}"
			}
			path := "/api/v1/audit-exports"
			if kind == "query" {
				path += "?scope=other"
			}
			request := workflowRequest(t, identity, testCorrelationID, "createAuditExport", nil, http.MethodPost, path, body)
			if kind != "missing cookie" {
				request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "owned-cookie"})
			}
			request.Header.Set("X-CSRF-Token", identity.CSRFToken)
			request.Header.Set("Idempotency-Key", input.IdempotencyKey)
			switch kind {
			case "duplicate cookie":
				request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "other-cookie"})
			case "bearer":
				request.Header.Set("Authorization", "Bearer other")
			case "csrf":
				request.Header.Set("X-CSRF-Token", "wrong")
			case "duplicate csrf":
				request.Header.Add("X-CSRF-Token", identity.CSRFToken)
			case "key":
				request.Header.Del("Idempotency-Key")
			case "duplicate key":
				request.Header.Add("Idempotency-Key", input.IdempotencyKey)
			case "media":
				request.Header.Set("Content-Type", "text/plain")
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			wantStatus, wantCode := http.StatusBadRequest, "invalid_request"
			switch kind {
			case "missing cookie", "duplicate cookie", "bearer":
				wantStatus, wantCode = http.StatusUnauthorized, "authentication_required"
			case "stale", "permission", "csrf", "duplicate csrf":
				wantStatus, wantCode = http.StatusForbidden, "forbidden"
			}
			var publicError struct {
				Code string `json:"code"`
			}
			if json.Unmarshal(response.Body.Bytes(), &publicError) != nil || publicError.Code != wantCode || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("wrong public rejection contract", response.Body.String())
			}
			if response.Code != wantStatus || generated != 0 || repository.creates != 0 || store.gets != 0 {
				t.Fatalf("rejected request reached side effects: %d generated=%d create=%d", response.Code, generated, repository.creates)
			}
		})
	}
}

func TestAuditExportHTTPCreateRejectsBrokenIDGenerator(t *testing.T) {
	for _, kind := range []string{"error", "invalid", "duplicate", "scope alias"} {
		t.Run(kind, func(t *testing.T) {
			_, _, identity, input := auditExportRepositoryFixture(t)
			repository := &auditExportHTTPStub{}
			store, _, _ := auditExportArtifactFixtureForTest(t)
			handler, err := newAuditExportHTTPHandler(repository, auditExportHTTPStorageFixture(t, store), []byte(strings.Repeat("k", 32)), func() (string, error) {
				switch kind {
				case "error":
					return "", errors.New("private generator detail")
				case "invalid":
					return "invalid", nil
				case "scope alias":
					return identity.Scope.OrganizationID().String(), nil
				}
				return input.ExportID, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			request := workflowRequest(t, identity, testCorrelationID, "createAuditExport", nil, http.MethodPost, "/api/v1/audit-exports", "{}")
			request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "owned-cookie"})
			request.Header.Set("X-CSRF-Token", identity.CSRFToken)
			request.Header.Set("Idempotency-Key", input.IdempotencyKey)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			var publicError struct {
				Code string `json:"code"`
			}
			if response.Code != http.StatusServiceUnavailable || json.Unmarshal(response.Body.Bytes(), &publicError) != nil || publicError.Code != "provider_unavailable" || strings.Contains(response.Body.String(), "private generator detail") || repository.creates != 0 || store.gets != 0 || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("generator failure escaped", response.Body.String())
			}
		})
	}
}

func TestAuditExportHTTPGetEmptyAndPending(t *testing.T) {
	for _, pending := range []bool{false, true} {
		store, result := auditExportEmptyContentsFixture(t)
		_, database, identity, _ := auditExportRepositoryFixture(t)
		if pending {
			result.export = AuditExportDescriptor{}
			if json.Unmarshal(database.responses[postgresAuditExportCreateSQL], &result.export) != nil {
				t.Fatal("fixture")
			}
			result.authority = nil
		}
		repository := &auditExportHTTPStub{pages: map[int64]auditExportReadResult{1: result}}
		handler, err := newAuditExportHTTPHandler(repository, auditExportHTTPStorageFixture(t, store), []byte(strings.Repeat("k", 32)), func() (string, error) { t.Fatal("GET generated ID"); return "", nil })
		if err != nil {
			t.Fatal(err)
		}
		request := workflowRequest(t, identity, testCorrelationID, "getAuditExport", map[string]string{"id": result.export.ID}, http.MethodGet, "/api/v1/audit-exports/"+result.export.ID, "")
		request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "owned-cookie"})
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		var page struct {
			Contents json.RawMessage `json:"contents"`
		}
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &page) != nil || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("GET state response", response.Body.String())
		}
		if pending {
			if string(page.Contents) != "null" || store.gets != 0 {
				t.Fatal("pending contents/provider access")
			}
		} else {
			var contents struct {
				Chunk json.RawMessage `json:"chunk"`
				SHA   json.RawMessage `json:"chunk_sha256"`
				Page  struct {
					More bool    `json:"has_more"`
					Next *string `json:"next_cursor"`
				} `json:"page_info"`
			}
			if json.Unmarshal(page.Contents, &contents) != nil || string(contents.Chunk) != "null" || string(contents.SHA) != "null" || contents.Page.More || contents.Page.Next != nil || store.gets != 1 {
				t.Fatal("empty export terminal contract")
			}
		}
	}
}

func TestAuditExportHTTPGetRefusesInvalidCursorBeforeCalls(t *testing.T) {
	for _, kind := range []string{"tamper", "foreign principal", "foreign export", "duplicate", "unknown query", "body"} {
		t.Run(kind, func(t *testing.T) {
			_, _, identity, input := auditExportRepositoryFixture(t)
			repository := &auditExportHTTPStub{}
			store, _, _ := auditExportArtifactFixtureForTest(t)
			handler, err := newAuditExportHTTPHandler(repository, auditExportHTTPStorageFixture(t, store), []byte(strings.Repeat("k", 32)), newWorkflowProductID)
			if err != nil {
				t.Fatal(err)
			}
			pin := sha256.Sum256([]byte("manifest fixture"))
			cursor, err := handler.cursor.Encode(identity, input.ExportID, pin[:], 2)
			if err != nil {
				t.Fatal(err)
			}
			id, query, body := input.ExportID, "?cursor="+cursor, ""
			want := http.StatusNotFound
			switch kind {
			case "tamper":
				query = "?cursor=x" + cursor
			case "foreign principal":
				identity.PrincipalID = identity.Scope.WorkspaceID()
			case "foreign export":
				id = "pid_73000009-0000-4000-8000-000000000009"
			case "duplicate":
				query += "&cursor=" + cursor
				want = http.StatusBadRequest
			case "unknown query":
				query = "?version=latest"
				want = http.StatusBadRequest
			case "body":
				body = "{}"
				want = http.StatusBadRequest
			}
			request := workflowRequest(t, identity, testCorrelationID, "getAuditExport", map[string]string{"id": id}, http.MethodGet, "/api/v1/audit-exports/"+id+query, body)
			request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "owned-cookie"})
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != want || repository.reads != 0 || store.gets != 0 || store.references != 0 {
				t.Fatalf("invalid GET status%d calls%d", response.Code, repository.reads)
			}
		})
	}
}

func TestAuditExportHTTPGetSanitizesPostReadFailures(t *testing.T) {
	for _, kind := range []string{"authentication", "forbidden", "not found", "provider", "foreign export", "foreign org", "canceled", "corrupt"} {
		t.Run(kind, func(t *testing.T) {
			store, result := auditExportEmptyContentsFixture(t)
			requestedID := result.export.ID
			_, _, identity, _ := auditExportRepositoryFixture(t)
			repository := &auditExportHTTPStub{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			want, code := http.StatusServiceUnavailable, "provider_unavailable"
			switch kind {
			case "authentication":
				repository.failure = ErrRepositoryAuthentication
				want, code = http.StatusUnauthorized, "authentication_required"
			case "forbidden":
				repository.failure = ErrAuditExportForbidden
				want, code = http.StatusForbidden, "forbidden"
			case "not found":
				repository.failure = ErrRepositoryNotFound
				want, code = http.StatusNotFound, "not_found"
			case "provider":
				repository.failure = errors.New("private SQL detail")
			case "foreign export":
				result.export.ID = "pid_73000010-0000-4000-8000-000000000010"
			case "foreign org":
				result.export.OrganizationID = "pid_73000011-0000-4000-8000-000000000011"
			case "canceled":
				repository.cancel = cancel
			case "corrupt":
				store.object.Body[0] = '!'
			}
			repository.pages = map[int64]auditExportReadResult{1: result}
			handler, err := newAuditExportHTTPHandler(repository, auditExportHTTPStorageFixture(t, store), []byte(strings.Repeat("k", 32)), newWorkflowProductID)
			if err != nil {
				t.Fatal(err)
			}
			request := workflowRequest(t, identity, testCorrelationID, "getAuditExport", map[string]string{"id": requestedID}, http.MethodGet, "/api/v1/audit-exports/"+requestedID, "")
			// Preserve authenticated/routed context while adding deterministic cancellation.
			ctx = context.WithValue(ctx, identityContextKey{}, identity)
			ctx = context.WithValue(ctx, routedOperationContextKey{}, RoutedOperation{OperationID: "getAuditExport", PathParameters: map[string]string{"id": requestedID}})
			request = request.WithContext(ctx)
			request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "owned-cookie"})
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			var publicError struct {
				Code string `json:"code"`
			}
			if response.Code != want || json.Unmarshal(response.Body.Bytes(), &publicError) != nil || publicError.Code != code || response.Header().Get("Cache-Control") != "no-store" || strings.Contains(response.Body.String(), "contents") || strings.Contains(response.Body.String(), "private") || strings.Contains(response.Body.String(), "s3://") {
				t.Fatal("post-read error escaped", response.Body.String())
			}
			if kind != "corrupt" && (store.gets != 0 || store.references != 0) {
				t.Fatal("rejected authority reached provider")
			}
		})
	}
}

func TestAuditExportHTTPCreateCancellationDoesNotPublishSuccess(t *testing.T) {
	_, database, identity, input := auditExportRepositoryFixture(t)
	repository := &auditExportHTTPStub{}
	if json.Unmarshal(database.responses[postgresAuditExportCreateSQL], &repository.descriptor) != nil {
		t.Fatal("fixture")
	}
	store, _, _ := auditExportArtifactFixtureForTest(t)
	handler, err := newAuditExportHTTPHandler(repository, auditExportHTTPStorageFixture(t, store), []byte(strings.Repeat("k", 32)), newWorkflowProductID)
	if err != nil {
		t.Fatal(err)
	}
	request := workflowRequest(t, identity, testCorrelationID, "createAuditExport", nil, http.MethodPost, "/api/v1/audit-exports", "{}")
	ctx, cancel := context.WithCancel(request.Context())
	defer cancel()
	request = request.WithContext(ctx)
	repository.cancel = cancel
	request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "owned-cookie"})
	request.Header.Set("X-CSRF-Token", identity.CSRFToken)
	request.Header.Set("Idempotency-Key", input.IdempotencyKey)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "queued") {
		t.Fatal("canceled Create published success", response.Body.String())
	}
}
