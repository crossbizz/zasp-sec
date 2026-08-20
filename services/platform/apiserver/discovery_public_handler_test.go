package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type discoveryPublicReadStub struct {
	sync        IntegrationSyncRecord
	page        IntegrationSyncPage
	schedule    IntegrationSchedule
	freshness   IntegrationFreshness
	beforeTime  *time.Time
	beforeID    string
	limit       int
	listCalls   int
	syncInput   PublicSyncRequest
	putInput    PublicSchedulePut
	deleteInput PublicScheduleDelete
}

func (stub *discoveryPublicReadStub) GetIntegrationSync(context.Context, domain.Scope, string, string) (IntegrationSyncRecord, error) {
	return stub.sync, nil
}

func (stub *discoveryPublicReadStub) ListIntegrationSyncs(_ context.Context, _ domain.Scope, _ string, beforeTime *time.Time, beforeID string, limit int) (IntegrationSyncPage, error) {
	stub.beforeTime, stub.beforeID, stub.limit = beforeTime, beforeID, limit
	stub.listCalls++
	return stub.page, nil
}

func (stub *discoveryPublicReadStub) GetIntegrationSchedule(context.Context, domain.Scope, string) (IntegrationSchedule, error) {
	return stub.schedule, nil
}

func (stub *discoveryPublicReadStub) GetIntegrationFreshness(context.Context, domain.Scope, string) (IntegrationFreshness, error) {
	return stub.freshness, nil
}

func (stub *discoveryPublicReadStub) RequestIntegrationSync(_ context.Context, _ RequestIdentity, input PublicSyncRequest) (IntegrationSyncMutationResult, error) {
	stub.syncInput = input
	return IntegrationSyncMutationResult{IntegrationSyncRecord: IntegrationSyncRecord{Value: IntegrationSync{ID: input.SyncID, IntegrationID: input.IntegrationID, TriggerKind: "manual", Status: "queued", RequestedAt: time.Date(2026, 8, 19, 20, 0, 0, 0, time.UTC)}, Version: 1}, AuditID: input.AuditID, CorrelationID: input.CorrelationID, ReceiptID: input.ReceiptID}, nil
}

func (stub *discoveryPublicReadStub) PutIntegrationSchedule(_ context.Context, _ RequestIdentity, input PublicSchedulePut) (IntegrationScheduleMutationResult, error) {
	stub.putInput = input
	now := time.Date(2026, 8, 19, 20, 0, 0, 0, time.UTC)
	next := now.Add(time.Duration(input.CadenceSeconds) * time.Second)
	value := IntegrationSchedule{IntegrationID: input.IntegrationID, CadenceSeconds: input.CadenceSeconds, State: input.State, TimeZone: "UTC", NextRunAt: &next, Version: input.ExpectedVersion + 1, CreatedAt: now, UpdatedAt: now}
	return IntegrationScheduleMutationResult{Value: value, Version: value.Version, AuditID: input.AuditID, CorrelationID: input.CorrelationID, ReceiptID: input.ReceiptID}, nil
}

func (stub *discoveryPublicReadStub) DeleteIntegrationSchedule(_ context.Context, _ RequestIdentity, input PublicScheduleDelete) (IntegrationScheduleMutationResult, error) {
	stub.deleteInput = input
	now := time.Date(2026, 8, 19, 20, 0, 0, 0, time.UTC)
	value := IntegrationSchedule{IntegrationID: input.IntegrationID, CadenceSeconds: 3600, State: "deleted", TimeZone: "UTC", Version: input.ExpectedVersion + 1, CreatedAt: now, UpdatedAt: now}
	return IntegrationScheduleMutationResult{Value: value, Version: value.Version, AuditID: input.AuditID, CorrelationID: input.CorrelationID, ReceiptID: input.ReceiptID}, nil
}

func discoveryPublicRequest(t *testing.T, identity RequestIdentity, method, path, operationID string, parameters map[string]string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(method, "https://app.zasp.test"+path, nil)
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
	return request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: operationID, PathParameters: parameters}))
}

func TestDiscoveryPublicHandlerReturnsStrictSyncAndETag(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	integrationID := "pid_82000001-0000-4000-8000-000000000001"
	syncID := "pid_82000002-0000-4000-8000-000000000002"
	requested := time.Date(2026, 8, 19, 20, 0, 0, 0, time.UTC)
	stub := &discoveryPublicReadStub{sync: IntegrationSyncRecord{Version: 3, Value: IntegrationSync{ID: syncID, IntegrationID: integrationID, TriggerKind: "manual", Status: "queued", RequestedAt: requested}}}
	handler, err := NewDiscoveryPublicHTTPHandler(stub, []byte(strings.Repeat("s", 32)))
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, discoveryPublicRequest(t, identity, http.MethodGet, "/api/v1/integrations/"+integrationID+"/syncs/"+syncID, "getIntegrationSync", map[string]string{"id": integrationID, "syncId": syncID}))
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"3"` || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d headers=%#v body=%s", response.Code, response.Header(), response.Body.String())
	}
	var body map[string]json.RawMessage
	if json.Unmarshal(response.Body.Bytes(), &body) != nil || len(body) != 14 || body["version"] != nil || body["job_id"] != nil {
		t.Fatalf("noncanonical body=%s", response.Body.String())
	}
}

func TestDiscoveryPublicHandlerSignsAndScopeBindsSyncHistoryCursor(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	integrationID := "pid_82000001-0000-4000-8000-000000000001"
	syncID := "pid_82000002-0000-4000-8000-000000000002"
	requested := time.Date(2026, 8, 19, 20, 0, 0, 0, time.UTC)
	stub := &discoveryPublicReadStub{page: IntegrationSyncPage{Items: []IntegrationSync{}, NextRequestedAt: &requested, NextID: syncID}}
	handler, err := NewDiscoveryPublicHTTPHandler(stub, []byte(strings.Repeat("s", 32)))
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, discoveryPublicRequest(t, identity, http.MethodGet, "/api/v1/integrations/"+integrationID+"/syncs?limit=25", "listIntegrationSyncs", map[string]string{"id": integrationID}))
	if response.Code != http.StatusOK || stub.limit != 25 {
		t.Fatalf("first status=%d limit=%d body=%s", response.Code, stub.limit, response.Body.String())
	}
	var body struct {
		PageInfo struct {
			NextCursor string `json:"next_cursor"`
			HasMore    bool   `json:"has_more"`
		} `json:"page_info"`
	}
	if json.Unmarshal(response.Body.Bytes(), &body) != nil || !body.PageInfo.HasMore || body.PageInfo.NextCursor == "" {
		t.Fatalf("page body=%s", response.Body.String())
	}

	stub.page = IntegrationSyncPage{Items: []IntegrationSync{}}
	response = httptest.NewRecorder()
	nextPath := "/api/v1/integrations/" + integrationID + "/syncs?cursor=" + url.QueryEscape(body.PageInfo.NextCursor)
	handler.ServeHTTP(response, discoveryPublicRequest(t, identity, http.MethodGet, nextPath, "listIntegrationSyncs", map[string]string{"id": integrationID}))
	if response.Code != http.StatusOK || stub.beforeTime == nil || !stub.beforeTime.Equal(requested) || stub.beforeID != syncID {
		t.Fatalf("second status=%d before=%v/%s body=%s", response.Code, stub.beforeTime, stub.beforeID, response.Body.String())
	}

	foreign := fixtureRequestIdentity(t)
	foreignOrganization, _ := domain.ParseProductID("pid_10000009-0000-4000-8000-000000000009")
	foreign.Scope, _ = domain.NewScope(foreignOrganization, identity.Scope.WorkspaceID(), identity.Scope.EnvironmentID())
	beforeCalls := stub.listCalls
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, discoveryPublicRequest(t, foreign, http.MethodGet, nextPath, "listIntegrationSyncs", map[string]string{"id": integrationID}))
	if response.Code < 400 || stub.listCalls != beforeCalls {
		t.Fatalf("foreign cursor status=%d calls=%d body=%s", response.Code, stub.listCalls, response.Body.String())
	}
}

func TestDiscoveryPublicHandlerReturnsScheduleAndFreshnessVersions(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	integrationID := "pid_82000001-0000-4000-8000-000000000001"
	now := time.Date(2026, 8, 19, 20, 0, 0, 0, time.UTC)
	stub := &discoveryPublicReadStub{
		schedule:  IntegrationSchedule{IntegrationID: integrationID, CadenceSeconds: 3600, State: "enabled", TimeZone: "UTC", NextRunAt: &now, Version: 4, CreatedAt: now, UpdatedAt: now},
		freshness: IntegrationFreshness{IntegrationID: integrationID, Version: 7, UpdatedAt: now},
	}
	handler, err := NewDiscoveryPublicHTTPHandler(stub, []byte(strings.Repeat("s", 32)))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		operation string
		path      string
		etag      string
	}{
		{operation: "getIntegrationSchedule", path: "/api/v1/integrations/" + integrationID + "/schedule", etag: `"4"`},
		{operation: "getIntegrationFreshness", path: "/api/v1/integrations/" + integrationID + "/freshness", etag: `"7"`},
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, discoveryPublicRequest(t, identity, http.MethodGet, test.path, test.operation, map[string]string{"id": integrationID}))
		if response.Code != http.StatusOK || response.Header().Get("ETag") != test.etag {
			t.Fatalf("%s status=%d headers=%#v body=%s", test.operation, response.Code, response.Header(), response.Body.String())
		}
	}
}

func TestDiscoveryPublicHandlerStrictlyMutatesSyncAndSchedule(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	integrationID := "pid_82000001-0000-4000-8000-000000000001"
	correlationID := "pid_82000009-0000-4000-8000-000000000009"
	ids := []string{
		"pid_82000002-0000-4000-8000-000000000002", "pid_82000003-0000-4000-8000-000000000003", "pid_82000004-0000-4000-8000-000000000004",
		"pid_82000005-0000-4000-8000-000000000005", "pid_82000006-0000-4000-8000-000000000006", "pid_82000007-0000-4000-8000-000000000007",
		"pid_82000008-0000-4000-8000-000000000008", "pid_83000001-0000-4000-8000-000000000001", "pid_83000002-0000-4000-8000-000000000002",
	}
	nextID := func() (string, error) {
		value := ids[0]
		ids = ids[1:]
		return value, nil
	}
	stub := &discoveryPublicReadStub{}
	handler, err := NewDiscoveryPublicHTTPHandler(stub, []byte(strings.Repeat("s", 32)), DiscoveryPublicHandlerConfig{ParserVersion: "parser-v1", ToolVersion: "tool-v1", NewProductID: nextID})
	if err != nil {
		t.Fatal(err)
	}

	syncRequest := discoveryPublicRequest(t, identity, http.MethodPost, "/api/v1/integrations/"+integrationID+"/sync", "syncIntegration", map[string]string{"id": integrationID})
	syncRequest.Body = io.NopCloser(strings.NewReader(`{}`))
	syncRequest.ContentLength = 2
	syncRequest.Header.Set("Content-Type", "application/json")
	syncRequest.Header.Set("Idempotency-Key", "sync-public-idempotency")
	syncRequest.Header.Set("If-Match", `"1"`)
	syncRequest = syncRequest.WithContext(context.WithValue(syncRequest.Context(), correlationContextKey{}, correlationID))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, syncRequest)
	if response.Code != http.StatusAccepted || response.Header().Get("ETag") != `"1"` || response.Header().Get("X-Audit-ID") != stub.syncInput.AuditID || response.Header().Get("X-Mutation-Receipt-ID") != stub.syncInput.ReceiptID || len(stub.syncInput.RequestDigest) != sha256.Size || stub.syncInput.ParserVersion != "parser-v1" || stub.syncInput.ToolVersion != "tool-v1" {
		t.Fatalf("sync status=%d headers=%#v input=%#v body=%s", response.Code, response.Header(), stub.syncInput, response.Body.String())
	}

	putRequest := discoveryPublicRequest(t, identity, http.MethodPut, "/api/v1/integrations/"+integrationID+"/schedule", "putIntegrationSchedule", map[string]string{"id": integrationID})
	putRequest.Body = io.NopCloser(strings.NewReader(`{"cadence_seconds":3600,"state":"enabled"}`))
	putRequest.ContentLength = 46
	putRequest.Header.Set("Content-Type", "application/json")
	putRequest.Header.Set("Idempotency-Key", "schedule-public-idempotency")
	putRequest.Header.Set("If-Match", `"0"`)
	putRequest = putRequest.WithContext(context.WithValue(putRequest.Context(), correlationContextKey{}, correlationID))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, putRequest)
	if response.Code != http.StatusOK || stub.putInput.ExpectedVersion != 0 || stub.putInput.CadenceSeconds != 3600 || response.Header().Get("ETag") != `"1"` {
		t.Fatalf("put status=%d input=%#v headers=%#v body=%s", response.Code, stub.putInput, response.Header(), response.Body.String())
	}

	deleteRequest := discoveryPublicRequest(t, identity, http.MethodDelete, "/api/v1/integrations/"+integrationID+"/schedule", "deleteIntegrationSchedule", map[string]string{"id": integrationID})
	deleteRequest.Header.Set("Idempotency-Key", "schedule-delete-idempotency")
	deleteRequest.Header.Set("If-Match", `"1"`)
	deleteRequest = deleteRequest.WithContext(context.WithValue(deleteRequest.Context(), correlationContextKey{}, correlationID))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, deleteRequest)
	if response.Code != http.StatusNoContent || response.Body.Len() != 0 || stub.deleteInput.ExpectedVersion != 1 || response.Header().Get("ETag") != `"2"` {
		t.Fatalf("delete status=%d input=%#v headers=%#v body=%s", response.Code, stub.deleteInput, response.Header(), response.Body.String())
	}
}

func TestDiscoveryPublicHandlerKeepsPATMutationsReceiptFree(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBearerToken
	identity.CSRFToken = ""
	integrationID := "pid_82000001-0000-4000-8000-000000000001"
	correlationID := "pid_82000009-0000-4000-8000-000000000009"
	ids := []string{
		"pid_82000002-0000-4000-8000-000000000002",
		"pid_82000003-0000-4000-8000-000000000003",
		"pid_82000004-0000-4000-8000-000000000004",
		"pid_82000005-0000-4000-8000-000000000005",
	}
	nextID := func() (string, error) {
		if len(ids) == 0 {
			t.Fatal("PAT mutation requested a browser receipt ID")
		}
		value := ids[0]
		ids = ids[1:]
		return value, nil
	}
	stub := &discoveryPublicReadStub{}
	handler, err := NewDiscoveryPublicHTTPHandler(stub, []byte(strings.Repeat("s", 32)), DiscoveryPublicHandlerConfig{ParserVersion: "parser-v1", ToolVersion: "tool-v1", NewProductID: nextID})
	if err != nil {
		t.Fatal(err)
	}
	request := discoveryPublicRequest(t, identity, http.MethodPost, "/api/v1/integrations/"+integrationID+"/sync", "syncIntegration", map[string]string{"id": integrationID})
	request.Body = io.NopCloser(strings.NewReader(`{}`))
	request.ContentLength = 2
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "sync-pat-idempotency")
	request.Header.Set("If-Match", `"1"`)
	request = request.WithContext(context.WithValue(request.Context(), correlationContextKey{}, correlationID))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || stub.syncInput.ReceiptID != "" || response.Header().Get("X-Mutation-Receipt-ID") != "" || len(ids) != 0 {
		t.Fatalf("PAT sync status=%d input=%#v headers=%#v remainingIDs=%d body=%s", response.Code, stub.syncInput, response.Header(), len(ids), response.Body.String())
	}
}

func TestDiscoveryPublicHandlerRejectsMutationHeaderAndBodyDrift(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	integrationID := "pid_82000001-0000-4000-8000-000000000001"
	stub := &discoveryPublicReadStub{}
	handler, err := NewDiscoveryPublicHTTPHandler(stub, []byte(strings.Repeat("s", 32)))
	if err != nil {
		t.Fatal(err)
	}
	for name, input := range map[string][2]string{
		"bare version":   {"1", `{}`},
		"leading zero":   {`"01"`, `{}`},
		"nonempty input": {`"1"`, `{"force":true}`},
	} {
		t.Run(name, func(t *testing.T) {
			request := discoveryPublicRequest(t, identity, http.MethodPost, "/api/v1/integrations/"+integrationID+"/sync", "syncIntegration", map[string]string{"id": integrationID})
			request.Body = io.NopCloser(strings.NewReader(input[1]))
			request.ContentLength = int64(len(input[1]))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Idempotency-Key", "sync-public-idempotency")
			request.Header.Set("If-Match", input[0])
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code < 400 || stub.syncInput.IntegrationID != "" {
				t.Fatalf("status=%d input=%#v body=%s", response.Code, stub.syncInput, response.Body.String())
			}
		})
	}
}
