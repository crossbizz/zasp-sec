package apiserver

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type inventoryRepositoryStub struct {
	page        InventoryPage
	detail      InventoryDetail
	pageCalls   int
	after       string
	limit       int
	kind        InventoryKind
	parent      domain.ProductID
	relation    RelationshipPage
	capability  CapabilityPage
	session     SessionPage
	home        HomeSummary
	mutation    AgentMutationResult
	updated     AgentOwnershipInput
	expected    int64
	idempotency string
}

func (repository *inventoryRepositoryStub) ListInventoryPage(_ context.Context, _ domain.Scope, kind InventoryKind, after string, limit int) (InventoryPage, error) {
	repository.pageCalls++
	repository.kind, repository.after, repository.limit = kind, after, limit
	return repository.page, nil
}
func (repository *inventoryRepositoryStub) GetInventory(context.Context, domain.Scope, domain.ProductID, InventoryKind) (InventoryDetail, error) {
	return repository.detail, nil
}
func (repository *inventoryRepositoryStub) ListAgentCapabilitiesPage(_ context.Context, _ domain.Scope, parent domain.ProductID, after string, limit int) (CapabilityPage, error) {
	repository.parent, repository.after, repository.limit = parent, after, limit
	return repository.capability, nil
}
func (repository *inventoryRepositoryStub) ListAgentRelationshipsPage(_ context.Context, _ domain.Scope, parent domain.ProductID, after string, limit int) (RelationshipPage, error) {
	repository.parent, repository.after, repository.limit = parent, after, limit
	return repository.relation, nil
}
func (repository *inventoryRepositoryStub) ListAgentSessionsPage(_ context.Context, _ domain.Scope, parent domain.ProductID, after string, limit int) (SessionPage, error) {
	repository.parent, repository.after, repository.limit = parent, after, limit
	return repository.session, nil
}
func (repository *inventoryRepositoryStub) GetHomeSummary(context.Context, domain.Scope) (HomeSummary, error) {
	return repository.home, nil
}
func (repository *inventoryRepositoryStub) UpdateAgentOwnership(_ context.Context, _ RequestIdentity, _ domain.ProductID, expected int64, idempotency string, input AgentOwnershipInput, _, _ string) (AgentMutationResult, error) {
	repository.expected, repository.idempotency, repository.updated = expected, idempotency, input
	return repository.mutation, nil
}

func inventoryRequest(t *testing.T, operation, target string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, target, nil)
	principal, err := domain.ParseProductID("pid_50000001-0000-4000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, RequestIdentity{PrincipalID: principal, Scope: inventoryScope(t), Permissions: []string{"view"}, CredentialKind: CredentialBearerToken}))
	return request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: operation, PathParameters: map[string]string{"id": "pid_10000001-0000-4000-8000-000000000001"}}))
}

func TestInventoryHandlerBindsCursorScopeKindOperationParentAndLimit(t *testing.T) {
	lastID := "pid_10000002-0000-4000-8000-000000000002"
	repository := &inventoryRepositoryStub{page: InventoryPage{Items: []InventorySummary{{ID: lastID}}, NextKey: lastID}}
	handler, err := newInventoryHTTPHandler(repository, []byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, inventoryRequest(t, "listAgents", "https://app.zasp.test/api/v1/agents?limit=1"))
	if response.Code != http.StatusOK || repository.kind != InventoryKindAgent || repository.limit != 1 {
		t.Fatalf("first status=%d kind=%q limit=%d body=%s", response.Code, repository.kind, repository.limit, response.Body.String())
	}
	var envelope struct {
		PageInfo struct {
			NextCursor *string `json:"next_cursor"`
		} `json:"page_info"`
	}
	if json.Unmarshal(response.Body.Bytes(), &envelope) != nil || envelope.PageInfo.NextCursor == nil {
		t.Fatalf("missing cursor: %s", response.Body.String())
	}
	cursor := *envelope.PageInfo.NextCursor
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, inventoryRequest(t, "listAgents", "https://app.zasp.test/api/v1/agents?limit=1&cursor="+cursor))
	if response.Code != http.StatusOK || repository.after != lastID || repository.pageCalls != 2 {
		t.Fatalf("next status=%d after=%q calls=%d body=%s", response.Code, repository.after, repository.pageCalls, response.Body.String())
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, inventoryRequest(t, "listTools", "https://app.zasp.test/api/v1/tools?limit=1&cursor="+cursor))
	if response.Code != http.StatusNotFound || repository.pageCalls != 2 {
		t.Fatalf("foreign status=%d calls=%d", response.Code, repository.pageCalls)
	}
}

func TestInventoryHandlerRejectsUnknownQueryBeforeRepository(t *testing.T) {
	repository := &inventoryRepositoryStub{}
	handler, err := newInventoryHTTPHandler(repository, []byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"https://app.zasp.test/api/v1/agents?limit=101", "https://app.zasp.test/api/v1/agents?cursor=%25%25%25", "https://app.zasp.test/api/v1/agents?secret=one"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, inventoryRequest(t, "listAgents", target))
		if response.Code != http.StatusBadRequest && response.Code != http.StatusNotFound {
			t.Fatalf("target=%s status=%d body=%s", target, response.Code, response.Body.String())
		}
	}
	if repository.pageCalls != 0 {
		t.Fatalf("invalid query calls=%d", repository.pageCalls)
	}
}

func TestInventoryHandlerUpdatesAgentOwnershipWithExactPreconditions(t *testing.T) {
	agentID := "pid_10000001-0000-4000-8000-000000000001"
	auditID := "pid_60000001-0000-4000-8000-000000000001"
	repository := &inventoryRepositoryStub{mutation: AgentMutationResult{Agent: InventorySummary{ID: agentID, Name: "Agent", Kind: InventoryKindAgent, Owner: "security", Team: "platform", Tags: []string{"critical", "production"}, EvidenceID: "pid_20000006-0000-4000-8000-000000000006", ConfidenceBasisPoints: 9500, FirstSeen: "2026-08-18T09:00:00Z", LastSeen: "2026-08-18T10:00:00Z", ObservedAt: "2026-08-18T10:00:00Z", FreshUntil: "2026-08-18T10:15:00Z", FreshnessState: "fresh", Version: 2}, AuditID: auditID}}
	handler, err := newInventoryHTTPHandler(repository, []byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	request := inventoryRequest(t, "updateAgent", "https://app.zasp.test/api/v1/agents/"+agentID)
	request.Method = http.MethodPatch
	request.Body = io.NopCloser(strings.NewReader(`{"owner":"security","team":"platform","tags":["production","critical"]}`))
	request.Header.Set("If-Match", `"1"`)
	request.Header.Set("Idempotency-Key", "agent-owner-key-0001")
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(context.WithValue(request.Context(), correlationContextKey{}, "pid_60000002-0000-4000-8000-000000000002"))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"2"` || response.Header().Get("X-Audit-ID") != auditID || repository.expected != 1 || repository.idempotency != "agent-owner-key-0001" || !reflect.DeepEqual(repository.updated.Tags, []string{"critical", "production"}) {
		t.Fatalf("status=%d headers=%v expected=%d key=%q input=%#v body=%s", response.Code, response.Header(), repository.expected, repository.idempotency, repository.updated, response.Body.String())
	}
}

func TestInventoryHandlerRejectsMalformedOwnershipBeforeRepository(t *testing.T) {
	for name, mutate := range map[string]func(*http.Request){
		"missing version": func(request *http.Request) { request.Header.Del("If-Match") },
		"unknown field": func(request *http.Request) {
			request.Body = io.NopCloser(strings.NewReader(`{"owner":"security","team":"platform","tags":[],"credential_reference":"ref:secret/value"}`))
		},
		"duplicate tag": func(request *http.Request) {
			request.Body = io.NopCloser(strings.NewReader(`{"owner":"security","team":"platform","tags":["critical","critical"]}`))
		},
	} {
		t.Run(name, func(t *testing.T) {
			repository := &inventoryRepositoryStub{}
			handler, err := newInventoryHTTPHandler(repository, []byte("01234567890123456789012345678901"))
			if err != nil {
				t.Fatal(err)
			}
			request := inventoryRequest(t, "updateAgent", "https://app.zasp.test/api/v1/agents/pid_10000001-0000-4000-8000-000000000001")
			request.Method = http.MethodPatch
			request.Body = io.NopCloser(strings.NewReader(`{"owner":"security","team":"platform","tags":[]}`))
			request.Header.Set("If-Match", `"1"`)
			request.Header.Set("Idempotency-Key", "agent-owner-key-0001")
			request.Header.Set("Content-Type", "application/json")
			mutate(request)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code < 400 || repository.idempotency != "" {
				t.Fatalf("status=%d repository key=%q body=%s", response.Code, repository.idempotency, response.Body.String())
			}
		})
	}
}
