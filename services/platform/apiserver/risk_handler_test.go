package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type riskRepositoryStub struct {
	finding       RiskFinding
	findingPage   RiskFindingPage
	path          RiskAttackPath
	pathPage      RiskAttackPathPage
	options       []RiskBreakOption
	home          json.RawMessage
	highCount     int64
	replay        RiskFindingMutationResult
	replayed      bool
	err           error
	scope         domain.Scope
	after         string
	limit         int
	pageCalls     int
	mutation      RiskFindingMutation
	mutationCalls int
	replayCalls   int
}

func (repository *riskRepositoryStub) GetRiskFinding(_ context.Context, scope domain.Scope, _ string) (RiskFinding, error) {
	repository.scope = scope
	return repository.finding, repository.err
}
func (repository *riskRepositoryStub) ListRiskFindingPage(_ context.Context, scope domain.Scope, after string, limit int) (RiskFindingPage, error) {
	repository.scope, repository.after, repository.limit = scope, after, limit
	repository.pageCalls++
	return repository.findingPage, repository.err
}
func (repository *riskRepositoryStub) GetRiskAttackPath(_ context.Context, scope domain.Scope, _ string) (RiskAttackPath, error) {
	repository.scope = scope
	return repository.path, repository.err
}
func (repository *riskRepositoryStub) ListRiskAttackPathPage(_ context.Context, scope domain.Scope, after string, limit int) (RiskAttackPathPage, error) {
	repository.scope, repository.after, repository.limit = scope, after, limit
	repository.pageCalls++
	return repository.pathPage, repository.err
}
func (repository *riskRepositoryStub) GetRiskBreakOptions(_ context.Context, scope domain.Scope, _ string) ([]RiskBreakOption, error) {
	repository.scope = scope
	return repository.options, repository.err
}
func (repository *riskRepositoryStub) CountHighRiskPaths(_ context.Context, scope domain.Scope) (int64, error) {
	repository.scope = scope
	return repository.highCount, repository.err
}
func (repository *riskRepositoryStub) Read(_ context.Context, scope domain.Scope, _ string) (json.RawMessage, error) {
	repository.scope = scope
	return repository.home, repository.err
}
func (repository *riskRepositoryStub) ReplayRiskFinding(_ context.Context, _ RequestIdentity, _, _ string, _ json.RawMessage) (RiskFindingMutationResult, bool, error) {
	repository.replayCalls++
	return repository.replay, repository.replayed, repository.err
}
func (repository *riskRepositoryStub) MutateRiskFinding(_ context.Context, _ RequestIdentity, mutation RiskFindingMutation) (RiskFindingMutationResult, error) {
	repository.mutation, repository.mutationCalls = mutation, repository.mutationCalls+1
	finding := repository.finding
	finding.Version = mutation.ExpectedVersion + 1
	finding.Status = mutation.Status
	finding.AcceptanceReason = mutation.Reason
	return RiskFindingMutationResult{Body: finding, Version: finding.Version, AuditID: mutation.AuditID, CorrelationID: mutation.CorrelationID, ReceiptID: mutation.ReceiptID}, repository.err
}

func fixtureRiskFinding() RiskFinding {
	created := time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC)
	return RiskFinding{ID: riskFindingID, Source: "posture", Title: "Public tool access", Severity: "high", Status: "open", EvidenceIDs: []string{riskEvidence}, RiskFactors: []RiskFactor{}, Version: 2, CreatedAt: created, UpdatedAt: created.Add(time.Second)}
}

func fixtureRiskPath() RiskAttackPath {
	created := time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC)
	return RiskAttackPath{ID: riskPathID, EntryID: riskNodeOne, SinkID: riskNodeTwo, NodeIDs: []string{riskNodeOne, riskNodeTwo}, State: "verified", EvidenceIDs: []string{riskEvidence}, BlockedEdge: -1, Version: 1, CreatedAt: created, UpdatedAt: created.Add(time.Second)}
}

func newRiskTestHandler(t *testing.T, repository *riskRepositoryStub) *riskHTTPHandler {
	t.Helper()
	handler, err := newRiskHTTPHandler(repository, []byte("0123456789abcdef0123456789abcdef"), func() time.Time { return time.Date(2026, 8, 19, 1, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func riskRequest(t *testing.T, identity RequestIdentity, operation, method, target, body string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
	request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: operation, PathParameters: map[string]string{"id": riskFindingID}}))
	request = request.WithContext(context.WithValue(request.Context(), correlationContextKey{}, "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"))
	return request
}

func TestRiskHandlerUsesSignedScopeOperationAndLimitBoundKeysets(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	repository := &riskRepositoryStub{findingPage: RiskFindingPage{Items: []RiskFinding{fixtureRiskFinding()}, NextID: riskFindingID}}
	handler := newRiskTestHandler(t, repository)
	request := riskRequest(t, identity, "listFindings", http.MethodGet, "https://app.zasp.test/api/v1/findings?limit=1", "")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var page struct {
		Items    []RiskFinding `json:"items"`
		PageInfo struct {
			NextCursor *string `json:"next_cursor"`
			HasMore    bool    `json:"has_more"`
		} `json:"page_info"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &page) != nil || page.PageInfo.NextCursor == nil || !page.PageInfo.HasMore {
		t.Fatalf("first page = %d %s", response.Code, response.Body.String())
	}
	cursor := *page.PageInfo.NextCursor
	request = riskRequest(t, identity, "listFindings", http.MethodGet, "https://app.zasp.test/api/v1/findings?limit=2&cursor="+cursor, "")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound || repository.pageCalls != 1 {
		t.Fatalf("limit-changed cursor = %d calls=%d %s", response.Code, repository.pageCalls, response.Body.String())
	}

	request = riskRequest(t, identity, "listAttackPaths", http.MethodGet, "https://app.zasp.test/api/v1/attack-paths?limit=1&cursor="+cursor, "")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound || repository.pageCalls != 1 {
		t.Fatalf("operation-changed cursor = %d calls=%d", response.Code, repository.pageCalls)
	}

	request = riskRequest(t, identity, "listFindings", http.MethodGet, "https://app.zasp.test/api/v1/findings?limit=1&cursor="+cursor, "")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || repository.after != riskFindingID || repository.limit != 1 || repository.scope != identity.Scope {
		t.Fatalf("next page = %d after=%q limit=%d scope=%#v", response.Code, repository.after, repository.limit, repository.scope)
	}
}

func TestRiskHandlerGetsTypedRiskRecordsAndETag(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	repository := &riskRepositoryStub{finding: fixtureRiskFinding(), path: fixtureRiskPath(), options: []RiskBreakOption{{PathID: riskPathID, TargetID: riskNodeOne, EvidenceID: riskEvidence, Kind: "remove_node", Rank: 1}}}
	handler := newRiskTestHandler(t, repository)

	request := riskRequest(t, identity, "getFinding", http.MethodGet, "https://app.zasp.test/api/v1/findings/"+riskFindingID, "")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"2"` || repository.scope != identity.Scope {
		t.Fatalf("finding = %d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
}

func TestRiskHandlerMutationsRequireStrictPreconditionsAndReturnBrowserReceipt(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	repository := &riskRepositoryStub{finding: fixtureRiskFinding()}
	handler := newRiskTestHandler(t, repository)
	request := riskRequest(t, identity, "updateFinding", http.MethodPatch, "https://app.zasp.test/api/v1/findings/"+riskFindingID, `{"status":"under_review"}`)
	request.Header.Set("If-Match", `"2"`)
	request.Header.Set("Idempotency-Key", "idem-risk-update-001")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"3"` || response.Header().Get("X-Audit-ID") == "" || response.Header().Get("X-Mutation-Receipt-ID") == "" || repository.mutationCalls != 1 || repository.mutation.ReceiptID == "" {
		t.Fatalf("browser mutation = %d headers=%v mutation=%#v body=%s", response.Code, response.Header(), repository.mutation, response.Body.String())
	}

	request = riskRequest(t, identity, "updateFinding", http.MethodPatch, "https://app.zasp.test/api/v1/findings/"+riskFindingID, `{"status":"open","extra":true}`)
	request.Header.Set("If-Match", `"2"`)
	request.Header.Set("Idempotency-Key", "idem-risk-update-002")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || repository.mutationCalls != 1 || repository.replayCalls != 1 {
		t.Fatalf("invalid body = %d mutation=%d replay=%d", response.Code, repository.mutationCalls, repository.replayCalls)
	}
}

func TestRiskHandlerPATMutationCreatesAuditButZeroBrowserReceipt(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBearerToken
	repository := &riskRepositoryStub{finding: fixtureRiskFinding()}
	handler := newRiskTestHandler(t, repository)
	request := riskRequest(t, identity, "acceptFindingRisk", http.MethodPost, "https://app.zasp.test/api/v1/findings/"+riskFindingID+"/accept-risk", `{"reason":"Approved exception"}`)
	request.Header.Set("If-Match", `"2"`)
	request.Header.Set("Idempotency-Key", "idem-risk-accept-001")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || repository.mutation.Status != "accepted" || repository.mutation.ReceiptID != "" || response.Header().Get("X-Mutation-Receipt-ID") != "" || response.Header().Get("X-Audit-ID") == "" {
		t.Fatalf("PAT mutation = %d headers=%v mutation=%#v", response.Code, response.Header(), repository.mutation)
	}
}

func TestRiskHandlerReplaysLostMutationWithoutWritingAgain(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	replayed := RiskFindingMutationResult{Body: fixtureRiskFinding(), Version: 2, AuditID: "pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", CorrelationID: "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", ReceiptID: "pid_cccccccc-cccc-4ccc-8ccc-cccccccccccc", Replayed: true}
	repository := &riskRepositoryStub{finding: fixtureRiskFinding(), replayed: true, replay: replayed}
	handler := newRiskTestHandler(t, repository)
	request := riskRequest(t, identity, "updateFinding", http.MethodPatch, "https://app.zasp.test/api/v1/findings/"+riskFindingID, `{"status":"under_review"}`)
	request.Header.Set("If-Match", `"1"`)
	request.Header.Set("Idempotency-Key", "idem-risk-update-001")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || repository.mutationCalls != 0 || response.Header().Get("X-Audit-ID") != replayed.AuditID || response.Header().Get("X-Mutation-Receipt-ID") != replayed.ReceiptID {
		t.Fatalf("replay = %d headers=%v mutation=%d body=%s", response.Code, response.Header(), repository.mutationCalls, response.Body.String())
	}
}

func TestRiskHandlerHomeSummaryUsesTypedProjectionCount(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	repository := &riskRepositoryStub{home: json.RawMessage(`{"agent_count":1,"high_risk_paths":999,"verified_changes":0,"blocked_changes":0,"pending_approvals":0,"oldest_approval_age_seconds":0,"needs_human_runs":0,"failed_runs":0,"inconclusive_runs":0,"recent_contained":0,"recent_remediated":0,"healthy":true,"attention_required":false}`), highCount: 3}
	handler := newRiskTestHandler(t, repository)
	request := riskRequest(t, identity, "getHomeSummary", http.MethodGet, "https://app.zasp.test/api/v1/home/summary", "")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var payload map[string]any
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &payload) != nil || payload["high_risk_paths"] != float64(3) {
		t.Fatalf("home = %d %s", response.Code, response.Body.String())
	}
}
