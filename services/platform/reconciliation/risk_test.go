package reconciliation

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestRemainingPostureRulesRequireExactEvidence(t *testing.T) {
	input := PostureInput{
		Scope: fixtureScope(t, 1), AgentID: fixtureID(t, 20), Owner: "security",
		ShellExecution: true, ProductionCredential: true, UnrestrictedEgress: true,
		SensitiveDataReach: true, UnapprovedRemoteTool: true, DestructiveTool: true,
		RuntimeControl: false, ProductionAgent: true, RuntimePolicySupported: false,
		HostFilesystem: true, Privileged: true, CICDWrite: true, ProductionSecretReach: true,
		AgentActive: false, CredentialActive: true,
		EvidenceIDs: []PostureEvidence{
			{Rule: RuleShellCredential, ID: fixtureID(t, 31)}, {Rule: RuleEgressSensitive, ID: fixtureID(t, 32)},
			{Rule: RuleUnapprovedTool, ID: fixtureID(t, 33)}, {Rule: RuleDestructiveNoControl, ID: fixtureID(t, 34)},
			{Rule: RuleNoRuntimeCoverage, ID: fixtureID(t, 35)}, {Rule: RuleWeakRuntimeIsolation, ID: fixtureID(t, 36)},
			{Rule: RuleCICDProductionSecret, ID: fixtureID(t, 37)}, {Rule: RuleZombieCredential, ID: fixtureID(t, 38)},
		},
	}
	findings, err := EvaluatePosture(context.Background(), input)
	if err != nil || len(findings) != 8 {
		t.Fatalf("findings=%+v err=%v", findings, err)
	}
	input.EvidenceIDs = input.EvidenceIDs[:7]
	if _, err := EvaluatePosture(context.Background(), input); err == nil {
		t.Fatal("matched rule without exact evidence passed")
	}
}

func TestRiskHTTPAuthorizedOperationsAndPreparseDenial(t *testing.T) {
	scope := fixtureScope(t, 1)
	findingID, agentID, pathID := fixtureID(t, 30), fixtureID(t, 20), fixtureID(t, 40)
	findings, err := NewFindingStore([]Finding{{ID: findingID, Scope: scope, AgentID: agentID, Source: FindingSourcePosture, Rule: RuleOwnerlessAgent, Title: "Owner missing", Severity: SeverityHigh, Status: FindingOpen, EvidenceIDs: []domain.ProductID{fixtureID(t, 31)}}})
	if err != nil {
		t.Fatal(err)
	}
	paths, err := NewAttackPathStore([]AttackPath{{ID: pathID, Scope: scope, EntryID: agentID, SinkID: fixtureID(t, 21), NodeIDs: []domain.ProductID{agentID, fixtureID(t, 22), fixtureID(t, 21)}, State: PathObserved, EvidenceIDs: []domain.ProductID{fixtureID(t, 41)}, BlockedEdge: 1}})
	if err != nil {
		t.Fatal(err)
	}
	search, err := NewSearchService([]SearchRecord{{ID: agentID, Scope: scope, Type: "agent", Name: "Support agent"}})
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewRiskService(findings, paths, search, HomeSummaryInput{Scope: scope, AgentCount: 1, HighRiskPaths: 1}, []byte("fixture-signing-key"), func(context.Context, []byte, string) (string, error) { return "ticket-1", nil })
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewRiskHTTPHandler(service, func(*http.Request) (domain.Scope, error) { return scope, nil })
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		method, path, body string
		status             int
	}{
		{http.MethodGet, "/api/v1/findings", "", http.StatusOK},
		{http.MethodGet, "/api/v1/findings/" + findingID.String(), "", http.StatusOK},
		{http.MethodPatch, "/api/v1/findings/" + findingID.String(), `{"status":"under_review"}`, http.StatusOK},
		{http.MethodPost, "/api/v1/findings/" + findingID.String() + "/accept-risk", `{"reason":"approved"}`, http.StatusOK},
		{http.MethodPost, "/api/v1/findings/" + findingID.String() + "/ticket", `{}`, http.StatusCreated},
		{http.MethodGet, "/api/v1/attack-paths", "", http.StatusOK},
		{http.MethodGet, "/api/v1/attack-paths/" + pathID.String(), "", http.StatusOK},
		{http.MethodGet, "/api/v1/attack-paths/" + pathID.String() + "/break-options", "", http.StatusOK},
		{http.MethodGet, "/api/v1/home/summary", "", http.StatusOK},
		{http.MethodGet, "/api/v1/search?q=support&limit=10", "", http.StatusOK},
	}
	for _, item := range cases {
		request := httptest.NewRequest(item.method, item.path, bytes.NewBufferString(item.body))
		if item.body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != item.status {
			t.Fatalf("%s %s status=%d body=%s", item.method, item.path, response.Code, response.Body.String())
		}
	}
	denied, _ := NewRiskHTTPHandler(service, func(*http.Request) (domain.Scope, error) { return domain.Scope{}, errors.New("denied") })
	request := httptest.NewRequest(http.MethodPatch, "/api/v1/findings/"+findingID.String(), bytes.NewBufferString(`{"status":`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	denied.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("denied status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestFindingLifecycleRelevanceRiskAndSignedTicket(t *testing.T) {
	scope := fixtureScope(t, 1)
	agentID := fixtureID(t, 20)
	store, err := NewFindingStore([]Finding{
		{ID: fixtureID(t, 30), Scope: scope, AgentID: agentID, Source: FindingSourcePosture, Rule: RuleOwnerlessAgent, Title: "Owner missing", Severity: SeverityHigh, Status: FindingOpen, EvidenceIDs: []domain.ProductID{fixtureID(t, 31)}, Factors: []RiskFactor{{Name: "production", EvidenceID: fixtureID(t, 31)}}},
		{ID: fixtureID(t, 32), Scope: scope, Source: FindingSourceProwler, Title: "Unrelated cloud record", Severity: SeverityMedium, Status: FindingOpen, EvidenceIDs: []domain.ProductID{fixtureID(t, 33)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	visible, err := store.List(context.Background(), scope, FindingFilter{VisibleByDefault: true})
	if err != nil || len(visible) != 1 || visible[0].AgentID != agentID || len(visible[0].Factors) != 1 {
		t.Fatalf("visible=%+v err=%v", visible, err)
	}
	updated, err := store.Update(context.Background(), scope, visible[0].ID, FindingUnderReview)
	if err != nil || updated.Status != FindingUnderReview {
		t.Fatalf("updated=%+v err=%v", updated, err)
	}
	accepted, err := store.AcceptRisk(context.Background(), scope, visible[0].ID, "approved exception")
	if err != nil || accepted.Status != FindingAccepted || accepted.AcceptanceReason != "approved exception" {
		t.Fatalf("accepted=%+v err=%v", accepted, err)
	}
	secret := []byte("fixture-signing-key")
	var payload []byte
	ticket, err := store.CreateTicket(context.Background(), scope, visible[0].ID, secret, func(_ context.Context, body []byte, signature string) (string, error) {
		payload = append([]byte(nil), body...)
		mac := hmac.New(sha256.New, secret)
		_, _ = mac.Write(body)
		if signature != hex.EncodeToString(mac.Sum(nil)) {
			t.Fatal("invalid signature")
		}
		return "ticket-1", nil
	})
	if err != nil || ticket != "ticket-1" || string(payload) == "" || string(payload) == string(secret) {
		t.Fatalf("ticket=%q payload=%q err=%v", ticket, payload, err)
	}
}

func TestAttackPathBreakOptionsHomeAndSafeSearch(t *testing.T) {
	scope := fixtureScope(t, 1)
	paths, err := NewAttackPathStore([]AttackPath{{ID: fixtureID(t, 40), Scope: scope, EntryID: fixtureID(t, 20), SinkID: fixtureID(t, 21), NodeIDs: []domain.ProductID{fixtureID(t, 20), fixtureID(t, 22), fixtureID(t, 21)}, State: PathObserved, EvidenceIDs: []domain.ProductID{fixtureID(t, 41)}, BlockedEdge: 1}})
	if err != nil {
		t.Fatal(err)
	}
	values, err := paths.List(context.Background(), scope)
	options, optionsErr := paths.BreakOptions(context.Background(), scope, fixtureID(t, 40))
	if err != nil || optionsErr != nil || len(values) != 1 || len(options) != 2 || options[0].PathID != fixtureID(t, 40) {
		t.Fatalf("paths=%+v options=%+v err=%v/%v", values, options, err, optionsErr)
	}
	summary, err := BuildHomeSummary(context.Background(), HomeSummaryInput{Scope: scope, AgentCount: 2, HighRiskPaths: 1, SourceStale: true, CoverageDegraded: false, VerifiedChanges: 1, BlockedChanges: 1})
	if err != nil || summary.Healthy || !summary.AttentionRequired {
		t.Fatalf("summary=%+v err=%v", summary, err)
	}
	search, err := NewSearchService([]SearchRecord{{ID: fixtureID(t, 20), Scope: scope, Type: "agent", Name: "Support agent"}, {ID: fixtureID(t, 21), Scope: fixtureScope(t, 50), Type: "agent", Name: "Foreign agent"}})
	if err != nil {
		t.Fatal(err)
	}
	results, err := search.Query(context.Background(), scope, "support", 10)
	if err != nil || len(results) != 1 || results[0].Name != "Support agent" {
		t.Fatalf("results=%+v err=%v", results, err)
	}
	if _, err := search.Query(context.Background(), scope, "MATCH (n)", 10); err == nil {
		t.Fatal("raw graph query passed")
	}
}
