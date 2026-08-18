package aigateway

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGovernedExplanationBoundary(t *testing.T) {
	redacted, err := RedactApprovedFields(map[string]string{"title": "Credential exposed", "severity": "high", "secret": "token", "email": "person@example.invalid"})
	if err != nil || redacted["title"] != "Credential exposed" {
		t.Fatalf("redacted=%+v err=%v", redacted, err)
	}
	if _, ok := redacted["secret"]; ok {
		t.Fatal("secret retained")
	}
	redacted, err = RedactApprovedFields(map[string]string{"evidence_summary": "contact person@example.invalid with ghp_seededtoken or 123-45-6789"})
	if err != nil || redacted["evidence_summary"] != "contact [REDACTED] with [REDACTED] or [REDACTED]" {
		t.Fatalf("redacted=%+v err=%v", redacted, err)
	}
	called := 0
	governor, err := NewGovernor(GovernanceConfig{Purposes: []string{"finding_explanation"}, Models: []string{"approved-model"}, Providers: []string{"approved-provider"}, RequireNoStorage: true, MaximumTokens: 512, MaximumCostCents: 5, MaximumConcurrency: 1, Deadline: time.Second}, func(ctx context.Context, request GovernedRequest) (GovernedResult, error) {
		called++
		return GovernedResult{Explanation: "Bounded explanation", Recommendation: "Review evidence", Provider: "approved-provider", Model: "approved-model", NoStorage: true}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	request := GovernedRequest{Purpose: "finding_explanation", Model: "approved-model", Provider: "approved-provider", Tokens: 256, CostCents: 2, Fields: redacted, RequireNoStorage: true}
	result, err := governor.Generate(context.Background(), request)
	if err != nil || called != 1 || result.Explanation == "" {
		t.Fatalf("result=%+v calls=%d err=%v", result, called, err)
	}
	request.Model = "unapproved"
	if _, err := governor.Generate(context.Background(), request); err == nil || called != 1 {
		t.Fatalf("unapproved request calls=%d err=%v", called, err)
	}
	handler, err := NewGovernedHTTPHandler(governor, func(r *http.Request) bool { return r.Header.Get("Authorization") == "Bearer allowed" })
	if err != nil {
		t.Fatal(err)
	}
	body := `{"purpose":"finding_explanation","model":"approved-model","provider":"approved-provider","tokens":256,"cost_cents":2,"fields":{"title":"Credential exposed","severity":"high"},"require_no_storage":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ai/explanations", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer allowed")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	denied := httptest.NewRecorder()
	handler.ServeHTTP(denied, httptest.NewRequest(http.MethodPost, "/api/v1/ai/explanations", bytes.NewBufferString(body)))
	if denied.Code != http.StatusForbidden || !bytes.Contains(denied.Body.Bytes(), []byte("ai_governance_rejected")) {
		t.Fatalf("status=%d body=%s", denied.Code, denied.Body.String())
	}
}

func TestSecurityResponsePlanPurposeRejectsFreeFormGovernor(t *testing.T) {
	_, err := NewGovernor(GovernanceConfig{Purposes: []string{string(PurposeSecurityResponsePlan)}, Models: []string{"approved-model"}, Providers: []string{"approved-provider"}, RequireNoStorage: true, MaximumTokens: 512, MaximumCostCents: 5, MaximumConcurrency: 1, Deadline: time.Second}, func(context.Context, GovernedRequest) (GovernedResult, error) {
		return GovernedResult{}, nil
	})
	if err == nil || !IsStructuredPurpose(PurposeSecurityResponsePlan) {
		t.Fatalf("err=%v structured=%v", err, IsStructuredPurpose(PurposeSecurityResponsePlan))
	}
}
