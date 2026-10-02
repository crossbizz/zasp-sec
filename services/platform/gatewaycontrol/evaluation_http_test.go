package gatewaycontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

type evaluationHTTPRepository struct{ *controlRepositoryStub }

func (r evaluationHTTPRepository) Record(ctx context.Context, event DecisionEvent) error {
	if !validDecisionEvent(event) {
		return errPostgresRepository
	}
	return r.controlRepositoryStub.Record(ctx, event)
}

func TestEvaluationRiskSignedHTTP(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	public, private := fixtureGatewayKey(t)
	authority := fixtureAuthority(public)
	for _, tc := range []struct {
		name, decision, risk string
		ids                  []string
	}{
		{"known block", "block", "high", []string{"policy-a"}},
		{"no match", "allow", "", []string{}},
		{"expired closed", "block", "", []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := evaluationHTTPRepository{&controlRepositoryStub{authority: authority}}
			handler, err := NewHTTPHandler(HTTPHandlerConfig{Repository: repo, Clock: func() time.Time { return now }, OperationTimeout: time.Second, MaximumBodyBytes: 16 * 1024})
			if err != nil {
				t.Fatal(err)
			}
			event := DecisionEvent{CredentialID: authority.CredentialID, DeviceID: authority.DeviceID, EventID: fixtureID(9), ExpectedFloor: 7, NextFloor: 8, PolicyVersion: 1, Decision: tc.decision, ActionKind: "mcp", PolicyIDs: tc.ids, Classification: map[string]string{"category": "runtime", "route_class": "local", "resource_class": "tool", "outcome": "requested", "session_id": fixtureID(11)}, OccurredAt: now, Evaluation: &EvaluationEvidence{Version: 1, Action: "tool_execute", AgentID: fixtureID(10), SessionID: fixtureID(11), ContributingPolicyIDs: tc.ids, Risk: tc.risk}}
			raw, _ := json.Marshal(event)
			request := httptest.NewRequest(http.MethodPost, "https://gateway-control.zasp.example"+DecisionPath, bytes.NewReader(raw))
			request.Header.Set("Content-Type", JSONMediaType)
			if err := SignRequest(request, raw, authority.CredentialID, private, now); err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusNoContent || !reflect.DeepEqual(repo.recorded, event) {
				t.Fatalf("signed event status=%d recorded=%#v body=%s", response.Code, repo.recorded, response.Body.String())
			}
			if tc.risk != "" {
				tampered := bytes.Replace(raw, []byte(`"risk":"high"`), []byte(`"risk":"critical"`), 1)
				request = httptest.NewRequest(http.MethodPost, "https://gateway-control.zasp.example"+DecisionPath, bytes.NewReader(tampered))
				request.Header.Set("Content-Type", JSONMediaType)
				if err := SignRequest(request, raw, authority.CredentialID, private, now); err != nil {
					t.Fatal(err)
				}
				response = httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if response.Code != http.StatusUnauthorized || repo.recordCalls != 1 {
					t.Fatal("tampered signed evaluation accepted", response.Code, repo.recordCalls)
				}
			}
		})
	}
}

func TestEvaluationRiskEventClone(t *testing.T) {
	original := DecisionEvent{PolicyIDs: []string{}, Evaluation: &EvaluationEvidence{Version: 1, ContributingPolicyIDs: []string{"policy-a"}, Risk: "high"}}
	clone := cloneDecisionEvent(original)
	if clone.PolicyIDs == nil {
		t.Error("empty matched policy list became absent")
	}
	clone.Evaluation.Risk = "low"
	clone.Evaluation.ContributingPolicyIDs[0] = "policy-b"
	if original.Evaluation.Risk != "high" || original.Evaluation.ContributingPolicyIDs[0] != "policy-a" {
		t.Fatal("event clone shares provenance")
	}
}

// The raw signed envelope must not erase evaluated evidence by decoding a null
// pointer or a later duplicate key. Omission remains the historical protocol.
func TestEvaluationRawEnvelopeSignedHTTP(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	public, private := fixtureGatewayKey(t)
	authority := fixtureAuthority(public)
	event := DecisionEvent{CredentialID: authority.CredentialID, DeviceID: authority.DeviceID, EventID: fixtureID(9), ExpectedFloor: 7, NextFloor: 8, PolicyVersion: 1, Decision: "block", ActionKind: "mcp", PolicyIDs: []string{"policy-a"}, Classification: map[string]string{"category": "runtime", "route_class": "local", "resource_class": "tool", "outcome": "requested", "session_id": fixtureID(11)}, OccurredAt: now}
	base, _ := json.Marshal(event)
	evaluation, _ := json.Marshal(EvaluationEvidence{Version: 1, Action: "tool_execute", AgentID: fixtureID(10), SessionID: fixtureID(11), ContributingPolicyIDs: []string{"policy-a"}, Risk: "high"})
	for _, tc := range []struct {
		name, suffix string
		status       int
	}{
		{"omitted", "", http.StatusNoContent},
		{"known", `,"evaluation":` + string(evaluation), http.StatusNoContent},
		{"null", `,"evaluation":null`, http.StatusBadRequest},
		{"annotated_then_null", `,"evaluation":` + string(evaluation) + `,"evaluation":null`, http.StatusBadRequest},
		{"null_then_annotated", `,"evaluation":null,"evaluation":` + string(evaluation), http.StatusBadRequest},
		{"equal_duplicate", `,"evaluation":` + string(evaluation) + `,"evaluation":` + string(evaluation), http.StatusBadRequest},
		{"case_null", `,"Evaluation":null`, http.StatusBadRequest},
		{"case_duplicate", `,"evaluation":` + string(evaluation) + `,"Evaluation":null`, http.StatusBadRequest},
		{"case_annotated", `,"EVALUATION":` + string(evaluation), http.StatusBadRequest},
		{"unknown_outer", `,"extra":true`, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := evaluationHTTPRepository{&controlRepositoryStub{authority: authority}}
			handler, err := NewHTTPHandler(HTTPHandlerConfig{Repository: repo, Clock: func() time.Time { return now }, OperationTimeout: time.Second, MaximumBodyBytes: 16 * 1024})
			if err != nil {
				t.Fatal(err)
			}
			raw := append(append([]byte{}, base[:len(base)-1]...), []byte(tc.suffix+"}")...)
			request := httptest.NewRequest(http.MethodPost, "https://gateway-control.zasp.example"+DecisionPath, bytes.NewReader(raw))
			request.Header.Set("Content-Type", JSONMediaType)
			if err := SignRequest(request, raw, authority.CredentialID, private, now); err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != tc.status {
				t.Fatalf("raw signed envelope status=%d want=%d body=%s", response.Code, tc.status, response.Body.String())
			}
			wantCalls := 0
			if tc.status == http.StatusNoContent {
				wantCalls = 1
			}
			if repo.recordCalls != wantCalls {
				t.Fatal("invalid envelope reached persistence", repo.recordCalls)
			}
		})
	}
}
