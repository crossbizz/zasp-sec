package apiserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSecurityAgentManualMutationProvenance(t *testing.T) {
	const runID = "pid_78000001-0000-4000-8000-000000000001"
	const approvalID = "pid_78000002-0000-4000-8000-000000000002"
	const auditID = "pid_78000005-0000-4000-8000-000000000005"
	const receiptID = "pid_78000007-0000-4000-8000-000000000007"
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	manual := map[string]any{"kind": "manual", "intent_digest": "sha256:" + strings.Repeat("a", 64), "version": 1}
	for _, operation := range []string{"cancel", "approve"} {
		for _, variant := range []string{"fresh", "replay", "null provenance", "mixed evidence", "null evidence", "wrong version", "foreign receipt", "missing fresh auth"} {
			if operation == "cancel" && variant == "missing fresh auth" {
				continue
			}
			t.Run(operation+"/"+variant, func(t *testing.T) {
				value := map[string]any{"id": runID, "agent_id": "pid_78000004-0000-4000-8000-000000000004", "state": "cancelled", "evidence_ids": []string{}, "definition_version": 1, "version": 2, "manual_trigger": manual, "audit_id": auditID, "correlation_id": testCorrelationID, "receipt_id": receiptID, "replayed": false}
				statement, operationID, path, body, id, evidence := postgresSecurityAgentCancelRunSQL, "cancelSecurityAgentRun", "/api/v1/security-agent-runs/"+runID+"/cancel", "", runID, "evidence_ids"
				if operation == "approve" {
					value = map[string]any{"id": approvalID, "run_id": runID, "step_id": "pid_78000003-0000-4000-8000-000000000003", "state": "approved", "expires_at": now.Add(time.Minute).Format(time.RFC3339), "version": 2, "expected_effect": "Create run-scoped evidence export", "reversible": true, "ttl_seconds": 0, "evidence_summary": []string{}, "manual_trigger": manual, "audit_id": auditID, "correlation_id": testCorrelationID, "receipt_id": receiptID, "replayed": false}
					statement, operationID, path, body, id, evidence = postgresSecurityAgentDecideApprovalSQL, "decideSecurityAgentApproval", "/api/v1/security-agent-approvals/"+approvalID+"/decision", `{"decision":"approved"}`, approvalID, "evidence_summary"
				}
				read := make(map[string]any)
				for key, item := range value {
					if key != "audit_id" && key != "correlation_id" && key != "receipt_id" && key != "replayed" {
						read[key] = item
					}
				}
				read["state"], read["version"] = "pending", 1
				switch variant {
				case "replay":
					value["replayed"] = true
					value["receipt_id"] = "pid_78000009-0000-4000-8000-000000000009"
				case "null provenance":
					value["manual_trigger"] = nil
				case "mixed evidence":
					value[evidence] = []string{"pid_78000004-0000-4000-8000-000000000004"}
				case "null evidence":
					value[evidence] = nil
				case "wrong version":
					value["version"] = 3
				case "foreign receipt":
					value["receipt_id"] = "pid_78000009-0000-4000-8000-000000000009"
				}
				raw, _ := json.Marshal(value)
				readRaw, _ := json.Marshal(read)
				database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{statement: raw, postgresSecurityAgentApprovalDetailSQL: readRaw}}
				repository := &PostgresRepository{database: database, securityAgentExecution: true}
				ids := []string{auditID, receiptID}
				handler, err := NewSecurityAgentPublicHTTPHandler(repository, http.NotFoundHandler(), SecurityAgentPublicHandlerConfig{Clock: func() time.Time { return now }, SigningKey: securityAgentTestSigningKey, NewProductID: func() (string, error) { id := ids[0]; ids = ids[1:]; return id, nil }})
				if err != nil {
					t.Fatal(err)
				}
				identity := fixtureRequestIdentity(t)
				identity.CredentialKind = CredentialBrowserSession
				identity.FreshAuthenticated = variant != "missing fresh auth"
				identity.FreshAuthExpiresAt = now.Add(time.Minute)
				request := workflowRequest(t, identity, testCorrelationID, operationID, map[string]string{"id": id}, http.MethodPost, path, body)
				request.Header.Set("Idempotency-Key", "manual-mutation-0001")
				request.Header.Set("If-Match", `"1"`)
				request.Header.Set("X-Zasp-Fresh-Auth", "confirmed")
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if variant != "fresh" && variant != "replay" {
					if response.Code == http.StatusOK {
						t.Fatal("invalid mutation response accepted")
					}
					return
				}
				if response.Code != http.StatusOK {
					t.Fatalf("valid manual mutation refused: %d %s", response.Code, response.Body.String())
				}
				var projected map[string]json.RawMessage
				if json.Unmarshal(response.Body.Bytes(), &projected) != nil {
					t.Fatal("invalid public response")
				}
				var got map[string]any
				if json.Unmarshal(projected["manual_trigger"], &got) != nil || got["intent_digest"] != manual["intent_digest"] || string(projected[evidence]) != "[]" {
					t.Fatal("mutation lost manual provenance")
				}
				if response.Header().Get("X-Mutation-Receipt-ID") != value["receipt_id"] || response.Header().Get("ETag") != `"2"` {
					t.Fatal("mutation lost original receipt or version")
				}
			})
		}
	}
}
