package apiserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

// These exercise the mounted production handler and PostgresRepository together.
// Only the SQL transport is replaced; MemoryStore and legacy handlers are absent.
func TestProductionRedTeamHandlerOperationAcceptance(t *testing.T) {
	const definitionID = "pid_79000501-0000-4000-8000-000000000001"
	const targetID = "pid_79000502-0000-4000-8000-000000000002"
	const runID = "pid_79000503-0000-4000-8000-000000000003"
	const auditID = "pid_79000504-0000-4000-8000-000000000004"
	const receiptID = "pid_79000505-0000-4000-8000-000000000005"
	const idempotency = "red-team-acceptance-0001"
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	definition := RedTeamDefinition{ID: definitionID, Version: 1, Name: "Prompt safety", TargetID: targetID, TargetKind: "agent_endpoint", Categories: []string{"prompt_injection"}, Safety: RedTeamSafety{Environment: "staging", CredentialClass: "read_only", ExpectedSideEffects: []string{"audit event"}}, Enabled: true, CreatedAt: now, UpdatedAt: now}
	updated := definition
	updated.Version = 2
	run := RedTeamRun{ID: runID, Version: 1, DefinitionID: definitionID, DefinitionVersion: 1, Status: "queued", Attempt: 0, QueuedAt: now}
	cancelled := run
	cancelled.Version, cancelled.Status, cancelled.CancelRequested, cancelled.CompletedAt, cancelled.ErrorCode = 2, "cancelled", true, &now, "cancelled"
	definitionMutation := func(body RedTeamDefinition) RedTeamDefinitionMutationResult {
		return RedTeamDefinitionMutationResult{Body: body, AuditID: auditID, CorrelationID: testCorrelationID, ReceiptID: receiptID}
	}
	runMutation := func(body RedTeamRun) RedTeamRunMutationResult {
		return RedTeamRunMutationResult{Body: body, AuditID: auditID, CorrelationID: testCorrelationID, ReceiptID: receiptID}
	}
	createBody := map[string]any{"id": definitionID, "name": definition.Name, "target_id": targetID, "target_kind": definition.TargetKind, "categories": definition.Categories, "safety": definition.Safety}
	updateBody := map[string]any{"name": definition.Name, "target_id": targetID, "target_kind": definition.TargetKind, "categories": definition.Categories, "safety": definition.Safety, "enabled": true}
	jsonValue := func(value any) json.RawMessage {
		t.Helper()
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	cases := []struct {
		operation, method, path, resourceID, statement, etag, ifMatch string
		body, databaseResult, publicResult                            any
		status                                                        int
	}{
		{"listTests", http.MethodGet, "/api/v1/tests?limit=2", "", postgresRedTeamListDefinitionsSQL, "", "", nil, RedTeamDefinitionPage{Items: []RedTeamDefinition{definition}}, map[string]any{"items": []RedTeamDefinition{definition}}, 200},
		{"createTest", http.MethodPost, "/api/v1/tests", "", postgresRedTeamCreateDefinitionSQL, `"1"`, `"0"`, createBody, definitionMutation(definition), definition, 201},
		{"getTest", http.MethodGet, "/api/v1/tests/" + definitionID, definitionID, postgresRedTeamGetDefinitionSQL, `"1"`, "", nil, definition, definition, 200},
		{"updateTest", http.MethodPatch, "/api/v1/tests/" + definitionID, definitionID, postgresRedTeamUpdateDefinitionSQL, `"2"`, `"1"`, updateBody, definitionMutation(updated), updated, 200},
		{"runTest", http.MethodPost, "/api/v1/tests/" + definitionID + "/runs", definitionID, postgresRedTeamRunTestSQL, `"1"`, `"1"`, map[string]string{"run_id": runID}, runMutation(run), run, 202},
		{"listTestRuns", http.MethodGet, "/api/v1/test-runs?limit=2", "", postgresRedTeamListRunsSQL, "", "", nil, map[string]any{"items": []RedTeamRun{run}, "next_cursor": nil}, map[string]any{"items": []RedTeamRun{run}}, 200},
		{"getTestRun", http.MethodGet, "/api/v1/test-runs/" + runID, runID, postgresRedTeamGetRunSQL, `"1"`, "", nil, RedTeamRunDetail{RedTeamRun: run, Attempts: []RedTeamAttempt{}}, RedTeamRunDetail{RedTeamRun: run, Attempts: []RedTeamAttempt{}}, 200},
		{"cancelTestRun", http.MethodPost, "/api/v1/test-runs/" + runID + "/cancel", runID, postgresRedTeamCancelRunSQL, `"2"`, `"1"`, nil, runMutation(cancelled), cancelled, 200},
	}
	for _, operation := range cases {
		t.Run(operation.operation, func(t *testing.T) {
			for _, credential := range []CredentialKind{CredentialBrowserSession, CredentialBearerToken} {
				for _, unavailable := range []bool{false, true} {
					t.Run(string(credential)+map[bool]string{false: "/authorized", true: "/stable-error"}[unavailable], func(t *testing.T) {
						identity := fixtureRequestIdentity(t)
						identity.CredentialKind = credential
						database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{}}
						if !unavailable {
							database.responses[operation.statement] = jsonValue(operation.databaseResult)
						}
						repository := &PostgresRepository{database: database, schema: ProductionRecoverySchemaVersion}
						handler, err := NewRedTeamPublicHTTPHandler(repository, []byte("0123456789abcdef0123456789abcdef"))
						if err != nil {
							t.Fatal(err)
						}
						body := ""
						if operation.body != nil {
							body = string(jsonValue(operation.body))
						}
						request := workflowRequest(t, identity, testCorrelationID, operation.operation, map[string]string{"id": operation.resourceID}, operation.method, operation.path, body)
						if operation.ifMatch != "" {
							request.Header.Set("If-Match", operation.ifMatch)
							request.Header.Set("Idempotency-Key", idempotency)
						}
						response := httptest.NewRecorder()
						handler.ServeHTTP(response, request)
						if !reflect.DeepEqual(database.statements, []string{operation.statement}) {
							t.Fatalf("wrong production authority: %#v; response=%s", database.statements, response.Body.String())
						}
						arguments := database.arguments[0]
						if len(arguments) < 3 || !reflect.DeepEqual(arguments[:3], []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String()}) {
							t.Fatalf("tenant scope changed: %#v", arguments)
						}
						if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Content-Type") != "application/json" {
							t.Fatalf("response headers=%v", response.Header())
						}
						wantStatus, wantBody := operation.status, operation.publicResult
						if unavailable {
							wantStatus, wantBody = http.StatusServiceUnavailable, map[string]any{"code": "provider_unavailable", "message": "Provider unavailable", "correlation_id": testCorrelationID, "retryable": true}
							for _, header := range []string{"ETag", "X-Audit-ID", "X-Mutation-Receipt-ID"} {
								if response.Header().Get(header) != "" {
									t.Fatalf("error granted mutation authority: %s", header)
								}
							}
						} else {
							if response.Header().Get("ETag") != operation.etag {
								t.Fatalf("ETag=%q", response.Header().Get("ETag"))
							}
							if operation.ifMatch != "" {
								if response.Header().Get("X-Audit-ID") != auditID {
									t.Fatal("audit identity missing")
								}
								wantReceipt := ""
								if credential == CredentialBrowserSession {
									wantReceipt = receiptID
								}
								if response.Header().Get("X-Mutation-Receipt-ID") != wantReceipt {
									t.Fatal("browser/PAT receipt boundary changed")
								}
							}
						}
						var got, want any
						if json.Unmarshal(response.Body.Bytes(), &got) != nil || json.Unmarshal(jsonValue(wantBody), &want) != nil || response.Code != wantStatus || !reflect.DeepEqual(got, want) {
							t.Fatalf("response=%d %s; want=%d %s", response.Code, response.Body.String(), wantStatus, jsonValue(wantBody))
						}
					})
				}
			}
		})
	}
}
