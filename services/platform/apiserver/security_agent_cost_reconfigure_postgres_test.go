package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestProductionSecurityAgentCostReconfigurationPreservesAdmittedRun(t *testing.T) {
	for _, mode := range []string{"increase", "remove"} {
		t.Run(mode, func(t *testing.T) {
			runSecurityAgentCostDefinitionFixture(t, func(ctx context.Context, owner *pgx.Conn, repository *PostgresRepository, identity RequestIdentity, id string) {
				identity.FreshAuthenticated = true
				identity.FreshAuthExpiresAt = time.Now().UTC().Add(4 * time.Minute)
				for index, target := range []string{"validated", "supervised"} {
					_, err := repository.ActivateSecurityAgent(ctx, identity, SecurityAgentActivation{DefinitionID: id, IdempotencyKey: "reconfigure-activate-" + target, ExpectedVersion: int64(index + 2), TargetActivation: target, FreshAuthExpiresAt: identity.FreshAuthExpiresAt, AuditID: "pid_aa000001-0000-4000-8000-00000000000" + strconv.Itoa(index+1), CorrelationID: "pid_bb000001-0000-4000-8000-000000000001", ReceiptID: "pid_cc000001-0000-4000-8000-00000000000" + strconv.Itoa(index+1)})
					if err != nil {
						t.Fatal(err)
					}
				}
				const findingID = "pid_ad000001-0000-4000-8000-000000000001"
				const runID = "pid_ad000002-0000-4000-8000-000000000002"
				if _, err := owner.Exec(ctx, `INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$4,'posture','exposed_credential','Budget reconfiguration fixture','high','open')`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), findingID); err != nil {
					t.Fatal(err)
				}
				run, err := repository.RunSecurityAgent(ctx, identity, SecurityAgentRunRequest{DefinitionID: id, IdempotencyKey: "reconfigure-manual-run-0001", RunID: runID, TriggerKind: "finding", TriggerID: findingID, ExpectedVersion: 4, AuditID: "pid_ad000003-0000-4000-8000-000000000003", CorrelationID: "pid_ad000004-0000-4000-8000-000000000004", ReceiptID: "pid_ad000005-0000-4000-8000-000000000005"})
				if err != nil || run.ID != runID || run.DefinitionVersion != 4 {
					t.Fatalf("manual run=%+v err=%v", run, err)
				}
				config := owner.Config().Copy()
				config.User = "security_agent_v33_worker_login"
				worker, err := pgx.ConnectConfig(ctx, config)
				if err != nil {
					t.Fatal(err)
				}
				defer worker.Close(context.Background())
				database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
				if err != nil {
					t.Fatal(err)
				}
				workerRepository, err := NewSecurityAgentWorkerRepository(database)
				if err != nil {
					t.Fatal(err)
				}
				claims, err := workerRepository.ClaimSecurityAgentRuns(ctx, "reconfigure-worker", "reconfigure-worker-lease-0001", 120, 1)
				if err != nil || len(claims) != 1 || claims[0].RunID != runID {
					t.Fatalf("claims=%+v err=%v", claims, err)
				}
				snapshot := func() string {
					t.Helper()
					var body string
					var exact bool
					if err := owner.QueryRow(ctx, `SELECT to_jsonb(b)::text,max_cost_nano_credits=987654321 AND definition_version=4 AND max_tokens=1000 AND max_steps=1 AND deadline_at=started_at+interval '300 seconds' FROM zasp_security_agent_run_budgets b WHERE run_id=$1`, runID).Scan(&body, &exact); err != nil || !exact {
						t.Fatalf("original budget authority exact=%v err=%v", exact, err)
					}
					return body
				}
				before := snapshot()
				value, err := repository.GetWorkflow(ctx, identity.Scope, "security_agent", id)
				if err != nil || value.Version != 4 {
					t.Fatalf("definition=%+v err=%v", value, err)
				}
				var definition map[string]any
				if err := json.Unmarshal(value.Body, &definition); err != nil {
					t.Fatal(err)
				}
				definition["enabled"] = false
				if mode == "increase" {
					definition["max_ai_cost_nano_credits"] = int64(1000000000000)
				} else {
					delete(definition, "max_ai_cost_nano_credits")
				}
				body, err := json.Marshal(definition)
				if err != nil {
					t.Fatal(err)
				}
				handler, err := newWorkflowHTTPHandler(repository, []byte("0123456789abcdef0123456789abcdef"), time.Now)
				if err != nil {
					t.Fatal(err)
				}
				sendUpdate := func(payload []byte) *httptest.ResponseRecorder {
					request := workflowRequest(t, identity, "pid_ac000001-0000-4000-8000-000000000001", "updateSecurityAgent", map[string]string{"id": id}, http.MethodPut, "/api/v1/security-agents/"+id, string(payload))
					request.Header.Set("If-Match", `"4"`)
					request.Header.Set("Idempotency-Key", "reconfigure-definition-0001")
					response := httptest.NewRecorder()
					handler.ServeHTTP(response, request)
					return response
				}
				response := sendUpdate(body)
				if response.Code != http.StatusOK {
					t.Fatalf("update status=%d body=%s", response.Code, response.Body.String())
				}
				state, err := repository.GetSecurityAgentActivation(ctx, identity, id)
				if err != nil || state.Activation != "draft" || state.Enabled || state.Version != 5 {
					t.Fatalf("edited state=%+v err=%v", state, err)
				}
				var stored map[string]json.RawMessage
				if err := json.Unmarshal(response.Body.Bytes(), &stored); err != nil {
					t.Fatal(err)
				}
				want := "1000000000000"
				if mode == "remove" {
					want = ""
				}
				if string(stored["max_ai_cost_nano_credits"]) != want {
					t.Fatalf("edited cost=%s want=%s", stored["max_ai_cost_nano_credits"], want)
				}
				if snapshot() != before {
					t.Fatal("definition edit changed existing run budget or deadline")
				}
				var auditVersion int64
				if err := owner.QueryRow(ctx, `SELECT resource_version FROM zasp_workflow_audit WHERE organization_id=$1 AND audit_id=$2`, identity.Scope.OrganizationID().String(), response.Header().Get("X-Audit-ID")).Scan(&auditVersion); err != nil || auditVersion != 5 {
					t.Fatalf("public audit version=%d err=%v", auditVersion, err)
				}
				_, err = repository.ActivateSecurityAgent(ctx, identity, SecurityAgentActivation{DefinitionID: id, IdempotencyKey: "reconfigure-revalidate-0001", ExpectedVersion: 5, TargetActivation: "validated", FreshAuthExpiresAt: identity.FreshAuthExpiresAt, AuditID: "pid_ae000001-0000-4000-8000-000000000001", CorrelationID: "pid_ae000002-0000-4000-8000-000000000002", ReceiptID: "pid_ae000003-0000-4000-8000-000000000003"})
				if err != nil {
					t.Fatal(err)
				}
				// Direct repository call bypasses the HTTP pre-read: SQL itself must reject stale CAS.
				intent, _ := json.Marshal(map[string]any{"body": definition, "resource_id": id, "expected_version": 4})
				sqlReplay, err := repository.MutateWorkflow(ctx, identity, WorkflowMutation{Action: "update", Kind: "security_agent", ID: id, Operation: "updateSecurityAgent", IdempotencyKey: "reconfigure-definition-0001", ExpectedVersion: 4, Intent: intent, Body: body, AuditID: "pid_af000001-0000-4000-8000-000000000001", CorrelationID: "pid_af000002-0000-4000-8000-000000000002", ReceiptID: "pid_af000003-0000-4000-8000-000000000003"})
				if err != nil || !sqlReplay.Replayed || sqlReplay.Version != 5 || sqlReplay.AuditID != response.Header().Get("X-Audit-ID") || sqlReplay.ReceiptID != response.Header().Get("X-Mutation-Receipt-ID") {
					t.Fatalf("direct SQL replay=%+v err=%v", sqlReplay, err)
				}
				_, err = repository.MutateWorkflow(ctx, identity, WorkflowMutation{Action: "update", Kind: "security_agent", ID: id, Operation: "updateSecurityAgent", IdempotencyKey: "reconfigure-stale-direct-0001", ExpectedVersion: 4, Intent: intent, Body: body, AuditID: "pid_af000001-0000-4000-8000-000000000001", CorrelationID: "pid_af000002-0000-4000-8000-000000000002", ReceiptID: "pid_af000003-0000-4000-8000-000000000003"})
				if !errors.Is(err, ErrRepositoryConflict) {
					t.Fatalf("stale SQL CAS err=%v", err)
				}
				replay := sendUpdate(body)
				if replay.Code != http.StatusOK || replay.Body.String() != response.Body.String() || replay.Header().Get("ETag") != response.Header().Get("ETag") || replay.Header().Get("X-Mutation-Receipt-ID") != response.Header().Get("X-Mutation-Receipt-ID") {
					t.Fatalf("replay status=%d body=%s", replay.Code, replay.Body.String())
				}
				definition["name"] = "Conflicting reused key"
				conflictingBody, _ := json.Marshal(definition)
				conflict := sendUpdate(conflictingBody)
				if conflict.Code != http.StatusConflict {
					t.Fatalf("conflicting replay status=%d body=%s", conflict.Code, conflict.Body.String())
				}
				state, err = repository.GetSecurityAgentActivation(ctx, identity, id)
				if err != nil || state.Version != 6 || state.Activation != "validated" {
					t.Fatalf("replay/stale calls changed state=%+v err=%v", state, err)
				}
				request := workflowRequest(t, identity, "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "deleteSecurityAgent", map[string]string{"id": id}, http.MethodDelete, "/api/v1/security-agents/"+id, "")
				request.Header.Set("If-Match", `"6"`)
				request.Header.Set("Idempotency-Key", "reconfigure-delete-0001")
				deleted := httptest.NewRecorder()
				handler.ServeHTTP(deleted, request)
				if deleted.Code != http.StatusNoContent {
					t.Fatalf("delete after activation status=%d body=%s", deleted.Code, deleted.Body.String())
				}
				if err := owner.QueryRow(ctx, `SELECT resource_version FROM zasp_workflow_audit WHERE organization_id=$1 AND audit_id=$2`, identity.Scope.OrganizationID().String(), deleted.Header().Get("X-Audit-ID")).Scan(&auditVersion); err != nil || auditVersion != 7 {
					t.Fatalf("delete audit version=%d err=%v", auditVersion, err)
				}
				if snapshot() != before {
					t.Fatal("replay, revalidation or deletion changed admitted budget")
				}
				var zeroEffects bool
				if err := owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_security_agent_effects) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_provider_reservations)`).Scan(&zeroEffects); err != nil || !zeroEffects {
					t.Fatalf("unexpected execution: zero=%v err=%v", zeroEffects, err)
				}
			})
		})
	}
}
