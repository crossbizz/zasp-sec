package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Actual HTTP handlers, owned PostgreSQL and a real local Temporal worker.
// Authentication, planner TLS responses, artifacts and runner output are local
// controlled fixtures, not evidence of Stytch, S3 or Promptfoo deployment.
func TestTemporalWorkflowActualWorkerPostgres(t *testing.T) {
	runTemporalWorkflowActualWorker(t, "")
}
func TestTemporalWorkflowShippedCoexistencePostgres(t *testing.T) {
	t.Setenv("ZASP_P3C_SHIPPED_COEXISTENCE", "true")
	runTemporalWorkflowActualWorker(t, "")
}
func TestTemporalWorkflowActualCancellationPostgres(t *testing.T) {
	runTemporalWorkflowActualWorker(t, "applied")
}
func TestTemporalWorkflowActualReservedCancellationPostgres(t *testing.T) {
	runTemporalWorkflowActualWorker(t, "reserved")
}
func runTemporalWorkflowActualWorker(t *testing.T, cancelStage string) {
	cancelWorkflow := cancelStage != ""
	runTemporalDomainFreshFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		runTemporalMigrationCLI(t, ctx, owner, "up-temporal-domain")
		public62Seed(t, ctx, owner, o, w, e, testID, actor)
		seedOrderedApplicationGateway(t, ctx, owner, o, w, e)
		seedOrderedTestSource(t, ctx, owner, o, w, e, actor)
		runTemporalMigrationCLI(t, ctx, owner, "up-temporal-executor")
		if _, err := owner.Exec(ctx, `CREATE ROLE temporal_executor_test_login LOGIN; CREATE ROLE temporal_compensation_test_login LOGIN; SELECT zasp_temporal68.register_principals('temporal_executor_test_login','temporal_compensation_test_login')`); err != nil {
			t.Fatal(err)
		}
		runTemporalMigrationCLI(t, ctx, owner, "up-temporal-workflow")
		if os.Getenv("ZASP_P3C_SHIPPED_COEXISTENCE") == "true" {
			runTemporalMigrationCLI(t, ctx, owner, "up-temporal-compatibility")
			runTemporalMigrationCLI(t, ctx, owner, "up-temporal-legacy-tests")
		}
		redWorker, adapter := orderedTestConnections(t, ctx, owner)
		defer redWorker.Close(ctx)
		defer adapter.Close(ctx)
		db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
		if err != nil {
			t.Fatal(err)
		}
		authority, err := NewSecurityAgentOrderedResourceAuthority(db)
		if err != nil {
			t.Fatal(err)
		}
		handler := orderedHTTPHandler(t, authority, http.NotFoundHandler())
		_, identity := public62GoRepository(t, api, o, w, e, actor)
		identity.FreshAuthenticated = true
		identity.FreshAuthExpiresAt = time.Now().UTC().Add(5 * time.Minute)
		manualRun := ""
		if os.Getenv("ZASP_P3C_SHIPPED_COEXISTENCE") == "true" {
			manualRun = seedShippedManualAdmission(t, ctx, owner, db, identity, o, w, e, testID, actor)
		}
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_temporal66.admission_routes VALUES($1,$2,$3,'temporal')`, o, w, e); err != nil {
			t.Fatal(err)
		}
		call := func(id RequestIdentity, op, resource, body, key, version string) *httptest.ResponseRecorder {
			request := orderedHTTPRequest(id, op, http.MethodPost, resource, body).WithContext(context.WithValue(context.WithValue(ctx, identityContextKey{}, id), routedOperationContextKey{}, RoutedOperation{op, map[string]string{"id": resource}}))
			request.Header.Set("If-Match", `"`+version+`"`)
			request.Header.Set("Idempotency-Key", key)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			return response
		}
		activated := call(identity, "activateSecurityAgent", public62Definition, `{"activation":"supervised"}`, "p3c-activate-0001", "1")
		if activated.Code != http.StatusOK {
			t.Fatal("HTTP activation", activated.Code, activated.Body.String())
		}
		body := fmt.Sprintf(`{"environment_id":%q,"trigger_kind":"finding","trigger_id":%q,"trigger_version":1,"trigger_source":"credential"}`, e, public62Finding)
		admitted := call(identity, "runSecurityAgent", public62Definition, body, "p3c-trigger-0001", "2")
		if admitted.Code != http.StatusAccepted {
			t.Fatal("HTTP admission", admitted.Code, admitted.Body.String())
		}
		var envelope SecurityAgentRun
		if json.Unmarshal(admitted.Body.Bytes(), &envelope) != nil || envelope.ID == "" {
			t.Fatal("typed admission", admitted.Body.String())
		}
		run := envelope.ID
		if manualRun != "" {
			assertShippedLegacyCollections(t, ctx, owner, worker, manualRun, run)
		}
		var fresh bool
		if err := owner.QueryRow(ctx, `SELECT state='queued' AND NOT EXISTS(SELECT 1 FROM zasp_temporal68.planning_jobs WHERE run_id=$1) FROM zasp_security_agent_runs WHERE run_id=$1`, run).Scan(&fresh); err != nil || !fresh {
			t.Fatal("not fresh before worker", fresh, err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET role='organization_admin' WHERE principal_id=$1; UPDATE zasp_authorized_scopes SET permissions='["view","manage_identity","manage_workflows","run_tests"]' WHERE principal_id=$1`, pgx.QueryExecModeSimpleProtocol, orderedProgressionApprover); err != nil {
			t.Fatal(err)
		}
		adminCfg := owner.Config().Copy()
		adminCfg.User = "security_agent_v33_discovery_api_login"
		admin, err := pgx.ConnectConfig(ctx, adminCfg)
		if err != nil {
			t.Fatal(err)
		}
		defer admin.Close(ctx)
		pricingRequest := orderedPricingAdminRequest(o, w, e, orderedProgressionApprover)
		policy := pricingRequest["policy"].(map[string]any)
		policy["request_token_limit"], policy["request_policy_version"] = 512, "security-agent-planner-v1"
		digest := sha256.Sum256([]byte("sk-or-v1-test-token-1234567890"))
		policy["credential_digest"] = "sha256:" + hex.EncodeToString(digest[:])
		pricing, err := orderedPricingCall(ctx, admin, "pricing_admin", pricingRequest)
		if err != nil {
			t.Fatal(err)
		}
		selection := orderedPricingLookupRequest(o, w, e, policy, pricing)
		delete(selection, "body")
		delete(selection, "body_digest")
		binding := map[string]any{}
		for _, k := range []string{"account_profile", "credential_reference", "policy_id", "policy_version", "policy_digest", "account_id", "account_version"} {
			binding[k] = selection[k]
		}
		binding["organization_id"], binding["workspace_id"], binding["environment_id"] = o, w, e
		encoded, _ := json.Marshal(binding)
		childCtx, cancel := context.WithTimeout(ctx, 4*time.Minute)
		defer cancel()
		command := exec.CommandContext(childCtx, "go", "test", "./agentsec-worker", "-run", "^TestTemporalOwnedWorkflow$", "-count=1", "-v")
		command.Dir = ".."
		command.WaitDelay = 5 * time.Second
		command.Env = append(os.Environ(), "ZASP_TEMPORAL_JOURNAL_OWNER_DSN="+owner.Config().ConnString(), "ZASP_ORDERED_ORG="+o, "ZASP_ORDERED_WORKSPACE="+w, "ZASP_ORDERED_ENVIRONMENT="+e, "ZASP_TEMPORAL_PARENT="+run, "ZASP_TEMPORAL_TEST_ID="+testID, "ZASP_TEMPORAL_PLANNER_BINDING="+string(encoded))
		if manualRun != "" {
			command.Env = append(command.Env, "ZASP_P3C_MANUAL_PARENT="+manualRun)
		}
		if cancelWorkflow {
			command.Env = append(command.Env, "ZASP_P3C_RAW_CANCEL="+cancelStage)
		}
		var output strings.Builder
		command.Stdout = io.MultiWriter(&output, temporalWorkflowTestLog{t})
		command.Stderr = command.Stdout
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		joined := make(chan error, 1)
		go func() { joined <- command.Wait() }()
		_, approver := public62GoRepository(t, api, o, w, e, orderedProgressionApprover)
		approver.FreshAuthenticated = true
		approver.FreshAuthExpiresAt = time.Now().UTC().Add(5 * time.Minute)
		approved := map[string]bool{}
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case err := <-joined:
				t.Log(output.String())
				if manualRun != "" {
					var inventory string
					if err := owner.QueryRow(ctx, `SELECT jsonb_agg(jsonb_build_object('run_id',r.run_id,'definition',r.definition_id,'state',r.state,'attempt',r.attempt,'trigger',tr.trigger_kind,'error',r.last_error_code,'settlement',(SELECT l.reconcile_settlement->'receipt' FROM zasp_security_agent_test_links l WHERE l.run_id=r.run_id)) ORDER BY r.run_id)::text FROM zasp_security_agent_runs r LEFT JOIN zasp_security_agent_trigger_receipts tr USING(organization_id,workspace_id,environment_id,definition_id,run_id,trigger_id) WHERE r.organization_id=$1`, o).Scan(&inventory); err != nil {
						t.Fatal(err)
					}
					t.Log("persisted coexistence decisions", inventory)
				}
				if err != nil || !strings.Contains(output.String(), "--- PASS: TestTemporalOwnedWorkflow") || strings.Contains(output.String(), "--- SKIP:") {
					t.Fatal("actual worker", err)
				}
				if manualRun != "" {
					assertShippedManualReceipt(t, ctx, owner, db, identity, manualRun)
					assertShippedLegacyClassifier(t, ctx, owner, adapter, o, w, e, manualRun, run)
				}
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, orderedHTTPRequest(identity, "getSecurityAgentRun", http.MethodGet, run, ""))
				var typed struct {
					SecurityAgentRunDetail
					Ordered struct {
						Steps []SecurityAgentPublicStep `json:"steps"`
					} `json:"ordered"`
				}
				wantState := "remediated"
				if cancelWorkflow {
					wantState = "needs_human"
				}
				if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &typed) != nil || typed.Run.State != wantState || len(typed.Ordered.Steps) != 2 {
					t.Fatal("typed final HTTP read", response.Code, response.Body.String())
				}
				var verified bool
				effects, settlements, stops := 2, 1, 0
				if cancelWorkflow {
					effects, settlements, stops = 1, 0, 1
					if cancelStage == "reserved" {
						effects = 2
					}
				}
				if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_temporal68.effects WHERE run_id=$1)=$2 AND (SELECT count(*) FROM zasp_temporal68.test_settlements WHERE run_id=$1)=$3 AND (SELECT count(*) FROM zasp_temporal69.stops WHERE run_id=$1)=$4 AND (SELECT count(*) FROM zasp_temporal68.planning_jobs WHERE run_id=$1 AND state='admitted')=1 AND NOT EXISTS(SELECT 1 FROM zasp_temporal68.effects WHERE run_id=$1 AND action_key='create_temporary_policy' AND state<>'cleaned')`, run, effects, settlements, stops).Scan(&verified); err != nil || !verified {
					t.Fatal("persisted product proof", verified, err)
				}
				t.Log("actual HTTP admission -> SQL outbox -> local Temporal SDK worker -> real planner/policy/linked journal executors -> signed cleanup -> typed HTTP receipt; controlled external providers")
				return
			case <-ticker.C:
				rows, err := owner.Query(ctx, `SELECT approval_id FROM zasp_security_agent_approvals WHERE run_id=$1 AND state='pending'`, run)
				if err != nil {
					cancel()
					<-joined
					t.Fatal(err)
				}
				var ids []string
				for rows.Next() {
					var id string
					if err := rows.Scan(&id); err != nil {
						rows.Close()
						cancel()
						<-joined
						t.Fatal(err)
					}
					ids = append(ids, id)
				}
				rows.Close()
				for _, id := range ids {
					approvalLimit := 1
					if cancelStage == "reserved" {
						approvalLimit = 2
					}
					if cancelWorkflow && len(approved) >= approvalLimit {
						continue
					}
					if !approved[id] {
						result := call(approver, "decideSecurityAgentApproval", id, `{"decision":"approved"}`, "p3c-approve-"+id, "1")
						if result.Code != http.StatusOK {
							cancel()
							<-joined
							t.Fatal("HTTP approval", result.Code, result.Body.String(), output.String())
						}
						approved[id] = true
					}
				}
			}
		}
	})
}

type temporalWorkflowTestLog struct{ t *testing.T }

func (w temporalWorkflowTestLog) Write(b []byte) (int, error) { w.t.Log(string(b)); return len(b), nil }
