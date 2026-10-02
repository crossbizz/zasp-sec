//go:build darwin || linux

package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestProductionSecurityAgentBudgetProviderSuppressionThroughWorker(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	binary := securityAgentBudgetWorkerBinary(t, ctx)
	for _, mode := range []string{"expired", "fresh", "fresh_heartbeat", "completion_heartbeat", "heartbeat", "missing_cost_authority", "run_once_missing_cost_authority"} {
		t.Run(mode, func(t *testing.T) {
			runSecurityAgentBudgetFixture(t, func(ctx context.Context, owner *pgx.Conn, dsn string) {
				const organization = "pid_6a000001-0000-4000-8000-000000000001"
				if _, err := owner.Exec(ctx, `UPDATE zasp_risk_attack_paths SET state='verified',version=version+1 WHERE organization_id=$1`, organization); err != nil {
					t.Fatal(err)
				}
				command := exec.Command(binary, "-test.run=^TestSecurityAgentBudgetProviderOwnedPostgres$", "-test.v", "-test.timeout=30s")
				command.Dir = "../agentsec-worker"
				for _, entry := range os.Environ() {
					if !strings.HasPrefix(entry, "ZASP_") && !strings.HasPrefix(entry, "PG") {
						command.Env = append(command.Env, entry)
					}
				}
				command.Env = append(command.Env, "ZASP_BUDGET_PROVIDER_TEST_DSN="+dsn, "ZASP_BUDGET_PROVIDER_TEST_MODE="+mode)
				output, err := runSandboxWorkerCommand(ctx, command)
				if err != nil || strings.Contains(string(output), "--- SKIP:") || !strings.Contains(string(output), "owned budget processor joined:") {
					t.Fatalf("owned budget worker: %v\n%s", err, output)
				}
				t.Logf("owned worker joined:\n%s", output)
				var state, reason string
				var plans, steps, approvals, effects, receipts int
				var leaseCleared bool
				if err := owner.QueryRow(ctx, `SELECT r.state,coalesce(b.stop_reason,''),
 (r.lease_owner IS NULL AND r.lease_token IS NULL AND r.lease_expires_at IS NULL),
 (SELECT count(*) FROM zasp_security_agent_plans),
 (SELECT count(*) FROM zasp_security_agent_steps),
 (SELECT count(*) FROM zasp_security_agent_approvals),
 (SELECT count(*) FROM zasp_security_agent_effects),
 (SELECT count(*) FROM zasp_security_agent_planner_receipts)
 FROM zasp_security_agent_runs r JOIN zasp_security_agent_run_budgets b USING(organization_id,workspace_id,environment_id,run_id) WHERE r.organization_id=$1`, organization).Scan(&state, &reason, &leaseCleared, &plans, &steps, &approvals, &effects, &receipts); err != nil {
					t.Fatal(err)
				}
				wantState, wantReason, wantArtifacts := "needs_human", "budget_deadline_exceeded", 0
				if mode == "missing_cost_authority" || mode == "run_once_missing_cost_authority" {
					wantReason = "budget_usage_unknown"
				}
				if mode == "fresh" || mode == "fresh_heartbeat" || mode == "completion_heartbeat" {
					wantState, wantReason, wantArtifacts = "waiting_approval", "", 1
				}
				if state != wantState || reason != wantReason || !leaseCleared || plans != wantArtifacts || steps != wantArtifacts || approvals != wantArtifacts || receipts != wantArtifacts || effects != 0 {
					t.Fatalf("state=%s reason=%s leaseCleared=%v plans=%d steps=%d approvals=%d effects=%d receipts=%d", state, reason, leaseCleared, plans, steps, approvals, effects, receipts)
				}
				if mode == "run_once_missing_cost_authority" {
					var runs, budgets int
					if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_security_agent_runs WHERE organization_id=$1),(SELECT count(*) FROM zasp_security_agent_run_budgets WHERE organization_id=$1)`, organization).Scan(&runs, &budgets); err != nil || runs != 1 || budgets != 1 {
						t.Fatalf("RunOnce repeat duplicated or omitted authority: runs=%d budgets=%d err=%v", runs, budgets, err)
					}
				}
				assertSecurityAgentPublicBudgetReason(t, ctx, owner, organization, wantReason)
				var reservations int
				if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_security_agent_provider_reservations WHERE organization_id=$1`, organization).Scan(&reservations); err != nil || reservations != wantArtifacts {
					t.Fatalf("reservations=%d want=%d err=%v", reservations, wantArtifacts, err)
				}
				if mode == "fresh" || mode == "fresh_heartbeat" || mode == "completion_heartbeat" {
					var exact bool
					if err := owner.QueryRow(ctx, `SELECT prompt_tokens=120 AND completion_tokens=40 AND total_tokens=160 AND cost_nano_credits=100 AND maximum_tokens=1000 AND maximum_cost_nano_credits=200 AND settled_at IS NOT NULL FROM zasp_security_agent_provider_reservations WHERE organization_id=$1`, organization).Scan(&exact); err != nil || !exact {
						t.Fatalf("controlled response accounting=%v err=%v", exact, err)
					}
				}
			})
		})
	}
}

func assertSecurityAgentPublicBudgetReason(t *testing.T, ctx context.Context, owner *pgx.Conn, organization, want string) {
	t.Helper()
	var workspace, environment, runID string
	if err := owner.QueryRow(ctx, `SELECT workspace_id,environment_id,run_id FROM zasp_security_agent_runs WHERE organization_id=$1`, organization).Scan(&workspace, &environment, &runID); err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	orgID, _ := domain.ParseProductID(organization)
	workspaceID, _ := domain.ParseProductID(workspace)
	environmentID, _ := domain.ParseProductID(environment)
	var err error
	identity.Scope, err = domain.NewScope(orgID, workspaceID, environmentID)
	if err != nil {
		t.Fatal(err)
	}
	identity.CredentialKind = CredentialBrowserSession
	config := owner.Config().Copy()
	config.User = "security_agent_v33_api_login"
	config.RuntimeParams["timezone"] = "UTC"
	connection, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewSecurityAgentPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewSecurityAgentPublicHTTPHandler(repository, http.NotFoundHandler(), SecurityAgentPublicHandlerConfig{Clock: time.Now, NewProductID: newWorkflowProductID, SigningKey: securityAgentTestSigningKey})
	if err != nil {
		t.Fatal(err)
	}
	read := func(reader RequestIdentity, budgetDetails bool) *httptest.ResponseRecorder {
		request := workflowRequest(t, reader, "pid_bb000004-0000-4000-8000-000000000004", "getSecurityAgentRun", map[string]string{"id": runID}, http.MethodGet, "/api/v1/security-agent-runs/"+runID, "")
		if budgetDetails {
			request.Header.Set("X-Zasp-Budget-Details", "v1")
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	legacy := read(identity, false)
	var legacyFields map[string]json.RawMessage
	if legacy.Code != http.StatusOK || legacy.Header().Get("Cache-Control") != "no-store" || json.Unmarshal(legacy.Body.Bytes(), &legacyFields) != nil || len(legacyFields) != 7 || legacyFields["budget_stop_reason"] != nil {
		t.Fatalf("legacy response changed: status=%d body=%s", legacy.Code, legacy.Body.String())
	}
	response := read(identity, true)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("public run status=%d body=%s", response.Code, response.Body.String())
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &fields); err != nil {
		t.Fatal(err)
	}
	wantJSON := ""
	if want != "" {
		bytes, _ := json.Marshal(want)
		wantJSON = string(bytes)
	}
	if string(fields["budget_stop_reason"]) != wantJSON {
		t.Fatalf("public budget reason=%s want=%s", fields["budget_stop_reason"], wantJSON)
	}
	foreign := fixtureRequestIdentity(t)
	foreign.CredentialKind = CredentialBrowserSession
	foreignWorkspace, foreignEnvironment := identity, identity
	foreignWorkspace.Scope, err = domain.NewScope(orgID, foreign.Scope.WorkspaceID(), environmentID)
	if err != nil {
		t.Fatal(err)
	}
	foreignEnvironment.Scope, err = domain.NewScope(orgID, workspaceID, foreign.Scope.EnvironmentID())
	if err != nil {
		t.Fatal(err)
	}
	for _, reader := range []RequestIdentity{foreign, foreignWorkspace, foreignEnvironment} {
		denied := read(reader, true)
		if denied.Code != http.StatusNotFound || strings.Contains(denied.Body.String(), "budget_stop_reason") {
			t.Fatalf("foreign scope public run status=%d body=%s", denied.Code, denied.Body.String())
		}
	}
}
