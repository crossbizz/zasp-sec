package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// Scoped projection on registered54. Seeded receipts are not live planner use,
// HTTP identity is supplied by the fixture, not a live authenticated browser.
func TestSecurityAgentRunContextRegisteredPostgres(t *testing.T) {
	runSecurityAgentBudgetFixture(t, func(ctx context.Context, owner *pgx.Conn, dsn string) {
		if err := precisionMigrationRunner(t, owner).UpProductionSecurityAgentRunContext(ctx); err != nil {
			t.Fatal(err)
		}
		const org = "pid_6a000001-0000-4000-8000-000000000001"
		const workspace = "pid_6a000002-0000-4000-8000-000000000002"
		const environment = "pid_6a000003-0000-4000-8000-000000000003"
		const foreignOrg = "pid_9a000001-0000-4000-8000-000000000001"
		const foreignWorkspace = "pid_9a000002-0000-4000-8000-000000000002"
		const foreignEnvironment = "pid_9a000003-0000-4000-8000-000000000003"
		for _, statement := range []string{
			`INSERT INTO zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state,attempt,plan_hash)
SELECT organization_id,workspace_id,environment_id,$1,definition_id,definition_version,'pid_6a000005-0000-4000-8000-000000000005','context-fixture','running',1,decode(repeat('a',64),'hex') FROM zasp_security_agent_definitions`,
			`INSERT INTO zasp_security_agent_trigger_receipts(organization_id,workspace_id,environment_id,definition_id,trigger_id,trigger_kind,trigger_version,trigger_digest,run_id)
SELECT organization_id,workspace_id,environment_id,definition_id,trigger_id,'attack_path',2,decode(repeat('c',64),'hex'),run_id FROM zasp_security_agent_runs WHERE run_id=$1`,
			`INSERT INTO zasp_security_agent_plans(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_digest,catalog_version,plan,plan_hash,expires_at)
SELECT organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,decode(repeat('c',64),'hex'),'security-agent-actions-v1','{}',plan_hash,clock_timestamp()+interval '1 hour' FROM zasp_security_agent_runs WHERE run_id=$1`,
			`INSERT INTO zasp_security_agent_steps(organization_id,workspace_id,environment_id,run_id,step_id,step_index,action_key,input_digest,authorization_result,state)
SELECT organization_id,workspace_id,environment_id,run_id,'pid_78000007-0000-4000-8000-000000000007',0,'create_temporary_policy',decode(repeat('c',64),'hex'),'allow','authorized' FROM zasp_security_agent_runs WHERE run_id=$1`,
			`INSERT INTO zasp_security_agent_planner_receipts(organization_id,workspace_id,environment_id,run_id,attempt,input_digest,output_digest,outcome,model,policy_version,response)
SELECT organization_id,workspace_id,environment_id,run_id,1,decode(repeat('c',64),'hex'),decode(repeat('d',64),'hex'),'accepted','fixture-model','fixture-policy',jsonb_build_object('run_id',run_id,'plan_hash','sha256:'||encode(plan_hash,'hex'),'planner_summary',CASE WHEN organization_id='pid_6a000001-0000-4000-8000-000000000001' THEN 'Tenant A password=seeded; review.' ELSE 'Tenant B rationale.' END) FROM zasp_security_agent_runs WHERE run_id=$1`,
		} {
			if _, err := owner.Exec(ctx, statement, runContextTestRunID); err != nil {
				t.Fatal(err)
			}
		}
		config, err := pgx.ParseConfig(dsn)
		if err != nil {
			t.Fatal(err)
		}
		config.User = "security_agent_v33_api_login"
		api, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer api.Close(context.Background())
		var canCheckRelease bool
		if err := api.QueryRow(ctx, `SELECT has_function_privilege(current_user,'public.zasp_production_security_agent_run_context_client_ready(text,text)','EXECUTE')`).Scan(&canCheckRelease); err != nil || !canCheckRelease {
			t.Fatalf("security agent API cannot check54 release: allowed=%v error=%v", canCheckRelease, err)
		}
		database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
		if err != nil {
			t.Fatal(err)
		}
		repository, err := NewSecurityAgentPostgresRepository(database)
		if err != nil {
			t.Fatal(err)
		}
		identityFor := func(organizationID, workspaceID, environmentID string) RequestIdentity {
			identity := fixtureRequestIdentity(t)
			orgID, _ := domain.ParseProductID(organizationID)
			workspace, _ := domain.ParseProductID(workspaceID)
			environment, _ := domain.ParseProductID(environmentID)
			identity.Scope, err = domain.NewScope(orgID, workspace, environment)
			if err != nil {
				t.Fatal(err)
			}
			identity.CredentialKind = CredentialBrowserSession
			return identity
		}
		read := func(organizationID, workspaceID, environmentID string) (SecurityAgentRunDetail, error) {
			return repository.GetSecurityAgentRun(ctx, identityFor(organizationID, workspaceID, environmentID), runContextTestRunID)
		}
		value, err := read(org, workspace, environment)
		if err != nil || value.RunContext == nil || value.RunContext.Rationale == nil || value.RunContext.Rationale.Summary != "Tenant A password=[REDACTED]; review." {
			t.Fatal("scoped candidate did not return sanitized A rationale", err)
		}
		handler, err := NewSecurityAgentPublicHTTPHandler(repository, http.NotFoundHandler(), SecurityAgentPublicHandlerConfig{Clock: time.Now, NewProductID: newWorkflowProductID, SigningKey: securityAgentTestSigningKey})
		if err != nil {
			t.Fatal(err)
		}
		for _, headers := range [][]string{nil, {"v1"}, {"v2"}, {"v1", "v1"}} {
			request := workflowRequest(t, identityFor(org, workspace, environment), "pid_bb000004-0000-4000-8000-000000000004", "getSecurityAgentRun", map[string]string{"id": runContextTestRunID}, http.MethodGet, "/api/v1/security-agent-runs/"+runContextTestRunID, "")
			for _, header := range headers {
				request.Header.Add("X-Zasp-Run-Context", header)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			var fields map[string]json.RawMessage
			if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" || json.Unmarshal(response.Body.Bytes(), &fields) != nil {
				t.Fatalf("registered HTTP status=%d", response.Code)
			}
			wantContext := len(headers) == 1 && headers[0] == "v1"
			wantFields := 7
			if wantContext {
				wantFields++
			}
			if len(fields) != wantFields || (fields["run_context"] != nil) != wantContext || strings.Contains(response.Body.String(), "seeded") || strings.Contains(response.Body.String(), "planner_receipt") {
				t.Fatal("registered HTTP negotiation or private-text boundary failed")
			}
			if wantContext && !strings.Contains(string(fields["run_context"]), "Tenant A password=[REDACTED]; review.") {
				t.Fatal("HTTP lost sanitized persisted rationale")
			}
		}
		if _, err := owner.Exec(ctx, `GRANT EXECUTE ON FUNCTION zasp_security_agent_run_context_v54(text,text,text,text) TO PUBLIC`); err != nil {
			t.Fatal(err)
		}
		if value, err := read(org, workspace, environment); err != ErrRepositoryUnavailable || value.RunContext != nil {
			t.Fatal("Get silently fell back across untrusted54 authority", err)
		}
		if _, err := owner.Exec(ctx, `REVOKE ALL ON FUNCTION zasp_security_agent_run_context_v54(text,text,text,text) FROM PUBLIC`); err != nil {
			t.Fatal(err)
		}
		foreign, err := read(foreignOrg, foreignWorkspace, foreignEnvironment)
		if err != nil || foreign.RunContext == nil || foreign.RunContext.Rationale == nil || foreign.RunContext.Rationale.Summary != "Tenant B rationale." {
			t.Fatal("colliding foreign run ID was not independently scoped", err)
		}
		if _, err := read(org, foreignWorkspace, foreignEnvironment); !errors.Is(err, ErrRepositoryNotFound) {
			t.Fatal("mixed tenant scope did not refuse", err)
		}
		if _, err := read(org, workspace, foreignEnvironment); !errors.Is(err, ErrRepositoryNotFound) {
			t.Fatal("foreign environment did not refuse", err)
		}
		var direct json.RawMessage
		if err := api.QueryRow(ctx, `SELECT response FROM zasp_security_agent_planner_receipts LIMIT 1`).Scan(&direct); err == nil {
			t.Fatal("API gained direct private receipt access")
		}
		config.User = "security_agent_v33_worker_login"
		worker, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close(context.Background())
		if err := worker.QueryRow(ctx, `SELECT zasp_security_agent_run_context_v54($1,$2,$3,$4)`, org, workspace, environment, runContextTestRunID).Scan(&direct); err == nil {
			t.Fatal("worker gained public detail access")
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_runs SET attempt=2 WHERE organization_id=$1 AND run_id=$2`, org, runContextTestRunID); err != nil {
			t.Fatal(err)
		}
		value, err = read(org, workspace, environment)
		if err != nil || value.RunContext.Rationale == nil {
			t.Fatal("execution retry lost accepted plan rationale", err)
		}
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_planner_receipts SELECT organization_id,workspace_id,environment_id,run_id,2,input_digest,output_digest,'planner_rejected',model,policy_version,response||'{"planner_summary":"Do not expose rejected response"}'::jsonb,created_at FROM zasp_security_agent_planner_receipts WHERE organization_id=$1 AND run_id=$2 AND attempt=1`, org, runContextTestRunID); err != nil {
			t.Fatal(err)
		}
		value, err = read(org, workspace, environment)
		if err != nil || value.RunContext.Rationale == nil || value.RunContext.Rationale.Summary != "Tenant A password=[REDACTED]; review." {
			t.Fatal("latest rejected receipt replaced accepted rationale", err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_planner_receipts SET outcome='accepted',response=response||jsonb_build_object('plan_hash','sha256:'||repeat('b',64)) WHERE organization_id=$1 AND run_id=$2 AND attempt=2`, org, runContextTestRunID); err != nil {
			t.Fatal(err)
		}
		value, err = read(org, workspace, environment)
		if err != nil || value.RunContext.Rationale == nil || value.RunContext.Rationale.Summary != "Tenant A password=[REDACTED]; review." {
			t.Fatal("different plan replaced displayed-plan rationale", err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_planner_receipts SET response=response||jsonb_build_object('plan_hash','sha256:'||repeat('a',64)) WHERE organization_id=$1 AND run_id=$2 AND attempt=2`, org, runContextTestRunID); err != nil {
			t.Fatal(err)
		}
		if _, err := read(org, workspace, environment); err == nil {
			t.Fatal("ambiguous accepted receipts were silently selected")
		}
		if _, err := owner.Exec(ctx, `DELETE FROM zasp_security_agent_planner_receipts WHERE organization_id=$1 AND run_id=$2`, org, runContextTestRunID); err != nil {
			t.Fatal(err)
		}
		value, err = read(org, workspace, environment)
		if err != nil || value.RunContext.Rationale != nil {
			t.Fatal("missing receipt was fabricated", err)
		}
	})
}
