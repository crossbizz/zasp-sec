package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// Tenant B's application, identity and pricing records are controlled setup.
// Definition creation, activation, manual admission and revocation use the
// shipped typed/API routes; no execution or proof journal is fixture-inserted.
func prepareTemporalTestLiveTenant(t *testing.T, ctx context.Context, owner, admin *pgx.Conn, repository *PostgresRepository, source RequestIdentity, testID string) {
	t.Helper()
	const o = "pid_9a000001-0000-4000-8000-000000000001"
	const w = "pid_9a000002-0000-4000-8000-000000000002"
	const e = "pid_9a000003-0000-4000-8000-000000000003"
	const actor = "pid_f0740000-0000-4000-8000-000000000301"
	const definition = "pid_f0740000-0000-4000-8000-000000000302"
	const run = "pid_f0740000-0000-4000-8000-000000000303"
	if _, err := owner.Exec(ctx, `UPDATE zasp_environments SET environment_class='staging' WHERE (organization_id,workspace_id,id)=($1,$2,$3);
INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role) VALUES($4,$1,'test74-tenant-b','test74-actor-b','organization_admin');
INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($4,$1,$2,$3,'Test74 tenant B','["view","manage_identity","manage_workflows","run_tests"]');
INSERT INTO zasp_security_agent_kill_switches(organization_id,workspace_id,environment_id,action_key,execution_enabled,updated_by) VALUES($1,$2,$3,'run_test',true,$4);
INSERT INTO zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,state,first_seen_at,last_seen_at,product_kind,observed_at,fresh_until,winning_attributes)
SELECT $1,$2,$3,id,kind,'Tenant B target',state,first_seen_at,last_seen_at,product_kind,observed_at,fresh_until,winning_attributes FROM zasp_inventory_entities WHERE (organization_id,workspace_id,environment_id,id)=($5,$6,$7,'pid_89000011-0000-4000-8000-000000000001');
SELECT zasp_attack_lab_register_credential_binding($1,$2,$3,'pid_89000013-0000-4000-8000-000000000003','pid_89000011-0000-4000-8000-000000000001','ref:red-team/versioned_draft_0001','read_only',1,decode(repeat('ab',32),'hex'),now()+interval '1 hour');
INSERT INTO zasp_red_team_definitions(organization_id,workspace_id,environment_id,definition_id,name,target_id,target_kind,categories,safety,created_by,enabled)
SELECT $1,$2,$3,definition_id,'Tenant B test',target_id,target_kind,categories,safety,$4,true FROM zasp_red_team_definitions WHERE (organization_id,workspace_id,environment_id,definition_id)=($5,$6,$7,$8)`, pgx.QueryExecModeSimpleProtocol, o, w, e, actor, source.Scope.OrganizationID().String(), source.Scope.WorkspaceID().String(), source.Scope.EnvironmentID().String(), testID); err != nil {
		t.Fatal("tenant B controlled resources", err)
	}
	ids := make([]domain.ProductID, 4)
	for i, v := range []string{o, w, e, actor} {
		var err error
		ids[i], err = domain.ParseProductID(v)
		if err != nil {
			t.Fatal(err)
		}
	}
	identity := source
	identity.Scope, _ = domain.NewScope(ids[0], ids[1], ids[2])
	identity.PrincipalID = ids[3]
	identity.FreshAuthExpiresAt = time.Now().UTC().Add(4 * time.Minute)
	var body, intent json.RawMessage
	if err := owner.QueryRow(ctx, `SELECT b,jsonb_build_object('resource_id','','expected_version',0,'body',b-'id') FROM (SELECT body||jsonb_build_object('id',$2::text,'environment_ids',jsonb_build_array($3::text),'enabled',false,'autonomy','supervised') b FROM zasp_security_agent_definitions WHERE (organization_id,definition_id)=($4,$1)) v`, public62Definition, definition, e, source.Scope.OrganizationID().String()).Scan(&body, &intent); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.MutateWorkflow(ctx, identity, WorkflowMutation{Action: "create", Kind: "security_agent", ID: definition, Operation: "createSecurityAgent", IdempotencyKey: "test74-live-b-create", Intent: intent, Body: body, AuditID: "pid_f0740000-0000-4000-8000-000000000310", CorrelationID: "pid_f0740000-0000-4000-8000-000000000311", ReceiptID: "pid_f0740000-0000-4000-8000-000000000312"}); err != nil {
		t.Fatal("tenant B actual create", err)
	}
	for i, a := range []string{"validated", "supervised", "autonomous"} {
		if _, err := repository.ActivateSecurityAgent(ctx, identity, SecurityAgentActivation{DefinitionID: definition, ExpectedVersion: int64(i + 1), TargetActivation: a, IdempotencyKey: "test74-live-b-" + a, FreshAuthExpiresAt: identity.FreshAuthExpiresAt, AuditID: fmt.Sprintf("pid_f0740000-0000-4000-8000-%012d", 320+i*3), CorrelationID: fmt.Sprintf("pid_f0740000-0000-4000-8000-%012d", 321+i*3), ReceiptID: fmt.Sprintf("pid_f0740000-0000-4000-8000-%012d", 322+i*3)}); err != nil {
			t.Fatal("tenant B actual activation", a, err)
		}
	}
	if _, err := repository.runSecurityAgentManual(ctx, identity, SecurityAgentRunRequest{DefinitionID: definition, ExpectedVersion: 4, IdempotencyKey: "test74-live-b-run", RunID: run, AuditID: "pid_f0740000-0000-4000-8000-000000000340", CorrelationID: "pid_f0740000-0000-4000-8000-000000000341", ReceiptID: "pid_f0740000-0000-4000-8000-000000000342", TriggerKind: "manual"}); err != nil {
		t.Fatal("tenant B actual admission", err)
	}
	policy := orderedPricingAdminRequest(o, w, e, actor)
	bindTemporalTestPlannerPricing(policy)
	priced, err := orderedPricingCall(ctx, admin, "pricing_admin", policy)
	if err != nil {
		t.Fatal(err)
	}
	selection := orderedPricingLookupRequest(o, w, e, policy["policy"].(map[string]any), priced)
	binding := map[string]any{}
	for _, k := range []string{"organization_id", "workspace_id", "environment_id", "account_profile", "credential_reference", "policy_id", "policy_version", "policy_digest", "account_id", "account_version"} {
		binding[k] = selection[k]
	}
	encoded, _ := json.Marshal(binding)
	t.Setenv("ZASP_TEST74_SECOND_BINDING", string(encoded))
	t.Setenv("ZASP_TEST74_SECOND_PARENT", run)
	prepareTemporalTestLiveCancellation(t, ctx, owner, repository, source)
	handler, err := newWorkflowHTTPHandler(repository, []byte("0123456789abcdef0123456789abcdef"), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPost && (request.URL.Path == "/cancellation-run" || request.URL.Path == "/cancel-run") {
			const cancelRun = "pid_f0740000-0000-4000-8000-000000000801"
			cancelIdentity := source
			cancelIdentity.PrincipalID, _ = domain.ParseProductID("pid_f0740000-0000-4000-8000-000000000609")
			cancelIdentity.FreshAuthExpiresAt = time.Now().UTC().Add(4 * time.Minute)
			if request.URL.Path == "/cancellation-run" {
				if _, err := repository.runSecurityAgentManual(ctx, cancelIdentity, SecurityAgentRunRequest{DefinitionID: "pid_f0740000-0000-4000-8000-000000000808", ExpectedVersion: 3, IdempotencyKey: "test74-live-cancel-admission", RunID: cancelRun, AuditID: "pid_f0740000-0000-4000-8000-000000000802", CorrelationID: "pid_f0740000-0000-4000-8000-000000000803", ReceiptID: "pid_f0740000-0000-4000-8000-000000000804", TriggerKind: "manual"}); err != nil {
					t.Fatal("live cancellation admission", err)
				}
				response.Header().Set("Content-Type", "application/json")
				json.NewEncoder(response).Encode(map[string]any{"run_id": cancelRun, "definition_version": 3})
				return
			}
			var version int64
			if err := owner.QueryRow(ctx, `SELECT version FROM zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4) AND state='waiting_approval'`, source.Scope.OrganizationID().String(), source.Scope.WorkspaceID().String(), source.Scope.EnvironmentID().String(), cancelRun).Scan(&version); err != nil {
				t.Fatal("live cancel exact waiting parent", err)
			}
			q := SecurityAgentCancelRequest{RunID: cancelRun, ExpectedVersion: version, IdempotencyKey: "test74-live-api-cancel", AuditID: "pid_f0740000-0000-4000-8000-000000000805", CorrelationID: "pid_f0740000-0000-4000-8000-000000000806", ReceiptID: "pid_f0740000-0000-4000-8000-000000000807"}
			if result, err := repository.CancelSecurityAgentRun(ctx, cancelIdentity, q); err != nil || result.State != "cancelled" {
				t.Fatal("live typed cancellation", result, err)
			}
			if result, err := repository.CancelSecurityAgentRun(ctx, cancelIdentity, q); err != nil || !result.Replayed {
				t.Fatal("live typed cancellation replay", result, err)
			}
			response.WriteHeader(http.StatusNoContent)
			return
		}
		if request.Method == http.MethodPost && request.URL.Path == "/automatic-rerun" {
			run := startTemporalTestLiveAutomaticRerun(t, ctx, owner, repository, handler, source, true)
			response.Header().Set("Content-Type", "application/json")
			json.NewEncoder(response).Encode(map[string]any{"run_id": run, "definition_version": 3})
			return
		}
		if request.Method == http.MethodPost && request.URL.Path == "/approve-automatic" {
			var approval string
			if err := owner.QueryRow(ctx, `SELECT a.approval_id FROM zasp_security_agent_approvals a JOIN zasp_temporal74.run_owners x USING(organization_id,workspace_id,environment_id,run_id) WHERE x.source_kind='automatic73' AND x.action_key='rerun_test' AND a.state='pending'`).Scan(&approval); err != nil {
				t.Fatal(err)
			}
			const approver = "pid_f0740000-0000-4000-8000-000000000609"
			var current bool
			if err := owner.QueryRow(ctx, `SELECT m.active AND s.permissions?&ARRAY['view','manage_workflows','run_tests'] FROM zasp_identity_memberships m JOIN zasp_authorized_scopes s USING(organization_id,principal_id) WHERE (s.organization_id,s.workspace_id,s.environment_id,s.principal_id)=($1,$2,$3,$4)`, source.Scope.OrganizationID().String(), source.Scope.WorkspaceID().String(), source.Scope.EnvironmentID().String(), approver).Scan(&current); err != nil || !current {
				t.Fatal("current prepared approver", current, err)
			}
			approvalIdentity := source
			approvalIdentity.PrincipalID, _ = domain.ParseProductID(approver)
			approvalIdentity.FreshAuthExpiresAt = time.Now().UTC().Add(4 * time.Minute)
			q := SecurityAgentApprovalDecisionRequest{ApprovalID: approval, IdempotencyKey: "test74-live-service-approval", ExpectedVersion: 1, Decision: "approved", FreshAuthAt: time.Now().UTC(), AuditID: "pid_f0740000-0000-4000-8000-000000000610", CorrelationID: "pid_f0740000-0000-4000-8000-000000000611", ReceiptID: "pid_f0740000-0000-4000-8000-000000000612"}
			if result, err := repository.DecideSecurityAgentApproval(ctx, approvalIdentity, q); err != nil || result.State != "approved" {
				t.Fatal("live current service approval", result, err)
			}
			if result, err := repository.DecideSecurityAgentApproval(ctx, approvalIdentity, q); err != nil || !result.Replayed {
				t.Fatal("live same approval replay", result, err)
			}
			response.WriteHeader(http.StatusNoContent)
			return
		}
		if request.Method != http.MethodPost || request.URL.Path != "/revoke-tenant-b" {
			http.Error(response, "rejected", 400)
			return
		}
		actual := workflowRequest(t, identity, "pid_f0740000-0000-4000-8000-000000000350", "deleteSecurityAgent", map[string]string{"id": definition}, http.MethodDelete, "/api/v1/security-agents/"+definition, "")
		actual.Header.Set("Idempotency-Key", "test74-live-b-revoke")
		actual.Header.Set("If-Match", `"4"`)
		handler.ServeHTTP(response, actual)
	}))
	t.Cleanup(server.Close)
	t.Setenv("ZASP_TEST74_REVOKE_URL", server.URL+"/revoke-tenant-b")
	t.Setenv("ZASP_TEST74_RERUN_URL", server.URL+"/automatic-rerun")
	t.Setenv("ZASP_TEST74_APPROVAL_URL", server.URL+"/approve-automatic")
	t.Setenv("ZASP_TEST74_CANCEL_ADMIT_URL", server.URL+"/cancellation-run")
	t.Setenv("ZASP_TEST74_CANCEL_URL", server.URL+"/cancel-run")
}

// Independent current human configuration, prepared before the live worker's
// bounded run. Its unused finding rule prevents incidental automatic admission.
// The actual manual admission still checks the installed creator/caller rules.
func prepareTemporalTestLiveCancellation(t *testing.T, ctx context.Context, owner *pgx.Conn, repository *PostgresRepository, source RequestIdentity) {
	t.Helper()
	const actor = "pid_f0740000-0000-4000-8000-000000000609"
	const definition = "pid_f0740000-0000-4000-8000-000000000808"
	o, w, e := source.Scope.OrganizationID().String(), source.Scope.WorkspaceID().String(), source.Scope.EnvironmentID().String()
	if _, err := owner.Exec(ctx, `INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role) VALUES($4,$1,'test74-org','test74-approver','organization_admin');INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($4,$1,$2,$3,'Approver','["view","manage_workflows","run_tests"]')`, pgx.QueryExecModeSimpleProtocol, o, w, e, actor); err != nil {
		t.Fatal(err)
	}
	identity := source
	identity.PrincipalID, _ = domain.ParseProductID(actor)
	identity.FreshAuthExpiresAt = time.Now().UTC().Add(4 * time.Minute)
	var absent bool
	if err := owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_risk_findings WHERE (organization_id,workspace_id,environment_id,rule)=($1,$2,$3,'test74_cancel_only'))`, o, w, e).Scan(&absent); err != nil || !absent {
		t.Fatal("manual cancellation source isolation", absent, err)
	}
	var body, intent json.RawMessage
	if err := owner.QueryRow(ctx, `SELECT b,jsonb_build_object('resource_id','','expected_version',0,'body',b-'id') FROM (SELECT body||jsonb_build_object('id',$2::text,'enabled',false,'autonomy','supervised','trigger_source','test74_cancel_only','allowed_actions',jsonb_build_array('run_test')) b FROM zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id)=($3,$4,$5,$1)) v`, public62Definition, definition, o, w, e).Scan(&body, &intent); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.MutateWorkflow(ctx, identity, WorkflowMutation{Action: "create", Kind: "security_agent", ID: definition, Operation: "createSecurityAgent", IdempotencyKey: "test74-cancel-definition-create", Intent: intent, Body: body, AuditID: "pid_f0740000-0000-4000-8000-000000000811", CorrelationID: "pid_f0740000-0000-4000-8000-000000000812", ReceiptID: "pid_f0740000-0000-4000-8000-000000000813"}); err != nil {
		t.Fatal("actual cancellation definition create", err)
	}
	for i, a := range []string{"validated", "supervised"} {
		if _, err := repository.ActivateSecurityAgent(ctx, identity, SecurityAgentActivation{DefinitionID: definition, ExpectedVersion: int64(i + 1), TargetActivation: a, IdempotencyKey: "test74-cancel-definition-" + a, FreshAuthExpiresAt: identity.FreshAuthExpiresAt, AuditID: fmt.Sprintf("pid_f0740000-0000-4000-8000-%012d", 814+i*3), CorrelationID: fmt.Sprintf("pid_f0740000-0000-4000-8000-%012d", 815+i*3), ReceiptID: fmt.Sprintf("pid_f0740000-0000-4000-8000-%012d", 816+i*3)}); err != nil {
			t.Fatal("actual cancellation definition activation", a, err)
		}
	}
}

func startTemporalTestLiveAutomaticRerun(t *testing.T, ctx context.Context, owner *pgx.Conn, repository *PostgresRepository, handler http.Handler, identity RequestIdentity, supervised ...bool) string {
	t.Helper()
	const definition = "pid_f0740000-0000-4000-8000-000000000401"
	o, w, e := identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String()
	identity.FreshAuthExpiresAt = time.Now().UTC().Add(4 * time.Minute)
	var body, intent json.RawMessage
	if err := owner.QueryRow(ctx, `SELECT b,jsonb_build_object('resource_id','','expected_version',0,'body',b-'id') FROM (SELECT body||jsonb_build_object('id',$2::text,'enabled',false,'autonomy','supervised','allowed_actions',jsonb_build_array('rerun_test')) b FROM zasp_security_agent_definitions WHERE (organization_id,definition_id)=($3,$1)) v`, public62Definition, definition, o).Scan(&body, &intent); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_kill_switches(organization_id,workspace_id,environment_id,action_key,execution_enabled,updated_by) VALUES($1,$2,$3,'rerun_test',true,$4)`, o, w, e, identity.PrincipalID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.MutateWorkflow(ctx, identity, WorkflowMutation{Action: "create", Kind: "security_agent", ID: definition, Operation: "createSecurityAgent", IdempotencyKey: "test74-live-rerun-create", Intent: intent, Body: body, AuditID: "pid_f0740000-0000-4000-8000-000000000402", CorrelationID: "pid_f0740000-0000-4000-8000-000000000403", ReceiptID: "pid_f0740000-0000-4000-8000-000000000404"}); err != nil {
		t.Fatal("actual rerun create", err)
	}
	activations := []string{"validated", "supervised", "autonomous"}
	if len(supervised) > 0 && supervised[0] {
		activations = activations[:2]
	}
	for i, a := range activations {
		if _, err := repository.ActivateSecurityAgent(ctx, identity, SecurityAgentActivation{DefinitionID: definition, ExpectedVersion: int64(i + 1), TargetActivation: a, IdempotencyKey: "test74-live-rerun-" + a, FreshAuthExpiresAt: identity.FreshAuthExpiresAt, AuditID: fmt.Sprintf("pid_f0740000-0000-4000-8000-%012d", 410+i*3), CorrelationID: fmt.Sprintf("pid_f0740000-0000-4000-8000-%012d", 411+i*3), ReceiptID: fmt.Sprintf("pid_f0740000-0000-4000-8000-%012d", 412+i*3)}); err != nil {
			t.Fatal("actual rerun activation", a, err)
		}
	}
	// These two controlled historical definitions were inserted without workflow
	// records. They are not deletable product resources. Disable their fixture
	// inputs only after checking exact identity/version and absent mirrors; this
	// is scheduler isolation, not evidence of product revocation.
	for _, d := range []struct {
		id      string
		version int
	}{{public62Definition, 1}, {temporalTestLegacyTampered, 2}} {
		var synthetic bool
		if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id,version)=($1,$2,$3,$4,$5) AND deleted_at IS NULL) AND NOT EXISTS(SELECT 1 FROM zasp_workflow_records WHERE (organization_id,workspace_id,environment_id,kind,id)=($1,$2,$3,'security_agent',$4))`, o, w, e, d.id, d.version).Scan(&synthetic); err != nil || !synthetic {
			t.Fatal("synthetic retirement premise", d.id, synthetic, err)
		}
		if result, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET body=jsonb_set(body,'{enabled}','false') WHERE (organization_id,workspace_id,environment_id,definition_id,version)=($1,$2,$3,$4,$5) AND deleted_at IS NULL`, o, w, e, d.id, d.version); err != nil || result.RowsAffected() != 1 {
			t.Fatal("controlled scheduler input disable", d.id, err)
		}
	}
	// The actual55-created definition has a real workflow record. Retire it
	// through the shipped configuration route, preserving its audit/receipt.
	for i, d := range []struct {
		id      string
		version int
	}{{temporalTestLegacyProved, 4}} {
		request := workflowRequest(t, identity, fmt.Sprintf("pid_f0740000-0000-4000-8000-%012d", 430+i), "deleteSecurityAgent", map[string]string{"id": d.id}, http.MethodDelete, "/api/v1/security-agents/"+d.id, "")
		request.Header.Set("Idempotency-Key", fmt.Sprintf("test74-live-retire-%d", i))
		request.Header.Set("If-Match", fmt.Sprintf(`"%d"`, d.version))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Fatal("actual setup definition retirement", d.id, response.Code, response.Body.String())
		}
	}
	cfg := owner.Config().Copy()
	cfg.User = "security_agent_v33_worker_login"
	worker, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close(ctx)
	db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
	if err != nil {
		t.Fatal(err)
	}
	scheduler, err := NewSecurityAgentWorkerRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	if count, err := scheduler.ScheduleSecurityAgentTriggers(ctx, "test74-live-automatic-rerun", 10); err != nil || count != 1 {
		t.Fatal("actual automatic rerun source admission", count, err)
	}
	var run string
	if err := owner.QueryRow(ctx, `SELECT run_id FROM zasp_temporal73.admissions WHERE (organization_id,workspace_id,environment_id,definition_id,definition_version)=($1,$2,$3,$4,$5)`, o, w, e, definition, len(activations)+1).Scan(&run); err != nil {
		t.Fatal(err)
	}
	// Controlled identity deactivation proves execution uses the persisted scoped
	// service grant, not an impersonated creator membership or login session.
	if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE (organization_id,principal_id)=($1,$2)`, o, identity.PrincipalID.String()); err != nil {
		t.Fatal(err)
	}
	return run
}
