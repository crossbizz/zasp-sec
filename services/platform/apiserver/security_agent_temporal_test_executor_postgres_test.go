package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/redteamadapter"
)

// The break caught here is delegation from an enabled definition without a
// current scoped run_tests grant. Exercise the installed API repository, so a
// migration-only helper cannot pass while production still selects obsolete55.
func TestTemporalTestExecutorServiceGrantPostgres(t *testing.T) {
	runTemporalTestGrantFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		// This grouped authority/ownership/native scenario outgrew the120s
		// predecessor fixture. Keep a finite owned bound and normal cleanup.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 4*time.Minute)
		defer cancel()
		installTemporalTestExecutorFixture(t, ctx, owner)
		db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
		if err != nil {
			t.Fatal(err)
		}
		repository := &PostgresRepository{database: db, securityAgentExecution: true}
		identity := fixtureRequestIdentity(t)
		parse := func(s string) domain.ProductID {
			id, err := domain.ParseProductID(s)
			if err != nil {
				t.Fatal(err)
			}
			return id
		}
		identity.Scope, err = domain.NewScope(parse(o), parse(w), parse(e))
		if err != nil {
			t.Fatal(err)
		}
		identity.PrincipalID = parse(actor)
		identity.CredentialKind = CredentialBrowserSession
		identity.FreshAuthenticated = true
		identity.FreshAuthExpiresAt = time.Now().UTC().Add(4 * time.Minute)
		if state, err := repository.GetSecurityAgentActivation(ctx, identity, temporalTestLegacyProved); err != nil || state.Version != 4 || !state.Enabled || state.Activation != "autonomous" {
			raw, handled, readErr := db.ReadTemporalTestDefinition(ctx, o, w, e, temporalTestLegacyProved, actor)
			t.Logf("typed read boundary handled=%v readErr=%v fixture=%s", handled, readErr, raw)
			t.Fatal("typed historical activation readback after55..74", state, err)
		}
		input := SecurityAgentActivation{DefinitionID: public62Definition, IdempotencyKey: "temporal-test-service-renewal", ExpectedVersion: 1, TargetActivation: "autonomous", FreshAuthExpiresAt: identity.FreshAuthExpiresAt,
			AuditID: "pid_f0740000-0000-4000-8000-000000000001", CorrelationID: "pid_f0740000-0000-4000-8000-000000000002", ReceiptID: "pid_f0740000-0000-4000-8000-000000000003"}
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET role='read_only_viewer' WHERE (organization_id,principal_id)=($1,$2);
UPDATE zasp_authorized_scopes SET permissions='["view","manage_workflows"]' WHERE (organization_id,workspace_id,environment_id,principal_id)=($1,$3,$4,$2)`, pgx.QueryExecModeSimpleProtocol, o, actor, w, e); err != nil {
			t.Fatal(err)
		}
		if _, err := repository.ActivateSecurityAgent(ctx, identity, input); err == nil {
			t.Fatal("read-only role delegated test execution")
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET role='security_engineer' WHERE (organization_id,principal_id)=($1,$2)`, o, actor); err != nil {
			t.Fatal(err)
		}
		var premise bool
		if err := owner.QueryRow(ctx, `SELECT public.zasp_effective_scope_permissions(s.permissions,m.role)?&ARRAY['view','manage_workflows','run_tests'] AND s.permissions?&ARRAY['view','manage_workflows'] AND NOT s.permissions?'run_tests' FROM zasp_authorized_scopes s JOIN zasp_identity_memberships m USING(organization_id,principal_id) WHERE (s.organization_id,s.workspace_id,s.environment_id,s.principal_id)=($1,$2,$3,$4)`, o, w, e, actor).Scan(&premise); err != nil || !premise {
			t.Fatal("role eligible but scoped run_tests absent premise", premise, err)
		}
		if _, err := repository.ActivateSecurityAgent(ctx, identity, input); err == nil {
			t.Fatal("manage_workflows alone delegated test execution")
		}
		var untouched bool
		if err := owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_temporal74.service_grants WHERE definition_id=$1) AND EXISTS(SELECT 1 FROM zasp_security_agent_definitions WHERE definition_id=$1 AND version=1)`, public62Definition).Scan(&untouched); err != nil || !untouched {
			t.Fatal("denied delegation changed configuration", untouched, err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET role='security_engineer' WHERE (organization_id,principal_id)=($1,$2);
UPDATE zasp_authorized_scopes SET permissions='["view","manage_workflows","run_tests"]' WHERE (organization_id,workspace_id,environment_id,principal_id)=($1,$3,$4,$2)`, pgx.QueryExecModeSimpleProtocol, o, actor, w, e); err != nil {
			t.Fatal(err)
		}
		result, err := repository.ActivateSecurityAgent(ctx, identity, input)
		if err != nil || result.Version != 2 || result.Replayed {
			t.Fatal("authorized current API grant renewal", result, err)
		}
		replayed, err := repository.ActivateSecurityAgent(ctx, identity, input)
		if err != nil || !replayed.Replayed || replayed.Version != 2 || replayed.AuditID != result.AuditID {
			t.Fatal("exact grant replay", replayed, err)
		}
		var bound bool
		if err := owner.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(principal_id=public.zasp_discovery_canonical_id(organization_id,workspace_id,environment_id,'security_agent_definition_service',definition_id)) AND bool_and(definition_version=2 AND action_key='run_test' AND test_definition_id=$2 AND grantor_id=$3 AND origin='activation') FROM zasp_temporal74.service_grants WHERE definition_id=$1`, public62Definition, testID, actor).Scan(&bound); err != nil || !bound {
			t.Fatal("service grant canonical scope and resource binding", bound, err)
		}
		// Exercise the normal transition too, including its unchanged domain
		// activation audit and exact receipt replay rather than a helper route.
		normal := input
		normal.DefinitionID = "pid_f0740000-0000-4000-8000-000000000010"
		normal.IdempotencyKey = "temporal-test-normal-activation"
		normal.AuditID = "pid_f0740000-0000-4000-8000-000000000011"
		normal.CorrelationID = "pid_f0740000-0000-4000-8000-000000000012"
		normal.ReceiptID = "pid_f0740000-0000-4000-8000-000000000013"
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_definitions(organization_id,workspace_id,environment_id,definition_id,activation,version,definition_version,body,plan_catalog_version) SELECT organization_id,workspace_id,environment_id,$2,'supervised',1,definition_version,jsonb_set(body,'{id}',to_jsonb($2::text)),plan_catalog_version FROM zasp_security_agent_definitions WHERE definition_id=$1;
INSERT INTO zasp_security_agent_definition_versions(organization_id,workspace_id,environment_id,definition_id,version,activation,definition,definition_digest,actor_id) SELECT organization_id,workspace_id,environment_id,definition_id,version,activation,body,digest(convert_to(body::text,'UTF8'),'sha256'),$3 FROM zasp_security_agent_definitions WHERE definition_id=$2`, pgx.QueryExecModeSimpleProtocol, public62Definition, normal.DefinitionID, actor); err != nil {
			t.Fatal(err)
		}
		if result, err := repository.ActivateSecurityAgent(ctx, identity, normal); err != nil || result.Version != 2 || result.Replayed {
			t.Fatal("normal activation with current service delegation", result, err)
		}
		if result, err := repository.ActivateSecurityAgent(ctx, identity, normal); err != nil || !result.Replayed || result.AuditID != normal.AuditID {
			t.Fatal("normal activation replay", result, err)
		}
		if err := owner.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(event_kind='definition_activated') FROM zasp_security_agent_audit WHERE audit_id=$1`, normal.AuditID).Scan(&bound); err != nil || !bound {
			t.Fatal("normal activation audit contract", bound, err)
		}
		assertTemporalTestFullActivation(t, ctx, owner, repository, identity)
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET body=jsonb_set(body,'{enabled}','false') WHERE definition_id=$1`, public62Definition); err != nil {
			t.Fatal(err)
		}
		if _, err := repository.ActivateSecurityAgent(ctx, identity, input); err == nil {
			t.Fatal("disabled definition replay retained delegation authority")
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET body=jsonb_set(body,'{enabled}','true') WHERE definition_id=$1`, public62Definition); err != nil {
			t.Fatal(err)
		}
		if err := owner.QueryRow(ctx, `SELECT zasp_temporal73.current_ready() AND zasp_temporal72.current_ready() AND zasp_temporal71.current_ready() AND zasp_temporal69.current_ready()`).Scan(&bound); err != nil || !bound {
			t.Fatal("accepted catalog changed", bound, err)
		}
		if _, err := owner.Exec(ctx, `CREATE ROLE temporal_test_executor_login LOGIN; CREATE ROLE temporal_test_compensation_login LOGIN; SELECT zasp_temporal68.register_principals('temporal_test_executor_login','temporal_test_compensation_login')`); err != nil {
			t.Fatal(err)
		}
		cfg := owner.Config().Copy()
		cfg.User = "temporal_test_executor_login"
		executor, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer executor.Close(ctx)
		manualRun := assertTemporalTestUntouchedOwnership(t, ctx, owner, api, executor, db, identity, o, w, e, testID, actor)
		assertTemporalTestPlanningPreparation(t, ctx, owner, executor, o, w, e, manualRun, testID, actor)
		seedOrderedTestSource(t, ctx, owner, o, w, e, actor)
		assertTemporalTestEffectPreparation(t, ctx, owner, api, executor, o, w, e, manualRun)
		if detail, err := repository.GetSecurityAgentRun(ctx, identity, manualRun); err != nil || detail.Run.State != "needs_human" || len(detail.ActionDetails) != 1 || detail.ActionDetails[0].ExistingTest == nil || detail.ActionDetails[0].ExistingTest.Verification == nil || detail.ActionDetails[0].ExistingTest.Verification.Reason != "test_baseline_unavailable" {
			t.Fatal("typed74 terminal receipt readback", detail, err)
		}
		assertTemporalTestStartAndUnknownCapacity(t, ctx, owner, api, executor, repository, identity, o, w, e, manualRun, testID)
		// The independent service grant survives its grantor losing login or
		// membership authority; the current product grant and config govern IO.
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE (organization_id,principal_id)=($1,$2)`, o, actor); err != nil {
			t.Fatal(err)
		}
		var authorized []byte
		if err := executor.QueryRow(ctx, `SELECT zasp_temporal74.authorize($1,$2,$3,$4,2)`, o, w, e, public62Definition).Scan(&authorized); err != nil {
			t.Fatal("version-bound service authority depends on creator login", err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET body=jsonb_set(body,'{enabled}','false') WHERE definition_id=$1`, public62Definition); err != nil {
			t.Fatal(err)
		}
		if err := executor.QueryRow(ctx, `SELECT zasp_temporal74.authorize($1,$2,$3,$4,2)`, o, w, e, public62Definition).Scan(&authorized); err == nil {
			t.Fatal("disabled service authority accepted")
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET body=jsonb_set(body,'{enabled}','true') WHERE definition_id=$1;
INSERT INTO zasp_temporal74.grant_revocations(organization_id,workspace_id,environment_id,definition_id,definition_version,actor_id,audit_id) VALUES($2,$3,$4,$1,2,$5,'pid_f0740000-0000-4000-8000-000000000031')`, pgx.QueryExecModeSimpleProtocol, public62Definition, o, w, e, actor); err != nil {
			t.Fatal(err)
		}
		if err := executor.QueryRow(ctx, `SELECT zasp_temporal74.authorize($1,$2,$3,$4,2)`, o, w, e, public62Definition).Scan(&authorized); err == nil {
			t.Fatal("explicitly revoked service authority accepted")
		}
		var backfill bool
		if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_temporal74.backfill_decisions WHERE definition_id=$1 AND outcome='missing_activation_proof') AND EXISTS(SELECT 1 FROM zasp_temporal74.backfill_decisions WHERE definition_id=$2 AND outcome='granted') AND EXISTS(SELECT 1 FROM zasp_temporal74.service_grants WHERE definition_id=$2 AND origin='migration') AND NOT EXISTS(SELECT 1 FROM zasp_temporal74.service_grants WHERE definition_id=$3)`, public62Definition, temporalTestLegacyProved, temporalTestLegacyTampered).Scan(&backfill); err != nil || !backfill {
			t.Fatal("conservative evidence-backed backfill", backfill, err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=true WHERE (organization_id,principal_id)=($1,$2);
UPDATE zasp_authorized_scopes SET permissions='["view","manage_workflows"]' WHERE (organization_id,workspace_id,environment_id,principal_id)=($1,$3,$4,$2)`, pgx.QueryExecModeSimpleProtocol, o, actor, w, e); err != nil {
			t.Fatal(err)
		}
		if err := executor.QueryRow(ctx, `SELECT zasp_temporal74.authorize($1,$2,$3,$4,4)`, o, w, e, temporalTestLegacyProved).Scan(&authorized); err != nil {
			t.Fatal("actual historical grant before configuration revoke", err)
		}
		handler, err := newWorkflowHTTPHandler(repository, []byte("0123456789abcdef0123456789abcdef"), time.Now)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2; i++ {
			request := workflowRequest(t, identity, "pid_f0740000-0000-4000-8000-000000000071", "deleteSecurityAgent", map[string]string{"id": temporalTestLegacyProved}, http.MethodDelete, "/api/v1/security-agents/"+temporalTestLegacyProved, "")
			request.Header.Set("Idempotency-Key", "temporal-test-grant-config-revoke")
			request.Header.Set("If-Match", `"4"`)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusNoContent {
				t.Fatalf("actual config delete/replay%d: %d %s", i, response.Code, response.Body.String())
			}
		}
		if err := executor.QueryRow(ctx, `SELECT zasp_temporal74.authorize($1,$2,$3,$4,4)`, o, w, e, temporalTestLegacyProved).Scan(&authorized); err == nil {
			t.Fatal("actual shipped config revocation retained service authority")
		}
		if err := owner.QueryRow(ctx, `SELECT count(*)=1 FROM zasp_temporal74.grant_revocations g JOIN zasp_workflow_audit a ON(a.organization_id,a.workspace_id,a.environment_id,a.audit_id,a.principal_id)=(g.organization_id,g.workspace_id,g.environment_id,g.audit_id,g.actor_id) JOIN zasp_workflow_receipts r ON(r.organization_id,r.workspace_id,r.environment_id,r.audit_id,r.principal_id)=(a.organization_id,a.workspace_id,a.environment_id,a.audit_id,a.principal_id) WHERE (g.organization_id,g.workspace_id,g.environment_id,g.definition_id,g.definition_version)=($1,$2,$3,$4,4) AND a.operation='deleteSecurityAgent' AND a.resource_version=5 AND r.resource_version=5 AND r.idempotency_key='temporal-test-grant-config-revoke'`, o, w, e, temporalTestLegacyProved).Scan(&bound); err != nil || !bound {
			t.Fatal("atomic configuration grant revocation audit/receipt", bound, err)
		}
	})
}

// A removed parent fence would let the installed70 worker claim this run after
// takeover. The fixture uses actual manual admission, not inserted run owners.
func assertTemporalTestUntouchedOwnership(t *testing.T, ctx context.Context, owner, api, executor *pgx.Conn, db *PostgresJSONDatabase, identity RequestIdentity, o, w, e, testID, actor string) string {
	t.Helper()
	run := seedShippedManualAdmission(t, ctx, owner, db, identity, o, w, e, testID, actor)
	const query = `SELECT zasp_temporal74.takeover($1,$2,$3,$4)`
	var raw json.RawMessage
	if err := api.QueryRow(ctx, query, o, w, e, run).Scan(&raw); err == nil {
		t.Fatal("API login acquired execution ownership")
	}
	if err := executor.QueryRow(ctx, query, o, w, w, run).Scan(&raw); err != nil || string(raw) != "null" {
		t.Fatal("cross-scope takeover", string(raw), err)
	}
	// A previous retained attempt is a permanent no-takeover signal even when
	// an expired worker has already cleared its lease and requeued the row.
	if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_runs SET attempt=1 WHERE run_id=$1`, run); err != nil {
		t.Fatal(err)
	}
	if err := executor.QueryRow(ctx, query, o, w, e, run).Scan(&raw); err != nil || string(raw) != "null" {
		t.Fatal("previous retained attempt was transferred", string(raw), err)
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_runs SET attempt=0 WHERE run_id=$1`, run); err != nil {
		t.Fatal(err)
	}
	locked, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := locked.Exec(ctx, `SELECT 1 FROM zasp_security_agent_runs WHERE run_id=$1 FOR UPDATE`, run); err != nil {
		t.Fatal(err)
	}
	type takeoverResult struct {
		raw json.RawMessage
		err error
	}
	race := make(chan takeoverResult, 1)
	go func() {
		var result takeoverResult
		result.err = executor.QueryRow(ctx, query, o, w, e, run).Scan(&result.raw)
		race <- result
	}()
	blocked := false
	until := time.Now().Add(10 * time.Second)
	for time.Now().Before(until) {
		if err := locked.QueryRow(ctx, `SELECT $1::integer=ANY(pg_blocking_pids($2::integer))`, int(owner.PgConn().PID()), int(executor.PgConn().PID())).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		select {
		case result := <-race:
			locked.Rollback(ctx)
			t.Fatal("takeover bypassed retained parent lock", string(result.raw), result.err)
		case <-time.After(10 * time.Millisecond):
		}
	}
	if !blocked {
		locked.Rollback(ctx)
		t.Fatal("takeover never contended on the held parent lock")
	}
	if _, err := locked.Exec(ctx, `UPDATE zasp_security_agent_runs SET attempt=1 WHERE run_id=$1`, run); err != nil {
		t.Fatal(err)
	}
	if err := locked.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if result := <-race; result.err != nil || string(result.raw) != "null" {
		t.Fatal("takeover used stale pre-lock eligibility", string(result.raw), result.err)
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_runs SET attempt=0 WHERE run_id=$1`, run); err != nil {
		t.Fatal(err)
	}
	if err := executor.QueryRow(ctx, query, o, w, e, run).Scan(&raw); err != nil || string(raw) == "null" {
		t.Fatal("untouched manual ownership transfer", string(raw), err)
	}
	first := string(raw)
	if err := executor.QueryRow(ctx, query, o, w, e, run).Scan(&raw); err != nil || string(raw) != first {
		t.Fatal("ownership retry changed logical workflow", string(raw), err)
	}
	var bound bool
	if err := owner.QueryRow(ctx, `SELECT x.workflow_id='security-agent-test/v1/'||x.organization_id||'/'||x.workspace_id||'/'||x.environment_id||'/'||x.run_id AND x.source_kind='manual65' AND old.execution_owner='legacy' AND x.definition_version=old.definition_version AND x.input_digest=old.input_digest FROM zasp_temporal74.run_owners x JOIN zasp_temporal66.run_owners old USING(organization_id,workspace_id,environment_id,run_id) WHERE x.run_id=$1`, run).Scan(&bound); err != nil || !bound {
		t.Fatal("successor changed original manual owner/input", bound, err)
	}
	config := owner.Config().Copy()
	config.User = "security_agent_v33_worker_login"
	worker, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close(ctx)
	if err := worker.QueryRow(ctx, `SELECT zasp_temporal70.op03($1,$2,$3,$4)`, "test74-fence", strings.Repeat("a", 32), 60, 10).Scan(&raw); err != nil || strings.Contains(string(raw), run) {
		t.Fatal("retained claim crossed successor fence", string(raw), err)
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_runs SET state='planning',lease_owner='old-worker',lease_token=repeat('a',32),lease_expires_at=clock_timestamp()+interval '1 minute' WHERE run_id=$1`, run); err == nil {
		t.Fatal("privileged lease mutation crossed successor fence")
	}
	if err := owner.QueryRow(ctx, `SELECT zasp_temporal74.current_ready() AND zasp_temporal73.current_ready() AND zasp_temporal71.current_ready() AND zasp_temporal69.current_ready()`).Scan(&bound); err != nil || !bound {
		t.Fatal("ownership fence changed predecessor readiness", bound, err)
	}
	workerDB, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
	if err != nil {
		t.Fatal(err)
	}
	workerRepository, err := NewSecurityAgentWorkerRepository(workerDB)
	if err != nil {
		t.Fatal(err)
	}
	if count, err := workerRepository.ScheduleSecurityAgentTriggers(ctx, "test74-owned-source", 10); err != nil || count < 1 {
		t.Fatal("real73 automatic source admission", count, err)
	}
	var automatic string
	if err := owner.QueryRow(ctx, `SELECT run_id FROM zasp_temporal73.admissions WHERE definition_id=$1`, public62Definition).Scan(&automatic); err != nil {
		t.Fatal(err)
	}
	if err := executor.QueryRow(ctx, query, o, w, e, automatic).Scan(&raw); err != nil || !strings.Contains(string(raw), `"automatic73"`) {
		t.Fatal("proved current service grant did not transfer automatic admission", string(raw), err)
	}
	if err := owner.QueryRow(ctx, `SELECT a.execution_owner='retained_single_action' AND a.trigger_digest=decode(x.input_digest,'hex') AND a.definition_version=x.definition_version FROM zasp_temporal73.admissions a JOIN zasp_temporal74.run_owners x USING(organization_id,workspace_id,environment_id,run_id) WHERE a.run_id=$1`, automatic).Scan(&bound); err != nil || !bound {
		t.Fatal("automatic successor rewrote73 admission", bound, err)
	}
	t.Log("untouched manual65 takeover preserves immutable66; repeat uses same workflow; retained70 claim and privileged lease write are fenced")
	return run
}

func assertTemporalTestPlanningPreparation(t *testing.T, ctx context.Context, owner, executor *pgx.Conn, o, w, e, run, testID, actor string, existingSelection ...map[string]any) {
	t.Helper()
	var version int64
	var action string
	if err := owner.QueryRow(ctx, `SELECT definition_version,action_key FROM zasp_temporal74.run_owners WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, o, w, e, run).Scan(&version, &action); err != nil {
		t.Fatal(err)
	}
	request := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "definition_version": version}
	call := func(op string, payload map[string]any) (map[string]any, error) {
		request["operation"] = op
		if payload == nil {
			delete(request, "payload")
		} else {
			request["payload"] = payload
		}
		body, _ := json.Marshal(request)
		var raw []byte
		err := executor.QueryRow(ctx, `SELECT zasp_temporal74.plan($1::jsonb)`, body).Scan(&raw)
		var result map[string]any
		if err == nil {
			err = json.Unmarshal(raw, &result)
		}
		return result, err
	}
	loaded, err := call("load", nil)
	if err != nil || loaded["state"] != "loaded" {
		t.Fatal("lease-free single-test planning load", loaded, err)
	}
	if again, err := call("load", nil); err != nil || !jsonEqualMaps(loaded, again) {
		t.Fatal("planning load retry changed durable context", err)
	}
	if _, err := call("start", map[string]any{}); err == nil {
		t.Fatal("unpriced/unprepared single-test planner obtained send permit")
	}
	var ready bool
	if err := owner.QueryRow(ctx, `SELECT r.state='planning' AND r.attempt=1 AND r.lease_owner IS NULL AND r.lease_token IS NULL AND r.lease_expires_at IS NULL AND b.max_steps=1 AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_provider_reservations WHERE run_id=$1) FROM zasp_security_agent_runs r JOIN zasp_security_agent_run_budgets b USING(organization_id,workspace_id,environment_id,run_id) WHERE r.run_id=$1`, run).Scan(&ready); err != nil || !ready {
		t.Fatal("planner used a retained lease/reservation", ready, err)
	}
	var selection map[string]any
	if len(existingSelection) != 0 {
		selection = existingSelection[0]
	} else {
		adminConfig := owner.Config().Copy()
		adminConfig.User = "security_agent_v33_discovery_api_login"
		admin, err := pgx.ConnectConfig(ctx, adminConfig)
		if err != nil {
			t.Fatal(err)
		}
		defer admin.Close(ctx)
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET role='organization_admin' WHERE principal_id=$1; UPDATE zasp_authorized_scopes SET permissions='["view","manage_identity","manage_workflows","run_tests"]' WHERE principal_id=$1`, pgx.QueryExecModeSimpleProtocol, actor); err != nil {
			t.Fatal(err)
		}
		policy := orderedPricingAdminRequest(o, w, e, actor)
		bindTemporalTestPlannerPricing(policy)
		pricing, err := orderedPricingCall(ctx, admin, "pricing_admin", policy)
		if err != nil {
			t.Fatal(err)
		}
		selection = orderedPricingLookupRequest(o, w, e, policy["policy"].(map[string]any), pricing)
	}
	delete(selection, "body")
	delete(selection, "body_digest")
	prepared, err := call("prepare", map[string]any{"pricing": selection, "input_version": "controlled-test74-input-v1"})
	if err != nil || prepared["state"] != "prepared" {
		t.Fatal("single-test exact pricing preparation", prepared, err)
	}
	if again, err := call("prepare", map[string]any{"pricing": selection, "input_version": "controlled-test74-input-v1"}); err != nil || !jsonEqualMaps(prepared, again) {
		t.Fatal("durable prepared request changed on retry", err)
	}
	started, err := call("start", map[string]any{})
	if err != nil || started["send_permit"] != true {
		t.Fatal("first committed planner dispatch permit", started, err)
	}
	if again, err := call("start", map[string]any{}); err != nil || again["send_permit"] != false {
		t.Fatal("unknown planner dispatch was resent", again, err)
	}
	candidate := map[string]any{"version": 1, "summary": "Run the pinned existing test", "steps": []any{map[string]any{"index": 0, "action": action, "target_id": testID}}}
	content, _ := json.Marshal(candidate)
	raw, _ := json.Marshal(map[string]any{"id": "controlled-test74-response", "model": "openai/gpt-5-mini", "choices": []any{map[string]any{"index": 0, "finish_reason": "stop", "message": map[string]any{"role": "assistant", "content": string(content)}}}, "usage": map[string]any{"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30, "cost": 0.00003}})
	if _, err := call("result", map[string]any{"raw": string(raw)}); err != nil {
		t.Fatal("controlled provider receipt", err)
	}
	settled, err := call("settle", map[string]any{})
	if err != nil || settled["state"] != "settled" {
		t.Fatal("actual usage settlement", settled, err)
	}
	if _, err := call("admit", map[string]any{}); err == nil {
		t.Fatal("plan admitted without artifact versions")
	}
	if _, err := call("artifacts", map[string]any{"input_version": "controlled-test74-input-v1", "output_version": "controlled-test74-output-v1", "output_digest": settled["output_digest"]}); err != nil {
		t.Fatal(err)
	}
	admitted, err := call("admit", map[string]any{})
	if err != nil || admitted["outcome"] != "admitted" {
		t.Fatal("single-test canonical plan admission", admitted, err)
	}
	if err := owner.QueryRow(ctx, `SELECT p.total_tokens=30 AND p.cost_nano_credits=30000 AND p.settled_at IS NOT NULL AND (SELECT count(*)=1 FROM zasp_security_agent_steps WHERE run_id=$1 AND step_index=0 AND action_key=$2) AND NOT EXISTS(SELECT 1 FROM zasp_sa_multistep_runs WHERE run_id=$1) FROM zasp_temporal74.provider_reservations p WHERE run_id=$1`, run, action).Scan(&ready); err != nil || !ready {
		t.Fatal("single-test usage/step evidence", ready, err)
	}
	t.Log("SQL planning group: durable load, exact pricing, one send permit, immutable controlled response, real usage settlement and one canonical step; external IO not claimed")
}

// This catches a retry minting a second child, bypassing current authority, or
// borrowing a retained lease to prepare the actual test transport.
func assertTemporalTestEffectPreparation(t *testing.T, ctx context.Context, owner, api, executor *pgx.Conn, o, w, e, run string) {
	t.Helper()
	var step, child string
	if err := owner.QueryRow(ctx, `SELECT step_id,test_run_id FROM zasp_temporal74.run_owners WHERE run_id=$1`, run).Scan(&step, &child); err != nil {
		t.Fatal(err)
	}
	call := func(conn *pgx.Conn, op string) (map[string]any, error) {
		body, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "step_id": step, "generation": 1, "operation": op, "payload": map[string]any{}})
		var raw []byte
		err := conn.QueryRow(ctx, `SELECT zasp_temporal74.effect($1::jsonb)`, body).Scan(&raw)
		var result map[string]any
		if err == nil {
			err = json.Unmarshal(raw, &result)
		}
		return result, err
	}
	reserved, err := call(executor, "reserve")
	if err != nil || reserved["state"] != "reserved" {
		t.Fatal("single-test effect preparation", reserved, err)
	}
	if again, err := call(executor, "reserve"); err != nil || !jsonEqualMaps(reserved, again) {
		t.Fatal("effect retry changed canonical child", again, err)
	}
	if _, err := call(api, "reserve"); err == nil {
		t.Fatal("API obtained executor effect authority")
	}
	if _, err := call(executor, "start"); err == nil {
		t.Fatal("test dispatched without immutable input")
	}
	var bound bool
	if err := owner.QueryRow(ctx, `SELECT c.state='queued' AND c.worker_id IS NULL AND c.lease_token IS NULL AND c.lease_expires_at IS NULL AND l.reconcile_token IS NULL AND l.reconcile_worker IS NULL AND l.baseline IS NULL AND EXISTS(SELECT 1 FROM zasp_red_team_outbox WHERE deterministic_key='test-jobs:'||$2 AND topic='test-jobs' AND payload=jsonb_build_object('organization_id',$3::text,'workspace_id',$4::text,'environment_id',$5::text,'run_id',$2::text,'definition_id',c.definition_id,'definition_version',c.definition_version,'input_digest',encode(c.input_digest,'hex'))) FROM zasp_security_agent_test_links l JOIN zasp_red_team_runs c ON(c.organization_id,c.workspace_id,c.environment_id,c.run_id)=(l.organization_id,l.workspace_id,l.environment_id,l.test_run_id) WHERE l.run_id=$1 AND c.run_id=$2`, run, child, o, w, e).Scan(&bound); err != nil || !bound {
		t.Fatal("canonical lease-free child and actual SQS outbox", bound, err)
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET body=jsonb_set(body,'{enabled}','false') WHERE definition_id=(SELECT definition_id FROM zasp_temporal74.run_owners WHERE run_id=$1)`, run); err != nil {
		t.Fatal(err)
	}
	if _, err := call(executor, "reserve"); err == nil {
		t.Fatal("disabled configuration retained fresh effect authority")
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET body=jsonb_set(body,'{enabled}','true') WHERE definition_id=(SELECT definition_id FROM zasp_temporal74.run_owners WHERE run_id=$1)`, run); err != nil {
		t.Fatal(err)
	}
	redWorker, adapter := orderedTestConnections(t, ctx, owner)
	defer redWorker.Close(ctx)
	defer adapter.Close(ctx)
	if _, err := adapter.Exec(ctx, `SELECT zasp_temporal74.lock_parent($1,$2,$3,$4,$5,$6)`, o, w, e, run, child, reserved["effect_key"]); err == nil {
		t.Fatal("adapter directly invoked private parent lock")
	}
	if _, err := adapter.Exec(ctx, `SET ROLE zasp_temporal74_parent_lock`); err == nil {
		t.Fatal("adapter assumed parent lock role")
	}
	if _, err := adapter.Exec(ctx, `UPDATE zasp_security_agent_effects SET state='verified' WHERE run_id=$1`, run); err == nil {
		t.Fatal("adapter directly mutated effect mirror")
	}
	lockTx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockTx.Exec(ctx, `SET LOCAL ROLE zasp_temporal74_parent_lock`); err != nil {
		t.Fatal(err)
	}
	_, mutationErr := lockTx.Exec(ctx, `UPDATE zasp_security_agent_runs SET version=version+1 WHERE run_id=$1`, run)
	if err := lockTx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if mutationErr == nil {
		t.Fatal("lock-only role acquired parent mutation authority")
	}
	driftTx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := driftTx.Exec(ctx, `ALTER ROLE zasp_temporal74_parent_lock LOGIN`); err != nil {
		t.Fatal(err)
	}
	var driftReady bool
	driftErr := driftTx.QueryRow(ctx, `SELECT zasp_temporal74.current_ready()`).Scan(&driftReady)
	if err := driftTx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if driftErr != nil || driftReady {
		t.Fatal("login-capable parent lock role passed readiness", driftReady, driftErr)
	}
	for _, change := range []struct{ name, sql string }{
		{"extra policy helper grant", `GRANT EXECUTE ON FUNCTION zasp_temporal66.legacy_visible(text,text,text,text) TO zasp_red_team_adapter`},
		{"changed predecessor helper", `CREATE OR REPLACE FUNCTION zasp_temporal66.legacy_visible(o text,w text,e text,r text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS 'SELECT true'`},
		{"changed fingerprint wrapper", `CREATE OR REPLACE FUNCTION zasp_temporal66.fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS 'SELECT repeat(''0'',64)'`},
		{"lock role membership", `GRANT zasp_red_team_adapter TO zasp_temporal74_parent_lock`},
	} {
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, change.sql); err != nil {
			t.Fatal(change.name, err)
		}
		var ready bool
		probeErr := tx.QueryRow(ctx, `SELECT zasp_temporal74.current_ready()`).Scan(&ready)
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		if probeErr != nil || ready {
			t.Fatal(change.name, "did not fail readiness", ready, probeErr)
		}
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_temporal74.predecessor_functions SET acl='' WHERE signature='zasp_temporal66.legacy_visible(text,text,text,text)'`); err == nil {
		t.Fatal("saved compatibility identity was mutable")
	}
	if err := owner.QueryRow(ctx, `SELECT zasp_temporal74.current_ready() AND zasp_temporal73.current_ready() AND zasp_temporal71.current_ready() AND zasp_temporal69.current_ready() AND zasp_temporal68.current_ready()`).Scan(&bound); err != nil || !bound {
		t.Fatal("legitimate predecessor readiness after negative probes", bound, err)
	}
	var testID string
	if err := owner.QueryRow(ctx, `SELECT test_definition_id FROM zasp_security_agent_test_links WHERE test_run_id=$1`, child).Scan(&testID); err != nil {
		t.Fatal(err)
	}
	orgID, _ := domain.ParseProductID(o)
	workspaceID, _ := domain.ParseProductID(w)
	environmentID, _ := domain.ParseProductID(e)
	scope, err := domain.NewScope(orgID, workspaceID, environmentID)
	if err != nil {
		t.Fatal(err)
	}
	var inputBody []byte
	if err := owner.QueryRow(ctx, `SELECT jsonb_build_object('schema_version','red-team-runner-input-v2','organization_id',l.organization_id,'workspace_id',l.workspace_id,'environment_id',l.environment_id,'run_id',c.run_id,'definition_id',l.test_definition_id,'definition_version',l.test_definition_version,'target_id',l.target_id,'target_kind',l.target_kind,'categories',l.test_categories,'input_digest',encode(c.input_digest,'hex'),'runner_image_digest','sha256:'||repeat('a',64)) FROM zasp_security_agent_test_links l JOIN zasp_red_team_runs c ON(c.organization_id,c.workspace_id,c.environment_id,c.run_id)=(l.organization_id,l.workspace_id,l.environment_id,l.test_run_id) WHERE c.run_id=$1`, child).Scan(&inputBody); err != nil {
		t.Fatal(err)
	}
	store, err := artifactstore.New(&orderedTestArtifactDriver{objects: make(map[artifactstore.DriverLocator]artifactstore.DriverObject)}, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	artifactID, _ := CanonicalDiscoveryID(scope, "security_agent_ordered_test_input", run+"\x1f"+step)
	ref, _ := domain.ParseEvidenceRef(artifactID)
	artifact, err := store.Put(ctx, artifactstore.PutRequest{Locator: artifactstore.Locator{Scope: scope, Reference: ref}, MediaType: "application/json", Body: inputBody})
	if err != nil {
		t.Fatal(err)
	}
	reference, err := store.ObjectReference(artifact.Locator)
	if err != nil {
		t.Fatal(err)
	}
	manifest := RedTeamArtifactReference{Reference: reference, VersionID: artifact.VersionID, SHA256: hex.EncodeToString(artifact.SHA256[:]), SizeBytes: artifact.Size}
	object, err := orderedTestReadArtifact(ctx, store, scope, artifactID, manifest, 65536)
	if err != nil {
		t.Fatal(err)
	}
	linked := func(op string, payload any) (map[string]any, error) {
		body, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "step_id": step, "generation": 1, "operation": op, "payload": payload})
		var raw []byte
		err := executor.QueryRow(ctx, `SELECT zasp_temporal74.linked($1::jsonb)`, body).Scan(&raw)
		var result map[string]any
		if err == nil {
			err = json.Unmarshal(raw, &result)
		}
		return result, err
	}
	prepared, err := linked("input", map[string]any{"manifest": manifest, "body": base64.StdEncoding.EncodeToString(object)})
	if err != nil || prepared["test_run_id"] != child {
		t.Fatal("immutable single-test runner input", prepared, err)
	}
	if result, err := linked("dispatch", map[string]any{}); err != nil || result["send_permit"] != true {
		t.Fatal("first single-test dispatch", result, err)
	}
	if result, err := linked("dispatch", map[string]any{}); err != nil || result["send_permit"] != false {
		t.Fatal("duplicate single-test dispatch", result, err)
	}
	category := prepared["categories"].([]any)[0].(string)
	adapterDB, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: adapter})
	router, err := redteamadapter.NewTestEffectRouter(ctx, adapterDB)
	if err != nil {
		t.Fatal("actual selected74 adapter readiness", err)
	}
	if _, err := router.ResolveTarget(ctx, redteamadapter.TargetResolution{Scope: scope, RunID: child, EffectKey: reserved["effect_key"].(string), TargetID: prepared["target_id"].(string), TargetKind: prepared["target_kind"].(string), Category: category}); err != nil {
		var protocol, raw []byte
		classifyErr := adapter.QueryRow(ctx, `SELECT zasp_temporal74.adapter_protocol($1,$2,$3,$4,$5)`, o, w, e, child, reserved["effect_key"]).Scan(&protocol)
		q, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": child, "effect_key": reserved["effect_key"], "operation": "resolve", "payload": map[string]any{"category": category, "target_id": prepared["target_id"], "target_kind": prepared["target_kind"]}, "checksum": migrations.ProductionTemporalTestExecutor().Checksum(), "fingerprint": migrations.TemporalTestExecutorFingerprint()})
		resolveErr := adapter.QueryRow(ctx, `SELECT zasp_temporal74.invocation($1::jsonb)`, q).Scan(&raw)
		t.Logf("adapter diagnostic protocol=%s classifyErr=%v resolveErr=%v returnedBytes=%d", protocol, classifyErr, resolveErr, len(raw))
		if detail, ok := resolveErr.(*pgconn.PgError); ok {
			t.Logf("adapter SQL context: %s", detail.Where)
		}
		t.Fatal("actual74 effect router scoped resolve", err)
	}
	var prompt string
	if err := owner.QueryRow(ctx, `SELECT zasp_sa_multistep_prior.test_prompt($1)`, category).Scan(&prompt); err != nil {
		t.Fatal(err)
	}
	promptJSON, _ := json.Marshal(prompt)
	requestBody := `{"schema_version":"red-team-target-v1","run_id":"` + child + `","target_id":"` + prepared["target_id"].(string) + `","target_kind":"` + prepared["target_kind"].(string) + `","category":"` + category + `","input":` + string(promptJSON) + `}`
	requestDigest := sha256.Sum256([]byte(requestBody))
	journal := func(op string, payload any) (map[string]any, error) {
		body, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": child, "effect_key": reserved["effect_key"], "operation": op, "payload": payload, "checksum": migrations.ProductionTemporalTestExecutor().Checksum(), "fingerprint": migrations.TemporalTestExecutorFingerprint()})
		var raw []byte
		err := adapter.QueryRow(ctx, `SELECT zasp_temporal74.invocation($1::jsonb)`, body).Scan(&raw)
		var result map[string]any
		if err == nil {
			err = json.Unmarshal(raw, &result)
		}
		return result, err
	}
	if _, err := adapter.Exec(ctx, `SELECT zasp_temporal71.op06($1,$2,$3,$4,decode(repeat('a',64),'hex'),$5,$6,$7,$8)`, o, w, e, child, category, requestDigest[:], migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()); err == nil {
		t.Fatal("old71 started a74-owned child")
	} else if pgErr, ok := err.(*pgconn.PgError); !ok || pgErr.Code != "42501" || pgErr.Message != "legacy test parent rejected" {
		t.Fatal("old71 denial was not its hidden parent boundary", err)
	}
	start := map[string]any{"category": category, "request_digest": hex.EncodeToString(requestDigest[:])}
	if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET body=jsonb_set(body,'{enabled}','false') WHERE definition_id=(SELECT definition_id FROM zasp_temporal74.run_owners WHERE run_id=$1)`, run); err != nil {
		t.Fatal(err)
	}
	if _, err := journal("start", start); err == nil {
		t.Fatal("disabled definition reached fresh category IO")
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET body=jsonb_set(body,'{enabled}','true') WHERE definition_id=(SELECT definition_id FROM zasp_temporal74.run_owners WHERE run_id=$1)`, run); err != nil {
		t.Fatal(err)
	}
	var original []byte
	if err := owner.QueryRow(ctx, `SELECT to_jsonb(f) FROM zasp_temporal74.effects f WHERE effect_key=$1`, reserved["effect_key"]).Scan(&original); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_temporal74.effects SET plan_hash=decode(repeat('d',64),'hex') WHERE effect_key=$1`, reserved["effect_key"]); err != nil {
		t.Fatal(err)
	}
	if _, err := journal("start", start); err == nil {
		t.Fatal("mismatched private/public plan reached category IO")
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_temporal74.effects f SET plan_hash=x.plan_hash FROM jsonb_populate_record(NULL::zasp_temporal74.effects,$2::jsonb)x WHERE f.effect_key=$1`, reserved["effect_key"], original); err != nil {
		t.Fatal(err)
	}
	if result, err := journal("start", start); err != nil || result["state"] != "started" {
		t.Fatal("explicit lease-free74 invocation", result, err)
	}
	if _, err := journal("start", start); err == nil {
		t.Fatal("unknown category invocation resent")
	}
	completion := map[string]any{"category": category, "request_digest": hex.EncodeToString(requestDigest[:]), "http_status": 200, "response_digest": strings.Repeat("b", 64), "protected": true, "credential_version_digest": strings.Repeat("c", 64)}
	completed, err := journal("complete", completion)
	if err != nil || completed["state"] != "completed" {
		t.Fatal("single-test immutable observation", completed, err)
	}
	if again, err := journal("complete", completion); err != nil || !jsonEqualMaps(completed, again) {
		t.Fatal("single-test observation replay", again, err)
	}
	if err := owner.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(attempt=1 AND state='completed') AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_test_invocations WHERE test_run_id=$1) FROM zasp_temporal74.invocations WHERE test_run_id=$1`, child).Scan(&bound); err != nil || !bound {
		t.Fatal("explicit journal ownership", bound, err)
	}
	// Every remaining category uses the real one-send journal. The controlled
	// engine artifact below cannot turn a missing/unknown observation into success.
	for _, item := range prepared["categories"].([]any)[1:] {
		category := item.(string)
		if err := owner.QueryRow(ctx, `SELECT zasp_sa_multistep_prior.test_prompt($1)`, category).Scan(&prompt); err != nil {
			t.Fatal(err)
		}
		promptJSON, _ := json.Marshal(prompt)
		requestBody := `{"schema_version":"red-team-target-v1","run_id":"` + child + `","target_id":"` + prepared["target_id"].(string) + `","target_kind":"` + prepared["target_kind"].(string) + `","category":"` + category + `","input":` + string(promptJSON) + `}`
		digest := sha256.Sum256([]byte(requestBody))
		start := map[string]any{"category": category, "request_digest": hex.EncodeToString(digest[:])}
		if _, err := journal("start", start); err != nil {
			t.Fatal(err)
		}
		if _, err := journal("complete", map[string]any{"category": category, "request_digest": hex.EncodeToString(digest[:]), "http_status": 200, "response_digest": strings.Repeat("b", 64), "protected": true, "credential_version_digest": strings.Repeat("c", 64)}); err != nil {
			t.Fatal(err)
		}
	}
	output := testOutputArtifactFromJournal(t, ctx, owner, store, scope, run, step, child, manifest, "zasp_temporal74.invocations")
	outputBody, err := orderedTestReadArtifact(ctx, store, scope, child, output, 1048576)
	if err != nil {
		t.Fatal(err)
	}
	settle := func(conn *pgx.Conn, op string, payload any) (map[string]any, error) {
		body, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "step_id": step, "generation": 1, "operation": op, "payload": payload})
		var raw []byte
		err := conn.QueryRow(ctx, `SELECT zasp_temporal74.test_settle($1::jsonb)`, body).Scan(&raw)
		var result map[string]any
		if err == nil {
			err = json.Unmarshal(raw, &result)
		}
		return result, err
	}
	childPayload := map[string]any{"output_manifest": output, "output_body": base64.StdEncoding.EncodeToString(outputBody)}
	badOutput := output
	badOutput.SHA256 = strings.Repeat("f", 64)
	if _, err := settle(executor, "child", map[string]any{"output_manifest": badOutput, "output_body": base64.StdEncoding.EncodeToString(outputBody)}); err == nil {
		t.Fatal("unverified output bytes completed child")
	}
	childReceipt, err := settle(executor, "child", childPayload)
	if err != nil || childReceipt["state"] != "complete" {
		t.Fatal("verified lease-free child completion", childReceipt, err)
	}
	if again, err := settle(executor, "child", childPayload); err != nil || !jsonEqualMaps(again, childReceipt) {
		t.Fatal("immutable child replay", again, err)
	}
	changedVersion := output
	changedVersion.VersionID = "different-object-version"
	if _, err := settle(executor, "child", map[string]any{"output_manifest": changedVersion, "output_body": base64.StdEncoding.EncodeToString(outputBody)}); err == nil {
		t.Fatal("child replay accepted another immutable object version")
	}
	if _, err := settle(api, "child", childPayload); err == nil {
		t.Fatal("API acquired execution settlement authority")
	}
	if err := owner.QueryRow(ctx, `SELECT r.state='running' AND c.state='complete' AND c.attempt=1 AND c.lease_token IS NULL AND a.completed_at=c.completed_at AND a.input_artifact=$3::jsonb FROM zasp_security_agent_runs r JOIN zasp_red_team_runs c ON c.run_id=$2 JOIN zasp_red_team_attempts a ON a.run_id=c.run_id AND a.attempt=1 WHERE r.run_id=$1`, run, child, manifest).Scan(&bound); err != nil || !bound {
		t.Fatal("child completion was confused with parent settlement", bound, err)
	}
	snapshot, err := settle(executor, "snapshot", map[string]any{})
	if err != nil || snapshot["before"] != nil {
		t.Fatal("exact missing baseline snapshot", snapshot, err)
	}
	after := snapshot["after"].(map[string]any)
	afterOutput := after["output_artifact"].(map[string]any)
	proof := map[string]any{"schema_version": "security-agent-test-verification-v1", "outcome": "needs_human", "reason": "test_baseline_unavailable", "after": map[string]any{"run_id": child, "attempt": 1, "input_digest": after["input_digest"], "input_artifact": after["input_artifact"], "output_artifact": map[string]any{"reference": afterOutput["reference"], "version_id": afterOutput["version_id"], "sha256": afterOutput["sha256"], "size_bytes": afterOutput["size_bytes"]}}}
	proofBytes, _ := json.Marshal(proof)
	parentPayload := map[string]any{"snapshot": snapshot, "proof_body": base64.StdEncoding.EncodeToString(proofBytes)}
	badProof := make(map[string]any)
	for key, value := range proof {
		badProof[key] = value
	}
	badProof["outcome"], badProof["reason"] = "remediated", "test_condition_changed"
	badBytes, _ := json.Marshal(badProof)
	if _, err := settle(executor, "complete", map[string]any{"snapshot": snapshot, "proof_body": base64.StdEncoding.EncodeToString(badBytes)}); err == nil {
		t.Fatal("pass without baseline became remediated")
	}
	parentReceipt, err := settle(executor, "complete", parentPayload)
	if err != nil || parentReceipt["state"] != "needs_human" || parentReceipt["reason"] != "test_baseline_unavailable" {
		t.Fatal("baseline-unavailable parent settlement", parentReceipt, err)
	}
	if again, err := settle(executor, "complete", parentPayload); err != nil || !jsonEqualMaps(again, parentReceipt) {
		t.Fatal("parent exact replay", again, err)
	}
	if err := owner.QueryRow(ctx, `SELECT r.state='needs_human' AND r.last_error_code='test_baseline_unavailable' AND r.lease_token IS NULL AND s.state='succeeded' AND l.reconcile_state='settled' AND l.reconcile_worker IS NULL AND l.reconcile_token IS NULL AND l.reconcile_settlement->'receipt'=$3::jsonb AND (SELECT count(*)=1 FROM zasp_security_agent_audit a WHERE a.run_id=r.run_id AND a.event_kind='test_reconciled') FROM zasp_security_agent_runs r JOIN zasp_security_agent_steps s USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_security_agent_test_links l USING(organization_id,workspace_id,environment_id,run_id,step_id) WHERE r.run_id=$1 AND s.step_id=$2`, run, step, parentReceipt).Scan(&bound); err != nil || !bound {
		t.Fatal("verified parent receipt persistence", bound, err)
	}
}

const temporalTestLegacyProved = "pid_f0740000-0000-4000-8000-000000000051"
const temporalTestLegacyTampered = "pid_f0740000-0000-4000-8000-000000000052"

func seedTemporalTestGrantLegacy(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e, testID, actor string, limits ...int) {
	t.Helper()
	limit, err := singleRecoveryFixtureConcurrency(limits)
	if err != nil {
		t.Fatal(err)
	}
	public62Seed(t, ctx, owner, o, w, e, testID, actor)
	if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_definitions SET enabled=true WHERE definition_id=$1;
UPDATE zasp_security_agent_definitions SET activation='autonomous',body=body||jsonb_build_object('autonomy','autonomous','max_steps',1,'allowed_actions',jsonb_build_array('run_test'),'enabled',true,'concurrency_limit',$4::integer) WHERE definition_id=$2;
INSERT INTO zasp_security_agent_definition_versions(organization_id,workspace_id,environment_id,definition_id,version,activation,definition,definition_digest,actor_id) SELECT organization_id,workspace_id,environment_id,definition_id,version,activation,body,digest(convert_to(body::text,'UTF8'),'sha256'),$3 FROM zasp_security_agent_definitions WHERE definition_id=$2`, pgx.QueryExecModeSimpleProtocol, testID, public62Definition, actor, limit); err != nil {
		t.Fatal(err)
	}
	// Controlled historical rows use the actual installed activation writer's
	// receipt and audit format; there is no current user session in this fixture.
	for _, id := range []string{temporalTestLegacyTampered} {
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_definitions(organization_id,workspace_id,environment_id,definition_id,activation,version,definition_version,body,plan_catalog_version) SELECT organization_id,workspace_id,environment_id,$2,activation,2,definition_version,jsonb_set(body,'{id}',to_jsonb($2::text)),plan_catalog_version FROM zasp_security_agent_definitions WHERE definition_id=$1;
INSERT INTO zasp_security_agent_definition_versions(organization_id,workspace_id,environment_id,definition_id,version,activation,definition,definition_digest,actor_id) SELECT organization_id,workspace_id,environment_id,definition_id,2,activation,body,digest(convert_to(body::text,'UTF8'),'sha256'),$3 FROM zasp_security_agent_definitions WHERE definition_id=$2;
INSERT INTO zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,actor_id,event_kind,event_digest,body) SELECT organization_id,workspace_id,environment_id,zasp_discovery_canonical_id(organization_id,workspace_id,environment_id,'legacy-activation-audit',definition_id),zasp_discovery_canonical_id(organization_id,workspace_id,environment_id,'legacy-activation-correlation',definition_id),$3,'definition_activated',digest(convert_to(jsonb_build_object('definition_id',definition_id,'activation',activation,'version',2)::text,'UTF8'),'sha256'),jsonb_build_object('definition_id',definition_id,'activation',activation,'version',2,'allowed_actions',body->'allowed_actions') FROM zasp_security_agent_definitions WHERE definition_id=$2;
INSERT INTO zasp_security_agent_request_receipts(organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key,resource_id,expected_version,intent,intent_digest,response,audit_id,correlation_id,receipt_id) SELECT organization_id,workspace_id,environment_id,$3,'activateSecurityAgent','legacy-activation-'||definition_id,definition_id,1,jsonb_build_object('activation',activation,'expected_version',1,'resource_id',definition_id,'fresh_auth_expires_at',clock_timestamp()-interval '1 day'),digest(convert_to(jsonb_build_object('activation',activation,'expected_version',1,'resource_id',definition_id)::text,'UTF8'),'sha256'),jsonb_build_object('id',definition_id,'activation',activation,'enabled',true,'version',2,'audit_id',zasp_discovery_canonical_id(organization_id,workspace_id,environment_id,'legacy-activation-audit',definition_id),'correlation_id',zasp_discovery_canonical_id(organization_id,workspace_id,environment_id,'legacy-activation-correlation',definition_id),'receipt_id',zasp_discovery_canonical_id(organization_id,workspace_id,environment_id,'legacy-activation-receipt',definition_id),'replayed',false),zasp_discovery_canonical_id(organization_id,workspace_id,environment_id,'legacy-activation-audit',definition_id),zasp_discovery_canonical_id(organization_id,workspace_id,environment_id,'legacy-activation-correlation',definition_id),zasp_discovery_canonical_id(organization_id,workspace_id,environment_id,'legacy-activation-receipt',definition_id) FROM zasp_security_agent_definitions WHERE definition_id=$2`, pgx.QueryExecModeSimpleProtocol, public62Definition, id, actor); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_audit SET event_digest=decode(repeat('0',64),'hex') WHERE body->>'definition_id'=$1`, temporalTestLegacyTampered); err != nil {
		t.Fatal(err)
	}
}

func runTemporalTestGrantFixture(t *testing.T, exercise func(context.Context, *pgx.Conn, *pgx.Conn, *pgx.Conn, string, string, string, string, string), starters ...func(*testing.T) string) {
	runTemporalTestGrantFixtureWithConcurrency(t, exercise, nil, starters...)
}
func runTemporalTestGrantFixtureWithConcurrency(t *testing.T, exercise func(context.Context, *pgx.Conn, *pgx.Conn, *pgx.Conn, string, string, string, string, string), limits []int, starters ...func(*testing.T) string) {
	t.Helper()
	if len(starters) > 1 {
		t.Fatal("one owned PostgreSQL starter required")
	}
	starter := func(t *testing.T) string { return startDisposablePostgresAs(t, "zasp_test") }
	if len(starters) == 1 {
		starter = starters[0]
	}
	multistepVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, testID, actor string) {
		seedTemporalTestGrantLegacy(t, ctx, owner, o, w, e, testID, actor, limits...)
		var draft, intent json.RawMessage
		if err := owner.QueryRow(ctx, `SELECT body||jsonb_build_object('id',$2::text,'enabled',false),jsonb_build_object('resource_id','','expected_version',0,'body',(body-'id')||jsonb_build_object('enabled',false)) FROM zasp_security_agent_definitions WHERE definition_id=$1`, public62Definition, temporalTestLegacyProved).Scan(&draft, &intent); err != nil {
			t.Fatal(err)
		}
		var created json.RawMessage
		createArgs := existingTestReadPins([]any{"create", temporalTestLegacyProved, o, w, e, actor, "createSecurityAgent", "actual-legacy-create-test", int64(0), intent, draft, "pid_f0740000-0000-4000-8000-000000000061", "pid_f0740000-0000-4000-8000-000000000062", "pid_f0740000-0000-4000-8000-000000000063"})
		if err := api.QueryRow(ctx, postgresSecurityAgentExistingTestDefinitionMutateSQL, createArgs...).Scan(&created); err != nil {
			t.Fatal("actual registered55 create", err)
		}
		// Historical success is produced by the actual registered55 API writer,
		// including its version history, definition_activated audit and receipt.
		for i, activation := range []string{"validated", "supervised", "autonomous"} {
			var ids [3]string
			for index, kind := range []string{"audit", "correlation", "receipt"} {
				if err := owner.QueryRow(ctx, `SELECT zasp_discovery_canonical_id($1,$2,$3,$4,$5)`, o, w, e, "legacy-test-"+kind, activation).Scan(&ids[index]); err != nil {
					t.Fatal(err)
				}
			}
			args := existingTestReadPins([]any{o, w, e, temporalTestLegacyProved, actor, "actual-legacy-activation-" + activation, int64(i + 1), activation, time.Now().UTC().Add(4 * time.Minute), ids[0], ids[1], ids[2]})
			var raw []byte
			if err := api.QueryRow(ctx, postgresExistingTestActivateSQL, args...).Scan(&raw); err != nil {
				t.Fatal("actual registered55 activation", activation, err)
			}
			var result SecurityAgentActivationResult
			if err := json.Unmarshal(raw, &result); err != nil || result.Version != int64(i+2) || result.Activation != activation || result.Replayed {
				t.Fatal("typed actual55 activation", result, err)
			}
		}
		runner := precisionMigrationRunner(t, owner)
		for _, up := range []func(context.Context) error{runner.UpProductionCompliance, runner.UpProductionSecurityAgentAttackLab, runner.UpProductionSecurityAgentExports, runner.UpProductionSecurityAgentWebhooks, runner.UpProductionDiscoveryScheduleReplay} {
			if err := up(ctx); err != nil {
				t.Fatal("actual activation upgrade56..60", err)
			}
		}
		exercise(ctx, owner, nil, api, o, w, e, testID, actor)
	}, starter)
}
