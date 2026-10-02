package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Removing the durable fence must expose the fresh Temporal run to a real old
// claim. Removing the facade must break manual admission on the same61 install.
func TestTemporalOwnershipAdmissionPostgres(t *testing.T) {
	runTemporalOwnershipAdmissionPostgres(t, false)
}

// The same product operations must survive the67 authority cutover. This is
// an affected integration group, not another test of unchanged66 mechanics.
func TestTemporalDomainUpgradePostgres(t *testing.T) {
	runTemporalOwnershipAdmissionPostgres(t, true)
}

func runTemporalOwnershipAdmissionPostgres(t *testing.T, domainCutover bool) {
	modes := []string{"registered66", "registered66_optional"}
	if domainCutover {
		modes = append(modes, "registered61_optional", "clean60")
	}
	for _, mode := range modes {
		optional := strings.HasSuffix(mode, "_optional")
		name := mode
		if !domainCutover {
			name = fmt.Sprintf("retire_optional_%t", optional)
		}
		t.Run(name, func(t *testing.T) {
			fixture := runOrderedProgressionFixture
			if mode == "clean60" {
				fixture = runTemporalDomainFreshFixture
			}
			fixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
				if mode != "clean60" {
					installTemporalOutbox(t, ctx, owner)
				}
				runner := precisionMigrationRunner(t, owner)
				if optional {
					if err := runner.UpProductionSecurityAgentWorker(ctx); err != nil {
						t.Fatal(err)
					}
					if err := runner.UpProductionSecurityAgentScheduler(ctx); err != nil {
						t.Fatal(err)
					}
				}
				up, ok := any(runner).(interface{ UpProductionTemporalOwnership(context.Context) error })
				if !ok {
					t.Fatal("Temporal ownership migration missing")
				}
				if mode != "registered61_optional" && mode != "clean60" {
					if !optional {
						runOwnershipCLI(t, ctx, owner)
					}
					if err := up.UpProductionTemporalOwnership(ctx); err != nil {
						tx, txErr := owner.Begin(ctx)
						if txErr != nil {
							t.Fatal(txErr)
						}
						defer tx.Rollback(ctx)
						_, ddlErr := tx.Exec(ctx, migrations.ProductionTemporalOwnership().UpSQL())
						var fingerprint string
						fpErr := tx.QueryRow(ctx, `SELECT zasp_temporal66.fingerprint()`).Scan(&fingerprint)
						t.Fatalf("ownership install=%v DDL=%#v fingerprint=%s query=%v", err, ddlErr, fingerprint, fpErr)
					}
					if err := up.UpProductionTemporalOwnership(ctx); err != nil {
						t.Fatal("ownership replay", err)
					}
				}
				cutover := func() {
					var historicalBefore, historicalAfter string
					if mode != "clean60" {
						if err := owner.QueryRow(ctx, `SELECT pg_get_functiondef('public.zasp_sa_multistep_readiness(text,text)'::regprocedure)`).Scan(&historicalBefore); err != nil {
							t.Fatal(err)
						}
					}
					runTemporalMigrationCLI(t, ctx, owner, "up-temporal-domain")
					if err := runner.UpProductionTemporalDomain(ctx); err != nil {
						t.Fatal("domain replay", err)
					}
					var portable string
					if err := owner.QueryRow(ctx, `SELECT zasp_temporal67.base_fingerprint()`).Scan(&portable); err != nil || portable != migrations.TemporalDomainBaseFingerprint() {
						t.Fatal("portable61 identity", portable, err)
					}
					if mode != "clean60" {
						if err := owner.QueryRow(ctx, `SELECT pg_get_functiondef('public.zasp_sa_multistep_readiness(text,text)'::regprocedure)`).Scan(&historicalAfter); err != nil || historicalBefore != historicalAfter {
							t.Fatal("historical61 readiness changed", err)
						}
					}
				}
				retainedOwner := domainCutover && strings.HasPrefix(mode, "registered66")
				if domainCutover && !retainedOwner {
					cutover()
				}
				if retainedOwner {
					if _, err := owner.Exec(ctx, `INSERT INTO zasp_temporal66.admission_routes(organization_id,workspace_id,environment_id,execution_owner) VALUES($1,$2,$3,'temporal')`, o, w, e); err != nil {
						t.Fatal(err)
					}
				}
				public62Seed(t, ctx, owner, o, w, e, testID, actor)
				q := public62Request(o, w, e, actor, "activate")
				q["definition_id"], q["definition_version"] = public62Definition, 1
				if _, err := public62Call(ctx, api, q); err != nil {
					t.Fatal("ordered activation", err)
				}
				q = public62Request(o, w, e, actor, "trigger_resource")
				q["definition_id"], q["definition_version"], q["trigger_id"], q["trigger_version"], q["idempotency_key"] = public62Definition, 2, public62Finding, 1, "owner-ordered-0001"
				q["trigger_kind"], q["trigger_source"] = "finding", "credential"
				ordered, err := public62Call(ctx, api, q)
				if err != nil {
					t.Fatal("ordered admission", err)
				}
				var orderedOwner string
				expectedOwner := "legacy"
				if retainedOwner {
					expectedOwner = "temporal"
				}
				if err := owner.QueryRow(ctx, `SELECT execution_owner FROM zasp_temporal66.run_owners WHERE run_id=$1`, ordered["id"]).Scan(&orderedOwner); err != nil || orderedOwner != expectedOwner {
					t.Fatal("default owner activated", orderedOwner, ordered, err)
				}
				if retainedOwner {
					snapshot := func() string {
						var value string
						if err := owner.QueryRow(ctx, `SELECT jsonb_build_array(to_jsonb(c),to_jsonb(r))::text FROM zasp_temporal65.commands c JOIN zasp_temporal66.run_owners r USING(organization_id,workspace_id,environment_id,run_id) WHERE c.run_id=$1`, ordered["id"]).Scan(&value); err != nil {
							t.Fatal(err)
						}
						return value
					}
					before := snapshot()
					cutover()
					if snapshot() != before {
						t.Fatal("cutover changed retained command/owner")
					}
				}
				// Only this disposable DB's superuser configures the candidate route.
				// The shipped migration grants no runtime role this capability.
				if _, err := owner.Exec(ctx, `INSERT INTO zasp_temporal66.admission_routes(organization_id,workspace_id,environment_id,execution_owner) VALUES($1,$2,$3,'temporal') ON CONFLICT DO NOTHING`, o, w, e); err != nil {
					t.Fatal(err)
				}
				const manualDefinition = "pid_aa000001-0000-4000-8000-000000000001"
				_, err = owner.Exec(ctx, `INSERT INTO zasp_security_agent_definitions(organization_id,workspace_id,environment_id,definition_id,activation,version,definition_version,body,plan_catalog_version)
 SELECT organization_id,workspace_id,environment_id,$4,'supervised',1,1,(body-'existing_test')||jsonb_build_object('id',$4::text,'enabled',true,'autonomy','supervised','max_steps',1,'allowed_actions',jsonb_build_array('create_evidence_export'),'verification_kind','export'),'security-agent-actions-v1' FROM zasp_security_agent_definitions WHERE definition_id=$5;
 INSERT INTO zasp_security_agent_definition_versions(organization_id,workspace_id,environment_id,definition_id,version,activation,definition,definition_digest,actor_id) SELECT organization_id,workspace_id,environment_id,definition_id,version,activation,body,digest(convert_to(body::text,'UTF8'),'sha256'),$6 FROM zasp_security_agent_definitions WHERE definition_id=$4;
 UPDATE zasp_authorized_scopes SET permissions='["view","manage_workflows","run_tests","view_audit"]' WHERE (organization_id,principal_id)=($1,$6);
 INSERT INTO zasp_security_agent_kill_switches(organization_id,workspace_id,environment_id,action_key,execution_enabled,updated_by) VALUES($1,$2,$3,'create_evidence_export',true,$6) ON CONFLICT DO NOTHING`, pgx.QueryExecModeSimpleProtocol, o, w, e, manualDefinition, public62Definition, actor)
				if err != nil {
					t.Fatal(err)
				}
				const run = "pid_aa000002-0000-4000-8000-000000000002"
				const audit = "pid_aa000003-0000-4000-8000-000000000003"
				const receipt = "pid_aa000004-0000-4000-8000-000000000004"
				database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
				if err != nil {
					t.Fatal(err)
				}
				identity := fixtureRequestIdentity(t)
				parse := func(raw string) domain.ProductID {
					v, err := domain.ParseProductID(raw)
					if err != nil {
						t.Fatal(err)
					}
					return v
				}
				identity.Scope, err = domain.NewScope(parse(o), parse(w), parse(e))
				if err != nil {
					t.Fatal(err)
				}
				identity.PrincipalID = parse(actor)
				identity.CredentialKind = CredentialBrowserSession
				repository := &PostgresRepository{database: database, securityAgentExecution: true}
				invoke := func(version int64) ([]byte, error) {
					result, err := repository.runSecurityAgentManual(ctx, identity, SecurityAgentRunRequest{DefinitionID: manualDefinition, ExpectedVersion: version, IdempotencyKey: "owner-manual-0001", RunID: run, AuditID: audit, CorrelationID: audit, ReceiptID: receipt, TriggerKind: "manual"})
					raw, _ := json.Marshal(result)
					return raw, err
				}
				if _, err := api.Exec(ctx, "BEGIN"); err != nil {
					t.Fatal(err)
				}
				if _, err := invoke(1); err != nil {
					t.Fatal("manual admission", err)
				}
				if _, err := api.Exec(ctx, "ROLLBACK"); err != nil {
					t.Fatal(err)
				}
				var count int
				if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_temporal66.run_owners WHERE run_id=$1`, run).Scan(&count); err != nil || count != 0 {
					t.Fatal("owner escaped rollback", count, err)
				}
				if _, err := invoke(1); err != nil {
					t.Fatal("manual admission", err)
				}
				raw, err := invoke(1)
				var replay map[string]any
				if err != nil || json.Unmarshal(raw, &replay) != nil || replay["replayed"] != true || replay["receipt_id"] != receipt {
					t.Fatal("manual replay", string(raw), err)
				}
				if _, err := invoke(2); err == nil {
					t.Fatal("stale definition admitted")
				}
				if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE (organization_id,principal_id)=($1,$2)`, o, actor); err != nil {
					t.Fatal(err)
				}
				if _, err := invoke(1); err == nil {
					t.Fatal("deactivated requester replayed admission")
				}
				if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=true WHERE (organization_id,principal_id)=($1,$2)`, o, actor); err != nil {
					t.Fatal(err)
				}
				if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_temporal65.commands c JOIN zasp_temporal66.run_owners r USING(organization_id,workspace_id,environment_id,run_id) WHERE c.run_id=$1 AND c.execution_owner='temporal' AND r.execution_owner='temporal'`, run).Scan(&count); err != nil || count != 1 {
					t.Fatal("capture owner differs", count, err)
				}
				// Old selectors cannot see the migrated run, even with correct tenant IDs.
				var claimed []byte
				if err := worker.QueryRow(ctx, `SELECT public.zasp_security_agent_claim_runs_v23('legacy-worker','legacy-token-000001',300,25)`).Scan(&claimed); err != nil {
					t.Fatal("old claim", err)
				}
				if strings.Contains(string(claimed), run) {
					t.Fatal("old selector exposed Temporal run", string(claimed))
				}
				for _, op := range []string{"claim", "reconcile", "start"} {
					q := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "worker_id": "old-worker", "lease_token": "old-worker-token-0001", "operation": op, "payload": map[string]any{}}
					_, err := orderedProgressionCall(ctx, worker, "planning", q)
					expected := "planning run absent"
					if mode == "clean60" {
						expected = "planning release unavailable"
					}
					if err == nil || !strings.Contains(err.Error(), expected) {
						t.Fatal("direct planning was not fenced at run read", op, err)
					}
				}
				var lease bool
				if err := owner.QueryRow(ctx, `SELECT lease_owner IS NOT NULL FROM zasp_security_agent_runs WHERE run_id=$1`, run).Scan(&lease); err != nil || lease {
					t.Fatal("legacy claimed temporal", lease, err)
				}
				if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_runs SET state='planning',lease_owner='old',lease_token='old-token-000001',lease_expires_at=clock_timestamp()+interval '1 minute' WHERE run_id=$1`, run); err == nil || !strings.Contains(err.Error(), "Temporal run rejects legacy execution authority") {
					t.Fatal("legacy lease row guard absent", err)
				}
				assertTemporalEffectGuard(t, ctx, owner, o, w, e, run)
				if mode != "clean60" {
					assertTemporalDirectClaims(t, ctx, owner, worker, o, w, e, run, manualDefinition)
				}
				if _, err := owner.Exec(ctx, `UPDATE zasp_temporal66.run_owners SET execution_owner='legacy' WHERE run_id=$1`, run); err == nil {
					t.Fatal("owner mutable")
				}
				detail, err := repository.GetSecurityAgentRun(ctx, identity, run)
				if err != nil || detail.Run.ManualTrigger == nil {
					t.Fatal("manual read contract lost", detail, err)
				}
				const decision = "pid_aa000005-0000-4000-8000-000000000005"
				if _, err := repository.CancelSecurityAgentRun(ctx, identity, SecurityAgentCancelRequest{RunID: run, IdempotencyKey: "owner-cancel-0001", ExpectedVersion: 1, AuditID: decision, CorrelationID: decision, ReceiptID: decision}); err != nil {
					t.Fatal("manual cancellation", err)
				}
				if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_temporal65.commands WHERE run_id=$1 AND kind='cancel' AND execution_owner='temporal' AND decision_id=$2`, run, decision).Scan(&count); err != nil || count != 1 {
					t.Fatal("decision owner missing", count, err)
				}
				for _, mutation := range []string{`ALTER TABLE public.zasp_security_agent_runs DISABLE TRIGGER zasp_temporal66_lease`, `DROP POLICY zasp_temporal66_owner ON public.zasp_security_agent_runs`, `ALTER TABLE zasp_temporal65.commands DISABLE TRIGGER zasp_temporal66_capture`} {
					tx, err := owner.Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := tx.Exec(ctx, mutation); err != nil {
						t.Fatal(err)
					}
					var ready bool
					if err := tx.QueryRow(ctx, `SELECT zasp_temporal66.ready($1,$2)`, migrations.ProductionTemporalOwnership().Checksum(), migrations.TemporalOwnershipFingerprint()).Scan(&ready); err != nil || ready {
						t.Fatal("drift accepted", ready, err)
					}
					if err := tx.Rollback(ctx); err != nil {
						t.Fatal(err)
					}
				}
				for _, statement := range []string{`INSERT INTO zasp_temporal66.admission_routes VALUES('x','x','x','temporal')`, `UPDATE zasp_temporal66.run_owners SET execution_owner='temporal'`, `UPDATE zasp_temporal65.commands SET execution_owner='temporal'`} {
					if _, err := api.Exec(ctx, statement); err == nil {
						t.Fatal("API can activate ownership", statement)
					}
				}
				if optional {
					for _, statement := range []string{`SELECT zasp_ordered_worker63.worker('x','x','{}')`, `SELECT zasp_ordered_scheduler64.scheduler('x','x','{}')`} {
						if _, err := worker.Exec(ctx, statement); err == nil || !strings.Contains(err.Error(), "permission denied for function") {
							t.Fatal("retired caller not denied by ACL", err)
						}
					}
				}
				if err := runner.UpProductionSecurityAgentWorker(ctx); err == nil {
					t.Fatal("retired worker could be installed after66")
				}
				if err := runner.UpProductionSecurityAgentScheduler(ctx); err == nil {
					t.Fatal("retired scheduler could be installed after66")
				}
			})
		})
	}
}

func assertTemporalDirectClaims(t *testing.T, ctx context.Context, owner, worker *pgx.Conn, o, w, e, r, definition string) {
	t.Helper()
	// Seed only lock prerequisites. These probes must reach the actual run read,
	// not fail on missing budget, malformed input or an unrelated approval check.
	if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_org_admissions VALUES($1) ON CONFLICT DO NOTHING;
 INSERT INTO zasp_security_agent_run_budgets(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,started_at,deadline_at,max_steps,max_tokens,concurrency_limit) VALUES($1,$2,$3,$4,$5,1,clock_timestamp(),clock_timestamp()+interval '1 hour',1,100,1)`, pgx.QueryExecModeSimpleProtocol, o, w, e, r, definition); err != nil {
		t.Fatal(err)
	}
	defer owner.Exec(ctx, `DELETE FROM zasp_security_agent_run_budgets WHERE run_id=$1`, r)
	action := orderedActionFenceConnection(t, ctx, owner)
	defer action.Close(ctx)
	deployment := orderedApplicationDeploymentConnection(t, ctx, owner)
	defer deployment.Close(ctx)
	for _, op := range []string{"claim", "heartbeat"} {
		for _, probe := range []struct {
			name string
			conn *pgx.Conn
			q    map[string]any
		}{
			{"application", action, orderedApplicationRequest(o, w, e, r, r, op, 1, 0)},
			{"cleanup", action, orderedCleanupRequest(o, w, e, r, r, op, 1, 1, 0)},
			{"test_action", worker, orderedTestActionRequest(o, w, e, r, r, op, 1, 0)},
		} {
			if _, err := orderedProgressionCall(ctx, probe.conn, probe.name, probe.q); err == nil || !strings.Contains(err.Error(), "ordered run absent") {
				t.Fatal("direct authority was not fenced at run read", probe.name, op, err)
			}
		}
	}
	q := orderedApplicationDeploymentRequest(o, w, e, r, r, map[string]any{"run_version": 1, "effect_version": 1, "targets": []any{map[string]any{"device_id": r, "credential_id": r, "sequence": 1, "envelope_digest": "sha256:" + strings.Repeat("a", 64), "desired_generation": 1}}})
	if _, err := orderedProgressionCall(ctx, deployment, "deployment", q); err == nil || !strings.Contains(err.Error(), "ordered run absent") {
		t.Fatal("deployment authority was not fenced at run read", err)
	}
	var result []byte
	if err := action.QueryRow(ctx, `SELECT zasp_security_agent_claim_temporary_policy_effects('legacy-action','legacy-action-lease',60,25)`).Scan(&result); err != nil || strings.Contains(string(result), r) {
		t.Fatal("legacy action/recovery selector exposed Temporal run", string(result), err)
	}
}

func assertTemporalEffectGuard(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e, r string) {
	t.Helper()
	tx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `INSERT INTO zasp_security_agent_effects(organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest,state,lease_owner,lease_token,lease_expires_at) VALUES($1,$2,$3,$4,$4,'create_temporary_policy',decode(repeat('ab',32),'hex'),'leased','legacy','legacy-token-0001',clock_timestamp()+interval '1 minute')`, o, w, e, r); err == nil || !strings.Contains(err.Error(), "Temporal run rejects legacy execution authority") {
		t.Fatal("effect insert bypassed guard", err)
	}
}

func runOwnershipCLI(t *testing.T, ctx context.Context, owner *pgx.Conn) {
	runTemporalMigrationCLI(t, ctx, owner, "up-temporal-ownership")
}

func runTemporalMigrationCLI(t *testing.T, ctx context.Context, owner *pgx.Conn, operation string) {
	t.Helper()
	command := exec.CommandContext(ctx, "go", "run", "../agentsec-migrate", operation)
	command.Env = append(os.Environ(), "ZASP_POSTGRES_DSN="+owner.Config().ConnString(), "ZASP_MIGRATION_TIMEOUT=30s", "ZASP_MIGRATION_DB_PRINCIPAL="+owner.Config().User)
	// Registration66 only checks the already-bound migration principal. Keep
	// the real existing principal bindings in the command environment.
	rows, err := owner.Query(ctx, `SELECT principal_name,authority_role FROM public.zasp_discovery_principal_bindings UNION SELECT principal_name,authority_role FROM public.zasp_security_agent_principal_bindings`)
	if err != nil {
		t.Fatal(err)
	}
	bindings := map[string]string{}
	for rows.Next() {
		var principal, role string
		if err := rows.Scan(&principal, &role); err != nil {
			t.Fatal(err)
		}
		bindings[role] = principal
	}
	rows.Close()
	for index, name := range []string{"DISCOVERY_API", "DISCOVERY_WORKER", "RUNTIME_INGEST", "RUNTIME_WORKER", "OUTBOX_WORKER", "RUNTIME_GATEWAY", "DISCOVERY_SCHEDULER", "PROJECTION_RISK_WORKER", "PROJECTION_GRAPH_WORKER", "PROJECTION_SEARCH_WORKER", "RUNTIME_COORDINATOR", "RUNTIME_ARCHIVE_WORKER", "RUNTIME_INDEX_WORKER", "RUNTIME_CORRELATION_WORKER", "RUNTIME_PROJECTION_WORKER", "GATEWAY_CONTROL", "SECURITY_AGENT_API", "SECURITY_AGENT_WORKER", "SECURITY_AGENT_ACTION_WORKER", "RED_TEAM_WORKER", "RED_TEAM_OUTBOX", "RED_TEAM_ADAPTER", "ATTACK_LAB_CONTROLLER", "ATTACK_LAB_OUTBOX", "ATTACK_LAB_PROXY", "RECOVERY_WORKER", "RECOVERY_OUTBOX", "POLICY_DEPLOYMENT_WORKER"} {
		principal := bindings["zasp_"+strings.ToLower(name)]
		if principal == "" {
			principal = fmt.Sprintf("unused_existing_principal_%02d", index)
		}
		envName := name
		if strings.HasPrefix(name, "PROJECTION_") || strings.HasPrefix(name, "RUNTIME_") && name != "RUNTIME_WORKER" || name == "POLICY_DEPLOYMENT_WORKER" || name == "SECURITY_AGENT_ACTION_WORKER" {
			envName = strings.TrimSuffix(name, "_WORKER")
		}
		command.Env = append(command.Env, "ZASP_"+envName+"_DB_PRINCIPAL="+principal)
	}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("actual ownership CLI: %v %s", err, output)
	}
}
