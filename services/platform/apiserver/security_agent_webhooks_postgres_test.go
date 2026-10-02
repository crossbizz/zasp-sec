package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func webhookOwnedPostgres(t *testing.T) string {
	t.Helper()
	port, err := strconv.Atoi(os.Getenv("ZASP_WEBHOOK_TEST_PORT"))
	if err != nil || port < 1024 || port > 65535 || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(os.Getenv("ZASP_WEBHOOK_TEST_CONTAINER")) {
		t.Fatal("webhook proof requires its owned network-disabled PostgreSQL runner")
	}
	return fmt.Sprintf("postgres://zasp_e2e@127.0.0.1:%d/postgres?sslmode=disable", port)
}

// Missing registration must fail after a real, exact release58 install. It
// cannot be hidden by an unavailable host initdb or an environment skip.
func runWebhookAuthorityFixture(t *testing.T, exercise func(context.Context, *pgx.Conn, *pgx.Conn, string, string, string, string)) {
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, testID, actor string) {
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionCompliance(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionSecurityAgentAttackLab(ctx); err != nil {
			t.Fatal(err)
		}
		applyExport58(t, ctx, owner)
		t.Logf("installed predecessor58 checksum=%s fingerprint=%s", migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint())
		upgrade, ok := any(runner).(interface{ UpProductionSecurityAgentWebhooks(context.Context) error })
		if !ok {
			t.Fatal("registered response webhook migration59 is missing")
		}
		if err := upgrade.UpProductionSecurityAgentWebhooks(ctx); err != nil {
			tx, debugErr := owner.Begin(ctx)
			if debugErr != nil {
				t.Fatalf("candidate59=%v diagnostic=%v", err, debugErr)
			}
			defer tx.Rollback(context.Background())
			_, debugErr = tx.Exec(ctx, migrations.ProductionSecurityAgentWebhooks().UpSQL())
			if debugErr != nil {
				t.Fatalf("candidate59=%v SQL=%v", err, debugErr)
			}
			var fingerprint string
			debugErr = tx.QueryRow(ctx, `SELECT public.zasp_sa_webhook_live_fingerprint()`).Scan(&fingerprint)
			t.Fatalf("candidate59=%v observed fingerprint=%s diagnostic=%v", err, fingerprint, debugErr)
		}
		var raw []byte
		t.Logf("installed candidate59 checksum=%s fingerprint=%s", migrations.ProductionSecurityAgentWebhooks().Checksum(), migrations.SecurityAgentWebhooksFingerprint())
		if err := api.QueryRow(ctx, `SELECT public.zasp_get_security_agent_webhook($1,$2,$3,$4,$5,$6,$7,$8)`, o, w, e, actor, "missing-session", testID, testID, testID).Scan(&raw); err == nil {
			t.Fatal("missing session gained webhook status authority")
		}
		exercise(ctx, owner, api, o, w, e, actor)
	}, webhookOwnedPostgres)
}

type webhookPGFixture struct {
	ctx                                  context.Context
	owner, api, worker, dispatch         *pgx.Conn
	o, w, e, actor, agent, run, approval string
	status                               ResponseWebhookStatus
	id                                   func() string
}

var webhookSequence int

func webhookNonExportSibling(t *testing.T, candidate bool, family string) {
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, testID, actor string) {
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionCompliance(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionSecurityAgentAttackLab(ctx); err != nil {
			t.Fatal(err)
		}
		applyExport58(t, ctx, owner)
		if candidate {
			if err := runner.UpProductionSecurityAgentWebhooks(ctx); err != nil {
				t.Fatal(err)
			}
		}
		t.Logf("non-webhook sibling release=%d", map[bool]int{false: 58, true: 59}[candidate])
		cfg := owner.Config().Copy()
		cfg.User = "security_agent_v33_worker_login"
		worker, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close(context.Background())
		f := &exportDBFixture{ctx: ctx, owner: owner, api: api, worker: worker, o: o, w: w, e: e, actor: actor}
		if family == "attack_lab" {
			seedExportRouteAttackLabDefinition(t, ctx, owner, api, o, w, e, testID, actor)
			exerciseAttackLabRegisteredDispatch(t, ctx, owner, api, o, w, e, testID, actor, true, false)
			var exact bool
			if err = owner.QueryRow(ctx, `SELECT d.activation='autonomous' AND d.version=5 AND h.activation=d.activation AND h.definition=d.body AND h.actor_id=$4 AND h.definition_digest=digest(convert_to(d.body::text,'UTF8'),'sha256') FROM zasp_security_agent_definitions d JOIN zasp_security_agent_definition_versions h USING(organization_id,workspace_id,environment_id,definition_id,version) WHERE (d.organization_id,d.workspace_id,d.environment_id,d.definition_id)=($1,$2,$3,'pid_6a000004-0000-4000-8000-000000000004')`, o, w, e, actor).Scan(&exact); err != nil || !exact {
				t.Fatalf("Attack Lab fixture changed registered definition history: exact=%t err=%v", exact, err)
			}
			var run string
			if err = owner.QueryRow(ctx, `SELECT run_id FROM zasp_sa_attack_lab_links WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)`, o, w, e).Scan(&run); err != nil {
				t.Fatal(err)
			}
			raw, err := exportRunKind(f, worker, o, w, e, run, "attack-lab-worker", "attack-lab-dispatch-lease")
			if err != nil || string(raw) != `{"export": false}` {
				t.Fatalf("durable Attack Lab replay route=%s %v", raw, err)
			}
			if _, err = exportRunKind(f, worker, o, w, e, run, "attack-lab-worker", "foreign-attack-lab-lease"); err == nil {
				t.Fatal("foreign Attack Lab replay routed")
			}
			if _, err = owner.Exec(ctx, `UPDATE zasp_security_agent_approvals SET version=version+1 WHERE run_id=$1`, run); err != nil {
				t.Fatal(err)
			}
			if _, err = exportRunKind(f, worker, o, w, e, run, "attack-lab-worker", "attack-lab-dispatch-lease"); err == nil {
				t.Fatal("changed Attack Lab approval routed")
			}
			return
		}
		const run = "pid_8e140001-0000-4000-8000-000000000001"
		const finding = "pid_8e140002-0000-4000-8000-000000000002"
		const workerID = "export-route-existing-test"
		const planningLease = "export-route-planning-lease"
		const dispatchLease = "export-route-dispatch-lease"
		seedExistingTestPreparation(t, ctx, owner, o, w, e, testID, actor, run, finding, "run_test", workerID, planningLease)
		if _, err = owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET activation='autonomous',body=jsonb_set(body,'{autonomy}','"autonomous"') WHERE organization_id=$1;
 INSERT INTO zasp_security_agent_definition_versions(organization_id,workspace_id,environment_id,definition_id,version,activation,definition,definition_digest,actor_id) SELECT organization_id,workspace_id,environment_id,definition_id,version,activation,body,digest(convert_to(body::text,'UTF8'),'sha256'),$2 FROM zasp_security_agent_definitions WHERE organization_id=$1 ON CONFLICT(organization_id,workspace_id,environment_id,definition_id,version) DO UPDATE SET activation=excluded.activation,definition=excluded.definition,definition_digest=excluded.definition_digest,actor_id=excluded.actor_id;
 INSERT INTO zasp_security_agent_kill_switches(organization_id,workspace_id,environment_id,action_key,execution_enabled,updated_by) VALUES($1,$3,$4,'run_test',true,$2) ON CONFLICT(organization_id,workspace_id,environment_id,action_key) DO UPDATE SET execution_enabled=true`, pgx.QueryExecModeSimpleProtocol, o, actor, w, e); err != nil {
			t.Fatal(err)
		}
		raw, err := exportRunKind(f, worker, o, w, e, run, workerID, planningLease)
		if err != nil || string(raw) != `{"export": false}` {
			t.Fatalf("unplanned existing-test route=%s %v", raw, err)
		}
		if err = worker.QueryRow(ctx, existingTestPrepareSQL, o, w, e, run, workerID, planningLease, "pid_8e140003-0000-4000-8000-000000000003", time.Now().UTC().Add(5*time.Minute), "pid_8e140004-0000-4000-8000-000000000004", "pid_8e140005-0000-4000-8000-000000000005").Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if err = worker.QueryRow(ctx, postgresSecurityAgentClaimRunsV24SQL, workerID, dispatchLease, 60, 1).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		raw, err = exportRunKind(f, worker, o, w, e, run, workerID, dispatchLease)
		if err != nil || string(raw) != `{"export": false}` {
			t.Fatalf("planned existing-test route=%s %v", raw, err)
		}
		execute := func() error {
			return worker.QueryRow(ctx, `SELECT zasp_production_security_agent_existing_tests_execute_run($1,$2,$3,$4,$5,$6,'pid_8e140006-0000-4000-8000-000000000006','pid_8e140007-0000-4000-8000-000000000007',$7,$8)`, o, w, e, run, workerID, dispatchLease, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()).Scan(&raw)
		}
		if err = execute(); err != nil {
			t.Fatal(err)
		}
		before := existingTestAcceptanceSnapshot(t, ctx, owner, o, w, e, run)
		if err = execute(); err == nil {
			t.Fatal("predecessor unexpectedly permits cleared-lease replay")
		}
		if _, err = exportRunKind(f, worker, o, w, e, run, workerID, dispatchLease); err == nil {
			t.Fatal("route invented existing-test replay authority")
		}
		if got := existingTestAcceptanceSnapshot(t, ctx, owner, o, w, e, run); got != before {
			t.Fatal("refused replay mutated state")
		}
	}, webhookOwnedPostgres)
}

func TestSecurityAgentWebhookPrior58ExistingTestPostgres(t *testing.T) {
	webhookNonExportSibling(t, false, "existing_test")
}
func TestSecurityAgentWebhookPrior58AttackLabPostgres(t *testing.T) {
	webhookNonExportSibling(t, false, "attack_lab")
}
func TestSecurityAgentWebhookCandidate59ExistingTestPostgres(t *testing.T) {
	webhookNonExportSibling(t, true, "existing_test")
}
func TestSecurityAgentWebhookCandidate59AttackLabPostgres(t *testing.T) {
	webhookNonExportSibling(t, true, "attack_lab")
}
func TestSecurityAgentWebhookPrior57ExistingTestPostgres(t *testing.T) {
	webhookPrior57Sibling(t, false)
}
func TestSecurityAgentWebhookPrior57AttackLabPostgres(t *testing.T) { webhookPrior57Sibling(t, true) }
func webhookPrior57Sibling(t *testing.T, attack bool) {
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, testID, actor string) {
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionCompliance(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionSecurityAgentAttackLab(ctx); err != nil {
			t.Fatal(err)
		}
		t.Logf("prior57 checksum=%s fingerprint=%s", migrations.ProductionSecurityAgentAttackLab().Checksum(), migrations.SecurityAgentAttackLabFingerprint())
		if attack {
			seedExportRouteAttackLabDefinition(t, ctx, owner, api, o, w, e, testID, actor)
			exerciseAttackLabRegisteredDispatch(t, ctx, owner, api, o, w, e, testID, actor, true, false)
			return
		}
		config := owner.Config().Copy()
		config.User = "security_agent_v33_worker_login"
		worker, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close(context.Background())
		const run = "pid_8e140001-0000-4000-8000-000000000001"
		const finding = "pid_8e140002-0000-4000-8000-000000000002"
		const workerID = "webhook-prior57-worker"
		const lease = "webhook-prior57-planning"
		seedExistingTestPreparation(t, ctx, owner, o, w, e, testID, actor, run, finding, "run_test", workerID, lease)
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_definition_versions(organization_id,workspace_id,environment_id,definition_id,version,activation,definition,definition_digest,actor_id) SELECT organization_id,workspace_id,environment_id,definition_id,version,'autonomous',jsonb_set(body,'{autonomy}','"autonomous"'),digest(convert_to(jsonb_set(body,'{autonomy}','"autonomous"')::text,'UTF8'),'sha256'),$2 FROM zasp_security_agent_definitions WHERE organization_id=$1 ON CONFLICT(organization_id,workspace_id,environment_id,definition_id,version) DO UPDATE SET activation=excluded.activation,definition=excluded.definition,definition_digest=excluded.definition_digest,actor_id=excluded.actor_id`, o, actor); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET activation='autonomous',body=jsonb_set(body,'{autonomy}','"autonomous"') WHERE organization_id=$1; INSERT INTO zasp_security_agent_kill_switches(organization_id,workspace_id,environment_id,action_key,execution_enabled,updated_by) VALUES($1,$3,$4,'run_test',true,$2) ON CONFLICT(organization_id,workspace_id,environment_id,action_key) DO UPDATE SET execution_enabled=true`, pgx.QueryExecModeSimpleProtocol, o, actor, w, e); err != nil {
			t.Fatal(err)
		}
		var raw []byte
		if err := worker.QueryRow(ctx, existingTestPrepareSQL, o, w, e, run, workerID, lease, "pid_8e140003-0000-4000-8000-000000000003", time.Now().Add(5*time.Minute), "pid_8e140004-0000-4000-8000-000000000004", "pid_8e140005-0000-4000-8000-000000000005").Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if err := worker.QueryRow(ctx, postgresSecurityAgentClaimRunsV24SQL, workerID, "webhook-prior57-dispatch", 60, 1).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		const execute = `SELECT public.zasp_production_security_agent_existing_tests_execute_run($1,$2,$3,$4,$5,'webhook-prior57-dispatch','pid_8e140006-0000-4000-8000-000000000006','pid_8e140007-0000-4000-8000-000000000007',$6,$7)`
		if err := worker.QueryRow(ctx, execute, o, w, e, run, workerID, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		before := existingTestAcceptanceSnapshot(t, ctx, owner, o, w, e, run)
		if err := worker.QueryRow(ctx, execute, o, w, e, run, workerID, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()).Scan(&raw); err == nil {
			t.Fatal("prior57 cleared-lease replay accepted")
		}
		if existingTestAcceptanceSnapshot(t, ctx, owner, o, w, e, run) != before {
			t.Fatal("prior57 refusal mutated state")
		}
	}, webhookOwnedPostgres)
}

func TestSecurityAgentWebhookAuthorityPostgres(t *testing.T) {
	runWebhookAuthorityFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, actor string) {
		f := webhookRegisteredPreparation(t, ctx, owner, api, o, w, e, actor)
		f.statusSessions(t)
		foreign := webhookRegisteredPreparation(t, ctx, owner, api, "pid_9a000001-0000-4000-8000-000000000001", "pid_9a000002-0000-4000-8000-000000000002", "pid_9a000003-0000-4000-8000-000000000003", f.id())
		foreign.statusSessions(t)
		newWorkspace, newEnvironment := f.id(), f.id()
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_workspaces(id,organization_id,name) VALUES($1,$2,'Webhook workspace'); INSERT INTO zasp_environments(id,organization_id,workspace_id,name,environment_class) VALUES($3,$2,$1,'Webhook environment','production')`, pgx.QueryExecModeSimpleProtocol, newWorkspace, o, newEnvironment); err != nil {
			t.Fatal(err)
		}
		workspace := webhookRegisteredPreparation(t, ctx, owner, api, o, newWorkspace, newEnvironment, f.id())
		workspace.statusSessions(t)
		otherEnvironment := f.id()
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_environments(id,organization_id,workspace_id,name,environment_class) VALUES($1,$2,$3,'Second webhook environment','production')`, otherEnvironment, o, w); err != nil {
			t.Fatal(err)
		}
		environment := webhookRegisteredPreparation(t, ctx, owner, api, o, w, otherEnvironment, f.id())
		environment.statusSessions(t)
		for _, other := range []*webhookPGFixture{foreign, workspace, environment} {
			var raw []byte
			token := strings.Repeat("webhook-", 5) + "session-two" + f.run
			if err := api.QueryRow(ctx, `SELECT public.zasp_get_security_agent_webhook($1,$2,$3,$4,$5,$6,$7,$8)`, other.o, other.w, other.e, f.actor, token, other.agent, other.run, other.status.DeliveryID).Scan(&raw); err == nil {
				t.Fatal("live session borrowed another valid scope")
			}
		}
	})
}

func webhookRegisteredPreparation(t *testing.T, ctx context.Context, owner, api *pgx.Conn, o, w, e, actor string, modes ...string) *webhookPGFixture {
	t.Helper()
	id := func() string {
		webhookSequence++
		return fmt.Sprintf("pid_9a590001-0000-4000-8000-%012d", webhookSequence)
	}
	read := func(conn *pgx.Conn, sql string, args ...any) json.RawMessage {
		t.Helper()
		var raw json.RawMessage
		if err := conn.QueryRow(ctx, sql, args...).Scan(&raw); err != nil {
			t.Fatalf("registered webhook fixture: %s: %v", sql, err)
		}
		return raw
	}
	if _, err := owner.Exec(ctx, `INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) VALUES($4,$1,'webhook-org',$4,'security_admin',true);
 INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($4,$1,$2,$3,'Webhook','["view","manage_integrations","manage_workflows","manage_identity","view_audit"]')`, pgx.QueryExecModeSimpleProtocol, o, w, e, actor); err != nil {
		t.Fatal(err)
	}
	integrationID, agentID, runID, approvalID := id(), id(), id(), id()
	body := map[string]any{"id": integrationID, "connector_key": "generic-webhook", "name": "Saved response", "status": "configured", "configuration": map[string]string{"destination_url": "https://hooks.example.test/response", "signing_secret_reference": "secret_ref_response", "signing_secret_version": strings.Repeat("a", 32)}, "created_at": "2026-09-19T00:00:00Z", "updated_at": "2026-09-19T00:00:00Z"}
	config := api.Config().Copy()
	config.User = "security_agent_v33_discovery_api_login"
	integrationAPI, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { integrationAPI.Close(context.Background()) })
	read(integrationAPI, postgresWorkflowMutateSQL, "create", "integration", integrationID, o, w, e, actor, "createIntegration", "webhook-integration-"+integrationID, int64(0), map[string]any{"resource_id": "", "expected_version": 0, "body": body}, body, id(), id(), id())
	def := map[string]any{"id": agentID, "name": "Response", "trigger_kind": "finding", "trigger_source": "credential", "environment_ids": []string{e}, "autonomy": "supervised", "max_steps": 1, "max_duration_seconds": 300, "temporary_policy_seconds": 600, "ai_token_budget": 1000, "max_ai_cost_nano_credits": 1000000, "concurrency_limit": 10, "allowed_actions": []string{"send_response_webhook"}, "verification_kind": "signed_delivery", "definition_version": 1, "enabled": false, "response_webhook_destination": map[string]any{"integration_id": integrationID, "integration_version": 1}}
	intentBody := map[string]any{}
	for k, v := range def {
		if k != "id" {
			intentBody[k] = v
		}
	}
	checksum, fp := migrations.ProductionSecurityAgentWebhooks().Checksum(), migrations.SecurityAgentWebhooksFingerprint()
	read(api, `SELECT public.zasp_sa_webhook_mutate_definition($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`, "create", agentID, o, w, e, actor, "createSecurityAgent", "webhook-definition-"+agentID, int64(0), map[string]any{"resource_id": "", "expected_version": 0, "body": intentBody}, def, id(), id(), id(), checksum, fp)
	var version, actionVersion int64
	if err := owner.QueryRow(ctx, `SELECT COALESCE((SELECT version FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key)=($1,$2,$3,'*')),0)`, o, w, e).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if err := owner.QueryRow(ctx, `SELECT COALESCE((SELECT version FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key)=($1,$2,$3,'send_response_webhook')),0)`, o, w, e).Scan(&actionVersion); err != nil {
		t.Fatal(err)
	}
	for _, control := range []struct {
		target, action string
		v              int64
	}{{"environment", "*", version}, {"action", "send_response_webhook", actionVersion}} {
		read(api, `SELECT public.zasp_sa_webhook_set_control($1,$2,$3,$4,$5,$6,$7,true,$8,$9,$10,$11,$12,$13,$14)`, o, w, e, actor, "webhook-control-"+control.target+"-"+agentID, control.target, control.action, control.v, time.Now().UTC().Add(4*time.Minute), id(), id(), id(), checksum, fp)
	}
	activation := "supervised"
	if len(modes) > 0 {
		activation = modes[0]
	}
	states := []string{"validated", "supervised"}
	if activation == "autonomous" {
		states = append(states, "autonomous")
	}
	definitionVersion := len(states) + 1
	for n, state := range states {
		read(api, `SELECT public.zasp_sa_webhook_activate($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, o, w, e, agentID, actor, "webhook-activation-"+state+"-"+agentID, int64(n+1), state, time.Now().UTC().Add(4*time.Minute), id(), id(), id(), checksum, fp)
	}
	read(api, fmt.Sprintf(`SELECT public.zasp_sa_manual_run($1,$2,$3,$4,$5,$6,%d,$7,$8,$9,$10,$11,$12)`, definitionVersion), o, w, e, agentID, actor, "webhook-manual-run-"+runID, runID, id(), id(), id(), migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint())
	config.User = "security_agent_v33_worker_login"
	worker, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { worker.Close(context.Background()) })
	const workerID = "webhook-planning-worker"
	const lease = "webhook-planning-lease-0001"
	read(worker, postgresSecurityAgentClaimRunsV24SQL, workerID, lease, 120, 1)
	raw := read(worker, `SELECT public.zasp_sa_webhook_planner_context($1,$2,$3,$4,$5,$6)`, o, w, e, runID, workerID, lease)
	var input struct {
		InputDigest string `json:"input_digest"`
		Context     struct {
			Selection json.RawMessage `json:"export_selection"`
		} `json:"context"`
	}
	if json.Unmarshal(raw, &input) != nil || input.InputDigest == "" {
		t.Fatalf("planner context=%s", raw)
	}
	output := strings.Repeat("ab", 32)
	read(worker, `SELECT public.zasp_sa_webhook_reserve_planner($1,$2,$3,$4,$5,$6,1,'webhook-reservation',decode($7,'hex'),'fixture-model','fixture-price-policy','openrouter_credit',50,100)`, o, w, e, runID, workerID, lease, strings.TrimPrefix(input.InputDigest, "sha256:"))
	accept := fmt.Sprintf(`SELECT public.zasp_accept_security_agent_webhook_plan($1,$2,$3,$4,$5,$6,1,$7,%d,decode($8,'hex'),decode($9,'hex'),'fixture-model','planner-policy-v1','Approved response handoff','send_response_webhook',$10,$11,$12,$13,$14,$15,$10,$16)`, definitionVersion)
	args := []any{o, w, e, runID, workerID, lease, agentID, strings.TrimPrefix(input.InputDigest, "sha256:"), output, integrationID, approvalID, time.Now().UTC().Add(5 * time.Minute), id(), id(), "webhook-acceptance-" + runID, input.Context.Selection}
	var unsettled []byte
	if err := worker.QueryRow(ctx, accept, args...).Scan(&unsettled); err == nil {
		t.Fatal("unsettled provider reservation accepted")
	}
	read(worker, `SELECT public.zasp_security_agent_budget_settle_planner($1,$2,$3,$4,$5,$6,1,'webhook-reservation',decode($7,'hex'),10,10,20,20)`, o, w, e, runID, workerID, lease, output)
	var leaseExpiry time.Time
	if err := owner.QueryRow(ctx, `SELECT lease_expires_at FROM zasp_security_agent_runs WHERE run_id=$1`, runID).Scan(&leaseExpiry); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_runs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1`, runID); err != nil {
		t.Fatal(err)
	}
	if err := worker.QueryRow(ctx, accept, args...).Scan(&unsettled); err == nil {
		t.Fatal("expired exact planning lease accepted")
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_runs SET lease_expires_at=$2 WHERE run_id=$1`, runID, leaseExpiry); err != nil {
		t.Fatal(err)
	}
	for name, index := range map[string]int{"stale-lease": 5, "foreign-worker": 4, "input": 7, "output": 8, "destination": 9} {
		t.Run(name, func(t *testing.T) {
			bad := append([]any(nil), args...)
			switch index {
			case 7, 8:
				bad[index] = strings.Repeat("cd", 32)
			case 9:
				bad[index] = id()
			default:
				bad[index] = "foreign-planning-lease-0001"
			}
			var raw []byte
			if err := worker.QueryRow(ctx, accept, bad...).Scan(&raw); err == nil {
				t.Fatal("invalid candidate accepted")
			}
		})
	}
	for name, statement := range map[string]string{"model": strings.Replace(accept, "fixture-model", "foreign-model", 1), "empty-policy": strings.Replace(accept, "planner-policy-v1", "", 1)} {
		t.Run(name, func(t *testing.T) {
			var raw []byte
			if err := worker.QueryRow(ctx, statement, args...).Scan(&raw); err == nil {
				t.Fatal("invalid model/policy accepted")
			}
		})
	}
	// A real audit PK collision fails after plan, step, approval, delivery and
	// planner receipt insertion. The registered statement must roll all back.
	if strings.Contains(t.Name(), "ApprovalPostgres") {
		webhookRollbackBeforePlan(t, ctx, owner, worker, accept, args, runID)
	}
	var existingAudit string
	if err := owner.QueryRow(ctx, `SELECT audit_id FROM zasp_security_agent_audit WHERE run_id=$1 LIMIT 1`, runID).Scan(&existingAudit); err != nil {
		t.Fatal(err)
	}
	bad := append([]any(nil), args...)
	bad[12] = existingAudit
	var rejected []byte
	if err := worker.QueryRow(ctx, accept, bad...).Scan(&rejected); err == nil {
		t.Fatal("late audit collision did not roll back")
	}
	var count int
	if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_security_agent_planner_receipts WHERE run_id=$1)+(SELECT count(*) FROM zasp_security_agent_plans WHERE run_id=$1)+(SELECT count(*) FROM zasp_security_agent_steps WHERE run_id=$1)+(SELECT count(*) FROM zasp_security_agent_approvals WHERE run_id=$1)+(SELECT count(*) FROM zasp_security_agent_webhook_deliveries WHERE run_id=$1)`, runID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("partial acceptance rows=%d err=%v", count, err)
	}
	prepared := read(worker, accept, args...)
	replay := read(worker, accept, args...)
	if string(prepared) != string(replay) {
		t.Fatalf("lost-response replay changed handoff: %s %s", prepared, replay)
	}
	altered := append([]any(nil), args...)
	altered[14] = "webhook-new-key-" + runID
	if raw := read(worker, accept, altered...); string(raw) != string(prepared) {
		t.Fatal("new key duplicated same action")
	}
	if err := worker.QueryRow(ctx, strings.Replace(accept, "planner-policy-v1", "planner-policy-v2", 1), args...).Scan(&rejected); err == nil {
		t.Fatal("changed policy replay accepted")
	}
	var receipts, plans, steps, approvals, deliveries int
	if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_security_agent_planner_receipts WHERE run_id=$1),(SELECT count(*) FROM zasp_security_agent_plans WHERE run_id=$1),(SELECT count(*) FROM zasp_security_agent_steps WHERE run_id=$1),(SELECT count(*) FROM zasp_security_agent_approvals WHERE run_id=$1),(SELECT count(*) FROM zasp_security_agent_webhook_deliveries WHERE run_id=$1)`, runID).Scan(&receipts, &plans, &steps, &approvals, &deliveries); err != nil || receipts != 1 || plans != 1 || steps != 1 || approvals != 1 || deliveries != 1 {
		t.Fatalf("atomic acceptance rows=%d/%d/%d/%d/%d error=%v", receipts, plans, steps, approvals, deliveries, err)
	}
	var pending bool
	if err := owner.QueryRow(ctx, `SELECT r.state='waiting_approval' AND a.state='pending' AND s.state='waiting_approval' AND s.authorization_result='approval_required' FROM zasp_security_agent_runs r JOIN zasp_security_agent_approvals a USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_security_agent_steps s USING(organization_id,workspace_id,environment_id,run_id,step_id) WHERE r.run_id=$1`, runID).Scan(&pending); err != nil || !pending {
		t.Fatalf("operator approval not required: %v %v", pending, err)
	}
	for _, index := range []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 15} {
		changed := append([]any(nil), args...)
		switch index {
		case 4, 5:
			changed[index] = "changed-worker-or-lease"
		case 7, 8:
			changed[index] = strings.Repeat("ef", 32)
		case 11:
			changed[index] = time.Now().Add(4 * time.Minute)
		case 15:
			changed[index] = json.RawMessage(`[]`)
		default:
			changed[index] = id()
		}
		if err := worker.QueryRow(ctx, accept, changed...).Scan(&rejected); err == nil {
			t.Fatal("altered acceptance dimension replayed", index)
		}
	}
	approver := id()
	if _, err := owner.Exec(ctx, `INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) VALUES($4,$1,'webhook-org',$4,'security_engineer',true); INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($4,$1,$2,$3,'Webhook approver','["view","manage_workflows","view_audit"]')`, pgx.QueryExecModeSimpleProtocol, o, w, e, approver); err != nil {
		t.Fatal(err)
	}
	decision := "approved"
	if len(modes) > 1 {
		decision = modes[1]
	}
	if decision != "pending" {
		read(api, `SELECT public.zasp_production_security_agent_existing_tests_decide_approval($1,$2,$3,$4,$5,'webhook-approval-0001',1,$6,$7,$8,$9,$10,$11,$12)`, o, w, e, approvalID, approver, decision, time.Now().UTC(), id(), id(), id(), migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint())
	}
	var status ResponseWebhookStatus
	if err := json.Unmarshal(prepared, &status); err != nil {
		t.Fatal(err)
	}
	var exists bool
	if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='webhook_dispatch_login')`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		if _, err := owner.Exec(ctx, `CREATE ROLE webhook_dispatch_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); err != nil {
			t.Fatal(err)
		}
		var registered bool
		if err := owner.QueryRow(ctx, `SELECT public.zasp_sa_webhook_register_principal(session_user,'webhook_dispatch_login')`).Scan(&registered); err != nil || !registered {
			t.Fatalf("dispatch register=%v %v", registered, err)
		}
	}
	config.User = "webhook_dispatch_login"
	dispatch, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dispatch.Close(context.Background()) })
	return &webhookPGFixture{ctx, owner, api, worker, dispatch, o, w, e, actor, agentID, runID, approvalID, status, id}
}

func (f *webhookPGFixture) statusSessions(t *testing.T) {
	t.Helper()
	const read = `SELECT public.zasp_get_security_agent_webhook($1,$2,$3,$4,$5,$6,$7,$8)`
	var raw []byte
	var old string
	for _, suffix := range []string{"session-one", "session-two"} {
		token := strings.Repeat("webhook-", 5) + suffix + f.run
		if err := f.owner.QueryRow(f.ctx, `SELECT public.zasp_create_product_session($1,$2,$3,$4,$5,$6,'["view","manage_workflows"]',$7)`, token, strings.Repeat("csrf", 10), f.actor, f.o, f.w, f.e, time.Now().Add(time.Hour)).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if err := f.api.QueryRow(f.ctx, read, f.o, f.w, f.e, f.actor, token, f.agent, f.run, f.status.DeliveryID).Scan(&raw); err != nil {
			t.Fatal("own live session", err)
		}
		if old != "" {
			if err := f.api.QueryRow(f.ctx, read, f.o, f.w, f.e, f.actor, old, f.agent, f.run, f.status.DeliveryID).Scan(&raw); err == nil {
				t.Fatal("revoked session read status")
			}
		}
		for _, index := range []int{0, 1, 2, 3, 5, 6, 7} {
			args := []any{f.o, f.w, f.e, f.actor, token, f.agent, f.run, f.status.DeliveryID}
			args[index] = f.id()
			if err := f.api.QueryRow(f.ctx, read, args...).Scan(&raw); err == nil {
				t.Fatal("foreign status dimension accepted", index)
			}
		}
		old = token
	}
	for _, conn := range []*pgx.Conn{f.api, f.worker, f.dispatch} {
		if _, err := conn.Exec(f.ctx, `SELECT * FROM public.zasp_security_agent_webhook_deliveries`); err == nil {
			t.Fatal("direct delivery table access")
		}
	}
	if _, err := f.worker.Exec(f.ctx, `SELECT public.zasp_claim_security_agent_webhook()`); err == nil {
		t.Fatal("settlement worker got dispatch grant")
	}
	if _, err := f.dispatch.Exec(f.ctx, `SELECT public.zasp_claim_security_agent_webhook_settlements('worker','settlement-token-0001',30,1)`); err == nil {
		t.Fatal("dispatch worker got settlement grant")
	}
}

func webhookRollbackBeforePlan(t *testing.T, ctx context.Context, owner, worker *pgx.Conn, statement string, args []any, run string) {
	t.Helper()
	tx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(ctx, `LOCK TABLE public.zasp_security_agent_plans IN SHARE MODE`); err != nil {
		t.Fatal(err)
	}
	outcome := make(chan error, 1)
	go func() { var raw []byte; outcome <- worker.QueryRow(ctx, statement, args...).Scan(&raw) }()
	blocked := false
	for until := time.Now().Add(3 * time.Second); time.Now().Before(until); {
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND relation='public.zasp_security_agent_plans'::regclass AND NOT granted AND mode='RowExclusiveLock')`, worker.PgConn().PID()).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	var cancelled bool
	if err = tx.QueryRow(ctx, `SELECT pg_cancel_backend($1)`, worker.PgConn().PID()).Scan(&cancelled); err != nil {
		t.Fatal(err)
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-outcome; err == nil || !blocked || !cancelled {
		t.Fatalf("pre-plan injection blocked=%v cancelled=%v error=%v", blocked, cancelled, err)
	}
	var rows int
	if err = owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_security_agent_planner_receipts WHERE run_id=$1)+(SELECT count(*) FROM zasp_security_agent_plans WHERE run_id=$1)+(SELECT count(*) FROM zasp_security_agent_steps WHERE run_id=$1)+(SELECT count(*) FROM zasp_security_agent_approvals WHERE run_id=$1)+(SELECT count(*) FROM zasp_security_agent_webhook_deliveries WHERE run_id=$1)`, run).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("pre-plan rollback rows=%d error=%v", rows, err)
	}
}

func TestSecurityAgentWebhookLeasePostgres(t *testing.T) {
	runWebhookAuthorityFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, actor string) {
		f := webhookRegisteredPreparation(t, ctx, owner, api, o, w, e, actor)
		other, err := pgx.ConnectConfig(ctx, f.dispatch.Config().Copy())
		if err != nil {
			t.Fatal(err)
		}
		defer other.Close(context.Background())
		var wg sync.WaitGroup
		answers := make(chan json.RawMessage, 2)
		errors := make(chan error, 2)
		for _, conn := range []*pgx.Conn{f.dispatch, other} {
			wg.Add(1)
			go func(conn *pgx.Conn) {
				defer wg.Done()
				var raw json.RawMessage
				err := conn.QueryRow(ctx, `SELECT public.zasp_claim_security_agent_webhook()`).Scan(&raw)
				answers <- raw
				errors <- err
			}(conn)
		}
		wg.Wait()
		close(answers)
		close(errors)
		for err := range errors {
			if err != nil {
				t.Fatal(err)
			}
		}
		claims := 0
		var claim struct {
			Token      string `json:"token"`
			Generation int64  `json:"generation"`
			DeliveryID string `json:"delivery_id"`
		}
		for raw := range answers {
			if string(raw) != "null" {
				claims++
				repository, _ := NewSecurityAgentWebhooksRepository(&exportSettlementDatabase{response: raw})
				if decoded, found, err := repository.ClaimResponseWebhook(ctx); err != nil || !found || decoded.DeliveryID != f.status.DeliveryID || decoded.PayloadDigest != f.status.PayloadDigest || decoded.SelectionDigest != f.status.SelectionDigest {
					t.Fatalf("registered claim failed canonical decoder: found=%v error=%v", found, err)
				}
				if err := json.Unmarshal(raw, &claim); err != nil {
					t.Fatal(err)
				}
			}
		}
		var rows int
		if err := owner.QueryRow(ctx, `SELECT count(*) FROM public.zasp_security_agent_webhook_deliveries WHERE run_id=$1`, f.run).Scan(&rows); err != nil {
			t.Fatal(err)
		}
		if claims != 1 || rows != 1 {
			t.Fatalf("claim fence failed: claims=%d rows=%d", claims, rows)
		}
		const begin = `SELECT public.zasp_begin_security_agent_webhook_dispatch($1,$2,$3,$4,$5,$6)`
		var raw []byte
		if err := f.dispatch.QueryRow(ctx, begin, o, w, e, claim.DeliveryID, "stale-token", claim.Generation).Scan(&raw); err == nil {
			t.Fatal("stale token began dispatch")
		}
		if err := f.dispatch.QueryRow(ctx, begin, o, w, e, claim.DeliveryID, claim.Token, claim.Generation+1).Scan(&raw); err == nil {
			t.Fatal("stale generation began dispatch")
		}
		if err := f.dispatch.QueryRow(ctx, begin, o, w, e, claim.DeliveryID, claim.Token, claim.Generation).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if err := f.dispatch.QueryRow(ctx, `SELECT public.zasp_complete_security_agent_webhook($1,$2,$3,$4,$5,$6,'acknowledged','')`, o, w, e, claim.DeliveryID, claim.Token, claim.Generation).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if err := f.dispatch.QueryRow(ctx, `SELECT public.zasp_complete_security_agent_webhook($1,$2,$3,$4,$5,$6,'uncertain','delivery_uncertain')`, o, w, e, claim.DeliveryID, claim.Token, claim.Generation).Scan(&raw); err == nil {
			t.Fatal("terminal acknowledgement overwritten")
		}
		f.settle(t, "needs_human", "webhook_handoff_acknowledged")
		cancelled := webhookRegisteredPreparation(t, ctx, owner, api, o, w, e, f.id())
		if err := cancelled.dispatch.QueryRow(ctx, `SELECT public.zasp_claim_security_agent_webhook()`).Scan(&raw); err != nil || json.Unmarshal(raw, &claim) != nil {
			t.Fatal(err)
		}
		if err := cancelled.dispatch.QueryRow(ctx, begin, o, w, e, claim.DeliveryID, claim.Token, claim.Generation).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var version int64
		if err := owner.QueryRow(ctx, `SELECT version FROM public.zasp_security_agent_runs WHERE run_id=$1`, cancelled.run).Scan(&version); err != nil {
			t.Fatal(err)
		}
		if err := api.QueryRow(ctx, `SELECT public.zasp_security_agent_cancel_run($1,$2,$3,$4,$5,'webhook-parent-cancel', $6,$7,$8,$9)`, o, w, e, cancelled.run, cancelled.actor, version, f.id(), f.id(), f.id()).Scan(&raw); err != nil {
			t.Fatal("registered cancellation", err)
		}
		if err := cancelled.dispatch.QueryRow(ctx, `SELECT public.zasp_complete_security_agent_webhook($1,$2,$3,$4,$5,$6,'acknowledged','')`, o, w, e, claim.DeliveryID, claim.Token, claim.Generation).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if err := cancelled.worker.QueryRow(ctx, `SELECT public.zasp_claim_security_agent_webhook_settlements('webhook-cancel-settler','cancel-settlement-token',30,1)`).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if err := cancelled.worker.QueryRow(ctx, `SELECT public.zasp_settle_security_agent_webhook_parent($1,$2,$3,$4,'cancel-settlement-token',1,'webhook-cancel-settler',$5,$6,$7)`, o, w, e, claim.DeliveryID, f.id(), f.id(), f.id()).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var result ResponseWebhookSettlementResult
		if json.Unmarshal(raw, &result) != nil || result.State != "cancelled" || result.Reason != "webhook_parent_cancelled" || result.DeliveryState != "acknowledged" {
			t.Fatalf("cancellation lost: %s", raw)
		}
	})
}

func (f *webhookPGFixture) settle(t *testing.T, wantState, wantReason string) {
	t.Helper()
	var raw []byte
	if err := f.worker.QueryRow(f.ctx, `SELECT public.zasp_claim_security_agent_webhook_settlements('webhook-settler','settlement-token-0001',30,1)`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Claims []struct {
			Generation int64 `json:"generation"`
		}
	}
	if json.Unmarshal(raw, &claims) != nil || len(claims.Claims) != 1 {
		t.Fatalf("settlement claim %s", raw)
	}
	const settle = `SELECT public.zasp_settle_security_agent_webhook_parent($1,$2,$3,$4,'settlement-token-0001',$5,'webhook-settler',$6,$7,$8)`
	args := []any{f.o, f.w, f.e, f.status.DeliveryID, claims.Claims[0].Generation, f.id(), f.id(), f.id()}
	stale := append([]any(nil), args...)
	stale[4] = claims.Claims[0].Generation + 1
	if err := f.worker.QueryRow(f.ctx, settle, stale...).Scan(&raw); err == nil {
		t.Fatal("stale settlement generation accepted")
	}
	if _, err := f.owner.Exec(f.ctx, `UPDATE public.zasp_security_agent_webhook_deliveries SET settlement_expires_at=clock_timestamp()-interval '1 second' WHERE delivery_id=$1`, f.status.DeliveryID); err != nil {
		t.Fatal(err)
	}
	if err := f.worker.QueryRow(f.ctx, settle, args...).Scan(&raw); err == nil {
		t.Fatal("expired settlement accepted")
	}
	if err := f.worker.QueryRow(f.ctx, `SELECT public.zasp_claim_security_agent_webhook_settlements('webhook-settler','settlement-token-0001',30,1)`).Scan(&raw); err != nil || json.Unmarshal(raw, &claims) != nil || len(claims.Claims) != 1 {
		t.Fatalf("settlement reclaim=%s %v", raw, err)
	}
	if err := f.worker.QueryRow(f.ctx, settle, args...).Scan(&raw); err == nil {
		t.Fatal("old settlement claimant accepted")
	}
	args[4] = claims.Claims[0].Generation
	if _, err := f.owner.Exec(f.ctx, `UPDATE public.zasp_security_agent_runs SET version=version+1 WHERE run_id=$1`, f.run); err != nil {
		t.Fatal(err)
	}
	if err := f.worker.QueryRow(f.ctx, settle, args...).Scan(&raw); err == nil {
		t.Fatal("settlement overwrote newer parent version")
	}
	if _, err := f.owner.Exec(f.ctx, `UPDATE public.zasp_security_agent_webhook_deliveries SET settlement_expires_at=clock_timestamp()-interval '1 second' WHERE delivery_id=$1`, f.status.DeliveryID); err != nil {
		t.Fatal(err)
	}
	if err := f.worker.QueryRow(f.ctx, `SELECT public.zasp_claim_security_agent_webhook_settlements('webhook-settler','settlement-token-0001',30,1)`).Scan(&raw); err != nil || json.Unmarshal(raw, &claims) != nil || len(claims.Claims) != 1 {
		t.Fatalf("settlement newer-parent reclaim=%s %v", raw, err)
	}
	args[4] = claims.Claims[0].Generation
	if err := f.worker.QueryRow(f.ctx, settle, args...).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var result ResponseWebhookSettlementResult
	if json.Unmarshal(raw, &result) != nil || result.State != wantState || result.Reason != wantReason {
		t.Fatalf("settlement=%s", raw)
	}
	var replay []byte
	if err := f.worker.QueryRow(f.ctx, settle, args...).Scan(&replay); err != nil || string(replay) != string(raw) {
		t.Fatalf("settlement replay=%s %v", replay, err)
	}
	if _, err := f.owner.Exec(f.ctx, `UPDATE public.zasp_security_agent_webhook_deliveries SET payload='{}' WHERE delivery_id=$1`, f.status.DeliveryID); err == nil {
		t.Fatal("immutable payload changed")
	}
	if _, err := f.owner.Exec(f.ctx, `UPDATE public.zasp_security_agent_webhook_deliveries SET state='prepared',acknowledged_at=NULL WHERE delivery_id=$1`, f.status.DeliveryID); err == nil {
		t.Fatal("terminal delivery overwritten")
	}
}

func TestSecurityAgentWebhookReleaseCyclePostgres(t *testing.T) {
	runWebhookAuthorityFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, actor string) {
		runner := precisionMigrationRunner(t, owner)
		if err := runner.DownProductionSecurityAgentWebhooks(ctx); err != nil {
			tx, beginErr := owner.Begin(ctx)
			if beginErr != nil {
				t.Fatal(beginErr)
			}
			defer tx.Rollback(context.Background())
			_, diagnostic := tx.Exec(ctx, migrations.ProductionSecurityAgentWebhooks().DownSQL())
			t.Fatalf("59->58=%v SQL=%v", err, diagnostic)
		}
		var ready bool
		if err := owner.QueryRow(ctx, `SELECT public.zasp_sa_export_readiness($1,$2)`, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&ready); err != nil || !ready {
			t.Fatalf("restored exact58=%v %v", ready, err)
		}
		if err := runner.UpProductionSecurityAgentWebhooks(ctx); err != nil {
			t.Fatal("58->59 second apply", err)
		}
		for _, pins := range [][2]string{{strings.Repeat("0", 64), migrations.SecurityAgentWebhooksFingerprint()}, {migrations.ProductionSecurityAgentWebhooks().Checksum(), strings.Repeat("0", 64)}} {
			if err := owner.QueryRow(ctx, `SELECT public.zasp_sa_webhook_readiness($1,$2)`, pins[0], pins[1]).Scan(&ready); err != nil || ready {
				t.Fatalf("unknown pin ready=%v %v", ready, err)
			}
		}
		f := webhookRegisteredPreparation(t, ctx, owner, api, o, w, e, actor)
		if err := runner.DownProductionSecurityAgentWebhooks(ctx); err == nil {
			t.Fatal("durable delivery evidence destroyed")
		}
		var count int
		if err := owner.QueryRow(ctx, `SELECT count(*) FROM public.zasp_security_agent_webhook_deliveries WHERE delivery_id=$1`, f.status.DeliveryID).Scan(&count); err != nil || count != 1 {
			t.Fatalf("evidence count=%d %v", count, err)
		}
	})
}

func TestSecurityAgentWebhookApprovalPostgres(t *testing.T) {
	runWebhookAuthorityFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, actor string) {
		webhookReviewRecoveryAndDeadlines(t, ctx, owner, api, o, w, e)
		mutations := []struct{ name, sql string }{
			{"stale-approval", `UPDATE zasp_security_agent_approvals SET version=version+1 WHERE approval_id=$1`},
			{"revoked-approval", `UPDATE zasp_security_agent_approvals SET state='rejected' WHERE approval_id=$1`},
			{"expired-approval", `UPDATE zasp_security_agent_approvals SET expires_at=clock_timestamp()-interval '1 second' WHERE approval_id=$1`},
			{"changed-definition", `UPDATE zasp_security_agent_definitions SET version=version+1 WHERE definition_id=$2`},
			{"changed-integration", `UPDATE zasp_workflow_records SET version=version+1 WHERE id=$3`},
			{"changed-key", `UPDATE zasp_workflow_records SET body=jsonb_set(body,'{configuration,signing_secret_version}',to_jsonb(repeat('b',32))) WHERE id=$3`},
			{"disabled-destination", `UPDATE zasp_workflow_records SET body=jsonb_set(body,'{status}','"disabled"') WHERE id=$3`},
			{"cancelled-parent", `UPDATE zasp_security_agent_runs SET state='cancelled' WHERE run_id=$4`},
			{"changed-control", `UPDATE zasp_security_agent_kill_switches SET version=version+1 WHERE (organization_id,workspace_id,environment_id,action_key)=($5,$6,$7,'send_response_webhook')`},
			{"kill-switch", `UPDATE zasp_security_agent_kill_switches SET execution_enabled=false WHERE (organization_id,workspace_id,environment_id,action_key)=($5,$6,$7,'send_response_webhook')`},
		}
		for n, mutation := range mutations {
			t.Run(mutation.name, func(t *testing.T) {
				a := actor
				if n > 0 {
					webhookSequence++
					a = fmt.Sprintf("pid_9a590001-0000-4000-8000-%012d", webhookSequence)
				}
				mode := "supervised"
				if n%2 == 1 {
					mode = "autonomous"
				}
				f := webhookRegisteredPreparation(t, ctx, owner, api, o, w, e, a, mode)
				var claim struct {
					Token      string `json:"token"`
					Generation int64  `json:"generation"`
				}
				var raw []byte
				if err := f.dispatch.QueryRow(ctx, `SELECT public.zasp_claim_security_agent_webhook()`).Scan(&raw); err != nil || json.Unmarshal(raw, &claim) != nil || claim.Token == "" {
					t.Fatalf("claim=%s %v", raw, err)
				}
				// Data-only adversarial authority mutation; no function-body injection.
				if _, err := owner.Exec(ctx, "WITH fixture AS (SELECT $1::text,$2::text,$3::text,$4::text,$5::text,$6::text,$7::text) "+mutation.sql, pgx.QueryExecModeSimpleProtocol, f.approval, f.agent, f.status.DestinationIntegrationID, f.run, o, w, e); err != nil {
					t.Fatal(err)
				}
				err := f.dispatch.QueryRow(ctx, `SELECT public.zasp_begin_security_agent_webhook_dispatch($1,$2,$3,$4,$5,$6)`, o, w, e, f.status.DeliveryID, claim.Token, claim.Generation).Scan(&raw)
				if err == nil && strings.Contains(string(raw), `true`) {
					t.Fatalf("changed authority began dispatch: %s", raw)
				}
				var state, payload, selection string
				if err := owner.QueryRow(ctx, `SELECT state,payload_digest,selection_digest FROM public.zasp_security_agent_webhook_deliveries WHERE delivery_id=$1`, f.status.DeliveryID).Scan(&state, &payload, &selection); err != nil || state == "dispatching" || payload != f.status.PayloadDigest || selection != f.status.SelectionDigest {
					t.Fatalf("authority mutation escaped: %s %v", state, err)
				}
			})
		}
	})
}

// These cases catch skipped prepared rows and authority checked before a
// blocking INSERT instead of at the final dispatch boundary.
func webhookReviewRecoveryAndDeadlines(t *testing.T, ctx context.Context, owner, api *pgx.Conn, o, w, e string) {
	for _, name := range []string{"cancel-before-approval", "cancel-before-claim", "rejected", "expired", "pending-expired"} {
		t.Run("recovery-"+name, func(t *testing.T) {
			webhookSequence++
			actor := fmt.Sprintf("pid_9b590001-0000-4000-8000-%012d", webhookSequence)
			decision := "pending"
			if name == "cancel-before-claim" {
				decision = "approved"
			}
			if name == "rejected" {
				decision = "rejected"
			}
			f := webhookRegisteredPreparation(t, ctx, owner, api, o, w, e, actor, "supervised", decision)
			var raw []byte
			if decision != "rejected" {
				if err := f.dispatch.QueryRow(ctx, `SELECT public.zasp_expire_security_agent_webhooks(1)`).Scan(&raw); err != nil || string(raw) != `{"expired": 0}` {
					t.Fatalf("live prepared delivery expired: %s %v", raw, err)
				}
			}
			if strings.HasPrefix(name, "cancel-") {
				var version int64
				if err := owner.QueryRow(ctx, `SELECT version FROM zasp_security_agent_runs WHERE run_id=$1`, f.run).Scan(&version); err != nil {
					t.Fatal(err)
				}
				if err := api.QueryRow(ctx, `SELECT public.zasp_security_agent_cancel_run($1,$2,$3,$4,$5,'review-cancel-run',$6,$7,$8,$9)`, o, w, e, f.run, f.actor, version, f.id(), f.id(), f.id()).Scan(&raw); err != nil {
					t.Fatal(err)
				}
			}
			if name == "expired" || name == "pending-expired" {
				if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_approvals SET expires_at=clock_timestamp()-interval '1 second' WHERE approval_id=$1`, f.approval); err != nil {
					t.Fatal(err)
				}
				if name == "expired" {
					if err := f.worker.QueryRow(ctx, `SELECT public.zasp_security_agent_expire_approvals_v28('review-expiry-worker',1)`).Scan(&raw); err != nil {
						t.Fatal(err)
					}
				}
			}
			var before []byte
			const facts = `SELECT jsonb_build_array(to_jsonb(r),to_jsonb(s)) FROM zasp_security_agent_runs r JOIN zasp_security_agent_steps s USING(organization_id,workspace_id,environment_id,run_id) WHERE r.run_id=$1`
			if err := owner.QueryRow(ctx, facts, f.run).Scan(&before); err != nil {
				t.Fatal(err)
			}
			if err := f.dispatch.QueryRow(ctx, `SELECT public.zasp_expire_security_agent_webhooks(1)`).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			if string(raw) != `{"expired": 1}` {
				t.Fatalf("recovery bound/count=%s", raw)
			}
			var status string
			if err := owner.QueryRow(ctx, `SELECT state FROM zasp_security_agent_webhook_deliveries WHERE delivery_id=$1`, f.status.DeliveryID).Scan(&status); err != nil || status != "cancelled" {
				t.Fatalf("invalid pre-dispatch delivery stranded: state=%s recovery=%s error=%v", status, raw, err)
			}
			if err := f.dispatch.QueryRow(ctx, `SELECT public.zasp_claim_security_agent_webhook()`).Scan(&raw); err != nil || string(raw) != "null" {
				t.Fatalf("invalidated delivery claim=%s %v", raw, err)
			}
			if err := f.worker.QueryRow(ctx, `SELECT public.zasp_claim_security_agent_webhook_settlements('review-settler','review-settlement-token',30,25)`).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			const settle = `SELECT public.zasp_settle_security_agent_webhook_parent($1,$2,$3,$4,'review-settlement-token',1,'review-settler',$5,$6,$7)`
			if err := f.worker.QueryRow(ctx, settle, o, w, e, f.status.DeliveryID, f.id(), f.id(), f.id()).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			var result ResponseWebhookSettlementResult
			if err := json.Unmarshal(raw, &result); err != nil {
				t.Fatal(err)
			}
			wantState, wantReason := "cancelled", "webhook_parent_cancelled"
			if name == "rejected" || name == "expired" {
				wantState, wantReason = "needs_human", "webhook_parent_outcome_preserved"
			}
			if name == "pending-expired" {
				wantReason = "webhook_delivery_cancelled"
			}
			if result.State != wantState || result.Reason != wantReason || result.DeliveryState != "cancelled" {
				t.Fatalf("recovery settlement=%s", raw)
			}
			var after []byte
			if err := owner.QueryRow(ctx, facts, f.run).Scan(&after); err != nil {
				t.Fatal(err)
			}
			if name != "pending-expired" && string(before) != string(after) {
				t.Fatalf("recovery rewrote parent/step: before=%s after=%s", before, after)
			}
			var replay []byte
			if err := f.worker.QueryRow(ctx, settle, o, w, e, f.status.DeliveryID, f.id(), f.id(), f.id()).Scan(&replay); err != nil || string(raw) != string(replay) {
				t.Fatalf("recovery replay changed: %s %v", replay, err)
			}
		})
	}
	for _, deadline := range []string{"approval", "plan", "budget"} {
		t.Run("delayed-begin-"+deadline, func(t *testing.T) {
			webhookSequence++
			f := webhookRegisteredPreparation(t, ctx, owner, api, o, w, e, fmt.Sprintf("pid_9b590001-0000-4000-8000-%012d", webhookSequence))
			var raw []byte
			var claim struct {
				Token      string `json:"token"`
				Generation int64  `json:"generation"`
			}
			if err := f.dispatch.QueryRow(ctx, `SELECT public.zasp_claim_security_agent_webhook()`).Scan(&raw); err != nil || json.Unmarshal(raw, &claim) != nil || claim.Token == "" {
				t.Fatalf("deadline claim=%s %v", raw, err)
			}
			statement := map[string]string{"approval": `UPDATE zasp_security_agent_approvals SET expires_at=clock_timestamp()+interval '2 seconds' WHERE run_id=$1 RETURNING expires_at`, "plan": `UPDATE zasp_security_agent_plans SET expires_at=clock_timestamp()+interval '2 seconds' WHERE run_id=$1 RETURNING expires_at`, "budget": `UPDATE zasp_security_agent_run_budgets SET deadline_at=clock_timestamp()+interval '2 seconds' WHERE run_id=$1 RETURNING deadline_at`}[deadline]
			var expires time.Time
			if err := owner.QueryRow(ctx, statement, f.run).Scan(&expires); err != nil {
				t.Fatal(err)
			}
			tx, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			if _, err = tx.Exec(ctx, `LOCK TABLE zasp_security_agent_step_reservations IN SHARE MODE`); err != nil {
				t.Fatal(err)
			}
			type answer struct {
				raw []byte
				err error
			}
			done := make(chan answer, 1)
			go func() {
				var value []byte
				err := f.dispatch.QueryRow(ctx, `SELECT public.zasp_begin_security_agent_webhook_dispatch($1,$2,$3,$4,$5,$6)`, o, w, e, f.status.DeliveryID, claim.Token, claim.Generation).Scan(&value)
				done <- answer{value, err}
			}()
			blocked := false
			for until := time.Now().Add(time.Second); time.Now().Before(until); time.Sleep(5 * time.Millisecond) {
				if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND relation='zasp_security_agent_step_reservations'::regclass AND mode='RowExclusiveLock' AND NOT granted)`, f.dispatch.PgConn().PID()).Scan(&blocked); err != nil {
					t.Fatal(err)
				}
				if blocked {
					break
				}
			}
			if !blocked {
				t.Fatal("begin never reached blocked reservation insert")
			}
			for {
				var expired bool
				if err := tx.QueryRow(ctx, `SELECT clock_timestamp()>$1::timestamptz`, expires).Scan(&expired); err != nil {
					t.Fatal(err)
				}
				if expired {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			result := <-done
			if result.err == nil && strings.Contains(string(result.raw), "true") {
				t.Fatalf("expired %s authorized send after blocked insert: %s", deadline, result.raw)
			}
			var safe bool
			if err := owner.QueryRow(ctx, `SELECT d.state='leased' AND d.lease_expires_at>clock_timestamp() AND d.dispatch_started_at IS NULL AND r.state='queued' AND s.state='authorized' AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_step_reservations WHERE run_id=d.run_id) FROM zasp_security_agent_webhook_deliveries d JOIN zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_security_agent_steps s USING(organization_id,workspace_id,environment_id,run_id,step_id) WHERE d.delivery_id=$1`, f.status.DeliveryID).Scan(&safe); err != nil || !safe {
				t.Fatalf("deadline refusal not atomic: %v %v", safe, err)
			}
			var version int64
			if err := owner.QueryRow(ctx, `SELECT version FROM zasp_security_agent_runs WHERE run_id=$1`, f.run).Scan(&version); err != nil {
				t.Fatal(err)
			}
			if err := api.QueryRow(ctx, `SELECT public.zasp_security_agent_cancel_run($1,$2,$3,$4,$5,'review-deadline-cancel',$6,$7,$8,$9)`, o, w, e, f.run, f.actor, version, f.id(), f.id(), f.id()).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			if err := f.dispatch.QueryRow(ctx, `SELECT public.zasp_expire_security_agent_webhooks(1)`).Scan(&raw); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSecurityAgentWebhookIdempotencyPostgres(t *testing.T) {
	runWebhookAuthorityFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, actor string) {
		f := webhookRegisteredPreparation(t, ctx, owner, api, o, w, e, actor)
		var raw []byte
		var claim struct {
			Token      string `json:"token"`
			Generation int64  `json:"generation"`
		}
		for n := 1; n <= 3; n++ {
			if err := f.dispatch.QueryRow(ctx, `SELECT public.zasp_claim_security_agent_webhook()`).Scan(&raw); err != nil || json.Unmarshal(raw, &claim) != nil || claim.Generation != int64(n) {
				t.Fatalf("claim %d=%s %v", n, raw, err)
			}
			if _, err := owner.Exec(ctx, `UPDATE public.zasp_security_agent_webhook_deliveries SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE delivery_id=$1`, f.status.DeliveryID); err != nil {
				t.Fatal(err)
			}
		}
		if err := f.dispatch.QueryRow(ctx, `SELECT public.zasp_expire_security_agent_webhooks(1)`).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if err := f.dispatch.QueryRow(ctx, `SELECT public.zasp_claim_security_agent_webhook()`).Scan(&raw); err != nil || string(raw) != "null" {
			t.Fatalf("claim exhaustion=%s %v", raw, err)
		}
		f.settle(t, "failed", "webhook_delivery_failed")
		second := webhookRegisteredPreparation(t, ctx, owner, api, o, w, e, f.id())
		if err := second.dispatch.QueryRow(ctx, `SELECT public.zasp_claim_security_agent_webhook()`).Scan(&raw); err != nil || json.Unmarshal(raw, &claim) != nil {
			t.Fatal(err)
		}
		if err := second.dispatch.QueryRow(ctx, `SELECT public.zasp_begin_security_agent_webhook_dispatch($1,$2,$3,$4,$5,$6)`, o, w, e, second.status.DeliveryID, claim.Token, claim.Generation).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `UPDATE public.zasp_security_agent_webhook_deliveries SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE delivery_id=$1`, second.status.DeliveryID); err != nil {
			t.Fatal(err)
		}
		if err := second.dispatch.QueryRow(ctx, `SELECT public.zasp_complete_security_agent_webhook($1,$2,$3,$4,$5,$6,'acknowledged','')`, o, w, e, second.status.DeliveryID, claim.Token, claim.Generation).Scan(&raw); err == nil {
			t.Fatal("expired dispatch acknowledged")
		}
		if err := second.dispatch.QueryRow(ctx, `SELECT public.zasp_expire_security_agent_webhooks(1)`).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if err := second.dispatch.QueryRow(ctx, `SELECT public.zasp_claim_security_agent_webhook()`).Scan(&raw); err != nil || string(raw) != "null" {
			t.Fatalf("uncertain redispatched=%s %v", raw, err)
		}
		second.settle(t, "needs_human", "webhook_delivery_uncertain")
	})
}
