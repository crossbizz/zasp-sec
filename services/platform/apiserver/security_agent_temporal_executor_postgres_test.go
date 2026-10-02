package apiserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
	"github.com/zasp-ai/zasp-sec/services/platform/redteamadapter"
)

// The disposable compiler fixture never registers its observed catalog. Its
// output is compared with independently checked-in post-transition pins.
func TestTemporalExecutorCatalogPostgres(t *testing.T) {
	runTemporalDomainFreshFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		runTemporalMigrationCLI(t, ctx, owner, "up-temporal-domain")
		if _, err := owner.Exec(ctx, migrations.ProductionTemporalExecutor().UpSQL()); err != nil {
			if p, ok := err.(*pgconn.PgError); ok && p.Position > 100 {
				sql := migrations.ProductionTemporalExecutor().UpSQL()
				t.Log(sql[p.Position-100 : min(int(p.Position)+100, len(sql))])
			}
			t.Fatalf("executor SQL compilation: %#v", err)
		}
		var base, domain, executor string
		if err := owner.QueryRow(ctx, `SELECT zasp_temporal67.base_fingerprint(),zasp_temporal67.fingerprint(),zasp_temporal68.fingerprint()`).Scan(&base, &domain, &executor); err != nil {
			t.Fatal(err)
		}
		if base != migrations.TemporalExecutorBaseFingerprint() || domain != migrations.TemporalExecutorDomainFingerprint() || executor != migrations.TemporalExecutorFingerprint() {
			t.Fatalf("compiled post-state differs: base=%s domain=%s executor=%s", base, domain, executor)
		}
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_temporal68.registration(checksum,fingerprint) VALUES($1,$2)`, migrations.ProductionTemporalExecutor().Checksum(), migrations.TemporalExecutorFingerprint()); err != nil {
			t.Fatal(err)
		}
		var ready bool
		if err := owner.QueryRow(ctx, `SELECT zasp_temporal68.current_ready()`).Scan(&ready); err != nil || !ready {
			t.Fatal("compiled installation not ready", ready, err)
		}
		for _, probe := range []string{`ALTER TABLE zasp_temporal68.delivery_revisions DISABLE TRIGGER ALL`, `ALTER TABLE zasp_temporal68.cleanup_renewals DISABLE TRIGGER ALL`, `ALTER TABLE zasp_temporal68.provider_reservations DISABLE TRIGGER ALL`, `ALTER TABLE zasp_temporal68.registration SET UNLOGGED`, `GRANT SELECT ON zasp_temporal68.planning_jobs TO zasp_security_agent_worker`, `GRANT zasp_temporal_accounting TO zasp_security_agent_worker`} {
			tx, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, probe); err != nil {
				tx.Rollback(ctx)
				t.Fatal(err)
			}
			err = tx.QueryRow(ctx, `SELECT zasp_temporal68.current_ready()`).Scan(&ready)
			tx.Rollback(ctx)
			if err != nil || ready {
				t.Fatalf("readiness accepted authority drift %s: %t %v", probe, ready, err)
			}
		}
	})
}

// A count made through worker RLS misses the other owner's active run. Either
// admission order must refuse the second run before it acquires a budget.
func TestTemporalExecutorMixedAdmissionPostgres(t *testing.T) {
	for _, mode := range []string{"temporal_first", "legacy_first", "minimum_active_limit"} {
		temporalFirst := mode != "legacy_first"
		t.Run(mode, func(t *testing.T) {
			runTemporalDomainFreshFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
				runTemporalMigrationCLI(t, ctx, owner, "up-temporal-domain")
				if _, err := owner.Exec(ctx, `INSERT INTO zasp_temporal66.admission_routes VALUES($1,$2,$3,'temporal')`, o, w, e); err != nil {
					t.Fatal(err)
				}
				public62Seed(t, ctx, owner, o, w, e, testID, actor)
				if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET body=jsonb_set(body,'{concurrency_limit}','1') WHERE definition_id=$1`, public62Definition); err != nil {
					t.Fatal(err)
				}
				q := public62Request(o, w, e, actor, "activate")
				q["definition_id"], q["definition_version"] = public62Definition, 1
				if _, err := public62Call(ctx, api, q); err != nil {
					t.Fatal(err)
				}
				q = public62Request(o, w, e, actor, "trigger_resource")
				q["definition_id"], q["definition_version"], q["trigger_id"], q["trigger_version"], q["idempotency_key"] = public62Definition, 2, public62Finding, 1, "executor-mixed-00001"
				q["trigger_kind"], q["trigger_source"] = "finding", "credential"
				created, err := public62Call(ctx, api, q)
				if err != nil {
					t.Fatal(err)
				}
				temporalRun := created["id"].(string)
				legacyRun := seedOrderedPlanningQueue(t, ctx, owner, o, w, e, testID, actor)
				if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET body=jsonb_set(body,'{concurrency_limit}','1') WHERE definition_id=(SELECT definition_id FROM zasp_security_agent_runs WHERE run_id=$1)`, legacyRun); err != nil {
					t.Fatal(err)
				}
				if mode == "minimum_active_limit" {
					if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET body=jsonb_set(body,'{concurrency_limit}','10') WHERE definition_id=(SELECT definition_id FROM zasp_security_agent_runs WHERE run_id=$1)`, legacyRun); err != nil {
						t.Fatal(err)
					}
				}
				if err := precisionMigrationRunner(t, owner).UpProductionTemporalExecutor(ctx); err != nil {
					t.Fatal(err)
				}
				if _, err := owner.Exec(ctx, `CREATE ROLE temporal_executor_test_login LOGIN; CREATE ROLE temporal_compensation_test_login LOGIN; SELECT zasp_temporal68.register_principals('temporal_executor_test_login','temporal_compensation_test_login')`); err != nil {
					t.Fatal(err)
				}
				config := owner.Config().Copy()
				config.User = "temporal_executor_test_login"
				executor, err := pgx.ConnectConfig(ctx, config)
				if err != nil {
					t.Fatal(err)
				}
				defer executor.Close(ctx)
				temporalQ, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": temporalRun, "definition_version": 2, "operation": "load"})
				temporalClaim := func() error {
					var b []byte
					return executor.QueryRow(ctx, `SELECT zasp_temporal68.plan($1::jsonb)`, temporalQ).Scan(&b)
				}
				legacyClaim := func() error {
					_, err := orderedPlanningCall(ctx, worker, map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": legacyRun, "worker_id": "mixed-owner", "lease_token": "mixed-owner-lease-0001", "operation": "claim", "payload": map[string]any{}})
					return err
				}
				first, second, loser := legacyClaim, temporalClaim, temporalRun
				if temporalFirst {
					first, second, loser = temporalClaim, legacyClaim, legacyRun
				}
				if err := first(); err != nil {
					t.Fatal("first admission", err)
				}
				if mode != "minimum_active_limit" {
					if err := second(); err == nil {
						t.Fatal("other owner exceeded concurrency limit")
					}
				}
				var intact bool
				if err := owner.QueryRow(ctx, `SELECT state='queued' AND version=1 AND attempt=0 AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_run_budgets WHERE run_id=$1) FROM zasp_security_agent_runs WHERE run_id=$1`, loser).Scan(&intact); err != nil || !intact {
					t.Fatal("rejected admission mutated run", intact, err)
				}
				var visible int
				// Existing worker selectors are the only worker-accessible route to runs.
				var result []byte
				if err := worker.QueryRow(ctx, `SELECT zasp_security_agent_claim_runs('mixed-worker','mixed-budget-lease-00001',30,1)`).Scan(&result); err != nil {
					t.Fatal(err)
				}
				var claims struct {
					Runs []map[string]any `json:"items"`
				}
				if err := json.Unmarshal(result, &claims); err != nil {
					t.Fatal(err)
				}
				if claims.Runs == nil {
					t.Fatal("claim response omitted items", string(result))
				}
				if len(claims.Runs) != 0 {
					t.Fatal("budgeted claim ignored shared active limit", string(result))
				}
				for _, run := range claims.Runs {
					if run["run_id"] == temporalRun {
						visible++
					}
				}
				if visible != 0 {
					t.Fatal("old budget selector exposed Temporal run")
				}
			})
		})
	}
}

// The API must create a genuinely queued Temporal-owned run. Admission cannot
// borrow a legacy claim or seed a plan, lease, budget or provider reservation.
func TestTemporalExecutorQueuedAdmissionPostgres(t *testing.T) {
	runTemporalExecutorAdmittedFixture(t, func(ctx context.Context, owner, executor, api *pgx.Conn, o, w, e, run, actor string) {
		approved := public62TypedDecision(t, ctx, api, o, w, e, run, 3)
		if approved.StepState != "authorized" || approved.RunVersion != 4 {
			t.Fatal("Temporal approval projection", approved)
		}
		repo, id := public62GoRepository(t, api, o, w, e, orderedProgressionApprover)
		cancelled, err := repo.Cancel(ctx, id, SecurityAgentPublicCancellation{RunID: run, RunVersion: 4, IdempotencyKey: "executor68-cancel-0001"})
		if err != nil || cancelled.RunState != "cancelled" || cancelled.CleanupRequired {
			t.Fatal("Temporal cancellation without effects", cancelled, err)
		}
	})
}

func runTemporalExecutorAdmittedFixture(t *testing.T, inspect func(context.Context, *pgx.Conn, *pgx.Conn, *pgx.Conn, string, string, string, string, string)) {
	runTemporalExecutorPlanningFixture(t, inspect, nil)
}

func TestTemporalExecutorPlanningTransportPostgres(t *testing.T) {
	runTemporalExecutorPlanningTransportFixture(t, "")
}

func TestTemporalExecutorPlanningTransportFaultsPostgres(t *testing.T) {
	for _, mode := range []string{"loaded_lost", "prepared_lost", "credential_changed", "lost_start", "lost_result", "unknown", "wire_missing_receipt", "wire_nested_context", "input_get", "output_get", "short_deadline"} {
		t.Run(mode, func(t *testing.T) { runTemporalExecutorPlanningTransportFixture(t, mode) })
	}
}

func runTemporalExecutorPlanningTransportFixture(t *testing.T, mode string) {
	runTemporalExecutorPlanningFixture(t, nil, nil, func(ctx context.Context, owner, executor, api *pgx.Conn, o, w, e, run, testID string, selection map[string]any) {
		binding := map[string]any{}
		for _, k := range []string{"organization_id", "workspace_id", "environment_id", "account_profile", "credential_reference", "policy_id", "policy_version", "policy_digest", "account_id", "account_version"} {
			binding[k] = selection[k]
		}
		encoded, _ := json.Marshal(binding)
		command := exec.CommandContext(ctx, "go", "test", "./agentsec-worker", "-run", "^TestTemporalOwnedPlanner$", "-count=1", "-v")
		command.Dir = ".."
		command.WaitDelay = 5 * time.Second
		command.Env = append(os.Environ(), "ZASP_TEMPORAL_PLANNER_DSN="+owner.Config().ConnString(), "ZASP_TEMPORAL_PARENT="+run, "ZASP_TEMPORAL_TEST_ID="+testID, "ZASP_TEMPORAL_PLANNER_BINDING="+string(encoded), "ZASP_TEMPORAL_PLANNER_FAULT="+mode)
		output, err := command.CombinedOutput()
		t.Log(string(output))
		if err != nil || !strings.Contains(string(output), "--- PASS: TestTemporalOwnedPlanner") || strings.Contains(string(output), "--- SKIP:") {
			t.Fatal("actual68 planner transport", err)
		}
		if mode != "" && mode != "input_get" && mode != "output_get" {
			return
		}
		var valid bool
		if err := owner.QueryRow(ctx, `SELECT r.state='waiting_approval' AND r.attempt=1 AND r.lease_token IS NULL AND r.lease_owner IS NULL AND r.lease_expires_at IS NULL AND (SELECT count(*) FROM zasp_temporal68.provider_reservations WHERE run_id=$1 AND total_tokens=30 AND cost_nano_credits=30000 AND settled_at IS NOT NULL)=1 AND (SELECT count(*) FROM zasp_temporal68.admissions WHERE run_id=$1)=1 FROM zasp_security_agent_runs r WHERE run_id=$1`, run).Scan(&valid); err != nil || !valid {
			t.Fatal("real planner durable accounting/admission", valid, err)
		}
	})
}

func runTemporalExecutorPlanningFixture(t *testing.T, inspect func(context.Context, *pgx.Conn, *pgx.Conn, *pgx.Conn, string, string, string, string, string), recovery func(context.Context, *pgx.Conn, *pgx.Conn, *pgx.Conn, string, string, string, string, string, []byte, func(string, map[string]any) (map[string]any, error)), transport ...func(context.Context, *pgx.Conn, *pgx.Conn, *pgx.Conn, string, string, string, string, string, map[string]any)) {
	runTemporalExecutorPlanningFixtureWithHook(t, nil, inspect, recovery, transport...)
}

// A handled hook owns the admitted run before any unsigned planning load. Old
// callers retain the complete fixture, including principal and stale negatives.
type temporalExecutorPlanningPreLoad func(context.Context, *pgx.Conn, *pgx.Conn, *pgx.Conn, string, string, string, string, string) bool

func runTemporalExecutorPlanningFixtureWithHook(t *testing.T, beforeLoad temporalExecutorPlanningPreLoad, inspect func(context.Context, *pgx.Conn, *pgx.Conn, *pgx.Conn, string, string, string, string, string), recovery func(context.Context, *pgx.Conn, *pgx.Conn, *pgx.Conn, string, string, string, string, string, []byte, func(string, map[string]any) (map[string]any, error)), transport ...func(context.Context, *pgx.Conn, *pgx.Conn, *pgx.Conn, string, string, string, string, string, map[string]any)) {
	t.Helper()
	runTemporalDomainFreshFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		runTemporalMigrationCLI(t, ctx, owner, "up-temporal-domain")
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_temporal66.admission_routes VALUES($1,$2,$3,'temporal')`, o, w, e); err != nil {
			t.Fatal(err)
		}
		public62Seed(t, ctx, owner, o, w, e, testID, actor)
		q := public62Request(o, w, e, actor, "activate")
		q["definition_id"], q["definition_version"] = public62Definition, 1
		if _, err := public62Call(ctx, api, q); err != nil {
			t.Fatal(err)
		}
		q = public62Request(o, w, e, actor, "trigger_resource")
		q["definition_id"], q["definition_version"], q["trigger_id"], q["trigger_version"], q["idempotency_key"] = public62Definition, 2, public62Finding, 1, "executor-temporal-0001"
		q["trigger_kind"], q["trigger_source"] = "finding", "credential"
		created, err := public62Call(ctx, api, q)
		if err != nil {
			t.Fatal(err)
		}
		run := created["id"].(string)
		var fresh bool
		if err := owner.QueryRow(ctx, `SELECT r.state='queued' AND r.plan_hash IS NULL AND r.lease_token IS NULL AND r.lease_owner IS NULL AND r.lease_expires_at IS NULL AND x.execution_owner='temporal' AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_run_budgets WHERE run_id=$1) FROM zasp_security_agent_runs r JOIN zasp_temporal66.run_owners x USING(organization_id,workspace_id,environment_id,run_id) WHERE r.run_id=$1`, run).Scan(&fresh); err != nil || !fresh {
			t.Fatal("API did not create fresh Temporal run", fresh, err)
		}
		runTemporalMigrationCLI(t, ctx, owner, "up-temporal-executor")
		if err := precisionMigrationRunner(t, owner).UpProductionTemporalExecutor(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `CREATE ROLE temporal_executor_test_login LOGIN IN ROLE zasp_temporal_executor`); err != nil {
			t.Fatal(err)
		}
		configuration := owner.Config().Copy()
		configuration.User = "temporal_executor_test_login"
		executor, err := pgx.ConnectConfig(ctx, configuration)
		if err != nil {
			t.Fatal(err)
		}
		defer executor.Close(ctx)
		request := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "definition_version": 2, "operation": "load"}
		body, _ := json.Marshal(request)
		var first, repeated []byte
		if err := executor.QueryRow(ctx, `SELECT zasp_temporal68.plan($1::jsonb)`, body).Scan(&first); err == nil {
			t.Fatal("role membership alone granted executor authority")
		}
		if _, err := owner.Exec(ctx, `SELECT zasp_temporal68.register_principals('temporal_executor_test_login','temporal_compensation_test_login')`); err == nil {
			t.Fatal("missing compensation principal accepted")
		}
		if _, err := owner.Exec(ctx, `CREATE ROLE temporal_compensation_test_login LOGIN; SELECT zasp_temporal68.register_principals('temporal_executor_test_login','temporal_compensation_test_login')`); err != nil {
			t.Fatal(err)
		}
		stale := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "definition_version": 1, "operation": "load"}
		staleBody, _ := json.Marshal(stale)
		if err := executor.QueryRow(ctx, `SELECT zasp_temporal68.plan($1::jsonb)`, staleBody).Scan(&first); err == nil {
			t.Fatal("stale definition acquired budget")
		}
		if beforeLoad != nil && beforeLoad(ctx, owner, executor, api, o, w, e, run, testID) {
			return
		}
		if err := executor.QueryRow(ctx, `SELECT zasp_temporal68.plan($1::jsonb)`, body).Scan(&first); err != nil {
			t.Fatal("lease-free plan load", err)
		}
		if err := executor.QueryRow(ctx, `SELECT zasp_temporal68.plan($1::jsonb)`, body).Scan(&repeated); err != nil || string(first) != string(repeated) {
			t.Fatal("load changed durable intent", err)
		}
		if err := owner.QueryRow(ctx, `SELECT r.state='planning' AND r.lease_token IS NULL AND r.lease_owner IS NULL AND r.lease_expires_at IS NULL AND (SELECT count(*) FROM zasp_security_agent_run_budgets WHERE run_id=$1)=1 AND NOT EXISTS(SELECT 1 FROM zasp_sa_multistep_prior.planning_jobs WHERE run_id=$1) FROM zasp_security_agent_runs r WHERE r.run_id=$1`, run).Scan(&fresh); err != nil || !fresh {
			t.Fatal("planning borrowed legacy lease authority", fresh, err)
		}
		if err := worker.QueryRow(ctx, `SELECT zasp_temporal68.plan($1::jsonb)`, body).Scan(&repeated); err == nil {
			t.Fatal("old worker acquired executor authority")
		}
		request["operation"], request["payload"] = "start", map[string]any{}
		body, _ = json.Marshal(request)
		if err := executor.QueryRow(ctx, `SELECT zasp_temporal68.plan($1::jsonb)`, body).Scan(&repeated); err == nil {
			t.Fatal("planner sent without prepared pricing/artifact intent")
		}
		// Pricing uses the existing registered administrative path. It does not
		// mutate the initiating requester's immutable planning context.
		adminConfig := owner.Config().Copy()
		adminConfig.User = "security_agent_v33_discovery_api_login"
		admin, err := pgx.ConnectConfig(ctx, adminConfig)
		if err != nil {
			t.Fatal(err)
		}
		defer admin.Close(ctx)
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET role='organization_admin' WHERE principal_id=$1; UPDATE zasp_authorized_scopes SET permissions='["view","manage_identity","manage_workflows","run_tests"]' WHERE principal_id=$1`, pgx.QueryExecModeSimpleProtocol, orderedProgressionApprover); err != nil {
			t.Fatal(err)
		}
		policy := orderedPricingAdminRequest(o, w, e, orderedProgressionApprover)
		if len(transport) > 0 {
			p := policy["policy"].(map[string]any)
			p["request_token_limit"], p["request_policy_version"] = 512, "security-agent-planner-v1"
			h := sha256.Sum256([]byte("sk-or-v1-test-token-1234567890"))
			p["credential_digest"] = "sha256:" + hex.EncodeToString(h[:])
		}
		pricing, err := orderedPricingCall(ctx, admin, "pricing_admin", policy)
		if err != nil {
			t.Fatal(err)
		}
		selection := orderedPricingLookupRequest(o, w, e, policy["policy"].(map[string]any), pricing)
		delete(selection, "body")
		delete(selection, "body_digest")
		if len(transport) > 0 {
			transport[0](ctx, owner, executor, api, o, w, e, run, testID, selection)
			return
		}
		call := func(op string, payload map[string]any) (map[string]any, error) {
			request["operation"], request["payload"] = op, payload
			b, _ := json.Marshal(request)
			var raw []byte
			err := executor.QueryRow(ctx, `SELECT zasp_temporal68.plan($1::jsonb)`, b).Scan(&raw)
			var result map[string]any
			if err == nil {
				err = json.Unmarshal(raw, &result)
			}
			return result, err
		}
		prepared, err := call("prepare", map[string]any{"pricing": selection, "input_version": "temporal-input-version-1"})
		if err != nil || prepared["state"] != "prepared" {
			t.Fatal("lease-free prepared intent", prepared, err)
		}
		if again, err := call("prepare", map[string]any{"pricing": selection, "input_version": "temporal-input-version-1"}); err != nil || !jsonEqualMaps(prepared, again) {
			t.Fatal("prepared intent changed", err)
		}
		if _, err := call("admit", map[string]any{}); err == nil {
			t.Fatal("admitted without usage or artifacts")
		}
		job, err := call("start", map[string]any{})
		if err != nil || job["send_permit"] != true {
			t.Fatal("initial planner send permit", job, err)
		}
		job, err = call("start", map[string]any{})
		if err != nil || job["send_permit"] != false {
			t.Fatal("uncertain start permitted another send", job, err)
		}
		candidate := map[string]any{"version": 1, "summary": "Contain and retest", "steps": []any{map[string]any{"index": 0, "action": "create_temporary_policy", "target_id": e}, map[string]any{"index": 1, "action": "run_test", "target_id": testID}}}
		content, _ := json.Marshal(candidate)
		raw, _ := json.Marshal(map[string]any{"model": "openai/gpt-5-mini", "choices": []any{map[string]any{"index": 0, "finish_reason": "stop", "message": map[string]any{"role": "assistant", "content": string(content)}}}, "usage": map[string]any{"prompt_tokens": 50, "completion_tokens": 50, "total_tokens": 100, "cost": 0.0000005}})
		if recovery != nil {
			recovery(ctx, owner, executor, api, o, w, e, run, actor, raw, call)
			return
		}
		if _, err := call("result", map[string]any{"raw": string(raw)}); err != nil {
			t.Fatal("persist result", err)
		}
		job, err = call("settle", map[string]any{})
		if err != nil || job["state"] != "settled" {
			t.Fatal("settle actual usage", job, err)
		}
		if _, err := call("admit", map[string]any{}); err == nil {
			t.Fatal("admitted without output artifact")
		}
		if _, err := call("artifacts", map[string]any{"input_version": "temporal-input-version-1", "output_version": "temporal-output-version-1", "output_digest": job["output_digest"]}); err != nil {
			t.Fatal("bind output artifact", err)
		}
		receipt, err := call("admit", map[string]any{})
		if err != nil || receipt["outcome"] != "admitted" {
			t.Fatal("lease-free plan admission", receipt, err)
		}
		if again, err := call("admit", map[string]any{}); err != nil || !jsonEqualMaps(receipt, again) {
			t.Fatal("admission replay changed", again, err)
		}
		var tokens, cost int64
		if err := owner.QueryRow(ctx, `SELECT total_tokens,cost_nano_credits FROM zasp_temporal68.provider_reservations WHERE run_id=$1`, run).Scan(&tokens, &cost); err != nil || tokens != 100 || cost != 500 {
			t.Fatal("actual planner accounting", tokens, cost, err)
		}
		inspect(ctx, owner, executor, api, o, w, e, run, actor)
	})
}

func TestTemporalExecutorPlannerRecoveryPostgres(t *testing.T) {
	for _, mode := range []string{"unknown", "over_budget", "requester_lost", "rejected", "expired"} {
		t.Run(mode, func(t *testing.T) {
			runTemporalExecutorPlanningFixture(t, nil, func(ctx context.Context, owner, executor, api *pgx.Conn, o, w, e, run, actor string, raw []byte, call func(string, map[string]any) (map[string]any, error)) {
				var provider map[string]any
				json.Unmarshal(raw, &provider)
				if mode == "over_budget" {
					provider["usage"].(map[string]any)["cost"] = 1000.0
					raw, _ = json.Marshal(provider)
				}
				if mode == "rejected" {
					provider["choices"].([]any)[0].(map[string]any)["message"].(map[string]any)["content"] = "not JSON"
					raw, _ = json.Marshal(provider)
				}
				var job map[string]any
				var err error
				if mode == "over_budget" || mode == "rejected" {
					if _, err := call("result", map[string]any{"raw": string(raw)}); err != nil {
						t.Fatal(err)
					}
					job, err = call("settle", map[string]any{})
				} else {
					if mode == "expired" {
						if _, err := owner.Exec(ctx, `WITH changed AS (UPDATE zasp_security_agent_run_budgets SET started_at=started_at-interval '1 day',deadline_at=deadline_at-interval '1 day' WHERE run_id=$1 RETURNING started_at,deadline_at) UPDATE zasp_temporal68.planning_jobs SET budget_started_at=changed.started_at,budget_deadline_at=changed.deadline_at FROM changed WHERE run_id=$1`, run); err != nil {
							t.Fatal(err)
						}
					} else if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE principal_id=$1`, actor); err != nil {
						t.Fatal(err)
					}
					if _, err := call("start", map[string]any{}); err == nil {
						t.Fatal("lost authority retained send permission")
					}
					config := owner.Config().Copy()
					config.User = "temporal_compensation_test_login"
					comp, connectErr := pgx.ConnectConfig(ctx, config)
					if connectErr != nil {
						t.Fatal(connectErr)
					}
					defer comp.Close(ctx)
					payload := map[string]any{}
					if mode == "requester_lost" || mode == "expired" {
						payload["raw"] = string(raw)
					}
					q := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "definition_version": 2, "operation": "reconcile", "payload": payload}
					b, _ := json.Marshal(q)
					var result []byte
					err = comp.QueryRow(ctx, `SELECT zasp_temporal68.plan($1::jsonb)`, b).Scan(&result)
					if err == nil {
						err = json.Unmarshal(result, &job)
					}
					if err == nil {
						var replay []byte
						if err := comp.QueryRow(ctx, `SELECT zasp_temporal68.plan($1::jsonb)`, b).Scan(&replay); err != nil || string(replay) != string(result) {
							t.Fatal("planner recovery replay changed", err)
						}
					}
				}
				if err != nil || job["state"] != "needs_human" {
					t.Fatal("planner terminal recovery", job, err)
				}
				repo, id := public62GoRepository(t, api, o, w, e, orderedProgressionApprover)
				detail, err := repo.Run(ctx, id, run)
				if err != nil || detail.State != "needs_human" {
					t.Fatal("public terminal planning", detail, err)
				}
				if _, err := call("start", map[string]any{}); err == nil {
					t.Fatal("terminal recovery permitted resend")
				}
				var charged *int64
				var events int
				if err := owner.QueryRow(ctx, `SELECT cost_nano_credits,(SELECT count(*) FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind='temporal_planning_terminal') FROM zasp_temporal68.provider_reservations WHERE run_id=$1`, run).Scan(&charged, &events); err != nil || events != 1 {
					t.Fatal("terminal evidence", events, err)
				}
				if mode == "unknown" {
					if charged != nil {
						t.Fatal("unknown usage fabricated", *charged)
					}
				} else {
					want := int64(500)
					if mode == "over_budget" {
						want = 1000000000000
					}
					if charged == nil || *charged != want {
						t.Fatal("actual cost not retained", charged, want)
					}
				}
			})
		})
	}
}

func TestTemporalExecutorPlannerLateUsagePostgres(t *testing.T) {
	for _, mode := range []string{"no_response", "unknown_usage"} {
		t.Run(mode, func(t *testing.T) {
			runTemporalExecutorPlanningFixture(t, nil, func(ctx context.Context, owner, executor, api *pgx.Conn, o, w, e, run, actor string, providerRaw []byte, call func(string, map[string]any) (map[string]any, error)) {
				var provider map[string]any
				json.Unmarshal(providerRaw, &provider)
				provider["id"] = "generation-late-1"
				providerRaw, _ = json.Marshal(provider)
				if mode == "unknown_usage" {
					unknown := map[string]any{}
					for k, v := range provider {
						unknown[k] = v
					}
					delete(unknown, "usage")
					raw, _ := json.Marshal(unknown)
					if _, err := call("result", map[string]any{"raw": string(raw)}); err != nil {
						t.Fatal(err)
					}
					if _, err := call("settle", map[string]any{}); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE principal_id=$1`, actor); err != nil {
					t.Fatal(err)
				}
				cfg := owner.Config().Copy()
				cfg.User = "temporal_compensation_test_login"
				comp, err := pgx.ConnectConfig(ctx, cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer comp.Close(ctx)
				database, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: comp})
				repository, _ := NewSecurityAgentTemporalExecutorRepository(database)
				actual, hasFacade := any(repository).(interface {
					TemporalPlannerLateUsage(context.Context, json.RawMessage) (json.RawMessage, error)
				})
				if !hasFacade {
					t.Error("actual68 late usage repository missing")
				}
				q := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "definition_version": 2, "operation": "reconcile", "payload": map[string]any{}}
				invoke := func(op string, payload any) ([]byte, error) {
					q["operation"], q["payload"] = op, payload
					b, _ := json.Marshal(q)
					if op == "late_usage" && hasFacade {
						return actual.TemporalPlannerLateUsage(ctx, b)
					}
					var raw []byte
					err := comp.QueryRow(ctx, `SELECT zasp_temporal68.plan($1::jsonb)`, b).Scan(&raw)
					return raw, err
				}
				original, err := invoke("reconcile", map[string]any{})
				if err != nil {
					t.Fatal(err)
				}
				var priorAudit string
				var requestDigest, credentialDigest, reservation string
				if err := owner.QueryRow(ctx, `SELECT request_digest,lookup_request->>'credential_digest',reservation_id,(SELECT to_jsonb(a)::text FROM zasp_security_agent_audit a WHERE a.run_id=j.run_id AND event_kind='temporal_planning_terminal') FROM zasp_temporal68.planning_jobs j WHERE run_id=$1`, run).Scan(&requestDigest, &credentialDigest, &reservation, &priorAudit); err != nil {
					t.Fatal(err)
				}
				digest := sha256.Sum256(providerRaw)
				payload := map[string]any{"raw": string(providerRaw), "request_digest": requestDigest, "credential_digest": credentialDigest, "reservation_id": reservation, "response_id": "generation-late-1", "response_digest": "sha256:" + hex.EncodeToString(digest[:])}
				for _, k := range []string{"request_digest", "credential_digest", "reservation_id", "response_id", "response_digest"} {
					bad := map[string]any{}
					for key, v := range payload {
						bad[key] = v
					}
					bad[k] = "sha256:" + strings.Repeat("f", 64)
					if k == "reservation_id" {
						bad[k] = o
					}
					if k == "response_id" {
						bad[k] = "generation-foreign"
					}
					if _, err := invoke("late_usage", bad); err == nil {
						t.Fatal("foreign late usage association", k)
					}
				}
				late, err := invoke("late_usage", payload)
				if err != nil {
					t.Fatal("authentic late known usage unavailable", err)
				}
				if string(late) != string(original) {
					t.Fatal("late usage rewrote original terminal job")
				}
				if replay, err := invoke("late_usage", payload); err != nil || string(replay) != string(original) {
					t.Fatal("late usage replay", err)
				}
				provider["usage"].(map[string]any)["cost"] = 1.0
				changed, _ := json.Marshal(provider)
				changedDigest := sha256.Sum256(changed)
				payload["raw"], payload["response_digest"] = string(changed), "sha256:"+hex.EncodeToString(changedDigest[:])
				if _, err := invoke("late_usage", payload); err == nil {
					t.Fatal("late usage conflict rewrote charge")
				}
				var valid bool
				if err := owner.QueryRow(ctx, `SELECT r.state='needs_human' AND r.plan_hash IS NULL AND p.total_tokens=100 AND p.cost_nano_credits=500 AND p.settled_at IS NOT NULL AND (SELECT count(*) FROM zasp_temporal68.provider_reservations WHERE run_id=$1)=1 AND NOT EXISTS(SELECT 1 FROM zasp_temporal68.admissions WHERE run_id=$1) AND (SELECT to_jsonb(a)::text FROM zasp_security_agent_audit a WHERE a.run_id=$1 AND event_kind='temporal_planning_terminal')=$2 AND (SELECT count(*) FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind='temporal_planning_late_usage')=1 FROM zasp_security_agent_runs r JOIN zasp_temporal68.provider_reservations p USING(organization_id,workspace_id,environment_id,run_id) WHERE r.run_id=$1`, run, priorAudit).Scan(&valid); err != nil || !valid {
					t.Fatal("late usage immutable evidence/single charge", valid, err)
				}
				repo, id := public62GoRepository(t, api, o, w, e, orderedProgressionApprover)
				detail, err := repo.Run(ctx, id, run)
				if err != nil || detail.State != "needs_human" {
					t.Fatal("late known usage broke public terminal evidence", detail, err)
				}
				if _, err := invoke("reconcile", map[string]any{}); err != nil {
					t.Fatal("late charge broke retained recovery", err)
				}
				if _, err := call("start", map[string]any{}); err == nil {
					t.Fatal("late charge reopened send")
				}
				if _, err := call("admit", map[string]any{}); err == nil {
					t.Fatal("late charge reopened admission")
				}
			})
		})
	}
}

func TestTemporalExecutorPlannerPreSendRecoveryPostgres(t *testing.T) {
	for _, state := range []string{"loaded", "prepared"} {
		t.Run(state, func(t *testing.T) {
			runTemporalExecutorPlanningFixture(t, nil, nil, func(ctx context.Context, owner, executor, api *pgx.Conn, o, w, e, run, testID string, selection map[string]any) {
				q := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "definition_version": 2, "operation": "prepare", "payload": map[string]any{"pricing": selection, "input_version": "pre-send-controlled-version"}}
				invoke := func(c *pgx.Conn, op string, payload any) ([]byte, error) {
					q["operation"], q["payload"] = op, payload
					b, _ := json.Marshal(q)
					var raw []byte
					err := c.QueryRow(ctx, `SELECT zasp_temporal68.plan($1::jsonb)`, b).Scan(&raw)
					return raw, err
				}
				if state == "prepared" {
					if _, err := invoke(executor, "prepare", q["payload"]); err != nil {
						t.Fatal(err)
					}
				}
				var actor string
				if err := owner.QueryRow(ctx, `SELECT requested_by FROM zasp_security_agent_runs WHERE run_id=$1`, run).Scan(&actor); err != nil {
					t.Fatal(err)
				}
				legacyRun := seedOrderedPlanningQueue(t, ctx, owner, o, w, e, testID, actor)
				if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET body=jsonb_set(body,'{concurrency_limit}','1') WHERE definition_id=(SELECT definition_id FROM zasp_security_agent_runs WHERE run_id=$1)`, legacyRun); err != nil {
					t.Fatal(err)
				}
				cfg := owner.Config().Copy()
				cfg.User = "security_agent_v33_worker_login"
				worker, err := pgx.ConnectConfig(ctx, cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer worker.Close(ctx)
				legacyClaim := func() error {
					_, err := orderedPlanningCall(ctx, worker, map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": legacyRun, "worker_id": "release-witness", "lease_token": "release-witness-lease-0001", "operation": "claim", "payload": map[string]any{}})
					return err
				}
				if err := legacyClaim(); err == nil {
					t.Fatal("active Temporal admission did not hold shared capacity")
				}
				if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE principal_id=$1`, actor); err != nil {
					t.Fatal(err)
				}
				cfg = owner.Config().Copy()
				cfg.User = "temporal_compensation_test_login"
				comp, err := pgx.ConnectConfig(ctx, cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer comp.Close(ctx)
				first, err := invoke(comp, "reconcile", map[string]any{})
				if err != nil {
					t.Fatal("provably unstarted planner recovery missing", err)
				}
				if again, err := invoke(comp, "reconcile", map[string]any{}); err != nil || string(again) != string(first) {
					t.Fatal("pre-send replay changed", err)
				}
				var valid bool
				if err := owner.QueryRow(ctx, `SELECT r.state='needs_human' AND r.last_error_code='planner_not_sent' AND r.plan_hash IS NULL AND j.state='needs_human' AND j.raw_result IS NULL AND (SELECT count(*) FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind='temporal_planning_terminal' AND body->>'dispatch_state'=$2)=1 AND NOT EXISTS(SELECT 1 FROM zasp_temporal68.admissions WHERE run_id=$1) FROM zasp_security_agent_runs r JOIN zasp_temporal68.planning_jobs j USING(organization_id,workspace_id,environment_id,run_id) WHERE r.run_id=$1`, run, state).Scan(&valid); err != nil || !valid {
					t.Fatal("pre-send immutable terminal proof", valid, err)
				}
				if state == "prepared" {
					if err := owner.QueryRow(ctx, `SELECT released_at IS NOT NULL AND settled_at IS NULL AND output_digest IS NULL AND total_tokens IS NULL AND cost_nano_credits IS NULL FROM zasp_temporal68.provider_reservations WHERE run_id=$1`, run).Scan(&valid); err != nil || !valid {
						t.Fatal("unused reservation not released or fabricated usage", valid, err)
					}
				} else {
					if err := owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_temporal68.provider_reservations WHERE run_id=$1)`, run).Scan(&valid); err != nil || !valid {
						t.Fatal("loaded recovery fabricated reservation", valid, err)
					}
				}
				repo, id := public62GoRepository(t, api, o, w, e, orderedProgressionApprover)
				detail, err := repo.Run(ctx, id, run)
				if err != nil || detail.State != "needs_human" {
					t.Fatal("pre-send public evidence", detail, err)
				}
				if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=true WHERE principal_id=$1`, actor); err != nil {
					t.Fatal(err)
				}
				if err := legacyClaim(); err != nil {
					t.Fatal("closed no-send intent still held authoritative shared capacity", err)
				}
				if _, err := invoke(executor, "start", map[string]any{}); err == nil {
					t.Fatal("released intent acquired fresh authorization")
				}
			})
		})
	}
}

// Removing current approval, plan, requester or budget checks must allow none
// of these requests to reserve a provider send. Retries consume one intent.
func TestTemporalExecutorEffectIntentPostgres(t *testing.T) {
	runTemporalExecutorAdmittedFixture(t, func(ctx context.Context, owner, executor, api *pgx.Conn, o, w, e, run, actor string) {
		seedOrderedApplicationGateway(t, ctx, owner, o, w, e)
		var installed bool
		if err := owner.QueryRow(ctx, `SELECT to_regprocedure('zasp_temporal68.effect(jsonb)') IS NOT NULL`).Scan(&installed); err != nil || !installed {
			t.Fatal("lease-free effect journal missing", err)
		}
		var step, next string
		if err := owner.QueryRow(ctx, `SELECT plan->'steps'->0->>'step_id',plan->'steps'->1->>'step_id' FROM zasp_security_agent_plans WHERE run_id=$1`, run).Scan(&step, &next); err != nil {
			t.Fatal(err)
		}
		q := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "step_id": step, "generation": 1, "operation": "reserve", "payload": map[string]any{}}
		call := func(conn *pgx.Conn, op string) (map[string]any, error) {
			q["operation"] = op
			b, _ := json.Marshal(q)
			var raw []byte
			err := conn.QueryRow(ctx, `SELECT zasp_temporal68.effect($1::jsonb)`, b).Scan(&raw)
			var value map[string]any
			if err == nil {
				err = json.Unmarshal(raw, &value)
			}
			return value, err
		}
		if _, err := call(executor, "reserve"); err == nil {
			t.Fatal("unapproved execution accepted")
		}
		public62TypedDecision(t, ctx, api, o, w, e, run, 3)
		for _, probe := range []struct{ change, restore, arg string }{
			{`UPDATE zasp_identity_memberships SET active=false WHERE principal_id=$1`, `UPDATE zasp_identity_memberships SET active=true WHERE principal_id=$1`, actor},
			{`UPDATE zasp_security_agent_run_budgets SET stop_reason='budget_tokens_exceeded' WHERE run_id=$1`, `UPDATE zasp_security_agent_run_budgets SET stop_reason=NULL WHERE run_id=$1`, run},
		} {
			if _, err := owner.Exec(ctx, probe.change, probe.arg); err != nil {
				t.Fatal(err)
			}
			_, err := call(executor, "reserve")
			if _, restoreErr := owner.Exec(ctx, probe.restore, probe.arg); restoreErr != nil {
				t.Fatal(restoreErr)
			}
			if err == nil {
				t.Fatal("changed authority reserved effect", probe.change)
			}
		}
		q["step_id"] = next
		if _, err := call(executor, "reserve"); err == nil {
			t.Fatal("successor without verified predecessor accepted")
		}
		q["step_id"] = step
		intent, err := call(executor, "reserve")
		if err != nil {
			t.Fatal("reserve", err)
		}
		if repeat, err := call(executor, "reserve"); err != nil || !jsonEqualMaps(intent, repeat) {
			t.Fatal("reservation replay changed", repeat, err)
		}
		q["generation"] = 2
		if _, err := call(executor, "reserve"); err == nil {
			t.Fatal("invented generation admitted")
		}
		q["generation"] = 1
		if _, err := executor.Exec(ctx, `BEGIN`); err != nil {
			t.Fatal(err)
		}
		started, err := call(executor, "start")
		if err != nil || started["send_permit"] != true {
			t.Fatal("initial send", started, err)
		}
		overlap, err := pgx.ConnectConfig(ctx, executor.Config().Copy())
		if err != nil {
			t.Fatal(err)
		}
		defer overlap.Close(ctx)
		startBytes, _ := json.Marshal(q)
		type overlappingResult struct {
			permit bool
			err    error
		}
		overlapDone := make(chan overlappingResult, 1)
		go func() {
			var raw []byte
			err := overlap.QueryRow(ctx, `SELECT zasp_temporal68.effect($1::jsonb)`, startBytes).Scan(&raw)
			var result struct {
				Permit bool `json:"send_permit"`
			}
			if err == nil {
				err = json.Unmarshal(raw, &result)
			}
			overlapDone <- overlappingResult{result.Permit, err}
		}()
		waitOrderedProgressionBlocked(t, ctx, executor, overlap)
		if _, err := executor.Exec(ctx, `COMMIT`); err != nil {
			t.Fatal(err)
		}
		if second := <-overlapDone; second.err != nil || second.permit {
			t.Fatal("overlap repeated send", second)
		}
		if repeat, err := call(executor, "start"); err != nil || repeat["send_permit"] != false {
			t.Fatal("uncertain send repeated", repeat, err)
		}
		if _, err := call(executor, "unknown"); err != nil {
			t.Fatal(err)
		}
		if repeat, err := call(executor, "start"); err != nil || repeat["send_permit"] != false {
			t.Fatal("unknown send repeated", repeat, err)
		}
		var count int
		var leaseFree bool
		if err := owner.QueryRow(ctx, `SELECT count(*),bool_and(lease_token IS NULL AND lease_owner IS NULL AND lease_expires_at IS NULL AND state='unknown_outcome') FROM zasp_security_agent_effects WHERE run_id=$1`, run).Scan(&count, &leaseFree); err != nil || count != 1 || !leaseFree {
			t.Fatal("public effect evidence", count, leaseFree, err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE principal_id=$1`, actor); err != nil {
			t.Fatal(err)
		}
		if _, err := call(executor, "start"); err == nil {
			t.Fatal("inactive requester retained send authority")
		}
		config := owner.Config().Copy()
		config.User = "temporal_compensation_test_login"
		compensation, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer compensation.Close(ctx)
		if _, err := call(compensation, "start"); err == nil {
			t.Fatal("compensation obtained execution permission")
		}
		if recovered, err := call(compensation, "unknown"); err != nil || recovered["state"] != "unknown" {
			t.Fatal("compensation lost scoped evidence", recovered, err)
		}
		q["workspace_id"] = o
		if _, err := call(compensation, "unknown"); err == nil {
			t.Fatal("cross-scope recovery accepted")
		}
	})
}

// A signed source is a scoped durable write. No application receipt exists
// until its composed bundle has been read back and verified.
func TestTemporalExecutorPolicySourcePostgres(t *testing.T) {
	runTemporalExecutorPolicyFixture(t, true, nil)
}

// Missing progress or a relaxed predecessor gate must leave this test red:
// only an actually stored, read-back and acknowledged application opens step1.
func TestTemporalExecutorProgressPostgres(t *testing.T) {
	runTemporalExecutorPolicyFixture(t, true, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, run, step string, keys policy.GatewayPolicyKeys, key ed25519.PrivateKey, call func(*pgx.Conn, string, string, any) (map[string]any, error)) {
		config := owner.Config().Copy()
		config.User = "temporal_executor_test_login"
		executor, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer executor.Close(ctx)
		var successor, actor string
		var version int64
		if err := owner.QueryRow(ctx, `SELECT p.plan->'steps'->1->>'step_id',r.requested_by,r.version FROM zasp_security_agent_runs r JOIN zasp_security_agent_plans p USING(organization_id,workspace_id,environment_id,run_id) WHERE r.run_id=$1`, run).Scan(&successor, &actor, &version); err != nil {
			t.Fatal(err)
		}
		request := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "step_id": successor, "operation": "progress", "actor_id": "temporal-executor", "run_version": version, "approval_version": 1, "fresh_auth_at": ""}
		invoke := func(conn *pgx.Conn) (map[string]any, error) {
			body, _ := json.Marshal(request)
			var raw []byte
			err := conn.QueryRow(ctx, `SELECT zasp_temporal68.progress($1::jsonb)`, body).Scan(&raw)
			var result map[string]any
			if err == nil {
				err = json.Unmarshal(raw, &result)
			}
			return result, err
		}
		var present bool
		if err := owner.QueryRow(ctx, `SELECT to_regprocedure('zasp_temporal68.progress(jsonb)') IS NOT NULL`).Scan(&present); err != nil || !present {
			t.Fatal("lease-free scoped progress missing", err)
		}
		if _, err := invoke(executor); err == nil {
			t.Fatal("deactivated requester progressed")
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=true WHERE principal_id=$1`, actor); err != nil {
			t.Fatal(err)
		}
		if _, err := invoke(api); err == nil {
			t.Fatal("API principal progressed executor")
		}
		first, err := invoke(executor)
		if err != nil || first["outcome"] != "ready" || first["run_state"] != "waiting_approval" {
			t.Fatal("verified application did not open second approval", first, err)
		}
		if repeat, err := invoke(executor); err != nil || !jsonEqualMaps(first, repeat) {
			t.Fatal("progress replay", repeat, err)
		}
		repo, id := public62GoRepository(t, api, o, w, e, orderedProgressionApprover)
		if _, err := repo.Run(ctx, id, run); err != nil {
			t.Fatal("public successor read", err)
		}
		var count int
		if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_security_agent_approvals WHERE run_id=$1`, run).Scan(&count); err != nil || count != 2 {
			t.Fatal("second approval cardinality", count, err)
		}
		request["operation"] = "approve"
		if _, err := invoke(executor); err == nil {
			t.Fatal("executor approved own successor")
		}
		request["operation"] = "stop"
		request["run_version"] = first["run_version"]
		if _, err := invoke(executor); err == nil {
			t.Fatal("unneeded stop accepted")
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE principal_id=$1`, actor); err != nil {
			t.Fatal(err)
		}
		config.User = "temporal_compensation_test_login"
		compensation, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer compensation.Close(ctx)
		stopped, err := invoke(compensation)
		if err != nil || stopped["run_state"] != "needs_human" {
			t.Fatal("narrow requester-loss stop", stopped, err)
		}
		if _, err := repo.Run(ctx, id, run); err != nil {
			t.Fatal("public stopped read", err)
		}
	})
}

func TestTemporalExecutorLinkedIntentPostgres(t *testing.T) {
	runTemporalExecutorLinkedIntentFixture(t, "")
}

func TestTemporalExecutorLinkedSettlementPostgres(t *testing.T) {
	runTemporalExecutorLinkedIntentFixture(t, "settle")
}

func TestTemporalExecutorLinkedStopPostgres(t *testing.T) {
	runTemporalExecutorLinkedIntentFixture(t, "stop")
}

func TestTemporalExecutorLinkedRepositoryPostgres(t *testing.T) {
	runTemporalExecutorLinkedIntentFixture(t, "repository")
}

func TestTemporalExecutorLinkedRunnerPostgres(t *testing.T) {
	runTemporalExecutorLinkedIntentFixture(t, "runner")
}

func TestTemporalExecutorLinkedRunnerFaultsPostgres(t *testing.T) {
	for _, mode := range []string{"reserved_lost", "input_lost", "lost_dispatch", "command_error", "lost_settle", "wire_missing_effects", "wire_duplicate_run", "input_get", "output_get"} {
		t.Run(mode, func(t *testing.T) { runTemporalExecutorLinkedIntentFixture(t, "runner_"+mode) })
	}
}

func TestTemporalExecutorLinkedHTTPSPostgres(t *testing.T) {
	for _, mode := range []string{"success", "lost_start", "lost_complete"} {
		t.Run(mode, func(t *testing.T) { runTemporalExecutorLinkedIntentFixture(t, mode) })
	}
}

func runTemporalExecutorLinkedIntentFixture(t *testing.T, network string) {
	runTemporalExecutorPolicyFixture(t, true, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, run, applyStep string, keys policy.GatewayPolicyKeys, key ed25519.PrivateKey, policyCall func(*pgx.Conn, string, string, any) (map[string]any, error)) {
		config := owner.Config().Copy()
		config.User = "temporal_executor_test_login"
		executor, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer executor.Close(ctx)
		var step, actor string
		var version int64
		if err := owner.QueryRow(ctx, `SELECT p.plan->'steps'->1->>'step_id',r.requested_by,r.version FROM zasp_security_agent_runs r JOIN zasp_security_agent_plans p USING(organization_id,workspace_id,environment_id,run_id) WHERE r.run_id=$1`, run).Scan(&step, &actor, &version); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=true WHERE principal_id=$1`, actor); err != nil {
			t.Fatal(err)
		}
		seedOrderedTestSource(t, ctx, owner, o, w, e, actor)
		progress, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "step_id": step, "operation": "progress", "actor_id": "temporal-executor", "run_version": version, "approval_version": 1, "fresh_auth_at": ""})
		var raw []byte
		if err := executor.QueryRow(ctx, `SELECT zasp_temporal68.progress($1::jsonb)`, progress).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var ready map[string]any
		json.Unmarshal(raw, &ready)
		public62TypedDecision(t, ctx, api, o, w, e, run, int64(ready["run_version"].(float64)))
		request := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "step_id": step, "generation": 1, "operation": "reserve", "payload": map[string]any{}}
		invoke := func(entry, op string, payload any) (map[string]any, error) {
			request["operation"], request["payload"] = op, payload
			body, _ := json.Marshal(request)
			var result []byte
			err := executor.QueryRow(ctx, `SELECT zasp_temporal68.`+entry+`($1::jsonb)`, body).Scan(&result)
			var decoded map[string]any
			if err == nil {
				err = json.Unmarshal(result, &decoded)
			}
			return decoded, err
		}
		intent, err := invoke("effect", "reserve", map[string]any{})
		if err != nil {
			t.Fatal(err)
		}
		var child, testID string
		if err := owner.QueryRow(ctx, `SELECT test_run_id,test_definition_id FROM zasp_security_agent_test_links WHERE run_id=$1 AND step_id=$2`, run, step).Scan(&child, &testID); err != nil {
			t.Fatal("lease-free linked child absent", err)
		}
		if replay, err := invoke("effect", "reserve", map[string]any{}); err != nil || !jsonEqualMaps(intent, replay) {
			t.Fatal("linked reserve replay", replay, err)
		}
		var leased bool
		if err := owner.QueryRow(ctx, `SELECT lease_token IS NOT NULL OR worker_id IS NOT NULL OR lease_expires_at IS NOT NULL FROM zasp_red_team_runs WHERE run_id=$1`, child).Scan(&leased); err != nil || leased {
			t.Fatal("linked child fabricated lease", leased, err)
		}
		if network == "runner" || strings.HasPrefix(network, "runner_") {
			worker, adapter := orderedTestConnections(t, ctx, owner)
			defer worker.Close(ctx)
			defer adapter.Close(ctx)
			var definitionVersion int64
			if err := owner.QueryRow(ctx, `SELECT definition_version FROM zasp_security_agent_runs WHERE run_id=$1`, run).Scan(&definitionVersion); err != nil {
				t.Fatal(err)
			}
			command := exec.CommandContext(ctx, "go", "test", "./agentsec-worker", "-run", "^TestTemporalOwnedRunner$", "-count=1", "-v")
			command.Dir = ".."
			command.WaitDelay = 5 * time.Second
			command.Env = append(os.Environ(), "ZASP_TEMPORAL_JOURNAL_OWNER_DSN="+owner.Config().ConnString(), "ZASP_ORDERED_ORG="+o, "ZASP_ORDERED_WORKSPACE="+w, "ZASP_ORDERED_ENVIRONMENT="+e, "ZASP_TEMPORAL_PARENT="+run, "ZASP_TEMPORAL_STEP="+step, "ZASP_TEMPORAL_DEFINITION_VERSION="+strconv.FormatInt(definitionVersion, 10))
			mode := strings.TrimPrefix(network, "runner_")
			if network == "runner" {
				mode = ""
			}
			command.Env = append(command.Env, "ZASP_TEMPORAL_RUNNER_MODE="+mode)
			output, err := command.CombinedOutput()
			t.Log(string(output))
			if err != nil || !strings.Contains(string(output), "--- PASS: TestTemporalOwnedRunner") || strings.Contains(string(output), "--- SKIP:") {
				t.Fatal("actual68 runner composition", err)
			}
			if strings.HasPrefix(mode, "wire_") {
				return
			}
			outcome := "remediated"
			if mode != "" && mode != "lost_settle" && mode != "input_get" {
				outcome = "needs_human"
			}
			verifyTemporalLinkedCleanup(t, ctx, owner, api, o, w, e, run, outcome, key, policyCall)
			return
		}
		store, manifest := orderedTestInputArtifact(t, ctx, owner, o, w, e, run, step, child, testID)
		if network == "repository" {
			database, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: executor})
			repository, _ := NewSecurityAgentTemporalExecutorRepository(database)
			actual, ok := any(repository).(interface {
				TemporalLinked(context.Context, json.RawMessage, artifactstore.ObjectReferencingArtifactStore) (json.RawMessage, error)
				TemporalTestSettle(context.Context, json.RawMessage, artifactstore.ObjectReferencingArtifactStore) (json.RawMessage, error)
			})
			if !ok {
				t.Error("actual68 linked artifact repository missing")
			} else {
				previous := invoke
				invoke = func(entry, op string, payload any) (map[string]any, error) {
					if entry != "linked" && entry != "test_settle" {
						return previous(entry, op, payload)
					}
					request["operation"], request["payload"] = op, payload
					body, _ := json.Marshal(request)
					var raw json.RawMessage
					var err error
					if entry == "linked" {
						raw, err = actual.TemporalLinked(ctx, body, store)
					} else {
						raw, err = actual.TemporalTestSettle(ctx, body, store)
					}
					var value map[string]any
					if err == nil {
						err = json.Unmarshal(raw, &value)
					}
					return value, err
				}
			}
		}
		scope, _ := orderedTestScope(o, w, e, run, step)
		artifactID, _ := CanonicalDiscoveryID(scope, "security_agent_ordered_test_input", run+"\x1f"+step)
		object, err := orderedTestReadArtifact(ctx, store, scope, artifactID, manifest, 65536)
		if err != nil {
			t.Fatal(err)
		}
		payload := map[string]any{"manifest": manifest, "body": base64.StdEncoding.EncodeToString(object)}
		prepared, err := invoke("linked", "input", payload)
		if err != nil || prepared["test_run_id"] != child || prepared["effect_key"] != intent["effect_key"] {
			t.Fatal("linked artifact preparation", prepared, err)
		}
		if replay, err := invoke("linked", "input", payload); err != nil || !jsonEqualMaps(prepared, replay) {
			t.Fatal("linked input replay", replay, err)
		}
		payload["body"] = base64.StdEncoding.EncodeToString([]byte("{}"))
		if _, err := invoke("linked", "input", payload); err == nil {
			t.Fatal("linked input body substitution")
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE principal_id=$1`, actor); err != nil {
			t.Fatal(err)
		}
		if _, err := invoke("linked", "dispatch", map[string]any{}); err == nil {
			t.Fatal("deactivated requester dispatched child")
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=true WHERE principal_id=$1`, actor); err != nil {
			t.Fatal(err)
		}
		dispatched, err := invoke("linked", "dispatch", map[string]any{})
		if err != nil || dispatched["send_permit"] != true {
			t.Fatal("linked dispatch", dispatched, err)
		}
		if again, err := invoke("linked", "dispatch", map[string]any{}); err != nil || again["send_permit"] != false {
			t.Fatal("linked duplicate dispatch", again, err)
		}
		var journalPresent bool
		if err := owner.QueryRow(ctx, `SELECT to_regprocedure('zasp_temporal68.invocation(jsonb)') IS NOT NULL`).Scan(&journalPresent); err != nil || !journalPresent {
			t.Fatal("lease-free invocation journal missing", err)
		}
		redWorker, adapter := orderedTestConnections(t, ctx, owner)
		defer redWorker.Close(ctx)
		defer adapter.Close(ctx)
		if network == "" {
			command := exec.CommandContext(ctx, "go", "test", "./red-team-adapter", "-run", "^TestProductionAdapterOwnedRouting$", "-count=1", "-v")
			command.Dir = ".."
			command.WaitDelay = 5 * time.Second
			command.Env = append(os.Environ(), "ZASP_ADAPTER_ROUTING_DSN="+owner.Config().ConnString(), "ZASP_TEMPORAL_ROUTING=1")
			output, err := command.CombinedOutput()
			t.Log(string(output))
			if err != nil || !strings.Contains(string(output), "--- PASS: TestProductionAdapterOwnedRouting") || strings.Contains(string(output), "--- SKIP:") {
				t.Fatal("actual68 adapter startup", err)
			}
			database, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: adapter})
			actual, err := redteamadapter.NewTemporalPostgresJournal(database, migrations.ProductionTemporalExecutor().Checksum(), migrations.TemporalExecutorFingerprint())
			if err != nil || actual.Ready(ctx) != nil {
				t.Fatal("actual adapter readiness", err)
			}
			standalone, _ := CanonicalDiscoveryID(scope, "temporal_standalone_regression", run)
			if err := api.QueryRow(ctx, `SELECT zasp_red_team_run_test($1,$2,$3,$4,'temporal-standalone-0001',$5,1,$6,$6)`, o, w, e, actor, testID, standalone).Scan(&raw); err != nil {
				t.Fatal("standalone admission", err)
			}
			lease := strings.Repeat("a", 32)
			if err := redWorker.QueryRow(ctx, `SELECT zasp_red_team_claim_run($1,$2,$3,$4,'standalone-worker',convert_to($5,'UTF8'),60)`, o, w, e, standalone, lease).Scan(&raw); err != nil {
				t.Fatal("standalone claim", err)
			}
			resolution := redteamadapter.TargetResolution{Scope: scope, RunID: standalone, LeaseToken: lease, TargetID: prepared["target_id"].(string), TargetKind: prepared["target_kind"].(string), Category: prepared["categories"].([]any)[0].(string)}
			if binding, err := actual.StandaloneResolver().ResolveTarget(ctx, resolution); err != nil || binding.TargetID != resolution.TargetID {
				t.Fatal("standalone68 facade", binding, err)
			}
			resolution.RunID = child
			if _, err := actual.StandaloneResolver().ResolveTarget(ctx, resolution); err == nil {
				t.Fatal("linked child entered standalone facade")
			}
			if err := redWorker.QueryRow(ctx, `SELECT zasp_red_team_claim_run($1,$2,$3,$4,'standalone-worker',convert_to($5,'UTF8'),60)`, o, w, e, child, lease).Scan(&raw); err == nil {
				t.Fatal("legacy worker claimed68 child")
			}
			if _, err := owner.Exec(ctx, `CREATE ROLE temporal_adapter_extra NOLOGIN; GRANT temporal_adapter_extra TO ordered_test_red_adapter`); err != nil {
				t.Fatal(err)
			}
			if err := actual.Ready(ctx); err == nil {
				t.Fatal("adapter extra role accepted")
			}
			if _, err := owner.Exec(ctx, `REVOKE temporal_adapter_extra FROM ordered_test_red_adapter`); err != nil {
				t.Fatal(err)
			}
		}
		category := prepared["categories"].([]any)[0].(string)
		var prompt string
		if err := owner.QueryRow(ctx, `SELECT zasp_sa_multistep_prior.test_prompt($1)`, category).Scan(&prompt); err != nil {
			t.Fatal(err)
		}
		encodedPrompt, _ := json.Marshal(prompt)
		requestBody := `{"schema_version":"red-team-target-v1","run_id":"` + child + `","target_id":"` + prepared["target_id"].(string) + `","target_kind":"` + prepared["target_kind"].(string) + `","category":"` + category + `","input":` + string(encodedPrompt) + `}`
		digest := sha256.Sum256([]byte(requestBody))
		jq := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": child, "effect_key": intent["effect_key"], "operation": "start", "payload": map[string]any{"category": category, "request_digest": hex.EncodeToString(digest[:])}, "checksum": migrations.ProductionTemporalExecutor().Checksum(), "fingerprint": migrations.TemporalExecutorFingerprint()}
		journal := func(conn *pgx.Conn, op string, payload any) (map[string]any, error) {
			jq["operation"], jq["payload"] = op, payload
			body, _ := json.Marshal(jq)
			var raw []byte
			err := conn.QueryRow(ctx, `SELECT zasp_temporal68.invocation($1::jsonb)`, body).Scan(&raw)
			var result map[string]any
			if err == nil {
				err = json.Unmarshal(raw, &result)
			}
			return result, err
		}
		startPayload := jq["payload"]
		if network == "" {
			var original []byte
			if err := owner.QueryRow(ctx, `SELECT to_jsonb(f) FROM zasp_temporal68.effects f WHERE effect_key=$1`, intent["effect_key"]).Scan(&original); err != nil {
				t.Fatal(err)
			}
			for _, mutation := range []struct{ name, sql string }{
				{"plan_hash", `UPDATE zasp_temporal68.effects SET plan_hash=decode(repeat('a',64),'hex') WHERE effect_key=$1`},
				{"snapshot_plan", `UPDATE zasp_temporal68.effects SET snapshot=jsonb_set(snapshot,'{plan_hash}',to_jsonb(repeat('a',64))),snapshot_digest=digest(convert_to(jsonb_set(snapshot,'{plan_hash}',to_jsonb(repeat('a',64)))::text,'UTF8'),'sha256') WHERE effect_key=$1`},
				{"snapshot_input", `UPDATE zasp_temporal68.effects SET snapshot=jsonb_set(snapshot,'{input_digest}',to_jsonb(repeat('a',64))),snapshot_digest=digest(convert_to(jsonb_set(snapshot,'{input_digest}',to_jsonb(repeat('a',64)))::text,'UTF8'),'sha256') WHERE effect_key=$1`},
				{"public_lease", `UPDATE zasp_security_agent_effects SET lease_owner='foreign-worker',lease_token=decode(repeat('a',64),'hex'),lease_expires_at=clock_timestamp()+interval '1 minute' WHERE (run_id,step_id)=(SELECT run_id,step_id FROM zasp_temporal68.effects WHERE effect_key=$1)`},
			} {
				if _, err := owner.Exec(ctx, mutation.sql, intent["effect_key"]); err != nil {
					if p, ok := err.(*pgconn.PgError); ok && mutation.name == "public_lease" && p.Code == "42501" {
						continue // The retained write fence prevented the corruption.
					}
					t.Fatal(mutation.name, err)
				}
				_, rejected := journal(adapter, "resolve", map[string]any{"category": category, "target_id": prepared["target_id"], "target_kind": prepared["target_kind"]})
				if _, err := owner.Exec(ctx, `UPDATE zasp_temporal68.effects f SET plan_hash=x.plan_hash,snapshot=x.snapshot,snapshot_digest=x.snapshot_digest FROM jsonb_populate_record(NULL::zasp_temporal68.effects,$2::jsonb) x WHERE f.effect_key=$1`, intent["effect_key"], original); err != nil {
					t.Fatal(err)
				}
				if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_effects SET lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL WHERE (run_id,step_id)=(SELECT run_id,step_id FROM zasp_temporal68.effects WHERE effect_key=$1)`, intent["effect_key"]); err != nil {
					t.Fatal(err)
				}
				if rejected == nil {
					t.Error("journal resolved a changed intent", mutation.name)
				}
			}
		}
		if _, err := journal(executor, "start", startPayload); err == nil {
			t.Fatal("executor used adapter journal")
		}
		if _, err := journal(adapter, "start", map[string]any{"category": category, "request_digest": strings.Repeat("a", 64)}); err == nil {
			t.Fatal("uncurated payload started")
		}
		jq["effect_key"] = strings.Repeat("b", 64)
		if _, err := journal(adapter, "start", startPayload); err == nil {
			t.Fatal("foreign effect started")
		}
		jq["effect_key"] = intent["effect_key"]
		if network != "" && network != "settle" && network != "stop" && network != "repository" {
			command := exec.CommandContext(ctx, "go", "test", "./redteamadapter", "-run", "^TestTemporalOwnedHTTPS$", "-count=1", "-v")
			command.Dir = ".."
			command.Env = append(os.Environ(), "ZASP_TEMPORAL_JOURNAL_OWNER_DSN="+owner.Config().ConnString(), "ZASP_TEMPORAL_JOURNAL_MODE="+network, "ZASP_ORDERED_ORG="+o, "ZASP_ORDERED_WORKSPACE="+w, "ZASP_ORDERED_ENVIRONMENT="+e, "ZASP_ORDERED_TEST_RUN="+child, "ZASP_TEMPORAL_EFFECT_KEY="+intent["effect_key"].(string), "ZASP_TEMPORAL_CATEGORY="+category, "ZASP_TEMPORAL_TARGET="+prepared["target_id"].(string), "ZASP_TEMPORAL_KIND="+prepared["target_kind"].(string))
			output, err := command.CombinedOutput()
			t.Log(string(output))
			if err != nil {
				t.Fatal("real68 journal HTTPS", err)
			}
			return
		}
		started, err := journal(adapter, "start", startPayload)
		if err != nil || started["state"] != "started" || started["effect_key"] != intent["effect_key"] {
			t.Fatal("journal first durable start", started, err)
		}
		if _, err := journal(adapter, "start", startPayload); err == nil {
			t.Fatal("unresolved invocation resent")
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE principal_id=$1`, actor); err != nil {
			t.Fatal(err)
		}
		var stopEvidence map[string]any
		if network == "stop" {
			stopEvidence, err = invoke("test_stop", "stop", map[string]any{})
			if err != nil || stopEvidence["run_state"] != "needs_human" {
				t.Fatal("linked unknown stop", stopEvidence, err)
			}
		}
		completion := map[string]any{"category": category, "request_digest": hex.EncodeToString(digest[:]), "http_status": 200, "response_digest": strings.Repeat("c", 64), "protected": true, "credential_version_digest": strings.Repeat("d", 64)}
		completed, err := journal(adapter, "complete", completion)
		if err != nil || completed["state"] != "completed" {
			t.Fatal("late scoped observation lost", completed, err)
		}
		if repeat, err := journal(adapter, "complete", completion); err != nil || !jsonEqualMaps(completed, repeat) {
			t.Fatal("observation replay changed", repeat, err)
		}
		completion["response_digest"] = strings.Repeat("e", 64)
		if _, err := journal(adapter, "complete", completion); err == nil {
			t.Fatal("observation conflict accepted")
		}
		if network == "stop" {
			if replay, err := invoke("test_stop", "stop", map[string]any{}); err != nil || !jsonEqualMaps(stopEvidence, replay) {
				t.Fatal("late observation rewrote stopped evidence", replay, err)
			}
			if _, err := journal(adapter, "start", startPayload); err == nil {
				t.Fatal("stopped effect reopened invocation")
			}
			verifyTemporalLinkedCleanup(t, ctx, owner, api, o, w, e, run, "needs_human", key, policyCall)
			return
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=true WHERE principal_id=$1`, actor); err != nil {
			t.Fatal(err)
		}
		if replay, err := journal(adapter, "start", startPayload); err != nil || !jsonEqualMaps(completed, replay) {
			t.Fatal("completed journal replay", replay, err)
		}
		if network == "settle" || network == "repository" {
			for _, item := range prepared["categories"].([]any)[1:] {
				cat := item.(string)
				if err := owner.QueryRow(ctx, `SELECT zasp_sa_multistep_prior.test_prompt($1)`, cat).Scan(&prompt); err != nil {
					t.Fatal(err)
				}
				encoded, _ := json.Marshal(prompt)
				body := `{"schema_version":"red-team-target-v1","run_id":"` + child + `","target_id":"` + prepared["target_id"].(string) + `","target_kind":"` + prepared["target_kind"].(string) + `","category":"` + cat + `","input":` + string(encoded) + `}`
				hash := sha256.Sum256([]byte(body))
				p := map[string]any{"category": cat, "request_digest": hex.EncodeToString(hash[:])}
				if _, err := journal(adapter, "start", p); err != nil {
					t.Fatal(err)
				}
				p["http_status"], p["response_digest"], p["protected"], p["credential_version_digest"] = 200, strings.Repeat("c", 64), true, strings.Repeat("d", 64)
				if _, err := journal(adapter, "complete", p); err != nil {
					t.Fatal(err)
				}
			}
			output := orderedTestOutputArtifactFromJournal(t, ctx, owner, store, o, w, e, run, step, child, manifest, true)
			outputBody, err := orderedTestReadArtifact(ctx, store, scope, child, output, 1048576)
			if err != nil {
				t.Fatal(err)
			}
			settlePayload := map[string]any{"output_manifest": output, "output_body": base64.StdEncoding.EncodeToString(outputBody)}
			settled, err := invoke("test_settle", "complete", settlePayload)
			if err != nil || settled["run_state"] != "contained" {
				t.Fatal("lease-free linked settlement", settled, err)
			}
			if replay, err := invoke("test_settle", "complete", settlePayload); err != nil || !jsonEqualMaps(settled, replay) {
				t.Fatal("settlement replay", replay, err)
			}
			var state string
			var attempts int
			if err := owner.QueryRow(ctx, `SELECT state,(SELECT count(*) FROM zasp_red_team_attempts WHERE run_id=$1) FROM zasp_red_team_runs WHERE run_id=$1 AND worker_id IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL`, child).Scan(&state, &attempts); err != nil || state != "complete" || attempts != 1 {
				t.Fatal("actual child terminal evidence", state, attempts, err)
			}
			verifyTemporalLinkedCleanup(t, ctx, owner, api, o, w, e, run, "remediated", key, policyCall)
			if network == "repository" {
				var version int64
				if err := owner.QueryRow(ctx, `SELECT definition_version FROM zasp_security_agent_runs WHERE run_id=$1`, run).Scan(&version); err != nil {
					t.Fatal(err)
				}
				q, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "definition_version": version})
				if err := executor.QueryRow(ctx, `SELECT zasp_temporal68.status($1::jsonb)`, q).Scan(&raw); err != nil {
					t.Error("general68 terminal status missing", err)
				}
			}
		}
	})
}

func verifyTemporalLinkedCleanup(t *testing.T, ctx context.Context, owner, api *pgx.Conn, o, w, e, run, wantState string, key ed25519.PrivateKey, call func(*pgx.Conn, string, string, any) (map[string]any, error)) {
	t.Helper()
	config := owner.Config().Copy()
	config.User = "temporal_compensation_test_login"
	comp, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer comp.Close(ctx)
	if prepared, err := call(comp, "cleanup", "prepare", map[string]any{}); err != nil || prepared["state"] != "pending" {
		t.Fatal("linked cleanup prepare", prepared, err)
	}
	repo, id := public62GoRepository(t, api, o, w, e, orderedProgressionApprover)
	if pending, err := repo.Run(ctx, id, run); err != nil || pending.State != "needs_human" || len(pending.Steps) != 2 || pending.Steps[0].Cleanup.State != "retryable" {
		t.Fatal("linked pending public read", pending, err)
	}
	claim, err := call(comp, "cleanup", "read", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	target := claim["targets"].([]any)[0].(map[string]any)
	now := time.Now().UTC().Truncate(time.Second)
	v := postgresTemporaryPolicyEnvelope(t, TemporaryPolicyEffectClaim{OrganizationID: o, WorkspaceID: w, EnvironmentID: e, Phase: "cleanup"}, TemporaryPolicyTarget{DeviceID: target["device_id"].(string), CredentialID: target["credential_id"].(string), Sequence: int64(target["sequence"].(float64)), PolicyVersion: int64(target["policy_version"].(float64))}, "ordered-key-01", key, now, now.Add(5*time.Minute), []policy.CompiledPolicy{})
	source := map[string]any{"device_id": target["device_id"], "credential_id": target["credential_id"], "sequence": target["sequence"], "policy_version": target["policy_version"], "key_id": v.KeyID, "issued_at": v.IssuedAt, "expires_at": v.ExpiresAt, "failure_mode": v.FailureMode, "payload_digest": v.PayloadDigest, "policies": v.Policies, "signature": base64.StdEncoding.EncodeToString(v.Signature), "envelope_digest": v.EnvelopeDigest}
	if _, err := call(comp, "cleanup", "source", source); err != nil {
		t.Fatal(err)
	}
	p := map[string]any{"device_id": target["device_id"], "phase": "cleanup"}
	delivery, err := call(comp, "delivery", "prepare", p)
	if err != nil {
		t.Fatal(err)
	}
	composition := delivery["composition"].(map[string]any)
	encoded, _ := json.Marshal(composition["policies"])
	var policies []policy.CompiledPolicy
	if json.Unmarshal(encoded, &policies) != nil {
		t.Fatal("cleanup policies")
	}
	expires, err := time.Parse(time.RFC3339Nano, composition["expires_at"].(string))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := policy.SignGatewayPolicyEnvelope(policy.GatewayPolicySigningInput{KeyID: "ordered-key-01", Binding: policy.GatewayPolicyBinding{OrganizationID: o, WorkspaceID: w, EnvironmentID: e, DeviceID: target["device_id"].(string)}, Sequence: uint64(delivery["sequence"].(float64)), PolicyVersion: uint64(delivery["sequence"].(float64)), Now: now, IssuedAt: now, ExpiresAt: expires, FailureMode: "closed", Policies: policies}, key)
	if err != nil {
		t.Fatal(err)
	}
	p["envelope"], p["digest"] = envelope, orderedEnvelopeDigest(envelope)
	if _, err := call(comp, "delivery", "store", p); err != nil {
		t.Fatal(err)
	}
	delete(p, "envelope")
	if _, err := call(comp, "delivery", "ack", p); err == nil {
		t.Fatal("linked cleanup ack without readback")
	}
	if _, err := call(comp, "delivery", "read", p); err != nil {
		t.Fatal(err)
	}
	if _, err := call(comp, "delivery", "ack", p); err != nil {
		t.Fatal(err)
	}
	cleaned, err := call(comp, "cleanup", "complete", map[string]any{})
	if err != nil || cleaned["state"] != "cleaned" {
		t.Fatal("linked cleanup complete", cleaned, err)
	}
	if replay, err := call(comp, "cleanup", "complete", map[string]any{}); err != nil || !jsonEqualMaps(cleaned, replay) {
		t.Fatal("linked cleanup replay", replay, err)
	}
	detail, err := repo.Run(ctx, id, run)
	if err != nil || detail.State != wantState || len(detail.Steps) != 2 || detail.Steps[0].Cleanup.State != "cleaned" {
		t.Fatal("linked terminal public read", detail, err)
	}
	var saved []byte
	if err := owner.QueryRow(ctx, `SELECT plan_hash FROM zasp_temporal68.effects WHERE run_id=$1 AND action_key='run_test'`, run).Scan(&saved); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_temporal68.effects SET plan_hash=decode(repeat('f',64),'hex') WHERE run_id=$1 AND action_key='run_test'`, run); err != nil {
		t.Fatal(err)
	}
	_, rejected := repo.Run(ctx, id, run)
	if _, err := owner.Exec(ctx, `UPDATE zasp_temporal68.effects SET plan_hash=$2 WHERE run_id=$1 AND action_key='run_test'`, run, saved); err != nil {
		t.Fatal(err)
	}
	if rejected == nil {
		t.Error("terminal public read accepted changed linked intent")
	}
}

type temporalExecutorPolicyAdmissionHook func(context.Context, *pgx.Conn, *pgx.Conn, *pgx.Conn, string, string, string, string, string, policy.GatewayPolicyKeys, ed25519.PrivateKey) bool

func runTemporalExecutorPolicyFixture(t *testing.T, complete bool, inspect func(context.Context, *pgx.Conn, *pgx.Conn, string, string, string, string, string, policy.GatewayPolicyKeys, ed25519.PrivateKey, func(*pgx.Conn, string, string, any) (map[string]any, error))) {
	runTemporalExecutorPolicyFixtureWithHook(t, complete, inspect, nil)
}

// The optional hook receives a genuinely admitted plan before any legacy
// approval or unsigned effect call. Current-profile tests own the complete
// checked approval/effect path; existing retained callers are unchanged.
func runTemporalExecutorPolicyFixtureWithHook(t *testing.T, complete bool, inspect func(context.Context, *pgx.Conn, *pgx.Conn, string, string, string, string, string, policy.GatewayPolicyKeys, ed25519.PrivateKey, func(*pgx.Conn, string, string, any) (map[string]any, error)), hook temporalExecutorPolicyAdmissionHook) {
	runTemporalExecutorAdmittedFixture(t, func(ctx context.Context, owner, executor, api *pgx.Conn, o, w, e, run, actor string) {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey)})
		seedOrderedApplicationGateway(t, ctx, owner, o, w, e)
		if hook != nil && hook(ctx, owner, executor, api, o, w, e, run, actor, keys, key) {
			return
		}
		public62TypedDecision(t, ctx, api, o, w, e, run, 3)
		var step string
		if err := owner.QueryRow(ctx, `SELECT plan->'steps'->0->>'step_id' FROM zasp_security_agent_plans WHERE run_id=$1`, run).Scan(&step); err != nil {
			t.Fatal(err)
		}
		q := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "step_id": step, "generation": 1, "operation": "reserve", "payload": map[string]any{}}
		call := func(conn *pgx.Conn, entry, op string, payload any) (map[string]any, error) {
			q["operation"], q["payload"] = op, payload
			b, _ := json.Marshal(q)
			var raw []byte
			var err error
			if (entry == "application" || entry == "cleanup") && (op == "read" || op == "source" || op == "renew") || entry == "delivery" {
				database, dbErr := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: conn})
				if dbErr != nil {
					return nil, dbErr
				}
				repository, repoErr := NewSecurityAgentTemporalExecutorRepository(database)
				if repoErr != nil {
					return nil, repoErr
				}
				if entry == "delivery" {
					raw, err = repository.TemporalDelivery(ctx, b, keys)
				} else if entry == "cleanup" {
					raw, err = repository.TemporalCleanupSource(ctx, b, keys)
				} else {
					raw, err = repository.TemporalApplication(ctx, b, keys)
				}
			} else {
				err = conn.QueryRow(ctx, `SELECT zasp_temporal68.`+entry+`($1::jsonb)`, b).Scan(&raw)
			}
			var value map[string]any
			if err == nil {
				err = json.Unmarshal(raw, &value)
			}
			return value, err
		}
		if _, err := call(executor, "effect", "reserve", map[string]any{}); err != nil {
			t.Fatal(err)
		}
		if _, err := call(executor, "effect", "start", map[string]any{}); err != nil {
			t.Fatal(err)
		}
		var present bool
		if err := owner.QueryRow(ctx, `SELECT to_regprocedure('zasp_temporal68.application(jsonb)') IS NOT NULL`).Scan(&present); err != nil || !present {
			t.Fatal("lease-free signed policy storage missing", err)
		}
		claim, err := call(executor, "application", "read", map[string]any{})
		if err != nil {
			t.Fatal(err)
		}
		source := orderedApplicationStoreRequest(t, o, w, e, run, step, claim, key)["envelope"]
		stored, err := call(executor, "application", "source", source)
		if err != nil {
			t.Fatal("signed source store", err)
		}
		if repeat, err := call(executor, "application", "source", source); err != nil || !jsonEqualMaps(stored, repeat) {
			t.Fatal("source replay", repeat, err)
		}
		if _, err := call(executor, "application", "complete", map[string]any{}); err == nil {
			t.Fatal("source accepted as verified delivery")
		}
		var leases, receipts int
		if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_security_agent_effects WHERE run_id=$1 AND (lease_token IS NOT NULL OR lease_owner IS NOT NULL OR lease_expires_at IS NOT NULL)),(SELECT count(*) FROM zasp_sa_multistep_receipts WHERE run_id=$1)`, run).Scan(&leases, &receipts); err != nil || leases != 0 || receipts != 0 {
			t.Fatal("source forged receipt or lease", leases, receipts, err)
		}
		if err := owner.QueryRow(ctx, `SELECT to_regprocedure('zasp_temporal68.delivery(jsonb)') IS NOT NULL`).Scan(&present); err != nil || !present {
			t.Fatal("lease-free signed delivery/readback missing", err)
		}
		delivery := map[string]any{"device_id": orderedApplicationDevice, "phase": "apply"}
		prepared, err := call(executor, "delivery", "prepare", delivery)
		if err != nil {
			t.Fatal("prepare composed delivery", err)
		}
		if _, err := call(executor, "delivery", "ack", delivery); err == nil {
			t.Fatal("acknowledged unsent bundle")
		}
		composition := prepared["composition"].(map[string]any)
		compiledRaw, _ := json.Marshal(composition["policies"])
		var compiled []policy.CompiledPolicy
		if err := json.Unmarshal(compiledRaw, &compiled); err != nil {
			t.Fatal(err)
		}
		expires, err := time.Parse(time.RFC3339Nano, composition["expires_at"].(string))
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC().Truncate(time.Second)
		envelope, err := policy.SignGatewayPolicyEnvelope(policy.GatewayPolicySigningInput{KeyID: "ordered-key-01", Binding: policy.GatewayPolicyBinding{OrganizationID: o, WorkspaceID: w, EnvironmentID: e, DeviceID: orderedApplicationDevice}, Sequence: uint64(prepared["sequence"].(float64)), PolicyVersion: uint64(prepared["sequence"].(float64)), Now: now, IssuedAt: now, ExpiresAt: expires, FailureMode: "closed", Policies: compiled}, key)
		if err != nil {
			t.Fatal(err)
		}
		delivery["envelope"], delivery["digest"] = envelope, orderedEnvelopeDigest(envelope)
		published, err := call(executor, "delivery", "store", delivery)
		if err != nil {
			t.Fatal("publish signed bundle", err)
		}
		if repeat, err := call(executor, "delivery", "store", delivery); err != nil || !jsonEqualMaps(published, repeat) {
			t.Fatal("publish replay", repeat, err)
		}
		delete(delivery, "envelope")
		if _, err := call(executor, "delivery", "ack", delivery); err == nil {
			t.Fatal("acknowledged without readback")
		}
		readback, err := call(executor, "delivery", "read", delivery)
		if err != nil {
			t.Fatal("readback", err)
		}
		readRaw, _ := json.Marshal(readback["envelope"])
		var signed policy.GatewayPolicyEnvelope
		if err := json.Unmarshal(readRaw, &signed); err != nil || !orderedVerifiedEnvelope(signed, keys, o, w, e, orderedApplicationDevice, int64(envelope.Sequence)) || orderedEnvelopeDigest(signed) != delivery["digest"] {
			t.Fatal("signed readback changed", err)
		}
		ack, err := call(executor, "delivery", "ack", delivery)
		if err != nil || ack["state"] != "acknowledged" {
			t.Fatal("delivery acknowledgement", ack, err)
		}
		if repeat, err := call(executor, "delivery", "ack", delivery); err != nil || !jsonEqualMaps(ack, repeat) {
			t.Fatal("ack replay", repeat, err)
		}
		if complete {
			completed, err := call(executor, "application", "complete", map[string]any{})
			if err != nil || completed["receipt_kind"] != "temporary_policy_applied.v1" {
				t.Fatal("verified application receipt", completed, err)
			}
			if repeat, err := call(executor, "application", "complete", map[string]any{}); err != nil || !jsonEqualMaps(completed, repeat) {
				t.Fatal("application receipt replay", repeat, err)
			}
		}
		source.(map[string]any)["credential_id"] = actor
		if _, err := call(executor, "application", "source", source); err == nil {
			t.Fatal("foreign credential accepted")
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE principal_id=$1`, actor); err != nil {
			t.Fatal(err)
		}
		if _, err := call(executor, "application", "source", source); err == nil {
			t.Fatal("deactivated requester wrote source")
		}
		if inspect != nil {
			inspect(ctx, owner, api, o, w, e, run, step, keys, key, call)
		}
	})
}

func TestTemporalExecutorCompensationPostgres(t *testing.T) {
	runTemporalCompensationCases(t, "")
}

func TestTemporalExecutorCleanupExpiryRecoveryPostgres(t *testing.T) {
	for _, pause := range []string{"source", "read", "ack"} {
		t.Run(pause, func(t *testing.T) { runTemporalCompensationCases(t, pause) })
	}
}

func TestTemporalExecutorCleanupReplacementRecoveryPostgres(t *testing.T) {
	for _, pause := range []string{"replacement_read", "replacement_ack", "changed_ack", "historical_source"} {
		t.Run(pause, func(t *testing.T) { runTemporalCompensationCases(t, pause) })
	}
}

func TestTemporalExecutorCleanupRotatedKeyRecoveryPostgres(t *testing.T) {
	runTemporalCompensationCases(t, "rotated_source")
}

func runTemporalCompensationCases(t *testing.T, pause string) {
	for _, complete := range []bool{true, false} {
		if !complete && strings.Contains(pause, "_") {
			continue
		}
		t.Run(map[bool]string{true: "applied", false: "partial"}[complete], func(t *testing.T) {
			runTemporalExecutorPolicyFixture(t, complete, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, run, step string, keys policy.GatewayPolicyKeys, key ed25519.PrivateKey, call func(*pgx.Conn, string, string, any) (map[string]any, error)) {
				var present bool
				if err := owner.QueryRow(ctx, `SELECT to_regprocedure('zasp_temporal68.cleanup(jsonb)') IS NOT NULL`).Scan(&present); err != nil || !present {
					t.Fatal("lease-free compensation repository missing", err)
				}
				config := owner.Config().Copy()
				config.User = "temporal_compensation_test_login"
				comp, err := pgx.ConnectConfig(ctx, config)
				if err != nil {
					t.Fatal(err)
				}
				defer comp.Close(ctx)
				wrongScope, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": orderedApplicationDevice, "run_id": run, "step_id": step, "generation": 1, "operation": "prepare", "payload": map[string]any{}})
				var refused []byte
				if err := comp.QueryRow(ctx, `SELECT zasp_temporal68.cleanup($1::jsonb)`, wrongScope).Scan(&refused); err == nil {
					t.Fatal("cross-scope cleanup accepted")
				}
				prepared, err := call(comp, "cleanup", "prepare", map[string]any{})
				if err != nil || prepared["state"] != "pending" {
					t.Fatal("cleanup prepare", prepared, err)
				}
				publicRead := func(state string) {
					repo, id := public62GoRepository(t, api, o, w, e, orderedProgressionApprover)
					detail, err := repo.Run(ctx, id, run)
					if err != nil || len(detail.Steps) != 2 || detail.Steps[0].Cleanup.State != state || detail.Steps[0].Cleanup.Partial == complete {
						t.Fatal("public cleanup", detail, err)
					}
				}
				publicRead("retryable")
				if _, err := call(comp, "effect", "start", map[string]any{}); err == nil {
					t.Fatal("compensation acquired new send authority")
				}
				if _, err := call(comp, "cleanup", "complete", map[string]any{}); err == nil {
					t.Fatal("cleanup completed without readback")
				}
				if unknown, err := call(comp, "cleanup", "unknown", map[string]any{}); err != nil || unknown["state"] != "unknown" {
					t.Fatal("cleanup unknown", unknown, err)
				}
				publicRead("retryable")
				claim, err := call(comp, "cleanup", "read", map[string]any{})
				if err != nil {
					t.Fatal("cleanup scoped read", err)
				}
				target := claim["targets"].([]any)[0].(map[string]any)
				now := time.Now().UTC().Truncate(time.Second)
				if pause != "" {
					now = now.Add(-4*time.Minute - 52*time.Second)
				}
				v := postgresTemporaryPolicyEnvelope(t, TemporaryPolicyEffectClaim{OrganizationID: o, WorkspaceID: w, EnvironmentID: e, Phase: "cleanup"}, TemporaryPolicyTarget{DeviceID: target["device_id"].(string), CredentialID: target["credential_id"].(string), Sequence: int64(target["sequence"].(float64)), PolicyVersion: int64(target["policy_version"].(float64))}, "ordered-key-01", key, now, now.Add(5*time.Minute), []policy.CompiledPolicy{})
				source := map[string]any{"device_id": target["device_id"], "credential_id": target["credential_id"], "sequence": target["sequence"], "policy_version": target["policy_version"], "key_id": v.KeyID, "issued_at": v.IssuedAt, "expires_at": v.ExpiresAt, "failure_mode": v.FailureMode, "payload_digest": v.PayloadDigest, "policies": v.Policies, "signature": base64.StdEncoding.EncodeToString(v.Signature), "envelope_digest": v.EnvelopeDigest}
				if _, err := call(comp, "cleanup", "source", source); err != nil {
					t.Fatal("cleanup signed source", err)
				}
				if pause == "historical_source" {
					// Seed genuine signed historical bytes in this owned fixture to
					// exercise the 24-hour cap without waiting a day. This is not a
					// current signing/storage success for an expired envelope.
					now = now.Add(-25 * time.Hour)
					historical := postgresTemporaryPolicyEnvelope(t, TemporaryPolicyEffectClaim{OrganizationID: o, WorkspaceID: w, EnvironmentID: e, Phase: "cleanup"}, TemporaryPolicyTarget{DeviceID: target["device_id"].(string), CredentialID: target["credential_id"].(string), Sequence: int64(target["sequence"].(float64)), PolicyVersion: int64(target["policy_version"].(float64))}, "ordered-key-01", key, now, now.Add(5*time.Minute), []policy.CompiledPolicy{})
					source["issued_at"], source["expires_at"], source["payload_digest"], source["signature"], source["envelope_digest"] = historical.IssuedAt, historical.ExpiresAt, historical.PayloadDigest, base64.StdEncoding.EncodeToString(historical.Signature), historical.EnvelopeDigest
					if _, err := call(comp, "cleanup", "source", source); err == nil {
						t.Fatal("historical expired source accepted as fresh")
					}
					if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_temporary_policy_targets SET issued_at=$2,expires_at=$3,stored_at=$2,payload_digest=decode(substr($4,8),'hex'),signature=$5,envelope_digest=decode(substr($6,8),'hex') WHERE run_id=$1 AND phase='cleanup'`, run, historical.IssuedAt, historical.ExpiresAt, historical.PayloadDigest, historical.Signature, historical.EnvelopeDigest); err != nil {
						t.Fatal(err)
					}
				}
				payload := map[string]any{"device_id": orderedApplicationDevice, "phase": "cleanup"}
				signingKeyID := "ordered-key-01"
				var rotationPriorBundles []byte
				deadline := now.Add(5*time.Minute + 20*time.Millisecond)
				var recoveredEnvelope *policy.GatewayPolicyEnvelope
				restart := func(stage string) {
					if pause != stage && pause != "replacement_"+stage && pause != "changed_"+stage && pause != "historical_"+stage && pause != "rotated_"+stage {
						return
					}
					// Real signed expiry, without mutating persisted proof or the DB clock.
					if delay := time.Until(deadline); delay > 0 {
						time.Sleep(delay)
					}
					comp.Close(ctx)
					comp, err = pgx.ConnectConfig(ctx, config)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { comp.Close(context.Background()) })
					if pause == "rotated_source" {
						// After reconnect, neither signing nor current verification uses A.
						_, key, err = ed25519.GenerateKey(rand.Reader)
						if err != nil {
							t.Fatal(err)
						}
						signingKeyID = "ordered-key-02"
						now = time.Now().UTC().Truncate(time.Second)
						keys, err = policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{signingKeyID: key.Public().(ed25519.PublicKey)})
						if err != nil {
							t.Fatal(err)
						}
						priorCall := call
						call = func(conn *pgx.Conn, entry, op string, payload any) (map[string]any, error) {
							if entry != "delivery" && !(entry == "cleanup" && (op == "read" || op == "source" || op == "renew")) {
								return priorCall(conn, entry, op, payload)
							}
							database, dbErr := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: conn})
							if dbErr != nil {
								return nil, dbErr
							}
							repository, repoErr := NewSecurityAgentTemporalExecutorRepository(database)
							if repoErr != nil {
								return nil, repoErr
							}
							request, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "step_id": step, "generation": 1, "operation": op, "payload": payload})
							var raw json.RawMessage
							var callErr error
							if entry == "delivery" {
								raw, callErr = repository.TemporalDelivery(ctx, request, keys)
							} else {
								raw, callErr = repository.TemporalCleanupSource(ctx, request, keys)
							}
							var value map[string]any
							if callErr == nil {
								callErr = json.Unmarshal(raw, &value)
							}
							return value, callErr
						}
						if err := owner.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(b) ORDER BY sequence) FROM zasp_runtime_gateway_policy_bundles b WHERE device_id=$1`, orderedApplicationDevice).Scan(&rotationPriorBundles); err != nil {
							t.Fatal(err)
						}
					}
					publicRead("retryable")
					if pause == "ack" {
						return
					}
					if pause == "changed_ack" {
						body := `{"id":"pid_79000001-0000-4000-8000-000000000001","name":"Unrelated persistent policy","scope":"environment","trigger":"tool","conditions":[{"field":"action","operator":"equals","value":"preserve-me"}],"action":"monitor","rollout":"enforced","failure_mode":"closed"}`
						if _, err := owner.Exec(ctx, `INSERT INTO zasp_workflow_records(organization_id,workspace_id,environment_id,id,kind,version,body) VALUES($1,$2,$3,'pid_79000001-0000-4000-8000-000000000001','policy',1,$4::jsonb); SELECT zasp_policy_deployment_enqueue_device($1,$2,$3,$5)`, pgx.QueryExecModeSimpleProtocol, o, w, e, body, orderedApplicationDevice); err != nil {
							t.Fatal(err)
						}
					}
					if _, err := call(comp, "cleanup", "complete", map[string]any{}); err == nil {
						t.Fatal("expired unfinished cleanup became complete")
					}
					if _, err := call(comp, "delivery", "prepare", map[string]any{"device_id": orderedApplicationDevice, "phase": "cleanup"}); err == nil {
						t.Fatal("expired marker authorized delivery")
					}
					if _, err := call(comp, "cleanup", "source", source); err == nil {
						t.Fatal("expired source accepted")
					}
					var before []byte
					if err := owner.QueryRow(ctx, `SELECT to_jsonb(t) FROM zasp_security_agent_temporary_policy_targets t WHERE run_id=$1 AND phase='cleanup'`, run).Scan(&before); err != nil {
						t.Fatal(err)
					}
					fresh := time.Now().UTC().Truncate(time.Second)
					renewed := postgresTemporaryPolicyEnvelope(t, TemporaryPolicyEffectClaim{OrganizationID: o, WorkspaceID: w, EnvironmentID: e, Phase: "cleanup"}, TemporaryPolicyTarget{DeviceID: target["device_id"].(string), CredentialID: target["credential_id"].(string), Sequence: int64(target["sequence"].(float64)), PolicyVersion: int64(target["policy_version"].(float64))}, signingKeyID, key, fresh, fresh.Add(5*time.Minute), []policy.CompiledPolicy{})
					renewal := map[string]any{"device_id": target["device_id"], "credential_id": target["credential_id"], "sequence": target["sequence"], "policy_version": target["policy_version"], "key_id": renewed.KeyID, "issued_at": renewed.IssuedAt, "expires_at": renewed.ExpiresAt, "failure_mode": renewed.FailureMode, "payload_digest": renewed.PayloadDigest, "policies": renewed.Policies, "signature": base64.StdEncoding.EncodeToString(renewed.Signature), "envelope_digest": renewed.EnvelopeDigest}
					renewalRequest := map[string]any{"source_digest": source["envelope_digest"], "envelope": renewal}
					if pause == "rotated_source" {
						for _, bad := range []string{"unknown_key", "invalid_signature"} {
							invalid := make(map[string]any, len(renewal))
							for name, value := range renewal {
								invalid[name] = value
							}
							if bad == "unknown_key" {
								untrusted := postgresTemporaryPolicyEnvelope(t, TemporaryPolicyEffectClaim{OrganizationID: o, WorkspaceID: w, EnvironmentID: e, Phase: "cleanup"}, TemporaryPolicyTarget{DeviceID: target["device_id"].(string), CredentialID: target["credential_id"].(string), Sequence: int64(target["sequence"].(float64)), PolicyVersion: int64(target["policy_version"].(float64))}, "untrusted-key-01", key, fresh, fresh.Add(5*time.Minute), []policy.CompiledPolicy{})
								invalid["key_id"], invalid["signature"], invalid["payload_digest"], invalid["envelope_digest"] = untrusted.KeyID, base64.StdEncoding.EncodeToString(untrusted.Signature), untrusted.PayloadDigest, untrusted.EnvelopeDigest
							} else {
								invalid["signature"] = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
							}
							if _, err := call(comp, "cleanup", "renew", map[string]any{"source_digest": source["envelope_digest"], "envelope": invalid}); !errors.Is(err, ErrRepositoryOperation) {
								t.Fatal("rotated-key verifier accepted invalid authority", bad, err)
							}
						}
					}
					badRequest := map[string]any{"source_digest": "sha256:" + strings.Repeat("f", 64), "envelope": renewal}
					if _, err := call(comp, "cleanup", "renew", badRequest); err == nil {
						t.Fatal("renewal accepted changed original source")
					}
					foreign, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": orderedApplicationDevice, "run_id": run, "step_id": step, "generation": 1, "operation": "renew", "payload": renewalRequest})
					if err := comp.QueryRow(ctx, `SELECT zasp_temporal68.cleanup($1::jsonb)`, foreign).Scan(&refused); err == nil {
						t.Fatal("cross-scope renewal accepted")
					}
					got, err := call(comp, "cleanup", "renew", renewalRequest)
					if err != nil {
						raw, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "step_id": step, "generation": 1, "operation": "renew", "payload": renewalRequest})
						diagnostic := comp.QueryRow(ctx, `SELECT zasp_temporal68.cleanup($1::jsonb)`, raw).Scan(&refused)
						t.Fatal("fresh scoped cleanup renewal", err, diagnostic)
					}
					if replay, err := call(comp, "cleanup", "renew", renewalRequest); err != nil || !jsonEqualMaps(got, replay) {
						t.Fatal("cleanup renewal replay", replay, err)
					}
					var after []byte
					var renewals int
					if err := owner.QueryRow(ctx, `SELECT to_jsonb(t),(SELECT count(*) FROM zasp_temporal68.cleanup_renewals WHERE run_id=$1) FROM zasp_security_agent_temporary_policy_targets t WHERE run_id=$1 AND phase='cleanup'`, run).Scan(&after, &renewals); err != nil || string(before) != string(after) || renewals != 1 {
						t.Fatal("renewal rewrote source or duplicated proof", renewals, err)
					}
					if _, err := owner.Exec(ctx, `UPDATE zasp_temporal68.cleanup_renewals SET body=body WHERE run_id=$1`, run); err == nil {
						t.Fatal("renewal evidence was mutable")
					}
					if pause == "rotated_source" {
						var oldKey, newKey, originalDigest, effectKey string
						if err := owner.QueryRow(ctx, `SELECT body->'source'->>'key_id',body->'envelope'->>'key_id','sha256:'||encode(decode(substr(body->'source'->>'envelope_digest',3),'hex'),'hex'),body->>'effect_key' FROM zasp_temporal68.cleanup_renewals WHERE run_id=$1`, run).Scan(&oldKey, &newKey, &originalDigest, &effectKey); err != nil || oldKey != "ordered-key-01" || newKey != "ordered-key-02" || originalDigest != source["envelope_digest"] || effectKey != prepared["effect_key"] {
							t.Fatal("rotated renewal lost original authority evidence", oldKey, newKey, originalDigest, effectKey, err)
						}
					}
					publicRead("retryable")
					if strings.HasPrefix(pause, "replacement_") || strings.HasPrefix(pause, "changed_") {
						var oldDelivery []byte
						if err := owner.QueryRow(ctx, `SELECT to_jsonb(d) FROM zasp_temporal68.deliveries d WHERE run_id=$1 AND phase='cleanup'`, run).Scan(&oldDelivery); err != nil {
							t.Fatal(err)
						}
						next, err := call(comp, "delivery", "prepare", map[string]any{"device_id": orderedApplicationDevice, "phase": "cleanup"})
						if err != nil {
							t.Fatal("cleanup replacement recompose", err)
						}
						var prior map[string]any
						json.Unmarshal(oldDelivery, &prior)
						if next["effect_key"] != got["effect_key"] || next["sequence"].(float64) <= prior["sequence"].(float64) {
							t.Fatal("replacement changed effect or reused sequence", next)
						}
						composition := next["composition"].(map[string]any)
						b, _ := json.Marshal(composition["policies"])
						var policies []policy.CompiledPolicy
						if err := json.Unmarshal(b, &policies); err != nil {
							t.Fatal(err)
						}
						if pause == "changed_ack" && (len(policies) != 1 || policies[0].ID != "pid_79000001-0000-4000-8000-000000000001") {
							t.Fatal("recomposition removed unrelated policy", policies)
						}
						expires, err := time.Parse(time.RFC3339Nano, composition["expires_at"].(string))
						if err != nil {
							t.Fatal(err)
						}
						signed, err := policy.SignGatewayPolicyEnvelope(policy.GatewayPolicySigningInput{KeyID: signingKeyID, Binding: policy.GatewayPolicyBinding{OrganizationID: o, WorkspaceID: w, EnvironmentID: e, DeviceID: orderedApplicationDevice}, Sequence: uint64(next["sequence"].(float64)), PolicyVersion: uint64(next["sequence"].(float64)), Now: fresh, IssuedAt: fresh, ExpiresAt: expires, FailureMode: "closed", Policies: policies}, key)
						if err != nil {
							t.Fatal(err)
						}
						payload["envelope"], payload["digest"] = signed, orderedEnvelopeDigest(signed)
						if _, err := call(comp, "delivery", "store", payload); err != nil {
							t.Fatal("renewed replacement store", err)
						}
						delete(payload, "envelope")
						if _, err := call(comp, "cleanup", "complete", map[string]any{}); err == nil {
							t.Fatal("recomposition without readback became clean")
						}
						if _, err := call(comp, "delivery", "read", payload); err != nil {
							t.Fatal(err)
						}
						if _, err := call(comp, "delivery", "ack", payload); err != nil {
							t.Fatal(err)
						}
						recoveredEnvelope = &signed
						var archived []byte
						if err := owner.QueryRow(ctx, `SELECT body FROM zasp_temporal68.delivery_revisions WHERE run_id=$1`, run).Scan(&archived); err != nil || string(archived) != string(oldDelivery) {
							t.Fatal("replacement overwrote original delivery", err)
						}
						if _, err := owner.Exec(ctx, `UPDATE zasp_temporal68.delivery_revisions SET body=body WHERE run_id=$1`, run); err == nil {
							t.Fatal("delivery history was mutable")
						}
						oldSequence := int64(prior["sequence"].(float64))
						oldSignature, _ := base64.RawURLEncoding.DecodeString(prior["envelope"].(map[string]any)["signature"].(string))
						if _, err := owner.Exec(ctx, `UPDATE zasp_runtime_gateway_policy_bundles SET signature=decode(repeat('00',64),'hex') WHERE device_id=$1 AND sequence=$2`, orderedApplicationDevice, oldSequence); err != nil {
							t.Fatal(err)
						}
						if _, err := call(comp, "cleanup", "complete", map[string]any{}); err == nil {
							t.Fatal("cleanup ignored changed historical signed evidence")
						}
						if _, err := owner.Exec(ctx, `UPDATE zasp_runtime_gateway_policy_bundles SET signature=$3 WHERE device_id=$1 AND sequence=$2`, orderedApplicationDevice, oldSequence, oldSignature); err != nil {
							t.Fatal(err)
						}
					}
				}
				restart("source")
				delivery, err := call(comp, "delivery", "prepare", payload)
				if err != nil {
					t.Fatal("cleanup delivery prepare", err)
				}
				composition := delivery["composition"].(map[string]any)
				policiesRaw, _ := json.Marshal(composition["policies"])
				var policies []policy.CompiledPolicy
				json.Unmarshal(policiesRaw, &policies)
				expires, err := time.Parse(time.RFC3339Nano, composition["expires_at"].(string))
				if err != nil {
					t.Fatal(err)
				}
				if pause == "historical_source" {
					if !expires.After(time.Now()) || expires.After(time.Now().Add(24*time.Hour)) {
						t.Fatal("historical cap was not renewed within bounds", expires)
					}
					now = time.Now().UTC().Truncate(time.Second)
				}
				if strings.HasPrefix(pause, "replacement_") {
					expires = time.Now().UTC().Truncate(time.Second).Add(65 * time.Second)
					deadline = expires.Add(20 * time.Millisecond)
				}
				envelope, err := policy.SignGatewayPolicyEnvelope(policy.GatewayPolicySigningInput{KeyID: signingKeyID, Binding: policy.GatewayPolicyBinding{OrganizationID: o, WorkspaceID: w, EnvironmentID: e, DeviceID: orderedApplicationDevice}, Sequence: uint64(delivery["sequence"].(float64)), PolicyVersion: uint64(delivery["sequence"].(float64)), Now: now, IssuedAt: now, ExpiresAt: expires, FailureMode: "closed", Policies: policies}, key)
				if err != nil {
					t.Fatal(err)
				}
				payload["envelope"], payload["digest"] = envelope, orderedEnvelopeDigest(envelope)
				if _, err := call(comp, "delivery", "store", payload); err != nil {
					t.Fatal("cleanup replacement store", err)
				}
				delete(payload, "envelope")
				if _, err := call(comp, "delivery", "ack", payload); err == nil {
					t.Fatal("cleanup ack without readback")
				}
				if _, err := call(comp, "delivery", "read", payload); err != nil {
					t.Fatal("cleanup readback", err)
				}
				restart("read")
				if recoveredEnvelope != nil {
					envelope = *recoveredEnvelope
				}
				// Stored bytes, not a client digest assertion, are the readback proof.
				if _, err := owner.Exec(ctx, `UPDATE zasp_runtime_gateway_policy_bundles SET signature=decode(repeat('00',64),'hex') WHERE device_id=$1 AND sequence=$2`, orderedApplicationDevice, envelope.Sequence); err != nil {
					t.Fatal(err)
				}
				if _, err := call(comp, "delivery", "ack", payload); err == nil {
					t.Fatal("changed signed readback accepted")
				}
				sig, _ := base64.RawURLEncoding.DecodeString(envelope.Signature)
				if _, err := owner.Exec(ctx, `UPDATE zasp_runtime_gateway_policy_bundles SET signature=$3 WHERE device_id=$1 AND sequence=$2`, orderedApplicationDevice, envelope.Sequence, sig); err != nil {
					t.Fatal(err)
				}
				if _, err := call(comp, "delivery", "ack", payload); err != nil {
					t.Fatal("cleanup controller ack", err)
				}
				restart("ack")
				cleaned, err := call(comp, "cleanup", "complete", map[string]any{})
				if err != nil || cleaned["state"] != "cleaned" {
					t.Fatal("cleanup complete", cleaned, err)
				}
				if replay, err := call(comp, "cleanup", "complete", map[string]any{}); err != nil || !jsonEqualMaps(cleaned, replay) {
					t.Fatal("cleanup replay", replay, err)
				}
				publicRead("cleaned")
				if pause == "rotated_source" {
					var retainedBundles []byte
					if err := owner.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(b) ORDER BY sequence) FROM zasp_runtime_gateway_policy_bundles b WHERE device_id=$1 AND sequence<$2`, orderedApplicationDevice, envelope.Sequence).Scan(&retainedBundles); err != nil || string(retainedBundles) != string(rotationPriorBundles) || envelope.KeyID != "ordered-key-02" {
						t.Fatal("rotated cleanup rewrote historical signed delivery", err)
					}
				}
				if pause != "" {
					before, err := call(comp, "delivery", "prepare", map[string]any{"device_id": orderedApplicationDevice, "phase": "cleanup"})
					if err != nil || before["state"] != "acknowledged" {
						t.Fatal("cleaned delivery reconcile", before, err)
					}
					if again, err := call(comp, "delivery", "prepare", map[string]any{"device_id": orderedApplicationDevice, "phase": "cleanup"}); err != nil || !jsonEqualMaps(before, again) {
						t.Fatal("reconciled delivery replay", again, err)
					}
					var archived, bundles int
					wantArchived := 0
					if strings.HasPrefix(pause, "replacement_") || pause == "changed_ack" {
						wantArchived = 1
					}
					if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_temporal68.delivery_revisions WHERE run_id=$1),(SELECT count(*) FROM zasp_runtime_gateway_policy_bundles WHERE device_id=$2)`, run, orderedApplicationDevice).Scan(&archived, &bundles); err != nil || archived != wantArchived || bundles != 2+wantArchived {
						t.Fatal("replay duplicated historical delivery", archived, bundles, err)
					}
				}
				var deliveries, finishes int
				wantFinishes := 1
				if pause == "replacement_ack" || pause == "changed_ack" {
					wantFinishes = 2
				}
				if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_temporal68.deliveries WHERE run_id=$1 AND phase='cleanup'),(SELECT count(*) FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind='temporal_cleanup_delivery_finish')`, run).Scan(&deliveries, &finishes); err != nil || deliveries != 1 || finishes != wantFinishes {
					t.Fatal("cleanup duplicated delivery", deliveries, finishes, err)
				}
			})
		})
	}
}
