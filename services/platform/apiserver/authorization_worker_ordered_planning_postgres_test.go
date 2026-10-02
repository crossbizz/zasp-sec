package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
)

// Real finding-trigger admission precedes the hook. Neither associations nor
// permission tuples are seeded; the installed worker boundary must derive them.
func TestP7WorkerOrdered68Planning(t *testing.T) {
	runWorkerOrdered68PlanningFixture(t, "")
}

func TestP7WorkerOrdered68SharedPlanner(t *testing.T) {
	for _, mode := range []string{"current", "prepared-revoke", "sent-revoke", "late-usage"} {
		t.Run(mode, func(t *testing.T) { runWorkerOrdered68PlanningFixture(t, mode) })
	}
}

func TestP7WorkerOrdered68PlanningTiming(t *testing.T) {
	runWorkerOrdered68PlanningFixture(t, "current-timing")
}

type ordered68AdmissionConsumer func(*testing.T, context.Context, *pgx.Conn, *pgx.Conn, *pgx.Conn, json.RawMessage)

func runWorkerOrdered68PlanningFixture(t *testing.T, mode string, afterAdmission ...ordered68AdmissionConsumer) {
	t.Helper()
	if len(afterAdmission) > 1 || len(afterAdmission) == 1 && mode != "lifecycle" && mode != "lifecycle-message" && mode != "lifecycle-planning" {
		t.Fatal("invalid ordered admission consumer")
	}
	consumed := false
	runTemporalExecutorPlanningFixtureWithHook(t, func(ctx context.Context, owner, executor, api *pgx.Conn, o, w, e, run, testID string) bool {
		consumed = true
		// Match the established composed worker-fixture allowance. This does
		// not change native budgets or the planner's per-call ten-second cap.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Minute)
		defer cancel()
		installAutomaticSourceFixture(t, ctx, owner)
		runner := workerMigrationRunner(t, owner)
		if err := runner.UpProductionTemporalFindingResponse(ctx); err != nil {
			t.Fatal("ordered predecessor profile", err)
		}
		{
			var actor string
			if err := owner.QueryRow(ctx, `SELECT requested_by FROM zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, o, w, e, run).Scan(&actor); err != nil {
				t.Fatal("actual ordered admission actor", err)
			}
			// Reuse the native68 fixture's actual winning source prerequisites
			// before installing capture triggers or deriving worker authority.
			seedOrderedTestSource(t, ctx, owner, o, w, e, actor)
			if len(afterAdmission) == 1 && mode == "lifecycle-message" {
				cancelRequest := public62Request(o, w, e, actor, "cancel")
				cancelRequest["run_id"], cancelRequest["run_version"], cancelRequest["idempotency_key"] = run, 1, "ordered69-lifecycle-cancel-0001"
				if _, err := public62Call(ctx, api, cancelRequest); err != nil {
					t.Fatal("actual committed lifecycle cancellation", err)
				}
			}
		}
		if err := runner.UpProductionAuthorizationTemporalProfile(ctx); err != nil {
			t.Fatal("ordered authorization profile", err)
		}
		if err := runner.UpProductionAuthorizationWorkerProfile(ctx); err != nil {
			t.Fatal("ordered worker profile", err)
		}
		var identity json.RawMessage
		var untouched bool
		if err := owner.QueryRow(ctx, `SELECT jsonb_build_object('organization_id',r.organization_id,'workspace_id',r.workspace_id,'environment_id',r.environment_id,'run_id',r.run_id,'definition_version',r.definition_version,'input_digest',c.input_digest),(CASE WHEN $2 THEN r.state='cancelled' AND r.version=2 ELSE r.state='queued' AND r.version=1 END) AND r.plan_hash IS NULL AND NOT EXISTS(SELECT 1 FROM zasp_temporal68.planning_jobs j WHERE j.run_id=r.run_id) FROM zasp_security_agent_runs r JOIN zasp_temporal65.commands c USING(organization_id,workspace_id,environment_id,run_id) WHERE r.run_id=$1 AND c.kind='start' AND c.execution_owner='temporal'`, run, mode == "lifecycle-message").Scan(&identity, &untouched); err != nil || !untouched {
			t.Fatal("actual untouched ordered admission", err)
		}
		if len(afterAdmission) == 1 && mode != "lifecycle-planning" {
			afterAdmission[0](t, ctx, owner, executor, api, identity)
			return true
		}
		var request map[string]any
		if json.Unmarshal(identity, &request) != nil {
			t.Fatal("ordered identity")
		}
		delete(request, "input_digest")
		for _, phase := range []string{"state", "load"} {
			statement := `SELECT zasp_temporal68.status($1::jsonb)->'planning'`
			if phase == "load" {
				request["operation"], statement = "load", `SELECT zasp_temporal68.plan($1::jsonb)`
			}
			raw, _ := json.Marshal(request)
			tx, err := executor.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			var result json.RawMessage
			err = tx.QueryRow(ctx, statement, raw).Scan(&result)
			var native *pgconn.PgError
			refused := errors.As(err, &native) && native.Code == "42501"
			if rollback := tx.Rollback(ctx); rollback != nil {
				t.Fatal(rollback)
			}
			if !refused {
				t.Errorf("unsigned registered executor obtained ordered planning %s: %v", phase, err)
			}
		}
		if t.Failed() {
			return true
		}
		poolFor := func(login string) *pgxpool.Pool {
			cfg, err := pgxpool.ParseConfig(owner.Config().ConnString())
			if err != nil {
				t.Fatal(err)
			}
			cfg.ConnConfig.User, cfg.MaxConns = login, 2
			pool, err := pgxpool.NewWithConfig(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(pool.Close)
			return pool
		}
		client, config := newAuthorizationProjectionFGA(t)
		checker, err := authorization.NewOpenFGA(client, config)
		if err != nil {
			t.Fatal(err)
		}
		writer, err := authorization.NewOpenFGATupleWriter(client, config)
		if err != nil {
			t.Fatal(err)
		}
		var projector string
		if err := owner.QueryRow(ctx, `SELECT principal_name FROM zasp_discovery_principal_bindings WHERE authority_role='zasp_outbox_worker'`).Scan(&projector); err != nil {
			t.Fatal(err)
		}
		projection, err := authorization.NewPostgresProjectionRepository(poolFor(projector))
		if err != nil {
			t.Fatal(err)
		}
		key, err := authorization.NewWorkerKey(authorization.WorkerForward, bytes.Repeat([]byte{41}, 32))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `SELECT zasp_authorization80_worker.register_verifier($1,$2,$3)`, string(authorization.WorkerForward), key.Version(), key.Verifier()); err != nil {
			t.Fatal(err)
		}
		forwardPool := poolFor("temporal_executor_test_login")
		forward, err := authorization.NewWorkerExecutor(forwardPool, checker, config.StoreID, config.ModelID, key)
		if err != nil {
			t.Fatal(err)
		}
		if err := forward.PrepareOrdered68(ctx, identity); err != nil {
			t.Fatal("derive original ordered task", err)
		}
		var selection any
		if mode != "" {
			compensationKey, err := authorization.NewWorkerKey(authorization.CapturedCompensation, bytes.Repeat([]byte{73}, 32))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := owner.Exec(ctx, `SELECT zasp_authorization80_worker.register_verifier($1,$2,$3)`, string(authorization.CapturedCompensation), compensationKey.Version(), compensationKey.Verifier()); err != nil {
				t.Fatal(err)
			}
		}
		if mode != "" && mode != "fences" && mode != "target-lineage" {
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
			bindTemporalTestPlannerPricing(policy)
			pricing, err := orderedPricingCall(ctx, admin, "pricing_admin", policy)
			if err != nil {
				t.Fatal("actual ordered pricing setup", err)
			}
			selected := orderedPricingLookupRequest(o, w, e, policy["policy"].(map[string]any), pricing)
			delete(selected, "body")
			delete(selected, "body_digest")
			selection = selected
		}
		if _, err := owner.Exec(ctx, `SELECT zasp_authorization79.configure($1,$2,$3)`, o, config.StoreID, config.ModelID); err != nil {
			t.Fatal(err)
		}
		if result, err := authorization.Reconcile(ctx, projection, writer, o, config.StoreID, config.ModelID); err != nil || !result.Applied {
			t.Fatal("actual ordered task projection", err)
		}
		raw, _ := json.Marshal(request)
		decision, err := forward.Authorize(ctx, "ordered68.planning.load", raw)
		if err != nil {
			t.Fatal("current ordered load authorization", err)
		}
		result, err := forward.Execute(ctx, decision)
		if err != nil {
			t.Fatal("signed ordered native load", err)
		}
		var job struct {
			RunID string `json:"run_id"`
			State string `json:"state"`
		}
		if json.Unmarshal(result, &job) != nil || job.RunID != run || job.State != "loaded" {
			t.Fatal("signed ordered load did not produce real intent")
		}
		if err := owner.QueryRow(ctx, `SELECT (SELECT count(*)=1 FROM zasp_temporal68.planning_jobs WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_temporal68.provider_reservations WHERE run_id=$1) AND NOT zasp_authorization80_worker.runtime_ready()`, run).Scan(&untouched); err != nil || !untouched {
			t.Fatal("ordered load cardinality or runtime gate", err)
		}
		if len(afterAdmission) == 1 && mode == "lifecycle-planning" {
			afterAdmission[0](t, ctx, owner, executor, api, identity)
			return true
		}
		if mode == "fences" {
			assertOrdered68PlanningFences(t, ctx, owner, identity)
		} else if mode == "target-lineage" {
			assertOrdered68TargetLineage(t, ctx, owner, executor, identity)
		} else if mode != "" {
			runWorkerOrdered68PlannerChild(t, ctx, owner, config, identity, selection, testID, mode)
		}
		return true
	}, nil, nil)
	if !t.Failed() && !consumed {
		t.Fatal("actual ordered admission hook did not run")
	}
}

func runWorkerOrdered68PlannerChild(t *testing.T, ctx context.Context, owner *pgx.Conn, config runtimeservices.Config, start json.RawMessage, selection any, testID, mode string) {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "ordered-planner-test")
	build := exec.CommandContext(ctx, "go", "test", "-c", "-o", binary, "../agentsec-worker")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("ordered planner child build: %v\n%s", err, output)
	}
	name := "TestP7WorkerOrdered68SharedPlannerNative"
	child := exec.CommandContext(ctx, binary, "-test.run=^"+name+"$", "-test.count=1", "-test.v")
	child.WaitDelay = 5 * time.Second
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "ZASP_") {
			child.Env = append(child.Env, value)
		}
	}
	encodedConfig, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	encodedSelection, err := json.Marshal(selection)
	if err != nil {
		t.Fatal(err)
	}
	child.Env = append(child.Env, "ZASP_P7_ORDERED_OWNER_DSN="+owner.Config().ConnString(), "ZASP_P7_ORDERED_CONFIG="+string(encodedConfig), "ZASP_P7_ORDERED_SELECTION="+string(encodedSelection), "ZASP_P7_ORDERED_START="+string(start), "ZASP_P7_ORDERED_MODE="+mode, "ZASP_P7_ORDERED_TEST_ID="+testID)
	output, err := child.CombinedOutput()
	if err != nil || !bytes.Contains(output, []byte("--- PASS: "+name)) || bytes.Contains(output, []byte("--- SKIP:")) {
		t.Fatalf("actual ordered planner child %s: %v\n%s", mode, err, output)
	}
	t.Logf("actual ordered planner child joined: %s", output)
}
