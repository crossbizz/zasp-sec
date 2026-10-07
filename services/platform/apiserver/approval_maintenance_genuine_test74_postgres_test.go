package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
)

// DRAFT: original native74 fixture assertions retained; no runtime/seal yet.
func TestApprovalMaintenanceGenuineSupervisedTest74EnqueueInactive(t *testing.T) {
	runApprovalOriginTest74PlanningFixture(t, "effect")
}

func runApprovalOriginTest74PlanningFixture(t *testing.T, mode string, afterCapture ...workerRuntimeCaptureConsumer) {
	if len(afterCapture) > 1 || (len(afterCapture) == 1 && mode != "runtime-retained") {
		t.Fatal("captured runtime fixture callback requires one retained runtime consumer")
	}
	runTemporalTestGrantFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
		fixtureBudget := 5 * time.Minute
		if mode == "adapter-complete" || strings.HasPrefix(mode, "adapter-http") || mode == "lifecycle-status-max" {
			fixtureBudget = 8 * time.Minute
		}
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), fixtureBudget)
		defer cancel()
		var runtimeSource workerRuntimeProjectedSource
		if mode == "runtime-retained" {
			runtimeSource = workerRuntimeHistoricalProjection(t, ctx, owner, o, w, e, actor)
		}
		installAutomaticSourceFixture(t, ctx, owner)
		runner := workerMigrationRunner(t, owner)
		if strings.HasPrefix(mode, "runtime-") {
			var err error
			runner, err = migrations.NewRunner(&runtimeObservedMigrationDatabase{workerObservedMigrationDatabase{integrationMigrationDatabase{connection: owner}, t}})
			if err != nil {
				t.Fatal(err)
			}
		}
		if err := runner.UpProductionTemporalFindingResponse(ctx); err != nil {
			t.Fatal("finding predecessor", err)
		}
		if _, err := owner.Exec(ctx, `CREATE ROLE worker_test_executor LOGIN; CREATE ROLE worker_test_compensation LOGIN;
SELECT zasp_temporal68.register_principals('worker_test_executor','worker_test_compensation');
UPDATE zasp_identity_memberships SET role='organization_admin' WHERE principal_id=$1;
UPDATE zasp_authorized_scopes SET permissions='["view","manage_identity","manage_workflows","run_tests"]' WHERE principal_id=$1`, pgx.QueryExecModeSimpleProtocol, actor); err != nil {
			t.Fatal(err)
		}
		seedOrderedTestSource(t, ctx, owner, o, w, e, actor)
		if mode == "lifecycle-status-max" {
			if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_definitions SET categories='["prompt_injection","tool_abuse","data_leakage","authorization_bypass","excessive_agency","sensitive_information"]' WHERE definition_id=$1`, testID); err != nil {
				t.Fatal(err)
			}
		}
		cfg := owner.Config().Copy()
		cfg.User = "worker_test_executor"
		executor, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer executor.Close(ctx)
		const run = "pid_f0807400-0000-4000-8000-000000000001"
		authority, identity := orderedResourceGo(t, api, o, w, e, actor)
		repository := &PostgresRepository{database: authority.repository.database, schema: SecurityAgentSessionIsolationSchemaVersion, securityAgentExecution: true}
		// The original autonomous version4 case remains preserved separately.
		// This positive uses the original authenticated create/activate writer, not row seeding.
		identity.FreshAuthenticated = true
		identity.FreshAuthExpiresAt = time.Now().UTC().Add(4 * time.Minute)
		assertTemporalTestFullActivation(t, ctx, owner, repository, identity, true)
		const supervisedDefinition = "pid_f0740000-0000-4000-8000-000000000101"
		admission := SecurityAgentRunRequest{DefinitionID: supervisedDefinition, ExpectedVersion: 3, IdempotencyKey: "worker74-real-manual-admission", RunID: run, TriggerKind: "manual",
			AuditID: "pid_f0807400-0000-4000-8000-000000000002", CorrelationID: "pid_f0807400-0000-4000-8000-000000000003", ReceiptID: "pid_f0807400-0000-4000-8000-000000000004"}
		sourceKind := "manual65"
		if mode == "runtime-retained" {
			admission.DefinitionID = workerRetainedRuntimeDefinition(t, ctx, owner, api, o, w, e, actor)
			admission.TriggerKind, admission.TriggerID = "session", runtimeSource.publish(t, ctx, owner, o, w, e)
			sourceKind = "resource65"
		}
		admit := repository.runSecurityAgentManual
		if mode == "runtime-retained" {
			admit = repository.RunSecurityAgent
		}
		if receipt, err := admit(ctx, identity, admission); err != nil || receipt.ID != run {
			t.Fatal("actual76 manual test admission", err)
		}
		var takeover json.RawMessage
		if err := executor.QueryRow(ctx, `SELECT zasp_temporal74.takeover($1,$2,$3,$4)`, o, w, e, run).Scan(&takeover); err != nil || string(takeover) == "null" {
			t.Fatal("actual74 untouched manual takeover", err)
		}
		var bound bool
		if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_temporal76.admissions h JOIN zasp_temporal74.run_owners x USING(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,input_digest) WHERE h.run_id=$1 AND h.requester_id=$2 AND h.source_kind=$3 AND x.source_kind=$3)`, run, actor, sourceKind).Scan(&bound); err != nil || !bound {
			t.Fatal("actual76/74 admission identity", err)
		}
		adminConfig := owner.Config().Copy()
		adminConfig.User = "security_agent_v33_discovery_api_login"
		admin, err := pgx.ConnectConfig(ctx, adminConfig)
		if err != nil {
			t.Fatal(err)
		}
		defer admin.Close(ctx)
		policy := orderedPricingAdminRequest(o, w, e, actor)
		bindTemporalTestPlannerPricing(policy)
		pricing, err := orderedPricingCall(ctx, admin, "pricing_admin", policy)
		if err != nil {
			t.Fatal("native74 pricing", err)
		}
		selection := orderedPricingLookupRequest(o, w, e, policy["policy"].(map[string]any), pricing)
		if err := runner.UpProductionAuthorizationTemporalProfile(ctx); err != nil {
			t.Fatal("composed profile", err)
		}
		if err := runner.UpProductionAuthorizationWorkerProfile(ctx); err != nil {
			t.Fatal("worker profile", err)
		}
		if err := runner.UpProductionApprovalMaintenanceProfile(ctx); err != nil {
			t.Fatal("actual supplementary origin module", err)
		}
		if _, err := owner.Exec(ctx, `INSERT INTO public.zasp_workflow_records(organization_id,workspace_id,environment_id,kind,id,body) VALUES($1,$2,$3,'integration',$4,jsonb_build_object('id',$4::text,'name','Owned approval fixture','connector_key','generic-webhook','status','configured','configuration',jsonb_build_object('destination_url','https://hooks.example.test/zasp','signing_secret_reference','secret_ref_approval_fixture')))`, o, w, e, productID(98001)); err != nil {
			t.Fatal("original unversioned notification destination", err)
		}
		captureWorkerTestCatalog(t, ctx, owner)
		if mode == "runtime-retained" {
			assertWorkerRuntimeCatalog(t, ctx, owner)
			if t.Failed() {
				return
			}
		}
		if mode == "lifecycle-prepared" {
			assertWorkerReceiptCatalogNative(t, ctx, owner)
		}
		if mode == "lifecycle-queued" {
			for _, v := range []struct {
				purpose authorization.WorkerPurpose
				seed    byte
			}{{authorization.WorkerForward, 41}, {authorization.CapturedCompensation, 73}} {
				key, err := authorization.NewWorkerKey(v.purpose, bytes.Repeat([]byte{v.seed}, 32))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := owner.Exec(ctx, `SELECT zasp_authorization80_worker.register_verifier($1,$2,$3)`, string(v.purpose), key.Version(), key.Verifier()); err != nil {
					t.Fatal(err)
				}
			}
			runWorkerTest74ProductChild(t, ctx, owner, run, "TestP7WorkerSingleTestQueuedLifecycleNative")
			return
		}
		for _, phase := range []string{"load", "state"} {
			tx, err := executor.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
			if err != nil {
				t.Fatal(err)
			}
			q := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "definition_version": admission.ExpectedVersion}
			query := `SELECT zasp_temporal74.planning_state($1::jsonb)`
			if phase == "load" {
				q["operation"], query = "load", `SELECT zasp_temporal74.plan($1::jsonb)`
			}
			body, _ := json.Marshal(q)
			var result json.RawMessage
			err = tx.QueryRow(ctx, query, body).Scan(&result)
			var refusal *pgconn.PgError
			if err == nil {
				t.Errorf("unproved registered executor obtained actual74 planning %s", phase)
			} else if !errors.As(err, &refusal) || refusal.Code != "42501" {
				t.Errorf("actual74 planning %s refusal class: %v", phase, err)
			}
			if err := tx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
		}
		if err := owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_temporal74.planning_jobs WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_temporal74.provider_reservations WHERE run_id=$1) AND EXISTS(SELECT 1 FROM zasp_security_agent_runs WHERE run_id=$1 AND state='queued' AND version=1)`, run).Scan(&bound); err != nil || !bound {
			t.Fatal("native74 rollback changed intent/debt", err)
		}
		if t.Failed() {
			return
		}
		assertApprovalOriginTest74PlanningLoad(t, ctx, owner, o, w, e, run, testID, selection, mode, afterCapture...)
	})
}

// The positive native load catches a fence that merely refuses every caller.
// Catalog probes catch exact changed bodies/triggers disappearing from the pin.
func assertApprovalOriginTest74PlanningLoad(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e, run, testID string, selection map[string]any, mode string, afterCapture ...workerRuntimeCaptureConsumer) {
	assertApprovalOriginTest74PlanningLoadWith(t, ctx, owner, o, w, e, run, testID, selection, mode, nil, afterCapture...)
}

// Test-only composition seam. It does not replace SQL admission, revision
// reconciliation, signed worker calls, artifacts, or planner transitions.
type approvalOriginSingleRecoveryPlanningSeam struct {
	checker        authorization.Checker
	writer         authorization.TupleWriter
	afterAdmission func(*authorization.WorkerExecutor, func(string) *pgxpool.Pool, func())
}

func assertApprovalOriginTest74PlanningLoadWith(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e, run, testID string, selection map[string]any, mode string, seam *approvalOriginSingleRecoveryPlanningSeam, afterCapture ...workerRuntimeCaptureConsumer) {
	if len(afterCapture) > 1 || (len(afterCapture) == 1 && mode != "runtime-retained") {
		t.Fatal("captured runtime callback requires one retained runtime consumer")
	}
	lifecycleChildCompleted := false
	defer func() {
		if (mode == "lifecycle-reserved" || mode == "lifecycle-pending" || mode == "lifecycle-status-max") && !t.Failed() && !lifecycleChildCompleted {
			t.Error("expected actual lifecycle product child did not complete")
		}
	}()
	t.Helper()
	for _, mutation := range []struct{ name, sql string }{
		{"planning body", `CREATE OR REPLACE FUNCTION zasp_temporal74.plan(q jsonb) RETURNS jsonb LANGUAGE sql AS $$ SELECT '{}'::jsonb $$`},
		{"planning reader", `CREATE OR REPLACE FUNCTION zasp_temporal74.planning_state(q jsonb) RETURNS jsonb LANGUAGE sql AS $$ SELECT '{}'::jsonb $$`},
		{"74 projection", `CREATE OR REPLACE FUNCTION zasp_temporal76.executor74_fingerprint() RETURNS text LANGUAGE sql AS $$ SELECT 'changed'::text $$`},
		{"target trigger disabled", `ALTER TABLE zasp_inventory_entities DISABLE TRIGGER zasp_authorization80_worker_target_capture`},
		{"credential trigger disabled", `ALTER TABLE zasp_attack_lab_credential_bindings DISABLE TRIGGER zasp_authorization80_worker_target_capture`},
		{"target capture body", `CREATE OR REPLACE FUNCTION zasp_authorization80_worker.capture_test_target() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN RETURN NEW; END $$`},
		{"target capture ACL", `GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.capture_test_target() TO PUBLIC`},
		{"expiry queue", `CREATE OR REPLACE FUNCTION zasp_authorization79.pending(n integer) RETURNS jsonb LANGUAGE sql AS $$ SELECT '[]'::jsonb $$`},
		{"domain projection", `CREATE OR REPLACE FUNCTION zasp_authorization80_temporal.projected_domain() RETURNS text LANGUAGE sql AS $$ SELECT 'changed'::text $$`},
	} {
		if mode != "" {
			break
		}
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, mutation.sql); err != nil {
			t.Fatal(mutation.name, err)
		}
		var refused bool
		err = tx.QueryRow(ctx, `SELECT NOT zasp_authorization80_worker.catalog_ready() AND NOT coalesce(zasp_temporal74.current_ready(),false) AND NOT coalesce(zasp_temporal78.current_ready(),false) AND NOT coalesce(zasp_authorization80_temporal.ready(),false)`).Scan(&refused)
		if rollbackErr := tx.Rollback(ctx); rollbackErr != nil {
			t.Fatal(rollbackErr)
		}
		if err != nil || !refused {
			t.Fatal("changed catalog remained ready", mutation.name, err)
		}
	}
	var checker authorization.Checker
	var writer authorization.TupleWriter
	var config runtimeservices.Config
	if seam != nil {
		if mode != "recovery-driver" || seam.checker == nil || seam.writer == nil || seam.afterAdmission == nil {
			t.Fatal("incomplete recovery planning seam")
		}
		checker, writer = seam.checker, seam.writer
		config.StoreID, config.ModelID = "01ARZ3NDEKTSV4RRFFQ69G5FAV", "01ARZ3NDEKTSV4RRFFQ69G5FAW"
	} else {
		client, c := newApprovalMaintenanceOwnedFGA(t)
		config = c
		var err error
		checker, err = authorization.NewOpenFGA(client, config)
		if err != nil {
			t.Fatal(err)
		}
		writer, err = authorization.NewOpenFGATupleWriter(client, config)
		if err != nil {
			t.Fatal(err)
		}
	}
	poolFor := func(login string) *pgxpool.Pool {
		t.Helper()
		cfg, err := pgxpool.ParseConfig(owner.Config().ConnString())
		if err != nil {
			t.Fatal(err)
		}
		cfg.ConnConfig.User, cfg.MaxConns = login, 2
		if strings.HasPrefix(mode, "runtime-") && os.Getenv("ZASP_WORKER_RUNTIME_TIMING") == "1" {
			cfg.ConnConfig.Tracer = workerRuntimeSQLTiming{t}
		}
		if seam == nil {
			cfg.ConnConfig.OnPgError = func(_ *pgconn.PgConn, failure *pgconn.PgError) bool {
				t.Logf("worker74 SQLSTATE=%s message=%s where=%s", failure.Code, failure.Message, failure.Where)
				return failure.Severity != "FATAL"
			}
		}
		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		return pool
	}
	var outbox string
	if err := owner.QueryRow(ctx, `SELECT principal_name FROM zasp_discovery_principal_bindings WHERE authority_role='zasp_outbox_worker'`).Scan(&outbox); err != nil {
		t.Fatal(err)
	}
	projection, err := authorization.NewPostgresProjectionRepository(poolFor(outbox))
	if err != nil {
		t.Fatal(err)
	}
	key, _ := authorization.NewWorkerKey(authorization.WorkerForward, bytes.Repeat([]byte{41}, 32))
	if _, err := owner.Exec(ctx, `SELECT zasp_authorization80_worker.register_verifier($1,$2,$3)`, string(authorization.WorkerForward), key.Version(), key.Verifier()); err != nil {
		t.Fatal(err)
	}
	forwardPool := poolFor("worker_test_executor")
	forward, err := authorization.NewApprovalOriginWorkerExecutor(ctx, forwardPool, workerObservedChecker{checker, t}, config.StoreID, config.ModelID, key, migrations.ApprovalMaintenanceProfileChecksum())
	if err != nil {
		t.Fatal(err)
	}
	var reference json.RawMessage
	if err := owner.QueryRow(ctx, `SELECT jsonb_build_object('organization_id',organization_id,'workspace_id',workspace_id,'environment_id',environment_id,'run_id',run_id,'definition_version',definition_version,'input_digest',input_digest) FROM zasp_temporal74.run_owners WHERE run_id=$1`, run).Scan(&reference); err != nil {
		t.Fatal(err)
	}
	if mode == "credential-expiry" {
		if _, err := owner.Exec(ctx, `UPDATE zasp_attack_lab_credential_bindings c SET valid_until=clock_timestamp()+interval '90 seconds' FROM zasp_red_team_definitions d WHERE(d.organization_id,d.workspace_id,d.environment_id,d.definition_id,d.target_id)=(c.organization_id,c.workspace_id,c.environment_id,$1,c.target_id)`, testID); err != nil {
			t.Fatal("owned credential expiry setup", err)
		}
	} else if mode == "inventory-expiry" {
		if _, err := owner.Exec(ctx, `UPDATE zasp_inventory_entities i SET fresh_until=clock_timestamp()+interval '90 seconds' FROM zasp_red_team_definitions d WHERE(d.organization_id,d.workspace_id,d.environment_id,d.definition_id,d.target_id)=(i.organization_id,i.workspace_id,i.environment_id,$1,i.id)`, testID); err != nil {
			t.Fatal("owned inventory expiry setup", err)
		}
	}
	if err := forward.PrepareTest74(ctx, reference); err != nil {
		t.Fatal("actual test target capture", err)
	}
	if _, err := owner.Exec(ctx, `SELECT zasp_authorization79.configure($1,$2,$3)`, o, config.StoreID, config.ModelID); err != nil {
		t.Fatal(err)
	}
	if result, err := authorization.Reconcile(ctx, projection, writer, o, config.StoreID, config.ModelID); err != nil || !result.Applied {
		t.Fatal("actual74 machine projection", err)
	}
	if mode == "product" || strings.HasPrefix(mode, "product-") {
		for _, v := range []struct {
			purpose authorization.WorkerPurpose
			seed    byte
		}{{authorization.WorkerForward, 42}, {authorization.CapturedCompensation, 73}} {
			key, err := authorization.NewWorkerKey(v.purpose, bytes.Repeat([]byte{v.seed}, 32))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := owner.Exec(ctx, `SELECT zasp_authorization80_worker.register_verifier($1,$2,$3)`, string(v.purpose), key.Version(), key.Verifier()); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := authorization.Reconcile(ctx, projection, writer, o, config.StoreID, config.ModelID); err != nil {
			t.Fatal(err)
		}
		phase := "planning"
		if mode != "product" {
			phase = strings.TrimPrefix(mode, "product-")
		}
		runWorkerProductChild(t, ctx, owner, config, reference, "test74-"+phase, selection)
		return
	}
	var nativeReference struct {
		DefinitionVersion int64 `json:"definition_version"`
	}
	if json.Unmarshal(reference, &nativeReference) != nil || nativeReference.DefinitionVersion < 1 {
		t.Fatal("native74 reference definition version")
	}
	request := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "definition_version": nativeReference.DefinitionVersion, "operation": "load"}
	execute := func(operation authorization.WorkerOperation, payload json.RawMessage) (json.RawMessage, error) {
		callContext := ctx
		if strings.HasPrefix(mode, "runtime-") {
			var cancel context.CancelFunc
			callContext, cancel = context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
		}
		started := time.Now()
		decision, err := forward.Authorize(callContext, operation, payload)
		if strings.HasPrefix(mode, "runtime-") && os.Getenv("ZASP_WORKER_RUNTIME_TIMING") == "1" {
			t.Logf("runtime planning Authorize operation=%s elapsed=%s error_type=%T deadline=%t", operation, time.Since(started).Round(time.Millisecond), err, errors.Is(callContext.Err(), context.DeadlineExceeded))
		}
		if err != nil {
			return nil, err
		}
		started = time.Now()
		result, err := forward.Execute(callContext, decision)
		if strings.HasPrefix(mode, "runtime-") && os.Getenv("ZASP_WORKER_RUNTIME_TIMING") == "1" {
			t.Logf("runtime planning Execute operation=%s elapsed=%s error_type=%T deadline=%t", operation, time.Since(started).Round(time.Millisecond), err, errors.Is(callContext.Err(), context.DeadlineExceeded))
		}
		return result, err
	}
	raw, _ := json.Marshal(request)
	if strings.HasPrefix(mode, "runtime-") {
		assertWorkerRuntimeSourceFacts(t, ctx, owner, forwardPool, run, mode, raw)
		if t.Failed() {
			return
		}
		if len(afterCapture) == 1 {
			afterCapture[0](t, ctx, owner, o, w, e, run)
			return
		}
	}
	if mode == "definition-binding" {
		var facts json.RawMessage
		if err := forwardPool.QueryRow(ctx, `SELECT zasp_authorization80_worker.planning74_source('load',$1::jsonb)`, raw).Scan(&facts); err != nil {
			t.Fatal("actual74 definition-bound source", err)
		}
		var metadata struct {
			DefinitionDigest string `json:"definition_digest"`
		}
		var historical string
		if err := owner.QueryRow(ctx, `SELECT encode(h.definition_digest,'hex') FROM zasp_security_agent_definition_versions h JOIN zasp_temporal74.run_owners x ON(h.organization_id,h.workspace_id,h.environment_id,h.definition_id,h.version)=(x.organization_id,x.workspace_id,x.environment_id,x.definition_id,x.definition_version) WHERE x.run_id=$1`, run).Scan(&historical); err != nil {
			t.Fatal("actual historical definition digest", err)
		}
		if json.Unmarshal(facts, &metadata) != nil || len(historical) != 64 || metadata.DefinitionDigest != historical {
			t.Fatal("worker74 source omitted exact immutable definition digest")
		}
		revision, err := forward.Revision(ctx, o)
		if err != nil {
			t.Fatal(err)
		}
		assertWorkerTest74SourceBindings(t, ctx, owner, forwardPool, key, revision, raw, false)
		return
	}
	loaded, err := execute("test74.planning.load", raw)
	if err != nil {
		t.Fatal("native74 signed load", err)
	}
	var job struct{ RunID, State string }
	var body map[string]json.RawMessage
	if json.Unmarshal(loaded, &body) != nil || json.Unmarshal(body["run_id"], &job.RunID) != nil || json.Unmarshal(body["state"], &job.State) != nil || job.RunID != run || job.State != "loaded" {
		t.Fatal("native74 load did not return its own loaded job")
	}
	delete(request, "operation")
	raw, _ = json.Marshal(request)
	if _, err := forward.Authorize(ctx, "test74.planning.state", raw); !errors.Is(err, authorization.ErrPending) {
		t.Fatal("committed native run revision did not hold forward planning pending", err)
	}
	if result, err := authorization.Reconcile(ctx, projection, writer, o, config.StoreID, config.ModelID); err != nil || !result.Applied {
		t.Fatal("native74 committed transition projection", err)
	}
	state, err := execute("test74.planning.state", raw)
	if err != nil || !bytes.Equal(state, loaded) {
		t.Fatal("signed74 state did not read exact loaded job", err)
	}
	var one bool
	if err := owner.QueryRow(ctx, `SELECT (SELECT count(*)=1 FROM zasp_temporal74.planning_jobs WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_temporal74.provider_reservations WHERE run_id=$1) AND NOT zasp_authorization80_worker.runtime_ready()`, run).Scan(&one); err != nil || !one {
		t.Fatal("native74 load cardinality or partial-runtime gate", err)
	}
	call := func(phase string, payload any) map[string]any {
		t.Helper()
		request["operation"] = phase
		request["payload"] = payload
		body, _ := json.Marshal(request)
		result, err := execute(authorization.WorkerOperation("test74.planning."+phase), body)
		if err != nil {
			t.Fatal("native74 planning phase", phase, err)
		}
		var decoded map[string]any
		if json.Unmarshal(result, &decoded) != nil {
			t.Fatal("native74 planning result decode", phase)
		}
		return decoded
	}
	delete(selection, "body")
	delete(selection, "body_digest")
	if prepared := call("prepare", map[string]any{"pricing": selection, "input_version": "worker74-input-v1"}); prepared["state"] != "prepared" {
		t.Fatal("native74 exact pricing preparation")
	}
	if mode == "lifecycle-prepared" {
		key, _ := authorization.NewWorkerKey(authorization.CapturedCompensation, bytes.Repeat([]byte{73}, 32))
		if _, err := owner.Exec(ctx, `SELECT zasp_authorization80_worker.register_verifier($1,$2,$3)`, string(authorization.CapturedCompensation), key.Version(), key.Verifier()); err != nil {
			t.Fatal(err)
		}
		runWorkerTest74ProductChild(t, ctx, owner, run, "TestP7WorkerSingleTestPreparedLifecycleNative")
		return
	}
	if mode == "credential-revoke" || mode == "credential-expiry" || mode == "inventory-expiry" {
		assertWorkerTest74CapturedPlanning(t, ctx, owner, poolFor("worker_test_compensation"), projection, writer, checker, forward, o, w, e, run, config.StoreID, config.ModelID, request, mode)
		return
	}
	if started := call("start", map[string]any{}); started["send_permit"] != true {
		t.Fatal("native74 first send permit")
	}
	if repeated := call("start", map[string]any{}); repeated["send_permit"] != false {
		t.Fatal("native74 duplicate send permit")
	}
	var action string
	if err := owner.QueryRow(ctx, `SELECT action_key FROM zasp_temporal74.run_owners WHERE run_id=$1`, run).Scan(&action); err != nil {
		t.Fatal(err)
	}
	candidate, _ := json.Marshal(map[string]any{"version": 1, "summary": "Run the pinned existing test", "steps": []any{map[string]any{"index": 0, "action": action, "target_id": testID}}})
	response, _ := json.Marshal(map[string]any{"id": "worker74-controlled-response", "model": "openai/gpt-5-mini", "choices": []any{map[string]any{"index": 0, "finish_reason": "stop", "message": map[string]any{"role": "assistant", "content": string(candidate)}}}, "usage": map[string]any{"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30, "cost": 0.00003}})
	call("result", map[string]any{"raw": string(response)})
	settled := call("settle", map[string]any{})
	call("artifacts", map[string]any{"input_version": "worker74-input-v1", "output_version": "worker74-output-v1", "output_digest": settled["output_digest"]})
	if receipt := call("admit", map[string]any{}); receipt["outcome"] != "admitted" {
		t.Fatal("native74 complete admission")
	}
	var nativeCapture bool
	if err := owner.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(o.status='captured_inactive' AND o.family='test74' AND o.delegation->>'purpose'='approval_notification_delivery' AND public.zasp_valid_product_id(o.delegation->>'task_id') AND o.delegation->>'grantor_id'=o.facts->>'grantor_id' AND o.delegation->>'principal_id'=o.facts->>'principal_id' AND o.payload_digest=n.payload_digest AND o.destination_url=n.destination_url AND o.secret_reference=n.secret_reference AND n.attempt=0 AND n.state='pending' AND jsonb_array_length(o.facts->'checks')>=2) FROM zasp_approval_maintenance.origins o JOIN public.zasp_security_agent_approval_notifications n USING(organization_id,workspace_id,environment_id,delivery_id) WHERE o.run_id=$1`, run).Scan(&nativeCapture); err != nil || !nativeCapture {
		t.Fatal("genuine signed74 admission failed inactive origin capture", err)
	}
	var projected bool
	if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_approval_maintenance.delivery_grants WHERE organization_id=$1)`, o).Scan(&projected); err != nil || projected {
		t.Fatal("inactive74 capture issued delegation", err)
	}
	if err := owner.QueryRow(ctx, `SELECT p.total_tokens=30 AND p.cost_nano_credits=30000 AND p.settled_at IS NOT NULL AND (SELECT count(*)=1 FROM zasp_security_agent_steps WHERE run_id=$1 AND step_index=0 AND action_key=$2) AND NOT EXISTS(SELECT 1 FROM zasp_sa_multistep_runs WHERE run_id=$1) FROM zasp_temporal74.provider_reservations p WHERE run_id=$1`, run, action).Scan(&one); err != nil || !one {
		t.Fatal("native74 accounting and single canonical step", err)
	}
	if seam != nil {
		seam.afterAdmission(forward, poolFor, func() {
			if _, err := authorization.Reconcile(ctx, projection, writer, o, config.StoreID, config.ModelID); err != nil {
				t.Fatal("controlled projection delivery", err)
			}
		})
		return
	}
	approveApprovalOriginSupervisedTest74(t, ctx, owner, o, w, e, run)
	if mode == "effect" || mode == "adapter" || mode == "adapter-complete" || strings.HasPrefix(mode, "adapter-http") || mode == "lifecycle-reserved" || mode == "lifecycle-pending" || mode == "lifecycle-status-max" {
		assertWorkerTest74UnsignedEffect(t, ctx, owner, forwardPool, o, w, e, run)
		var afterDispatch func(map[string]any) bool
		var afterRevocation func(*authorization.WorkerExecutor)
		var afterReserve []func()
		if mode == "lifecycle-status-max" {
			afterDispatch = func(linked map[string]any) bool {
				worker, adapter := orderedTestConnections(t, ctx, owner)
				_ = worker.Close(ctx)
				_ = adapter.Close(ctx)
				compKey, _ := authorization.NewWorkerKey(authorization.CapturedCompensation, bytes.Repeat([]byte{73}, 32))
				if _, err := owner.Exec(ctx, `SELECT zasp_authorization80_worker.register_verifier($1,$2,$3)`, string(authorization.CapturedCompensation), compKey.Version(), compKey.Verifier()); err != nil {
					t.Fatal(err)
				}
				if _, err := authorization.Reconcile(ctx, projection, writer, o, config.StoreID, config.ModelID); err != nil {
					t.Fatal(err)
				}
				machine, err := authorization.NewWorkerAdapter(poolFor("ordered_test_red_adapter"), checker, config.StoreID, config.ModelID, key)
				if err != nil {
					t.Fatal(err)
				}
				comp, err := authorization.NewWorkerExecutor(poolFor("worker_test_compensation"), nil, "", "", compKey)
				if err != nil {
					t.Fatal(err)
				}
				assertWorkerMaximumRecoveryStatus(t, ctx, owner, machine, comp, o, w, e, run, linked)
				lifecycleChildCompleted = true
				return true
			}
		}
		if mode == "lifecycle-reserved" || mode == "lifecycle-pending" {
			consume := func(name string) {
				key, _ := authorization.NewWorkerKey(authorization.CapturedCompensation, bytes.Repeat([]byte{73}, 32))
				if _, err := owner.Exec(ctx, `SELECT zasp_authorization80_worker.register_verifier($1,$2,$3)`, string(authorization.CapturedCompensation), key.Version(), key.Verifier()); err != nil {
					t.Fatal(err)
				}
				runWorkerTest74ProductChild(t, ctx, owner, run, name)
				lifecycleChildCompleted = true
			}
			if mode == "lifecycle-reserved" {
				afterReserve = []func(){func() { consume("TestP7WorkerSingleTestReservedLifecycleNative") }}
			} else {
				afterDispatch = func(map[string]any) bool { consume("TestP7WorkerSingleTestPendingLifecycleNative"); return true }
			}
		}
		if mode == "adapter" || mode == "adapter-complete" {
			afterDispatch = func(linked map[string]any) bool {
				assertWorkerTest74UnsignedAdapter(t, ctx, owner, o, w, e, run, linked, func() *authorization.WorkerExecutor {
					machine, err := authorization.NewWorkerAdapter(poolFor("ordered_test_red_adapter"), workerObservedChecker{checker, t}, config.StoreID, config.ModelID, key)
					if err != nil {
						t.Fatal(err)
					}
					return machine
				})
				if mode == "adapter-complete" {
					afterRevocation = func(compensation *authorization.WorkerExecutor) {
						assertWorkerTest74CapturedComplete(t, ctx, owner, compensation, o, w, e, run, linked)
					}
				}
				return false
			}
		}
		if strings.HasPrefix(mode, "adapter-http") {
			afterDispatch = func(linked map[string]any) bool {
				worker, adapter := orderedTestConnections(t, ctx, owner)
				_ = worker.Close(ctx)
				_ = adapter.Close(ctx)
				compKey, _ := authorization.NewWorkerKey(authorization.CapturedCompensation, bytes.Repeat([]byte{73}, 32))
				if _, err := owner.Exec(ctx, `SELECT zasp_authorization80_worker.register_verifier($1,$2,$3)`, string(authorization.CapturedCompensation), compKey.Version(), compKey.Verifier()); err != nil {
					t.Fatal(err)
				}
				if _, err := authorization.Reconcile(ctx, projection, writer, o, config.StoreID, config.ModelID); err != nil {
					t.Fatal(err)
				}
				runWorkerAdapterHTTPChild(t, ctx, owner, config, o, w, e, run, linked, mode == "adapter-http-diagnostic", mode == "adapter-http-receipt" || mode == "adapter-http-settlement")
				if mode == "adapter-http-settlement" {
					assertWorkerRecoveredArtifactNative(t, ctx, owner, linked["test_run_id"].(string))
				}
				if mode == "adapter-http-receipt" || mode == "adapter-http-settlement" {
					assertWorkerCompletedReceiptNative(t, ctx, owner, poolFor("worker_test_compensation"), linked["test_run_id"].(string))
				}
				if mode == "adapter-http-settlement" || mode == "adapter-http-lifecycle-diagnostic" {
					runWorkerRecoveredProductChild(t, ctx, owner, run)
				}
				return true
			}
		}
		assertWorkerTest74SignedEffect(t, ctx, owner, forwardPool, poolFor("worker_test_compensation"), forward, o, w, e, run, mode != "adapter-http-diagnostic" && mode != "adapter-http-receipt" && mode != "adapter-http-settlement" && mode != "adapter-http-lifecycle-diagnostic" && !strings.HasPrefix(mode, "lifecycle-"), func() {
			if _, err := authorization.Reconcile(ctx, projection, writer, o, config.StoreID, config.ModelID); err != nil {
				t.Fatal("normal effect projection", err)
			}
		}, afterDispatch, func(compensation *authorization.WorkerExecutor) {
			if afterRevocation != nil {
				afterRevocation(compensation)
			}
		}, afterReserve...)
	}
	if strings.HasPrefix(mode, "adapter-http") {
		t.Log("actual74 planning fixture uses controlled native response input; the adapter child separately consumes actual HTTPS")
	} else {
		t.Log("actual74 signed native planning admission/accounting and one send permit; this fixture uses controlled native response input, not HTTPS")
	}
}

// Original test74 human fixture identity is separate from the requester.
// Approval/notification/delegation/task rows are produced solely by their real writers.
func approveApprovalOriginSupervisedTest74(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e, run string) {
	t.Helper()
	var approval, requester string
	if err := owner.QueryRow(ctx, `SELECT a.approval_id,a.requester_id FROM public.zasp_security_agent_approvals a JOIN public.zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id) WHERE a.run_id=$1 AND a.state='pending' AND r.state='waiting_approval'`, run).Scan(&approval, &requester); err != nil {
		t.Fatal("genuine supervised74 pending approval unavailable")
	}
	cfg := owner.Config().Copy()
	cfg.User = "security_agent_v33_api_login"
	api, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal("genuine supervised74 API connection refused")
	}
	defer api.Close(ctx)
	source, requesterIdentity := public62GoRepository(t, api, o, w, e, requester)
	repository := &PostgresRepository{database: source.database, schema: SecurityAgentSessionIsolationSchemaVersion, securityAgentExecution: true}
	requesterIdentity.FreshAuthenticated = true
	requesterIdentity.FreshAuthExpiresAt = time.Now().UTC().Add(4 * time.Minute)
	q := SecurityAgentApprovalDecisionRequest{ApprovalID: approval, IdempotencyKey: "maintenance-supervised74-approve", ExpectedVersion: 1, Decision: "approved", FreshAuthAt: time.Now().UTC(), AuditID: "pid_f0740000-0000-4000-8000-000000000610", CorrelationID: "pid_f0740000-0000-4000-8000-000000000611", ReceiptID: "pid_f0740000-0000-4000-8000-000000000612"}
	if _, err := repository.DecideSecurityAgentApproval(ctx, requesterIdentity, q); err == nil {
		t.Fatal("genuine supervised74 self approval accepted")
	}
	const approver = "pid_f0740000-0000-4000-8000-000000000609"
	// Exact original test74 distinct human identity fixture; this is not a native task/delegation grant.
	if _, err := owner.Exec(ctx, `INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role) VALUES($4,$1,'test74-org','test74-approver','organization_admin');INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($4,$1,$2,$3,'Approver','["view","manage_workflows","run_tests"]')`, pgx.QueryExecModeSimpleProtocol, o, w, e, approver); err != nil {
		t.Fatal("original supervised74 human identity fixture refused")
	}
	_, identity := public62GoRepository(t, api, o, w, e, approver)
	identity.FreshAuthenticated = true
	identity.FreshAuthExpiresAt = time.Now().UTC().Add(4 * time.Minute)
	result, err := repository.DecideSecurityAgentApproval(ctx, identity, q)
	if err != nil || result.State != "approved" || result.Replayed {
		t.Fatal("genuine supervised74 fresh distinct human approval refused")
	}
	if replay, err := repository.DecideSecurityAgentApproval(ctx, identity, q); err != nil || replay.State != "approved" || !replay.Replayed {
		t.Fatal("genuine supervised74 approval replay refused")
	}
}
