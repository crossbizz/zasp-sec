package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const lifecycleControlsSQL = `SELECT public.zasp_production_security_agent_existing_tests_controls($1,$2,$3,$4,$5)`
const lifecycleSetControlSQL = `SELECT public.zasp_production_security_agent_existing_tests_set_control($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`

// This catches public controls omitted from55 and an activation fence left in
// place after public admission is installed. Only underlying test/global
// deployment prerequisites are seeded; definitions and tenant controls use API SQL.
func TestExistingTestLifecycleBatchPublicActivationPostgres(t *testing.T) {
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, testID, actor string) {
		pins := []any{migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()}
		var raw json.RawMessage
		if err := api.QueryRow(ctx, lifecycleControlsSQL, append([]any{o, w, e}, pins...)...).Scan(&raw); err != nil {
			t.Fatalf("public control read: %v", err)
		}
		var controls SecurityAgentExecutionControls
		if json.Unmarshal(raw, &controls) != nil {
			t.Fatal(string(raw))
		}
		keys := []string{}
		for _, control := range controls.Actions {
			keys = append(keys, control.ActionKey)
			if (control.ActionKey == "run_test" || control.ActionKey == "rerun_test") && (control.Enabled || control.Version != 0) {
				t.Fatal("test controls enabled without public mutation")
			}
		}
		want := []string{"create_temporary_policy", "isolate_session", "rerun_test", "revoke_integration_connection", "run_test", "update_finding_response"}
		if !reflect.DeepEqual(keys, want) {
			t.Fatalf("control keys=%v", keys)
		}
		if !controls.Global.Enabled {
			t.Fatal("fixture deployment-global prerequisite disabled")
		}
		seq := 0
		next := func() string { seq++; return fmt.Sprintf("pid_8ba00000-0000-4000-8000-%012d", seq) }
		control := func(target, key string, version int64) {
			t.Helper()
			args := append([]any{o, w, e, actor, "lifecycle-control-" + next(), target, key, true, version, time.Now().UTC().Add(4 * time.Minute), next(), next(), next()}, pins...)
			if err := api.QueryRow(ctx, lifecycleSetControlSQL, args...).Scan(&raw); err != nil {
				t.Fatalf("enable %s: %v", key, err)
			}
		}
		control("environment", "*", controls.Environment.Version)
		db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
		if err != nil {
			t.Fatal(err)
		}
		repository, err := NewSecurityAgentPostgresRepository(db)
		if err != nil {
			t.Fatal(err)
		}
		identity := fixtureRequestIdentity(t)
		orgID, _ := domain.ParseProductID(o)
		wsID, _ := domain.ParseProductID(w)
		envID, _ := domain.ParseProductID(e)
		identity.Scope, _ = domain.NewScope(orgID, wsID, envID)
		identity.PrincipalID, _ = domain.ParseProductID(actor)
		for _, action := range []string{"run_test", "rerun_test"} {
			id := next()
			createExistingTestLifecycleDraft(t, ctx, api, o, w, e, id, testID, actor, action)
			activate := func(version int64, mode string) error {
				return api.QueryRow(ctx, existingTestActivateSQL, append([]any{o, w, e, id, actor, "lifecycle-activate-" + next(), version, mode, time.Now().UTC().Add(4 * time.Minute), next(), next(), next()}, pins...)...).Scan(&raw)
			}
			if err := activate(1, "validated"); err != nil {
				t.Fatal(err)
			}
			before := existingTestActivationSnapshot(t, ctx, owner, o, w, e, id)
			if err := activate(2, "supervised"); err == nil {
				t.Fatal("missing action control accepted")
			}
			if !equalIntegrationJSON(before, existingTestActivationSnapshot(t, ctx, owner, o, w, e, id)) {
				t.Fatal("control refusal changed state")
			}
			control("action", action, 0)
			if err := activate(2, "supervised"); err != nil {
				t.Fatalf("supervised %s: %v", action, err)
			}
			if state, err := repository.GetSecurityAgentActivation(ctx, identity, id); err != nil || !state.Enabled || state.Activation != "supervised" {
				t.Fatalf("supervised %s readback: %+v %v", action, state, err)
			}
			if err := activate(3, "autonomous"); err != nil {
				t.Fatalf("autonomous %s: %v", action, err)
			}
			if state, err := repository.GetSecurityAgentActivation(ctx, identity, id); err != nil || !state.Enabled || state.Activation != "autonomous" {
				t.Fatalf("autonomous %s readback: %+v %v", action, state, err)
			}
		}
	})
}

// Both callers must meet at one scoped receipt, not create a second run.
func TestExistingTestLifecycleBatchAdmissionPostgres(t *testing.T) {
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, testID, actor string) {
		config := owner.Config().Copy()
		config.User = "security_agent_v33_worker_login"
		worker, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close(context.Background())
		var raw json.RawMessage
		if err := worker.QueryRow(ctx, `SELECT public.zasp_production_security_agent_existing_tests_schedule($1,$2,$3,$4)`, "lifecycle-scheduler", 1, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()).Scan(&raw); err != nil {
			t.Fatalf("registered55 scheduler unavailable: %v", err)
		}
		const finding = "pid_8bb10000-0000-4000-8000-000000000001"
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$4,'posture','credential','Public admission','high','open')`, o, w, e, finding); err != nil {
			t.Fatal(err)
		}
		for index, action := range []string{"run_test", "rerun_test"} {
			id := fmt.Sprintf("pid_8bb20000-0000-4000-8000-%012d", index+1)
			lifecycleEnableTestControl(t, ctx, api, o, w, e, actor, action, index+1)
			createExistingTestLifecycleDraft(t, ctx, api, o, w, e, id, testID, actor, action)
			lifecycleActivateDraft(t, ctx, api, o, w, e, id, actor, index+1)
			pins := []any{migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()}
			args := append([]any{o, w, e, id, actor, "lifecycle-manual-" + action, int64(3), fmt.Sprintf("pid_8bb30000-0000-4000-8000-%012d", index+1), "finding", finding, fmt.Sprintf("pid_8bb40000-0000-4000-8000-%012d", index+1), fmt.Sprintf("pid_8bb50000-0000-4000-8000-%012d", index+1), fmt.Sprintf("pid_8bb60000-0000-4000-8000-%012d", index+1)}, pins...)
			if err := api.QueryRow(ctx, postgresExistingTestRunSQL, args...).Scan(&raw); err != nil {
				t.Fatalf("public manual %s: %v", action, err)
			}
			var result SecurityAgentRunResult
			if json.Unmarshal(raw, &result) != nil || result.ID != args[7] || result.Replayed || result.State != "queued" {
				t.Fatalf("invalid admission: %s", raw)
			}
			if err := api.QueryRow(ctx, postgresExistingTestRunSQL, args...).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			if json.Unmarshal(raw, &result) != nil || !result.Replayed || result.ID != args[7] {
				t.Fatal("manual replay changed run")
			}
			if err := worker.QueryRow(ctx, `SELECT public.zasp_production_security_agent_existing_tests_schedule($1,$2,$3,$4)`, "lifecycle-scheduler", 1, pins[0], pins[1]).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			var count int
			if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$4)`, o, w, e, id).Scan(&count); err != nil || count != 1 {
				t.Fatalf("manual/automatic duplicated: %d %v", count, err)
			}
		}
	})
}

func lifecycleEnableTestControl(t *testing.T, ctx context.Context, api *pgx.Conn, o, w, e, actor, action string, seq int) {
	t.Helper()
	var raw json.RawMessage
	if seq == 1 {
		if err := api.QueryRow(ctx, lifecycleControlsSQL, o, w, e, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var controls SecurityAgentExecutionControls
		if json.Unmarshal(raw, &controls) != nil {
			t.Fatal(string(raw))
		}
		if err := api.QueryRow(ctx, lifecycleSetControlSQL, o, w, e, actor, "admission-environment-control", "environment", "*", true, controls.Environment.Version, time.Now().UTC().Add(4*time.Minute), "pid_8bc10000-0000-4000-8000-000000000099", "pid_8bc20000-0000-4000-8000-000000000099", "pid_8bc30000-0000-4000-8000-000000000099", migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()).Scan(&raw); err != nil {
			t.Fatal(err)
		}
	}
	err := api.QueryRow(ctx, lifecycleSetControlSQL, o, w, e, actor, "admission-control-"+action, "action", action, true, int64(0), time.Now().UTC().Add(4*time.Minute), fmt.Sprintf("pid_8bc10000-0000-4000-8000-%012d", seq), fmt.Sprintf("pid_8bc20000-0000-4000-8000-%012d", seq), fmt.Sprintf("pid_8bc30000-0000-4000-8000-%012d", seq), migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()).Scan(&raw)
	if err != nil {
		t.Fatal(err)
	}
}

func TestExistingTestLifecycleBatchSafetyPostgres(t *testing.T) {
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, testID, actor string) {
		const id = "pid_8c000000-0000-4000-8000-000000000001"
		const finding = "pid_8c000000-0000-4000-8000-000000000002"
		pins := []any{migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()}
		lifecycleEnableTestControl(t, ctx, api, o, w, e, actor, "run_test", 1)
		createExistingTestLifecycleDraft(t, ctx, api, o, w, e, id, testID, actor, "run_test")
		var raw json.RawMessage
		activate := append([]any{o, w, e, id, actor, "safety-validation-0001", int64(1), "validated", time.Now().UTC().Add(4 * time.Minute), "pid_8c010000-0000-4000-8000-000000000001", "pid_8c020000-0000-4000-8000-000000000001", "pid_8c030000-0000-4000-8000-000000000001"}, pins...)
		if err := api.QueryRow(ctx, existingTestActivateSQL, activate...).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		activate[5], activate[6], activate[7] = "safety-activation-0001", int64(2), "supervised"
		activate[9], activate[10], activate[11] = "pid_8c010000-0000-4000-8000-000000000002", "pid_8c020000-0000-4000-8000-000000000002", "pid_8c030000-0000-4000-8000-000000000002"
		assertRefused := func(query string, args []any) {
			t.Helper()
			before := existingTestActivationSnapshot(t, ctx, owner, o, w, e, id)
			var pg *pgconn.PgError
			err := api.QueryRow(ctx, query, args...).Scan(&raw)
			if !errors.As(err, &pg) {
				t.Fatalf("expected SQL refusal: %s %v", raw, err)
			}
			if !equalIntegrationJSON(before, existingTestActivationSnapshot(t, ctx, owner, o, w, e, id)) {
				t.Fatal("refusal changed durable authority")
			}
		}
		deadline := time.Now().UTC().Add(2 * time.Second)
		late := append([]any(nil), activate...)
		late[8] = deadline
		before := existingTestActivationSnapshot(t, ctx, owner, o, w, e, id)
		err := existingTestAcceptanceWait(t, ctx, owner, api, id, "audit_lifecycle", func() error { return api.QueryRow(ctx, existingTestActivateSQL, late...).Scan(&raw) }, deadline)
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "40001" || !equalIntegrationJSON(before, existingTestActivationSnapshot(t, ctx, owner, o, w, e, id)) {
			t.Fatalf("activation post-lock expiry accepted: %v", err)
		}
		if err := api.QueryRow(ctx, existingTestActivateSQL, activate...).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if err := api.QueryRow(ctx, existingTestActivateSQL, activate...).Scan(&raw); err != nil {
			t.Fatalf("activation replay: %v", err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_request_receipts SET intent=jsonb_set(intent,'{fresh_auth_expires_at}',to_jsonb(clock_timestamp()-interval '1 second')) WHERE (organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key)=($1,$2,$3,$4,'activateSecurityAgent','safety-activation-0001')`, o, w, e, actor); err != nil {
			t.Fatal(err)
		}
		assertRefused(existingTestActivateSQL, activate)
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$4,'posture','credential','Safety trigger','high','open')`, o, w, e, finding); err != nil {
			t.Fatal(err)
		}
		runArgs := append([]any{o, w, e, id, actor, "safety-run-00000001", int64(3), "pid_8c040000-0000-4000-8000-000000000001", "finding", finding, "pid_8c050000-0000-4000-8000-000000000001", "pid_8c060000-0000-4000-8000-000000000001", "pid_8c070000-0000-4000-8000-000000000001"}, pins...)
		for _, change := range []struct {
			index int
			value any
		}{{2, "pid_8c990000-0000-4000-8000-000000000001"}, {6, int64(2)}, {9, "pid_8c990000-0000-4000-8000-000000000002"}, {14, "forged"}} {
			args := append([]any(nil), runArgs...)
			args[change.index] = change.value
			assertRefused(postgresExistingTestRunSQL, args)
		}
		for _, mutation := range []struct{ sql, restore string }{
			{`UPDATE zasp_red_team_definitions SET version=2 WHERE definition_id=$1`, `UPDATE zasp_red_team_definitions SET version=1 WHERE definition_id=$1`},
			{`UPDATE zasp_red_team_definitions SET enabled=false WHERE definition_id=$1`, `UPDATE zasp_red_team_definitions SET enabled=true WHERE definition_id=$1`},
			{`UPDATE zasp_attack_lab_credential_bindings SET state='revoked' WHERE target_id='pid_89000011-0000-4000-8000-000000000001' AND $1::text IS NOT NULL`, `UPDATE zasp_attack_lab_credential_bindings SET state='active' WHERE target_id='pid_89000011-0000-4000-8000-000000000001' AND $1::text IS NOT NULL`},
		} {
			if _, err := owner.Exec(ctx, mutation.sql, testID); err != nil {
				t.Fatal(err)
			}
			assertRefused(postgresExistingTestRunSQL, runArgs)
			if _, err := owner.Exec(ctx, mutation.restore, testID); err != nil {
				t.Fatal(err)
			}
		}
		if err := api.QueryRow(ctx, postgresExistingTestRunSQL, runArgs...).Scan(&raw); err != nil {
			t.Fatalf("positive after refusals: %v", err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_risk_findings SET version=version+1 WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)`, o, w, e, finding); err != nil {
			t.Fatal(err)
		}
		assertRefused(postgresExistingTestRunSQL, runArgs)
		controlArgs := append([]any{o, w, e, actor, "safety-control-off-0001", "action", "run_test", false, int64(1), time.Now().UTC().Add(4 * time.Minute), "pid_8c080000-0000-4000-8000-000000000001", "pid_8c090000-0000-4000-8000-000000000001", "pid_8c100000-0000-4000-8000-000000000001"}, pins...)
		deadline = time.Now().UTC().Add(2 * time.Second)
		lateControl := append([]any(nil), controlArgs...)
		lateControl[9] = deadline
		before = existingTestActivationSnapshot(t, ctx, owner, o, w, e, id)
		err = existingTestAcceptanceWait(t, ctx, owner, api, id, "audit_lifecycle", func() error { return api.QueryRow(ctx, lifecycleSetControlSQL, lateControl...).Scan(&raw) }, deadline)
		if !errors.As(err, &pg) || pg.Code != "40001" || !equalIntegrationJSON(before, existingTestActivationSnapshot(t, ctx, owner, o, w, e, id)) {
			t.Fatalf("control post-lock expiry accepted: %v", err)
		}
		if err := api.QueryRow(ctx, lifecycleSetControlSQL, controlArgs...).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		assertRefused(postgresExistingTestRunSQL, runArgs)
		changed := append([]any(nil), controlArgs...)
		changed[7] = true
		assertRefused(lifecycleSetControlSQL, changed)
		stale := append([]any(nil), controlArgs...)
		stale[4] = "safety-control-stale-001"
		assertRefused(lifecycleSetControlSQL, stale)
		// A disabled action stops new admission; stored definition/history reads stay usable.
		if err := api.QueryRow(ctx, postgresSecurityAgentDefinitionActivationSQL, o, w, e, id).Scan(&raw); err != nil {
			t.Fatalf("control-off history: %v", err)
		}
		db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
		if err != nil {
			t.Fatal(err)
		}
		repo, err := NewSecurityAgentPostgresRepository(db)
		if err != nil {
			t.Fatal(err)
		}
		identity := fixtureRequestIdentity(t)
		a, _ := domain.ParseProductID(o)
		b, _ := domain.ParseProductID(w)
		c, _ := domain.ParseProductID(e)
		identity.Scope, _ = domain.NewScope(a, b, c)
		identity.PrincipalID, _ = domain.ParseProductID(actor)
		if state, err := repo.GetSecurityAgentActivation(ctx, identity, id); err != nil || !state.Enabled {
			t.Fatalf("control-off enabled readback: %+v %v", state, err)
		}
		if history, err := repo.GetSecurityAgentRun(ctx, identity, runArgs[7].(string)); err != nil || history.Run.ID != runArgs[7] {
			t.Fatalf("control-off run history: %+v %v", history, err)
		}
	})
}
func lifecycleActivateDraft(t *testing.T, ctx context.Context, api *pgx.Conn, o, w, e, id, actor string, seq int) {
	t.Helper()
	var raw json.RawMessage
	for index, mode := range []string{"validated", "supervised"} {
		suffix := seq*10 + index
		err := api.QueryRow(ctx, existingTestActivateSQL, o, w, e, id, actor, "admission-activate-"+id+mode, int64(index+1), mode, time.Now().UTC().Add(4*time.Minute), fmt.Sprintf("pid_8bd10000-0000-4000-8000-%012d", suffix), fmt.Sprintf("pid_8bd20000-0000-4000-8000-%012d", suffix), fmt.Sprintf("pid_8bd30000-0000-4000-8000-%012d", suffix), migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()).Scan(&raw)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestExistingTestLifecycleBatchTriggerMatrixPostgres(t *testing.T) {
	runExistingTestLifecycleTriggerMatrix(t, "")
}

func TestExistingTestLifecycleBatchLateAuthorityPostgres(t *testing.T) {
	for _, mode := range []string{"request_receipt", "execution_state", "delegated_wait"} {
		t.Run(mode, func(t *testing.T) { runExistingTestLifecycleTriggerMatrix(t, mode) })
	}
}

func runExistingTestLifecycleTriggerMatrix(t *testing.T, lateMode string) {
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, testID, actor string) {
		config := owner.Config().Copy()
		config.User = "security_agent_v33_worker_login"
		worker, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close(context.Background())
		pins := []any{migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()}
		const finding = "pid_8be00000-0000-4000-8000-000000000001"
		const session = "pid_8be00000-0000-4000-8000-000000000002"
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$4,'posture','credential','Matrix evidence','high','open');
 UPDATE zasp_risk_attack_paths SET state='observed' WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,'pid_6a000005-0000-4000-8000-000000000005');
 INSERT INTO zasp_gateway_devices(organization_id,workspace_id,environment_id,id,name,state) VALUES($1,$2,$3,'pid_8be10000-0000-4000-8000-000000000001','Lifecycle gateway','active');
 INSERT INTO zasp_gateway_enrollment_tokens(organization_id,workspace_id,environment_id,id,device_id,audience,salt,token_hash,expires_at) VALUES($1,$2,$3,'pid_8be20000-0000-4000-8000-000000000001','pid_8be10000-0000-4000-8000-000000000001','runtime-gateway-enroll',decode(repeat('01',16),'hex'),decode(repeat('ab',32),'hex'),clock_timestamp()+interval '1 hour');
 INSERT INTO zasp_gateway_credentials(organization_id,workspace_id,environment_id,id,device_id,enrollment_token_id,enrollment_digest,audience,key_reference,public_key,issued_at,expires_at,format_version,credential_generation,key_id,algorithm,v15_issued_at) VALUES($1,$2,$3,'pid_8be30000-0000-4000-8000-000000000001','pid_8be10000-0000-4000-8000-000000000001','pid_8be20000-0000-4000-8000-000000000001',decode(repeat('cd',32),'hex'),'runtime-gateway','ref:gateway/public/lifecycle',decode(repeat('04',32),'hex'),clock_timestamp()-interval '1 hour',clock_timestamp()+interval '1 hour',1,1,'lifecycle','Ed25519',clock_timestamp()-interval '1 hour');
 INSERT INTO zasp_runtime_gateway_events(organization_id,workspace_id,environment_id,device_id,credential_id,event_id,sequence,request_digest,policy_version,decision,action_kind,classification,occurred_at) VALUES($1,$2,$3,'pid_8be10000-0000-4000-8000-000000000001','pid_8be30000-0000-4000-8000-000000000001','pid_8be40000-0000-4000-8000-000000000001',1,decode(repeat('fa',32),'hex'),1,'block','http',jsonb_build_object('category','security','route_class','runtime','resource_class','session','outcome','gateway','session_id',$5),clock_timestamp())`, pgx.QueryExecModeSimpleProtocol, o, w, e, finding, session); err != nil {
			t.Fatal(err)
		}
		db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
		if err != nil {
			t.Fatal(err)
		}
		repository, err := NewSecurityAgentPostgresRepository(db)
		if err != nil {
			t.Fatal(err)
		}
		// Two exact event versions share one session. Once the newest evidence has
		// been admitted, an older unreceipted event must not become fresh authority.
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_runtime_gateway_events(organization_id,workspace_id,environment_id,device_id,credential_id,event_id,sequence,request_digest,policy_version,decision,action_kind,classification,occurred_at) SELECT organization_id,workspace_id,environment_id,device_id,credential_id,'pid_8be40000-0000-4000-8000-000000000002',2,request_digest,policy_version,decision,action_kind,classification,clock_timestamp() FROM zasp_runtime_gateway_events WHERE event_id='pid_8be40000-0000-4000-8000-000000000001'`); err != nil {
			t.Fatal(err)
		}
		identity := fixtureRequestIdentity(t)
		orgID, _ := domain.ParseProductID(o)
		wsID, _ := domain.ParseProductID(w)
		envID, _ := domain.ParseProductID(e)
		identity.Scope, _ = domain.NewScope(orgID, wsID, envID)
		identity.PrincipalID, _ = domain.ParseProductID(actor)
		seq := 0
		for actionIndex, action := range []string{"run_test", "rerun_test"} {
			lifecycleEnableTestControl(t, ctx, api, o, w, e, actor, action, actionIndex+1)
			for _, kind := range []string{"finding", "attack_path", "runtime_decision"} {
				for _, automatic := range []bool{false, true} {
					seq++
					n := seq
					// Automatic late-wait cases own their single runtime definition.
					// The base matrix separately covers the earlier manual definition.
					if n == 5 && (lateMode == "execution_state" || lateMode == "delegated_wait") {
						continue
					}
					id := fmt.Sprintf("pid_8bf00000-0000-4000-8000-%012d", n)
					trigger, source, manualKind := finding, "credential", kind
					if kind == "attack_path" {
						trigger, source = "pid_6a000005-0000-4000-8000-000000000005", "observed"
					}
					if kind == "runtime_decision" {
						trigger, source, manualKind = session, "gateway", "session"
					}
					createExistingTestLifecycleTriggerDraft(t, ctx, api, o, w, e, id, testID, actor, action, kind, source)
					lifecycleActivateDraft(t, ctx, api, o, w, e, id, actor, n)
					if state, err := repository.GetSecurityAgentActivation(ctx, identity, id); err != nil || !state.Enabled || state.Activation != "supervised" {
						t.Fatalf("public readback: %+v %v", state, err)
					}
					request := SecurityAgentRunRequest{DefinitionID: id, IdempotencyKey: fmt.Sprintf("matrix-manual-%04d", n), ExpectedVersion: 3, RunID: fmt.Sprintf("pid_8bf10000-0000-4000-8000-%012d", n), TriggerKind: manualKind, TriggerID: trigger, AuditID: fmt.Sprintf("pid_8bf20000-0000-4000-8000-%012d", n), CorrelationID: fmt.Sprintf("pid_8bf30000-0000-4000-8000-%012d", n), ReceiptID: fmt.Sprintf("pid_8bf40000-0000-4000-8000-%012d", n)}
					if (lateMode == "request_receipt" && n == 5) || ((lateMode == "execution_state" || lateMode == "delegated_wait") && n == 6) {
						var legacyControlVersion int64
						if lateMode == "delegated_wait" {
							var raw json.RawMessage
							if err := api.QueryRow(ctx, lifecycleControlsSQL, o, w, e, pins[0], pins[1]).Scan(&raw); err != nil {
								t.Fatal(err)
							}
							var controls SecurityAgentExecutionControls
							if json.Unmarshal(raw, &controls) != nil {
								t.Fatal(string(raw))
							}
							for _, control := range controls.Actions {
								if control.ActionKey == "update_finding_response" {
									legacyControlVersion = control.Version
								}
							}
							if err := api.QueryRow(ctx, lifecycleSetControlSQL, o, w, e, actor, "late-enable-legacy-control", "action", "update_finding_response", true, legacyControlVersion, time.Now().UTC().Add(4*time.Minute), "pid_8bfc0000-0000-4000-8000-000000000001", "pid_8bfd0000-0000-4000-8000-000000000001", "pid_8bfe0000-0000-4000-8000-000000000001", pins[0], pins[1]).Scan(&raw); err != nil {
								t.Fatal(err)
							}
							legacyControlVersion++
							createExistingTestLifecycleDraft(t, ctx, api, o, w, e, "pid_8bf00000-0000-4000-8000-000000000099", testID, actor, "update_finding_response")
							lifecycleActivateDraft(t, ctx, api, o, w, e, "pid_8bf00000-0000-4000-8000-000000000099", actor, 99)
						}
						// Production ingestion accepts timestamps up to 30s ahead. This
						// already recorded event becomes eligible while the final write waits.
						deadline := time.Now().UTC().Add(2 * time.Second)
						if _, err := owner.Exec(ctx, `INSERT INTO zasp_runtime_gateway_events(organization_id,workspace_id,environment_id,device_id,credential_id,event_id,sequence,request_digest,policy_version,decision,action_kind,classification,occurred_at) SELECT organization_id,workspace_id,environment_id,device_id,credential_id,'pid_8be40000-0000-4000-8000-000000000003',3,request_digest,policy_version,decision,action_kind,classification,$1 FROM zasp_runtime_gateway_events WHERE event_id='pid_8be40000-0000-4000-8000-000000000001'`, deadline); err != nil {
							t.Fatal(err)
						}
						before := existingTestActivationSnapshot(t, ctx, owner, o, w, e, id)
						var lateRaw json.RawMessage
						connection := api
						invoke := func() error { _, err := repository.RunSecurityAgent(ctx, identity, request); return err }
						if automatic {
							connection = worker
							limit := 1
							if lateMode == "delegated_wait" {
								limit = 2
							}
							invoke = func() error {
								err := worker.QueryRow(ctx, `SELECT public.zasp_production_security_agent_existing_tests_schedule($1,$2,$3,$4)`, "late-worker", limit, pins[0], pins[1]).Scan(&lateRaw)
								t.Logf("%s scheduler returned %s, err=%v", lateMode, lateRaw, err)
								return err
							}
						}
						err := lifecycleFinalWriteWait(t, ctx, owner, connection, lateMode, deadline, invoke)
						if (!automatic || lateMode == "delegated_wait") && err == nil || automatic && lateMode != "delegated_wait" && (err != nil || string(lateRaw) != `{"created": 0}`) {
							t.Fatalf("%s admitted stale runtime authority: result=%s err=%v", lateMode, lateRaw, err)
						}
						if !equalIntegrationJSON(before, existingTestActivationSnapshot(t, ctx, owner, o, w, e, id)) {
							t.Fatalf("%s refusal retained partial admission", lateMode)
						}
						if lateMode == "delegated_wait" {
							var raw json.RawMessage
							if err := api.QueryRow(ctx, lifecycleSetControlSQL, o, w, e, actor, "late-disable-legacy-control", "action", "update_finding_response", false, legacyControlVersion, time.Now().UTC().Add(4*time.Minute), "pid_8bfc0000-0000-4000-8000-000000000002", "pid_8bfd0000-0000-4000-8000-000000000002", "pid_8bfe0000-0000-4000-8000-000000000002", pins[0], pins[1]).Scan(&raw); err != nil {
								t.Fatal(err)
							}
						}
					}
					if automatic {
						var raw json.RawMessage
						if err := worker.QueryRow(ctx, `SELECT public.zasp_production_security_agent_existing_tests_schedule($1,$2,$3,$4)`, "matrix-worker", 1, pins[0], pins[1]).Scan(&raw); err != nil {
							t.Fatal(err)
						}
						if string(raw) != `{"created": 1}` {
							t.Fatalf("automatic %s %s: %s", action, kind, raw)
						}
					}
					result, err := repository.RunSecurityAgent(ctx, identity, request)
					if err != nil || result.Replayed != automatic {
						t.Fatalf("%s %s auto=%t: %+v %v", action, kind, automatic, result, err)
					}
					var count int
					if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_security_agent_trigger_receipts WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$4)`, o, w, e, id).Scan(&count); err != nil || count != 1 {
						t.Fatalf("dedup receipt count %d %v", count, err)
					}
					if n == 1 {
						lifecyclePrepareAdmitted(t, ctx, worker, o, w, e, result.ID, testID, action)
					}
					if kind == "runtime_decision" {
						if _, err := repository.CancelSecurityAgentRun(ctx, identity, SecurityAgentCancelRequest{RunID: result.ID, IdempotencyKey: fmt.Sprintf("matrix-cancel-%04d", n), ExpectedVersion: result.Version, AuditID: fmt.Sprintf("pid_8bf80000-0000-4000-8000-%012d", n), CorrelationID: fmt.Sprintf("pid_8bf90000-0000-4000-8000-%012d", n), ReceiptID: fmt.Sprintf("pid_8bfa0000-0000-4000-8000-%012d", n)}); err != nil {
							t.Fatal(err)
						}
						var raw json.RawMessage
						if err := worker.QueryRow(ctx, `SELECT public.zasp_production_security_agent_existing_tests_schedule($1,$2,$3,$4)`, "matrix-worker", 1, pins[0], pins[1]).Scan(&raw); err != nil {
							t.Fatal(err)
						}
						if string(raw) != `{"created": 0}` {
							t.Fatalf("stale runtime event admitted after newest: %s", raw)
						}
					}
				}
			}
		}
	})
}

func lifecyclePrepareAdmitted(t *testing.T, ctx context.Context, worker *pgx.Conn, o, w, e, r, testID, action string) {
	t.Helper()
	const workerID = "lifecycle-planner"
	const lease = "lifecycle-planner-lease-0001"
	db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
	if err != nil {
		t.Fatal(err)
	}
	repo, err := NewSecurityAgentWorkerRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := repo.ClaimSecurityAgentRuns(ctx, workerID, lease, 120, 1)
	if err != nil || len(claims) != 1 || claims[0].RunID != r {
		t.Fatalf("public admitted claim: %+v %v", claims, err)
	}
	planner, err := repo.LoadSecurityAgentPlannerContext(ctx, claims[0], workerID, lease)
	if err != nil || planner.ExistingTest == nil || planner.ExistingTest.DefinitionID != testID {
		t.Fatalf("admitted planner context: %+v %v", planner, err)
	}
	input, ok := decodeSecurityAgentDigest(planner.InputDigest)
	if !ok {
		t.Fatal("context digest absent")
	}
	candidate := json.RawMessage(`{"version":1,"summary":"Execute pinned existing test","steps":[{"index":0,"action":"` + action + `","target_id":"` + testID + `"}]}`)
	output := sha256.Sum256(candidate)
	var raw json.RawMessage
	if err := worker.QueryRow(ctx, existingTestAcceptSQL, o, w, e, r, workerID, lease, input, output[:], "fixture-model", "fixture-policy", candidate, "pid_8bf50000-0000-4000-8000-000000000001", time.Now().UTC().Add(5*time.Minute), "pid_8bf60000-0000-4000-8000-000000000001", "pid_8bf70000-0000-4000-8000-000000000001").Scan(&raw); err != nil {
		t.Fatalf("registered planner acceptance: %v", err)
	}
	var prepared SecurityAgentPrepareResult
	if json.Unmarshal(raw, &prepared) != nil || prepared.State != "waiting_approval" || prepared.RunID != r || prepared.ApprovalID == "" {
		t.Fatalf("public admitted preparation: %s", raw)
	}
}

// Publicly enabled legacy and test definitions compete for one caller limit.
// Foreign evidence and a disabled underlying test must not create partial work.
func TestExistingTestLifecycleBatchMixedSchedulePostgres(t *testing.T) {
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, testID, actor string) {
		const id = "pid_8d000000-0000-4000-8000-000000000001"
		const finding = "pid_8d100000-0000-4000-8000-000000000001"
		const foreignOrg = "pid_9a000001-0000-4000-8000-000000000001"
		const foreignWorkspace = "pid_9a000002-0000-4000-8000-000000000002"
		const foreignEnvironment = "pid_9a000003-0000-4000-8000-000000000003"
		config := owner.Config().Copy()
		config.User = "security_agent_v33_worker_login"
		worker, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close(context.Background())
		pins := []any{migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()}
		schedule := func(limit, want int) {
			t.Helper()
			var raw json.RawMessage
			if err := worker.QueryRow(ctx, `SELECT public.zasp_production_security_agent_existing_tests_schedule($1,$2,$3,$4)`, "mixed-lifecycle-worker", limit, pins[0], pins[1]).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			var got struct {
				Created int `json:"created"`
			}
			if json.Unmarshal(raw, &got) != nil || got.Created != want || got.Created > limit {
				t.Fatalf("schedule limit%d want%d: %s", limit, want, raw)
			}
		}
		lifecycleEnableTestControl(t, ctx, api, o, w, e, actor, "run_test", 1)
		createExistingTestLifecycleDraft(t, ctx, api, o, w, e, id, testID, actor, "run_test")
		lifecycleActivateDraft(t, ctx, api, o, w, e, id, actor, 1)
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$4,'posture','credential','Foreign scheduler evidence','high','open')`, foreignOrg, foreignWorkspace, foreignEnvironment, finding); err != nil {
			t.Fatal(err)
		}
		foreignBefore := existingTestActivationSnapshot(t, ctx, owner, foreignOrg, foreignWorkspace, foreignEnvironment, id)
		before := existingTestActivationSnapshot(t, ctx, owner, o, w, e, id)
		schedule(2, 0)
		if !equalIntegrationJSON(before, existingTestActivationSnapshot(t, ctx, owner, o, w, e, id)) {
			t.Fatal("foreign evidence mutated local admission")
		}
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$4,'posture','credential','Local scheduler evidence','high','open')`, o, w, e, finding); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_definitions SET enabled=false WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$4)`, o, w, e, testID); err != nil {
			t.Fatal(err)
		}
		before = existingTestActivationSnapshot(t, ctx, owner, o, w, e, id)
		schedule(2, 0)
		if !equalIntegrationJSON(before, existingTestActivationSnapshot(t, ctx, owner, o, w, e, id)) {
			t.Fatal("disabled binding left partial automatic work")
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_definitions SET enabled=true WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$4)`, o, w, e, testID); err != nil {
			t.Fatal(err)
		}
		var raw json.RawMessage
		if err := api.QueryRow(ctx, lifecycleControlsSQL, append([]any{o, w, e}, pins...)...).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var controls SecurityAgentExecutionControls
		if json.Unmarshal(raw, &controls) != nil {
			t.Fatal(string(raw))
		}
		var legacyVersion int64
		for _, control := range controls.Actions {
			if control.ActionKey == "update_finding_response" {
				legacyVersion = control.Version
			}
		}
		if err := api.QueryRow(ctx, lifecycleSetControlSQL, append([]any{o, w, e, actor, "mixed-legacy-control-0001", "action", "update_finding_response", true, legacyVersion, time.Now().UTC().Add(4 * time.Minute), "pid_8d200000-0000-4000-8000-000000000001", "pid_8d300000-0000-4000-8000-000000000001", "pid_8d400000-0000-4000-8000-000000000001"}, pins...)...).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		for index := 2; index <= 3; index++ {
			legacyID := fmt.Sprintf("pid_8d000000-0000-4000-8000-%012d", index)
			createExistingTestLifecycleDraft(t, ctx, api, o, w, e, legacyID, testID, actor, "update_finding_response")
			lifecycleActivateDraft(t, ctx, api, o, w, e, legacyID, actor, index)
		}
		schedule(2, 2)
		var testRuns, legacyRuns int
		if err := owner.QueryRow(ctx, `SELECT count(*) FILTER(WHERE definition_id=$4),count(*) FILTER(WHERE definition_id IN('pid_8d000000-0000-4000-8000-000000000002','pid_8d000000-0000-4000-8000-000000000003')) FROM zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)`, o, w, e, id).Scan(&testRuns, &legacyRuns); err != nil || testRuns != 1 || legacyRuns != 1 {
			t.Fatalf("mixed budget split test%d legacy%d: %v", testRuns, legacyRuns, err)
		}
		schedule(1, 1)
		schedule(25, 0)
		const laterID = "pid_8d000000-0000-4000-8000-000000000004"
		createExistingTestLifecycleDraft(t, ctx, api, o, w, e, laterID, testID, actor, "run_test")
		lifecycleActivateDraft(t, ctx, api, o, w, e, laterID, actor, 4)
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,'pid_8d100000-0000-4000-8000-000000000002','posture','credential','Second local evidence','high','open')`, o, w, e); err != nil {
			t.Fatal(err)
		}
		// The first definition is already at concurrency1, with another matching
		// unreceipted finding. It cannot starve the later eligible definition.
		schedule(1, 1)
		if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$4)`, o, w, e, laterID).Scan(&testRuns); err != nil || testRuns != 1 {
			t.Fatalf("later eligible definition starved: %d %v", testRuns, err)
		}
		if !equalIntegrationJSON(foreignBefore, existingTestActivationSnapshot(t, ctx, owner, foreignOrg, foreignWorkspace, foreignEnvironment, id)) {
			t.Fatal("automatic scheduler mutated foreign scope")
		}
		for _, limit := range []int{0, 26} {
			if err := worker.QueryRow(ctx, `SELECT public.zasp_production_security_agent_existing_tests_schedule($1,$2,$3,$4)`, "mixed-lifecycle-worker", limit, pins[0], pins[1]).Scan(&raw); err == nil {
				t.Fatalf("invalid scheduler limit%d accepted", limit)
			}
		}
	})
}

func lifecycleFinalWriteWait(t *testing.T, ctx context.Context, owner, caller *pgx.Conn, mode string, deadline time.Time, invoke func() error) error {
	t.Helper()
	blocker, err := pgx.ConnectConfig(ctx, owner.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close(context.Background())
	lockSQL := `BEGIN; LOCK TABLE zasp_security_agent_request_receipts IN SHARE MODE`
	if mode == "execution_state" {
		lockSQL = `BEGIN; SELECT 1 FROM zasp_security_agent_execution_state WHERE singleton FOR UPDATE`
	}
	if mode == "delegated_wait" {
		// The inherited finding scheduler locks this exact scoped advisory key,
		// not its definition row. New55 admission uses a separate organization key.
		lockSQL = `BEGIN; SELECT pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_id,workspace_id,environment_id,definition_id,'automatic-trigger'),0)) FROM zasp_security_agent_definitions WHERE definition_id='pid_8bf00000-0000-4000-8000-000000000099'`
	}
	if _, err := blocker.Exec(ctx, lockSQL); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- invoke() }()
	joined := false
	defer func() {
		blocker.Exec(context.Background(), "ROLLBACK")
		if !joined {
			<-done
		}
	}()
	observed := false
	for time.Now().Before(deadline) {
		if err := blocker.QueryRow(ctx, `SELECT pg_backend_pid()=ANY(pg_blocking_pids($1))`, caller.PgConn().PID()).Scan(&observed); err != nil {
			t.Fatal(err)
		}
		if observed {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !observed {
		var state string
		if err := blocker.QueryRow(ctx, `SELECT concat_ws('/',state,wait_event_type,wait_event) FROM pg_stat_activity WHERE pid=$1`, caller.PgConn().PID()).Scan(&state); err != nil {
			t.Fatal(err)
		}
		t.Fatalf("admission did not reach held %s write before deadline; caller=%s", mode, state)
	}
	if mode == "delegated_wait" {
		var written bool
		if err := blocker.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND granted AND relation='public.zasp_security_agent_runs'::regclass AND mode='RowExclusiveLock') AND EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND NOT granted AND locktype='advisory')`, caller.PgConn().PID()).Scan(&written); err != nil || !written {
			t.Fatalf("delegated wait was not after prior run writes: %t %v", written, err)
		}
		t.Log("observed delegated legacy advisory wait after test run writes")
	}
	if wait := time.Until(deadline) + 50*time.Millisecond; wait > 0 {
		time.Sleep(wait)
	}
	if _, err := blocker.Exec(ctx, "ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	err = <-done
	joined = true
	return err
}

func TestExistingTestLifecycleBatchDisabledHeadPostgres(t *testing.T) {
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, testID, actor string) {
		const healthyTest = "pid_8e000000-0000-4000-8000-000000000001"
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_red_team_definitions(organization_id,workspace_id,environment_id,definition_id,version,name,target_id,target_kind,categories,safety,enabled,created_by) SELECT organization_id,workspace_id,environment_id,$5,version,'Separate healthy test',target_id,target_kind,categories,safety,true,created_by FROM zasp_red_team_definitions WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$4)`, o, w, e, testID, healthyTest); err != nil {
			t.Fatal(err)
		}
		lifecycleEnableTestControl(t, ctx, api, o, w, e, actor, "run_test", 1)
		for n := 1; n <= 6; n++ {
			selected := testID
			if n == 6 {
				selected = healthyTest
			}
			id := fmt.Sprintf("pid_8e100000-0000-4000-8000-%012d", n)
			createExistingTestLifecycleDraft(t, ctx, api, o, w, e, id, selected, actor, "run_test")
			lifecycleActivateDraft(t, ctx, api, o, w, e, id, actor, n)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_definitions SET enabled=false WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$4); INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,'pid_8e200000-0000-4000-8000-000000000001','posture','credential','Shared head evidence','high','open')`, pgx.QueryExecModeSimpleProtocol, o, w, e, testID); err != nil {
			t.Fatal(err)
		}
		config := owner.Config().Copy()
		config.User = "security_agent_v33_worker_login"
		worker, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close(context.Background())
		var raw json.RawMessage
		if err := worker.QueryRow(ctx, `SELECT public.zasp_production_security_agent_existing_tests_schedule($1,$2,$3,$4)`, "disabled-head-worker", 1, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if string(raw) != `{"created": 1}` {
			t.Fatalf("five disabled head candidates starved healthy later definition: %s", raw)
		}
		var good, bad int
		if err := owner.QueryRow(ctx, `SELECT count(*) FILTER(WHERE definition_id='pid_8e100000-0000-4000-8000-000000000006'),count(*) FILTER(WHERE definition_id<>'pid_8e100000-0000-4000-8000-000000000006') FROM zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)`, o, w, e).Scan(&good, &bad); err != nil || good != 1 || bad != 0 {
			t.Fatalf("head scheduling leaked stale work good%d bad%d: %v", good, bad, err)
		}
	})
}
