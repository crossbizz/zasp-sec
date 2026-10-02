package apiserver

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

// An apply lease is not permission to outlive the run's budget. This exercises
// actual signed policy-source storage/enqueue after claim, not gateway delivery.
func TestProductionSecurityAgentBudgetStopsClaimedPolicyApply(t *testing.T) {
	cases := []string{"expired", "fresh", "busy_effect", "busy_deployment", "target_wait_expired", "target_wait_fresh", "stopped_reclaim", "stored_reclaim", "pending_stopped", "pending_stored", "partial_devices", "legacy_temporary_expired", "legacy_temporary_fresh", "legacy_session_expired", "legacy_session_fresh", "legacy_temporary_target_wait_expired", "legacy_temporary_target_wait_fresh", "legacy_session_target_wait_expired", "legacy_session_target_wait_fresh", "legacy_temporary_busy_credential", "legacy_session_busy_credential", "legacy_temporary_bundle_wait_expired", "legacy_temporary_bundle_wait_fresh", "legacy_session_bundle_wait_expired", "legacy_session_bundle_wait_fresh"}
	cases = append(cases, "legacy_temporary_cleanup_replay", "legacy_session_cleanup_replay")
	cases = append(cases, "isolation_expired", "isolation_fresh", "legacy_session_isolation_expired", "legacy_session_isolation_fresh")
	cases = append(cases, "isolation_cleanup_replay", "legacy_session_isolation_cleanup_replay")
	for _, name := range cases {
		isolation := strings.Contains(name, "isolation_")
		legacy := strings.HasPrefix(name, "legacy_")
		cleanupReplay := strings.HasSuffix(name, "cleanup_replay")
		partial := name == "partial_devices"
		storedReclaim := name == "stored_reclaim" || name == "pending_stored" || partial || cleanupReplay
		stoppedReclaim := name == "stopped_reclaim" || name == "pending_stopped"
		pending := name == "pending_stopped" || name == "pending_stored"
		expired := name == "expired" || name == "target_wait_expired" || stoppedReclaim || (legacy || isolation) && strings.HasSuffix(name, "_expired")
		bundleWait := strings.Contains(name, "bundle_wait_")
		targetWait := strings.Contains(name, "target_wait_") || bundleWait
		busyCredential := strings.HasSuffix(name, "busy_credential")
		busy := name == "busy_effect" || name == "busy_deployment" || busyCredential
		t.Run(name, func(t *testing.T) {
			runSecurityAgentBudgetFixture(t, func(ctx context.Context, owner *pgx.Conn, dsn string) {
				var version int64
				if err := owner.QueryRow(ctx, `SELECT max(version) FROM zasp_schema_versions`).Scan(&version); err != nil || version != 53 {
					t.Fatalf("action lifecycle requires registered release53: version=%d err=%v", version, err)
				}
				const organization = "pid_6a000001-0000-4000-8000-000000000001"
				const workspace = "pid_6a000002-0000-4000-8000-000000000002"
				const environment = "pid_6a000003-0000-4000-8000-000000000003"
				const device = "pid_6a000060-0000-4000-8000-000000000060"
				const enrollment = "pid_6a000061-0000-4000-8000-000000000061"
				const credential = "pid_6a000062-0000-4000-8000-000000000062"
				const session = "pid_6a000080-0000-4000-8000-000000000080"
				const plannerID, plannerLease = "budget-apply-planner", "budget-apply-planner-lease"
				const actionID, actionLease = "budget-apply-action", "budget-apply-action-lease"
				if _, err := owner.Exec(ctx, `CREATE ROLE budget_apply_action_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); err != nil {
					t.Fatal(err)
				}
				var ready bool
				if err := owner.QueryRow(ctx, `SELECT zasp_security_agent_register_action_principal(session_user,'budget_apply_action_login')`).Scan(&ready); err != nil || !ready {
					t.Fatalf("action registration=%v error=%v", ready, err)
				}
				connect := func(user string) *pgx.Conn {
					t.Helper()
					config, err := pgx.ParseConfig(dsn)
					if err != nil {
						t.Fatal(err)
					}
					config.User = user
					connection, err := pgx.ConnectConfig(ctx, config)
					if err != nil {
						t.Fatal(err)
					}
					return connection
				}
				plannerConnection := connect("security_agent_v33_worker_login")
				defer plannerConnection.Close(context.Background())
				actionConnection := connect("budget_apply_action_login")
				defer actionConnection.Close(context.Background())
				plannerDatabase, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: plannerConnection})
				if err != nil {
					t.Fatal(err)
				}
				planner, err := NewSecurityAgentWorkerRepository(plannerDatabase)
				if err != nil {
					t.Fatal(err)
				}
				actionDatabase, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: actionConnection})
				if err != nil {
					t.Fatal(err)
				}
				action, err := NewSecurityAgentActionRepository(actionDatabase)
				if err != nil {
					t.Fatal("migrated action readiness", err)
				}
				if legacy {
					// Keep the actual role, validation and receipt decoder; select
					// the old callable leaf explicitly to test its own enforcement.
					if strings.HasPrefix(name, "legacy_temporary_") {
						action.storeSQL = strings.Replace(postgresSecurityAgentActionStoreSQL, "target(", "target_v27(", 1)
					} else {
						action.storeSQL = strings.Replace(postgresSecurityAgentActionStoreV24SQL, "target(", "target_v27(", 1)
					}
				}
				if err := planner.Ready(ctx); err != nil {
					t.Fatal("migrated planner readiness", err)
				}
				if err := action.Ready(ctx); err != nil {
					t.Fatal("migrated action readiness", err)
				}
				for _, statement := range []struct {
					sql  string
					args []any
				}{
					{`UPDATE zasp_risk_attack_paths SET state='verified',version=version+1 WHERE organization_id=$1`, []any{organization}},
					{`INSERT INTO zasp_gateway_devices(organization_id,workspace_id,environment_id,id,name,state) VALUES($1,$2,$3,$4,'Budget test gateway','active')`, []any{organization, workspace, environment, device}},
					{`INSERT INTO zasp_gateway_enrollment_tokens(organization_id,workspace_id,environment_id,id,device_id,audience,salt,token_hash,expires_at) VALUES($1,$2,$3,$4,$5,'runtime-gateway-enroll',decode(repeat('01',16),'hex'),decode(repeat('02',32),'hex'),clock_timestamp()+interval '1 hour')`, []any{organization, workspace, environment, enrollment, device}},
					{`INSERT INTO zasp_gateway_credentials(organization_id,workspace_id,environment_id,id,device_id,enrollment_token_id,enrollment_digest,audience,key_reference,public_key,expires_at,format_version,credential_generation,key_id,algorithm,v15_issued_at) VALUES($1,$2,$3,$4,$5,$6,decode(repeat('03',32),'hex'),'runtime-gateway','ref:gateway/public/gateway-device-key-01',decode(repeat('04',32),'hex'),clock_timestamp()+interval '1 hour',1,1,'gateway-device-key-01','Ed25519',clock_timestamp())`, []any{organization, workspace, environment, credential, device, enrollment}},
				} {
					if _, err := owner.Exec(ctx, statement.sql, statement.args...); err != nil {
						t.Fatal(err)
					}
				}
				if isolation {
					// Seed real runtime evidence before scheduling. The planner must
					// create an isolate_session effect; do not relabel a policy effect.
					for _, statement := range []string{
						`UPDATE zasp_security_agent_definitions SET body=body || '{"trigger_kind":"runtime_decision","trigger_source":"gateway","allowed_actions":["isolate_session"],"verification_kind":"gateway_decision"}'::jsonb WHERE organization_id=$1`,
						`UPDATE zasp_security_agent_kill_switches SET action_key='isolate_session' WHERE organization_id=$1 AND action_key='create_temporary_policy'`,
					} {
						if _, err := owner.Exec(ctx, statement, organization); err != nil {
							t.Fatal(err)
						}
					}
					for index, event := range []string{"pid_6a000081-0000-4000-8000-000000000081", "pid_6a000082-0000-4000-8000-000000000082", "pid_6a000083-0000-4000-8000-000000000083"} {
						if _, err := owner.Exec(ctx, `INSERT INTO zasp_runtime_gateway_events(organization_id,workspace_id,environment_id,device_id,credential_id,event_id,sequence,request_digest,policy_version,decision,action_kind,classification,occurred_at) VALUES($1,$2,$3,$4,$5,$6,$7,digest(convert_to($6,'UTF8'),'sha256'),1,'block','http',jsonb_build_object('category','security','route_class','runtime','resource_class','session','outcome','gateway','session_id',$8::text),clock_timestamp())`, organization, workspace, environment, device, credential, event, index+1, session); err != nil {
							t.Fatal(err)
						}
					}
				}
				if partial {
					for _, statement := range []string{
						`INSERT INTO zasp_gateway_devices(organization_id,workspace_id,environment_id,id,name,state) SELECT organization_id,workspace_id,environment_id,'pid_6a000070-0000-4000-8000-000000000070','Second budget gateway',state FROM zasp_gateway_devices WHERE id='pid_6a000060-0000-4000-8000-000000000060'`,
						`INSERT INTO zasp_gateway_enrollment_tokens(organization_id,workspace_id,environment_id,id,device_id,audience,salt,token_hash,expires_at) SELECT organization_id,workspace_id,environment_id,'pid_6a000071-0000-4000-8000-000000000071','pid_6a000070-0000-4000-8000-000000000070',audience,decode(repeat('11',16),'hex'),decode(repeat('12',32),'hex'),expires_at FROM zasp_gateway_enrollment_tokens WHERE id='pid_6a000061-0000-4000-8000-000000000061'`,
						`INSERT INTO zasp_gateway_credentials(organization_id,workspace_id,environment_id,id,device_id,enrollment_token_id,enrollment_digest,audience,key_reference,public_key,expires_at,format_version,credential_generation,key_id,algorithm,v15_issued_at) SELECT organization_id,workspace_id,environment_id,'pid_6a000072-0000-4000-8000-000000000072','pid_6a000070-0000-4000-8000-000000000070','pid_6a000071-0000-4000-8000-000000000071',decode(repeat('13',32),'hex'),audience,key_reference,decode(repeat('14',32),'hex'),expires_at,format_version,credential_generation,key_id,algorithm,v15_issued_at FROM zasp_gateway_credentials WHERE id='pid_6a000062-0000-4000-8000-000000000062'`,
					} {
						if _, err := owner.Exec(ctx, statement); err != nil {
							t.Fatal(err)
						}
					}
				}
				if count, err := planner.ScheduleSecurityAgentTriggers(ctx, plannerID, 1); err != nil || count != 1 {
					t.Fatalf("schedule=%d error=%v", count, err)
				}
				claim := func() SecurityAgentRunClaim {
					t.Helper()
					claims, err := planner.ClaimSecurityAgentRuns(ctx, plannerID, plannerLease, 60, 1)
					if err != nil || len(claims) != 1 {
						t.Fatalf("claims=%d error=%v", len(claims), err)
					}
					return claims[0]
				}
				current := claim()
				if result, err := planner.PrepareSecurityAgentRun(ctx, current, plannerID, plannerLease,
					"pid_6a000030-0000-4000-8000-000000000030", time.Now().UTC().Add(10*time.Minute),
					"pid_6a000031-0000-4000-8000-000000000031", "pid_6a000032-0000-4000-8000-000000000032"); err != nil || result.State != "waiting_approval" {
					t.Fatalf("prepare=%+v error=%v", result, err)
				}
				// Fixture approval isolates apply authority; it is not an API proof.
				for _, statement := range []string{
					`UPDATE zasp_security_agent_approvals SET state='approved',approver_id='pid_6a000033-0000-4000-8000-000000000033',fresh_auth_at=clock_timestamp(),decided_at=clock_timestamp(),version=version+1 WHERE organization_id=$1`,
					`UPDATE zasp_security_agent_steps SET state='authorized',version=version+1 WHERE organization_id=$1`,
					`UPDATE zasp_security_agent_runs SET state='queued',version=version+1 WHERE organization_id=$1`,
				} {
					if _, err := owner.Exec(ctx, statement, organization); err != nil {
						t.Fatal(err)
					}
				}
				current = claim()
				if result, err := planner.ExecuteSecurityAgentRun(ctx, current, plannerID, plannerLease,
					"pid_6a000034-0000-4000-8000-000000000034", "pid_6a000035-0000-4000-8000-000000000035"); err != nil || result.State != "running" {
					t.Fatalf("dispatch=%+v error=%v", result, err)
				}
				effects, err := action.ClaimTemporaryPolicyEffects(ctx, actionID, actionLease, 60, 1)
				wantTargets := 1
				if partial {
					wantTargets = 2
				}
				if err != nil || len(effects) != 1 || effects[0].Phase != "apply" || len(effects[0].Targets) != wantTargets {
					t.Fatalf("action claims=%+v error=%v", effects, err)
				}
				if isolation && (effects[0].ActionKey != "isolate_session" || effects[0].SessionID != session) {
					t.Fatalf("not a real session isolation claim: %+v", effects[0])
				}
				if name == "expired" || stoppedReclaim || (legacy || isolation) && expired && !targetWait {
					if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_run_budgets SET started_at=clock_timestamp()-interval '301 seconds',deadline_at=clock_timestamp()-interval '1 second' WHERE organization_id=$1`, organization); err != nil {
						t.Fatal(err)
					}
				}
				_, key, err := ed25519.GenerateKey(nil)
				if err != nil {
					t.Fatal(err)
				}
				now := time.Now().UTC().Truncate(time.Second)
				policies := postgresTemporaryContainmentPolicies(t)
				if isolation {
					policies = postgresSessionIsolationPolicies(t, session)
				}
				envelope := postgresTemporaryPolicyEnvelope(t, effects[0], effects[0].Targets[0], "gateway-key-01", key, now, now.Add(time.Duration(effects[0].TTLSeconds)*time.Second), policies)
				var generationBefore int64
				if err := owner.QueryRow(ctx, `SELECT coalesce(sum(desired_generation),0)::bigint FROM zasp_policy_deployment_work WHERE organization_id=$1`, organization).Scan(&generationBefore); err != nil {
					t.Fatal(err)
				}
				var held pgx.Tx
				if targetWait && expired {
					if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_run_budgets SET started_at=clock_timestamp()-interval '295 seconds',deadline_at=clock_timestamp()+interval '5 seconds' WHERE organization_id=$1`, organization); err != nil {
						t.Fatal(err)
					}
				}
				if busy || targetWait {
					held, err = owner.Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer held.Rollback(context.Background())
					statement := `SELECT 1 FROM zasp_security_agent_effects WHERE organization_id=$1 FOR UPDATE`
					if name == "busy_deployment" {
						statement = `SELECT 1 FROM zasp_policy_deployment_work WHERE organization_id=$1 FOR UPDATE`
					}
					if busyCredential {
						statement = `SELECT 1 FROM zasp_gateway_credentials WHERE organization_id=$1 FOR UPDATE`
					}
					if targetWait {
						statement = `SELECT 1 FROM zasp_security_agent_temporary_policy_targets WHERE organization_id=$1 FOR UPDATE`
					}
					if bundleWait {
						_, err = held.Exec(ctx, `INSERT INTO zasp_runtime_gateway_policy_bundles(organization_id,workspace_id,environment_id,device_id,credential_id,sequence,policy_version,key_id,algorithm,audience,issued_at,expires_at,failure_mode,payload_digest,policies,signature,envelope_digest) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'Ed25519','runtime-gateway-policy',$9,$10,$11,decode($12,'hex'),$13::jsonb,$14,decode($15,'hex'))`, organization, workspace, environment, envelope.Target.DeviceID, envelope.Target.CredentialID, envelope.Target.Sequence, envelope.Target.PolicyVersion, envelope.KeyID, envelope.IssuedAt, envelope.ExpiresAt, envelope.FailureMode, strings.TrimPrefix(envelope.PayloadDigest, "sha256:"), string(envelope.Policies), envelope.Signature, strings.TrimPrefix(envelope.EnvelopeDigest, "sha256:"))
					} else {
						_, err = held.Exec(ctx, statement, organization)
					}
					if err != nil {
						t.Fatal(err)
					}
				}
				callTimeout := 3 * time.Second
				if targetWait {
					callTimeout = 12 * time.Second
				}
				callContext, cancel := context.WithTimeout(ctx, callTimeout)
				defer cancel()
				var storeErr error
				if targetWait {
					observer := connect("zasp_e2e")
					defer observer.Close(context.Background())
					done := make(chan error, 1)
					joined := false
					defer func() {
						cancel()
						_ = held.Rollback(context.Background())
						if !joined {
							<-done
						}
					}()
					go func() {
						done <- action.StoreTemporaryPolicyTarget(callContext, effects[0], actionID, actionLease, envelope)
					}()
					observedBeforeExpiry := false
					for {
						var waiting, deadlinePassed bool
						if err := observer.QueryRow(callContext, `SELECT $2::integer=ANY(pg_blocking_pids($1::integer)),(SELECT deadline_at<=clock_timestamp() FROM zasp_security_agent_run_budgets WHERE organization_id=$3)`, actionConnection.PgConn().PID(), owner.PgConn().PID(), organization).Scan(&waiting, &deadlinePassed); err != nil {
							t.Fatal(err)
						}
						if waiting && !deadlinePassed {
							observedBeforeExpiry = true
						}
						if observedBeforeExpiry && (!expired || deadlinePassed) {
							break
						}
						select {
						case storeErr = <-done:
							joined = true
							t.Fatalf("apply exited before observed target wait: %v", storeErr)
						case <-callContext.Done():
							t.Fatal("target wait/deadline not observed")
						case <-time.After(10 * time.Millisecond):
						}
					}
					if err := held.Rollback(callContext); err != nil {
						t.Fatal(err)
					}
					storeErr = <-done
					joined = true
					t.Logf("observed action lock before expiry; bundle conflict=%v released after deadline=%v; joined store", bundleWait, expired)
				} else {
					storeErr = action.StoreTemporaryPolicyTarget(callContext, effects[0], actionID, actionLease, envelope)
				}
				if callContext.Err() != nil {
					t.Fatalf("action source waited on held authority: %v", callContext.Err())
				}
				if busy {
					if err := held.Rollback(ctx); err != nil {
						t.Fatal(err)
					}
				}
				var state, reason string
				var bundles, storedTargets int
				var effectCount, reservationCount int
				var generationAfter int64
				if err := owner.QueryRow(ctx, `SELECT r.state,coalesce(b.stop_reason,''),
 (SELECT count(*) FROM zasp_runtime_gateway_policy_bundles),
 (SELECT count(*) FROM zasp_security_agent_temporary_policy_targets WHERE state='stored'),
 (SELECT coalesce(sum(desired_generation),0)::bigint FROM zasp_policy_deployment_work WHERE organization_id=$1),
 (SELECT count(*) FROM zasp_security_agent_effects WHERE organization_id=$1),
 (SELECT count(*) FROM zasp_security_agent_step_reservations WHERE organization_id=$1)
 FROM zasp_security_agent_runs r JOIN zasp_security_agent_run_budgets b USING(organization_id,workspace_id,environment_id,run_id) WHERE r.organization_id=$1`, organization).Scan(&state, &reason, &bundles, &storedTargets, &generationAfter, &effectCount, &reservationCount); err != nil {
					t.Fatal(err)
				}
				if effectCount != 1 || reservationCount != 1 {
					t.Fatalf("effect/reservation history changed: effects=%d reservations=%d", effectCount, reservationCount)
				}
				if expired {
					if !errors.Is(storeErr, ErrSecurityAgentBudgetStopped) || state != "needs_human" || reason != "budget_deadline_exceeded" || bundles != 0 || storedTargets != 0 || generationAfter != generationBefore {
						t.Fatalf("apply after deadline: error=%v state=%s reason=%s bundles=%d storedTargets=%d generation=%d->%d", storeErr, state, reason, bundles, storedTargets, generationBefore, generationAfter)
					}
				} else if busy {
					if !errors.Is(storeErr, ErrRepositoryConflict) || state != "running" || reason != "" || bundles != 0 || storedTargets != 0 || generationAfter != generationBefore {
						t.Fatalf("busy apply: error=%v state=%s reason=%s bundles=%d storedTargets=%d generation=%d->%d", storeErr, state, reason, bundles, storedTargets, generationBefore, generationAfter)
					}
				} else {
					wantBundles, wantGeneration := 0, generationBefore+1
					if legacy {
						wantBundles, wantGeneration = 1, generationBefore
					}
					if storeErr != nil || state != "running" || reason != "" || bundles != wantBundles || storedTargets != 1 || generationAfter != wantGeneration {
						t.Fatalf("fresh apply: error=%v state=%s reason=%s bundles=%d storedTargets=%d generation=%d->%d", storeErr, state, reason, bundles, storedTargets, generationBefore, generationAfter)
					}
				}
				if stoppedReclaim || storedReclaim {
					if partial {
						if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_run_budgets SET started_at=clock_timestamp()-interval '301 seconds',deadline_at=clock_timestamp()-interval '1 second' WHERE organization_id=$1`, organization); err != nil {
							t.Fatal(err)
						}
						second := postgresTemporaryPolicyEnvelope(t, effects[0], effects[0].Targets[1], "gateway-key-01", key, now, now.Add(time.Duration(effects[0].TTLSeconds)*time.Second), postgresTemporaryContainmentPolicies(t))
						if err := action.StoreTemporaryPolicyTarget(ctx, effects[0], actionID, actionLease, second); !errors.Is(err, ErrSecurityAgentBudgetStopped) {
							t.Fatalf("second target after expiry: %v", err)
						}
					}
					if storedReclaim && !partial {
						// Stored source is real; seed a later sticky stop to isolate
						// reclaim before deployment/verification has completed.
						if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_run_budgets SET stop_reason='budget_deadline_exceeded' WHERE organization_id=$1`, organization); err != nil {
							t.Fatal(err)
						}
						if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_runs SET state='needs_human',last_error_code='budget_deadline_exceeded' WHERE organization_id=$1`, organization); err != nil {
							t.Fatal(err)
						}
					}
					// Simulate worker loss after the committed stop. Expire only the
					// effect lease; the persisted budget stop must survive reclamation.
					if cleanupReplay {
						if err := action.StoreTemporaryPolicyTarget(ctx, effects[0], actionID, actionLease, envelope); err != nil {
							t.Fatalf("exact stored apply replay blocked by stop: %v", err)
						}
					}
					if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_effects SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE organization_id=$1`, organization); err != nil {
						t.Fatal(err)
					}
					if pending {
						if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_effects SET state='pending',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL WHERE organization_id=$1`, organization); err != nil {
							t.Fatal(err)
						}
					}
					reclaimed, err := action.ClaimTemporaryPolicyEffects(ctx, actionID, "budget-action-reclaim-lease", 60, 1)
					if err != nil {
						t.Fatal(err)
					}
					if err := owner.QueryRow(ctx, `SELECT r.state,b.stop_reason,(SELECT count(*) FROM zasp_security_agent_effects),(SELECT count(*) FROM zasp_security_agent_step_reservations) FROM zasp_security_agent_runs r JOIN zasp_security_agent_run_budgets b USING(organization_id,workspace_id,environment_id,run_id) WHERE r.organization_id=$1`, organization).Scan(&state, &reason, &effectCount, &reservationCount); err != nil {
						t.Fatal(err)
					}
					if state != "needs_human" || reason != "budget_deadline_exceeded" || effectCount != 1 || reservationCount != 1 {
						t.Fatalf("reclaim changed stop/history: state=%s reason=%s effects=%d reservations=%d", state, reason, effectCount, reservationCount)
					}
					if storedReclaim && (len(reclaimed) != 1 || reclaimed[0].Phase != "cleanup" || len(reclaimed[0].Targets) != 1) {
						t.Fatalf("stored source not reclaimed for cleanup: %+v", reclaimed)
					}
					if storedReclaim {
						cleanup := reclaimed[0]
						if isolation && (cleanup.ActionKey != "isolate_session" || cleanup.SessionID != session || cleanup.RunID != effects[0].RunID || cleanup.StepID != effects[0].StepID) {
							t.Fatalf("cleanup lost isolation binding: %+v", cleanup)
						}
						wantCleanupGeneration := generationBefore + 2
						if legacy {
							wantCleanupGeneration = generationBefore
						}
						if partial && cleanup.Targets[0].DeviceID != effects[0].Targets[0].DeviceID {
							t.Fatal("cleanup did not select stored device")
						}
						issued := time.Now().UTC().Truncate(time.Second)
						cleanupEnvelope := postgresTemporaryPolicyEnvelope(t, cleanup, cleanup.Targets[0], "gateway-key-01", key, issued, issued.Add(5*time.Minute), []policy.CompiledPolicy{})
						if err := action.StoreTemporaryPolicyTarget(ctx, cleanup, actionID, "budget-action-reclaim-lease", cleanupEnvelope); err != nil {
							t.Fatalf("cleanup source blocked by budget: %v", err)
						}
						var cleanups int
						if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_security_agent_temporary_policy_targets WHERE phase='cleanup' AND state='stored' AND policies='[]'::jsonb),(SELECT sum(desired_generation)::bigint FROM zasp_policy_deployment_work WHERE organization_id=$1)`, organization).Scan(&cleanups, &generationAfter); err != nil {
							t.Fatal(err)
						}
						if cleanups != 1 || generationAfter != wantCleanupGeneration {
							t.Fatalf("cleanup enqueue: sources=%d generation=%d->%d", cleanups, generationBefore, generationAfter)
						}
						// A second worker loss must preserve the exact stored cleanup
						// source, return cleanup again, and replay without re-enqueue.
						if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_effects SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE organization_id=$1`, organization); err != nil {
							t.Fatal(err)
						}
						retry, err := action.ClaimTemporaryPolicyEffects(ctx, actionID, "budget-cleanup-retry-lease", 60, 1)
						if err != nil || len(retry) != 1 || retry[0].Phase != "cleanup" || len(retry[0].Targets) != 1 || retry[0].Targets[0] != cleanup.Targets[0] {
							t.Fatalf("cleanup retry=%+v err=%v", retry, err)
						}
						if isolation && (retry[0].ActionKey != "isolate_session" || retry[0].SessionID != session || retry[0].RunID != cleanup.RunID || retry[0].StepID != cleanup.StepID) {
							t.Fatalf("cleanup retry lost isolation binding: %+v", retry[0])
						}
						if err := action.StoreTemporaryPolicyTarget(ctx, retry[0], actionID, "budget-cleanup-retry-lease", cleanupEnvelope); err != nil {
							t.Fatalf("cleanup replay: %v", err)
						}
						if err := owner.QueryRow(ctx, `SELECT r.state,b.stop_reason,(SELECT sum(desired_generation)::bigint FROM zasp_policy_deployment_work WHERE organization_id=$1) FROM zasp_security_agent_runs r JOIN zasp_security_agent_run_budgets b USING(organization_id,workspace_id,environment_id,run_id) WHERE r.organization_id=$1`, organization).Scan(&state, &reason, &generationAfter); err != nil {
							t.Fatal(err)
						}
						if state != "needs_human" || reason != "budget_deadline_exceeded" || generationAfter != wantCleanupGeneration {
							t.Fatalf("cleanup replay changed stop/enqueue: state=%s reason=%s generation=%d", state, reason, generationAfter)
						}
						if legacy {
							var cleanupBundles int
							if err := owner.QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE policies='[]'::jsonb) FROM zasp_runtime_gateway_policy_bundles`).Scan(&bundles, &cleanupBundles); err != nil {
								t.Fatal(err)
							}
							if bundles != 2 || cleanupBundles != 1 {
								t.Fatalf("legacy cleanup replay duplicated/missed bundle: total=%d cleanup=%d", bundles, cleanupBundles)
							}
						}
						if partial {
							var untouched, cleanupTargets int
							if err := owner.QueryRow(ctx, `SELECT count(*) FILTER (WHERE phase='apply' AND state='planned' AND desired_generation IS NULL),count(*) FILTER (WHERE phase='cleanup') FROM zasp_security_agent_temporary_policy_targets WHERE device_id=$1`, effects[0].Targets[1].DeviceID).Scan(&untouched, &cleanupTargets); err != nil {
								t.Fatal(err)
							}
							if untouched != 1 || cleanupTargets != 0 {
								t.Fatalf("untouched device altered: planned=%d cleanups=%d", untouched, cleanupTargets)
							}
						}
					}
					for _, next := range reclaimed {
						if next.Phase == "apply" {
							t.Fatalf("stopped run reclaimed for new apply: run=%s step=%s targets=%d", next.RunID, next.StepID, len(next.Targets))
						}
					}
				}
			})
		})
	}
}
