package apiserver

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func orderedAdmissionReviewFixture(t *testing.T, run func(context.Context, *pgx.Conn, *pgx.Conn, string, string, string, string, string)) {
	t.Helper()
	multistepVersionedExistingTestFixture(t, func(ctx context.Context, owner, _ *pgx.Conn, o, w, e, testID, actor string) {
		runner := precisionMigrationRunner(t, owner)
		for _, up := range []func(context.Context) error{runner.UpProductionCompliance, runner.UpProductionSecurityAgentAttackLab, runner.UpProductionSecurityAgentExports, runner.UpProductionSecurityAgentWebhooks, runner.UpProductionDiscoveryScheduleReplay, runner.UpProductionSecurityAgentMultistep} {
			if err := up(ctx); err != nil {
				t.Fatal(err)
			}
		}
		config := owner.Config().Copy()
		config.User = "security_agent_v33_worker_login"
		worker, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close(ctx)
		run(ctx, owner, worker, o, w, e, testID, actor)
	})
}

func invokeOrderedAdmission(ctx context.Context, worker *pgx.Conn, request map[string]any) (string, error) {
	raw, err := json.Marshal(request)
	if err != nil {
		return "", err
	}
	var receipt string
	err = worker.QueryRow(ctx, `SELECT zasp_sa_multistep_prior.admit($1,$2,$3::jsonb)::text`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint(), raw).Scan(&receipt)
	return receipt, err
}

func TestSecurityAgentMultistepAdmissionReplayHeadersPostgres(t *testing.T) {
	orderedAdmissionReviewFixture(t, func(ctx context.Context, owner, worker *pgx.Conn, o, w, e, testID, actor string) {
		cases := []struct{ name, mutation string }{
			{"plan_definition_id", `UPDATE zasp_security_agent_plans SET definition_id='pid_78000004-0000-4000-8000-000000000004' WHERE run_id=$1`},
			{"plan_definition_version", `UPDATE zasp_security_agent_plans SET definition_version=definition_version+1 WHERE run_id=$1`},
			{"plan_trigger_digest", `UPDATE zasp_security_agent_plans SET trigger_digest=decode(repeat('ee',32),'hex') WHERE run_id=$1`},
			{"plan_catalog_version", `UPDATE zasp_security_agent_plans SET catalog_version='other-catalog' WHERE run_id=$1`},
			{"plan_expiry", `UPDATE zasp_security_agent_plans SET expires_at=expires_at+interval '1 hour' WHERE run_id=$1`},
			{"approval_expiry", `UPDATE zasp_security_agent_approvals SET expires_at=expires_at+interval '1 hour' WHERE run_id=$1`},
			{"joint_expiry", `UPDATE zasp_security_agent_plans SET expires_at=expires_at+interval '1 hour' WHERE run_id=$1;UPDATE zasp_security_agent_approvals SET expires_at=expires_at+interval '1 hour' WHERE run_id=$1`},
			{"approval_state", `UPDATE zasp_security_agent_approvals SET state='approved' WHERE run_id=$1`},
			{"approval_requester", `UPDATE zasp_security_agent_approvals SET requester_id='other-requester' WHERE run_id=$1`},
			{"approval_approver", `UPDATE zasp_security_agent_approvals SET approver_id='other-approver' WHERE run_id=$1`},
			{"approval_fresh_auth", `UPDATE zasp_security_agent_approvals SET fresh_auth_at=clock_timestamp() WHERE run_id=$1`},
			{"approval_decided", `UPDATE zasp_security_agent_approvals SET decided_at=clock_timestamp() WHERE run_id=$1`},
			{"approval_version", `UPDATE zasp_security_agent_approvals SET version=version+1 WHERE run_id=$1`},
			{"step0_version", `UPDATE zasp_security_agent_steps SET version=version+1 WHERE run_id=$1 AND step_index=0`},
			{"step1_version", `UPDATE zasp_security_agent_steps SET version=version+1 WHERE run_id=$1 AND step_index=1`},
			{"joint_expiry_after_hashed_expiry", `UPDATE zasp_security_agent_run_budgets SET deadline_at=clock_timestamp()+interval '1 hour' WHERE run_id=$1;UPDATE zasp_security_agent_plans SET expires_at=expires_at+interval '1 hour' WHERE run_id=$1;UPDATE zasp_security_agent_approvals SET expires_at=expires_at+interval '1 hour' WHERE run_id=$1`},
		}
		for i, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				request := seedOrderedAdmission(t, ctx, owner, o, w, e, testID, actor, 100+i)
				run := request["run_id"].(string)
				if tc.name == "joint_expiry_after_hashed_expiry" {
					if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_run_budgets SET deadline_at=clock_timestamp()+interval '2 seconds' WHERE run_id=$1`, run); err != nil {
						t.Fatal(err)
					}
				}
				first, err := invokeOrderedAdmission(ctx, worker, request)
				if err != nil {
					t.Fatal("initial admission", err)
				}
				before := orderedAdmissionSnapshot(t, ctx, owner, run)
				if second, err := invokeOrderedAdmission(ctx, worker, request); err != nil || second != first || orderedAdmissionSnapshot(t, ctx, owner, run) != before {
					t.Fatal("unmodified replay changed", err)
				}
				if _, err := owner.Exec(ctx, tc.mutation, pgx.QueryExecModeSimpleProtocol, run); err != nil {
					t.Fatal("header mutation", err)
				}
				if tc.name == "joint_expiry_after_hashed_expiry" {
					expired := false
					for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
						if err := owner.QueryRow(ctx, `SELECT (plan->>'expires_at')::timestamptz<clock_timestamp() FROM zasp_security_agent_plans WHERE run_id=$1`, run).Scan(&expired); err != nil {
							t.Fatal(err)
						}
						if expired {
							break
						}
					}
					var live bool
					if err := owner.QueryRow(ctx, `SELECT a.lease_expires_at>clock_timestamp() AND b.deadline_at>clock_timestamp() AND p.expires_at>clock_timestamp() FROM zasp_sa_multistep_prior.admissions a JOIN zasp_security_agent_run_budgets b USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_security_agent_plans p USING(organization_id,workspace_id,environment_id,run_id) WHERE a.run_id=$1`, run).Scan(&live); err != nil || !expired || !live {
						t.Fatal("fixture must expire only the immutable hashed plan", expired, live, err)
					}
				}
				before = orderedAdmissionSnapshot(t, ctx, owner, run)
				if _, err := invokeOrderedAdmission(ctx, worker, request); err == nil {
					t.Error("replay accepted changed admission header")
				}
				if after := orderedAdmissionSnapshot(t, ctx, owner, run); after != before {
					t.Error("refused replay changed persisted state")
				}
			})
		}
	})
}

// Pause a real admission after readiness but before its Organization lock.
// Retry/down must wait at schema admission, never own run locks while waiting
// for the schema relations already held by that admission. Releasing the gate
// creates the former static cycle without depending on scheduler timing.
func TestSecurityAgentMultistepAdmissionMigrationLockOrderPostgres(t *testing.T) {
	orderedAdmissionReviewFixture(t, func(ctx context.Context, owner, worker *pgx.Conn, o, w, e, testID, actor string) {
		for i, tc := range []struct {
			direction string
			preflight bool
		}{{"retry", false}, {"down", false}, {"retry", true}, {"down", true}} {
			name := tc.direction
			if tc.preflight {
				name += "_transactional_preflight"
			}
			t.Run(name, func(t *testing.T) {
				request := seedOrderedAdmission(t, ctx, owner, o, w, e, testID, actor, 200+i)
				if tc.preflight {
					if _, err := worker.Exec(ctx, `BEGIN`); err != nil {
						t.Fatal(err)
					}
					defer worker.Exec(ctx, `ROLLBACK`)
					var ready string
					if err := worker.QueryRow(ctx, securityAgentMultistepAdmissionReadySQL, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint()).Scan(&ready); err != nil {
						t.Fatal(err)
					}
				}
				gate, err := owner.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer gate.Rollback(ctx)
				if _, err = gate.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||$1,0))`, o); err != nil {
					t.Fatal(err)
				}
				attemptCtx, cancel := context.WithCancel(ctx)
				defer cancel()
				admissionDone := make(chan error, 1)
				go func() {
					_, err := invokeOrderedAdmission(attemptCtx, worker, request)
					if tc.preflight && err == nil {
						_, err = worker.Exec(attemptCtx, `COMMIT`)
					}
					admissionDone <- err
				}()
				admissionJoined := false
				defer func() {
					cancel()
					gate.Rollback(ctx)
					if !admissionJoined {
						<-admissionDone
					}
				}()
				waiting := false
				for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
					if err = gate.QueryRow(ctx, `SELECT pg_backend_pid()=ANY(pg_blocking_pids($1)) AND EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND relation='zasp_schema_versions'::regclass AND mode='AccessShareLock' AND granted)`, worker.PgConn().PID()).Scan(&waiting); err != nil {
						t.Fatal(err)
					}
					if waiting {
						break
					}
				}
				if !waiting {
					t.Fatal("admission did not reach Organization gate after readiness")
				}
				migrator, err := pgx.ConnectConfig(ctx, owner.Config().Copy())
				if err != nil {
					t.Fatal(err)
				}
				defer migrator.Close(ctx)
				runner, _ := migrations.NewRunner(&orderedAdmissionMigrationDatabase{connection: migrator, t: t})
				migrationDone := make(chan error, 1)
				go func() {
					if tc.direction == "retry" {
						migrationDone <- runner.UpProductionSecurityAgentMultistep(attemptCtx)
					} else {
						migrationDone <- runner.DownProductionSecurityAgentMultistep(attemptCtx)
					}
				}()
				migrationJoined := false
				defer func() {
					cancel()
					if !migrationJoined {
						<-migrationDone
					}
				}()
				waiting = false
				var ownsRuns bool
				for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
					if err = gate.QueryRow(ctx, `SELECT $1=ANY(pg_blocking_pids($2)),EXISTS(SELECT 1 FROM pg_locks WHERE pid=$2 AND relation='zasp_security_agent_runs'::regclass AND mode='AccessExclusiveLock' AND granted)`, worker.PgConn().PID(), migrator.PgConn().PID()).Scan(&waiting, &ownsRuns); err != nil {
						t.Fatal(err)
					}
					if waiting {
						break
					}
				}
				if !waiting {
					t.Fatal("migration did not wait behind admission")
				}
				if ownsRuns {
					t.Error("lock inversion: migration owns run table while waiting for admission schema reads")
				}
				if err = gate.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				admissionErr := <-admissionDone
				admissionJoined = true
				migrationErr := <-migrationDone
				migrationJoined = true
				if admissionErr != nil {
					t.Error("admission failed across migration fence", admissionErr)
				}
				if tc.direction == "retry" && migrationErr != nil || tc.direction == "down" && migrationErr == nil {
					t.Error("migration must retry exactly or retain admitted evidence on down", migrationErr)
				}
			})
		}
		for i, entry := range []string{"ready", "admit"} {
			t.Run("migration_fences_"+entry, func(t *testing.T) {
				request := seedOrderedAdmission(t, ctx, owner, o, w, e, testID, actor, 210+i)
				before := orderedAdmissionSnapshot(t, ctx, owner, request["run_id"].(string))
				gate, err := owner.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer gate.Rollback(ctx)
				if _, err = gate.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('zasp-schema-migrations',0));UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_security_agent_multistep_checksum'`); err != nil {
					t.Fatal(err)
				}
				attemptCtx, cancel := context.WithCancel(ctx)
				defer cancel()
				done := make(chan bool, 1)
				go func() {
					if entry == "admit" {
						_, err := invokeOrderedAdmission(attemptCtx, worker, request)
						done <- err == nil
					} else {
						var ready bool
						err := worker.QueryRow(attemptCtx, `SELECT (zasp_sa_multistep_prior.ready($1,$2)->>'release')::boolean`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint()).Scan(&ready)
						done <- err == nil && ready
					}
				}()
				joined := false
				defer func() {
					cancel()
					gate.Rollback(ctx)
					if !joined {
						<-done
					}
				}()
				waiting, ownsSchema := false, false
				for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
					if err = gate.QueryRow(ctx, `SELECT pg_backend_pid()=ANY(pg_blocking_pids($1)),EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND relation IN('zasp_schema_versions'::regclass,'zasp_schema_metadata'::regclass) AND granted)`, worker.PgConn().PID()).Scan(&waiting, &ownsSchema); err != nil {
						t.Fatal(err)
					}
					if waiting {
						break
					}
				}
				if !waiting || ownsSchema {
					t.Error("admission readiness must wait at migration fence before schema reads", waiting, ownsSchema)
				}
				if err = gate.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				defer owner.Exec(ctx, `UPDATE zasp_schema_metadata SET value=$1 WHERE key='production_security_agent_multistep_checksum'`, migrations.ProductionSecurityAgentMultistep().Checksum())
				accepted := <-done
				joined = true
				if accepted || orderedAdmissionSnapshot(t, ctx, owner, request["run_id"].(string)) != before {
					t.Error("readiness did not recheck migration drift after fence wait")
				}
			})
		}
	})
}
