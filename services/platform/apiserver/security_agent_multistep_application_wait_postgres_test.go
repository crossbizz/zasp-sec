package apiserver

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestSecurityAgentMultistepApplicationWaitPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		action := orderedActionFenceConnection(t, ctx, owner)
		defer action.Close(ctx)
		seedOrderedApplicationGateway(t, ctx, owner, o, w, e)
		for i, mode := range []string{"schema", "organization", "run", "plan", "approval", "deadline"} {
			t.Run(mode, func(t *testing.T) {
				r, steps := seedOrderedApplicationRun(t, ctx, owner, worker, api, o, w, e, testID, actor, 770+i, true)
				if mode == "deadline" {
					if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_run_budgets SET deadline_at=clock_timestamp()+interval '1 second' WHERE run_id=$1`, r); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := owner.Exec(ctx, `BEGIN`); err != nil {
					t.Fatal(err)
				}
				defer owner.Exec(ctx, `ROLLBACK`)
				switch mode {
				case "schema":
					if _, err := owner.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('zasp-schema-migrations',0))`); err != nil {
						t.Fatal(err)
					}
				case "organization", "deadline":
					if _, err := owner.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||$1,0))`, o); err != nil {
						t.Fatal(err)
					}
				case "run":
					if _, err := owner.Exec(ctx, `SELECT 1 FROM zasp_security_agent_runs WHERE run_id=$1 FOR UPDATE`, r); err != nil {
						t.Fatal(err)
					}
				case "plan":
					if _, err := owner.Exec(ctx, `SELECT 1 FROM zasp_security_agent_plans WHERE run_id=$1 FOR UPDATE`, r); err != nil {
						t.Fatal(err)
					}
				case "approval":
					if _, err := owner.Exec(ctx, `SELECT 1 FROM zasp_security_agent_approvals WHERE run_id=$1 FOR UPDATE`, r); err != nil {
						t.Fatal(err)
					}
				}
				done := make(chan error, 1)
				go func() {
					_, err := orderedProgressionCall(ctx, action, "application", orderedApplicationRequest(o, w, e, r, steps[0], "claim", 4, 0))
					done <- err
				}()
				waitOrderedProgressionBlocked(t, ctx, owner, action)
				if mode == "schema" {
					var early bool
					if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND granted AND relation=ANY(ARRAY['zasp_schema_versions'::regclass,'zasp_security_agent_runs'::regclass,'zasp_security_agent_plans'::regclass,'zasp_security_agent_effects'::regclass,'zasp_policy_deployment_work'::regclass]))`, action.PgConn().PID()).Scan(&early); err != nil || early {
						t.Fatal("application acquired relation before schema fence", early, err)
					}
				}
				fault := map[string]string{"schema": `UPDATE zasp_security_agent_run_budgets SET stop_reason='budget_usage_unknown' WHERE run_id=$1`, "organization": `UPDATE zasp_security_agent_run_budgets SET stop_reason='budget_usage_unknown' WHERE run_id=$1`, "run": `UPDATE zasp_security_agent_runs SET state='cancelled',version=version+1 WHERE run_id=$1`, "plan": `UPDATE zasp_security_agent_plans SET expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1`, "approval": `UPDATE zasp_security_agent_approvals SET state='rejected',version=version+1 WHERE run_id=$1`}[mode]
				if fault != "" {
					if _, err := owner.Exec(ctx, fault, r); err != nil {
						t.Fatal(err)
					}
				} else {
					if _, err := owner.Exec(ctx, `SELECT pg_sleep(1.05)`); err != nil {
						t.Fatal(err)
					}
				}
				before := orderedApplicationSnapshot(t, ctx, owner, r)
				if _, err := owner.Exec(ctx, `COMMIT`); err != nil {
					t.Fatal(err)
				}
				if err := <-done; err == nil || orderedApplicationSnapshot(t, ctx, owner, r) != before {
					t.Fatal("claim used pre-wait authority", mode, err)
				}
				assertOrderedApplicationCounts(t, ctx, owner, r, 0, 0, 0, 1)
			})
		}
	})
}

func TestSecurityAgentMultistepApplicationGatewaySafetyPostgres(t *testing.T) {
	for _, mode := range []string{"device_revocation", "credential_rotation"} {
		t.Run(mode, func(t *testing.T) {
			runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
				action := orderedActionFenceConnection(t, ctx, owner)
				defer action.Close(ctx)
				seedOrderedApplicationGateway(t, ctx, owner, o, w, e)
				r, steps := seedOrderedApplicationRun(t, ctx, owner, worker, api, o, w, e, testID, actor, 790, true)
				if _, err := orderedProgressionCall(ctx, action, "application", orderedApplicationRequest(o, w, e, r, steps[0], "claim", 4, 0)); err != nil {
					t.Fatal(err)
				}
				if _, err := owner.Exec(ctx, `BEGIN; SET LOCAL statement_timeout='3s'`); err != nil {
					t.Fatal(err)
				}
				defer owner.Exec(ctx, `ROLLBACK`)
				lock := `SELECT 1 FROM zasp_gateway_devices WHERE id=$1 FOR UPDATE`
				if mode == "credential_rotation" {
					lock = `SELECT 1 FROM zasp_gateway_credentials WHERE id=$1 FOR UPDATE`
				}
				if _, err := owner.Exec(ctx, lock, orderedApplicationDevice); err != nil {
					t.Fatal(err)
				}
				request := orderedApplicationRequest(o, w, e, r, steps[0], "heartbeat", 5, 1)
				if _, err := orderedProgressionCall(ctx, action, "application", request); err == nil {
					t.Fatal("application waited behind safety source")
				}
				if mode == "device_revocation" {
					if _, err := owner.Exec(ctx, `UPDATE zasp_gateway_devices SET state='revoked',revoked_at=clock_timestamp() WHERE id=$1`, orderedApplicationDevice); err != nil {
						t.Fatal("revocation writer aborted", err)
					}
				} else {
					if _, err := owner.Exec(ctx, `UPDATE zasp_gateway_credentials SET revoked_at=clock_timestamp() WHERE id=$1`, orderedApplicationDevice); err != nil {
						t.Fatal("rotation revocation aborted", err)
					}
					if _, err := owner.Exec(ctx, `INSERT INTO zasp_gateway_credentials(organization_id,workspace_id,environment_id,id,device_id,enrollment_token_id,enrollment_digest,audience,key_reference,public_key,expires_at,format_version,credential_generation,key_id,algorithm,v15_issued_at) SELECT organization_id,workspace_id,environment_id,'pid_8f000009-0000-4000-8000-000000000009',device_id,enrollment_token_id,enrollment_digest,audience,key_reference,public_key,expires_at,format_version,2,key_id,algorithm,clock_timestamp() FROM zasp_gateway_credentials WHERE id=$1`, orderedApplicationDevice); err != nil {
						t.Fatal("rotation writer aborted", err)
					}
				}
				if _, err := owner.Exec(ctx, `COMMIT`); err != nil {
					t.Fatal(err)
				}
				before := orderedApplicationSnapshot(t, ctx, owner, r)
				if _, err := orderedProgressionCall(ctx, action, "application", request); err == nil || orderedApplicationSnapshot(t, ctx, owner, r) != before {
					t.Fatal("changed safety authority accepted", err)
				}
				assertOrderedApplicationCounts(t, ctx, owner, r, 1, 1, 0, 1)
			})
		})
	}
}
