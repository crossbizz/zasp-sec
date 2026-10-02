package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

var orderedLegacyExecuteNames = []string{"zasp_security_agent_execute_run", "zasp_security_agent_execute_run_v21", "zasp_security_agent_execute_run_v22", "zasp_security_agent_execute_run_v23", "zasp_security_agent_execute_run_v24"}

func TestSecurityAgentMultistepLegacyExecuteFencePostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		for index, name := range orderedLegacyExecuteNames {
			t.Run(name, func(t *testing.T) {
				r, _ := seedOrderedActionFence(t, ctx, owner, worker, api, o, w, e, testID, actor, 600+index, true)
				// A planning-state fixture prevents refusal from depending on the
				// current dormant parent state instead of the immutable identity.
				if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_runs SET state='planning',lease_owner='ordered-worker',lease_token='ordered-admission-lease',lease_expires_at=clock_timestamp()+interval '1 hour' WHERE run_id=$1`, r); err != nil {
					t.Fatal(err)
				}
				caller := worker
				var granted bool
				if err := owner.QueryRow(ctx, `SELECT has_function_privilege($1,$2,'EXECUTE')`, worker.Config().User, "public."+name+"(text,text,text,text,text,text,text,text)").Scan(&granted); err != nil {
					t.Fatal(err)
				}
				if !granted {
					// The historical unversioned leaf is private. Inspect its guard
					// through the owner without granting any new caller authority.
					caller = owner
				}
				if _, err := caller.Exec(ctx, `SET lock_timeout='200ms'`); err != nil {
					t.Fatal(err)
				}
				defer caller.Exec(ctx, `RESET lock_timeout`)
				blocker, err := pgx.ConnectConfig(ctx, owner.Config().Copy())
				if err != nil {
					t.Fatal(err)
				}
				defer blocker.Close(ctx)
				tx, err := blocker.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(ctx)
				if _, err = tx.Exec(ctx, `SELECT 1 FROM zasp_security_agent_runs WHERE run_id=$1 FOR UPDATE`, r); err != nil {
					t.Fatal(err)
				}
				before := orderedActionFenceSnapshot(t, ctx, owner, r)
				var result json.RawMessage
				err = caller.QueryRow(ctx, `SELECT `+name+`($1,$2,$3,$4,'ordered-worker','ordered-admission-lease',$4,$4)`, o, w, e, r).Scan(&result)
				assertOrderedActionRefused(t, err)
				if orderedActionFenceSnapshot(t, ctx, owner, r) != before {
					t.Fatal("legacy execute entry changed ordered authority")
				}
			})
		}
	})
}

func TestSecurityAgentMultistepLegacyExecuteMigrationWaitPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		for index, name := range orderedLegacyExecuteNames {
			t.Run(name, func(t *testing.T) {
				r := seedOrderedLegacyExecute(t, ctx, owner, worker, api, o, w, e, testID, actor, 610+index)
				caller := worker
				if index == 0 {
					// The unversioned finding-response leaf remains ungranted.
					var err error
					caller, err = pgx.ConnectConfig(ctx, owner.Config().Copy())
					if err != nil {
						t.Fatal(err)
					}
					defer caller.Close(ctx)
				}
				tx, err := owner.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(ctx)
				// The migration's first lock is schema-exclusive. A caller must
				// wait there without owning Organization or relation/row locks.
				if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('zasp-schema-migrations',0))`); err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() {
					var result json.RawMessage
					done <- caller.QueryRow(ctx, `SELECT `+name+`($1,$2,$3,$4,'ordered-worker','ordered-admission-lease',$4,$4)`, o, w, e, r).Scan(&result)
				}()
				joined := false
				defer func() {
					tx.Rollback(ctx)
					if !joined {
						<-done
					}
				}()
				waitOrderedProgressionBlocked(t, ctx, owner, caller)
				var organizationFree bool
				if err = tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||$1,0))`, o).Scan(&organizationFree); err != nil || !organizationFree {
					t.Error("execute owns Organization admission before schema fence", organizationFree, err)
				}
				probe, err := tx.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				// Use a savepoint so the NOWAIT probe never retains downstream
				// locks or leaves the migration transaction aborted on RED.
				_, err = probe.Exec(ctx, `LOCK TABLE zasp_security_agent_runs IN ACCESS EXCLUSIVE MODE NOWAIT`)
				probe.Rollback(ctx)
				if err != nil {
					t.Error("migration/execute inversion: caller locked runs before schema fence", err)
				}
				if err = tx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				err, joined = <-done, true
				if index < 2 {
					// These older finding-only entries retain their existing refusal
					// for this temporary-policy fixture after schema admission.
					wantCode := "42501"
					if index == 1 {
						wantCode = "P0002"
					}
					var provider *pgconn.PgError
					if !errors.As(err, &provider) || provider.Code != wantCode {
						t.Fatal("historical finding-only entry changed", err)
					}
					return
				}
				if err != nil {
					t.Fatal("legacy execute changed after migration wait", err)
				}
				var state string
				if err = owner.QueryRow(ctx, `SELECT state FROM zasp_security_agent_effects WHERE run_id=$1`, r).Scan(&state); err != nil || state != "pending" {
					t.Fatal("legacy execute did not dispatch its single step", state, err)
				}
			})
		}
	})
}

func TestSecurityAgentMultistepLegacyExecutePrivateLeafPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		action := orderedActionFenceConnection(t, ctx, owner)
		defer action.Close(ctx)
		r, _ := seedOrderedActionFence(t, ctx, owner, worker, api, o, w, e, testID, actor, 620, true)
		for _, caller := range []*pgx.Conn{worker, api, action} {
			var result json.RawMessage
			err := caller.QueryRow(ctx, `SELECT zasp_security_agent_dispatch_temporary_policy_run($1,$2,$3,$4,'ordered-worker','ordered-admission-lease',$4,$4)`, o, w, e, r).Scan(&result)
			var provider *pgconn.PgError
			if !errors.As(err, &provider) || provider.Code != "42501" || !strings.Contains(provider.Message, "permission denied for function") {
				t.Error("private dispatch leaf became externally callable", caller.Config().User, err)
			}
		}
		var clean bool
		if err := owner.QueryRow(ctx, `SELECT position('zasp_sa_multistep_prior.legacy_action_fence' IN pg_get_functiondef('public.zasp_security_agent_dispatch_temporary_policy_run(text,text,text,text,text,text,text,text)'::regprocedure))=0 AND NOT EXISTS(SELECT 1 FROM zasp_sa_multistep_prior.functions WHERE signature='public.zasp_security_agent_dispatch_temporary_policy_run(text,text,text,text,text,text,text,text)')`).Scan(&clean); err != nil || !clean {
			t.Fatal("private dispatch leaf gained a late schema fence", clean, err)
		}
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err = tx.Exec(ctx, `GRANT EXECUTE ON FUNCTION public.zasp_security_agent_dispatch_temporary_policy_run(text,text,text,text,text,text,text,text) TO zasp_security_agent_worker`); err != nil {
			t.Fatal(err)
		}
		var ready bool
		if err = tx.QueryRow(ctx, `SELECT zasp_sa_multistep_readiness($1,$2)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint()).Scan(&ready); err != nil || ready {
			t.Fatal("private dispatch ACL drift was not fingerprinted", ready, err)
		}
	})
}

func seedOrderedLegacyExecute(t *testing.T, ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string, index int) string {
	t.Helper()
	r, s := seedOrderedActionFence(t, ctx, owner, worker, api, o, w, e, testID, actor, index, false)
	if _, err := owner.Exec(ctx, `DELETE FROM zasp_security_agent_effects WHERE run_id=$4;
 UPDATE zasp_security_agent_steps SET state='authorized' WHERE run_id=$4;
 INSERT INTO zasp_security_agent_approvals(organization_id,workspace_id,environment_id,approval_id,run_id,step_id,plan_hash,state,requester_id,approver_id,fresh_auth_at,expires_at,version,decided_at) SELECT $1,$2,$3,$4,$4,$5,plan_hash,'approved',$6,$7,clock_timestamp(),expires_at,2,clock_timestamp() FROM zasp_security_agent_plans WHERE run_id=$4;
 UPDATE zasp_security_agent_runs SET state='planning',lease_owner='ordered-worker',lease_token='ordered-admission-lease',lease_expires_at=clock_timestamp()+interval '1 hour' WHERE run_id=$4`, pgx.QueryExecModeSimpleProtocol, o, w, e, r, s, actor, orderedProgressionApprover); err != nil {
		t.Fatal(err)
	}
	return r
}
