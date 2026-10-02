package apiserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestSecurityAgentMultistepTestWaitPostgres(t *testing.T) {
	for index, mode := range []string{"concurrent_claim", "cancel_wins", "stop_wait", "schema_wait", "heartbeat_expiry_write_wait", "child_nowait"} {
		t.Run(mode, func(t *testing.T) {
			runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
				action := orderedActionFenceConnection(t, ctx, owner)
				defer action.Close(ctx)
				seedOrderedApplicationGateway(t, ctx, owner, o, w, e)
				r, steps := seedOrderedTestPredecessor(t, ctx, owner, worker, api, action, o, w, e, testID, actor, 910+index)
				request := orderedTestActionRequest(o, w, e, r, steps[1], "claim", 8, 0)
				var child string
				if mode == "heartbeat_expiry_write_wait" || mode == "child_nowait" {
					claim, err := orderedTestActionCall(ctx, worker, request)
					if err != nil {
						t.Fatal(err)
					}
					child = claim["test_run_id"].(string)
					request = orderedTestActionRequest(o, w, e, r, steps[1], "heartbeat", 9, 1)
				}
				blocker, err := pgx.ConnectConfig(ctx, owner.Config().Copy())
				if err != nil {
					t.Fatal(err)
				}
				defer blocker.Close(ctx)
				if _, err = blocker.Exec(ctx, `BEGIN`); err != nil {
					t.Fatal(err)
				}
				defer blocker.Exec(ctx, `ROLLBACK`)
				gate := `SELECT pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||$1,0))`
				args := []any{o}
				if mode == "schema_wait" {
					gate = `SELECT pg_advisory_xact_lock(hashtextextended('zasp-schema-migrations',0))`
					args = nil
				}
				if mode == "heartbeat_expiry_write_wait" {
					gate = `LOCK TABLE zasp_security_agent_audit IN SHARE MODE`
					args = nil
					if _, err = owner.Exec(ctx, `UPDATE zasp_security_agent_effects SET lease_expires_at=clock_timestamp()+interval '2 seconds' WHERE run_id=$1 AND action_key='run_test'`, r); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "child_nowait" {
					gate = `SELECT 1 FROM zasp_red_team_runs WHERE run_id=$1 FOR UPDATE`
					args = []any{child}
				}
				if _, err = blocker.Exec(ctx, gate, args...); err != nil {
					t.Fatal(err)
				}
				before := orderedTestSnapshot(t, ctx, owner, r)
				done := make(chan error, 1)
				go func() { _, err := orderedTestActionCall(ctx, worker, request); done <- err }()
				joined := false
				defer func() {
					if !joined {
						blocker.Exec(ctx, `ROLLBACK`)
						<-done
					}
				}()
				if mode == "child_nowait" {
					select {
					case err := <-done:
						joined = true
						if err == nil {
							t.Fatal("ordered heartbeat waited behind child writer")
						}
					case <-time.After(3 * time.Second):
						t.Fatal("ordered heartbeat blocked safety child writer")
					}
					if _, err = blocker.Exec(ctx, `UPDATE zasp_red_team_runs SET cancel_requested=true WHERE run_id=$1`, child); err != nil {
						t.Fatal(err)
					}
					if _, err = blocker.Exec(ctx, `ROLLBACK`); err != nil {
						t.Fatal(err)
					}
					if orderedTestSnapshot(t, ctx, owner, r) != before {
						t.Fatal("NOWAIT refusal mutated authority")
					}
					return
				}
				waitOrderedProgressionBlocked(t, ctx, blocker, worker)
				var second chan error
				if mode == "concurrent_claim" {
					other, err := pgx.ConnectConfig(ctx, worker.Config().Copy())
					if err != nil {
						t.Fatal(err)
					}
					defer other.Close(ctx)
					otherRequest := orderedTestActionRequest(o, w, e, r, steps[1], "claim", 8, 0)
					otherRequest["lease_token"] = strings.Repeat("b", 32)
					second = make(chan error, 1)
					go func() { _, err := orderedTestActionCall(ctx, other, otherRequest); second <- err }()
					waitOrderedProgressionBlocked(t, ctx, blocker, other)
				}
				switch mode {
				case "cancel_wins":
					if _, err = blocker.Exec(ctx, `SET SESSION AUTHORIZATION security_agent_v33_api_login`); err == nil {
						_, err = orderedProgressionCall(ctx, blocker, "transition", orderedProgressionRequest(o, w, e, r, steps[1], "cancel", orderedProgressionApprover, 8))
					}
				case "stop_wait":
					_, err = blocker.Exec(ctx, `UPDATE zasp_security_agent_run_budgets SET stop_reason='budget_usage_unknown' WHERE run_id=$1`, r)
				case "schema_wait":
					var reads bool
					if err = blocker.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND relation='zasp_security_agent_runs'::regclass AND granted)`, worker.PgConn().PID()).Scan(&reads); err != nil || reads {
						t.Fatal("schema waiter retained run authority", reads, err)
					}
					_, err = blocker.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_security_agent_multistep_checksum'`)
				case "heartbeat_expiry_write_wait":
					time.Sleep(2100 * time.Millisecond)
				}
				if err != nil {
					t.Fatal(err)
				}
				if _, err = blocker.Exec(ctx, `COMMIT`); err != nil {
					t.Fatal(err)
				}
				callErr := <-done
				joined = true
				if mode == "schema_wait" {
					if _, err = owner.Exec(ctx, `UPDATE zasp_schema_metadata SET value=$1 WHERE key='production_security_agent_multistep_checksum'`, migrations.ProductionSecurityAgentMultistep().Checksum()); err != nil {
						t.Fatal(err)
					}
				}
				if second != nil {
					otherErr := <-second
					if (callErr == nil) == (otherErr == nil) {
						t.Fatal("concurrent claim did not yield one lease", callErr, otherErr)
					}
					assertOrderedApplicationCounts(t, ctx, owner, r, 2, 2, 1, 2)
				} else if callErr == nil {
					t.Fatal("post-wait stale authority accepted")
				}
				if mode == "heartbeat_expiry_write_wait" || mode == "schema_wait" {
					if orderedTestSnapshot(t, ctx, owner, r) != before {
						t.Fatal("post-wait refusal mutated authority")
					}
				}
				if mode == "cancel_wins" || mode == "stop_wait" {
					assertOrderedApplicationCounts(t, ctx, owner, r, 1, 1, 1, 2)
				}
			})
		})
	}
}

func orderedTestSettlementWait(t *testing.T, ctx context.Context, owner, worker *pgx.Conn, store artifactstore.ObjectReferencingArtifactStore, o, w, e, r, s string, raw json.RawMessage, cancel bool) {
	t.Helper()
	blocker, err := pgx.ConnectConfig(ctx, owner.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close(ctx)
	if _, err = blocker.Exec(ctx, `BEGIN`); err != nil {
		t.Fatal(err)
	}
	defer blocker.Exec(ctx, `ROLLBACK`)
	gate := `LOCK TABLE zasp_security_agent_audit IN SHARE MODE`
	args := []any{}
	if cancel {
		gate = `SELECT pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||$1,0))`
		args = []any{o}
	} else if _, err = owner.Exec(ctx, `UPDATE zasp_security_agent_effects SET lease_expires_at=clock_timestamp()+interval '2 seconds' WHERE run_id=$1 AND action_key='run_test';UPDATE zasp_red_team_runs SET lease_expires_at=clock_timestamp()+interval '2 seconds' WHERE run_id IN(SELECT test_run_id FROM zasp_security_agent_test_links WHERE run_id=$1)`, pgx.QueryExecModeSimpleProtocol, r); err != nil {
		t.Fatal(err)
	}
	if _, err = blocker.Exec(ctx, gate, args...); err != nil {
		t.Fatal(err)
	}
	before := orderedTestSnapshot(t, ctx, owner, r)
	db, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
	repository := &securityAgentMultistepAdmissionRepository{database: db}
	done := make(chan error, 1)
	go func() { _, err := repository.testSettle(ctx, raw, store); done <- err }()
	joined := false
	defer func() {
		if !joined {
			blocker.Exec(ctx, `ROLLBACK`)
			<-done
		}
	}()
	waitOrderedProgressionBlocked(t, ctx, blocker, worker)
	var cancellationErr error
	if cancel {
		if _, err = blocker.Exec(ctx, `SET SESSION AUTHORIZATION security_agent_v33_api_login`); err != nil {
			t.Fatal(err)
		}
		db, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: blocker})
		request := orderedProgressionRequest(o, w, e, r, s, "cancel", orderedProgressionApprover, 9)
		request["approval_version"] = 2
		body, _ := json.Marshal(request)
		_, cancellationErr = (&securityAgentMultistepAdmissionRepository{database: db}).transition(ctx, body)
	} else {
		time.Sleep(2100 * time.Millisecond)
	}
	if _, err = blocker.Exec(ctx, `COMMIT`); err != nil {
		t.Fatal(err)
	}
	callErr := <-done
	joined = true
	if callErr == nil {
		t.Fatal("stale post-wait test settlement committed")
	}
	if !cancel && orderedTestSnapshot(t, ctx, owner, r) != before {
		t.Fatal("expired settlement mutated authority")
	}
	assertOrderedApplicationCounts(t, ctx, owner, r, 2, 2, 1, 2)
	if cancellationErr != nil {
		t.Fatal("private cancellation committed but its executing successor response was refused", cancellationErr)
	}
}
