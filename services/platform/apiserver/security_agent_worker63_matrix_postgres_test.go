package apiserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

func TestSecurityAgentWorker63CurrentHandoffPostgres(t *testing.T) {
	for _, expired := range []bool{false, true} {
		name := "live"
		if expired {
			name = "expired"
		}
		t.Run(name, func(t *testing.T) {
			runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
				runner := precisionMigrationRunner(t, owner)
				if err := runner.UpProductionSecurityAgentPublic(ctx); err != nil {
					t.Fatal(err)
				}
				if err := runner.UpProductionSecurityAgentWorker(ctx); err != nil {
					t.Fatal(err)
				}
				worker63Activate(t, ctx, owner, api, o, w, e, testID, actor)
				worker63Pricing(t, ctx, owner, o, w, e, actor)
				r := worker63Trigger(t, ctx, owner, api, o, w, e, actor, 500)
				q := worker63ClaimRequest("worker63-current-handoff")
				got, err := worker63Call(ctx, worker, q)
				if err != nil {
					t.Fatal(err)
				}
				item := got["item"].(map[string]any)
				worker63Admit(t, ctx, worker, o, w, e, r, testID, q, item)
				if expired {
					expiry, _ := time.Parse(time.RFC3339Nano, item["lease_expires_at"].(string))
					timer := time.NewTimer(time.Until(expiry) + 100*time.Millisecond)
					defer timer.Stop()
					select {
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					case <-timer.C:
					}
				}
				for _, mode := range []string{"kill-switch", "failed", "inconclusive", "contained", "remediated"} {
					tx, err := owner.Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					if mode == "kill-switch" {
						_, err = tx.Exec(ctx, `UPDATE zasp_security_agent_kill_switches SET execution_enabled=false WHERE (organization_id,workspace_id,environment_id,action_key)=($1,$2,$3,'*')`, o, w, e)
					} else {
						_, err = tx.Exec(ctx, `UPDATE zasp_security_agent_runs SET state=$2,completed_at=clock_timestamp() WHERE run_id=$1`, r, mode)
					}
					if err != nil {
						t.Fatal(err)
					}
					if _, err = tx.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{worker.Config().User}.Sanitize()); err != nil {
						t.Fatal(err)
					}
					request := map[string]any{"operation": "finish", "worker_id": q["worker_id"], "lease_token": q["lease_token"], "dispatch_id": item["dispatch_id"], "run_version": 3, "dispatch_version": 1}
					if expired {
						request = worker63ClaimRequest("worker63-current-expired")
					}
					raw, _ := json.Marshal(request)
					var response []byte
					callErr := tx.QueryRow(ctx, `SELECT zasp_ordered_worker63.worker($1,$2,$3::jsonb)`, worker63Checksum(), worker63Fingerprint(), raw).Scan(&response)
					released := false
					if callErr == nil {
						if _, err = tx.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{owner.Config().User}.Sanitize()); err != nil {
							t.Fatal(err)
						}
						if err = tx.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_ordered_worker63.dispatch_leases WHERE run_id=$1)`, r).Scan(&released); err != nil {
							t.Fatal(err)
						}
					}
					tx.Rollback(ctx)
					if released || mode != "kill-switch" && callErr == nil || !expired && callErr == nil {
						t.Error("released/refused no current handoff authority", name, mode, string(response), callErr)
					}
				}
			})
		})
	}
}
func worker63AssertHandoff(t *testing.T, ctx context.Context, owner, worker *pgx.Conn, r string, q, item map[string]any, expired, want bool) {
	t.Helper()
	before := orderedCleanupSnapshot(t, ctx, owner, r)
	var version int
	if err := owner.QueryRow(ctx, `SELECT version FROM zasp_security_agent_runs WHERE run_id=$1`, r).Scan(&version); err != nil {
		t.Fatal(err)
	}
	request := map[string]any{"operation": "finish", "worker_id": q["worker_id"], "lease_token": q["lease_token"], "dispatch_id": item["dispatch_id"], "run_version": version, "dispatch_version": 1}
	if expired {
		request = worker63ClaimRequest("worker63-matrix-observer")
	}
	tx, err := worker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(request)
	var response []byte
	callErr := tx.QueryRow(ctx, `SELECT zasp_ordered_worker63.worker($1,$2,$3::jsonb)`, worker63Checksum(), worker63Fingerprint(), raw).Scan(&response)
	if callErr == nil && !expired {
		var got map[string]any
		_ = json.Unmarshal(response, &got)
		if got["outcome"] != "finished" {
			t.Fatal(string(response))
		}
	}
	// Roll back only the probe, preserving genuine dispatch ownership so later
	// authority transitions can test the next matrix entry on the same real run.
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if !expired && ((callErr == nil) != want) {
		t.Fatal("live finish mismatch", want, string(response), callErr)
	}
	if expired {
		// Call as the real worker login, inspect its in-transaction deletion as
		// the owner, then roll back this probe so the next genuine stage can run.
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{worker.Config().User}.Sanitize()); err != nil {
			t.Fatal(err)
		}
		callErr = tx.QueryRow(ctx, `SELECT zasp_ordered_worker63.worker($1,$2,$3::jsonb)`, worker63Checksum(), worker63Fingerprint(), raw).Scan(&response)
		released := false
		if callErr == nil {
			if _, err = tx.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{owner.Config().User}.Sanitize()); err != nil {
				t.Fatal(err)
			}
			if err = tx.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_ordered_worker63.dispatch_leases WHERE run_id=$1)`, r).Scan(&released); err != nil {
				t.Fatal(err)
			}
		}
		tx.Rollback(ctx)
		if released != want {
			t.Fatal("expired handoff mismatch", want, released, string(response), callErr)
		}
	}
	if orderedCleanupSnapshot(t, ctx, owner, r) != before {
		t.Fatal("handoff probe altered predecessor")
	}
}

func worker63Wait(t *testing.T, ctx context.Context, expires time.Time) {
	t.Helper()
	timer := time.NewTimer(time.Until(expires) + 100*time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-timer.C:
	}
}

func TestSecurityAgentWorker63FinishMatrixPostgres(t *testing.T) {
	for _, mode := range []string{"progression", "action-expired", "cleanup-expired", "rejected", "cancelled"} {
		for _, expired := range []bool{false, true} {
			name := mode + "/live"
			if expired {
				name = mode + "/expired"
			}
			t.Run(name, func(t *testing.T) {
				runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
					ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
					defer cancel()
					runner := precisionMigrationRunner(t, owner)
					if err := runner.UpProductionSecurityAgentPublic(ctx); err != nil {
						t.Fatal(err)
					}
					if err := runner.UpProductionSecurityAgentWorker(ctx); err != nil {
						t.Fatal(err)
					}
					worker63Activate(t, ctx, owner, api, o, w, e, testID, actor)
					worker63Pricing(t, ctx, owner, o, w, e, actor)
					action := orderedActionFenceConnection(t, ctx, owner)
					defer action.Close(ctx)
					seedOrderedApplicationGateway(t, ctx, owner, o, w, e)
					seedOrderedTestSource(t, ctx, owner, o, w, e, actor)
					r := worker63Trigger(t, ctx, owner, api, o, w, e, actor, 600)
					q := worker63ClaimRequest("worker63-matrix-planner")
					if !expired {
						q["lease_seconds"] = 300
					}
					got, err := worker63Call(ctx, worker, q)
					if err != nil {
						t.Fatal(err)
					}
					item := got["item"].(map[string]any)
					worker63Admit(t, ctx, worker, o, w, e, r, testID, q, item)
					var steps []string
					if err = owner.QueryRow(ctx, `SELECT array_agg(step_id ORDER BY step_index) FROM zasp_security_agent_steps WHERE run_id=$1`, r).Scan(&steps); err != nil {
						t.Fatal(err)
					}
					if expired {
						expiry, _ := time.Parse(time.RFC3339Nano, item["lease_expires_at"].(string))
						worker63Wait(t, ctx, expiry)
					}
					worker63AssertHandoff(t, ctx, owner, worker, r, q, item, expired, true)
					if mode == "rejected" || mode == "cancelled" {
						op := "reject"
						if mode == "cancelled" {
							op = "cancel"
						}
						result, err := orderedProgressionCall(ctx, api, "transition", orderedProgressionRequest(o, w, e, r, steps[0], op, orderedProgressionApprover, 3))
						want := "needs_human"
						if mode == "cancelled" {
							want = "cancelled"
						}
						if err != nil || result["run_state"] != want {
							t.Fatal("authentic terminal", result, err)
						}
						worker63AssertHandoff(t, ctx, owner, worker, r, q, item, expired, true)
						return
					}
					if _, err = orderedProgressionCall(ctx, api, "transition", orderedProgressionRequest(o, w, e, r, steps[0], "approve", orderedProgressionApprover, 3)); err != nil {
						t.Fatal(err)
					}
					worker63AssertHandoff(t, ctx, owner, worker, r, q, item, expired, false)
					applicationRequest := orderedApplicationRequest(o, w, e, r, steps[0], "claim", 4, 0)
					if mode == "action-expired" {
						applicationRequest["lease_seconds"] = 30
					}
					claim, err := orderedApplicationCall(ctx, action, applicationRequest, policy.GatewayPolicyKeys{})
					if err != nil {
						t.Fatal(err)
					}
					worker63AssertHandoff(t, ctx, owner, worker, r, q, item, expired, true)
					if mode == "action-expired" {
						var expiry time.Time
						if err = owner.QueryRow(ctx, `SELECT lease_expires_at FROM zasp_security_agent_effects WHERE run_id=$1 AND step_id=$2`, r, steps[0]).Scan(&expiry); err != nil {
							t.Fatal(err)
						}
						worker63Wait(t, ctx, expiry)
						worker63AssertHandoff(t, ctx, owner, worker, r, q, item, expired, false)
						return
					}
					_, key, err := ed25519.GenerateKey(rand.Reader)
					if err != nil {
						t.Fatal(err)
					}
					keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey)})
					stored, err := orderedApplicationCall(ctx, action, orderedApplicationStoreRequest(t, o, w, e, r, steps[0], claim, key), keys)
					if err != nil {
						t.Fatal(err)
					}
					deployOrderedApplication(t, ctx, owner, key, stored)
					if _, err = orderedApplicationCall(ctx, action, orderedApplicationRequest(o, w, e, r, steps[0], "complete", 5, 2), keys); err != nil {
						t.Fatal(err)
					}
					worker63AssertHandoff(t, ctx, owner, worker, r, q, item, expired, false)
					if _, err = orderedProgressionCall(ctx, worker, "transition", orderedProgressionRequest(o, w, e, r, steps[1], "progress", "ordered-test-worker", 6)); err != nil {
						t.Fatal(err)
					}
					worker63AssertHandoff(t, ctx, owner, worker, r, q, item, expired, true)
					if _, err = orderedProgressionCall(ctx, api, "transition", orderedProgressionRequest(o, w, e, r, steps[1], "approve", orderedProgressionApprover, 7)); err != nil {
						t.Fatal(err)
					}
					worker63AssertHandoff(t, ctx, owner, worker, r, q, item, expired, false)
					testRequest := orderedTestActionRequest(o, w, e, r, steps[1], "claim", 8, 0)
					testRequest["lease_seconds"] = 30
					testClaim, err := orderedTestActionCall(ctx, worker, testRequest)
					if err != nil {
						t.Fatal(err)
					}
					worker63AssertHandoff(t, ctx, owner, worker, r, q, item, expired, true)
					var testExpiry time.Time
					if err = owner.QueryRow(ctx, `SELECT lease_expires_at FROM zasp_security_agent_effects WHERE run_id=$1 AND step_id=$2`, r, steps[1]).Scan(&testExpiry); err != nil {
						t.Fatal(err)
					}
					worker63Wait(t, ctx, testExpiry)
					worker63AssertHandoff(t, ctx, owner, worker, r, q, item, expired, false)
					testRequest = orderedTestActionRequest(o, w, e, r, steps[1], "claim", 9, 1)
					testRequest["lease_token"] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
					testClaim, err = orderedTestActionCall(ctx, worker, testRequest)
					if err != nil {
						t.Fatal(err)
					}
					redWorker, adapter := orderedTestConnections(t, ctx, owner)
					defer redWorker.Close(ctx)
					defer adapter.Close(ctx)
					store, input := orderedTestInputArtifact(t, ctx, owner, o, w, e, r, steps[1], testClaim["test_run_id"].(string), testID)
					database, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: redWorker})
					boundary := &securityAgentMultistepAdmissionRepository{database: database}
					dispatch := orderedTestActionRequest(o, w, e, r, steps[1], "dispatch", 10, 2)
					dispatch["lease_token"] = testRequest["lease_token"]
					dispatch["payload"] = map[string]any{"input_artifact": input}
					raw, _ := json.Marshal(dispatch)
					if _, err = boundary.testDispatch(ctx, raw, store); err != nil {
						t.Fatal("test dispatch", err)
					}
					runOrderedJournalHTTPS(t, ctx, owner, o, w, e, testClaim["test_run_id"].(string), false)
					output := orderedTestOutputArtifact(t, ctx, owner, store, o, w, e, r, steps[1], testClaim["test_run_id"].(string), input)
					settle := orderedTestActionRequest(o, w, e, r, steps[1], "settle", 10, 2)
					settle["lease_token"] = testRequest["lease_token"]
					settle["payload"] = map[string]any{"input_artifact": input, "output_artifact": output}
					raw, _ = json.Marshal(settle)
					result, err := boundary.testSettle(ctx, raw, store)
					if err != nil {
						t.Fatal("test settlement", string(result), err)
					}
					var terminal map[string]any
					_ = json.Unmarshal(result, &terminal)
					if terminal["run_state"] != "contained" {
						t.Fatal(terminal)
					}
					worker63AssertHandoff(t, ctx, owner, worker, r, q, item, expired, true)
					cleanupRequest := orderedCleanupRequest(o, w, e, r, steps[0], "claim", 11, 3, 0)
					if mode == "cleanup-expired" {
						cleanupRequest["lease_seconds"] = 30
					}
					cleanup, err := orderedCleanupCall(ctx, action, cleanupRequest, keys)
					if err != nil {
						t.Fatal("cleanup claim", err)
					}
					worker63AssertHandoff(t, ctx, owner, worker, r, q, item, expired, true)
					if mode == "cleanup-expired" {
						expiry, _ := time.Parse(time.RFC3339Nano, cleanup["lease_expires_at"].(string))
						worker63Wait(t, ctx, expiry)
						worker63AssertHandoff(t, ctx, owner, worker, r, q, item, expired, false)
						return
					}
					cleanupStore := orderedCleanupStoreRequest(t, o, w, e, r, steps[0], cleanup, key)
					cleanupStored, err := orderedCleanupCall(ctx, action, cleanupStore, keys)
					if err != nil {
						t.Fatal(err)
					}
					deployOrderedCleanup(t, ctx, owner, key, cleanupStored)
					complete, err := orderedCleanupCall(ctx, action, orderedCleanupRequest(o, w, e, r, steps[0], "complete", 11, 5, 2), keys)
					if err != nil || complete["run_state"] != "remediated" {
						t.Fatal("authentic remediated", complete, err)
					}
					worker63AssertHandoff(t, ctx, owner, worker, r, q, item, expired, true)
				})
			})
		}
	}
}
