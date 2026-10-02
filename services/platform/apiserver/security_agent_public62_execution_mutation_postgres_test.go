package apiserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

func public62TypedDecision(t *testing.T, ctx context.Context, api *pgx.Conn, o, w, e, run string, version int64) SecurityAgentPublicDecisionResult {
	t.Helper()
	repo, id := public62GoRepository(t, api, o, w, e, orderedProgressionApprover)
	id.FreshAuthenticated = true
	id.FreshAuthExpiresAt = time.Now().UTC().Add(5 * time.Minute)
	detail, err := repo.Run(ctx, id, run)
	if err != nil {
		t.Fatal(err)
	}
	var approval string
	for _, s := range detail.Steps {
		if s.State == "waiting_approval" {
			approval = *s.Approval.ApprovalID
		}
	}
	got, err := repo.Decide(ctx, id, SecurityAgentPublicDecision{RunID: run, RunVersion: version, ApprovalID: approval, ApprovalVersion: 1, Decision: "approved", IdempotencyKey: "public62-decision-" + approval})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// Every positive state comes from public activation/trigger, the real planning
// process, and the reviewed execution interfaces. Owner writes only configure
// gateways or advance an expired lease clock.
func TestSecurityAgentPublic62ExecutionCancellationPostgres(t *testing.T) {
	for _, stage := range []string{"waiting", "authorized", "application", "stored", "between", "revoked", "successor", "dispatched", "uncertainty"} {
		t.Run(stage, func(t *testing.T) {
			runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
				seedOrderedApplicationGateway(t, ctx, owner, o, w, e)
				seedOrderedTestSource(t, ctx, owner, o, w, e, actor)
				run, steps := public62PlannedRun(t, ctx, owner, api, o, w, e, testID, actor)
				action := orderedActionFenceConnection(t, ctx, owner)
				defer action.Close(ctx)
				repo, id := public62GoRepository(t, api, o, w, e, orderedProgressionApprover)
				version := int64(3)
				selected := steps[0]
				cleanup := false
				if stage != "waiting" {
					public62TypedDecision(t, ctx, api, o, w, e, run, 3)
					version = 4
				}
				if stage != "waiting" && stage != "authorized" {
					claim, err := orderedApplicationCall(ctx, action, orderedApplicationRequest(o, w, e, run, steps[0], "claim", 4, 0), policy.GatewayPolicyKeys{})
					if err != nil {
						t.Fatal(err)
					}
					version = 5
					cleanup = true
					if stage != "application" {
						_, key, _ := ed25519.GenerateKey(rand.Reader)
						keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey)})
						stored, err := orderedApplicationCall(ctx, action, orderedApplicationStoreRequest(t, o, w, e, run, steps[0], claim, key), keys)
						if err != nil {
							t.Fatal(err)
						}
						if stage != "stored" {
							deployOrderedApplication(t, ctx, owner, key, stored)
							if _, err := orderedApplicationCall(ctx, action, orderedApplicationRequest(o, w, e, run, steps[0], "complete", 5, 2), keys); err != nil {
								t.Fatal(err)
							}
							version = 6
							selected = steps[1]
							if stage != "between" && stage != "revoked" {
								if _, err := orderedProgressionCall(ctx, worker, "transition", orderedProgressionRequest(o, w, e, run, steps[1], "progress", "ordered-test-worker", 6)); err != nil {
									t.Fatal(err)
								}
								version = 7
								if stage != "successor" {
									result := public62TypedDecision(t, ctx, api, o, w, e, run, 7)
									if result.StepID != steps[1] || result.StepVersion != 3 {
										t.Fatal("successor decision", result)
									}
									decision := public62DecisionRequest(o, w, e, orderedProgressionApprover, run, result.ApprovalID, "approved", 7)
									decision["idempotency_key"] = "public62-decision-" + result.ApprovalID
									var decisionFreshAuth string
									if err := owner.QueryRow(ctx, `SELECT intent->>'fresh_auth_at' FROM zasp_security_agent_request_receipts WHERE receipt_id=$1`, result.ReceiptID).Scan(&decisionFreshAuth); err != nil {
										t.Fatal(err)
									}
									decision["fresh_auth_at"] = decisionFreshAuth
									public62MutationVersionRefused(t, ctx, owner, api, decision, run)
									q := orderedTestActionRequest(o, w, e, run, steps[1], "claim", 8, 0)
									q["lease_token"] = strings.Repeat("a", 32)
									testClaim, err := orderedProgressionCall(ctx, worker, "test_action", q)
									if err != nil {
										t.Fatal(err)
									}
									version = 9
									store, input := orderedTestInputArtifact(t, ctx, owner, o, w, e, run, steps[1], testClaim["test_run_id"].(string), testID)
									redWorker, adapter := orderedTestConnections(t, ctx, owner)
									defer redWorker.Close(ctx)
									defer adapter.Close(ctx)
									db, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: redWorker})
									private := &securityAgentMultistepAdmissionRepository{database: db}
									q = orderedTestActionRequest(o, w, e, run, steps[1], "dispatch", 9, 1)
									q["payload"] = map[string]any{"input_artifact": input}
									raw, _ := json.Marshal(q)
									if _, err := private.testDispatch(ctx, raw, store); err != nil {
										t.Fatal(err)
									}
									if stage == "uncertainty" {
										runOrderedJournalHTTPS(t, ctx, owner, o, w, e, testClaim["test_run_id"].(string), true)
									}
								}
							}
						}
					}
				}
				evidence := func() string {
					var s string
					if err := owner.QueryRow(ctx, `SELECT jsonb_build_array((SELECT jsonb_agg(to_jsonb(x) ORDER BY step_id) FROM zasp_security_agent_effects x WHERE run_id=$1),(SELECT jsonb_agg(to_jsonb(x) ORDER BY step_id) FROM zasp_sa_multistep_receipts x WHERE run_id=$1),(SELECT jsonb_agg(to_jsonb(x) ORDER BY step_id) FROM zasp_sa_multistep_prior.cleanups x WHERE run_id=$1),(SELECT jsonb_agg(to_jsonb(x) ORDER BY step_id,phase,device_id) FROM zasp_security_agent_temporary_policy_targets x WHERE run_id=$1))::text`, run).Scan(&s); err != nil {
						t.Fatal(err)
					}
					return s
				}
				before := evidence()
				if stage == "revoked" {
					if _, err := owner.Exec(ctx, `UPDATE zasp_gateway_credentials SET revoked_at=clock_timestamp() WHERE organization_id=$1`, o); err != nil {
						t.Fatal(err)
					}
				}
				q := SecurityAgentPublicCancellation{RunID: run, RunVersion: version, IdempotencyKey: "public62-execution-cancel-0001"}
				got, err := repo.Cancel(ctx, id, q)
				if err != nil || got.RunState != "cancelled" || got.RunVersion != version+1 || got.StepID == nil || *got.StepID != selected || got.CleanupRequired != cleanup || before != evidence() {
					probe := public62Request(o, w, e, orderedProgressionApprover, "cancel")
					probe["run_id"], probe["run_version"], probe["idempotency_key"] = run, version, q.IdempotencyKey
					raw, rawErr := public62Call(ctx, api, probe)
					t.Log("raw cancellation diagnostic", raw, rawErr)
					t.Fatal("cancel changed retained evidence", got, err)
				}
				phase := map[string]string{"waiting": "pending-approval", "authorized": "authorized", "application": "executing", "stored": "executing", "between": "queued", "revoked": "queued", "successor": "pending-approval", "dispatched": "executing", "uncertainty": "executing"}[stage]
				wantApprovalVersion := "1"
				if phase == "authorized" || phase == "executing" {
					wantApprovalVersion = "2"
				}
				var retainedApprovalVersion string
				if err := owner.QueryRow(ctx, `SELECT body->'request'->>'approval_version' FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind='ordered_run_cancelled'`, run).Scan(&retainedApprovalVersion); err != nil || retainedApprovalVersion != wantApprovalVersion || got.CancellationPhase != phase {
					t.Fatal("cancellation phase lost positive transition evidence", got, retainedApprovalVersion, err)
				}
				conn, err := pgx.ConnectConfig(ctx, api.Config().Copy())
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close(ctx)
				again, _ := public62GoRepository(t, conn, o, w, e, orderedProgressionApprover)
				replay, err := again.Cancel(ctx, id, q)
				got.Replayed = true
				if err != nil || !reflect.DeepEqual(got, replay) || before != evidence() {
					t.Fatal("cancel restart", replay, err)
				}
				wire := public62Request(o, w, e, orderedProgressionApprover, "cancel")
				wire["run_id"], wire["run_version"], wire["idempotency_key"] = run, version, q.IdempotencyKey
				public62MutationVersionRefused(t, ctx, owner, api, wire, run)
				if stage == "authorized" {
					public62MutationRefused(t, ctx, owner, api, wire, run, `DELETE FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind='ordered_approval_decided'; UPDATE zasp_security_agent_approvals SET state='cancelled' WHERE run_id=$1; UPDATE zasp_security_agent_request_receipts SET response=jsonb_set(jsonb_set(response,'{step_version}','2'),'{cancellation_phase}','"pending-approval"') WHERE resource_id=$1 AND operation='cancelSecurityAgentRun'; UPDATE zasp_security_agent_audit a SET body=jsonb_set(a.body,'{response}',x.response) FROM zasp_security_agent_request_receipts x WHERE x.resource_id=$1 AND x.operation='cancelSecurityAgentRun' AND a.audit_id=x.audit_id; UPDATE zasp_security_agent_audit SET event_digest=digest(convert_to(body::text,'UTF8'),'sha256') WHERE run_id=$1 AND event_kind='ordered_public_cancel'`)
					public62MutationRefused(t, ctx, owner, api, wire, run, `UPDATE zasp_security_agent_approvals SET state='cancelled' WHERE run_id=$1; UPDATE zasp_security_agent_request_receipts SET response=jsonb_set(response,'{step_version}','2') WHERE resource_id=$1 AND operation='cancelSecurityAgentRun'; UPDATE zasp_security_agent_audit a SET body=jsonb_set(a.body,'{response}',x.response) FROM zasp_security_agent_request_receipts x WHERE x.resource_id=$1 AND x.operation='cancelSecurityAgentRun' AND a.audit_id=x.audit_id; UPDATE zasp_security_agent_audit SET event_digest=digest(convert_to(body::text,'UTF8'),'sha256') WHERE run_id=$1 AND event_kind='ordered_public_cancel'`)
					public62MutationRefused(t, ctx, owner, api, wire, run, `UPDATE zasp_security_agent_approvals SET state='cancelled' WHERE run_id=$1; UPDATE zasp_security_agent_request_receipts SET response=jsonb_set(jsonb_set(response,'{step_version}','2'),'{cancellation_phase}','"pending-approval"') WHERE resource_id=$1 AND operation='cancelSecurityAgentRun'; UPDATE zasp_security_agent_audit a SET body=jsonb_set(a.body,'{response}',x.response) FROM zasp_security_agent_request_receipts x WHERE x.resource_id=$1 AND x.operation='cancelSecurityAgentRun' AND a.audit_id=x.audit_id; UPDATE zasp_security_agent_audit SET event_digest=digest(convert_to(body::text,'UTF8'),'sha256') WHERE run_id=$1 AND event_kind='ordered_public_cancel'`)
					for _, fault := range []string{
						`UPDATE zasp_security_agent_audit SET body=jsonb_set(body,'{request,approval_version}','1'),event_digest=digest(convert_to(jsonb_set(body->'request','{approval_version}','1')::text,'UTF8'),'sha256') WHERE run_id=$1 AND event_kind='ordered_run_cancelled'`,
						`UPDATE zasp_security_agent_audit SET body=jsonb_set(body,'{response,outcome}','"blocked"') WHERE run_id=$1 AND event_kind='ordered_approval_decided'`,
						`UPDATE zasp_security_agent_audit SET body=jsonb_set(body,'{request,operation}','"reject"'),event_digest=digest(convert_to(jsonb_set(body->'request','{operation}','"reject"')::text,'UTF8'),'sha256') WHERE run_id=$1 AND event_kind='ordered_approval_decided'`,
						`DELETE FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind='ordered_approval_decided'`,
					} {
						public62MutationRefused(t, ctx, owner, api, wire, run, fault)
					}
				}
				if stage == "stored" {
					wire := public62Request(o, w, e, orderedProgressionApprover, "cancel")
					wire["run_id"], wire["run_version"], wire["idempotency_key"] = run, version, q.IdempotencyKey
					public62MutationRefused(t, ctx, owner, api, wire, run, `UPDATE zasp_security_agent_request_receipts SET response=jsonb_set(response,'{cleanup_required}','false') WHERE resource_id=$1 AND operation='cancelSecurityAgentRun'; UPDATE zasp_security_agent_audit a SET body=jsonb_set(a.body,'{response}',x.response) FROM zasp_security_agent_request_receipts x WHERE x.resource_id=$1 AND x.operation='cancelSecurityAgentRun' AND a.audit_id=x.audit_id; UPDATE zasp_security_agent_audit SET event_digest=digest(convert_to(body::text,'UTF8'),'sha256') WHERE run_id=$1 AND event_kind='ordered_public_cancel'`)
				}
				q.IdempotencyKey = "public62-other-cancel-0001"
				q.RunVersion = version + 1
				if _, err = repo.Cancel(ctx, id, q); err != ErrRepositoryConflict {
					t.Fatal("terminal accepted", err)
				}
			})
		})
	}
}

func TestSecurityAgentPublic62ConcurrentMutationPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
		run, _ := public62PlannedRun(t, ctx, owner, api, o, w, e, testID, actor)
		var approval string
		if err := owner.QueryRow(ctx, `SELECT approval_id FROM zasp_security_agent_approvals WHERE run_id=$1`, run).Scan(&approval); err != nil {
			t.Fatal(err)
		}
		second, err := pgx.ConnectConfig(ctx, api.Config().Copy())
		if err != nil {
			t.Fatal(err)
		}
		defer second.Close(ctx)
		decision := public62DecisionRequest(o, w, e, orderedProgressionApprover, run, approval, "approved", 3)
		cancel := public62Request(o, w, e, orderedProgressionApprover, "cancel")
		cancel["run_id"], cancel["run_version"], cancel["idempotency_key"] = run, 3, "public62-race-cancel-0001"
		done := make(chan error, 2)
		start := make(chan struct{})
		go func() { <-start; _, err := public62Call(ctx, api, decision); done <- err }()
		go func() { <-start; _, err := public62Call(ctx, second, cancel); done <- err }()
		close(start)
		a, b := <-done, <-done
		if (a == nil) == (b == nil) {
			t.Fatal("race did not select exactly one mutation", a, b)
		}
		var counts string
		if err := owner.QueryRow(ctx, `SELECT jsonb_build_array((SELECT count(*) FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind IN('ordered_public_decide','ordered_public_cancel')),(SELECT count(*) FROM zasp_security_agent_steps WHERE run_id=$1),(SELECT count(*) FROM zasp_security_agent_approvals WHERE run_id=$1),(SELECT count(*) FROM zasp_security_agent_effects WHERE run_id=$1),(SELECT count(*) FROM zasp_sa_multistep_receipts WHERE run_id=$1))::text`, run).Scan(&counts); err != nil || counts != "[1, 2, 1, 0, 0]" {
			t.Fatal("race duplicated authority", counts, err)
		}
	})
}

func TestSecurityAgentPublic62CleanupCancellationRefusedPostgres(t *testing.T) {
	for _, partial := range []bool{false, true} {
		name := "completed"
		if partial {
			name = "partial"
		}
		t.Run(name, func(t *testing.T) {
			public62TerminalFixture(t, func(ctx context.Context, owner, _, api, action *pgx.Conn, o, w, e, run string, steps []string) {
				repo, id := public62GoRepository(t, api, o, w, e, orderedProgressionApprover)
				refuse := func() {
					t.Helper()
					var version int64
					if err := owner.QueryRow(ctx, `SELECT version FROM zasp_security_agent_runs WHERE run_id=$1`, run).Scan(&version); err != nil {
						t.Fatal(err)
					}
					snapshot := func() string {
						var v string
						if err := owner.QueryRow(ctx, `SELECT jsonb_build_array((SELECT jsonb_agg(to_jsonb(x)) FROM zasp_sa_multistep_prior.cleanups x WHERE run_id=$1),(SELECT jsonb_agg(to_jsonb(x)) FROM zasp_sa_multistep_prior.cleanup_receipts x WHERE run_id=$1),(SELECT jsonb_agg(to_jsonb(x)) FROM zasp_security_agent_effects x WHERE run_id=$1))::text`, run).Scan(&v); err != nil {
							t.Fatal(err)
						}
						return v + public62Snapshot(t, ctx, owner)
					}
					before := snapshot()
					if _, err := repo.Cancel(ctx, id, SecurityAgentPublicCancellation{RunID: run, RunVersion: version, IdempotencyKey: "public62-cleanup-cancel-0001"}); err != ErrRepositoryConflict {
						t.Fatal("terminal cleanup cancellation", err)
					}
					if before != snapshot() {
						t.Fatal("cancel mutated cleanup")
					}
				}
				refuse()
				_, key, _ := ed25519.GenerateKey(rand.Reader)
				keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey)})
				effectVersion := 3
				if partial {
					effectVersion = 4
				}
				claim, err := orderedCleanupCall(ctx, action, orderedCleanupRequest(o, w, e, run, steps[0], "claim", 10, effectVersion, 0), keys)
				if err != nil {
					t.Fatal(err)
				}
				refuse()
				stored := claim
				for _, target := range claim["targets"].([]any) {
					selected := cloneOrderedApplicationRequest(t, stored)
					selected["targets"] = []any{target}
					stored, err = orderedCleanupCall(ctx, action, orderedCleanupStoreRequest(t, o, w, e, run, steps[0], selected, key), keys)
					if err != nil {
						t.Fatal(err)
					}
				}
				selected := stored
				if partial {
					selected = cloneOrderedApplicationRequest(t, stored)
					selected["targets"] = []any{stored["targets"].([]any)[0]}
				}
				deployOrderedCleanup(t, ctx, owner, key, selected)
				if partial {
					if _, err := owner.Exec(ctx, `UPDATE zasp_sa_multistep_prior.cleanups SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1;UPDATE zasp_security_agent_effects SET lease_expires_at=(SELECT lease_expires_at FROM zasp_sa_multistep_prior.cleanups WHERE run_id=$1) WHERE run_id=$1 AND action_key='create_temporary_policy'`, pgx.QueryExecModeSimpleProtocol, run); err != nil {
						t.Fatal(err)
					}
					if _, err := orderedCleanupCall(ctx, action, orderedCleanupRequest(o, w, e, run, steps[0], "reconcile", 10, 7, 3), keys); err != nil {
						t.Fatal(err)
					}
				} else {
					if _, err := orderedCleanupCall(ctx, action, orderedCleanupRequest(o, w, e, run, steps[0], "complete", 10, 5, 2), keys); err != nil {
						t.Fatal(err)
					}
				}
				refuse()
			}, partial)
		})
	}
}
