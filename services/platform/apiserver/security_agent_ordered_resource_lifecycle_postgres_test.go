package apiserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

func orderedResourceGo(t *testing.T, c *pgx.Conn, o, w, e, actor string) (*SecurityAgentOrderedResourceAuthority, RequestIdentity) {
	t.Helper()
	repo, id := public62GoRepository(t, c, o, w, e, actor)
	a, err := NewSecurityAgentOrderedResourceAuthority(repo.database)
	if err != nil {
		t.Fatal(err)
	}
	return a, id
}

func TestSecurityAgentOrderedResourceLifecyclePostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		if err := precisionMigrationRunner(t, owner).UpProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
		public62Seed(t, ctx, owner, o, w, e, testID, actor)
		a, id := orderedResourceGo(t, api, o, w, e, actor)
		aq := SecurityAgentOrderedActivation{public62Definition, 1, "supervised", "ordered-resource-typed-activation"}
		result, err := a.Activate(ctx, id, aq)
		if err != nil || result.Version != 2 {
			t.Fatal(result, err)
		}
		before := public62Snapshot(t, ctx, owner)
		replay, err := a.Activate(ctx, id, aq)
		result.Replayed = true
		if err != nil || result != replay || public62Snapshot(t, ctx, owner) != before {
			t.Fatal(replay, err)
		}
		aq.Version = 2
		if _, err := a.Activate(ctx, id, aq); err != ErrRepositoryConflict || public62Snapshot(t, ctx, owner) != before {
			t.Fatal(err)
		}
		tq := SecurityAgentOrderedTrigger{SecurityAgentPublicTrigger{public62Definition, 2, public62Finding, 1, "ordered-resource-typed-trigger"}, "finding", "credential"}
		run, err := a.Trigger(ctx, id, tq)
		if err != nil || !validSecurityAgentRunResult(run, SecurityAgentRunRequest{DefinitionID: public62Definition, ExpectedVersion: 2, TriggerKind: "finding", TriggerID: public62Finding}) {
			t.Fatal(run, err)
		}
		before = public62Snapshot(t, ctx, owner)
		tq.TriggerSource = "wrong"
		if _, err := a.Trigger(ctx, id, tq); err != ErrRepositoryConflict || public62Snapshot(t, ctx, owner) != before {
			t.Fatal(err)
		}
		tq.TriggerSource = "credential"
		conn, err := pgx.ConnectConfig(ctx, api.Config().Copy())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close(ctx)
		restarted, _ := orderedResourceGo(t, conn, o, w, e, actor)
		again, err := restarted.Trigger(ctx, id, tq)
		run.Replayed = true
		if err != nil || !reflect.DeepEqual(run, again) || public62Snapshot(t, ctx, owner) != before {
			t.Fatal(again, err)
		}
		detail, err := a.Run(ctx, id, run.ID)
		if err != nil || detail.Detail.Run.State != "queued" || detail.Detail.Plan != nil {
			t.Fatal(detail, err)
		}
		if _, err := orderedPlanningCall(ctx, worker, map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run.ID, "worker_id": "ordered-resource-planner", "lease_token": "ordered-resource-lease-0001", "operation": "claim", "payload": map[string]any{}}); err != nil {
			t.Fatal(err)
		}
		detail, err = a.Run(ctx, id, run.ID)
		if err != nil || detail.Detail.Run.State != "planning" {
			t.Fatal(detail, err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_kill_switches SET execution_enabled=false WHERE organization_id=$1`, o); err != nil {
			t.Fatal(err)
		}
		cq := SecurityAgentPublicCancellation{run.ID, 2, "ordered-resource-typed-cancel"}
		cancelled, err := a.Cancel(ctx, id, cq)
		if err != nil || cancelled.Result.State != "needs_human" || cancelled.Result.Version != 3 || cancelled.CleanupRequired {
			t.Fatal(cancelled, err)
		}
		before = public62Snapshot(t, ctx, owner)
		repeated, err := restarted.Cancel(ctx, id, cq)
		cancelled.Result.Replayed = true
		if err != nil || !reflect.DeepEqual(cancelled, repeated) || public62Snapshot(t, ctx, owner) != before {
			t.Fatal(repeated, err)
		}
		cq.RunVersion = 3
		if _, err := a.Cancel(ctx, id, cq); err != ErrRepositoryConflict || public62Snapshot(t, ctx, owner) != before {
			t.Fatal(err)
		}
	})
}

func TestSecurityAgentOrderedResourceAdmittedPostgres(t *testing.T) {
	for _, decision := range []string{"approved", "rejected", "cancelled"} {
		t.Run(decision, func(t *testing.T) {
			runOrderedProgressionFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
				run, steps := public62PlannedRun(t, ctx, owner, api, o, w, e, testID, actor)
				a, id := orderedResourceGo(t, api, o, w, e, orderedProgressionApprover)
				id.FreshAuthenticated = true
				id.FreshAuthExpiresAt = time.Now().UTC().Add(4 * time.Minute)
				detail, err := a.Run(ctx, id, run)
				if err != nil || len(detail.Detail.Approvals) != 1 || !detail.Steps[1].Dependency.Blocked {
					t.Fatal(detail, err)
				}
				approval := detail.Detail.Approvals[0]
				got, err := a.Approval(ctx, id, approval.ID)
				if err != nil || got.Approval.State != "pending" || got.RunVersion != 3 {
					t.Fatal(got, err)
				}
				before := public62Snapshot(t, ctx, owner)
				blocked, _ := CanonicalDiscoveryID(id.Scope, "security_agent_ordered_approval", run+"\x1f"+steps[1])
				if _, err := a.Decide(ctx, id, SecurityAgentOrderedDecision{blocked, 1, "approved", "ordered-resource-early-step1"}); err != ErrSecurityAgentNotOwned || public62Snapshot(t, ctx, owner) != before {
					t.Fatal(err)
				}
				if decision == "cancelled" {
					result, err := a.Cancel(ctx, id, SecurityAgentPublicCancellation{run, 3, "ordered-resource-waiting-cancel"})
					if err != nil || result.Result.State != "cancelled" || result.CleanupRequired {
						t.Fatal(result, err)
					}
				} else {
					q := SecurityAgentOrderedDecision{approval.ID, 1, decision, "ordered-resource-typed-decision"}
					result, err := a.Decide(ctx, id, q)
					if err != nil || !validSecurityAgentApprovalResult(result, SecurityAgentApprovalDecisionRequest{ApprovalID: approval.ID, ExpectedVersion: 1, Decision: decision}) {
						t.Fatal(result, err)
					}
					before = public62Snapshot(t, ctx, owner)
					again, err := a.Decide(ctx, id, q)
					result.Replayed = true
					if err != nil || !reflect.DeepEqual(result, again) || public62Snapshot(t, ctx, owner) != before {
						t.Fatal(again, err)
					}
					read := public62Request(o, w, e, orderedProgressionApprover, "resource_approval")
					read["approval_id"] = approval.ID
					t.Run("decision-actor-proof", func(t *testing.T) {
						orderedResourceRefusal(t, ctx, owner, api, read, run, `UPDATE zasp_security_agent_approvals SET approver_id='pid_8d300001-0000-4000-8000-000000000003' WHERE run_id=$1`)
					})
					q.Decision = "rejected"
					if decision == "rejected" {
						q.Decision = "approved"
					}
					if _, err := a.Decide(ctx, id, q); err != ErrRepositoryConflict || public62Snapshot(t, ctx, owner) != before {
						t.Fatal(err)
					}
				}
				got, err = a.Approval(ctx, id, approval.ID)
				if err != nil || got.Approval.State != decision || got.Approval.Version != 2 {
					t.Fatal(got, err)
				}
			})
		})
	}
}

func TestSecurityAgentOrderedResourceRevokedApplicationPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		seedOrderedApplicationGateway(t, ctx, owner, o, w, e)
		run, steps := public62PlannedRun(t, ctx, owner, api, o, w, e, testID, actor)
		public62TypedDecision(t, ctx, api, o, w, e, run, 3)
		action := orderedActionFenceConnection(t, ctx, owner)
		defer action.Close(ctx)
		claim, err := orderedApplicationCall(ctx, action, orderedApplicationRequest(o, w, e, run, steps[0], "claim", 4, 0), policy.GatewayPolicyKeys{})
		if err != nil {
			t.Fatal(err)
		}
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey)})
		stored, err := orderedApplicationCall(ctx, action, orderedApplicationStoreRequest(t, o, w, e, run, steps[0], claim, key), keys)
		if err != nil {
			t.Fatal(err)
		}
		deployOrderedApplication(t, ctx, owner, key, stored)
		if _, err := orderedApplicationCall(ctx, action, orderedApplicationRequest(o, w, e, run, steps[0], "complete", 5, 2), keys); err != nil {
			t.Fatal(err)
		}
		if _, err := orderedProgressionCall(ctx, worker, "transition", orderedProgressionRequest(o, w, e, run, steps[1], "progress", "ordered-test-worker", 6)); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_gateway_credentials SET revoked_at=clock_timestamp() WHERE organization_id=$1`, o); err != nil {
			t.Fatal(err)
		}
		a, id := orderedResourceGo(t, api, o, w, e, orderedProgressionApprover)
		before := public62Snapshot(t, ctx, owner)
		detail, err := a.Run(ctx, id, run)
		if err != nil || detail.Steps[0].Receipt == nil || detail.Steps[1].Dependency.Ready || len(detail.Detail.Approvals) != 2 || public62Snapshot(t, ctx, owner) != before {
			t.Fatal(detail, err)
		}
		id.FreshAuthenticated = true
		id.FreshAuthExpiresAt = time.Now().UTC().Add(4 * time.Minute)
		if _, err := a.Decide(ctx, id, SecurityAgentOrderedDecision{detail.Detail.Approvals[1].ID, 1, "approved", "ordered-resource-revoked-decision"}); err == nil || public62Snapshot(t, ctx, owner) != before {
			t.Fatal("retained read authorized execution after revocation", err)
		}
		q := public62Request(o, w, e, orderedProgressionApprover, "resource_run")
		q["run_id"] = run
		for name, mutation := range map[string]string{
			"receipt":    `UPDATE zasp_sa_multistep_receipts SET body=jsonb_set(body,'{deployment_id}','"pid_8d300001-0000-4000-8000-000000000003"') WHERE run_id=$1`,
			"effect":     `UPDATE zasp_security_agent_effects SET result_digest=decode(repeat('00',32),'hex') WHERE run_id=$1`,
			"control":    `UPDATE zasp_security_agent_controls SET version=version+2 WHERE run_id=$1`,
			"deployment": `UPDATE zasp_security_agent_temporary_policy_targets SET desired_generation=desired_generation+1 WHERE run_id=$1`,
			"approval":   `UPDATE zasp_security_agent_approvals SET expires_at=expires_at+interval '1 minute' WHERE run_id=$1`,
		} {
			t.Run(name, func(t *testing.T) { orderedResourceRefusal(t, ctx, owner, api, q, run, mutation) })
		}
		legacyRead := public62Request(o, w, e, orderedProgressionApprover, "detail")
		legacyRead["run_id"] = run
		if _, err := public62Call(ctx, api, legacyRead); err == nil || public62Snapshot(t, ctx, owner) != before {
			t.Fatal("existing live projection weakened", err)
		}
		result, err := a.Cancel(ctx, id, SecurityAgentPublicCancellation{run, 7, "ordered-resource-revoked-cancel"})
		if err != nil || result.Result.State != "cancelled" || !result.CleanupRequired {
			t.Fatal(result, err)
		}
	})
}

func TestSecurityAgentOrderedResourceTerminalPostgres(t *testing.T) {
	public62TerminalFixture(t, func(ctx context.Context, owner, _, api, _ *pgx.Conn, o, w, e, run string, steps []string) {
		a, id := orderedResourceGo(t, api, o, w, e, orderedProgressionApprover)
		detail, err := a.Run(ctx, id, run)
		if err != nil || detail.Detail.Run.State != "contained" || detail.Detail.Verification != "verified" || len(detail.Detail.Approvals) != 2 || detail.Steps[1].Settlement != "not_reproduced" {
			t.Fatal(detail, err)
		}
		for _, approval := range detail.Detail.Approvals {
			got, err := a.Approval(ctx, id, approval.ID)
			if err != nil || got.Approval.State != "approved" {
				t.Fatal(got, err)
			}
		}
		before := public62Snapshot(t, ctx, owner)
		if _, err := a.Cancel(ctx, id, SecurityAgentPublicCancellation{run, detail.Detail.Run.Version, "ordered-resource-terminal-cancel"}); err != ErrRepositoryConflict || public62Snapshot(t, ctx, owner) != before {
			t.Fatal(err)
		}
	}, false)
}

func TestSecurityAgentOrderedResourceSuccessorPostgres(t *testing.T) {
	for _, decision := range []string{"approved", "rejected", "cancelled"} {
		t.Run(decision, func(t *testing.T) {
			runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
				seedOrderedApplicationGateway(t, ctx, owner, o, w, e)
				run, steps := public62PlannedRun(t, ctx, owner, api, o, w, e, testID, actor)
				public62TypedDecision(t, ctx, api, o, w, e, run, 3)
				action := orderedActionFenceConnection(t, ctx, owner)
				defer action.Close(ctx)
				claim, err := orderedApplicationCall(ctx, action, orderedApplicationRequest(o, w, e, run, steps[0], "claim", 4, 0), policy.GatewayPolicyKeys{})
				if err != nil {
					t.Fatal(err)
				}
				_, key, _ := ed25519.GenerateKey(rand.Reader)
				keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey)})
				stored, err := orderedApplicationCall(ctx, action, orderedApplicationStoreRequest(t, o, w, e, run, steps[0], claim, key), keys)
				if err != nil {
					t.Fatal(err)
				}
				deployOrderedApplication(t, ctx, owner, key, stored)
				if _, err := orderedApplicationCall(ctx, action, orderedApplicationRequest(o, w, e, run, steps[0], "complete", 5, 2), keys); err != nil {
					t.Fatal(err)
				}
				if _, err := orderedProgressionCall(ctx, worker, "transition", orderedProgressionRequest(o, w, e, run, steps[1], "progress", "ordered-test-worker", 6)); err != nil {
					t.Fatal(err)
				}
				a, id := orderedResourceGo(t, api, o, w, e, orderedProgressionApprover)
				id.FreshAuthenticated = true
				id.FreshAuthExpiresAt = time.Now().UTC().Add(4 * time.Minute)
				detail, err := a.Run(ctx, id, run)
				if err != nil || len(detail.Detail.Approvals) != 2 || !detail.Steps[1].Dependency.Ready {
					t.Fatal(detail, err)
				}
				approval := detail.Detail.Approvals[1]
				read, err := a.Approval(ctx, id, approval.ID)
				if err != nil || read.Approval.State != "pending" || read.Approval.TTLSeconds != 0 || read.Approval.Reversible || read.Approval.ExpectedEffect != "Run existing test" {
					t.Fatal(read, err)
				}
				if decision == "cancelled" {
					result, err := a.Cancel(ctx, id, SecurityAgentPublicCancellation{run, 7, "ordered-resource-successor-cancel"})
					if err != nil || !result.CleanupRequired || result.Result.Version != 8 {
						t.Fatal(result, err)
					}
				} else {
					q := SecurityAgentOrderedDecision{approval.ID, 1, decision, "ordered-resource-successor-decision"}
					result, err := a.Decide(ctx, id, q)
					if err != nil || result.Version != 2 || result.State != decision {
						t.Fatal(result, err)
					}
					before := public62Snapshot(t, ctx, owner)
					conn, err := pgx.ConnectConfig(ctx, api.Config().Copy())
					if err != nil {
						t.Fatal(err)
					}
					defer conn.Close(ctx)
					again, _ := orderedResourceGo(t, conn, o, w, e, orderedProgressionApprover)
					replay, err := again.Decide(ctx, id, q)
					result.Replayed = true
					if err != nil || !reflect.DeepEqual(result, replay) || public62Snapshot(t, ctx, owner) != before {
						t.Fatal(replay, err)
					}
				}
				read, err = a.Approval(ctx, id, approval.ID)
				if err != nil || read.Approval.State != decision || read.Approval.Version != 2 {
					t.Fatal(read, err)
				}
			})
		})
	}
}

// SQL must reject metadata before the combined mutation commits, not merely
// return bytes that the Go decoder will reject after durable authorization.
func TestSecurityAgentOrderedResourceFutureApprovalPostgres(t *testing.T) {
	for _, mode := range []string{"raw", "typed"} {
		t.Run(mode, func(t *testing.T) {
			runOrderedProgressionFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
				run, _ := public62PlannedRun(t, ctx, owner, api, o, w, e, testID, actor)
				for _, instant := range []string{"clock_timestamp()+interval '1 day'", "'infinity'::timestamptz", "'-infinity'::timestamptz"} {
					var approval string
					if err := owner.QueryRow(ctx, `UPDATE zasp_security_agent_approvals SET created_at=`+instant+` WHERE run_id=$1 RETURNING approval_id`, run).Scan(&approval); err != nil {
						t.Fatal(err)
					}
					before := public62Snapshot(t, ctx, owner)
					read := public62Request(o, w, e, orderedProgressionApprover, "resource_approval")
					read["approval_id"] = approval
					if _, err := public62Call(ctx, api, read); err == nil || public62Snapshot(t, ctx, owner) != before {
						t.Error("future approval read accepted or changed state", err)
					}
					var err error
					if mode == "raw" {
						q := public62Request(o, w, e, orderedProgressionApprover, "decide_resource")
						q["approval_id"], q["approval_version"], q["decision"], q["idempotency_key"], q["fresh_auth_at"] = approval, 1, "approved", "ordered-resource-future-approval", time.Now().UTC().Format(time.RFC3339Nano)
						_, err = public62Call(ctx, api, q)
					} else {
						a, id := orderedResourceGo(t, api, o, w, e, orderedProgressionApprover)
						id.FreshAuthenticated, id.FreshAuthExpiresAt = true, time.Now().UTC().Add(4*time.Minute)
						_, err = a.Decide(ctx, id, SecurityAgentOrderedDecision{approval, 1, "approved", "ordered-resource-future-approval"})
					}
					if err == nil || public62Snapshot(t, ctx, owner) != before {
						t.Fatal("future approval decision accepted or committed before refusal", err)
					}
				}
			})
		})
	}
}
