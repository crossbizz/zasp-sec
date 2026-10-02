package apiserver

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func public62DecisionRequest(o, w, e, actor, run, approval, decision string, version int) map[string]any {
	q := public62Request(o, w, e, actor, "decide")
	q["run_id"], q["run_version"], q["approval_id"], q["approval_version"], q["decision"], q["idempotency_key"], q["fresh_auth_at"] = run, version, approval, 1, decision, "public62-decision-0001", time.Now().UTC().Format(time.RFC3339Nano)
	return q
}

func public62MutationVersionRefused(t *testing.T, ctx context.Context, owner, api *pgx.Conn, q map[string]any, run string) {
	t.Helper()
	public62MutationRefused(t, ctx, owner, api, q, run, `UPDATE zasp_security_agent_request_receipts SET response=jsonb_set(response,'{step_version}',to_jsonb((response->>'step_version')::bigint-1)) WHERE resource_id=$1 AND operation IN('decideSecurityAgentApproval','cancelSecurityAgentRun'); UPDATE zasp_security_agent_audit a SET body=jsonb_set(a.body,'{response}',x.response) FROM zasp_security_agent_request_receipts x WHERE x.resource_id=$1 AND x.operation IN('decideSecurityAgentApproval','cancelSecurityAgentRun') AND a.audit_id=x.audit_id; UPDATE zasp_security_agent_audit SET event_digest=digest(convert_to(body::text,'UTF8'),'sha256') WHERE run_id=$1 AND event_kind IN('ordered_public_decide','ordered_public_cancel')`)
}

func public62PreAdmissionStateRefused(t *testing.T, ctx context.Context, owner, api *pgx.Conn, q map[string]any, run string) {
	t.Helper()
	public62MutationRefused(t, ctx, owner, api, q, run, `UPDATE zasp_security_agent_request_receipts SET response=jsonb_set(response,'{run_state}',CASE response->>'run_state' WHEN 'cancelled' THEN '"needs_human"'::jsonb ELSE '"cancelled"'::jsonb END) WHERE resource_id=$1 AND operation='cancelSecurityAgentRun'; UPDATE zasp_security_agent_audit a SET body=jsonb_set(a.body,'{response}',x.response) FROM zasp_security_agent_request_receipts x WHERE x.resource_id=$1 AND x.operation='cancelSecurityAgentRun' AND a.audit_id=x.audit_id; UPDATE zasp_security_agent_audit SET event_digest=digest(convert_to(body::text,'UTF8'),'sha256') WHERE run_id=$1 AND event_kind='ordered_public_cancel'`)
}

func public62QueuedMutationRun(t *testing.T, ctx context.Context, owner, api *pgx.Conn, o, w, e, testID, actor string) (*SecurityAgentPublicRepository, RequestIdentity, string) {
	t.Helper()
	if err := precisionMigrationRunner(t, owner).UpProductionSecurityAgentPublic(ctx); err != nil {
		t.Fatal(err)
	}
	public62Seed(t, ctx, owner, o, w, e, testID, actor)
	repo, id := public62GoRepository(t, api, o, w, e, actor)
	if _, err := repo.Activate(ctx, id, public62Definition, 1); err != nil {
		t.Fatal(err)
	}
	got, err := repo.Trigger(ctx, id, SecurityAgentPublicTrigger{DefinitionID: public62Definition, DefinitionVersion: 2, TriggerID: public62Finding, TriggerVersion: 1, IdempotencyKey: "public62-mutation-trigger-0001"})
	if err != nil {
		t.Fatal(err)
	}
	return repo, id, got.RunID
}

func TestSecurityAgentPublic62PlanningCancellationPostgres(t *testing.T) {
	for _, stage := range []string{"claimed", "started", "completed"} {
		t.Run(stage, func(t *testing.T) {
			runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
				repo, id, run := public62QueuedMutationRun(t, ctx, owner, api, o, w, e, testID, actor)
				if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET role='organization_admin' WHERE principal_id=$1;UPDATE zasp_authorized_scopes SET permissions='["view","manage_identity","manage_workflows","run_tests"]' WHERE principal_id=$1`, pgx.QueryExecModeSimpleProtocol, actor); err != nil {
					t.Fatal(err)
				}
				q := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "worker_id": "ordered-planner", "lease_token": "ordered-planner-lease-0001", "operation": "claim", "payload": map[string]any{}}
				if _, err := orderedPlanningCall(ctx, worker, q); err != nil {
					t.Fatal(err)
				}
				if stage != "claimed" {
					cfg := owner.Config().Copy()
					cfg.User = "security_agent_v33_discovery_api_login"
					admin, err := pgx.ConnectConfig(ctx, cfg)
					if err != nil {
						t.Fatal(err)
					}
					defer admin.Close(ctx)
					pricing := orderedPricingAdminRequest(o, w, e, actor)
					created, err := orderedPricingCall(ctx, admin, "pricing_admin", pricing)
					if err != nil {
						t.Fatal(err)
					}
					selection := orderedPricingLookupRequest(o, w, e, pricing["policy"].(map[string]any), created)
					delete(selection, "body")
					delete(selection, "body_digest")
					q["operation"], q["payload"] = "prepare", map[string]any{"pricing": selection, "input_version": "public62-input-version"}
					if _, err = orderedPlanningCall(ctx, worker, q); err != nil {
						t.Fatal(err)
					}
					q["operation"], q["payload"] = "start", map[string]any{}
					if _, err = orderedPlanningCall(ctx, worker, q); err != nil {
						t.Fatal(err)
					}
					if stage == "completed" {
						candidate, _ := json.Marshal(map[string]any{"version": 1, "summary": "Contain and retest", "steps": []any{map[string]any{"index": 0, "action": "create_temporary_policy", "target_id": e}, map[string]any{"index": 1, "action": "run_test", "target_id": testID}}})
						raw, _ := json.Marshal(map[string]any{"model": "openai/gpt-5-mini", "choices": []any{map[string]any{"index": 0, "finish_reason": "stop", "message": map[string]any{"role": "assistant", "content": string(candidate)}}}, "usage": map[string]any{"prompt_tokens": 50, "completion_tokens": 50, "total_tokens": 100, "cost": 0.0000005}})
						q["operation"], q["payload"] = "result", map[string]any{"raw": string(raw)}
						if _, err = orderedPlanningCall(ctx, worker, q); err != nil {
							t.Fatal(err)
						}
					}
				}
				snapshot := func() string {
					var v string
					if err := owner.QueryRow(ctx, `SELECT jsonb_build_array((SELECT to_jsonb(j) FROM zasp_sa_multistep_prior.planning_jobs j WHERE run_id=$1),(SELECT jsonb_agg(to_jsonb(p)) FROM zasp_security_agent_provider_reservations p WHERE run_id=$1),(SELECT to_jsonb(b) FROM zasp_security_agent_run_budgets b WHERE run_id=$1))::text`, run).Scan(&v); err != nil {
						t.Fatal(err)
					}
					return v
				}
				before := snapshot()
				request := SecurityAgentPublicCancellation{RunID: run, RunVersion: 2, IdempotencyKey: "public62-planning-cancel-0001"}
				got, err := repo.Cancel(ctx, id, request)
				if err != nil || got.RunState != "needs_human" || got.StepID != nil || got.CleanupRequired || snapshot() != before {
					t.Fatal("planning cancellation lost evidence", got, err)
				}
				wire := public62Request(o, w, e, actor, "cancel")
				wire["run_id"], wire["run_version"], wire["idempotency_key"] = run, 2, request.IdempotencyKey
				public62PreAdmissionStateRefused(t, ctx, owner, api, wire, run)
				if detail, err := repo.Run(ctx, id, run); err != nil || detail.State != "needs_human" || detail.Admitted {
					t.Fatal(detail, err)
				}
				q["operation"], q["payload"] = "claim", map[string]any{}
				if _, err := orderedPlanningCall(ctx, worker, q); err == nil {
					t.Fatal("late planner retained authority")
				}
				// Advance only the owned lease clock, never manufacture provider evidence.
				if _, err := owner.Exec(ctx, `UPDATE zasp_sa_multistep_prior.planning_jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1`, run); err != nil {
					t.Fatal(err)
				}
				q["operation"] = "reconcile"
				recovered, err := orderedPlanningCall(ctx, worker, q)
				if err != nil || recovered["state"] != "needs_human" {
					t.Fatal("cancel stranded retained recovery", recovered, err)
				}
				var settled bool
				if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_security_agent_provider_reservations WHERE run_id=$1 AND settled_at IS NOT NULL AND total_tokens=100 AND cost_nano_credits=500)`, run).Scan(&settled); err != nil || settled != (stage == "completed") {
					t.Fatal("recovery settlement", settled, err)
				}
				replay, err := repo.Cancel(ctx, id, request)
				if err != nil || !replay.Replayed || replay.RunVersion != 3 {
					t.Fatal("recovery changed cancellation receipt", replay, err)
				}
			})
		})
	}
}

func TestSecurityAgentPublic62DecisionRefusalsPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
		run, steps := public62PlannedRun(t, ctx, owner, api, o, w, e, testID, actor)
		var approval string
		if err := owner.QueryRow(ctx, `SELECT approval_id FROM zasp_security_agent_approvals WHERE run_id=$1`, run).Scan(&approval); err != nil {
			t.Fatal(err)
		}
		q := public62DecisionRequest(o, w, e, orderedProgressionApprover, run, approval, "approved", 3)
		_, scopeID := public62GoRepository(t, api, o, w, e, actor)
		early, _ := CanonicalDiscoveryID(scopeID.Scope, "security_agent_ordered_approval", run+"\x1f"+steps[1])
		for name, patch := range map[string]map[string]any{"early-successor": {"approval_id": early}, "self": {"actor_id": actor}, "stale-run": {"run_version": 2}, "stale-approval": {"approval_version": 2}, "expired-auth": {"fresh_auth_at": time.Now().UTC().Add(-6 * time.Minute).Format(time.RFC3339Nano)}, "future-auth": {"fresh_auth_at": time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)}, "wrong-decision": {"decision": "cancelled"}, "caller-step": {"step_id": steps[1]}, "foreign": {"organization_id": "pid_ffffffff-ffff-4fff-8fff-ffffffffffff"}, "missing": {"run_id": "pid_ffffffff-ffff-4fff-8fff-ffffffffffff"}} {
			t.Run(name, func(t *testing.T) {
				bad := cloneOrderedApplicationRequest(t, q)
				for k, v := range patch {
					bad[k] = v
				}
				before := public62Snapshot(t, ctx, owner) + orderedAdmissionSnapshot(t, ctx, owner, run)
				if _, err := public62Call(ctx, api, bad); err == nil {
					t.Fatal("invalid decision accepted")
				}
				if before != public62Snapshot(t, ctx, owner)+orderedAdmissionSnapshot(t, ctx, owner, run) {
					t.Fatal("refusal mutated owner")
				}
			})
		}
		repo, id := public62GoRepository(t, api, o, w, e, orderedProgressionApprover)
		id.FreshAuthenticated = true
		id.FreshAuthExpiresAt = time.Now().UTC().Add(5 * time.Minute)
		request := SecurityAgentPublicDecision{RunID: run, RunVersion: 3, ApprovalID: approval, ApprovalVersion: 1, Decision: "approved", IdempotencyKey: "public62-typed-decision-0001"}
		if got, err := repo.Decide(ctx, id, request); err != nil || got.StepID != steps[0] || got.RunVersion != 4 {
			t.Fatal(got, err)
		}
		request.IdempotencyKey = "public62-other-decision-0001"
		request.RunVersion = 4
		if _, err := repo.Decide(ctx, id, request); err != ErrRepositoryConflict {
			t.Fatal("decided approval accepted", err)
		}
	})
}

func TestSecurityAgentPublic62DecisionAuthorityPostgres(t *testing.T) {
	for _, decision := range []string{"approved", "rejected"} {
		t.Run(decision, func(t *testing.T) {
			runOrderedProgressionFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
				run, steps := public62PlannedRun(t, ctx, owner, api, o, w, e, testID, actor)
				var approval string
				if err := owner.QueryRow(ctx, `SELECT approval_id FROM zasp_security_agent_approvals WHERE run_id=$1 AND step_id=$2`, run, steps[0]).Scan(&approval); err != nil {
					t.Fatal(err)
				}
				q := public62DecisionRequest(o, w, e, orderedProgressionApprover, run, approval, decision, 3)
				got, err := public62Call(ctx, api, q)
				if err != nil {
					t.Fatal("public decision missing", err)
				}
				state, outcome, stepState := "running", "approved", "authorized"
				if decision == "rejected" {
					state, outcome, stepState = "needs_human", "blocked", "cancelled"
				}
				if got["run_version"] != float64(4) || got["approval_version"] != float64(2) || got["step_version"] != float64(2) || got["decision"] != decision || got["run_state"] != state || got["outcome"] != outcome || got["step_state"] != stepState || got["step_id"] != steps[0] {
					t.Fatal(got)
				}
				before := public62Snapshot(t, ctx, owner) + orderedAdmissionSnapshot(t, ctx, owner, run)
				conn, err := pgx.ConnectConfig(ctx, api.Config().Copy())
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close(ctx)
				replay, err := public62Call(ctx, conn, q)
				got["replayed"] = true
				if err != nil || !reflect.DeepEqual(got, replay) || before != public62Snapshot(t, ctx, owner)+orderedAdmissionSnapshot(t, ctx, owner, run) {
					t.Fatal("restart replay", replay, err)
				}
				public62MutationRefused(t, ctx, owner, api, q, run, `UPDATE zasp_security_agent_request_receipts SET response=jsonb_set(response,'{step_version}','"2"') WHERE resource_id=$1 AND operation='decideSecurityAgentApproval'; UPDATE zasp_security_agent_audit a SET body=jsonb_set(a.body,'{response}',x.response) FROM zasp_security_agent_request_receipts x WHERE x.resource_id=$1 AND x.operation='decideSecurityAgentApproval' AND a.audit_id=x.audit_id; UPDATE zasp_security_agent_audit SET event_digest=digest(convert_to(body::text,'UTF8'),'sha256') WHERE run_id=$1 AND event_kind='ordered_public_decide'`)
				public62MutationRefused(t, ctx, owner, api, q, run, `UPDATE zasp_security_agent_approvals SET approver_id=requester_id WHERE run_id=$1`)
				public62MutationVersionRefused(t, ctx, owner, api, q, run)
				q["decision"] = "rejected"
				if decision == "rejected" {
					q["decision"] = "approved"
				}
				if _, err = public62Call(ctx, conn, q); err == nil {
					t.Fatal("conflicting replay accepted")
				}
			})
		})
	}
}

func TestSecurityAgentPublic62CancelBeforeAdmissionPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
		if err := precisionMigrationRunner(t, owner).UpProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
		public62Seed(t, ctx, owner, o, w, e, testID, actor)
		q := public62Request(o, w, e, actor, "activate")
		q["definition_id"], q["definition_version"] = public62Definition, 1
		if _, err := public62Call(ctx, api, q); err != nil {
			t.Fatal(err)
		}
		q = public62Request(o, w, e, actor, "trigger")
		q["definition_id"], q["definition_version"], q["trigger_id"], q["trigger_version"], q["idempotency_key"] = public62Definition, 2, public62Finding, 1, "public62-cancel-trigger-0001"
		trigger, err := public62Call(ctx, api, q)
		if err != nil {
			t.Fatal(err)
		}
		q = public62Request(o, w, e, actor, "cancel")
		q["run_id"], q["run_version"], q["idempotency_key"] = trigger["run_id"], 1, "public62-cancel-0001"
		for name, patch := range map[string]map[string]any{"stale": {"run_version": 2}, "foreign": {"organization_id": "pid_ffffffff-ffff-4fff-8fff-ffffffffffff"}, "missing": {"run_id": "pid_ffffffff-ffff-4fff-8fff-ffffffffffff"}, "caller-step": {"step_id": public62Definition}, "caller-lease": {"lease_token": "unauthorized-lease"}, "idempotency": {"idempotency_key": "short"}} {
			t.Run(name, func(t *testing.T) {
				bad := cloneOrderedApplicationRequest(t, q)
				for k, v := range patch {
					bad[k] = v
				}
				before := public62Snapshot(t, ctx, owner)
				if _, err := public62Call(ctx, api, bad); err == nil {
					t.Fatal("invalid cancellation accepted")
				}
				if before != public62Snapshot(t, ctx, owner) {
					t.Fatal("cancellation denial changed owner")
				}
			})
		}
		got, err := public62Call(ctx, api, q)
		if err != nil {
			t.Fatal("public cancellation missing", err)
		}
		if got["run_state"] != "cancelled" || got["run_version"] != float64(2) || got["step_id"] != nil || got["step_state"] != nil || got["step_version"] != float64(0) || got["cleanup_required"] != false {
			t.Fatal(got)
		}
		public62PreAdmissionStateRefused(t, ctx, owner, api, q, trigger["run_id"].(string))
	})
}
