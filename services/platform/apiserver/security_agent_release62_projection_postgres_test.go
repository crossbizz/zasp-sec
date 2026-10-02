package apiserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

func TestSecurityAgentRelease62AdmittedProjectionPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		run, admittedSteps := public62PlannedRun(t, ctx, owner, api, o, w, e, testID, actor)
		q := public62Request(o, w, e, actor, "detail")
		q["run_id"] = run
		value, err := public62Call(ctx, api, q)
		if err != nil {
			t.Fatal("admitted public projection absent", err)
		}
		steps := value["steps"].([]any)
		if len(steps) != 2 || steps[0].(map[string]any)["state"] != "waiting_approval" || steps[1].(map[string]any)["state"] != "blocked" {
			t.Fatal("ordered admission projection", value)
		}
		if steps[1].(map[string]any)["approval"].(map[string]any)["state"] != "absent" {
			t.Fatal("invented successor approval")
		}
		public62AssertRedacted(t, value)
		approve := orderedProgressionRequest(o, w, e, run, admittedSteps[0], "approve", orderedProgressionApprover, 3)
		if _, err = orderedProgressionCall(ctx, api, "transition", approve); err != nil {
			t.Fatal(err)
		}
		value, err = public62Call(ctx, api, q)
		if err != nil || value["state"] != "running" {
			t.Fatal("running projection", value, err)
		}
		if _, err = owner.Exec(ctx, `UPDATE zasp_security_agent_plans SET plan=plan||'{"unexpected":true}'::jsonb WHERE run_id=$1`, run); err != nil {
			t.Fatal(err)
		}
		before := orderedAdmissionSnapshot(t, ctx, owner, run)
		if _, err = public62Call(ctx, api, q); err == nil {
			t.Fatal("malformed stored plan normalized")
		}
		if orderedAdmissionSnapshot(t, ctx, owner, run) != before {
			t.Fatal("read mutated malformed state")
		}
	})
}

func TestSecurityAgentRelease62TerminalProjectionPostgres(t *testing.T) {
	public62TerminalFixture(t, func(ctx context.Context, owner, _, api, action *pgx.Conn, o, w, e, r string, steps []string) {
		if err := precisionMigrationRunner(t, owner).UpProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
		var actor string
		if err := owner.QueryRow(ctx, `SELECT requested_by FROM zasp_security_agent_runs WHERE run_id=$1`, r).Scan(&actor); err != nil {
			t.Fatal(err)
		}
		q := public62Request(o, w, e, actor, "detail")
		q["run_id"] = r
		value, err := public62Call(ctx, api, q)
		if err != nil {
			t.Fatal("terminal public projection absent", err)
		}
		if value["state"] != "contained" || value["verification"] != "contained" {
			t.Fatal("optimistic terminal outcome", value)
		}
		ordered := value["steps"].([]any)
		if ordered[1].(map[string]any)["settlement"] != "not_reproduced" {
			t.Fatal("settlement summary missing", value)
		}
		if ordered[0].(map[string]any)["cleanup"].(map[string]any)["state"] != "pending" {
			t.Fatal("cleanup pending hidden", value)
		}
		public62AssertRedacted(t, value)
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey)})
		claim, err := orderedCleanupCall(ctx, action, orderedCleanupRequest(o, w, e, r, steps[0], "claim", 10, 3, 0), keys)
		if err != nil {
			t.Fatal(err)
		}
		value, err = public62Call(ctx, api, q)
		if err != nil || value["steps"].([]any)[0].(map[string]any)["cleanup"].(map[string]any)["state"] != "leased" {
			t.Fatal("leased cleanup projection", value, err)
		}
		stored, err := orderedCleanupCall(ctx, action, orderedCleanupStoreRequest(t, o, w, e, r, steps[0], claim, key), keys)
		if err != nil {
			t.Fatal(err)
		}
		deployOrderedCleanup(t, ctx, owner, key, stored)
		if _, err = orderedCleanupCall(ctx, action, orderedCleanupRequest(o, w, e, r, steps[0], "complete", 10, 5, 2), keys); err != nil {
			t.Fatal(err)
		}
		value, err = public62Call(ctx, api, q)
		if err != nil || value["verification"] != "remediated" || value["steps"].([]any)[0].(map[string]any)["cleanup"].(map[string]any)["cleaned"] != true {
			t.Fatal("cleaned projection", value, err)
		}
		public62AssertRedacted(t, value)
		public62CompletionRefusals(t, ctx, owner, api, q, r)
	}, false)
}

func public62AssertRedacted(t *testing.T, value map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(value)
	if len(raw) > 65536 {
		t.Fatal("unbounded response")
	}
	for _, secret := range []string{"lease_token", "lease_owner", "worker_id", "credential_reference", "input_body", "artifact", "envelope", "receipt_body", "signing", "ref:red-team"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("private field disclosed", secret)
		}
	}
}

func public62CompletionRefusals(t *testing.T, ctx context.Context, owner, api *pgx.Conn, q map[string]any, run string) {
	t.Helper()
	for name, mutation := range map[string]string{
		"effect-pending":      `UPDATE zasp_security_agent_effects SET state='cleanup_pending' WHERE run_id=$1 AND action_key='create_temporary_policy'`,
		"effect-version":      `UPDATE zasp_security_agent_effects SET version=version+1 WHERE run_id=$1 AND action_key='create_temporary_policy'`,
		"effect-lease":        `UPDATE zasp_security_agent_effects SET lease_owner='unexpected',lease_token='unexpected-lease-token',lease_expires_at=clock_timestamp()+interval '1 hour' WHERE run_id=$1 AND action_key='create_temporary_policy'`,
		"control-active":      `UPDATE zasp_security_agent_controls SET state='active',version=version-1 WHERE run_id=$1`,
		"control-version":     `UPDATE zasp_security_agent_controls SET version=version+1 WHERE run_id=$1`,
		"control-missing":     `DELETE FROM zasp_security_agent_controls WHERE run_id=$1`,
		"control-extra":       `INSERT INTO zasp_security_agent_controls SELECT (jsonb_populate_record(NULL::zasp_security_agent_controls,to_jsonb(c)||'{"control_id":"pid_ffffffff-ffff-4fff-8fff-fffffffffff1"}')).* FROM zasp_security_agent_controls c WHERE run_id=$1`,
		"completion-missing":  `DELETE FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind='ordered_cleanup_complete'`,
		"completion-extra":    `INSERT INTO zasp_security_agent_audit SELECT (jsonb_populate_record(NULL::zasp_security_agent_audit,to_jsonb(a)||'{"audit_id":"pid_ffffffff-ffff-4fff-8fff-fffffffffff2","correlation_id":"pid_ffffffff-ffff-4fff-8fff-fffffffffff2"}')).* FROM zasp_security_agent_audit a WHERE run_id=$1 AND event_kind='ordered_cleanup_complete'`,
		"completion-response": `UPDATE zasp_security_agent_audit SET body=jsonb_set(body,'{response,effect_version}','999') WHERE run_id=$1 AND event_kind='ordered_cleanup_complete'`,
		"receipt-missing":     `DELETE FROM zasp_sa_multistep_prior.cleanup_receipts WHERE run_id=$1`,
		"receipt-extra":       `INSERT INTO zasp_sa_multistep_prior.cleanups SELECT (jsonb_populate_record(NULL::zasp_sa_multistep_prior.cleanups,to_jsonb(c)||jsonb_build_object('step_id',(SELECT step_id FROM zasp_security_agent_steps WHERE run_id=$1 AND step_index=1),'cleanup_id','pid_ffffffff-ffff-4fff-8fff-fffffffffff3'))).* FROM zasp_sa_multistep_prior.cleanups c WHERE run_id=$1; INSERT INTO zasp_sa_multistep_prior.cleanup_receipts SELECT (jsonb_populate_record(NULL::zasp_sa_multistep_prior.cleanup_receipts,to_jsonb(c)||jsonb_build_object('step_id',(SELECT step_id FROM zasp_security_agent_steps WHERE run_id=$1 AND step_index=1)))).* FROM zasp_sa_multistep_prior.cleanup_receipts c WHERE run_id=$1`,
	} {
		t.Run(name, func(t *testing.T) { public62MutationRefused(t, ctx, owner, api, q, run, mutation) })
	}
}

// Owner-only data corruption bypasses immutable-row triggers, not catalog
// readiness. Each API call must independently reject the contradictory data.
func public62MutationRefused(t *testing.T, ctx context.Context, owner, api *pgx.Conn, q map[string]any, run, mutation string) {
	t.Helper()
	if _, err := owner.Exec(ctx, `BEGIN; SET LOCAL session_replication_role=replica`); err != nil {
		t.Fatal(err)
	}
	defer owner.Exec(ctx, `ROLLBACK`)
	if _, err := owner.Exec(ctx, mutation, pgx.QueryExecModeSimpleProtocol, run); err != nil {
		t.Fatal("corruption fixture", err)
	}
	if _, err := owner.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{api.Config().User}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	if got, err := public62Call(ctx, owner, q); err == nil {
		t.Fatal("contradictory authority projected", got)
	} else {
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "40001" {
			t.Fatal("refusal did not reach retained authority check", err)
		}
	}
}

func TestSecurityAgentRelease62PartialCleanupProjectionPostgres(t *testing.T) {
	public62TerminalFixture(t, func(ctx context.Context, owner, _, api, action *pgx.Conn, o, w, e, r string, steps []string) {
		if err := precisionMigrationRunner(t, owner).UpProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
		var actor string
		if err := owner.QueryRow(ctx, `SELECT requested_by FROM zasp_security_agent_runs WHERE run_id=$1`, r).Scan(&actor); err != nil {
			t.Fatal(err)
		}
		q := public62Request(o, w, e, actor, "detail")
		q["run_id"] = r
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey)})
		claim, err := orderedCleanupCall(ctx, action, orderedCleanupRequest(o, w, e, r, steps[0], "claim", 10, 4, 0), keys)
		if err != nil {
			t.Fatal(err)
		}
		stored := claim
		for _, target := range claim["targets"].([]any) {
			selected := cloneOrderedApplicationRequest(t, stored)
			selected["targets"] = []any{target}
			stored, err = orderedCleanupCall(ctx, action, orderedCleanupStoreRequest(t, o, w, e, r, steps[0], selected, key), keys)
			if err != nil {
				t.Fatal(err)
			}
		}
		selected := cloneOrderedApplicationRequest(t, stored)
		selected["targets"] = []any{stored["targets"].([]any)[0]}
		deployOrderedCleanup(t, ctx, owner, key, selected)
		if _, err = owner.Exec(ctx, `UPDATE zasp_sa_multistep_prior.cleanups SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1;UPDATE zasp_security_agent_effects SET lease_expires_at=(SELECT lease_expires_at FROM zasp_sa_multistep_prior.cleanups WHERE run_id=$1) WHERE run_id=$1 AND action_key='create_temporary_policy'`, pgx.QueryExecModeSimpleProtocol, r); err != nil {
			t.Fatal(err)
		}
		if _, err = orderedCleanupCall(ctx, action, orderedCleanupRequest(o, w, e, r, steps[0], "reconcile", 10, 7, 3), keys); err != nil {
			t.Fatal(err)
		}
		value, err := public62Call(ctx, api, q)
		if err != nil {
			t.Fatal(err)
		}
		cleanup := value["steps"].([]any)[0].(map[string]any)["cleanup"].(map[string]any)
		if value["verification"] != "needs_human" || cleanup["state"] != "retryable" || cleanup["partial"] != true || cleanup["cleaned"] != false || cleanup["attempt"] != float64(1) {
			t.Fatal("partial cleanup projection lost retained recovery state", value)
		}
		public62AssertRedacted(t, value)
		retry := orderedCleanupRequest(o, w, e, r, steps[0], "claim", 11, 8, 4)
		retry["lease_token"] = "ordered-cleanup-partial-retry"
		stored, err = orderedCleanupCall(ctx, action, retry, keys)
		if err != nil {
			t.Fatal(err)
		}
		stored["cleanup_lease_token"] = "ordered-cleanup-partial-retry"
		value, err = public62Call(ctx, api, q)
		if err != nil || value["steps"].([]any)[0].(map[string]any)["cleanup"].(map[string]any)["attempt"] != float64(2) {
			t.Fatal("cleanup retry projection", value, err)
		}
		selected = cloneOrderedApplicationRequest(t, stored)
		selected["targets"] = []any{stored["targets"].([]any)[1]}
		deployOrderedCleanup(t, ctx, owner, key, selected)
		complete := orderedCleanupRequest(o, w, e, r, steps[0], "complete", 11, 9, 5)
		complete["lease_token"] = "ordered-cleanup-partial-retry"
		if _, err = orderedCleanupCall(ctx, action, complete, keys); err != nil {
			t.Fatal(err)
		}
		value, err = public62Call(ctx, api, q)
		if err != nil || value["verification"] != "needs_human" || value["steps"].([]any)[0].(map[string]any)["cleanup"].(map[string]any)["cleaned"] != true {
			t.Fatal("cleanup retry fabricated remediation", value, err)
		}
		public62AssertRedacted(t, value)
	}, true)
}

func TestSecurityAgentRelease62PartialApplicationCleanedPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
		seedOrderedApplicationGateway(t, ctx, owner, o, w, e)
		deployment := orderedApplicationDeploymentConnection(t, ctx, owner)
		defer deployment.Close(ctx)
		r, steps := public62PlannedRun(t, ctx, owner, api, o, w, e, testID, actor)
		action := orderedActionFenceConnection(t, ctx, owner)
		defer action.Close(ctx)
		if _, err := orderedProgressionCall(ctx, api, "transition", orderedProgressionRequest(o, w, e, r, steps[0], "approve", orderedProgressionApprover, 3)); err != nil {
			t.Fatal(err)
		}
		claim, err := orderedApplicationCall(ctx, action, orderedApplicationRequest(o, w, e, r, steps[0], "claim", 4, 0), policy.GatewayPolicyKeys{})
		if err != nil {
			t.Fatal(err)
		}
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey)})
		if _, err = orderedApplicationCall(ctx, action, orderedApplicationStoreRequest(t, o, w, e, r, steps[0], claim, key), keys); err != nil {
			t.Fatal(err)
		}
		cancel := orderedProgressionRequest(o, w, e, r, steps[0], "cancel", orderedProgressionApprover, 5)
		cancel["approval_version"] = 2
		if _, err = orderedProgressionCall(ctx, api, "transition", cancel); err != nil {
			t.Fatal(err)
		}
		claim, err = orderedCleanupCall(ctx, action, orderedCleanupRequest(o, w, e, r, steps[0], "claim", 6, 2, 0), keys)
		if err != nil {
			t.Fatal(err)
		}
		stored, err := orderedCleanupCall(ctx, action, orderedCleanupStoreRequest(t, o, w, e, r, steps[0], claim, key), keys)
		if err != nil {
			t.Fatal(err)
		}
		deployOrderedCleanup(t, ctx, owner, key, stored)
		if _, err = orderedCleanupCall(ctx, action, orderedCleanupRequest(o, w, e, r, steps[0], "complete", 6, 4, 2), keys); err != nil {
			t.Fatal(err)
		}
		q := public62Request(o, w, e, actor, "detail")
		q["run_id"] = r
		value, err := public62Call(ctx, api, q)
		if err != nil {
			t.Fatal("genuine partial removal not readable", err)
		}
		cleanup := value["steps"].([]any)[0].(map[string]any)["cleanup"].(map[string]any)
		if value["verification"] != "cancelled" || cleanup["cleaned"] != true || cleanup["partial"] != true || value["steps"].([]any)[0].(map[string]any)["receipt"] != nil {
			t.Fatal("partial cleanup fabricated application or remediation", value)
		}
		public62AssertRedacted(t, value)
		for name, mutation := range map[string]string{
			"effect-version":       `UPDATE zasp_security_agent_effects SET version=version+1 WHERE run_id=$1 AND action_key='create_temporary_policy'`,
			"effect-lease":         `UPDATE zasp_security_agent_effects SET lease_owner='unexpected',lease_token='unexpected-lease-token',lease_expires_at=clock_timestamp()+interval '1 hour' WHERE run_id=$1 AND action_key='create_temporary_policy'`,
			"completion-missing":   `DELETE FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind='ordered_cleanup_complete'`,
			"full-receipt-kind":    `UPDATE zasp_sa_multistep_prior.cleanup_receipts SET receipt_kind='temporary_policy_cleaned.v1' WHERE run_id=$1`,
			"invented-remediation": `UPDATE zasp_security_agent_runs SET state='remediated' WHERE run_id=$1`,
		} {
			t.Run(name, func(t *testing.T) { public62MutationRefused(t, ctx, owner, api, q, r, mutation) })
		}
	})
}
