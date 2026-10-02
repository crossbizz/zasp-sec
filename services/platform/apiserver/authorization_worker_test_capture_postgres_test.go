package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

// Expiry must wake an already-synchronized organization without a row write.
// A previously signed start must still refuse before projection catches up;
// only the captured compensation principal may release the unsent reservation.
func assertWorkerTest74CapturedPlanning(t *testing.T, ctx context.Context, owner *pgx.Conn, compensationPool *pgxpool.Pool, projection *authorization.PostgresProjectionRepository, writer authorization.TupleWriter, checker authorization.Checker, forward *authorization.WorkerExecutor, o, w, e, run, store, model string, request map[string]any, mode string) {
	t.Helper()
	key, _ := authorization.NewWorkerKey(authorization.CapturedCompensation, bytes.Repeat([]byte{73}, 32))
	if _, err := owner.Exec(ctx, `SELECT zasp_authorization80_worker.register_verifier($1,$2,$3)`, string(authorization.CapturedCompensation), key.Version(), key.Verifier()); err != nil {
		t.Fatal(err)
	}
	compensation, err := authorization.NewWorkerExecutor(compensationPool, nil, "", "", key)
	if err != nil {
		t.Fatal(err)
	}
	reconcile := func() {
		t.Helper()
		if result, err := authorization.Reconcile(ctx, projection, writer, o, store, model); err != nil || !result.Applied {
			t.Fatal("actual74 target reconciliation", err)
		}
	}
	reconcile()
	before, err := forward.Revision(ctx, o)
	if err != nil || before.Desired != before.Applied {
		t.Fatal("target fixture was not synchronized", err)
	}
	var principal, targetKind, targetID string
	var expires time.Time
	if err := owner.QueryRow(ctx, `SELECT a.principal_id,a.target_kind,a.target_id,s.fresh_until FROM zasp_authorization80_worker.test_associations a JOIN zasp_authorization80_worker.test_state s USING(organization_id,workspace_id,environment_id,run_id) WHERE a.run_id=$1`, run).Scan(&principal, &targetKind, &targetID, &expires); err != nil {
		t.Fatal(err)
	}
	check := authorization.CheckRequest{PrincipalKind: "service", PrincipalID: principal, TaskID: run, OrganizationID: o, WorkspaceID: w, EnvironmentID: e, ResourceType: targetKind, ResourceID: targetID, Permission: "view"}
	if decision, err := checker.Check(ctx, check); err != nil || !decision.Allowed {
		t.Fatal("captured target was not projected before invalidation", err)
	}
	request["operation"] = "recovery"
	delete(request, "payload")
	recoveryRequest, _ := json.Marshal(request)
	assertWorkerTest74SourceBindings(t, ctx, owner, compensationPool, key, authorization.Revision{}, recoveryRequest, true)
	waitUntil := func(deadline time.Time) {
		t.Helper()
		for time.Now().Before(deadline) {
			delay := time.Until(deadline)
			if delay > 20*time.Second {
				delay = 20 * time.Second
			}
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				t.Fatal("owned expiry wait deadline")
			case <-timer.C:
			}
		}
	}
	if mode != "credential-revoke" {
		if remaining := time.Until(expires); remaining < 30*time.Second {
			t.Fatal("fixture reached expiry too early for a fresh signed proof", remaining)
		}
		t.Log("waiting for captured target expiry; no unrelated mutation")
		waitUntil(expires.Add(-25 * time.Second))
	}
	request["operation"], request["payload"] = "start", map[string]any{}
	startRequest, _ := json.Marshal(request)
	proofStarted := time.Now()
	held, err := forward.Authorize(ctx, "test74.planning.start", startRequest)
	if err != nil {
		t.Fatal("current start proof before target invalidation", err)
	}
	if mode == "credential-revoke" {
		if _, err := owner.Exec(ctx, `UPDATE zasp_attack_lab_credential_bindings c SET state='revoked' FROM zasp_authorization80_worker.test_associations a WHERE(a.organization_id,a.workspace_id,a.environment_id,a.credential_binding_id,a.run_id)=(c.organization_id,c.workspace_id,c.environment_id,c.binding_id,$1)`, run); err != nil {
			t.Fatal("owned credential revocation", err)
		}
	} else {
		if remaining := time.Until(expires); remaining <= 0 || remaining >= 29*time.Second {
			t.Fatal("expiry proof could not be consumed within its live lifetime", remaining)
		}
		waitUntil(expires.Add(25 * time.Millisecond))
		unchanged, err := forward.Revision(ctx, o)
		if err != nil || unchanged != before {
			t.Fatal("wall-clock expiry required an unrelated revision write", err)
		}
	}
	_, refusal := forward.Execute(ctx, held)
	// Authorize signs after its source/Check work. Starting this timer before
	// that work is a conservative lower bound on the proof's issue time.
	if elapsed := time.Since(proofStarted); elapsed >= 30*time.Second {
		t.Fatal("source expiry refusal was not proved within live proof lifetime", elapsed)
	}
	if !errors.Is(refusal, authorization.ErrConflict) {
		t.Fatal("native74 signed start did not refuse changed/expired target", mode, refusal)
	}
	var unchanged bool
	if err := owner.QueryRow(ctx, `SELECT j.state='prepared' AND p.settled_at IS NULL AND p.released_at IS NULL AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_plans WHERE run_id=$1) FROM zasp_temporal74.planning_jobs j JOIN zasp_temporal74.provider_reservations p USING(organization_id,workspace_id,environment_id,run_id) WHERE j.run_id=$1`, run).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("refused start changed prepared debt or admitted plan", err)
	}
	queue, err := projection.Pending(ctx, 100)
	if err != nil {
		t.Fatal("normal projection pending", err)
	}
	found := false
	for _, entry := range queue {
		found = found || entry.OrganizationID == o
	}
	if !found {
		t.Fatal("normal Pending omitted invalidated or expired capture")
	}
	reconcile()
	after, err := forward.Revision(ctx, o)
	if err != nil || after.Desired <= before.Desired || after.Desired != after.Applied {
		t.Fatal("expiry/capture reconciliation did not advance and apply revision", err)
	}
	if decision, err := checker.Check(ctx, check); err != nil || decision.Allowed {
		t.Fatal("normal reconciliation retained revoked/expired task grant", err)
	}
	if _, err := forward.Authorize(ctx, "test74.planning.start", startRequest); err == nil {
		t.Fatal("fresh planning allowed after invalidation")
	}
	for _, phase := range []string{"recovery", "reconcile", "reconcile"} {
		request["operation"] = phase
		delete(request, "payload")
		if phase == "reconcile" {
			request["payload"] = map[string]any{}
		}
		raw, _ := json.Marshal(request)
		decision, err := compensation.Authorize(ctx, authorization.WorkerOperation("test74.planning."+phase), raw)
		if err != nil {
			t.Fatal("captured74 recovery authorization", phase, err)
		}
		result, err := compensation.Execute(ctx, decision)
		if err != nil {
			t.Fatal("captured74 native recovery", phase, err)
		}
		var fields map[string]json.RawMessage
		var state string
		if json.Unmarshal(result, &fields) != nil || len(fields) != 7 || json.Unmarshal(fields["state"], &state) != nil || phase == "recovery" && state != "prepared" || phase == "reconcile" && state != "needs_human" {
			t.Fatal("captured74 metadata disclosed context or wrong settlement state")
		}
		for _, name := range []string{"run_id", "state", "reservation_id", "request_digest", "credential_digest", "usage_known", "has_response"} {
			if len(fields[name]) == 0 {
				t.Fatal("captured74 metadata field missing", name)
			}
		}
	}
	if err := owner.QueryRow(ctx, `SELECT j.state='needs_human' AND p.released_at IS NOT NULL AND p.settled_at IS NULL AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_plans WHERE run_id=$1) AND (SELECT count(*)=1 FROM zasp_authorization80_worker.test_associations) AND (SELECT count(*)=1 AND bool_and(NOT target_current) FROM zasp_authorization80_worker.test_state) AND (SELECT count(*)=1 FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind='temporal_planning_terminal') FROM zasp_temporal74.planning_jobs j JOIN zasp_temporal74.provider_reservations p USING(organization_id,workspace_id,environment_id,run_id) WHERE j.run_id=$1`, run).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("captured74 unsent settlement/cardinality", err)
	}
	t.Log("real target invalidation refused signed native start, Pending-to-Reconcile removed task tuple, captured compensation released exact unsent debt and replayed without context")
}
