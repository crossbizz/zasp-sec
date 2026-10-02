//go:build darwin || linux

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

// A stale reader signal cannot turn a restored live run into terminal evidence;
// only the worker principal and current exact scope/version may stop it.
func TestSecurityAgentRelease61StopAuthorityPostgres(t *testing.T) {
	buildCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	binary := multistepBudgetWorkerBinary(t, buildCtx)
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		r, _ := release61PreflightPlan(t, ctx, owner, binary, o, w, e, testID, actor)
		var step string
		var version int
		if err := owner.QueryRow(ctx, `SELECT s.step_id,r.version FROM zasp_security_agent_runs r JOIN zasp_security_agent_steps s USING(organization_id,workspace_id,environment_id,run_id) WHERE r.run_id=$1 AND s.step_index=1`, r).Scan(&step, &version); err != nil {
			t.Fatal(err)
		}
		db, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
		repo := &securityAgentMultistepAdmissionRepository{database: db}
		read := func() bool {
			q := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": r, "worker_id": "release61-stop-worker", "lease_token": "not-a-foreign-secret", "deployment_worker_id": "release61-delivery", "deployment_lease_token": "not-a-delivery-secret"}
			raw, err := repo.orchestrationState(ctx, mustJSON(t, q))
			var value struct {
				Stop bool `json:"stop_required"`
			}
			if err != nil || json.Unmarshal(raw, &value) != nil {
				t.Fatal("stop reader", err)
			}
			return value.Stop
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE organization_id=$1 AND principal_id=$2`, o, actor); err != nil {
			t.Fatal(err)
		}
		if !read() {
			t.Fatal("revocation omitted stop signal")
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=true WHERE organization_id=$1 AND principal_id=$2`, o, actor); err != nil {
			t.Fatal(err)
		}
		q := orderedProgressionRequest(o, w, e, r, step, "stop", "release61-stop-worker", version)
		before := orderedCleanupSnapshot(t, ctx, owner, r)
		if _, err := orderedProgressionCall(ctx, worker, "transition", q); err == nil || before != orderedCleanupSnapshot(t, ctx, owner, r) || read() {
			t.Fatal("stale stop signal terminalized restored authority", err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_kill_switches SET execution_enabled=false WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3`, o, w, e); err != nil {
			t.Fatal(err)
		}
		for _, mode := range []string{"principal", "tenant", "version"} {
			bad := cloneOrderedApplicationRequest(t, q)
			conn := worker
			switch mode {
			case "principal":
				conn = api
			case "tenant":
				bad["organization_id"] = orderedProgressionApprover
			case "version":
				bad["run_version"] = version - 1
			}
			before = orderedCleanupSnapshot(t, ctx, owner, r)
			if _, err := orderedProgressionCall(ctx, conn, "transition", bad); err == nil || before != orderedCleanupSnapshot(t, ctx, owner, r) {
				t.Fatal("unsafe stop accepted", mode, err)
			}
		}
		stopped, err := orderedProgressionCall(ctx, worker, "transition", q)
		if err != nil || stopped["run_state"] != "needs_human" || stopped["outcome"] != "blocked" {
			t.Fatal("closed worker stop authority absent", stopped, err)
		}
		q["run_version"] = stopped["run_version"]
		before = orderedCleanupSnapshot(t, ctx, owner, r)
		if replay, err := orderedProgressionCall(ctx, worker, "transition", q); err != nil || replay["run_version"] != stopped["run_version"] || before != orderedCleanupSnapshot(t, ctx, owner, r) {
			t.Fatal("stop replay changed evidence", err)
		}
	})
}

func TestSecurityAgentRelease61LaterStopPostgres(t *testing.T) {
	buildCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	binary := multistepBudgetWorkerBinary(t, buildCtx)
	for _, stage := range []string{"approval", "executing"} {
		t.Run(stage, func(t *testing.T) {
			runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
				r, _ := release61PreflightPlan(t, ctx, owner, binary, o, w, e, testID, actor)
				action := orderedActionFenceConnection(t, ctx, owner)
				defer action.Close(ctx)
				seedOrderedApplicationGateway(t, ctx, owner, o, w, e)
				var steps []string
				var rv int
				if err := owner.QueryRow(ctx, `SELECT array_agg(s.step_id ORDER BY s.step_index),max(r.version) FROM zasp_security_agent_runs r JOIN zasp_security_agent_steps s USING(organization_id,workspace_id,environment_id,run_id) WHERE r.run_id=$1`, r).Scan(&steps, &rv); err != nil {
					t.Fatal(err)
				}
				approved, err := orderedProgressionCall(ctx, api, "transition", orderedProgressionRequest(o, w, e, r, steps[0], "approve", orderedProgressionApprover, rv))
				if err != nil {
					t.Fatal(err)
				}
				claim, err := orderedApplicationCall(ctx, action, orderedApplicationRequest(o, w, e, r, steps[0], "claim", int(approved["run_version"].(float64)), 0), policy.GatewayPolicyKeys{})
				if err != nil {
					t.Fatal(err)
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
				complete, err := orderedApplicationCall(ctx, action, orderedApplicationRequest(o, w, e, r, steps[0], "complete", int(stored["run_version"].(float64)), int(stored["effect_version"].(float64))), keys)
				if err != nil {
					t.Fatal(err)
				}
				ready, err := orderedProgressionCall(ctx, worker, "transition", orderedProgressionRequest(o, w, e, r, steps[1], "progress", "ordered-test-worker", int(complete["run_version"].(float64))))
				if err != nil {
					t.Fatal(err)
				}
				rv = int(ready["run_version"].(float64))
				if stage == "executing" {
					approved, err = orderedProgressionCall(ctx, api, "transition", orderedProgressionRequest(o, w, e, r, steps[1], "approve", orderedProgressionApprover, rv))
					if err != nil {
						t.Fatal(err)
					}
					testClaim, claimErr := orderedTestActionCall(ctx, worker, orderedTestActionRequest(o, w, e, r, steps[1], "claim", int(approved["run_version"].(float64)), 0))
					if claimErr != nil {
						t.Fatal(claimErr)
					}
					rv = int(testClaim["run_version"].(float64))
				}
				if _, err = owner.Exec(ctx, `UPDATE zasp_security_agent_kill_switches SET execution_enabled=false WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3`, o, w, e); err != nil {
					t.Fatal(err)
				}
				db, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
				stateQ := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": r, "worker_id": "ordered-test-worker", "lease_token": "not-a-foreign-secret", "deployment_worker_id": "ordered-delivery-worker", "deployment_lease_token": "not-a-delivery-secret"}
				stateRaw, readErr := (&securityAgentMultistepAdmissionRepository{database: db}).orchestrationState(ctx, mustJSON(t, stateQ))
				var state map[string]any
				if readErr != nil || json.Unmarshal(stateRaw, &state) != nil || state["stop_required"] != true {
					t.Fatal("authoritative reader omitted switch-only stop", state, readErr)
				}
				q := orderedProgressionRequest(o, w, e, r, steps[1], "stop", "ordered-test-worker", rv)
				stopped, err := orderedProgressionCall(ctx, worker, "transition", q)
				if err != nil || stopped["run_state"] != "needs_human" {
					t.Fatal("switch-only durable stop rejected", stopped, err)
				}
				var exact bool
				if err = owner.QueryRow(ctx, `SELECT count(*)=1 FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind='ordered_step_ready' AND body->'response'->>'outcome'='blocked' AND (body->'response'->>'run_version')::bigint=$2`, r, int(stopped["run_version"].(float64))).Scan(&exact); err != nil || !exact {
					t.Fatal("stop reused ready audit and lost terminal evidence", exact, err)
				}
				before := orderedCleanupSnapshot(t, ctx, owner, r)
				q["run_version"] = stopped["run_version"]
				replay, err := orderedProgressionCall(ctx, worker, "transition", q)
				if err != nil || replay["run_version"] != stopped["run_version"] || before != orderedCleanupSnapshot(t, ctx, owner, r) {
					t.Fatal("stop replay changed durable state", replay, err)
				}
			})
		})
	}
}
