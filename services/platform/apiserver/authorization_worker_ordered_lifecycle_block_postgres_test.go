package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

// Each parent independently commits the real approval and named Block effect.
// The lifecycle consumer stops before any policy source, signing or delivery.
func TestP7Ordered69BlockEffectStop(t *testing.T) {
	for _, phase := range []string{"block-reserved", "block-started"} {
		t.Run(phase, func(t *testing.T) {
			runOrdered68PolicyBoundary(t, false, false, false, ordered69LifecycleConsumer{phase: phase, consume: func(t *testing.T, ctx context.Context, owner *pgx.Conn, identity json.RawMessage, step string) {
				assertOrdered69BlockEffectStop(t, ctx, owner, identity, step, phase)
			}})
		})
	}
}

func assertOrdered69BlockEffectStop(t *testing.T, ctx context.Context, owner *pgx.Conn, identity json.RawMessage, step, phase string) {
	t.Helper()
	var start map[string]any
	if err := json.Unmarshal(identity, &start); err != nil {
		t.Fatal(err)
	}
	run := start["run_id"].(string)
	effect := func() []byte {
		t.Helper()
		var raw []byte
		if err := owner.QueryRow(ctx, `SELECT to_jsonb(f) FROM zasp_temporal68.effects f WHERE run_id=$1 AND step_id=$2 AND generation=1 AND action_key='create_temporary_policy'`, run, step).Scan(&raw); err != nil {
			t.Fatal("actual Block effect", err)
		}
		return raw
	}
	beforeEffect := effect()
	var original map[string]any
	wantState := map[string]string{"block-reserved": "reserved", "block-started": "started"}[phase]
	if wantState == "" || json.Unmarshal(beforeEffect, &original) != nil || original["state"] != wantState || original["effect_key"] == nil || original["effect_key"] == "" {
		t.Fatal("Block lifecycle producer checkpoint")
	}
	targets := func() []byte {
		t.Helper()
		var raw []byte
		if err := owner.QueryRow(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY phase,device_id),'[]'::jsonb) FROM zasp_security_agent_temporary_policy_targets x WHERE run_id=$1`, run).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	// Reservation itself captures the planned destination. Stop must preserve
	// that evidence, not pretend the destination row never existed.
	beforeTargets := targets()
	legacyIntent := func() []byte {
		t.Helper()
		var raw []byte
		if err := owner.QueryRow(ctx, `SELECT jsonb_build_array((SELECT to_jsonb(x) FROM zasp_security_agent_effects x WHERE run_id=$1 AND step_id=$2),(SELECT to_jsonb(x) FROM zasp_security_agent_step_reservations x WHERE run_id=$1 AND step_id=$2),(SELECT jsonb_agg(to_jsonb(x)) FROM zasp_sa_multistep_receipts x WHERE run_id=$1 AND step_id=$2))`, run, step).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	beforeLegacy := legacyIntent()
	key, err := authorization.NewWorkerKey(authorization.CapturedCompensation, bytes.Repeat([]byte{89}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `SELECT zasp_authorization80_worker.register_verifier($1,$2,$3)`, string(authorization.CapturedCompensation), key.Version(), key.Verifier()); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(owner.Config().ConnString())
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.User, cfg.MaxConns = "temporal_compensation_test_login", 2
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	worker, err := authorization.NewWorkerExecutor(pool, nil, "", "", key)
	if err != nil {
		t.Fatal(err)
	}
	call := func(operation string, q json.RawMessage) json.RawMessage {
		t.Helper()
		bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		began := time.Now()
		d, err := worker.Authorize(bounded, authorization.WorkerOperation("ordered69."+operation), q)
		if err != nil {
			t.Fatal("Block lifecycle authorize", operation, err)
		}
		value, err := worker.Execute(bounded, d)
		if err != nil {
			t.Fatal("Block lifecycle execute", operation, err)
		}
		t.Log("Block lifecycle duration", phase, operation, time.Since(began))
		return value
	}
	inspect := func(raw json.RawMessage, terminal bool) {
		t.Helper()
		var state map[string]json.RawMessage
		var effects []map[string]any
		if json.Unmarshal(raw, &state) != nil || len(state) != 11 || string(state["admitted"]) != "true" || string(state["terminal"]) != map[bool]string{true: "true", false: "false"}[terminal] || string(state["cleanup_required"]) != "false" || string(state["cleanup_markers"]) != "[]" || json.Unmarshal(state["effects"], &effects) != nil || len(effects) != 1 || effects[0]["step_id"] != step || effects[0]["state"] != wantState || effects[0]["effect_key"] != original["effect_key"] {
			t.Fatal("Block lifecycle exceeded retained effect scope")
		}
	}
	inspect(call("inspect", identity), false)
	tag, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE active AND principal_id=(SELECT requested_by FROM zasp_security_agent_runs WHERE run_id=$1)`, run)
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatal("Block requester revocation", tag, err)
	}
	stop := map[string]any{}
	for k, v := range start {
		stop[k] = v
	}
	stop["reason"] = "workflow_cancelled"
	stopRaw, _ := json.Marshal(stop)
	stopped := call("stop", stopRaw)
	var receipt map[string]any
	if json.Unmarshal(stopped, &receipt) != nil || receipt["run_id"] != run || receipt["reason"] != "workflow_cancelled" || !bytes.Equal(beforeEffect, effect()) || !bytes.Equal(beforeTargets, targets()) || !bytes.Equal(beforeLegacy, legacyIntent()) {
		t.Fatal("Block stop changed original effect or receipt scope")
	}
	var exact bool
	if err := owner.QueryRow(ctx, `SELECT (SELECT count(*)=1 FROM zasp_temporal69.stops WHERE run_id=$1)
 AND (SELECT count(*)=1 FROM zasp_temporal68.effects WHERE run_id=$1)
 AND NOT EXISTS(SELECT 1 FROM zasp_sa_multistep_receipts WHERE run_id=$1)
 AND NOT EXISTS(SELECT 1 FROM zasp_temporal68.deliveries WHERE run_id=$1)
 AND (SELECT count(*)=1 AND bool_and(phase='apply' AND state='planned') FROM zasp_security_agent_temporary_policy_targets WHERE run_id=$1)
 AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_controls WHERE run_id=$1)
 AND NOT zasp_authorization80_worker.runtime_ready()`, run).Scan(&exact); err != nil || !exact {
		t.Fatal("Block stop manufactured application or cleanup work", err)
	}
	evidence := func() []byte {
		t.Helper()
		var raw []byte
		if err := owner.QueryRow(ctx, `SELECT jsonb_build_array((SELECT to_jsonb(r) FROM zasp_security_agent_runs r WHERE run_id=$1),(SELECT to_jsonb(s) FROM zasp_temporal69.stops s WHERE run_id=$1),(SELECT jsonb_agg(to_jsonb(f) ORDER BY step_id,generation) FROM zasp_temporal68.effects f WHERE run_id=$1),(SELECT jsonb_agg(to_jsonb(a) ORDER BY audit_id) FROM zasp_security_agent_audit a WHERE run_id=$1),(SELECT jsonb_agg(to_jsonb(s) ORDER BY step_id) FROM zasp_security_agent_steps s WHERE run_id=$1))`, run).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	before := evidence()
	if again := call("stop", stopRaw); !bytes.Equal(again, stopped) || !bytes.Equal(before, evidence()) {
		t.Fatal("Block lifecycle retry changed retained evidence")
	}
	inspect(call("inspect", identity), true)
	if !bytes.Equal(before, evidence()) || !bytes.Equal(beforeEffect, effect()) || !bytes.Equal(beforeTargets, targets()) || !bytes.Equal(beforeLegacy, legacyIntent()) {
		t.Fatal("terminal Block inspection changed retained evidence")
	}
}
