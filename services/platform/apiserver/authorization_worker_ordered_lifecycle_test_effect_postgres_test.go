package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

// The producer commits the real signed reservation or linked dispatch first.
// Missing child terminalization, a fabricated success receipt, changed Block
// cleanup evidence, or another mutation on replay must break this consumer.
func assertOrdered69TestStop(c ordered68ApprovedTestContext, phase string) {
	t, ctx := c.t, c.ctx
	t.Helper()
	wantState, childState, childError, stopReason := "reserved", "cancelled", "cancelled", "test_cancelled_before_dispatch"
	switch phase {
	case "test-reserved":
	case "test-started":
		wantState, childState, childError, stopReason = "started", "failed", "outcome_unknown", "test_outcome_unknown"
	default:
		t.Fatal("unsupported Test lifecycle checkpoint", phase)
	}
	var start map[string]any
	if c.owner == nil || c.compensation == nil || c.scope.Validate() != nil || json.Unmarshal(c.identity, &start) != nil || start["run_id"] != c.run || start["definition_version"] != float64(c.definitionVersion) || start["organization_id"] != c.scope.OrganizationID().String() || start["workspace_id"] != c.scope.WorkspaceID().String() || start["environment_id"] != c.scope.EnvironmentID().String() {
		t.Fatal("Test lifecycle context does not match actual parent")
	}
	var child, effectKey string
	var childVersion int64
	var ready bool
	if err := c.owner.QueryRow(ctx, `SELECT l.test_run_id,f.effect_key,ch.version,
 f.state=$6 AND f.action_key='run_test' AND f.generation=1
 AND f.snapshot_digest=digest(convert_to(f.snapshot::text,'UTF8'),'sha256')
 AND f.snapshot->'targets'->>'test_run_id'=l.test_run_id
 AND f.snapshot->'targets'->>'input_digest'=encode(ch.input_digest,'hex')
 AND f.input_digest=l.input_digest AND l.step_id=$5
 AND ch.state='queued' AND ch.attempt=0 AND NOT ch.cancel_requested
 AND ch.worker_id IS NULL AND ch.lease_token IS NULL AND ch.lease_expires_at IS NULL
 AND l.reconcile_state='pending' AND l.reconcile_version=1
 AND l.reconcile_worker IS NULL AND l.reconcile_token IS NULL AND l.reconcile_expires_at IS NULL AND l.reconcile_settlement IS NULL
 AND (CASE WHEN $6='reserved' THEN f.started_at IS NULL AND NOT EXISTS(SELECT 1 FROM zasp_temporal68.test_inputs i WHERE i.test_run_id=l.test_run_id)
 ELSE f.started_at IS NOT NULL AND EXISTS(SELECT 1 FROM zasp_temporal68.test_inputs i WHERE(i.organization_id,i.workspace_id,i.environment_id,i.run_id,i.step_id,i.test_run_id)=(f.organization_id,f.workspace_id,f.environment_id,f.run_id,f.step_id,l.test_run_id)) END)
 AND NOT EXISTS(SELECT 1 FROM zasp_red_team_attempts a WHERE a.run_id=ch.run_id)
 AND NOT EXISTS(SELECT 1 FROM zasp_temporal68.test_settlements s WHERE s.run_id=f.run_id)
 AND NOT EXISTS(SELECT 1 FROM zasp_temporal68.test_stops s WHERE s.run_id=f.run_id)
 AND (SELECT count(*)=2 FROM zasp_temporal68.effects v WHERE v.run_id=f.run_id)
 AND EXISTS(SELECT 1 FROM zasp_temporal68.effects b WHERE b.run_id=f.run_id AND b.action_key='create_temporary_policy' AND b.state='cleanup_pending')
 AND EXISTS(SELECT 1 FROM zasp_sa_multistep_receipts b WHERE b.run_id=f.run_id AND b.action_key='create_temporary_policy')
 FROM zasp_temporal68.effects f JOIN zasp_security_agent_test_links l USING(organization_id,workspace_id,environment_id,run_id,step_id)
 JOIN zasp_red_team_runs ch ON(ch.organization_id,ch.workspace_id,ch.environment_id,ch.run_id)=(l.organization_id,l.workspace_id,l.environment_id,l.test_run_id)
 WHERE(f.organization_id,f.workspace_id,f.environment_id,f.run_id,f.step_id)=($1,$2,$3,$4,$5)`, c.scope.OrganizationID().String(), c.scope.WorkspaceID().String(), c.scope.EnvironmentID().String(), c.run, c.step, wantState).Scan(&child, &effectKey, &childVersion, &ready); err != nil || !ready {
		t.Fatal("actual Test checkpoint association", err)
	}
	query := func(statement string) []byte {
		t.Helper()
		var raw []byte
		if err := c.owner.QueryRow(ctx, statement, c.run, c.step, child).Scan(&raw); err != nil {
			t.Fatal("Test lifecycle evidence", err)
		}
		return raw
	}
	// Freeze all completed Block work, including control and delivery rows. Stop
	// may report cleanup debt but cannot perform or erase policy cleanup here.
	block := func() []byte {
		return query(`SELECT jsonb_build_array(
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY step_id) FROM zasp_temporal68.effects x WHERE run_id=$1 AND action_key='create_temporary_policy'),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY step_id) FROM zasp_security_agent_effects x WHERE run_id=$1 AND step_id<>$2),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY step_id) FROM zasp_security_agent_steps x WHERE run_id=$1 AND step_id<>$2),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY step_id) FROM zasp_sa_multistep_receipts x WHERE run_id=$1 AND step_id<>$2),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY phase,device_id) FROM zasp_security_agent_temporary_policy_targets x WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY phase,device_id) FROM zasp_temporal68.deliveries x WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY step_id) FROM zasp_temporal68.cleanups x WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY control_id) FROM zasp_security_agent_controls x WHERE run_id=$1),$3::text)`)
	}
	immutableTest := func() []byte {
		return query(`SELECT jsonb_build_array(
 (SELECT to_jsonb(x)-ARRAY['state','completed_at'] FROM zasp_temporal68.effects x WHERE run_id=$1 AND step_id=$2),
 (SELECT to_jsonb(x)-ARRAY['state','error_code','version','completed_at','updated_at'] FROM zasp_red_team_runs x WHERE run_id=$3),
 (SELECT to_jsonb(x) FROM zasp_security_agent_test_links x WHERE run_id=$1 AND step_id=$2),
 (SELECT to_jsonb(x) FROM zasp_temporal68.test_inputs x WHERE run_id=$1 AND step_id=$2),
 (SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY category),'[]'::jsonb) FROM zasp_temporal68.invocations x WHERE test_run_id=$3))`)
	}
	beforeBlock, beforeTest := block(), immutableTest()
	call := func(operation string, request json.RawMessage) json.RawMessage {
		t.Helper()
		bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		began := time.Now()
		decision, err := c.compensation.Authorize(bounded, authorization.WorkerOperation("ordered69."+operation), request)
		if err != nil {
			t.Fatal("Test lifecycle authorize", phase, operation, err)
		}
		result, err := c.compensation.Execute(bounded, decision)
		if err != nil {
			t.Fatal("Test lifecycle execute", phase, operation, err)
		}
		t.Log("Test lifecycle duration", phase, operation, time.Since(began))
		return result
	}
	inspect := func(raw json.RawMessage, terminal bool, state string) {
		t.Helper()
		var value map[string]json.RawMessage
		matched := 0
		var listed []map[string]any
		if json.Unmarshal(raw, &value) != nil || len(value) != 11 || string(value["admitted"]) != "true" || string(value["cleanup_required"]) != "true" || string(value["cleanup_markers"]) != "[]" || string(value["terminal"]) != map[bool]string{true: "true", false: "false"}[terminal] || json.Unmarshal(value["effects"], &listed) != nil || len(listed) != 2 {
			t.Fatal("Test stop lost applied Block cleanup debt")
		}
		for _, item := range listed {
			if item["step_id"] == c.step && item["effect_key"] == effectKey && item["state"] == state && item["action_key"] == "run_test" {
				matched++
			}
		}
		if matched != 1 {
			t.Fatal("Test lifecycle projection changed effect identity")
		}
	}
	inspect(call("inspect", c.identity), false, wantState)
	tag, err := c.owner.Exec(ctx, `UPDATE zasp_identity_memberships m SET active=false FROM zasp_security_agent_runs r WHERE(r.organization_id,r.workspace_id,r.environment_id,r.run_id)=($1,$2,$3,$4) AND(m.organization_id,m.principal_id)=(r.organization_id,r.requested_by) AND m.active`, c.scope.OrganizationID().String(), c.scope.WorkspaceID().String(), c.scope.EnvironmentID().String(), c.run)
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatal("Test lifecycle requester revocation", tag, err)
	}
	start["reason"] = "workflow_cancelled"
	stop, err := json.Marshal(start)
	if err != nil {
		t.Fatal(err)
	}
	stopped := call("stop", stop)
	var receipt map[string]any
	if json.Unmarshal(stopped, &receipt) != nil || receipt["run_id"] != c.run || receipt["reason"] != "workflow_cancelled" || !bytes.Equal(beforeBlock, block()) || !bytes.Equal(beforeTest, immutableTest()) {
		t.Fatal("Test lifecycle stop changed retained Block or immutable Test evidence")
	}
	var valid bool
	if err := c.owner.QueryRow(ctx, `SELECT ch.state=$4 AND ch.error_code=$5 AND ch.completed_at IS NOT NULL AND ch.attempt=0 AND ch.version=$8+1
 AND ch.worker_id IS NULL AND ch.lease_token IS NULL AND ch.lease_expires_at IS NULL
 AND f.state='stopped' AND f.completed_at IS NOT NULL AND f.effect_key=$6
 AND s.state='inconclusive' AND x.state='unknown_outcome' AND x.result_digest IS NULL AND x.outcome_id IS NULL
 AND x.lease_owner IS NULL AND x.lease_token IS NULL AND x.lease_expires_at IS NULL
 AND (SELECT count(*)=1 FROM zasp_temporal69.stops WHERE run_id=$1)
 AND (SELECT count(*)=1 AND bool_and(effect_key=$6 AND response->>'reason'=$7 AND response->>'test_run_id'=$3) FROM zasp_temporal68.test_stops WHERE run_id=$1 AND step_id=$2)
 AND (SELECT count(*)=1 FROM zasp_security_agent_audit WHERE run_id=$1 AND step_id=$2 AND event_kind='temporal_test_stopped')
 AND NOT EXISTS(SELECT 1 FROM zasp_red_team_attempts WHERE run_id=$3)
 AND NOT EXISTS(SELECT 1 FROM zasp_temporal68.test_settlements WHERE run_id=$1)
 AND NOT EXISTS(SELECT 1 FROM zasp_sa_multistep_receipts WHERE run_id=$1 AND step_id=$2)
 AND NOT zasp_authorization80_worker.runtime_ready()
 FROM zasp_temporal68.effects f
 JOIN zasp_security_agent_steps s USING(organization_id,workspace_id,environment_id,run_id,step_id)
 JOIN zasp_security_agent_effects x USING(organization_id,workspace_id,environment_id,run_id,step_id)
 CROSS JOIN zasp_red_team_runs ch
 WHERE ch.run_id=$3 AND f.run_id=$1 AND f.step_id=$2`, c.run, c.step, child, childState, childError, effectKey, stopReason, childVersion).Scan(&valid); err != nil || !valid {
		t.Fatal("Test stop fabricated settlement or lost uncertainty", err)
	}
	evidence := func() []byte {
		return query(`SELECT jsonb_build_array(
 (SELECT to_jsonb(x) FROM zasp_security_agent_runs x WHERE run_id=$1),
 (SELECT to_jsonb(x) FROM zasp_red_team_runs x WHERE run_id=$3),
 (SELECT to_jsonb(x) FROM zasp_temporal69.stops x WHERE run_id=$1),
 (SELECT to_jsonb(x) FROM zasp_temporal68.test_stops x WHERE run_id=$1 AND step_id=$2),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY audit_id) FROM zasp_security_agent_audit x WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY step_id) FROM zasp_security_agent_steps x WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY step_id) FROM zasp_security_agent_effects x WHERE run_id=$1))`)
	}
	beforeReplay := evidence()
	if again := call("stop", stop); !bytes.Equal(again, stopped) || !bytes.Equal(beforeReplay, evidence()) {
		t.Fatal("Test lifecycle replay mutated retained receipt or child")
	}
	inspect(call("inspect", c.identity), true, "stopped")
	if !bytes.Equal(beforeReplay, evidence()) || !bytes.Equal(beforeBlock, block()) || !bytes.Equal(beforeTest, immutableTest()) {
		t.Fatal("Test terminal inspection or replay changed cleanup or journal evidence")
	}
}
