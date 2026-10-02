package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

func TestP7OrderedPostAdapterRecovery(t *testing.T) {
	for _, phase := range []string{"test-response-revoked", "test-disconnected"} {
		t.Run(phase, func(t *testing.T) { runOrderedActualRunnerConsumer(t, phase) })
	}
}

func orderedRunnerArtifactSnapshot(t *testing.T, directory string) map[string][32]byte {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	result := map[string][32]byte{}
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			t.Fatal("non-file in owned artifact store")
		}
		body, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		result[entry.Name()] = sha256.Sum256(body)
	}
	if len(result) < 1 || len(result) > 2 {
		t.Fatal("post-adapter durable object cardinality", len(result))
	}
	return result
}

// The parent observes the entire retry interval, including child construction
// and shutdown, without relying on the retried product to report its writes.
func orderedPostRecoveryEvidence(c ordered68ApprovedTestContext, directory string) []byte {
	c.t.Helper()
	var native json.RawMessage
	if err := c.owner.QueryRow(c.ctx, `SELECT jsonb_build_array(
 (SELECT to_jsonb(x) FROM zasp_security_agent_runs x WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY step_id) FROM zasp_security_agent_steps x WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY step_id) FROM zasp_temporal68.effects x WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY step_id) FROM zasp_security_agent_effects x WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY step_id) FROM zasp_security_agent_test_links x WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY step_id) FROM zasp_temporal68.test_inputs x WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY run_id) FROM zasp_red_team_runs x WHERE run_id IN(SELECT test_run_id FROM zasp_security_agent_test_links WHERE run_id=$1)),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY x.run_id,x.attempt) FROM zasp_red_team_attempts x WHERE run_id IN(SELECT test_run_id FROM zasp_security_agent_test_links WHERE run_id=$1)),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY step_id) FROM zasp_temporal68.test_settlements x WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY x.test_run_id,x.category) FROM zasp_temporal68.invocations x WHERE test_run_id IN(SELECT test_run_id FROM zasp_security_agent_test_links WHERE run_id=$1)),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY step_id) FROM zasp_temporal68.test_stops x WHERE run_id=$1),
 (SELECT to_jsonb(x) FROM zasp_temporal69.stops x WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY step_id) FROM zasp_sa_multistep_receipts x WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY phase,device_id) FROM zasp_security_agent_temporary_policy_targets x WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY phase,device_id) FROM zasp_temporal68.deliveries x WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY step_id) FROM zasp_temporal68.cleanups x WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY device_id,revision) FROM zasp_temporal68.cleanup_renewals x WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY control_id) FROM zasp_security_agent_controls x WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY device_id,sequence) FROM zasp_runtime_gateway_policy_bundles x WHERE device_id IN(SELECT device_id FROM zasp_security_agent_temporary_policy_targets WHERE run_id=$1)),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY device_id) FROM zasp_policy_deployment_work x WHERE device_id IN(SELECT device_id FROM zasp_security_agent_temporary_policy_targets WHERE run_id=$1)),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY audit_id) FROM zasp_security_agent_audit x WHERE run_id=$1))`, c.run).Scan(&native); err != nil {
		c.t.Fatal("post-recovery parent evidence", err)
	}
	value, err := json.Marshal(struct {
		Native    json.RawMessage
		Artifacts map[string][32]byte
	}{native, orderedRunnerArtifactSnapshot(c.t, directory)})
	if err != nil {
		c.t.Fatal(err)
	}
	return value
}

// Unlike the pre-engine checkpoint consumer, this sees an actual customer
// request and preserves either its completed response or its unresolved send.
func assertOrdered69PostAdapterStop(c ordered68ApprovedTestContext, phase, artifactDirectory string) {
	t, ctx := c.t, c.ctx
	t.Helper()
	completed := phase == "test-response-revoked"
	if !completed && phase != "test-disconnected" {
		t.Fatal("invalid post-adapter recovery phase")
	}
	var child, effect, state, childState string
	var childVersion int64
	var valid bool
	if err := c.owner.QueryRow(ctx, `SELECT l.test_run_id,f.effect_key,f.state,ch.state,ch.version,
 f.action_key='run_test' AND f.generation=1 AND f.started_at IS NOT NULL
 AND f.snapshot_digest=digest(convert_to(f.snapshot::text,'UTF8'),'sha256')
 AND f.snapshot->'targets'->>'test_run_id'=ch.run_id AND f.input_digest=l.input_digest
 AND ch.attempt=0 AND ch.worker_id IS NULL AND ch.lease_token IS NULL AND ch.lease_expires_at IS NULL
 AND l.reconcile_state='pending' AND l.reconcile_version=1 AND l.reconcile_settlement IS NULL
 AND EXISTS(SELECT 1 FROM zasp_temporal68.test_inputs i WHERE(i.organization_id,i.workspace_id,i.environment_id,i.run_id,i.step_id,i.test_run_id)=(f.organization_id,f.workspace_id,f.environment_id,f.run_id,f.step_id,ch.run_id))
 AND (SELECT count(*)=1 AND bool_and(attempt=1 AND CASE WHEN $3 THEN state='completed' AND http_status=200 AND protected AND completed_at IS NOT NULL ELSE state='started' AND completed_at IS NULL AND http_status IS NULL AND protected IS NULL AND response_digest IS NULL END) FROM zasp_temporal68.invocations WHERE test_run_id=ch.run_id)
 AND NOT EXISTS(SELECT 1 FROM zasp_temporal68.test_settlements WHERE run_id=$1)
 AND NOT EXISTS(SELECT 1 FROM zasp_red_team_attempts WHERE run_id=ch.run_id)
 AND EXISTS(SELECT 1 FROM zasp_temporal68.effects b WHERE b.run_id=f.run_id AND b.action_key='create_temporary_policy' AND b.state='cleanup_pending')
 FROM zasp_temporal68.effects f JOIN zasp_security_agent_test_links l USING(organization_id,workspace_id,environment_id,run_id,step_id)
 JOIN zasp_red_team_runs ch ON(ch.organization_id,ch.workspace_id,ch.environment_id,ch.run_id)=(l.organization_id,l.workspace_id,l.environment_id,l.test_run_id)
 WHERE f.run_id=$1 AND f.step_id=$2`, c.run, c.step, completed).Scan(&child, &effect, &state, &childState, &childVersion, &valid); err != nil || !valid {
		t.Fatal("actual post-adapter recovery evidence", err)
	}
	if completed && (state != "started" || childState != "queued") || !completed && state != "started" && state != "unknown" && state != "stopped" {
		t.Fatal("unexpected post-adapter state", state, childState)
	}
	alreadyStopped := state == "stopped"
	if alreadyStopped && childState != "failed" || !alreadyStopped && childState != "queued" {
		t.Fatal("post-adapter child did not follow real producer state")
	}
	query := func(sql string) []byte {
		var raw []byte
		if err := c.owner.QueryRow(ctx, sql, c.run, c.step, child).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	block := func() []byte {
		return query(`SELECT jsonb_build_array(
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY step_id) FROM zasp_temporal68.effects x WHERE run_id=$1 AND step_id<>$2),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY step_id) FROM zasp_security_agent_effects x WHERE run_id=$1 AND step_id<>$2),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY step_id) FROM zasp_security_agent_steps x WHERE run_id=$1 AND step_id<>$2),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY step_id) FROM zasp_sa_multistep_receipts x WHERE run_id=$1 AND step_id<>$2),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY phase,device_id) FROM zasp_security_agent_temporary_policy_targets x WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY phase,device_id) FROM zasp_temporal68.deliveries x WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY step_id) FROM zasp_temporal68.cleanups x WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY control_id) FROM zasp_security_agent_controls x WHERE run_id=$1),$3::text)`)
	}
	immutable := func() []byte {
		return query(`SELECT jsonb_build_array(
 (SELECT to_jsonb(x)-ARRAY['state','completed_at'] FROM zasp_temporal68.effects x WHERE run_id=$1 AND step_id=$2),
 (SELECT to_jsonb(x) FROM zasp_security_agent_test_links x WHERE run_id=$1 AND step_id=$2),
 (SELECT to_jsonb(x) FROM zasp_temporal68.test_inputs x WHERE run_id=$1 AND step_id=$2),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY category) FROM zasp_temporal68.invocations x WHERE test_run_id=$3))`)
	}
	priorStop := query(`SELECT jsonb_build_array((SELECT to_jsonb(x) FROM zasp_temporal68.test_stops x WHERE run_id=$1 AND step_id=$2),$3::text)`)
	beforeBlock, beforeImmutable := block(), immutable()
	artifacts := orderedRunnerArtifactSnapshot(t, artifactDirectory)
	if completed {
		var revoked bool
		if err := c.owner.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(NOT m.active) FROM zasp_identity_memberships m JOIN zasp_security_agent_runs r ON(m.organization_id,m.principal_id)=(r.organization_id,r.requested_by) WHERE r.run_id=$1`, c.run).Scan(&revoked); err != nil || !revoked {
			t.Fatal("post-start actual revocation absent", err)
		}
	} else {
		tag, err := c.owner.Exec(ctx, `UPDATE zasp_identity_memberships m SET active=false FROM zasp_security_agent_runs r WHERE r.run_id=$1 AND(m.organization_id,m.principal_id)=(r.organization_id,r.requested_by) AND m.active`, c.run)
		if err != nil || tag.RowsAffected() != 1 {
			t.Fatal("disconnect captured recovery requester revocation", err)
		}
	}
	call := func(op string, request json.RawMessage) json.RawMessage {
		bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		decision, err := c.compensation.Authorize(bounded, authorization.WorkerOperation("ordered69."+op), request)
		if err != nil {
			t.Fatal("post-adapter69 authorize", op, err)
		}
		value, err := c.compensation.Execute(bounded, decision)
		if err != nil {
			t.Fatal("post-adapter69 execute", op, err)
		}
		return value
	}
	var request map[string]any
	if json.Unmarshal(c.identity, &request) != nil {
		t.Fatal("actual parent identity")
	}
	request["reason"] = "workflow_cancelled"
	stop, _ := json.Marshal(request)
	first := call("stop", stop)
	if !bytes.Equal(beforeBlock, block()) || !bytes.Equal(beforeImmutable, immutable()) {
		t.Fatal("captured stop altered Block debt or actual adapter evidence")
	}
	wantVersion := childVersion
	if !alreadyStopped {
		wantVersion++
	}
	if err := c.owner.QueryRow(ctx, `SELECT ch.state='failed' AND ch.error_code='outcome_unknown' AND ch.attempt=0 AND ch.version=$4 AND ch.completed_at IS NOT NULL
 AND f.state='stopped' AND f.effect_key=$5 AND f.completed_at IS NOT NULL
 AND s.state='inconclusive' AND x.state='unknown_outcome' AND x.result_digest IS NULL AND x.outcome_id IS NULL
 AND (SELECT count(*)=1 FROM zasp_temporal68.test_stops WHERE run_id=$1 AND step_id=$2)
 AND (SELECT count(*)=1 FROM zasp_temporal69.stops WHERE run_id=$1)
 AND (SELECT count(*)=1 FROM zasp_security_agent_audit WHERE run_id=$1 AND step_id=$2 AND event_kind='temporal_test_stopped')
 AND NOT EXISTS(SELECT 1 FROM zasp_temporal68.test_settlements WHERE run_id=$1)
 AND NOT EXISTS(SELECT 1 FROM zasp_red_team_attempts WHERE run_id=$3)
 AND NOT EXISTS(SELECT 1 FROM zasp_sa_multistep_receipts WHERE run_id=$1 AND step_id=$2)
 FROM zasp_temporal68.effects f JOIN zasp_security_agent_steps s USING(organization_id,workspace_id,environment_id,run_id,step_id)
 JOIN zasp_security_agent_effects x USING(organization_id,workspace_id,environment_id,run_id,step_id) CROSS JOIN zasp_red_team_runs ch
 WHERE f.run_id=$1 AND f.step_id=$2 AND ch.run_id=$3`, c.run, c.step, child, wantVersion, effect).Scan(&valid); err != nil || !valid {
		t.Fatal("post-adapter stop fabricated success or lost unknown outcome", err)
	}
	if alreadyStopped && !bytes.Equal(priorStop, query(`SELECT jsonb_build_array((SELECT to_jsonb(x) FROM zasp_temporal68.test_stops x WHERE run_id=$1 AND step_id=$2),$3::text)`)) {
		t.Fatal("69 rewrote actual runner stop receipt")
	}
	evidence := func() []byte {
		return query(`SELECT jsonb_build_array(
 (SELECT to_jsonb(x) FROM zasp_security_agent_runs x WHERE run_id=$1),
 (SELECT to_jsonb(x) FROM zasp_red_team_runs x WHERE run_id=$3),
 (SELECT to_jsonb(x) FROM zasp_temporal69.stops x WHERE run_id=$1),
 (SELECT to_jsonb(x) FROM zasp_temporal68.test_stops x WHERE run_id=$1 AND step_id=$2),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY audit_id) FROM zasp_security_agent_audit x WHERE run_id=$1))`)
	}
	beforeReplay := evidence()
	if replay := call("stop", stop); !bytes.Equal(first, replay) || !bytes.Equal(beforeReplay, evidence()) {
		t.Fatal("post-adapter stop replay mutated receipt")
	}
	var view struct {
		Terminal        bool              `json:"terminal"`
		CleanupRequired bool              `json:"cleanup_required"`
		CleanupMarkers  []json.RawMessage `json:"cleanup_markers"`
	}
	if json.Unmarshal(call("inspect", c.identity), &view) != nil || !view.Terminal || !view.CleanupRequired || len(view.CleanupMarkers) != 0 {
		t.Fatal("post-adapter recovery lost applied Block cleanup debt")
	}
	if !bytes.Equal(beforeBlock, block()) || !bytes.Equal(beforeImmutable, immutable()) || !bytes.Equal(beforeReplay, evidence()) || !reflect.DeepEqual(artifacts, orderedRunnerArtifactSnapshot(t, artifactDirectory)) {
		t.Fatal("post-adapter replay changed durable evidence or artifacts")
	}
}
