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

// The parent admits the original plan and commits approval through the actual
// current HTTP/FGA boundary. This consumer never inserts approval/effect rows.
func TestP7Ordered69CommittedApproval(t *testing.T) {
	runOrdered68PolicyBoundary(t, false, true, false, ordered69LifecycleConsumer{phase: "approval", consume: func(t *testing.T, ctx context.Context, owner *pgx.Conn, identity json.RawMessage, step string) {
		var start map[string]any
		if err := json.Unmarshal(identity, &start); err != nil {
			t.Fatal(err)
		}
		run := start["run_id"].(string)
		var message json.RawMessage
		var exact bool
		if err := owner.QueryRow(ctx, `SELECT jsonb_build_object('organization_id',c.organization_id,'workspace_id',c.workspace_id,'environment_id',c.environment_id,'run_id',c.run_id,'event_id',c.event_id,'decision_id',c.decision_id,'kind',c.kind),
 (SELECT count(*)=1 FROM zasp_temporal65.commands WHERE run_id=$1 AND kind='approval')
 FROM zasp_temporal65.commands c
 JOIN zasp_security_agent_request_receipts r ON(r.organization_id,r.workspace_id,r.environment_id,r.receipt_id)=(c.organization_id,c.workspace_id,c.environment_id,c.decision_id)
 JOIN zasp_security_agent_approvals a ON(a.organization_id,a.workspace_id,a.environment_id,a.approval_id)=(c.organization_id,c.workspace_id,c.environment_id,r.intent->>'approval_id')
 WHERE c.run_id=$1 AND c.kind='approval' AND a.step_id=$2 AND a.state='approved'`, run, step).Scan(&message, &exact); err != nil || !exact {
			t.Fatal("exact committed approval message", err)
		}
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
		call := func(phase string, q json.RawMessage) json.RawMessage {
			t.Helper()
			bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			began := time.Now()
			d, err := worker.Authorize(bounded, authorization.WorkerOperation("ordered69."+phase), q)
			if err != nil {
				t.Fatal("approval lifecycle authorize", phase, err)
			}
			value, err := worker.Execute(bounded, d)
			if err != nil {
				t.Fatal("approval lifecycle execute", phase, err)
			}
			t.Log("approval lifecycle duration", phase, time.Since(began))
			return value
		}
		inspect := func(raw json.RawMessage, terminal bool) {
			t.Helper()
			var state map[string]json.RawMessage
			if json.Unmarshal(raw, &state) != nil || len(state) != 11 || string(state["admitted"]) != "true" || string(state["terminal"]) != map[bool]string{true: "true", false: "false"}[terminal] || string(state["effects"]) != "[]" {
				t.Fatal("approval lifecycle retained metadata", state)
			}
		}
		evidence := func() []byte {
			t.Helper()
			var raw []byte
			if err := owner.QueryRow(ctx, `SELECT jsonb_build_array(
 (SELECT to_jsonb(r) FROM zasp_security_agent_runs r WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(c) ORDER BY event_id) FROM zasp_temporal65.commands c WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(a) ORDER BY audit_id) FROM zasp_security_agent_audit a WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(a) ORDER BY approval_id) FROM zasp_security_agent_approvals a WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(s) ORDER BY step_id) FROM zasp_security_agent_steps s WHERE run_id=$1),
 (SELECT to_jsonb(s) FROM zasp_temporal69.stops s WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(f) ORDER BY step_id,generation) FROM zasp_temporal68.effects f WHERE run_id=$1))`, run).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			return raw
		}
		before := evidence()
		inspect(call("message", message), false)
		if !bytes.Equal(before, evidence()) {
			t.Fatal("committed approval notification mutated native state")
		}
		tag, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE active AND principal_id=(SELECT requested_by FROM zasp_security_agent_runs WHERE run_id=$1)`, run)
		if err != nil || tag.RowsAffected() != 1 {
			t.Fatal("approval requester revocation", tag, err)
		}
		inspect(call("message", message), false)
		if !bytes.Equal(before, evidence()) {
			t.Fatal("revoked approval notification mutated native state")
		}
		stop := map[string]any{}
		for k, v := range start {
			stop[k] = v
		}
		stop["reason"] = "workflow_cancelled"
		stopRaw, _ := json.Marshal(stop)
		stopped := call("stop", stopRaw)
		before = evidence()
		if again := call("stop", stopRaw); !bytes.Equal(again, stopped) || !bytes.Equal(before, evidence()) {
			t.Fatal("admitted stop replay changed native evidence")
		}
		inspect(call("message", message), true)
		if !bytes.Equal(before, evidence()) {
			t.Fatal("terminal approval notification mutated native state")
		}
		if err := owner.QueryRow(ctx, `SELECT (SELECT count(*)=1 FROM zasp_temporal69.stops WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_temporal68.effects WHERE run_id=$1) AND NOT zasp_authorization80_worker.runtime_ready()`, run).Scan(&exact); err != nil || !exact {
			t.Fatal("approval lifecycle minted effect authority", err)
		}
	}})
}
