package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

// Catch lost applied-policy debt, fabricated cleanup acknowledgement, duplicate
// delivery, and receipt mutation across captured stop and actual cleanup.
// All effect, source, delivery and receipt rows come from the named producer.
func TestP7Ordered69AppliedBlockCleanup(t *testing.T) {
	consumed := false
	runOrdered68PolicyBoundary(t, false, false, false, ordered69LifecycleConsumer{
		connectedConsumer: true,
		phase: "application-complete", application: func(c ordered68TestFlowContext) {
			assertOrdered69AppliedBlockCleanup(c)
			consumed = true
		},
	})
	if !t.Failed() && !consumed {
		t.Fatal("applied Block cleanup consumer did not run")
	}
}

func assertOrdered69AppliedBlockCleanup(c ordered68TestFlowContext) {
	t, ctx := c.t, c.ctx
	t.Helper()
	var identity map[string]any
	if json.Unmarshal(c.identity, &identity) != nil || c.policySigner == nil || !c.policyKeys.Valid() {
		t.Fatal("missing actual application context")
	}
	run, ok := identity["run_id"].(string)
	if !ok || run == "" {
		t.Fatal("missing captured run")
	}
	var step string
	var valid bool
	if err := c.owner.QueryRow(ctx, `SELECT f.step_id,f.state='cleanup_pending'
 AND (SELECT count(*)=1 AND bool_and(receipt_kind='temporary_policy_applied.v1') FROM zasp_sa_multistep_receipts WHERE run_id=$1)
 AND (SELECT count(*)=1 AND bool_and(phase='apply' AND state='acknowledged' AND read_at IS NOT NULL AND acknowledged_at IS NOT NULL) FROM zasp_temporal68.deliveries WHERE run_id=$1)
 AND (SELECT count(*)=1 AND bool_and(state='active') FROM zasp_security_agent_controls WHERE run_id=$1)
 AND NOT EXISTS(SELECT 1 FROM zasp_temporal68.cleanups WHERE run_id=$1)
 AND NOT EXISTS(SELECT 1 FROM zasp_temporal68.effects WHERE run_id=$1 AND action_key='run_test')
 FROM zasp_temporal68.effects f WHERE run_id=$1 AND action_key='create_temporary_policy'`, run).Scan(&step, &valid); err != nil || !valid {
		t.Fatal("actual applied Block evidence absent", err)
	}
	query := func(sql string) []byte {
		var raw []byte
		if err := c.owner.QueryRow(ctx, sql, run).Scan(&raw); err != nil {
			t.Fatal("applied cleanup evidence", err)
		}
		return raw
	}
	application := func() []byte {
		return query(`SELECT jsonb_build_array(
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY step_id) FROM zasp_sa_multistep_receipts x WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY device_id) FROM zasp_temporal68.deliveries x WHERE run_id=$1 AND phase='apply'),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY device_id) FROM zasp_security_agent_temporary_policy_targets x WHERE run_id=$1 AND phase='apply'))`)
	}
	evidence := func() []byte {
		return query(`SELECT jsonb_build_array(
 (SELECT to_jsonb(x) FROM zasp_security_agent_runs x WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY step_id) FROM zasp_security_agent_steps x WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY step_id) FROM zasp_temporal68.effects x WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY step_id) FROM zasp_security_agent_effects x WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY phase,device_id) FROM zasp_temporal68.deliveries x WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY phase,device_id) FROM zasp_security_agent_temporary_policy_targets x WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY step_id) FROM zasp_temporal68.cleanups x WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY control_id) FROM zasp_security_agent_controls x WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY audit_id) FROM zasp_security_agent_audit x WHERE run_id=$1),
 (SELECT to_jsonb(x) FROM zasp_temporal69.stops x WHERE run_id=$1))`)
	}
	request := func(op string, payload map[string]any) json.RawMessage {
		raw, err := json.Marshal(map[string]any{"organization_id": identity["organization_id"], "workspace_id": identity["workspace_id"], "environment_id": identity["environment_id"], "run_id": run, "step_id": step, "generation": 1, "operation": op, "payload": payload})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	signatures := 0
	signer := func(ctx context.Context, input policy.GatewayPolicySigningInput) (policy.GatewayPolicyEnvelope, error) {
		signatures++
		return c.policySigner(ctx, input)
	}
	call := func(op authorization.WorkerOperation, raw json.RawMessage, signing bool) (json.RawMessage, error) {
		bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		decision, err := c.compensation.Authorize(bounded, op, raw)
		if err != nil {
			return nil, err
		}
		if signing {
			return c.compensation.SignOrderedPolicy(bounded, decision, "ordered-key-01", c.policyKeys, signer)
		}
		return c.compensation.Execute(bounded, decision)
	}
	must := func(op authorization.WorkerOperation, raw json.RawMessage, signing bool) json.RawMessage {
		t.Helper()
		value, err := call(op, raw, signing)
		if err != nil {
			t.Fatal("applied cleanup named operation", op, err)
		}
		return value
	}
	refuse := func(op authorization.WorkerOperation, raw json.RawMessage) {
		before := evidence()
		count := signatures
		_, err := call(op, raw, false)
		if !errors.Is(err, authorization.ErrConflict) || errors.Is(err, authorization.ErrUnavailable) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			t.Fatal("cleanup refusal did not prove native conflict", op, err)
		}
		if count != signatures || !bytes.Equal(before, evidence()) {
			t.Fatal("refused cleanup changed evidence")
		}
	}
	inspect := func(wantDebt bool, wantMarkers int) {
		var view struct {
			Terminal        bool            `json:"terminal"`
			CleanupRequired bool            `json:"cleanup_required"`
			Markers         json.RawMessage `json:"cleanup_markers"`
		}
		if json.Unmarshal(must("ordered69.inspect", c.identity, false), &view) != nil || !view.Terminal || view.CleanupRequired != wantDebt {
			t.Fatal("captured lifecycle lost cleanup state")
		}
		var markers []json.RawMessage
		if json.Unmarshal(view.Markers, &markers) != nil || len(markers) != wantMarkers {
			t.Fatal("cleanup marker cardinality")
		}
		// Compare the public marker with the actual stored signing source, not a
		// manufactured expected digest or the delivery's separate envelope.
		expected := query(`SELECT COALESCE(jsonb_agg(jsonb_build_object('device_id',device_id,'source_digest','sha256:'||encode(envelope_digest,'hex'),'expires_at',expires_at) ORDER BY device_id),'[]'::jsonb) FROM zasp_security_agent_temporary_policy_targets x WHERE run_id=$1 AND phase='cleanup' AND state<>'planned'`)
		var left, right any
		if json.Unmarshal(view.Markers, &left) != nil || json.Unmarshal(expected, &right) != nil {
			t.Fatal("marker JSON")
		}
		canonicalLeft, _ := json.Marshal(left)
		canonicalRight, _ := json.Marshal(right)
		if !bytes.Equal(canonicalLeft, canonicalRight) {
			t.Fatal("inspect marker not bound to actual signed cleanup source")
		}
	}
	originalApplication := application()
	if tag, err := c.owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE organization_id=$1 AND principal_id=$2 AND active`, identity["organization_id"], c.actor); err != nil || tag.RowsAffected() != 1 {
		t.Fatal("actual requester revocation", err)
	}
	c.reconcile()
	identity["reason"] = "workflow_cancelled"
	stop, _ := json.Marshal(identity)
	firstStop := must("ordered69.stop", stop, false)
	before := evidence()
	if !bytes.Equal(firstStop, must("ordered69.stop", stop, false)) || !bytes.Equal(before, evidence()) {
		t.Fatal("applied Block stop replay changed evidence")
	}
	inspect(true, 0)
	if !bytes.Equal(originalApplication, application()) {
		t.Fatal("stop changed applied receipt or delivery")
	}
	empty := map[string]any{}
	must("ordered68.cleanup.prepare", request("prepare", empty), false)
	inspect(true, 0)
	refuse("ordered68.cleanup.complete", request("complete", empty))
	must("ordered68.cleanup.source", request("source", map[string]any{"device_id": orderedApplicationDevice}), true)
	inspect(true, 1)
	payload := map[string]any{"device_id": orderedApplicationDevice, "phase": "cleanup"}
	must("ordered68.delivery.cleanup.prepare", request("prepare", payload), false)
	stored := must("ordered68.delivery.cleanup.store", request("store", payload), true)
	var value struct {
		Envelope policy.GatewayPolicyEnvelope `json:"envelope"`
	}
	if json.Unmarshal(stored, &value) != nil || !orderedCleanupVerifiedEnvelope(value.Envelope, c.policyKeys, identity["organization_id"].(string), identity["workspace_id"].(string), identity["environment_id"].(string), orderedApplicationDevice, int64(value.Envelope.Sequence)) {
		t.Fatal("actual cleanup delivery signature")
	}
	payload["digest"] = orderedEnvelopeDigest(value.Envelope)
	refuse("ordered68.delivery.cleanup.ack", request("ack", payload))
	read := must("ordered68.delivery.cleanup.read", request("read", payload), false)
	var observed struct {
		Envelope policy.GatewayPolicyEnvelope `json:"envelope"`
	}
	if json.Unmarshal(read, &observed) != nil || orderedEnvelopeDigest(observed.Envelope) != payload["digest"] || !orderedCleanupVerifiedEnvelope(observed.Envelope, c.policyKeys, identity["organization_id"].(string), identity["workspace_id"].(string), identity["environment_id"].(string), orderedApplicationDevice, int64(value.Envelope.Sequence)) {
		t.Fatal("cleanup readback mismatch")
	}
	ack := must("ordered68.delivery.cleanup.ack", request("ack", payload), false)
	before = evidence()
	if !bytes.Equal(ack, must("ordered68.delivery.cleanup.ack", request("ack", payload), false)) || !bytes.Equal(before, evidence()) {
		t.Fatal("cleanup acknowledgement replay changed evidence")
	}
	cleaned := must("ordered68.cleanup.complete", request("complete", empty), false)
	before = evidence()
	if !bytes.Equal(cleaned, must("ordered68.cleanup.complete", request("complete", empty), false)) || !bytes.Equal(before, evidence()) {
		t.Fatal("cleanup completion replay changed evidence")
	}
	inspect(false, 1)
	if !bytes.Equal(firstStop, must("ordered69.stop", stop, false)) || !bytes.Equal(before, evidence()) || !bytes.Equal(originalApplication, application()) {
		t.Fatal("post-cleanup stop or inspection rewrote committed outcome")
	}
	if signatures != 2 {
		t.Fatal("unexpected compensation signing count", signatures)
	}
	if err := c.owner.QueryRow(ctx, `SELECT
 (SELECT count(*)=1 AND bool_and(state='cleaned' AND receipt->>'outcome'='cleaned' AND receipt_digest=digest(convert_to(receipt::text,'UTF8'),'sha256')) FROM zasp_temporal68.cleanups WHERE run_id=$1)
 AND (SELECT count(*)=1 AND bool_and(state='cleaned') FROM zasp_temporal68.effects WHERE run_id=$1)
 AND (SELECT count(*)=2 AND bool_and(state='acknowledged' AND read_at IS NOT NULL AND acknowledged_at IS NOT NULL) FROM zasp_temporal68.deliveries WHERE run_id=$1)
 AND (SELECT count(*)=1 AND bool_and(state='disabled') FROM zasp_security_agent_controls WHERE run_id=$1)
 AND (SELECT count(*)=1 FROM zasp_temporal69.stops WHERE run_id=$1)
 AND (SELECT count(*)=1 FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind='temporal_cleanup_required')
 AND (SELECT count(*)=2 FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind IN('ordered_delivery_finish','temporal_cleanup_delivery_finish'))
 AND NOT EXISTS(SELECT 1 FROM zasp_temporal68.cleanup_renewals WHERE run_id=$1)
 AND NOT EXISTS(SELECT 1 FROM zasp_temporal68.test_settlements WHERE run_id=$1)
 AND NOT zasp_authorization80_worker.runtime_ready()`, run).Scan(&valid); err != nil || !valid {
		t.Fatal("applied cleanup cardinality/debt", err)
	}
}
