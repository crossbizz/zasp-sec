package apiserver

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

// Removing any signed native fence, accepting completion without stored
// readback, or requiring fresh FGA for captured cleanup must break this flow.
// Its parent supplies a real admitted plan and checked approval. Neither this
// helper nor its signer inserts an effect, delivery, acknowledgement or receipt.
type ordered69EffectConsumer struct {
	phase       string
	consume     func()
	application func(*authorization.WorkerExecutor, *authorization.WorkerExecutor)
}

func assertOrdered68SignedPolicyFlow(t *testing.T, ctx context.Context, owner *pgx.Conn, forwardLogin, o, w, e, run, step, actor string, keys policy.GatewayPolicyKeys, private ed25519.PrivateKey, checker authorization.Checker, storeID, modelID string, reconcile func(), projectionAttempt orderedPolicyProjectionAttempt, afterEffect ...ordered69EffectConsumer) {
	t.Helper()
	if len(afterEffect) > 1 || len(afterEffect) == 1 && !afterEffect[0].valid() {
		t.Fatal("invalid ordered effect consumer")
	}
	poolFor := func(login string) *pgxpool.Pool {
		cfg, err := pgxpool.ParseConfig(owner.Config().ConnString())
		if err != nil {
			t.Fatal(err)
		}
		cfg.ConnConfig.User, cfg.MaxConns = login, 2
		cfg.ConnConfig.Tracer = orderedPolicyDiagnosticTracer(t, cfg.ConnConfig.Tracer)
		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		return pool
	}
	newWorker := func(purpose authorization.WorkerPurpose, login string, seed byte, check authorization.Checker) *authorization.WorkerExecutor {
		key, err := authorization.NewWorkerKey(purpose, bytes.Repeat([]byte{seed}, 32))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `SELECT zasp_authorization80_worker.register_verifier($1,$2,$3)`, string(purpose), key.Version(), key.Verifier()); err != nil {
			t.Fatal("policy worker verifier", err)
		}
		worker, err := authorization.NewWorkerExecutor(poolFor(login), check, storeID, modelID, key)
		if err != nil {
			t.Fatal(err)
		}
		return worker
	}
	forward := newWorker(authorization.WorkerForward, forwardLogin, 91, checker)
	trap := &orderedPolicyNoForwardChecks{}
	compensation := newWorker(authorization.CapturedCompensation, "temporal_compensation_test_login", 92, trap)
	request := func(operation string, payload map[string]any) json.RawMessage {
		raw, err := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "step_id": step, "generation": 1, "operation": operation, "payload": payload})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	decode := func(raw json.RawMessage) map[string]any {
		var value map[string]any
		if json.Unmarshal(raw, &value) != nil || value == nil {
			t.Fatal("native policy response is not an object")
		}
		return value
	}
	signCalls := 0
	signer := func(c context.Context, input policy.GatewayPolicySigningInput) (policy.GatewayPolicyEnvelope, error) {
		signCalls++
		if c.Err() != nil {
			return policy.GatewayPolicyEnvelope{}, c.Err()
		}
		return policy.SignGatewayPolicyEnvelope(input, private)
	}
	// Projection is a separate committed consumer. Policy preparation awaits
	// that actual consumer within its unchanged ten-second operation budget.
	capture := func(op authorization.WorkerOperation, raw json.RawMessage) {
		bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := orderedPolicyFixtureCapture(t, bounded, owner, o, forward, op, raw, projectionAttempt)
		cancel()
		if err != nil {
			orderedPolicyProviderDiagnostic(t, ctx, owner, o, w, e, run)
			t.Fatal("native policy capture", op, err)
		}
		reconcile()
	}
	call := func(worker *authorization.WorkerExecutor, op authorization.WorkerOperation, raw json.RawMessage, signing bool) (json.RawMessage, error) {
		if op == "ordered68.application.source" && os.Getenv("ZASP_ORDERED_POLICY_FUNCTION_TIMING") == "1" {
			tracked, report := orderedPolicyTrackedWorker(t, ctx, owner, forwardLogin, checker, storeID, modelID)
			worker = tracked
			defer report()
		}
		bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		began := time.Now()
		decision, err := worker.Authorize(bounded, op, raw)
		authorized := time.Now()
		if err != nil {
			t.Log("ordered policy phase", op, "authorize_ms", authorized.Sub(began).Milliseconds(), "class", ordered62TraceClass(err))
			return nil, err
		}
		var result json.RawMessage
		if signing {
			result, err = worker.SignOrderedPolicy(bounded, decision, "ordered-key-01", keys, signer)
		} else {
			result, err = worker.Execute(bounded, decision)
		}
		t.Log("ordered policy phase", op, "authorize_ms", authorized.Sub(began).Milliseconds(), "execute_ms", time.Since(authorized).Milliseconds(), "class", ordered62TraceClass(err))
		return result, err
	}
	must := func(worker *authorization.WorkerExecutor, op authorization.WorkerOperation, raw json.RawMessage, signing bool) json.RawMessage {
		t.Helper()
		result, err := call(worker, op, raw, signing)
		if err != nil {
			t.Fatal("signed native policy operation", op, err)
		}
		decode(result)
		return result
	}
	// Native evidence excludes authorization projection bookkeeping, so a
	// legitimate reconciliation cannot hide a changed effect or receipt.
	evidence := func() []byte {
		t.Helper()
		var raw []byte
		if err := owner.QueryRow(ctx, `SELECT jsonb_build_array(
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY generation) FROM zasp_temporal68.effects x WHERE run_id=$1 AND step_id=$2),
 (SELECT jsonb_agg(to_jsonb(x)) FROM zasp_sa_multistep_receipts x WHERE run_id=$1 AND step_id=$2),
 (SELECT jsonb_agg(to_jsonb(x)) FROM zasp_temporal68.cleanups x WHERE run_id=$1 AND step_id=$2),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY phase,device_id) FROM zasp_temporal68.deliveries x WHERE run_id=$1 AND step_id=$2),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY phase,device_id) FROM zasp_security_agent_temporary_policy_targets x WHERE run_id=$1 AND step_id=$2),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY audit_id) FROM zasp_security_agent_audit x WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY step_id) FROM zasp_security_agent_steps x WHERE run_id=$1),
 (SELECT to_jsonb(x) FROM zasp_security_agent_runs x WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY control_id) FROM zasp_security_agent_controls x WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY sequence) FROM zasp_runtime_gateway_policy_bundles x WHERE device_id=$3),
 (SELECT to_jsonb(x) FROM zasp_policy_deployment_work x WHERE device_id=$3))`, run, step, orderedApplicationDevice).Scan(&raw); err != nil {
			t.Fatal("policy immutable evidence", err)
		}
		return raw
	}
	refuse := func(worker *authorization.WorkerExecutor, op authorization.WorkerOperation, raw json.RawMessage, signing bool, want error) {
		t.Helper()
		before, signatures := evidence(), signCalls
		_, err := call(worker, op, raw, signing)
		if !errors.Is(err, want) || errors.Is(err, authorization.ErrUnavailable) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("native policy refusal class", op, "want", want, "got", err)
		}
		if signatures != signCalls || !bytes.Equal(before, evidence()) {
			t.Fatal("refused policy operation signed or changed native evidence", op)
		}
	}
	empty := map[string]any{}
	reserve := request("reserve", empty)
	assertOrdered68ProviderEvidence(t, ctx, owner, forwardLogin, o, w, e, run, reserve)
	capture("ordered68.effect.reserve", reserve)
	reserved := decode(must(forward, "ordered68.effect.reserve", reserve, false))
	if reserved["state"] != "reserved" {
		t.Fatal("reservation did not persist reserved state")
	}
	if len(afterEffect) == 1 && afterEffect[0].phase == "block-reserved" {
		afterEffect[0].consume()
		return
	}
	reconcile()
	started := decode(must(forward, "ordered68.effect.start", request("start", empty), false))
	if started["state"] != "started" || started["effect_key"] != reserved["effect_key"] {
		t.Fatal("start changed the admitted effect identity")
	}
	if len(afterEffect) == 1 && afterEffect[0].phase == "block-started" {
		afterEffect[0].consume()
		return
	}
	reconcile()
	claim := decode(must(forward, "ordered68.application.read", request("read", empty), false))
	targets, ok := claim["targets"].([]any)
	if !ok || len(targets) != 1 {
		t.Fatal("original fixture destination set changed")
	}
	target, ok := targets[0].(map[string]any)
	if !ok || target["device_id"] != orderedApplicationDevice {
		t.Fatal("native claim selected a foreign device")
	}
	source := request("source", map[string]any{"device_id": orderedApplicationDevice})
	capture("ordered68.application.source", source)
	must(forward, "ordered68.application.source", source, true)
	reconcile()
	refuse(forward, "ordered68.application.complete", request("complete", empty), false, authorization.ErrConflict)
	// Same real native delivery chain for apply and compensation. Readback is
	// independently signature-verified before ack; no acknowledgement is seeded.
	delivery := func(phase string, worker *authorization.WorkerExecutor) {
		verify := orderedVerifiedEnvelope
		if phase == "cleanup" {
			verify = orderedCleanupVerifiedEnvelope
		}
		payload := map[string]any{"device_id": orderedApplicationDevice, "phase": phase}
		prepare := request("prepare", payload)
		prepareOp := authorization.WorkerOperation("ordered68.delivery." + phase + ".prepare")
		if phase == "apply" {
			capture(prepareOp, prepare)
		}
		prepared := decode(must(worker, prepareOp, prepare, false))
		if prepared["state"] != "prepared" {
			t.Fatal("delivery preparation state", phase)
		}
		storeOp := authorization.WorkerOperation("ordered68.delivery." + phase + ".store")
		store := request("store", payload)
		if phase == "apply" {
			capture(storeOp, store)
		}
		stored := decode(must(worker, storeOp, store, true))
		encoded, _ := json.Marshal(stored["envelope"])
		var envelope policy.GatewayPolicyEnvelope
		if json.Unmarshal(encoded, &envelope) != nil || !verify(envelope, keys, o, w, e, orderedApplicationDevice, int64(envelope.Sequence)) {
			t.Fatal("stored delivery signature", phase)
		}
		payload["digest"] = orderedEnvelopeDigest(envelope)
		ackOp := authorization.WorkerOperation("ordered68.delivery." + phase + ".ack")
		refuse(compensation, ackOp, request("ack", payload), false, authorization.ErrConflict)
		read := decode(must(compensation, authorization.WorkerOperation("ordered68.delivery."+phase+".read"), request("read", payload), false))
		readRaw, _ := json.Marshal(read["envelope"])
		var observed policy.GatewayPolicyEnvelope
		if json.Unmarshal(readRaw, &observed) != nil || !verify(observed, keys, o, w, e, orderedApplicationDevice, int64(envelope.Sequence)) || orderedEnvelopeDigest(observed) != payload["digest"] {
			t.Fatal("native delivery readback changed signed bytes", phase)
		}
		ack := must(compensation, ackOp, request("ack", payload), false)
		if decode(ack)["state"] != "acknowledged" || !bytes.Equal(ack, must(compensation, ackOp, request("ack", payload), false)) {
			t.Fatal("delivery acknowledgement or exact replay", phase)
		}
	}
	delivery("apply", forward)
	reconcile()
	completed := must(forward, "ordered68.application.complete", request("complete", empty), false)
	if decode(completed)["receipt_kind"] != "temporary_policy_applied.v1" {
		t.Fatal("application did not produce the retained receipt")
	}
	reconcile()
	beforeReplay := evidence()
	if !bytes.Equal(completed, must(forward, "ordered68.application.complete", request("complete", empty), false)) || !bytes.Equal(beforeReplay, evidence()) {
		t.Fatal("application replay changed original receipt")
	}
	if len(afterEffect) == 1 && afterEffect[0].phase == "application-complete" {
		afterEffect[0].application(forward, compensation)
		return
	}
	if tag, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE organization_id=$1 AND principal_id=$2`, o, actor); err != nil || tag.RowsAffected() != 1 {
		t.Fatal("revoke original requesting grantor", err)
	}
	reconcile()
	refuse(forward, "ordered68.application.complete", request("complete", empty), false, authorization.ErrDenied)
	cleanup := decode(must(compensation, "ordered68.cleanup.prepare", request("prepare", empty), false))
	if cleanup["state"] != "pending" {
		t.Fatal("revoked captured cleanup was not prepared")
	}
	refuse(compensation, "ordered68.cleanup.complete", request("complete", empty), false, authorization.ErrConflict)
	must(compensation, "ordered68.cleanup.source", source, true)
	delivery("cleanup", compensation)
	cleaned := must(compensation, "ordered68.cleanup.complete", request("complete", empty), false)
	beforeReplay = evidence()
	if decode(cleaned)["state"] != "cleaned" || !bytes.Equal(cleaned, must(compensation, "ordered68.cleanup.complete", request("complete", empty), false)) || !bytes.Equal(beforeReplay, evidence()) {
		t.Fatal("cleanup receipt or exact replay")
	}
	if trap.calls != 0 || signCalls != 4 {
		t.Fatal("captured cleanup performed forward checks or unexpected signatures", trap.calls, signCalls)
	}
	var exact bool
	if err := owner.QueryRow(ctx, `SELECT
 (SELECT count(*)=1 AND bool_and(state='cleaned' AND started_at IS NOT NULL AND completed_at IS NOT NULL) FROM zasp_temporal68.effects WHERE run_id=$1 AND step_id=$2)
 AND (SELECT count(*)=1 AND bool_and(receipt_kind='temporary_policy_applied.v1') FROM zasp_sa_multistep_receipts WHERE run_id=$1 AND step_id=$2)
 AND (SELECT count(*)=1 AND bool_and(state='cleaned' AND receipt IS NOT NULL AND receipt_digest IS NOT NULL) FROM zasp_temporal68.cleanups WHERE run_id=$1 AND step_id=$2)
 AND (SELECT count(*)=2 AND bool_and(state='acknowledged' AND read_at IS NOT NULL AND acknowledged_at IS NOT NULL) FROM zasp_temporal68.deliveries WHERE run_id=$1 AND step_id=$2)
 AND (SELECT count(*)=2 FROM zasp_security_agent_audit WHERE run_id=$1 AND step_id=$2 AND event_kind IN('ordered_delivery_finish','temporal_cleanup_delivery_finish'))
 AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_controls WHERE run_id=$1 AND step_id=$2 AND state='active')
 AND NOT zasp_authorization80_worker.runtime_ready()`, run, step).Scan(&exact); err != nil || !exact {
		t.Fatal("policy lifecycle cardinality or unresolved control", err)
	}
}

func (c ordered69EffectConsumer) valid() bool {
	switch c.phase {
	case "block-reserved", "block-started":
		return c.consume != nil && c.application == nil
	case "application-complete":
		return c.consume == nil && c.application != nil
	default:
		return false
	}
}

type orderedPolicyNoForwardChecks struct{ calls int }

func (c *orderedPolicyNoForwardChecks) Check(context.Context, authorization.CheckRequest) (authorization.Decision, error) {
	c.calls++
	return authorization.Decision{}, errors.New("captured policy path attempted forward authorization")
}
