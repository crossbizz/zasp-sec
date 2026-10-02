package apiserver

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

// These controls share one genuinely admitted/approved/started Block. The
// registered projector is deliberately released only after committed pending
// and a completed registered worker revision read have both been observed.
func TestP7Ordered68PolicyConvergence(t *testing.T) {
	runOrdered68PolicyAcceptance(t, false, false, false, &ordered68PolicyAcceptance{
		prepare: func(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e string) {
			for i := 1; i <= 3; i++ {
				seedOrderedApplicationGatewayAt(t, ctx, owner, o, w, e, ordered68MaximumDevice(i))
			}
		},
		consume: func(f ordered68PolicyAcceptanceContext) {
			worker := f.newWorker(f.checker)
			f.start(worker)
			for i, name := range []string{"hold-release", "persistent-pending", "requester-revoked", "target-changed"} {
				if !t.Run(name, func(t *testing.T) {
					f.t = t
					device := orderedApplicationDevice
					if i > 0 {
						device = ordered68MaximumDevice(i)
					}
					assertOrderedPolicyConvergence(t, f, worker, device, name)
				}) {
					return
				}
			}
		},
	})
}

type orderedConvergenceTraceKey struct{}
type orderedConvergenceTrace struct {
	prior pgx.QueryTracer
	reads chan struct{}
}

func (p *orderedConvergenceTrace) TraceQueryStart(ctx context.Context, c *pgx.Conn, q pgx.TraceQueryStartData) context.Context {
	if p.prior != nil {
		ctx = p.prior.TraceQueryStart(ctx, c, q)
	}
	if q.SQL == `SELECT zasp_authorization80_worker.revision($1)` {
		ctx = context.WithValue(ctx, orderedConvergenceTraceKey{}, true)
	}
	return ctx
}
func (p *orderedConvergenceTrace) TraceQueryEnd(ctx context.Context, c *pgx.Conn, q pgx.TraceQueryEndData) {
	if p.prior != nil {
		p.prior.TraceQueryEnd(ctx, c, q)
	}
	if ctx.Value(orderedConvergenceTraceKey{}) == true && q.Err == nil {
		select {
		case p.reads <- struct{}{}:
		default:
		}
	}
}

type orderedConvergenceObservation struct {
	desired, applied, generation             int64
	stored, verified, acknowledged, receipts int
}

func orderedPolicyConvergenceObservation(t *testing.T, f ordered68PolicyAcceptanceContext) orderedConvergenceObservation {
	t.Helper()
	var v orderedConvergenceObservation
	if err := f.owner.QueryRow(f.ctx, `SELECT desired,applied,generation,
 (SELECT count(*) FROM zasp_security_agent_temporary_policy_targets WHERE run_id=$2 AND phase='apply' AND state='stored'),
 (SELECT count(*) FROM zasp_security_agent_temporary_policy_targets WHERE run_id=$2 AND phase='apply' AND state='verified'),
 (SELECT count(*) FROM zasp_temporal68.deliveries WHERE run_id=$2 AND phase='apply' AND state='acknowledged'),
 (SELECT count(*) FROM zasp_sa_multistep_receipts WHERE run_id=$2 AND receipt_kind='temporary_policy_applied.v1')
 FROM zasp_authorization79.organizations WHERE organization_id=$1`, f.o, f.run).Scan(&v.desired, &v.applied, &v.generation, &v.stored, &v.verified, &v.acknowledged, &v.receipts); err != nil {
		t.Fatal("convergence observation", ordered68ErrorClass(err))
	}
	return v
}
func (v orderedConvergenceObservation) log(t *testing.T, phase string) {
	t.Log("policy convergence", phase, "desired", v.desired, "applied", v.applied, "generation", v.generation, "stored_sources", v.stored, "verified_sources", v.verified, "acknowledged_deliveries", v.acknowledged, "application_receipts", v.receipts)
}

func assertOrderedPolicyConvergence(t *testing.T, f ordered68PolicyAcceptanceContext, worker ordered68AcceptanceWorker, device, mode string) {
	t.Helper()
	f.reconcile()
	before := orderedPolicyConvergenceObservation(t, f)
	if before.desired != before.applied {
		t.Fatal("control did not start converged")
	}
	before.log(t, "before")
	nativeBefore := f.evidence()
	trace := &orderedConvergenceTrace{prior: worker.trace.prior, reads: make(chan struct{}, 1)}
	worker.trace.prior = trace
	ctx, cancel := context.WithTimeout(f.ctx, 10*time.Second)
	defer cancel()
	type result struct {
		phase      string
		err        error
		contextErr error
	}
	done := make(chan result, 1)
	var signatures atomic.Int64
	q := f.request("source", map[string]any{"device_id": device})
	began := time.Now()
	go func() {
		if err := worker.worker.PrepareOrdered68Operation(ctx, "ordered68.application.source", q); err != nil {
			done <- result{"prepare", err, ctx.Err()}
			return
		}
		decision, err := worker.worker.Authorize(ctx, "ordered68.application.source", q)
		authorizeContextErr := ctx.Err()
		if err != nil {
			done <- result{"authorize", err, authorizeContextErr}
			return
		}
		_, err = worker.worker.SignOrderedPolicy(ctx, decision, "ordered-key-01", f.keys, func(c context.Context, input policy.GatewayPolicySigningInput) (policy.GatewayPolicyEnvelope, error) {
			signatures.Add(1)
			if err := c.Err(); err != nil {
				return policy.GatewayPolicyEnvelope{}, err
			}
			return policy.SignGatewayPolicyEnvelope(input, f.private)
		})
		done <- result{"sign", err, ctx.Err()}
	}()
	joined := false
	var restoreRequester func()
	defer func() {
		cancel()
		if !joined {
			select {
			case <-done:
				joined = true
			case <-time.After(3 * time.Second):
				t.Error("convergence worker did not join after cancellation")
				// Keep ownership until the already-cancelled operation exits;
				// never race fixture pool/PG cleanup with a borrowed client.
				<-done
				joined = true
			}
		}
		if joined {
			if restoreRequester != nil {
				restoreRequester()
			}
			worker.trace.prior = trace.prior
		}
	}()
	var pending orderedConvergenceObservation
	for {
		select {
		case r := <-done:
			joined = true
			t.Fatal("operation returned before observed pending", r.phase, ordered68ErrorClass(r.err))
		default:
		}
		pending = orderedPolicyConvergenceObservation(t, f)
		if pending.desired > before.desired && pending.desired > pending.applied {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("no committed pending observed")
		case <-time.After(20 * time.Millisecond):
		}
	}
	select {
	case <-trace.reads:
	case r := <-done:
		joined = true
		t.Fatal("no completed pending revision read", r.phase, ordered68ErrorClass(r.err))
	case <-ctx.Done():
		t.Fatal("revision read not witnessed")
	}
	pending.log(t, "held-after-capture")
	select {
	case r := <-done:
		joined = true
		t.Fatal("pending operation escaped projection hold", r.phase, ordered68ErrorClass(r.err))
	default:
	}
	if mode == "requester-revoked" {
		tag, err := f.owner.Exec(f.ctx, `UPDATE zasp_identity_memberships SET active=false WHERE organization_id=$1 AND principal_id=$2 AND active`, f.o, f.actor)
		if err != nil || tag.RowsAffected() != 1 {
			t.Fatal("exact requester revoke", ordered68ErrorClass(err))
		}
		restoreRequester = func() {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(f.ctx), 5*time.Second)
			defer stop()
			tag, err := f.owner.Exec(cleanup, `UPDATE zasp_identity_memberships SET active=true WHERE organization_id=$1 AND principal_id=$2 AND NOT active`, f.o, f.actor)
			if err != nil || tag.RowsAffected() != 1 {
				t.Error("exact requester restore", ordered68ErrorClass(err))
			}
		}
	}
	if mode == "target-changed" {
		orderedConvergenceRevokeDevice(t, f, device)
	}
	if mode != "persistent-pending" {
		f.reconcile()
	}
	var outcome result
	select {
	case outcome = <-done:
		joined = true
	case <-time.After(time.Until(began.Add(13 * time.Second))):
		t.Fatal("convergence operation exceeded original budget plus join allowance")
	}
	t.Log("policy convergence result", mode, "phase", outcome.phase, "class", ordered68ErrorClass(outcome.err), "elapsed_ms", time.Since(began).Milliseconds(), "signatures", signatures.Load())
	after := orderedPolicyConvergenceObservation(t, f)
	after.log(t, "after")
	switch mode {
	case "hold-release":
		if outcome.err != nil || outcome.phase != "sign" || signatures.Load() != 1 || after.stored != before.stored+1 {
			t.Fatal("released projection did not reach actual native signing")
		}
	case "persistent-pending":
		if !errors.Is(outcome.err, context.DeadlineExceeded) || outcome.phase != "prepare" || signatures.Load() != 0 || !bytes.Equal(nativeBefore, f.evidence()) {
			t.Fatal("persistent projection did not preserve budget/evidence")
		}
	default:
		if outcome.phase != "authorize" || outcome.contextErr != nil || !(errors.Is(outcome.err, authorization.ErrDenied) || errors.Is(outcome.err, authorization.ErrConflict)) || signatures.Load() != 0 || !bytes.Equal(nativeBefore, f.evidence()) {
			t.Fatal("changed authority escaped fresh authorization", ordered68ErrorClass(outcome.err))
		}
	}
}

func orderedConvergenceRevokeDevice(t *testing.T, f ordered68PolicyAcceptanceContext, device string) {
	t.Helper()
	cfg := f.owner.Config().Copy()
	if err := f.owner.QueryRow(f.ctx, `SELECT principal_name FROM zasp_discovery_principal_bindings WHERE authority_role='zasp_discovery_api'`).Scan(&cfg.User); err != nil {
		t.Fatal("registered device API", ordered68ErrorClass(err))
	}
	api, err := pgx.ConnectConfig(f.ctx, cfg)
	if err != nil {
		t.Fatal("device API connect", ordered68ErrorClass(err))
	}
	defer func() {
		c, cancel := context.WithTimeout(context.WithoutCancel(f.ctx), 3*time.Second)
		defer cancel()
		if err := api.Close(c); err != nil {
			t.Error("device API close", ordered68ErrorClass(err))
		}
	}()
	if _, err = api.Exec(f.ctx, `SELECT public.zasp_discovery_transition_gateway_device($1,$2,$3,$4,1,'revoked')`, f.o, f.w, f.e, device); err != nil {
		t.Fatal("actual target transition", ordered68ErrorClass(err))
	}
}
