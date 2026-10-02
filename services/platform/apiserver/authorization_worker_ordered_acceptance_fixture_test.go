package apiserver

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
)

// Test-only consumers reuse actual admission/HTTP approval. Neither callback
// may manufacture accepted effects, receipts, authorization facts or proofs.
type ordered68PolicyAcceptance struct {
	capacity bool // observer only; product activity keeps its original twenty minutes
	prepare  func(*testing.T, context.Context, *pgx.Conn, string, string, string)
	consume  func(ordered68PolicyAcceptanceContext)
}

type ordered68PolicyAcceptanceContext struct {
	t                                              *testing.T
	ctx                                            context.Context
	owner                                          *pgx.Conn
	o, w, e, run, step, actor, login, store, model string
	keys                                           policy.GatewayPolicyKeys
	private                                        ed25519.PrivateKey
	checker                                        authorization.Checker
	reconcile                                      func()
	projectionAttempt                              orderedPolicyProjectionAttempt
	config                                         runtimeservices.Config
}

type ordered68AcceptanceWorker struct {
	worker *authorization.WorkerExecutor
	pool   *pgxpool.Pool
	key    *authorization.WorkerKey
	trace  *ordered68ProofCapture
}

// Capture only the proof actually emitted by the real worker. It stays in
// process memory, never in logs, environment, artifacts or production code.
type ordered68ProofCapture struct {
	prior pgx.QueryTracer
	mu    sync.Mutex
	proof []byte
}

func (p *ordered68ProofCapture) TraceQueryStart(ctx context.Context, c *pgx.Conn, q pgx.TraceQueryStartData) context.Context {
	if p.prior != nil {
		ctx = p.prior.TraceQueryStart(ctx, c, q)
	}
	if q.SQL == `SELECT set_config('zasp.worker_proof',$1,true)` && len(q.Args) == 1 {
		if s, ok := q.Args[0].(string); ok {
			p.mu.Lock()
			clear(p.proof)
			p.proof = append([]byte(nil), s...)
			p.mu.Unlock()
		}
	}
	return ctx
}
func (p *ordered68ProofCapture) TraceQueryEnd(ctx context.Context, c *pgx.Conn, q pgx.TraceQueryEndData) {
	if p.prior != nil {
		p.prior.TraceQueryEnd(ctx, c, q)
	}
}
func (p *ordered68ProofCapture) take() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]byte(nil), p.proof...)
}

func (f ordered68PolicyAcceptanceContext) newWorker(check authorization.Checker) ordered68AcceptanceWorker {
	f.t.Helper()
	key, err := authorization.NewWorkerKey(authorization.WorkerForward, bytes.Repeat([]byte{91}, 32))
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err = f.owner.Exec(f.ctx, `SELECT zasp_authorization80_worker.register_verifier($1,$2,$3)`, string(authorization.WorkerForward), key.Version(), key.Verifier()); err != nil {
		f.t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(f.owner.Config().ConnString())
	if err != nil {
		f.t.Fatal(err)
	}
	cfg.ConnConfig.User, cfg.MaxConns = f.login, 2
	trace := &ordered68ProofCapture{prior: orderedPolicyDiagnosticTracer(f.t, cfg.ConnConfig.Tracer)}
	cfg.ConnConfig.Tracer = trace
	pool, err := pgxpool.NewWithConfig(f.ctx, cfg)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { pool.Close(); trace.mu.Lock(); clear(trace.proof); trace.mu.Unlock() })
	worker, err := authorization.NewWorkerExecutor(pool, check, f.store, f.model, key)
	if err != nil {
		f.t.Fatal(err)
	}
	return ordered68AcceptanceWorker{worker, pool, key, trace}
}
func (f ordered68PolicyAcceptanceContext) request(operation string, payload map[string]any) json.RawMessage {
	raw, err := json.Marshal(map[string]any{"organization_id": f.o, "workspace_id": f.w, "environment_id": f.e, "run_id": f.run, "step_id": f.step, "generation": 1, "operation": operation, "payload": payload})
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}
func (f ordered68PolicyAcceptanceContext) capture(w ordered68AcceptanceWorker, op authorization.WorkerOperation, q json.RawMessage) {
	c, cancel := context.WithTimeout(f.ctx, 10*time.Second)
	defer cancel()
	if err := orderedPolicyFixtureCapture(f.t, c, f.owner, f.o, w.worker, op, q, f.projectionAttempt); err != nil {
		f.t.Fatal("actual acceptance capture", op, err)
	}
	f.reconcile()
}
func (f ordered68PolicyAcceptanceContext) execute(w ordered68AcceptanceWorker, op authorization.WorkerOperation, q json.RawMessage) json.RawMessage {
	c, cancel := context.WithTimeout(f.ctx, 10*time.Second)
	defer cancel()
	began := time.Now()
	d, err := w.worker.Authorize(c, op, q)
	if err != nil {
		f.t.Fatal("acceptance authorize", op, err)
	}
	raw, err := w.worker.Execute(c, d)
	if err != nil {
		f.t.Fatal("acceptance execute", op, err)
	}
	f.t.Log("ordered acceptance operation", op, "elapsed_ms", time.Since(began).Milliseconds())
	return raw
}
func (f ordered68PolicyAcceptanceContext) start(w ordered68AcceptanceWorker) {
	q := f.request("reserve", map[string]any{})
	f.capture(w, "ordered68.effect.reserve", q)
	f.execute(w, "ordered68.effect.reserve", q)
	f.reconcile()
	f.execute(w, "ordered68.effect.start", f.request("start", map[string]any{}))
	f.reconcile()
}
func (f ordered68PolicyAcceptanceContext) evidence() []byte {
	var raw []byte
	if err := f.owner.QueryRow(f.ctx, `SELECT jsonb_build_array(
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY generation) FROM zasp_temporal68.effects x WHERE run_id=$1 AND step_id=$2),
 (SELECT jsonb_agg(to_jsonb(x)) FROM zasp_sa_multistep_receipts x WHERE run_id=$1 AND step_id=$2),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY device_id,phase) FROM zasp_security_agent_temporary_policy_targets x WHERE run_id=$1 AND step_id=$2),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY device_id,phase) FROM zasp_temporal68.deliveries x WHERE run_id=$1 AND step_id=$2),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY audit_id) FROM zasp_security_agent_audit x WHERE run_id=$1),
 (SELECT to_jsonb(x) FROM zasp_security_agent_runs x WHERE run_id=$1),
 (SELECT to_jsonb(x) FROM zasp_security_agent_steps x WHERE run_id=$1 AND step_id=$2))`, f.run, f.step).Scan(&raw); err != nil {
		f.t.Fatal("acceptance immutable evidence", err)
	}
	return raw
}

func ordered68Rollback(t *testing.T, ctx context.Context, tx pgx.Tx) {
	t.Helper()
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	if err := tx.Rollback(cleanup); err != nil {
		t.Error("acceptance rollback", ordered68ErrorClass(err))
	}
}

// Never format driver errors from a proof-bearing session: only fixed classes
// or the five-character SQLSTATE are permitted in acceptance diagnostics.
func ordered68ErrorClass(err error) string {
	if err == nil {
		return "ok"
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) && len(pg.Code) == 5 {
		for _, c := range pg.Code {
			if c < '0' || c > '9' && c < 'A' || c > 'Z' {
				return "database-error"
			}
		}
		return pg.Code
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "deadline"
	}
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	return "error"
}
