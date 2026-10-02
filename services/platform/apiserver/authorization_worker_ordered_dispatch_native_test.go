package apiserver

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

// The existing producer commits actual linked.dispatch and crashes before the
// engine. These controls cannot manufacture a prepared input or a send. Each
// native invocation retains its own original ten-second budget.
func TestP7OrderedDispatchNativeBoundaries(t *testing.T) {
	runOrderedActualRunnerConsumer(t, "test-started", assertOrderedDispatchNativeBoundaries)
}

type orderedDispatchProofCapture struct {
	mu    sync.Mutex
	proof []byte
}

func (p *orderedDispatchProofCapture) TraceQueryStart(ctx context.Context, _ *pgx.Conn, q pgx.TraceQueryStartData) context.Context {
	if q.SQL == `SELECT set_config('zasp.worker_proof',$1,true)` && len(q.Args) == 1 {
		if v, ok := q.Args[0].(string); ok {
			p.mu.Lock()
			p.proof = append(p.proof[:0], v...)
			p.mu.Unlock()
		}
	}
	return ctx
}
func (*orderedDispatchProofCapture) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {
}
func (p *orderedDispatchProofCapture) take() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	v := bytes.Clone(p.proof)
	clear(p.proof)
	p.proof = nil
	return v
}

func assertOrderedDispatchNativeBoundaries(c ordered68ApprovedTestContext) {
	t, ctx := c.t, c.ctx
	t.Helper()
	cfg, err := pgxpool.ParseConfig(c.owner.Config().ConnString())
	if err != nil {
		t.Fatal(err)
	}
	trace := &orderedDispatchProofCapture{}
	cfg.ConnConfig.User = c.forwardLogin
	cfg.ConnConfig.Tracer = trace
	cfg.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	key, err := authorization.NewWorkerKey(authorization.WorkerForward, bytes.Repeat([]byte{91}, 32))
	if err != nil {
		t.Fatal(err)
	}
	worker, err := authorization.NewWorkerExecutor(pool, c.checker, c.storeID, c.modelID, key)
	if err != nil {
		t.Fatal(err)
	}
	q, _ := json.Marshal(map[string]any{"organization_id": c.scope.OrganizationID().String(), "workspace_id": c.scope.WorkspaceID().String(), "environment_id": c.scope.EnvironmentID().String(), "run_id": c.run, "step_id": c.step, "generation": 1, "operation": "dispatch", "payload": map[string]any{}})
	evidence := func() []byte {
		var b []byte
		if err := c.owner.QueryRow(ctx, `SELECT jsonb_build_array(
 (SELECT jsonb_agg(to_jsonb(f) ORDER BY step_id) FROM zasp_temporal68.effects f WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(i) ORDER BY step_id) FROM zasp_temporal68.test_inputs i WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(l) ORDER BY step_id) FROM zasp_security_agent_test_links l WHERE run_id=$1),
 (SELECT jsonb_agg(to_jsonb(j) ORDER BY j.category) FROM zasp_temporal68.invocations j JOIN zasp_temporal68.effects f USING(effect_key) WHERE f.run_id=$1),
 (SELECT jsonb_agg(to_jsonb(s) ORDER BY step_id) FROM zasp_temporal68.test_settlements s WHERE run_id=$1))`, c.run).Scan(&b); err != nil {
			t.Fatal("dispatch evidence", err)
		}
		return b
	}
	native := func(callCtx context.Context, proof, request []byte, read bool, principal ...string) (json.RawMessage, error) {
		tx, err := c.owner.BeginTx(callCtx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
		if err != nil {
			return nil, err
		}
		defer func() {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(callCtx), 5*time.Second)
			defer cancel()
			_ = tx.Rollback(cleanup)
		}()
		login := c.forwardLogin
		if len(principal) == 1 {
			login = principal[0]
		}
		if _, err = tx.Exec(callCtx, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{login}.Sanitize()); err != nil {
			return nil, err
		}
		if _, err = tx.Exec(callCtx, `SELECT set_config('zasp.worker_proof',$1,true)`, string(proof)); err != nil {
			return nil, err
		}
		sql := `SELECT zasp_temporal68.linked($1::jsonb)`
		if read {
			sql = `SELECT zasp_authorization80_worker.ordered68_dispatch_readback($1::jsonb)`
		}
		var result json.RawMessage
		if err = tx.QueryRow(callCtx, sql, json.RawMessage(request)).Scan(&result); err != nil {
			return nil, err
		}
		return result, tx.Commit(callCtx)
	}
	beforeCatalog := evidence()
	catalogConnection, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal("registered catalog executor", err)
	}
	func() {
		defer catalogConnection.Release()
		assertOrderedTestInstalledCatalog(t, ctx, c.owner, catalogConnection.Conn())
	}()
	if !bytes.Equal(beforeCatalog, evidence()) {
		t.Fatal("catalog controls changed actual checkpoint")
	}
	for _, name := range []string{"unchanged", "revoked-after-readback", "input-after-readback", "expired-after-readback", "foreign-request", "wrong-phase", "readback-missing-proof", "readback-foreign-request", "readback-wrong-proof-phase", "readback-foreign-principal"} {
		t.Run(name, func(t *testing.T) {
			before := evidence()
			c.reconcile()
			authCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			decision, err := worker.Authorize(authCtx, "ordered68.linked.dispatch", q)
			if err == nil {
				_, err = worker.ExecuteOrderedTestDispatchReadback(authCtx, decision)
			}
			cancel()
			if err != nil {
				t.Fatal("actual dispatch proof/readback", err)
			}
			proof := trace.take()
			defer clear(proof)
			if len(proof) == 0 {
				t.Fatal("actual dispatch proof absent")
			}
			var wire struct {
				Body    []byte `json:"body"`
				Version string `json:"version"`
				MAC     string `json:"mac"`
			}
			if json.Unmarshal(proof, &wire) != nil || len(wire.Body) > 32768 {
				t.Fatal("bounded genuine proof")
			}
			if name == "readback-missing-proof" || name == "readback-foreign-request" || name == "readback-wrong-proof-phase" || name == "readback-foreign-principal" {
				request := bytes.Clone(q)
				login := c.forwardLogin
				switch name {
				case "readback-missing-proof":
					proof = nil
				case "readback-foreign-request":
					var value map[string]any
					_ = json.Unmarshal(request, &value)
					value["run_id"] = value["organization_id"]
					request, _ = json.Marshal(value)
				case "readback-wrong-proof-phase":
					var value map[string]json.RawMessage
					_ = json.Unmarshal(wire.Body, &value)
					value["operation"] = json.RawMessage(`"ordered68.linked.read"`)
					wire.Body, _ = json.Marshal(value)
					mac := hmac.New(sha256.New, key.Verifier())
					mac.Write([]byte("zasp-authorization-worker-forward-v1\x00"))
					mac.Write(wire.Body)
					wire.MAC = hex.EncodeToString(mac.Sum(nil))
					proof, _ = json.Marshal(wire)
				case "readback-foreign-principal":
					login = "temporal_compensation_test_login"
				}
				bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
				defer cancel()
				_, err := native(bounded, proof, request, true, login)
				var pg *pgconn.PgError
				want := "42501"
				// Large requests are bound by source facts. A foreign run reaches
				// the source's canonical successor check before facts equality.
				if name == "readback-foreign-request" {
					want = "40001"
				}
				if !errors.As(err, &pg) || pg.Code != want || bounded.Err() != nil {
					t.Fatal("direct readback proof/principal refusal", name, err)
				}
				if !bytes.Equal(before, evidence()) {
					t.Fatal("direct readback refusal changed evidence")
				}
				return
			}
			var expires int64
			if name == "expired-after-readback" {
				var body map[string]json.RawMessage
				if json.Unmarshal(wire.Body, &body) != nil {
					t.Fatal("proof body")
				}
				expires = time.Now().Add(5 * time.Second).UnixMilli()
				body["expires_at"], _ = json.Marshal(expires)
				wire.Body, _ = json.Marshal(body)
				mac := hmac.New(sha256.New, key.Verifier())
				mac.Write([]byte("zasp-authorization-worker-forward-v1\x00"))
				mac.Write(wire.Body)
				wire.MAC = hex.EncodeToString(mac.Sum(nil))
				proof, _ = json.Marshal(wire)
			}
			readCtx, readCancel := context.WithTimeout(ctx, 10*time.Second)
			prior, err := native(readCtx, proof, q, true)
			readCancel()
			var state temporalLinkedState
			if err != nil || json.Unmarshal(prior, &state) != nil || state.SendPermit || state.InputManifest == nil {
				t.Fatal("native no-send readback", err)
			}
			restore := func() {}
			switch name {
			case "revoked-after-readback":
				tag, e := c.owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE organization_id=$1 AND principal_id=$2 AND active`, c.scope.OrganizationID().String(), c.actor)
				if e != nil || tag.RowsAffected() != 1 {
					t.Fatal("committed requester revocation", e)
				}
				restore = func() {
					tag, e := c.owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=true WHERE organization_id=$1 AND principal_id=$2 AND NOT active`, c.scope.OrganizationID().String(), c.actor)
					if e != nil || tag.RowsAffected() != 1 {
						t.Fatal("restore requester", e)
					}
					c.reconcile()
				}
			case "input-after-readback":
				var original []byte
				if e := c.owner.QueryRow(ctx, `SELECT body FROM zasp_temporal68.test_inputs WHERE run_id=$1 AND step_id=$2`, c.run, c.step).Scan(&original); e != nil {
					t.Fatal(e)
				}
				mutate := func(body []byte) {
					tx, e := c.owner.Begin(ctx)
					if e != nil {
						t.Fatal(e)
					}
					defer tx.Rollback(ctx)
					if _, e = tx.Exec(ctx, `ALTER TABLE zasp_temporal68.test_inputs DISABLE TRIGGER immutable`); e != nil {
						t.Fatal(e)
					}
					tag, e := tx.Exec(ctx, `UPDATE zasp_temporal68.test_inputs SET body=$3 WHERE run_id=$1 AND step_id=$2`, c.run, c.step, body)
					if e != nil || tag.RowsAffected() != 1 {
						t.Fatal("scoped corrupt-input fixture", e)
					}
					if _, e = tx.Exec(ctx, `ALTER TABLE zasp_temporal68.test_inputs ENABLE TRIGGER immutable`); e != nil {
						t.Fatal(e)
					}
					if e = tx.Commit(ctx); e != nil {
						t.Fatal(e)
					}
				}
				mutate(append(bytes.Clone(original), ' '))
				restore = func() { mutate(original) }
			case "expired-after-readback":
				if time.Now().UnixMilli() >= expires {
					t.Fatal("proof expired before wait witness")
				}
				timer := time.NewTimer(time.Until(time.UnixMilli(expires)) + 20*time.Millisecond)
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-ctx.Done():
					t.Fatal("test context ended before expiry")
				}
			}
			func() {
				defer restore()
				request := bytes.Clone(q)
				if name == "foreign-request" || name == "wrong-phase" {
					var v map[string]any
					_ = json.Unmarshal(request, &v)
					if name == "foreign-request" {
						v["run_id"] = v["organization_id"]
					} else {
						v["operation"] = "read"
					}
					request, _ = json.Marshal(v)
				}
				executeCtx, executeCancel := context.WithTimeout(ctx, 10*time.Second)
				defer executeCancel()
				result, e := native(executeCtx, proof, request, false)
				if name == "unchanged" {
					if e != nil || !bytes.Equal(prior, result) {
						t.Fatal("started dispatch replay changed", e)
					}
					return
				}
				var pg *pgconn.PgError
				if !errors.As(e, &pg) || pg.Code != "42501" && pg.Code != "40001" || executeCtx.Err() != nil {
					t.Fatal("native refusal was not authority/source/proof", name, e)
				}
				t.Log("dispatch native refusal", name, "sqlstate", pg.Code, "context_live", executeCtx.Err() == nil)
			}()
			if !bytes.Equal(before, evidence()) {
				t.Fatal("readback/refusal changed native Test evidence")
			}
		})
	}
}
