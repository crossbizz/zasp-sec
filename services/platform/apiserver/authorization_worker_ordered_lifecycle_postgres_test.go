package apiserver

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

// A lifecycle source must bootstrap from the actual committed65/66 start and
// request receipt, not a planning capture or a freshly authorized requester.
func TestP7Ordered69CapturedLifecycle(t *testing.T) {
	t.Run("queued", func(t *testing.T) { runOrdered69Lifecycle(t, false) })
	t.Run("committed-cancel", func(t *testing.T) { runOrdered69Lifecycle(t, true) })
}

func TestP7Ordered69SourceLockWitness(t *testing.T) {
	runWorkerOrdered68PlanningFixture(t, "lifecycle", func(t *testing.T, ctx context.Context, owner, executor, api *pgx.Conn, identity json.RawMessage) {
		assertOrdered69SourceParentOrder(t, ctx, owner, identity)
	})
}

// The parent has created the loaded planning intent through its actual signed
// worker path. No planning row, reservation, approval or effect is inserted by
// this consumer, and no remote provider is contacted.
func TestP7Ordered69LoadedPlanningStop(t *testing.T) {
	runWorkerOrdered68PlanningFixture(t, "lifecycle-planning", func(t *testing.T, ctx context.Context, owner, executor, api *pgx.Conn, identity json.RawMessage) {
		var start map[string]any
		if err := json.Unmarshal(identity, &start); err != nil {
			t.Fatal(err)
		}
		run := start["run_id"].(string)
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
				t.Fatal("loaded lifecycle authorize", phase, err)
			}
			value, err := worker.Execute(bounded, d)
			if err != nil {
				t.Fatal("loaded lifecycle execute", phase, err)
			}
			t.Log("loaded lifecycle duration", phase, time.Since(began))
			return value
		}
		var state map[string]json.RawMessage
		if json.Unmarshal(call("inspect", identity), &state) != nil || len(state) != 11 || string(state["planning_state"]) != `"loaded"` || string(state["admitted"]) != "false" || string(state["terminal"]) != "false" || string(state["effects"]) != "[]" {
			t.Fatal("actual loaded lifecycle metadata", state)
		}
		tag, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE active AND principal_id=(SELECT requested_by FROM zasp_security_agent_runs WHERE run_id=$1)`, run)
		if err != nil || tag.RowsAffected() != 1 {
			t.Fatal("loaded requester revocation", tag, err)
		}
		stop := map[string]any{}
		for k, v := range start {
			stop[k] = v
		}
		stop["reason"] = "workflow_cancelled"
		stopRaw, _ := json.Marshal(stop)
		stopped := call("stop", stopRaw)
		var receipt map[string]any
		if json.Unmarshal(stopped, &receipt) != nil || receipt["run_id"] != run || receipt["reason"] != "workflow_cancelled" {
			t.Fatal("loaded stop receipt", string(stopped))
		}
		var exact bool
		if err := owner.QueryRow(ctx, `SELECT r.state='needs_human' AND r.completed_at IS NOT NULL AND j.state='needs_human'
 AND NOT EXISTS(SELECT 1 FROM zasp_temporal68.provider_reservations WHERE run_id=$1)
 AND NOT EXISTS(SELECT 1 FROM zasp_temporal68.admissions WHERE run_id=$1)
 AND NOT EXISTS(SELECT 1 FROM zasp_temporal68.effects WHERE run_id=$1)
 AND (SELECT count(*)=1 FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind='temporal_planning_terminal')
 AND (SELECT count(*)=1 FROM zasp_temporal69.stops WHERE run_id=$1)
 AND NOT zasp_authorization80_worker.runtime_ready()
 FROM zasp_security_agent_runs r JOIN zasp_temporal68.planning_jobs j USING(organization_id,workspace_id,environment_id,run_id) WHERE r.run_id=$1`, run).Scan(&exact); err != nil || !exact {
			t.Fatal("loaded recovery did not preserve terminal evidence", err)
		}
		evidence := func() []byte {
			t.Helper()
			var raw []byte
			if err := owner.QueryRow(ctx, `SELECT jsonb_build_array((SELECT to_jsonb(r) FROM zasp_security_agent_runs r WHERE run_id=$1),(SELECT to_jsonb(j) FROM zasp_temporal68.planning_jobs j WHERE run_id=$1),(SELECT jsonb_agg(to_jsonb(a) ORDER BY audit_id) FROM zasp_security_agent_audit a WHERE run_id=$1),(SELECT to_jsonb(s) FROM zasp_temporal69.stops s WHERE run_id=$1))`, run).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			return raw
		}
		before := evidence()
		if again := call("stop", stopRaw); !bytes.Equal(again, stopped) || !bytes.Equal(before, evidence()) {
			t.Fatal("loaded lifecycle replay changed immutable evidence")
		}
		if json.Unmarshal(call("inspect", identity), &state) != nil || string(state["planning_state"]) != `"needs_human"` || string(state["terminal"]) != "true" || string(state["admitted"]) != "false" {
			t.Fatal("loaded terminal metadata", state)
		}
	})
}

func runOrdered69Lifecycle(t *testing.T, committed bool) {
	mode := "lifecycle"
	if committed {
		mode = "lifecycle-message"
	}
	runWorkerOrdered68PlanningFixture(t, mode, func(t *testing.T, ctx context.Context, owner, executor, api *pgx.Conn, identity json.RawMessage) {
		var start map[string]any
		if err := json.Unmarshal(identity, &start); err != nil {
			t.Fatal(err)
		}
		run := start["run_id"].(string)
		var message json.RawMessage
		if committed {
			if err := owner.QueryRow(ctx, `SELECT jsonb_build_object('organization_id',organization_id,'workspace_id',workspace_id,'environment_id',environment_id,'run_id',run_id,'event_id',event_id,'decision_id',decision_id,'kind',kind) FROM zasp_temporal65.commands WHERE run_id=$1 AND kind='cancel'`, run).Scan(&message); err != nil {
				t.Fatal("committed cancellation message", err)
			}
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
		call := func(t *testing.T, phase string, q json.RawMessage) json.RawMessage {
			t.Helper()
			bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			began := time.Now()
			d, err := worker.Authorize(bounded, authorization.WorkerOperation("ordered69."+phase), q)
			if err != nil {
				t.Fatal("lifecycle authorize", phase, err)
			}
			v, err := worker.Execute(bounded, d)
			if err != nil {
				t.Fatal("lifecycle execute", phase, err)
			}
			t.Log("lifecycle duration", phase, time.Since(began))
			return v
		}
		inspect := func(t *testing.T, q json.RawMessage, terminal bool) {
			t.Helper()
			var v map[string]json.RawMessage
			if json.Unmarshal(q, &v) != nil || len(v) != 11 || string(v["terminal"]) != map[bool]string{true: "true", false: "false"}[terminal] || string(v["admitted"]) != "false" || string(v["planning_state"]) != "null" || string(v["effects"]) != "[]" {
				t.Fatal("lifecycle redacted state", string(q))
			}
			for _, forbidden := range []string{"planning", "request_body", "raw_result", "snapshot", "provider", "model"} {
				if _, ok := v[forbidden]; ok {
					t.Fatal("lifecycle disclosed private body", forbidden)
				}
			}
		}
		t.Run("bootstrap-inspect", func(t *testing.T) { inspect(t, call(t, "inspect", identity), committed) })
		if committed {
			t.Run("committed-message", func(t *testing.T) { inspect(t, call(t, "message", message), true) })
		}
		if t.Failed() {
			return
		}
		if !committed {
			assertOrdered69NativeFences(t, ctx, owner, identity, key)
			assertOrdered69SourceParentOrder(t, ctx, owner, identity)
			assertOrdered69ProofExpiryAfterWait(t, ctx, owner, identity, key)
		}
		var empty bool
		if err := owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_authorization80_worker.ordered_associations WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_temporal68.planning_jobs WHERE run_id=$1) AND NOT zasp_authorization80_worker.runtime_ready()`, run).Scan(&empty); err != nil || !empty {
			t.Fatal("lifecycle created forward capture", err)
		}
		revoked, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE active AND principal_id=(SELECT requested_by FROM zasp_security_agent_runs WHERE run_id=$1)`, run)
		if err != nil || revoked.RowsAffected() != 1 {
			t.Fatal("exact requester membership revocation", revoked, err)
		}
		t.Run("revoked-inspect", func(t *testing.T) { inspect(t, call(t, "inspect", identity), committed) })
		if committed {
			t.Run("revoked-message", func(t *testing.T) { inspect(t, call(t, "message", message), true) })
		}
		stop := map[string]any{}
		for k, v := range start {
			stop[k] = v
		}
		stop["reason"] = "workflow_cancelled"
		stopRaw, _ := json.Marshal(stop)
		var stopped json.RawMessage
		stopSucceeded := t.Run("stop-after-revocation", func(t *testing.T) {
			stopped = call(t, "stop", stopRaw)
			var v map[string]any
			if json.Unmarshal(stopped, &v) != nil || v["run_id"] != run || v["reason"] != "workflow_cancelled" {
				t.Fatal("stop receipt", string(stopped))
			}
		})
		if !stopSucceeded {
			return
		}
		t.Run("stop-replay", func(t *testing.T) {
			again := call(t, "stop", stopRaw)
			if !bytes.Equal(again, stopped) {
				t.Fatal("stop changed on replay")
			}
		})
		t.Run("terminal-inspect", func(t *testing.T) { inspect(t, call(t, "inspect", identity), true) })
		if committed {
			t.Run("terminal-message", func(t *testing.T) { inspect(t, call(t, "message", message), true) })
		}
		for _, phase := range []string{"inspect", "message", "stop"} {
			if phase == "message" && !committed {
				continue
			}
			t.Run(phase+"-foreign", func(t *testing.T) {
				var q map[string]any
				raw := identity
				if phase == "message" {
					raw = message
				} else if phase == "stop" {
					raw = stopRaw
				}
				if json.Unmarshal(raw, &q) != nil {
					t.Fatal("request")
				}
				q["run_id"] = "pid_99999999-0000-4000-8000-000000000001"
				bad, _ := json.Marshal(q)
				if _, err := worker.Authorize(ctx, authorization.WorkerOperation("ordered69."+phase), bad); !errors.Is(err, authorization.ErrConflict) || errors.Is(err, authorization.ErrUnavailable) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("foreign lifecycle did not return retained association conflict", err)
				}
			})
		}
	})
}

func ordered69Proof(t *testing.T, key *authorization.WorkerKey, facts json.RawMessage, operation, login string, issued, expires int64) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{"purpose": "captured-compensation", "key_version": key.Version(), "operation": operation, "request": nil, "facts": facts, "revision": authorization.Revision{}, "session_user": login, "issued_at": issued, "expires_at": expires})
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, key.Verifier())
	_, _ = mac.Write([]byte("zasp-authorization-captured-compensation-v1\x00"))
	_, _ = mac.Write(body)
	wire, err := json.Marshal(map[string]any{"body": body, "version": key.Version(), "mac": hex.EncodeToString(mac.Sum(nil))})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

// Real native metadata and a registered key supply this controlled proof. The
// positive case verifies the envelope before any negative catalog/proof case;
// all mutations and all resulting native work are rolled back together.
func assertOrdered69NativeFences(t *testing.T, ctx context.Context, owner *pgx.Conn, identity json.RawMessage, key *authorization.WorkerKey) {
	t.Helper()
	const login = "temporal_compensation_test_login"
	cfg := owner.Config().Copy()
	cfg.User = login
	comp, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer comp.Close(ctx)
	for _, entry := range []string{"ordered69_status_inner", "ordered69_reconcile_inner", "ordered69_inspect_inner", "ordered69_message_inner", "ordered69_stop_inner", "ordered69_stop_test_inner", "ordered69_finish"} {
		t.Run("private-denied-"+entry, func(t *testing.T) {
			var value json.RawMessage
			err := comp.QueryRow(ctx, "SELECT zasp_authorization80_worker."+entry+"($1::jsonb)", identity).Scan(&value)
			var native *pgconn.PgError
			if !errors.As(err, &native) || native.Code != "42501" {
				t.Fatal("private lifecycle helper exposed", entry, err)
			}
		})
	}
	for _, name := range []string{"positive", "helper-body", "helper-acl", "public69-body", "saved-row", "retained-admission", "phase", "session", "request", "expired", "missing"} {
		t.Run("native-fence-"+name, func(t *testing.T) {
			var facts json.RawMessage
			if err := comp.QueryRow(ctx, `SELECT zasp_authorization80_worker.ordered69_source('inspect',$1::jsonb)`, identity).Scan(&facts); err != nil {
				t.Fatal("actual lifecycle facts", err)
			}
			now := time.Now().UnixMilli()
			expires := now + 30000
			op := "ordered69.inspect"
			session := login
			request := identity
			switch name {
			case "phase":
				op = "ordered69.stop"
			case "session":
				session = "temporal_executor_test_login"
			case "expired":
				expires = now - 1
			case "request":
				var q map[string]any
				if json.Unmarshal(identity, &q) != nil {
					t.Fatal("request")
				}
				q["input_digest"] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
				request, _ = json.Marshal(q)
			}
			wire := ordered69Proof(t, key, facts, op, session, now, expires)
			tx, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			mutation := ""
			switch name {
			case "helper-body":
				mutation = `CREATE OR REPLACE FUNCTION zasp_authorization80_worker.ordered69_status_inner(q jsonb) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS 'SELECT NULL::jsonb'`
			case "helper-acl":
				mutation = `GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.ordered69_status_inner(jsonb) TO zasp_temporal_executor`
			case "public69-body":
				mutation = `CREATE OR REPLACE FUNCTION zasp_temporal69.inspect_message(q jsonb) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS 'SELECT NULL::jsonb'`
			case "saved-row":
				mutation = `ALTER TABLE zasp_authorization80_worker.predecessor_functions DISABLE TRIGGER immutable; UPDATE zasp_authorization80_worker.predecessor_functions SET definition=definition||E'\n-- altered saved69' WHERE signature='zasp_temporal69.inspect(jsonb)'; ALTER TABLE zasp_authorization80_worker.predecessor_functions ENABLE TRIGGER immutable`
			}
			if mutation != "" {
				if _, err := tx.Exec(ctx, mutation, pgx.QueryExecModeSimpleProtocol); err != nil {
					t.Fatal("controlled catalog mutation", err)
				}
			}
			if name == "retained-admission" {
				if _, err := tx.Exec(ctx, `ALTER TABLE zasp_temporal66.run_owners DISABLE TRIGGER immutable`); err != nil {
					t.Fatal(err)
				}
				tag, err := tx.Exec(ctx, `UPDATE zasp_temporal66.run_owners SET input_digest=repeat('a',64) WHERE run_id=($1::jsonb->>'run_id') AND input_digest<>repeat('a',64)`, identity)
				if err != nil || tag.RowsAffected() != 1 {
					t.Fatal("exact retained admission mutation", tag, err)
				}
				if _, err := tx.Exec(ctx, `ALTER TABLE zasp_temporal66.run_owners ENABLE TRIGGER immutable`); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := tx.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION temporal_compensation_test_login`); err != nil {
				t.Fatal(err)
			}
			if name != "missing" {
				if _, err := tx.Exec(ctx, `SELECT set_config('zasp.worker_proof',$1,true)`, string(wire)); err != nil {
					t.Fatal(err)
				}
			}
			var value json.RawMessage
			err = tx.QueryRow(ctx, `SELECT zasp_authorization80_worker.ordered69_inspect($1::jsonb)`, request).Scan(&value)
			if name == "positive" {
				if err != nil {
					t.Fatal("registered proof control", err)
				}
			} else {
				var native *pgconn.PgError
				if !errors.As(err, &native) || (native.Code != "42501" && native.Code != "40001") {
					t.Fatal("native lifecycle fence bypass", name, err)
				}
			}
			if err := tx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// This is a lock/freshness control, not an operation latency measurement. Its
// proof is valid on entry and expires only after the actual native entry has
// demonstrably reached the held organization row.
func assertOrdered69ProofExpiryAfterWait(t *testing.T, ctx context.Context, owner *pgx.Conn, identity json.RawMessage, key *authorization.WorkerKey) {
	t.Helper()
	t.Run("proof-expires-during-organization-wait", func(t *testing.T) {
		bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		cfg := owner.Config().Copy()
		cfg.User = "temporal_compensation_test_login"
		consumer, err := pgx.ConnectConfig(bounded, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer consumer.Close(ctx)
		var facts json.RawMessage
		if err := consumer.QueryRow(bounded, `SELECT zasp_authorization80_worker.ordered69_source('inspect',$1::jsonb)`, identity).Scan(&facts); err != nil {
			t.Fatal(err)
		}
		blocker, err := owner.Begin(bounded)
		if err != nil {
			t.Fatal(err)
		}
		defer blocker.Rollback(ctx)
		if _, err := blocker.Exec(bounded, `SELECT 1 FROM zasp_authorization79.organizations WHERE organization_id=($1::jsonb->>'organization_id') FOR UPDATE`, identity); err != nil {
			t.Fatal(err)
		}
		tx, err := consumer.Begin(bounded)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		now := time.Now().UnixMilli()
		expires := now + 6000
		wire := ordered69Proof(t, key, facts, "ordered69.inspect", cfg.User, now, expires)
		if _, err := tx.Exec(bounded, `SELECT set_config('zasp.worker_proof',$1,true)`, string(wire)); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			var value json.RawMessage
			done <- tx.QueryRow(bounded, `SELECT zasp_authorization80_worker.ordered69_inspect($1::jsonb)`, identity).Scan(&value)
		}()
		waiting := false
		for time.Now().UnixMilli() < expires {
			select {
			case err := <-done:
				t.Fatal("native entry returned before organization release", err)
			default:
			}
			if err := blocker.QueryRow(bounded, `SELECT pg_backend_pid()=ANY(pg_blocking_pids($1))`, consumer.PgConn().PID()).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if waiting {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !waiting || time.Now().UnixMilli() >= expires {
			t.Fatal("proof was not valid when native entry reached organization wait")
		}
		time.Sleep(time.Until(time.UnixMilli(expires).Add(25 * time.Millisecond)))
		if err := blocker.Commit(bounded); err != nil {
			t.Fatal(err)
		}
		err = <-done
		var native *pgconn.PgError
		if !errors.As(err, &native) || native.Code != "42501" {
			t.Fatal("proof expiring during organization wait admitted", err)
		}
	})
}

const ordered69ParentLockQuery = `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND relation IN('public.zasp_security_agent_runs'::regclass,'public.zasp_security_agent_run_budgets'::regclass,'zasp_temporal66.run_owners'::regclass,'zasp_temporal65.commands'::regclass) AND (locktype<>'relation' OR mode<>'AccessShareLock'))`

// Moving the retained budget lock after a source row would deadlock a native
// predecessor reader. A read-plan AccessShareLock does not take a row lock;
// every other lock type/mode, including an ungranted request, is rejected.
func assertOrdered69SourceParentOrder(t *testing.T, ctx context.Context, owner *pgx.Conn, identity json.RawMessage) {
	t.Helper()
	var q map[string]any
	if json.Unmarshal(identity, &q) != nil {
		t.Fatal("identity")
	}
	for _, clause := range []string{"FOR SHARE", "FOR UPDATE"} {
		t.Run("parent-row-lock-witness-"+clause, func(t *testing.T) {
			// Exercise exactly the same predicate against actual held parent row
			// locks, so excluding AccessShare cannot conceal a row-lock regression.
			probe, err := pgx.ConnectConfig(ctx, owner.Config().Copy())
			if err != nil {
				t.Fatal(err)
			}
			defer probe.Close(ctx)
			tx, err := probe.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			var run string
			if err := tx.QueryRow(ctx, `SELECT run_id FROM public.zasp_security_agent_runs WHERE run_id=$1 `+clause, q["run_id"]).Scan(&run); err != nil {
				t.Fatal("controlled parent row lock", err)
			}
			var rejected bool
			if err := owner.QueryRow(ctx, ordered69ParentLockQuery, probe.PgConn().PID()).Scan(&rejected); err != nil || !rejected {
				t.Fatal("parent row lock escaped witness", clause, err)
			}
		})
	}
	for _, mutation := range []string{"organization", "unchanged", "principal", "catalog"} {
		t.Run("source-budget-wait-"+mutation, func(t *testing.T) {
			cfg := owner.Config().Copy()
			cfg.User = "temporal_compensation_test_login"
			consumer, err := pgx.ConnectConfig(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer consumer.Close(ctx)
			blocker, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer blocker.Rollback(ctx)
			lockSQL := `SELECT pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||$1,0))`
			if mutation == "organization" {
				lockSQL = `SELECT 1 FROM zasp_authorization79.organizations WHERE organization_id=$1 FOR UPDATE`
			}
			if _, err := blocker.Exec(ctx, lockSQL, q["organization_id"]); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				var value json.RawMessage
				done <- consumer.QueryRow(ctx, `SELECT zasp_authorization80_worker.ordered69_source('inspect',$1::jsonb)`, identity).Scan(&value)
			}()
			waiting := false
			until := time.Now().Add(10 * time.Second)
			for time.Now().Before(until) {
				select {
				case err := <-done:
					t.Fatal("source returned before retained budget release", err)
				default:
				}
				if err := blocker.QueryRow(ctx, `SELECT pg_backend_pid()=ANY(pg_blocking_pids($1))`, consumer.PgConn().PID()).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !waiting {
				t.Fatal("source did not wait for retained budget lock")
			}
			var parentTouched bool
			var locks json.RawMessage
			if err := blocker.QueryRow(ctx, `SELECT COALESCE(jsonb_agg(jsonb_build_object('relation',relation::regclass::text,'locktype',locktype,'mode',mode,'granted',granted,'page',page,'tuple',tuple) ORDER BY relation,mode),'[]'::jsonb) FROM pg_locks WHERE pid=$1 AND relation IN('public.zasp_security_agent_runs'::regclass,'public.zasp_security_agent_run_budgets'::regclass,'zasp_temporal66.run_owners'::regclass,'zasp_temporal65.commands'::regclass)`, consumer.PgConn().PID()).Scan(&locks); err != nil {
				t.Fatal(err)
			}
			t.Log("native parent lock witness", string(locks))
			if err := blocker.QueryRow(ctx, ordered69ParentLockQuery, consumer.PgConn().PID()).Scan(&parentTouched); err != nil || parentTouched {
				t.Fatal("source parent lock preceded retained budget", err)
			}
			switch mutation {
			case "principal":
				if _, err := blocker.Exec(ctx, `ALTER ROLE temporal_compensation_test_login NOINHERIT`); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := owner.Exec(ctx, `ALTER ROLE temporal_compensation_test_login INHERIT`); err != nil {
						t.Error("restore principal", err)
					}
				}()
			case "catalog":
				if _, err := blocker.Exec(ctx, `GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.ordered69_status_inner(jsonb) TO zasp_temporal_executor`); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := owner.Exec(ctx, `REVOKE EXECUTE ON FUNCTION zasp_authorization80_worker.ordered69_status_inner(jsonb) FROM zasp_temporal_executor`); err != nil {
						t.Error("restore helper ACL", err)
					}
				}()
			}
			if err := blocker.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			err = <-done
			if mutation == "unchanged" || mutation == "organization" {
				if err != nil {
					t.Fatal("retained budget release", err)
				}
			} else {
				var native *pgconn.PgError
				refused := errors.As(err, &native) && (native.Code == "42501" || mutation == "principal" && native.Code == "40001" && native.Message == "ordered lifecycle retained owner changed")
				if !refused {
					t.Fatal("after-wait drift admitted", mutation, err)
				}
			}
		})
	}
}
