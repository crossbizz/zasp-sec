package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// A retained raw grant must fail the four denial controls. A retirement that
// breaks named settled recovery, rewrites a successful receipt or erases Block
// debt must fail before those controls. The producer is the actual happy Test,
// including engine, journal, artifact validation, settlement and no-send retry.
func TestP7Ordered69RetirementSettledTest(t *testing.T) {
	runOrderedActualRunnerWithSettledConsumer(t, "", assertOrdered69SettledRetirement)
}

// Readiness acceptance consumes the same settled recovery without asserting
// retirement of raw grants, which remains a separate tests-first boundary.
func TestP7Ordered69ReadinessSettledRecovery(t *testing.T) {
	runOrderedActualRunnerWithSettledConsumer(t, "", func(c ordered68ApprovedTestContext, directory string) {
		assertOrdered69SettledRecovery(c, directory)
	})
}

func assertOrdered69SettledRetirement(c ordered68ApprovedTestContext, directory string) {
	message, stop := assertOrdered69SettledRecovery(c, directory)
	assertOrdered69RawRetirement(c, directory, message, stop)
}

func assertOrdered69SettledRecovery(c ordered68ApprovedTestContext, directory string) (json.RawMessage, json.RawMessage) {
	t, ctx := c.t, c.ctx
	t.Helper()
	var ready bool
	if err := c.owner.QueryRow(ctx, `SELECT r.state='contained' AND r.completed_at IS NOT NULL
 AND f.state='verified' AND f.completed_at IS NOT NULL
 AND l.reconcile_state='settled' AND l.reconcile_settlement IS NOT NULL
 AND ch.state='complete' AND ch.attempt=1 AND ch.completed_at IS NOT NULL
 AND (SELECT count(*)=1 FROM zasp_red_team_attempts WHERE run_id=ch.run_id)
 AND (SELECT count(*)=1 AND bool_and(state='completed' AND attempt=1 AND http_status=200 AND protected AND completed_at IS NOT NULL) FROM zasp_temporal68.invocations WHERE test_run_id=ch.run_id)
 AND (SELECT count(*)=1 FROM zasp_temporal68.test_settlements WHERE run_id=r.run_id AND step_id=f.step_id)
 AND EXISTS(SELECT 1 FROM zasp_sa_multistep_receipts WHERE run_id=r.run_id AND step_id=f.step_id AND action_key='run_test')
 AND EXISTS(SELECT 1 FROM zasp_temporal68.effects WHERE run_id=r.run_id AND action_key='create_temporary_policy' AND state='cleanup_pending')
 AND NOT EXISTS(SELECT 1 FROM zasp_temporal68.test_stops WHERE run_id=r.run_id)
 AND NOT EXISTS(SELECT 1 FROM zasp_temporal69.stops WHERE run_id=r.run_id)
 FROM zasp_security_agent_runs r JOIN zasp_temporal68.effects f USING(organization_id,workspace_id,environment_id,run_id)
 JOIN zasp_security_agent_test_links l USING(organization_id,workspace_id,environment_id,run_id,step_id)
 JOIN zasp_red_team_runs ch ON(ch.organization_id,ch.workspace_id,ch.environment_id,ch.run_id)=(l.organization_id,l.workspace_id,l.environment_id,l.test_run_id)
 WHERE r.run_id=$1 AND f.step_id=$2`, c.run, c.step).Scan(&ready); err != nil || !ready {
		t.Fatal("retirement requires actual successful settled Test and retained Block debt", ordered68ErrorClass(err))
	}
	// Use an actual committed Test approval association. No new command,
	// receipt, proof or notification is inserted by this consumer.
	var message json.RawMessage
	var exactMessage bool
	if err := c.owner.QueryRow(ctx, `SELECT jsonb_build_object('organization_id',cmd.organization_id,'workspace_id',cmd.workspace_id,'environment_id',cmd.environment_id,'run_id',cmd.run_id,'event_id',cmd.event_id,'decision_id',cmd.decision_id,'kind',cmd.kind),count(*) OVER()=1
 FROM zasp_temporal65.commands cmd
 JOIN zasp_security_agent_request_receipts rr ON(rr.organization_id,rr.workspace_id,rr.environment_id,rr.receipt_id)=(cmd.organization_id,cmd.workspace_id,cmd.environment_id,cmd.decision_id)
 JOIN zasp_security_agent_approvals a ON(a.organization_id,a.workspace_id,a.environment_id,a.approval_id,a.run_id)=(cmd.organization_id,cmd.workspace_id,cmd.environment_id,rr.intent->>'approval_id',cmd.run_id)
 WHERE cmd.run_id=$1 AND cmd.kind='approval' AND cmd.execution_owner='temporal' AND a.step_id=$2 AND a.state='approved'`, c.run, c.step).Scan(&message, &exactMessage); err != nil || !exactMessage {
		t.Fatal("exact committed Test approval message absent", ordered68ErrorClass(err))
	}
	var start map[string]json.RawMessage
	if json.Unmarshal(c.identity, &start) != nil {
		t.Fatal("retirement actual start identity")
	}
	start["reason"] = json.RawMessage(`"workflow_cancelled"`)
	stop, err := json.Marshal(start)
	if err != nil {
		t.Fatal("retirement stop request")
	}
	call := func(operation string, request json.RawMessage) json.RawMessage {
		t.Helper()
		bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		began := time.Now()
		decision, err := c.compensation.Authorize(bounded, authorization.WorkerOperation("ordered69."+operation), request)
		if err != nil {
			t.Fatal("settled retirement named authorize", operation, ordered68ErrorClass(err))
		}
		result, err := c.compensation.Execute(bounded, decision)
		if err != nil || bounded.Err() != nil {
			t.Fatal("settled retirement named execute", operation, ordered68ErrorClass(err))
		}
		t.Log("settled retirement named", operation, "elapsed_ms", time.Since(began).Milliseconds())
		return result
	}
	assertView := func(raw json.RawMessage) {
		t.Helper()
		var view struct {
			State    string            `json:"run_state"`
			Terminal bool              `json:"terminal"`
			Cleanup  bool              `json:"cleanup_required"`
			Markers  []json.RawMessage `json:"cleanup_markers"`
		}
		if json.Unmarshal(raw, &view) != nil || view.State != "contained" || !view.Terminal || !view.Cleanup || len(view.Markers) != 0 {
			t.Fatal("settled retirement changed outcome or cleanup debt")
		}
	}
	before := orderedPostRecoveryEvidence(c, directory)
	assertView(call("inspect", c.identity))
	if !bytes.Equal(before, orderedPostRecoveryEvidence(c, directory)) {
		t.Fatal("settled inspection changed native evidence")
	}
	tag, err := c.owner.Exec(ctx, `UPDATE zasp_identity_memberships m SET active=false FROM zasp_security_agent_runs r WHERE r.run_id=$1 AND(m.organization_id,m.principal_id)=(r.organization_id,r.requested_by) AND m.active`, c.run)
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatal("retirement exact requester revocation", ordered68ErrorClass(err))
	}
	// The real registered projector consumes revocation; it does not supply
	// positive authority to any captured lifecycle operation.
	c.reconcile()
	assertView(call("message", message))
	assertView(call("inspect", c.identity))
	first := call("stop", stop)
	after := orderedPostRecoveryEvidence(c, directory)
	if !bytes.Equal(orderedRetirementWithoutStop(t, before), orderedRetirementWithoutStop(t, after)) {
		t.Fatal("terminal stop changed settled Test, artifacts, parent outcome or Block debt")
	}
	var saved json.RawMessage
	if err := c.owner.QueryRow(ctx, `SELECT to_jsonb(s) FROM zasp_temporal69.stops s WHERE run_id=$1`, c.run).Scan(&saved); err != nil || !bytes.Equal(saved, first) {
		t.Fatal("terminal stop did not return its exact immutable receipt", ordered68ErrorClass(err))
	}
	if replay := call("stop", stop); !bytes.Equal(first, replay) {
		t.Fatal("terminal settled stop replay changed receipt")
	}
	assertView(call("message", message))
	assertView(call("inspect", c.identity))
	if !bytes.Equal(after, orderedPostRecoveryEvidence(c, directory)) {
		t.Fatal("settled named replay changed complete durable evidence")
	}
	t.Log("settled named stop/replay positive complete")
	return message, stop
}

// The shared evidence snapshot has a fixed 21-element native array; only its
// workflow-stop slot may change on the first terminal stop. All native Test,
// Block, journal, audit and artifact bytes remain part of the comparison.
func orderedRetirementWithoutStop(t *testing.T, raw []byte) []byte {
	t.Helper()
	var snapshot struct {
		Native    []json.RawMessage
		Artifacts map[string][32]byte
	}
	if json.Unmarshal(raw, &snapshot) != nil || len(snapshot.Native) != 21 || len(snapshot.Artifacts) != 2 {
		t.Fatal("retirement evidence shape changed")
	}
	snapshot.Native[11] = json.RawMessage(`null`)
	result, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal("retirement evidence encoding")
	}
	return result
}

func assertOrdered69RawRetirement(c ordered68ApprovedTestContext, directory string, message, stop json.RawMessage) {
	t, ctx := c.t, c.ctx
	t.Helper()
	before := orderedPostRecoveryEvidence(c, directory)
	for _, principal := range []struct{ login, role string }{
		{c.forwardLogin, "zasp_temporal_executor"},
		{"temporal_compensation_test_login", "zasp_temporal_compensation"},
	} {
		func() {
			cfg := c.owner.Config().Copy()
			cfg.User = principal.login
			bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			conn, err := pgx.ConnectConfig(bounded, cfg)
			if err != nil {
				t.Fatal("retirement registered principal connection", principal.role, ordered68ErrorClass(err))
			}
			defer func() {
				clean, done := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
				defer done()
				if err := conn.Close(clean); err != nil {
					t.Error("retirement principal close", ordered68ErrorClass(err))
				}
			}()
			var retained bool
			if err := conn.QueryRow(bounded, `SELECT session_user=$1 AND pg_has_role(session_user,$2,'USAGE') AND has_schema_privilege(session_user,'zasp_temporal69','USAGE') AND has_function_privilege(session_user,'zasp_temporal69.ready(text,text)','EXECUTE') AND has_function_privilege(session_user,'zasp_temporal69.principal_ready(text)','EXECUTE') AND zasp_temporal69.ready($3,$4) AND zasp_temporal69.principal_ready($2)`, principal.login, principal.role, migrations.ProductionTemporalWorkflow().Checksum(), migrations.TemporalWorkflowFingerprint()).Scan(&retained); err != nil || !retained {
				t.Fatal("retirement damaged retained ready/principal/schema privileges", principal.role, ordered68ErrorClass(err))
			}
			probes := []struct {
				signature, statement string
				request              json.RawMessage
			}{
				{"zasp_temporal69.inspect(jsonb)", `SELECT zasp_temporal69.inspect($1::jsonb)`, c.identity},
			}
			if principal.role == "zasp_temporal_executor" {
				probes = append(probes, struct {
					signature, statement string
					request              json.RawMessage
				}{"zasp_temporal69.inspect_message(jsonb)", `SELECT zasp_temporal69.inspect_message($1::jsonb)`, message})
			} else {
				probes = append(probes, struct {
					signature, statement string
					request              json.RawMessage
				}{"zasp_temporal69.stop(jsonb)", `SELECT zasp_temporal69.stop($1::jsonb)`, stop})
			}
			for _, probe := range probes {
				func() {
					callCtx, end := context.WithTimeout(ctx, 10*time.Second)
					defer end()
					var granted bool
					if err := conn.QueryRow(callCtx, `SELECT has_function_privilege(session_user,$1,'EXECUTE')`, probe.signature).Scan(&granted); err != nil {
						t.Fatal("retirement raw ACL query", ordered68ErrorClass(err))
					}
					tx, err := conn.BeginTx(callCtx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
					if err != nil {
						t.Fatal("retirement probe begin", ordered68ErrorClass(err))
					}
					var value json.RawMessage
					err = tx.QueryRow(callCtx, probe.statement, probe.request).Scan(&value)
					live := callCtx.Err() == nil
					ordered68Rollback(t, ctx, tx)
					var native *pgconn.PgError
					// A body's own42501 is insufficient: EXECUTE must also be
					// absent for this exact registered login and signature.
					if granted || !live || !errors.As(err, &native) || native.Code != "42501" {
						t.Errorf("raw69 retirement edge remains: role=%s function=%s granted=%t live=%t class=%s", principal.role, probe.signature, granted, live, ordered68ErrorClass(err))
					}
				}()
			}
		}()
	}
	if !bytes.Equal(before, orderedPostRecoveryEvidence(c, directory)) {
		t.Fatal("rollback raw probes changed settled evidence or durable artifacts")
	}
}
