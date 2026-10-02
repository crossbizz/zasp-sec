package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

func installTemporalOutbox(t *testing.T, ctx context.Context, owner *pgx.Conn) {
	t.Helper()
	runner := precisionMigrationRunner(t, owner)
	version, err := runner.Version(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for index, up := range []func(context.Context) error{runner.UpProductionSecurityAgentWebhooks, runner.UpProductionDiscoveryScheduleReplay} {
		if version < int64(59+index) {
			if err := up(ctx); err != nil {
				t.Fatal(err)
			}
		}
	}
	if version == 61 {
		if err := runner.UpProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
	}
	extension, ok := any(runner).(interface{ UpProductionTemporalOutbox(context.Context) error })
	if !ok {
		t.Fatal("transactional Temporal outbox migration missing")
	}
	if err := extension.UpProductionTemporalOutbox(ctx); err != nil {
		tx, txErr := owner.Begin(ctx)
		if txErr != nil {
			t.Fatal(txErr)
		}
		defer tx.Rollback(ctx)
		_, ddlErr := tx.Exec(ctx, migrations.ProductionTemporalOutbox().UpSQL())
		var fp string
		fpErr := tx.QueryRow(ctx, `SELECT zasp_temporal65.fingerprint()`).Scan(&fp)
		t.Fatalf("outbox install=%v DDL=%v fingerprint=%s query=%v", err, ddlErr, fp, fpErr)
	}
}

type stuckTenantEngine struct {
	organization string
	slow         bool
	expire       context.CancelCauseFunc
}

func (e *stuckTenantEngine) Start(ctx context.Context, r orchestration.StartRequest) error {
	if r.Ref.OrganizationID != e.organization {
		return nil
	}
	if e.slow {
		// Expire the poll only after SQL selection and its durable attempt
		// have completed. The unit test also covers an actual timer deadline.
		e.expire(context.DeadlineExceeded)
		<-ctx.Done()
		return orchestration.ErrUnavailable
	}
	return orchestration.ErrConflict
}
func (e *stuckTenantEngine) Notify(context.Context, orchestration.Message) error { return nil }

func TestTemporalOutboxFairPollingPostgres(t *testing.T) {
	for _, slow := range []bool{false, true} {
		t.Run(fmt.Sprintf("deadline_%t", slow), func(t *testing.T) {
			runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
				installTemporalOutbox(t, ctx, owner)
				prefix := 100
				if slow {
					prefix = 2
				}
				healthyOrg := "pid_6a000009-0000-4000-8000-000000000009"
				healthyRun := fmt.Sprintf("pid_9f000001-0000-4000-8000-%012d", prefix+1)
				// Delivery-only fixture: seed valid retained queue/run rows directly. The
				// other tests exercise admission and decisions through their real APIs.
				for i := 1; i <= prefix+1; i++ {
					org := o
					if i > prefix {
						org = healthyOrg
					}
					run := fmt.Sprintf("pid_9f000001-0000-4000-8000-%012d", i)
					if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state) VALUES($1,$2,$3,$4,$4,1,$4,$5,'queued'); INSERT INTO zasp_temporal65.commands(organization_id,workspace_id,environment_id,run_id,event_id,kind,definition_version,input_digest,execution_owner,created_at) VALUES($1,$2,$3,$4,$4,'start',1,repeat('a',64),'temporal',clock_timestamp()-interval '1 hour'+$6::int*interval '1 millisecond')`, pgx.QueryExecModeSimpleProtocol, org, w, e, run, actor, i); err != nil {
						t.Fatal(err)
					}
				}
				database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
				if err != nil {
					t.Fatal(err)
				}
				store := orchestration.SQLStore{Database: database, Timeout: time.Second}
				engine := &stuckTenantEngine{organization: o, slow: slow}
				relay := orchestration.Relay{Store: store, Engine: engine}
				for poll := 0; poll < 3; poll++ {
					pollCtx := ctx
					cancel := func() {}
					if slow {
						bounded, stop := context.WithTimeout(ctx, 5*time.Second)
						pollCtx, engine.expire = context.WithCancelCause(bounded)
						cancel = func() { engine.expire(nil); stop() }
					}
					err = relay.RunOnce(pollCtx)
					cancel()
					if err == nil {
						t.Fatal("failed prefix reported complete acceptance")
					}
					if slow && poll < prefix {
						var attempted, accepted int
						if err := owner.QueryRow(ctx, `SELECT count(*) FILTER(WHERE last_attempt_at IS NOT NULL),count(*) FILTER(WHERE accepted_at IS NOT NULL) FROM zasp_temporal65.commands`).Scan(&attempted, &accepted); err != nil || attempted != poll+1 || accepted != 0 {
							t.Fatalf("failed RPC lost its durable turn or acknowledged: attempted=%d accepted=%d err=%v", attempted, accepted, err)
						}
					}
				}
				var accepted, retained int
				if err = owner.QueryRow(ctx, `SELECT count(*) FILTER(WHERE accepted_at IS NOT NULL),count(*) FILTER(WHERE accepted_at IS NULL) FROM zasp_temporal65.commands`).Scan(&accepted, &retained); err != nil || accepted != 1 || retained != prefix {
					var turns string
					_ = owner.QueryRow(ctx, `SELECT jsonb_agg(jsonb_build_object('run',run_id,'attempted',last_attempt_at IS NOT NULL,'accepted',accepted_at IS NOT NULL) ORDER BY run_id)::text FROM zasp_temporal65.commands`).Scan(&turns)
					t.Log("retained delivery turns", turns)
					t.Fatalf("healthy later tenant starved or failed evidence lost: accepted=%d retained=%d err=%v", accepted, retained, err)
				}
				var healthy bool
				if err = owner.QueryRow(ctx, `SELECT accepted_at IS NOT NULL FROM zasp_temporal65.commands WHERE (organization_id,run_id)=($1,$2)`, healthyOrg, healthyRun).Scan(&healthy); err != nil || !healthy {
					t.Fatal("wrong tenant accepted", err)
				}
			})
		})
	}
}

// Catch a commit gap, duplicate commands on replay, and accepting a different
// intent under the original business key. All admission writes use the API role.
func TestTemporalOutboxManualAtomicPostgres(t *testing.T) {
	runManualAdmissionFixture(t, "create_evidence_export", func(ctx context.Context, owner, api *pgx.Conn, o, w, e, _, actor, definition string, version int64) {
		installTemporalOutbox(t, ctx, owner)
		const r = "pid_8e190001-0000-4000-8000-000000000001"
		const a = "pid_8e190003-0000-4000-8000-000000000003"
		const receipt = "pid_8e190005-0000-4000-8000-000000000005"
		invoke := func(v int64) ([]byte, error) {
			var raw []byte
			err := api.QueryRow(ctx, postgresSecurityAgentManualRunSQL, o, w, e, definition, actor, "temporal-manual-0001", v, r, a, a, receipt, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&raw)
			return raw, err
		}
		if _, err := api.Exec(ctx, "BEGIN"); err != nil {
			t.Fatal(err)
		}
		if _, err := invoke(version); err != nil {
			t.Fatal(err)
		}
		if _, err := api.Exec(ctx, "ROLLBACK"); err != nil {
			t.Fatal(err)
		}
		var count int
		if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_temporal65.commands)+(SELECT count(*) FROM zasp_security_agent_runs WHERE run_id=$1)`, r).Scan(&count); err != nil || count != 0 {
			t.Fatal("rollback leaked admission", count, err)
		}
		original, err := invoke(version)
		if err != nil {
			t.Fatal(err)
		}
		replay, err := invoke(version)
		if err != nil {
			t.Fatal(err)
		}
		var first, second map[string]any
		_ = json.Unmarshal(original, &first)
		_ = json.Unmarshal(replay, &second)
		if first["receipt_id"] != second["receipt_id"] || second["replayed"] != true {
			t.Fatal("replay receipt changed")
		}
		if _, err := invoke(version + 1); err == nil {
			t.Fatal("conflicting business key accepted")
		}
		if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_temporal65.commands WHERE (organization_id,workspace_id,environment_id,run_id,kind,execution_owner)=($1,$2,$3,$4,'start','legacy') AND input_digest=(SELECT encode(intent_digest,'hex') FROM zasp_security_agent_request_receipts WHERE receipt_id=$5)`, o, w, e, r, receipt).Scan(&count); err != nil || count != 1 {
			t.Fatal("admission command not singular/bound", count, err)
		}
		const decision = "pid_8e190006-0000-4000-8000-000000000006"
		for i := 0; i < 2; i++ {
			var raw []byte
			if err := api.QueryRow(ctx, postgresSecurityAgentCancelRunSQL, o, w, e, r, actor, "temporal-manual-cancel", 1, decision, decision, decision).Scan(&raw); err != nil {
				t.Fatal("legacy cancellation", err)
			}
		}
		if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_temporal65.commands WHERE kind='cancel' AND decision_id=$1`, decision).Scan(&count); err != nil || count != 1 {
			t.Fatal("legacy decision not singular", count, err)
		}
	})
}

func TestTemporalOutboxOrderedAtomicPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		installTemporalOutbox(t, ctx, owner)
		public62Seed(t, ctx, owner, o, w, e, testID, actor)
		q := public62Request(o, w, e, actor, "activate")
		q["definition_id"], q["definition_version"] = public62Definition, 1
		if _, err := public62Call(ctx, api, q); err != nil {
			t.Fatal(err)
		}
		q = public62Request(o, w, e, actor, "trigger_resource")
		q["definition_id"], q["definition_version"], q["trigger_id"], q["trigger_version"], q["idempotency_key"] = public62Definition, 2, public62Finding, 1, "temporal-ordered-0001"
		q["trigger_kind"], q["trigger_source"] = "finding", "excessive_permissions"
		// Resolve the source from the seeded definition; the authority still checks it.
		var qSource string
		if err := owner.QueryRow(ctx, `SELECT body->>'trigger_source' FROM zasp_security_agent_definitions WHERE definition_id=$1`, public62Definition).Scan(&qSource); err != nil {
			t.Fatal(err)
		}
		q["trigger_source"] = qSource
		first, err := public62Call(ctx, api, q)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = public62Call(ctx, api, q); err != nil {
			t.Fatal(err)
		}
		var r string
		var count int
		if err = owner.QueryRow(ctx, `SELECT run_id FROM zasp_temporal65.commands WHERE kind='start'`).Scan(&r); err != nil {
			t.Fatal(err, first)
		}
		if err = owner.QueryRow(ctx, `SELECT count(*) FROM zasp_temporal65.commands`).Scan(&count); err != nil || count != 1 {
			t.Fatal("nested admission duplicated", count, err)
		}
		cancel := public62Request(o, w, e, actor, "cancel")
		cancel["run_id"], cancel["run_version"], cancel["idempotency_key"] = r, 1, "temporal-cancel-0001"
		result, err := public62Call(ctx, api, cancel)
		if err != nil {
			t.Fatal(err)
		}
		if result["outcome"] != "cancelled-request" {
			t.Fatal("cancellation claimed completion", result)
		}
		if err = owner.QueryRow(ctx, `SELECT count(*) FROM zasp_temporal65.commands c JOIN zasp_security_agent_request_receipts r ON (c.organization_id,c.workspace_id,c.environment_id,c.decision_id)=(r.organization_id,r.workspace_id,r.environment_id,r.receipt_id) WHERE c.kind='cancel' AND c.run_id=$1 AND r.operation='cancelSecurityAgentRun'`, r).Scan(&count); err != nil || count != 1 {
			t.Fatal("cancel missing committed decision", count, err)
		}
		verifyTemporalDeliverySQL(t, ctx, owner, worker, o, w, e, r)
	})
}

type temporalAcceptanceFixture struct {
	unavailable bool
	starts      int
	messages    int
}

func (f *temporalAcceptanceFixture) Start(context.Context, orchestration.StartRequest) error {
	f.starts++
	if f.unavailable {
		return errors.New("service offline")
	}
	return nil
}
func (f *temporalAcceptanceFixture) Notify(context.Context, orchestration.Message) error {
	f.messages++
	return nil
}
func verifyTemporalDeliverySQL(t *testing.T, ctx context.Context, owner, worker *pgx.Conn, o, w, e, r string) {
	t.Helper()
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
	if err != nil {
		t.Fatal(err)
	}
	store := orchestration.SQLStore{Database: database, Timeout: time.Second}
	if commands, err := store.Pending(ctx); err != nil || len(commands) != 0 {
		t.Fatal("staged owner dispatched", commands, err)
	}
	// Owner-only fixture simulates P3's future selector fence. Neither runtime
	// role has table writes or an owner-change function in this packet.
	if _, err = owner.Exec(ctx, `UPDATE zasp_temporal65.commands SET execution_owner='temporal' WHERE run_id=$1`, r); err != nil {
		t.Fatal(err)
	}
	commands, err := store.Pending(ctx)
	if err != nil || len(commands) != 1 || commands[0].Kind != "start" {
		t.Fatal("decision overtook admission", commands, err)
	}
	wrong := commands[0]
	wrong.Ref.EnvironmentID = wrong.Ref.WorkspaceID
	if err = store.Ack(ctx, wrong); err == nil {
		t.Fatal("tenant mismatched acknowledgement accepted")
	}
	if err = store.Attempt(ctx, wrong); err == nil {
		t.Fatal("tenant mismatched polling turn accepted")
	}
	engine := &temporalAcceptanceFixture{unavailable: true}
	relay := orchestration.Relay{Store: store, Engine: engine}
	if err = relay.RunOnce(ctx); err == nil {
		t.Fatal("unavailable service reported acceptance")
	}
	commands, err = store.Pending(ctx)
	if err != nil || len(commands) != 1 {
		t.Fatal("unavailable service lost command", err)
	}
	engine.unavailable = false
	if err = relay.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if err = store.Ack(ctx, commands[0]); err != nil {
		t.Fatal("idempotent ack failed", err)
	}
	if err = relay.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if commands, err = store.Pending(ctx); err != nil || len(commands) != 0 || engine.messages != 1 {
		t.Fatal("decision delivery failed", commands, err)
	}
	var state string
	if err = owner.QueryRow(ctx, `SELECT state FROM zasp_security_agent_runs WHERE run_id=$1`, r).Scan(&state); err != nil || state != "cancelled" {
		t.Fatal("ack changed product outcome", state, err)
	}
}

func TestTemporalOutboxApprovalAtomicPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		installTemporalOutbox(t, ctx, owner)
		r, steps := public62PlannedRun(t, ctx, owner, api, o, w, e, testID, actor)
		var approval string
		if err := owner.QueryRow(ctx, `SELECT approval_id FROM zasp_security_agent_approvals WHERE run_id=$1 AND step_id=$2`, r, steps[0]).Scan(&approval); err != nil {
			t.Fatal(err)
		}
		q := public62Request(o, w, e, orderedProgressionApprover, "decide_resource")
		q["approval_id"], q["approval_version"], q["decision"], q["fresh_auth_at"], q["idempotency_key"] = approval, 1, "approved", time.Now().UTC().Format(time.RFC3339Nano), "temporal-approval-0001"
		if _, err := api.Exec(ctx, "BEGIN"); err != nil {
			t.Fatal(err)
		}
		if _, err := public62Call(ctx, api, q); err != nil {
			t.Fatal(err)
		}
		if _, err := api.Exec(ctx, "ROLLBACK"); err != nil {
			t.Fatal(err)
		}
		var count int
		if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_temporal65.commands WHERE kind='approval'`).Scan(&count); err != nil || count != 0 {
			t.Fatal("decision rollback leaked command", count, err)
		}
		for i := 0; i < 2; i++ {
			if _, err := public62Call(ctx, api, q); err != nil {
				t.Fatal(err)
			}
		}
		if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_temporal65.commands c JOIN zasp_security_agent_request_receipts d ON (c.organization_id,c.workspace_id,c.environment_id,c.decision_id)=(d.organization_id,d.workspace_id,d.environment_id,d.receipt_id) WHERE c.kind='approval' AND c.run_id=$1 AND d.operation='decideSecurityAgentApproval'`, r).Scan(&count); err != nil || count != 1 {
			t.Fatal("approval missing committed decision", count, err)
		}
	})
}
