package apiserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func assertTemporalTestCancelledDelivery(t *testing.T, ctx context.Context, owner, api, executor, delivery *pgx.Conn, repository *PostgresRepository, identity RequestIdentity, testID, firstRun string, selection map[string]any) {
	t.Helper()
	o, w, e := identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String()
	const foreignOrg = "pid_9d740000-0000-4000-8000-000000000001"
	const foreignWorkspace = "pid_9d740000-0000-4000-8000-000000000002"
	const foreignEnvironment = "pid_9d740000-0000-4000-8000-000000000003"
	if _, err := owner.Exec(ctx, `INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role) VALUES($4,$1,'test74-cancel-other','test74-cancel-manager','organization_admin'); INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($4,$1,$2,$3,'Other manager','["view","manage_workflows","run_tests"]')`, pgx.QueryExecModeSimpleProtocol, foreignOrg, foreignWorkspace, foreignEnvironment, identity.PrincipalID.String()); err != nil {
		t.Fatal(err)
	}
	foreign := identity
	fo, _ := domain.ParseProductID(foreignOrg)
	fw, _ := domain.ParseProductID(foreignWorkspace)
	fe, _ := domain.ParseProductID(foreignEnvironment)
	foreign.Scope, _ = domain.NewScope(fo, fw, fe)
	cfg := owner.Config().Copy()
	cfg.User = "temporal_test_compensation_login"
	comp, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer comp.Close(ctx)
	call := func(c *pgx.Conn, sql string, q any) (map[string]any, error) {
		raw, _ := json.Marshal(q)
		var encoded []byte
		err := c.QueryRow(ctx, sql, raw).Scan(&encoded)
		var v map[string]any
		if err == nil {
			err = json.Unmarshal(encoded, &v)
		}
		return v, err
	}
	// Cancellation can commit after untouched transfer, before the start relay
	// records acceptance or any planning job exists. It must remain deliverable.
	var earlyDigest string
	var earlyVersion int64
	if err := owner.QueryRow(ctx, `SELECT x.input_digest,r.version FROM zasp_temporal74.run_owners x JOIN zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id) WHERE x.run_id=$1`, firstRun).Scan(&earlyDigest, &earlyVersion); err != nil {
		t.Fatal(err)
	}
	if result, err := repository.CancelSecurityAgentRun(ctx, identity, SecurityAgentCancelRequest{RunID: firstRun, ExpectedVersion: earlyVersion, IdempotencyKey: "test74-before-start-cancel", AuditID: "pid_f0740000-0000-4000-8000-000000000911", CorrelationID: "pid_f0740000-0000-4000-8000-000000000912", ReceiptID: "pid_f0740000-0000-4000-8000-000000000913"}); err != nil || result.State != "cancelled" {
		t.Fatal("prestart actual API cancellation", result, err)
	}
	var raw json.RawMessage
	if err := executor.QueryRow(ctx, `SELECT zasp_temporal74.pending_controls()`).Scan(&raw); err != nil || string(raw) != "[]" {
		t.Fatal("decision bypassed original start acceptance", string(raw), err)
	}
	earlyStart := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": firstRun, "definition_version": 1, "input_digest": earlyDigest, "reason": "workflow_cancelled"}
	if result, err := call(comp, `SELECT zasp_temporal74.cleanup($1::jsonb)`, earlyStart); err != nil || result["pending"] != false {
		t.Fatal("actual prestart cancellation cleanup", result, err)
	}
	delete(earlyStart, "reason")
	if _, err := call(executor, `SELECT zasp_temporal74.accept_start($1::jsonb)`, earlyStart); err != nil {
		t.Fatal(err)
	}
	if err := executor.QueryRow(ctx, `SELECT zasp_temporal74.pending_controls()`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var earlyControls []struct {
		ID       string `json:"control_id"`
		Terminal bool   `json:"terminal"`
	}
	if json.Unmarshal(raw, &earlyControls) != nil || len(earlyControls) != 1 || !earlyControls[0].Terminal {
		t.Fatal("verified queued cancellation delivery", string(raw))
	}
	earlyStart["control_id"] = earlyControls[0].ID
	if _, err := call(executor, `SELECT zasp_temporal74.accept_control($1::jsonb)`, earlyStart); err != nil {
		t.Fatal(err)
	}
	var empty bool
	if err := owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_temporal74.planning_jobs WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_temporal74.effects WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_temporal74.provider_reservations WHERE run_id=$1) AND NOT zasp_temporal74.unresolved($2,$3,$4,$1)`, firstRun, o, w, e).Scan(&empty); err != nil || !empty {
		t.Fatal("prestart cancel manufactured work/debt", empty, err)
	}
	firstRun = "pid_f0740000-0000-4000-8000-000000000921"
	if _, err := repository.runSecurityAgentManual(ctx, identity, SecurityAgentRunRequest{DefinitionID: public62Definition, ExpectedVersion: 1, IdempotencyKey: "test74-reserved-cancellation", RunID: firstRun, AuditID: "pid_f0740000-0000-4000-8000-000000000922", CorrelationID: "pid_f0740000-0000-4000-8000-000000000923", ReceiptID: "pid_f0740000-0000-4000-8000-000000000924", TriggerKind: "manual"}); err != nil {
		t.Fatal(err)
	}
	if err := executor.QueryRow(ctx, `SELECT zasp_temporal74.takeover($1,$2,$3,$4)`, o, w, e, firstRun).Scan(&raw); err != nil || string(raw) == "null" {
		t.Fatal(err)
	}
	for _, phase := range []string{"reserved", "unknown"} {
		run := firstRun
		if phase == "unknown" {
			run = "pid_f0740000-0000-4000-8000-000000000501"
			if _, err := repository.runSecurityAgentManual(ctx, identity, SecurityAgentRunRequest{DefinitionID: public62Definition, ExpectedVersion: 1, IdempotencyKey: "test74-cancel-unknown", RunID: run, AuditID: "pid_f0740000-0000-4000-8000-000000000502", CorrelationID: "pid_f0740000-0000-4000-8000-000000000503", ReceiptID: "pid_f0740000-0000-4000-8000-000000000504", TriggerKind: "manual"}); err != nil {
				t.Fatal(err)
			}
			var raw []byte
			if err := executor.QueryRow(ctx, `SELECT zasp_temporal74.takeover($1,$2,$3,$4)`, o, w, e, run).Scan(&raw); err != nil {
				t.Fatal(err)
			}
		}
		assertTemporalTestPlanningPreparation(t, ctx, owner, executor, o, w, e, run, testID, identity.PrincipalID.String(), selection)
		var step, child, digest string
		if err := owner.QueryRow(ctx, `SELECT step_id,test_run_id,input_digest FROM zasp_temporal74.run_owners WHERE run_id=$1`, run).Scan(&step, &child, &digest); err != nil {
			t.Fatal(err)
		}
		q := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "step_id": step, "generation": 1, "operation": "reserve", "payload": map[string]any{}}
		reserved, err := call(executor, `SELECT zasp_temporal74.effect($1::jsonb)`, q)
		if err != nil {
			t.Fatal("cancel reserve", err)
		}
		start := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "definition_version": 1, "input_digest": digest}
		if _, err := call(executor, `SELECT zasp_temporal74.accept_start($1::jsonb)`, start); err != nil {
			t.Fatal(err)
		}
		{
			store, manifest := orderedTestInputArtifact(t, ctx, owner, o, w, e, run, step, child, testID, "run_test")
			id, _ := CanonicalDiscoveryID(identity.Scope, "security_agent_ordered_test_input", run+"\x1f"+step)
			body, err := orderedTestReadArtifact(ctx, store, identity.Scope, id, manifest, 65536)
			if err != nil {
				t.Fatal(err)
			}
			q["operation"], q["payload"] = "input", map[string]any{"manifest": manifest, "body": base64.StdEncoding.EncodeToString(body)}
			if _, err := call(executor, `SELECT zasp_temporal74.linked($1::jsonb)`, q); err != nil {
				t.Fatal(err)
			}
		}
		if phase == "unknown" {
			q["operation"], q["payload"] = "dispatch", map[string]any{}
			if v, err := call(executor, `SELECT zasp_temporal74.linked($1::jsonb)`, q); err != nil || v["send_permit"] != true {
				t.Fatal(v, err)
			}
			command := exec.CommandContext(ctx, "go", "test", "./redteamadapter", "-run", "^TestTemporalOwnedHTTPS$", "-count=1", "-v")
			command.Dir = ".."
			command.WaitDelay = 5 * time.Second
			command.Env = append(os.Environ(), "ZASP_TEST74_NATIVE=true", "ZASP_TEMPORAL_JOURNAL_OWNER_DSN="+owner.Config().ConnString(), "ZASP_TEMPORAL_JOURNAL_MODE=lost_start", "ZASP_ORDERED_ORG="+o, "ZASP_ORDERED_WORKSPACE="+w, "ZASP_ORDERED_ENVIRONMENT="+e, "ZASP_ORDERED_TEST_RUN="+child, "ZASP_TEMPORAL_EFFECT_KEY="+reserved["effect_key"].(string), "ZASP_TEMPORAL_CATEGORY=prompt_injection", "ZASP_TEMPORAL_TARGET=pid_89000011-0000-4000-8000-000000000001", "ZASP_TEMPORAL_KIND=agent_endpoint")
			output, err := command.CombinedOutput()
			t.Log(string(output))
			if err != nil || !strings.Contains(string(output), "provider_calls=0 credential_reads=0") {
				t.Fatal("actual lost-start no-resend", err)
			}
		}
		var parentVersion int64
		if err := owner.QueryRow(ctx, `SELECT version FROM zasp_security_agent_runs WHERE run_id=$1`, run).Scan(&parentVersion); err != nil {
			t.Fatal(err)
		}
		var ids [3]string
		for i, kind := range []string{"audit", "correlation", "receipt"} {
			if err := owner.QueryRow(ctx, `SELECT zasp_discovery_canonical_id($1,$2,$3,$4,$5)`, o, w, e, "test74-api-stop-"+kind, run).Scan(&ids[i]); err != nil {
				t.Fatal(err)
			}
		}
		cancelInput := SecurityAgentCancelRequest{RunID: run, ExpectedVersion: parentVersion, IdempotencyKey: "test74-api-stop-" + phase, AuditID: ids[0], CorrelationID: ids[1], ReceiptID: ids[2]}
		if _, err := repository.CancelSecurityAgentRun(ctx, foreign, cancelInput); err == nil {
			t.Fatal("foreign currently authorized manager cancelled source run")
		}
		stale := cancelInput
		stale.ExpectedVersion++
		if _, err := repository.CancelSecurityAgentRun(ctx, identity, stale); err == nil {
			t.Fatal("stale cancellation accepted")
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_authorized_scopes SET permissions='["view","run_tests"]' WHERE (organization_id,workspace_id,environment_id,principal_id)=($1,$2,$3,$4)`, o, w, e, identity.PrincipalID.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := repository.CancelSecurityAgentRun(ctx, identity, cancelInput); err == nil {
			t.Fatal("revoked manager cancellation accepted")
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_authorized_scopes SET permissions='["view","manage_identity","manage_workflows","run_tests"]' WHERE (organization_id,workspace_id,environment_id,principal_id)=($1,$2,$3,$4)`, o, w, e, identity.PrincipalID.String()); err != nil {
			t.Fatal(err)
		}
		if phase == "reserved" {
			locked, err := api.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer locked.Rollback(context.Background())
			if result, err := repository.CancelSecurityAgentRun(ctx, identity, cancelInput); err != nil || result.State != "cancelled" {
				t.Fatal("actual74 atomic API cancellation", result, err)
			}
			q["operation"], q["payload"] = "dispatch", map[string]any{}
			raceCtx, cancelRace := context.WithTimeout(ctx, 15*time.Second)
			result := make(chan error, 1)
			go func() { _, err := call(executor, `SELECT zasp_temporal74.linked($1::jsonb)`, q); result <- err }()
			blocked := false
			for !blocked && raceCtx.Err() == nil {
				if err := owner.QueryRow(raceCtx, `SELECT $1::integer=ANY(pg_blocking_pids($2::integer))`, int(api.PgConn().PID()), int(executor.PgConn().PID())).Scan(&blocked); err != nil {
					break
				}
				if !blocked {
					select {
					case err := <-result:
						locked.Rollback(ctx)
						cancelRace()
						t.Fatal("dispatch bypassed actual cancel transaction", err)
					case <-time.After(10 * time.Millisecond):
					}
				}
			}
			if !blocked {
				locked.Rollback(ctx)
				cancelRace()
				<-result
				t.Fatal("dispatch did not contend on cancellation lock")
			}
			if err := locked.Commit(ctx); err != nil {
				cancelRace()
				t.Fatal(err)
			}
			if err := <-result; err == nil {
				cancelRace()
				t.Fatal("dispatch sent after winning cancellation")
			}
			cancelRace()
		} else if result, err := repository.CancelSecurityAgentRun(ctx, identity, cancelInput); err != nil || result.State != "cancelled" {
			t.Fatal("actual74 API cancellation after uncertain dispatch", result, err)
		}
		if replay, err := repository.CancelSecurityAgentRun(ctx, identity, cancelInput); err != nil || !replay.Replayed || replay.ReceiptID != cancelInput.ReceiptID {
			t.Fatal("cancel immutable replay", replay, err)
		}
		if _, err := repository.CancelSecurityAgentRun(ctx, identity, stale); err == nil {
			t.Fatal("changed cancellation intent replay accepted")
		}
		var controlCount int
		if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_temporal74.control_intents WHERE run_id=$1`, run).Scan(&controlCount); err != nil || controlCount != 1 {
			t.Fatal("cancel control identity", controlCount, err)
		}
		q["operation"], q["payload"] = "reserve", map[string]any{}
		if _, err := call(executor, `SELECT zasp_temporal74.effect($1::jsonb)`, q); err == nil {
			t.Fatal("cancelled parent reopened pre-IO")
		}
		start["reason"] = "workflow_cancelled"
		stopped, err := call(comp, `SELECT zasp_temporal74.cleanup($1::jsonb)`, start)
		if err != nil || stopped["pending"] != (phase == "unknown") {
			t.Fatal("cancel proof", phase, stopped, err)
		}
		var message json.RawMessage
		if err := owner.QueryRow(ctx, `SELECT payload FROM zasp_red_team_outbox WHERE payload->>'run_id'=$1`, child).Scan(&message); err != nil {
			t.Fatal(err)
		}
		read := func() (map[string]any, error) {
			return call(delivery, `SELECT zasp_temporal74.delivery($1::jsonb)`, map[string]any{"operation": "read", "message": message})
		}
		decision, err := read()
		if err != nil || decision["terminal"] != (phase == "reserved") {
			t.Fatal("cancel delivery terminal proof", phase, decision, err)
		}
		if phase == "reserved" {
			if detail, err := repository.GetSecurityAgentRun(ctx, identity, run); err != nil || detail.Run.State != "cancelled" || len(detail.ActionDetails) != 1 || detail.ActionDetails[0].ExistingTest == nil || detail.ActionDetails[0].ExistingTest.Verification == nil || detail.ActionDetails[0].ExistingTest.Verification.Outcome != "cancelled" || detail.ActionDetails[0].ExistingTest.CancellationOutcome == nil || *detail.ActionDetails[0].ExistingTest.CancellationOutcome != "cancelled_before_execution" {
				t.Fatal("typed never-dispatched cancellation reload", detail, err)
			}
			var settlement json.RawMessage
			if err := owner.QueryRow(ctx, `SELECT reconcile_settlement FROM zasp_security_agent_test_links WHERE run_id=$1`, run).Scan(&settlement); err != nil {
				t.Fatal(err)
			}
			for _, broken := range []json.RawMessage{json.RawMessage(`null`), json.RawMessage(`{"kind":"stopped_before_dispatch","receipt":{"outcome":"remediated"}}`)} {
				if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_test_links SET reconcile_settlement=NULLIF($2::jsonb,'null'::jsonb) WHERE run_id=$1`, run, broken); err != nil {
					t.Fatal(err)
				}
				if _, err := read(); err == nil {
					t.Fatal("missing/tampered cancelled link receipt accepted")
				}
			}
			if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_test_links SET reconcile_settlement=$2::jsonb WHERE run_id=$1`, run, settlement); err != nil {
				t.Fatal(err)
			}
			var noSuccess bool
			if err := owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_temporal74.parent_receipts WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_temporal74.child_receipts WHERE run_id=$1) AND NOT zasp_temporal73.unresolved($2,$3,$4,$1) AND NOT zasp_temporal74.unresolved($2,$3,$4,$1)`, run, o, w, e).Scan(&noSuccess); err != nil || !noSuccess {
				t.Fatal("cancel invented native success or retained capacity", noSuccess, err)
			}
			var stop json.RawMessage
			if err := owner.QueryRow(ctx, `SELECT to_jsonb(s) FROM zasp_temporal74.stops s WHERE run_id=$1`, run).Scan(&stop); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.Exec(ctx, `ALTER TABLE zasp_temporal74.stops DISABLE TRIGGER immutable;DELETE FROM zasp_temporal74.stops WHERE run_id=$1;ALTER TABLE zasp_temporal74.stops ENABLE TRIGGER immutable`, pgx.QueryExecModeSimpleProtocol, run); err != nil {
				t.Fatal(err)
			}
			if value, err := read(); err == nil && value["terminal"] == true {
				t.Fatal("terminal status without stop proof accepted")
			}
			if _, err := owner.Exec(ctx, `INSERT INTO zasp_temporal74.stops SELECT * FROM jsonb_populate_record(NULL::zasp_temporal74.stops,$1::jsonb)`, stop); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.Exec(ctx, `UPDATE zasp_temporal74.effects SET started_at=clock_timestamp() WHERE run_id=$1`, run); err != nil {
				t.Fatal(err)
			}
			if _, err := read(); err == nil {
				t.Fatal("started effect accepted never-dispatched terminal proof")
			}
			if _, err := owner.Exec(ctx, `UPDATE zasp_temporal74.effects SET started_at=NULL WHERE run_id=$1`, run); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.Exec(ctx, `UPDATE zasp_temporal74.start_deliveries SET accepted_at=NULL WHERE run_id=$1`, run); err != nil {
				t.Fatal(err)
			}
			if _, err := read(); err == nil {
				t.Fatal("terminal delivery without durable original start accepted")
			}
			delete(start, "reason")
			if _, err := call(executor, `SELECT zasp_temporal74.accept_start($1::jsonb)`, start); err != nil {
				t.Fatal(err)
			}
		}
		command := exec.CommandContext(ctx, "go", "test", "./agentsec-worker", "-run", "^TestTemporalSingleTestCancelledDeliveryPostgres$", "-count=1", "-v")
		command.Dir = ".."
		command.WaitDelay = 5 * time.Second
		command.Env = append(os.Environ(), "ZASP_TEST74_OWNER_DSN="+owner.Config().ConnString(), "ZASP_TEST74_PARENT="+run, "ZASP_TEST74_CANCEL_TERMINAL="+phase)
		output, err := command.CombinedOutput()
		t.Log(string(output))
		if err != nil || strings.Contains(string(output), "--- SKIP:") {
			t.Fatal("actual cancelled delivery processor", err)
		}
	}
	for _, sql := range []string{`GRANT EXECUTE ON FUNCTION zasp_temporal74.delivery_parent_matches(jsonb) TO zasp_red_team_worker`, `ALTER FUNCTION zasp_temporal74.delivery_parent_matches(jsonb) SECURITY INVOKER`, `ALTER POLICY zasp_temporal74_owner ON public.zasp_security_agent_effects USING(true)`, `GRANT SELECT ON public.zasp_security_agent_effects TO zasp_red_team_worker`, `GRANT UPDATE ON public.zasp_security_agent_effects TO zasp_red_team_worker`, `GRANT SELECT(state) ON public.zasp_security_agent_effects TO zasp_red_team_worker WITH GRANT OPTION`, `CREATE ROLE test74_delivery_extra NOLOGIN; GRANT test74_delivery_extra TO zasp_red_team_worker`} {
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
		var ready bool
		err = tx.QueryRow(ctx, `SELECT zasp_temporal74.current_ready()`).Scan(&ready)
		tx.Rollback(ctx)
		if err != nil || ready {
			t.Fatal("delivery privilege/catalog drift accepted", sql, ready, err)
		}
	}
}
