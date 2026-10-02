package apiserver

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func orderedTestExpiredUnknown(t *testing.T, ctx context.Context, owner, worker, redWorker *pgx.Conn, o, w, e, r, s string, completed ...bool) {
	t.Helper()
	request := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": r, "step_id": s, "operation": "reconcile_uncertain", "worker_id": "ordered-test-reconciler", "run_version": 9, "effect_version": 1}
	raw, _ := json.Marshal(request)
	call := func(connection *pgx.Conn) (json.RawMessage, error) {
		database, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
		return (&securityAgentMultistepAdmissionRepository{database: database}).testReconcileUncertain(ctx, raw)
	}
	before := orderedTestSnapshot(t, ctx, owner, r)
	if _, err := call(worker); err == nil || orderedTestSnapshot(t, ctx, owner, r) != before {
		t.Fatal("reconciler closed live worker lease", err)
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_effects SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1 AND action_key='run_test';UPDATE zasp_red_team_runs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id IN(SELECT test_run_id FROM zasp_security_agent_test_links WHERE run_id=$1)`, pgx.QueryExecModeSimpleProtocol, r); err != nil {
		t.Fatal(err)
	}
	before = orderedTestSnapshot(t, ctx, owner, r)
	if _, err := call(redWorker); err == nil || orderedTestSnapshot(t, ctx, owner, r) != before {
		t.Fatal("stale invocation worker gained expiry reconciliation authority", err)
	}
	for _, mode := range []string{"effect_live", "child_live", "effect_input", "effect_token", "child_cancel", "control", "approval", "stopped", "cancelled", "readiness"} {
		t.Run(mode, func(t *testing.T) {
			fault := map[string]string{
				"effect_live":  `UPDATE zasp_security_agent_effects SET lease_expires_at=clock_timestamp()+interval '1 minute' WHERE run_id=$1 AND action_key='run_test'`,
				"child_live":   `UPDATE zasp_red_team_runs SET lease_expires_at=clock_timestamp()+interval '1 minute' WHERE run_id IN(SELECT test_run_id FROM zasp_security_agent_test_links WHERE run_id=$1)`,
				"effect_input": `UPDATE zasp_security_agent_effects SET input_digest=decode(repeat('ab',32),'hex') WHERE run_id=$1 AND action_key='run_test'`,
				"effect_token": `UPDATE zasp_security_agent_effects SET lease_token=repeat('b',32) WHERE run_id=$1 AND action_key='run_test'`,
				"child_cancel": `UPDATE zasp_red_team_runs SET cancel_requested=true WHERE run_id IN(SELECT test_run_id FROM zasp_security_agent_test_links WHERE run_id=$1)`,
				"control":      `UPDATE zasp_security_agent_controls SET state='disabled' WHERE run_id=$1`,
				"approval":     `UPDATE zasp_security_agent_approvals SET expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1`,
				"stopped":      `UPDATE zasp_security_agent_run_budgets SET stop_reason='budget_usage_unknown' WHERE run_id=$1`,
				"cancelled":    `UPDATE zasp_security_agent_runs SET state='cancelled' WHERE run_id=$1`,
				"readiness":    `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_security_agent_multistep_checksum' AND $1::text IS NOT NULL`,
			}[mode]
			if _, err := owner.Exec(ctx, `BEGIN`); err != nil {
				t.Fatal(err)
			}
			defer owner.Exec(ctx, `ROLLBACK`)
			if _, err := owner.Exec(ctx, fault, r); err != nil {
				t.Fatal(err)
			}
			before := orderedTestSnapshot(t, ctx, owner, r)
			if _, err := owner.Exec(ctx, `SAVEPOINT attempt; SET SESSION AUTHORIZATION `+pgx.Identifier{worker.Config().User}.Sanitize()); err != nil {
				t.Fatal(err)
			}
			_, callErr := call(owner)
			if _, err := owner.Exec(ctx, `ROLLBACK TO SAVEPOINT attempt`); err != nil {
				t.Fatal(err)
			}
			if callErr == nil || orderedTestSnapshot(t, ctx, owner, r) != before {
				t.Fatal("expired reconciliation accepted current drift", mode, callErr)
			}
			if _, err := owner.Exec(ctx, `ROLLBACK`); err != nil {
				t.Fatal(err)
			}
		})
	}
	result, err := call(worker)
	if err != nil {
		var direct json.RawMessage
		directErr := worker.QueryRow(ctx, `SELECT zasp_sa_multistep_prior.test_reconcile_uncertain($1,$2,$3::jsonb)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint(), raw).Scan(&direct)
		t.Fatal("expiry boundary refused", err, "direct SQL", directErr, string(direct))
	}
	var got map[string]any
	journalState, reason, journalRows := "started", "test_outcome_unknown", 1
	if len(completed) > 0 && completed[0] {
		journalState, reason, journalRows = "completed_unsettled", "test_evidence_unsettled", 2
	}
	if err != nil || json.Unmarshal(result, &got) != nil || got["run_state"] != "needs_human" || got["step_state"] != "inconclusive" || got["effect_state"] != "unknown_outcome" || got["receipt_created"] != false || got["operation"] != "reconcile_uncertain" || got["journal_state"] != journalState || got["reason"] != reason {
		t.Fatal("expired started journal has no deterministic conservative close", string(result), err)
	}
	before = orderedTestSnapshot(t, ctx, owner, r)
	replay, err := call(worker)
	if err != nil || string(replay) != string(result) || orderedTestSnapshot(t, ctx, owner, r) != before {
		t.Fatal("expiry reconciliation replay changed authority", string(replay), err)
	}
	orderedTestTerminalReplayRefusals(t, ctx, owner, r, s, raw, false, true)
	assertOrderedApplicationCounts(t, ctx, owner, r, 2, 2, 1, 2)
	var preserved bool
	journalValue := "started"
	if journalRows == 2 {
		journalValue = "completed"
	}
	if err = owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_security_agent_controls WHERE run_id=$1 AND state='active') AND EXISTS(SELECT 1 FROM zasp_security_agent_effects WHERE run_id=$1 AND action_key='create_temporary_policy' AND state='cleanup_pending') AND (SELECT count(*) FROM zasp_security_agent_test_invocations WHERE test_run_id IN(SELECT test_run_id FROM zasp_security_agent_test_links WHERE run_id=$1) AND state=$2)=$3 AND EXISTS(SELECT 1 FROM zasp_red_team_runs WHERE run_id IN(SELECT test_run_id FROM zasp_security_agent_test_links WHERE run_id=$1) AND state='failed' AND error_code='outcome_unknown')`, r, journalValue, journalRows).Scan(&preserved); err != nil || !preserved {
		t.Fatal("expiry reconciliation lost unknown journal or cleanup", preserved, err)
	}
	if err = owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_security_agent_runs WHERE run_id=$1 AND last_error_code=$2) AND (SELECT count(*) FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind='ordered_test_expired' AND body->'response'->>'reason'=$2 AND body->'response'->>'journal_state'=$3 AND body->'response'=$4::jsonb AND event_digest=digest(convert_to(body::text,'UTF8'),'sha256'))=1`, r, reason, journalState, result).Scan(&preserved); err != nil || !preserved {
		t.Fatal("expiry reason lost from immutable audit", preserved, err)
	}
}

func orderedTestExpiryWait(t *testing.T, ctx context.Context, owner, worker, redWorker *pgx.Conn, store artifactstore.ObjectReferencingArtifactStore, o, w, e, r, s, mode string, settlement json.RawMessage, completed ...bool) {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": r, "step_id": s, "operation": "reconcile_uncertain", "worker_id": "ordered-test-reconciler", "run_version": 9, "effect_version": 1})
	if mode != "expiry_settlement" {
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_effects SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1 AND action_key='run_test';UPDATE zasp_red_team_runs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id IN(SELECT test_run_id FROM zasp_security_agent_test_links WHERE run_id=$1)`, pgx.QueryExecModeSimpleProtocol, r); err != nil {
			t.Fatal(err)
		}
	}
	blocker, err := pgx.ConnectConfig(ctx, owner.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close(ctx)
	if _, err = blocker.Exec(ctx, `BEGIN;SELECT pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||$1,0))`, pgx.QueryExecModeSimpleProtocol, o); err != nil {
		t.Fatal(err)
	}
	defer blocker.Exec(ctx, `ROLLBACK`)
	database, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
	done := make(chan error, 1)
	go func() {
		_, err := (&securityAgentMultistepAdmissionRepository{database: database}).testReconcileUncertain(ctx, raw)
		done <- err
	}()
	joined := false
	defer func() {
		if !joined {
			blocker.Exec(ctx, `ROLLBACK`)
			<-done
		}
	}()
	waitOrderedProgressionBlocked(t, ctx, blocker, worker)
	var stale chan error
	staleJoined := false
	defer func() {
		if stale != nil && !staleJoined {
			blocker.Exec(ctx, `ROLLBACK`)
			<-stale
		}
	}()
	if mode == "expiry_race" {
		stale = make(chan error, 1)
		request, _ := json.Marshal(orderedTestActionRequest(o, w, e, r, s, "uncertain", 9, 1))
		redDB, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: redWorker})
		go func() {
			var err error
			if len(completed) > 0 && completed[0] {
				_, err = (&securityAgentMultistepAdmissionRepository{database: redDB}).testSettle(ctx, settlement, store)
			} else {
				_, err = (&securityAgentMultistepAdmissionRepository{database: redDB}).testUncertain(ctx, request)
			}
			stale <- err
		}()
		waitOrderedProgressionBlocked(t, ctx, blocker, redWorker)
	}
	switch mode {
	case "expiry_stop":
		_, err = blocker.Exec(ctx, `UPDATE zasp_security_agent_run_budgets SET stop_reason='budget_usage_unknown' WHERE run_id=$1`, r)
	case "expiry_cancel":
		if _, err = blocker.Exec(ctx, `SET SESSION AUTHORIZATION security_agent_v33_api_login`); err == nil {
			request := orderedProgressionRequest(o, w, e, r, s, "cancel", orderedProgressionApprover, 9)
			request["approval_version"] = 2
			body, _ := json.Marshal(request)
			db, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: blocker})
			_, err = (&securityAgentMultistepAdmissionRepository{database: db}).transition(ctx, body)
		}
	case "expiry_settlement":
		if _, err = blocker.Exec(ctx, `SET SESSION AUTHORIZATION ordered_test_red_worker`); err == nil {
			db, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: blocker})
			_, err = (&securityAgentMultistepAdmissionRepository{database: db}).testSettle(ctx, settlement, store)
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err = blocker.Exec(ctx, `COMMIT`); err != nil {
		t.Fatal(err)
	}
	callErr := <-done
	joined = true
	if mode == "expiry_race" {
		oldErr := <-stale
		staleJoined = true
		if callErr != nil || oldErr == nil {
			t.Fatal("expired reconciler/stale worker race", callErr, oldErr)
		}
		var exact bool
		if err = owner.QueryRow(ctx, `SELECT r.state='needs_human' AND s.state='inconclusive' AND f.state='unknown_outcome' AND (SELECT count(*) FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind='ordered_test_expired')=1 FROM zasp_security_agent_runs r JOIN zasp_security_agent_steps s USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_security_agent_effects f USING(organization_id,workspace_id,environment_id,run_id,step_id) WHERE r.run_id=$1 AND s.step_id=$2`, r, s).Scan(&exact); err != nil || !exact {
			t.Fatal("expiry race did not close once", exact, err)
		}
	} else if callErr == nil {
		t.Fatal("reconciler ignored winning current authority", mode)
	}
	receipts := 1
	if mode == "expiry_settlement" {
		receipts = 2
	}
	assertOrderedApplicationCounts(t, ctx, owner, r, 2, 2, receipts, 2)
	if mode == "expiry_stop" || mode == "expiry_cancel" {
		var intact bool
		if err = owner.QueryRow(ctx, `SELECT s.state='executing' AND s.version=4 AND f.state='leased' AND f.version=1 AND c.state='leased' FROM zasp_security_agent_steps s JOIN zasp_security_agent_effects f USING(organization_id,workspace_id,environment_id,run_id,step_id) JOIN zasp_security_agent_test_links l USING(organization_id,workspace_id,environment_id,run_id,step_id) JOIN zasp_red_team_runs c ON(c.organization_id,c.workspace_id,c.environment_id,c.run_id)=(l.organization_id,l.workspace_id,l.environment_id,l.test_run_id) WHERE s.run_id=$1 AND s.step_id=$2`, r, s).Scan(&intact); err != nil || !intact {
			t.Fatal("stopped expiry wrote descendants", intact, err)
		}
	}
}
