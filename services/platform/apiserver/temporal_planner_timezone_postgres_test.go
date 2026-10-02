package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5"
)

// A worker replacement may use a different session timezone. Recovery must
// consume the original immutable receipt without rewriting its audit bytes,
// charging an unsent request, or acquiring a fresh send permit.
func TestTemporalPlannerTerminalCrossSessionPostgres(t *testing.T) {
	runTemporalExecutorPlanningFixture(t, nil, nil, func(ctx context.Context, owner, executor, api *pgx.Conn, o, w, e, run, testID string, selection map[string]any) {
		invoke := func(c *pgx.Conn, operation string, payload any) error {
			body, err := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "definition_version": 2, "operation": operation, "payload": payload})
			if err != nil {
				t.Fatal(err)
			}
			var result json.RawMessage
			return c.QueryRow(ctx, `SELECT zasp_temporal68.plan($1::jsonb)`, body).Scan(&result)
		}
		if err := invoke(executor, "prepare", map[string]any{"pricing": selection, "input_version": "timezone-owned-input-v1"}); err != nil {
			t.Fatal("prepare original unsent request", err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE principal_id=(SELECT requested_by FROM zasp_security_agent_runs WHERE run_id=$1)`, run); err != nil {
			t.Fatal(err)
		}
		connect := func(zone string) *pgx.Conn {
			config := owner.Config().Copy()
			config.User = "temporal_compensation_test_login"
			config.RuntimeParams["timezone"] = zone
			connection, err := pgx.ConnectConfig(ctx, config)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = connection.Close(context.Background()) })
			return connection
		}
		original := connect("America/Los_Angeles")
		if err := invoke(original, "reconcile", map[string]any{}); err != nil {
			t.Fatal("original captured recovery", err)
		}
		if err := invoke(original, "reconcile", map[string]any{}); err != nil {
			t.Fatal("same-session recovery positive control", err)
		}
		const evidence = `SELECT a.body::text,encode(a.event_digest,'hex'),a.event_digest=digest(convert_to(a.body::text,'UTF8'),'sha256'),
 p.released_at IS NOT NULL AND p.settled_at IS NULL AND p.output_digest IS NULL AND p.total_tokens IS NULL AND p.cost_nano_credits IS NULL,
 (SELECT count(*)=1 FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind='temporal_planning_terminal')
 FROM zasp_security_agent_audit a JOIN zasp_temporal68.provider_reservations p USING(organization_id,workspace_id,environment_id,run_id)
 WHERE a.run_id=$1 AND a.event_kind='temporal_planning_terminal'`
		readEvidence := func() (string, string) {
			var body, digest string
			var digestValid, noCharge, oneReceipt bool
			if err := owner.QueryRow(ctx, evidence, run).Scan(&body, &digest, &digestValid, &noCharge, &oneReceipt); err != nil || !digestValid || !noCharge || !oneReceipt {
				t.Fatal("immutable terminal accounting evidence", err)
			}
			return body, digest
		}
		beforeBody, beforeDigest := readEvidence()
		upgradePlannerTimezoneFixture(t, ctx, owner)
		replacement := connect("UTC")
		if err := invoke(replacement, "reconcile", map[string]any{}); err != nil {
			t.Error("replacement session rejected valid captured receipt after timezone change", err)
		}
		assertPlannerReceiptTimeComparisons(t, ctx, owner, run)
		assertPlannerNullAuditRejected(t, ctx, owner, run)
		afterBody, afterDigest := readEvidence()
		if beforeBody != afterBody || beforeDigest != afterDigest {
			t.Fatal("cross-session recovery rewrote original audit evidence")
		}
		if err := invoke(executor, "start", map[string]any{}); err == nil {
			t.Fatal("terminal recovery reopened provider send")
		}
		var ready bool
		if err := owner.QueryRow(ctx, `SELECT zasp_temporal68.current_ready()`).Scan(&ready); err != nil || !ready {
			t.Fatal("cross-session recovery changed installed catalog", err)
		}
	})
}

func upgradePlannerTimezoneFixture(t *testing.T, ctx context.Context, owner *pgx.Conn) {
	t.Helper()
	// Register the real discovery prerequisite through its existing operator
	// boundary. Historical bytes remain intact throughout the additive upgrade.
	if _, err := owner.Exec(ctx, `CREATE ROLE timezone_scheduler LOGIN INHERIT; CREATE ROLE timezone_risk LOGIN INHERIT; CREATE ROLE timezone_graph LOGIN INHERIT; CREATE ROLE timezone_search LOGIN INHERIT; SELECT zasp_execution_register_principals(session_user,'timezone_scheduler','security_agent_v33_discovery_worker_login','timezone_risk','timezone_graph','timezone_search')`); err != nil {
		t.Fatal("register discovery upgrade prerequisites", err)
	}
	runner := precisionMigrationRunner(t, owner)
	for _, stage := range []struct {
		name string
		up   func(context.Context) error
	}{
		{"workflow69", runner.UpProductionTemporalWorkflow},
		{"compatibility70", runner.UpProductionTemporalCompatibility},
		{"legacy-tests71", runner.UpProductionTemporalLegacyTests},
		{"discovery72", runner.UpProductionTemporalDiscovery},
		{"admission73", runner.UpProductionTemporalAdmission},
		{"test-executor74", runner.UpProductionTemporalTestExecutor},
		{"selector75", runner.UpProductionTemporalTestSelector},
		{"human76", runner.UpProductionTemporalHumanAdmission},
		{"automatic77", runner.UpProductionTemporalAutomaticSources},
		{"finding78", runner.UpProductionTemporalFindingResponse},
		{"authorization80", runner.UpProductionAuthorizationTemporalProfile},
		{"worker80", runner.UpProductionAuthorizationWorkerProfile},
	} {
		if err := stage.up(ctx); err != nil {
			t.Fatalf("preserved terminal-run upgrade at %s: %v", stage.name, err)
		}
	}
}

func TestTemporalPlannerLateUsageCrossSessionPostgres(t *testing.T) {
	runTemporalExecutorPlanningFixture(t, nil, func(ctx context.Context, owner, executor, api *pgx.Conn, o, w, e, run, actor string, providerRaw []byte, forward func(string, map[string]any) (map[string]any, error)) {
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE principal_id=$1`, actor); err != nil {
			t.Fatal(err)
		}
		connect := func(zone string) *pgx.Conn {
			config := owner.Config().Copy()
			config.User = "temporal_compensation_test_login"
			config.RuntimeParams["timezone"] = zone
			connection, err := pgx.ConnectConfig(ctx, config)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = connection.Close(context.Background()) })
			return connection
		}
		invoke := func(c *pgx.Conn, operation string, payload any) error {
			request, err := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "definition_version": 2, "operation": operation, "payload": payload})
			if err != nil {
				t.Fatal(err)
			}
			var raw json.RawMessage
			if err := c.QueryRow(ctx, `SELECT zasp_temporal68.plan($1::jsonb)`, request).Scan(&raw); err != nil {
				return err
			}
			var result struct {
				RunID string `json:"run_id"`
				State string `json:"state"`
			}
			if err := json.Unmarshal(raw, &result); err != nil || result.RunID != run || result.State != "needs_human" {
				t.Fatal("captured recovery returned a different run or state", err)
			}
			return nil
		}
		original := connect("America/Los_Angeles")
		if err := invoke(original, "reconcile", map[string]any{}); err != nil {
			t.Fatal("terminal unknown-usage capture", err)
		}
		const originalEvidence = `SELECT body::text,encode(event_digest,'hex') FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind='temporal_planning_terminal'`
		var originalBody, originalDigest, requestDigest, credentialDigest, reservation string
		if err := owner.QueryRow(ctx, originalEvidence, run).Scan(&originalBody, &originalDigest); err != nil {
			t.Fatal(err)
		}
		if err := owner.QueryRow(ctx, `SELECT request_digest,lookup_request->>'credential_digest',reservation_id FROM zasp_temporal68.planning_jobs WHERE run_id=$1`, run).Scan(&requestDigest, &credentialDigest, &reservation); err != nil {
			t.Fatal(err)
		}
		upgradePlannerTimezoneFixture(t, ctx, owner)
		var provider map[string]any
		if err := json.Unmarshal(providerRaw, &provider); err != nil {
			t.Fatal(err)
		}
		provider["id"] = "timezone-late-response-1"
		providerRaw, err := json.Marshal(provider)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(providerRaw)
		payload := map[string]any{"raw": string(providerRaw), "request_digest": requestDigest, "credential_digest": credentialDigest, "reservation_id": reservation, "response_id": provider["id"], "response_digest": "sha256:" + hex.EncodeToString(digest[:])}
		utc := connect("UTC")
		if err := invoke(utc, "late_usage", payload); err != nil {
			t.Fatal("UTC late usage could not consume original offset receipt", err)
		}
		later := connect("Asia/Kolkata")
		if err := invoke(later, "late_usage", payload); err != nil {
			t.Fatal("third-session late charge replay", err)
		}
		if err := invoke(later, "reconcile", map[string]any{}); err != nil {
			t.Fatal("third-session terminal recovery after late charge", err)
		}
		payload["reservation_id"] = o
		if err := invoke(later, "late_usage", payload); err == nil {
			t.Fatal("foreign late charge association accepted")
		}
		payload["reservation_id"] = reservation
		provider["usage"].(map[string]any)["cost"] = 1.0
		changed, _ := json.Marshal(provider)
		changedDigest := sha256.Sum256(changed)
		payload["raw"], payload["response_digest"] = string(changed), "sha256:"+hex.EncodeToString(changedDigest[:])
		if err := invoke(later, "late_usage", payload); err == nil {
			t.Fatal("changed response rewrote late charge")
		}
		var afterBody, afterDigest string
		if err := owner.QueryRow(ctx, originalEvidence, run).Scan(&afterBody, &afterDigest); err != nil || afterBody != originalBody || afterDigest != originalDigest {
			t.Fatal("late usage rewrote original evidence", err)
		}
		var exact bool
		if err := owner.QueryRow(ctx, `SELECT p.total_tokens=100 AND p.cost_nano_credits=500 AND p.settled_at IS NOT NULL AND p.released_at IS NULL AND (SELECT count(*)=1 FROM zasp_temporal68.planning_late_usage WHERE run_id=$1) AND (SELECT count(*)=1 FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind='temporal_planning_late_usage') AND NOT EXISTS(SELECT 1 FROM zasp_temporal68.admissions WHERE run_id=$1) AND zasp_temporal68.current_ready() FROM zasp_temporal68.provider_reservations p WHERE run_id=$1`, run).Scan(&exact); err != nil || !exact {
			t.Fatal("late charge accounting/cardinality/catalog changed", err)
		}
		if _, err := forward("start", map[string]any{}); err == nil {
			t.Fatal("late charge reopened send")
		}
		if _, err := forward("admit", map[string]any{}); err == nil {
			t.Fatal("late charge reopened admission")
		}
	})
}

func assertPlannerNullAuditRejected(t *testing.T, ctx context.Context, owner *pgx.Conn, run string) {
	t.Helper()
	for _, field := range []string{"job", "reservation"} {
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		// Owned corruption fixture only. Trigger definitions, grants and catalog
		// remain unchanged; rollback restores both data and replication mode.
		if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role='replica'`); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, `UPDATE zasp_security_agent_audit SET body=jsonb_set(body,ARRAY[$2::text],'null'),event_digest=digest(convert_to(jsonb_set(body,ARRAY[$2::text],'null')::text,'UTF8'),'sha256') WHERE run_id=$1 AND event_kind='temporal_planning_terminal'`, run, field)
		if err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal("owned null audit corruption", err)
		}
		var accepted, digestValid bool
		err = tx.QueryRow(ctx, `SELECT zasp_temporal68.planning_terminal_valid(organization_id,workspace_id,environment_id,run_id),event_digest=digest(convert_to(body::text,'UTF8'),'sha256') FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind='temporal_planning_terminal'`, run).Scan(&accepted, &digestValid)
		if rollbackErr := tx.Rollback(ctx); rollbackErr != nil {
			t.Fatal(rollbackErr)
		}
		if err != nil || !digestValid || accepted {
			t.Errorf("native validator accepted malformed null %s with recomputed audit digest: accepted=%t digestValid=%t err=%v", field, accepted, digestValid, err)
		}
	}
}

func assertPlannerReceiptTimeComparisons(t *testing.T, ctx context.Context, owner *pgx.Conn, run string) {
	t.Helper()
	tx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SET LOCAL timezone='UTC'`); err != nil {
		t.Fatal(err)
	}
	// These mutations isolate what the new comparison is allowed to normalize.
	// Everything except a different rendering of the same instant must fail.
	for _, mutation := range []string{
		`captured||'{"unexpected":true}'::jsonb`,
		`jsonb_set(captured,'{state}','"planning"')`,
		`captured-'budget_started_at'`,
		`jsonb_set(captured,'{budget_started_at}','null')`,
		`jsonb_set(captured,'{budget_started_at}','"2026-09-25T12:00:00"')`,
		`jsonb_set(captured,'{budget_started_at}','"2026-99-25T12:00:00+00:00"')`,
		`jsonb_set(captured,'{budget_started_at}',to_jsonb((captured->>'budget_started_at')::timestamptz+interval '1 microsecond'))`,
	} {
		var accepted bool
		query := `WITH evidence AS(SELECT a.body->'job' captured,to_jsonb(j) actual FROM zasp_security_agent_audit a JOIN zasp_temporal68.planning_jobs j USING(organization_id,workspace_id,environment_id,run_id) WHERE a.run_id=$1 AND a.event_kind='temporal_planning_terminal'), changed AS(SELECT ` + mutation + ` captured,actual FROM evidence) SELECT zasp_authorization80_worker.planner_receipt_row(captured,actual,'job') IS NOT DISTINCT FROM captured FROM changed`
		if err := tx.QueryRow(ctx, query, run).Scan(&accepted); err != nil || accepted {
			t.Fatal("receipt comparison accepted a non-rendering mutation", mutation, err)
		}
	}
	var correct bool
	if err := tx.QueryRow(ctx, `SELECT zasp_authorization80_worker.planner_receipt_row(a.body->'job',to_jsonb(j),'job')=a.body->'job' AND zasp_authorization80_worker.planner_job_digest(a.body->'job')=zasp_authorization80_worker.planner_job_digest(to_jsonb(j)) AND zasp_authorization80_worker.planner_job_digest(to_jsonb(j))<>zasp_authorization80_worker.planner_job_digest(to_jsonb(j)||'{"unexpected":true}') FROM zasp_security_agent_audit a JOIN zasp_temporal68.planning_jobs j USING(organization_id,workspace_id,environment_id,run_id) WHERE a.run_id=$1 AND a.event_kind='temporal_planning_terminal'`, run).Scan(&correct); err != nil || !correct {
		t.Fatal("cross-timezone receipt/digest positive control or full-row coverage failed", err)
	}
}
