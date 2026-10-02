package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestSecurityAgentMultistepPlanningConcurrentPostgres(t *testing.T) {
	runOrderedPlanningFixture(t, func(ctx context.Context, owner, worker *pgx.Conn, q map[string]any, selection map[string]any, _ string) {
		other, err := pgx.ConnectConfig(ctx, worker.Config().Copy())
		if err != nil {
			t.Fatal(err)
		}
		defer other.Close(ctx)
		type result struct {
			value map[string]any
			err   error
		}
		both := func() (map[string]any, map[string]any) {
			t.Helper()
			done := make(chan result, 2)
			for _, c := range []*pgx.Conn{worker, other} {
				go func(c *pgx.Conn) { v, e := orderedPlanningCall(ctx, c, q); done <- result{v, e} }(c)
			}
			a, b := <-done, <-done
			if a.err != nil || b.err != nil {
				t.Fatal("concurrent authority", a.err, b.err)
			}
			return a.value, b.value
		}
		a, b := both()
		if !jsonEqualMaps(a, b) {
			t.Fatal("concurrent claim changed identities")
		}
		q["operation"] = "prepare"
		q["payload"] = map[string]any{"pricing": selection, "input_version": "controlled-input-version"}
		a, b = both()
		if !jsonEqualMaps(a, b) {
			t.Fatal("concurrent intent changed identities")
		}
		q["operation"] = "start"
		q["payload"] = map[string]any{}
		a, b = both()
		if a["send_permit"] == b["send_permit"] {
			t.Fatal("expected exactly one durable send permit", a["send_permit"], b["send_permit"])
		}
		var reservations int
		if err = owner.QueryRow(ctx, `SELECT count(*) FROM zasp_security_agent_provider_reservations WHERE run_id=$1`, q["run_id"]).Scan(&reservations); err != nil || reservations != 1 {
			t.Fatal("duplicate reservation", reservations, err)
		}
	})
}

func TestSecurityAgentMultistepPlanningLegacyRestorationPostgres(t *testing.T) {
	multistepBudgetFixture(t, func(ctx context.Context, owner *pgx.Conn, _ string) {
		const org = "pid_6a000001-0000-4000-8000-000000000001"
		runner := precisionMigrationRunner(t, owner)
		const snapshot = `SELECT jsonb_build_object('definition',pg_get_functiondef(p.oid),'owner',p.proowner::regrole::text,'acl',p.proacl::text)::text FROM pg_proc p WHERE p.oid='public.zasp_security_agent_budget_settle_planner(text,text,text,text,text,text,bigint,text,bytea,bigint,bigint,bigint,bigint)'::regprocedure`
		var before, after string
		config := owner.Config().Copy()
		config.User = "security_agent_v33_worker_login"
		worker, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close(ctx)
		database, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
		repository, err := NewSecurityAgentWorkerRepository(database)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = owner.Exec(ctx, `UPDATE zasp_risk_attack_paths SET state='verified',version=version+1 WHERE organization_id=$1`, org); err != nil {
			t.Fatal(err)
		}
		const workerID, lease = "legacy-compat-worker", "legacy-compat-worker-lease"
		if count, err := repository.ScheduleSecurityAgentTriggers(ctx, workerID, 1); err != nil || count != 1 {
			t.Fatal("legacy schedule", count, err)
		}
		claims, err := repository.ClaimSecurityAgentRuns(ctx, workerID, lease, 60, 1)
		if err != nil || len(claims) != 1 {
			t.Fatal("legacy claim", err)
		}
		claim := claims[0]
		// Controlled legacy budget configuration, matching the existing
		// settlement fixture; this is not usage or reservation authority.
		if _, err = owner.Exec(ctx, `UPDATE zasp_security_agent_run_budgets SET max_tokens=100,max_cost_nano_credits=1000 WHERE run_id=$1`, claim.RunID); err != nil {
			t.Fatal(err)
		}
		planner, err := repository.LoadSecurityAgentPlannerContext(ctx, claim, workerID, lease)
		if err != nil {
			t.Fatal(err)
		}
		input, ok := decodeSecurityAgentDigest(planner.InputDigest)
		if !ok {
			t.Fatal("legacy input digest")
		}
		var permit json.RawMessage
		if err = worker.QueryRow(ctx, multistepReservePlannerBudgetTestSQL, org, claim.WorkspaceID, claim.EnvironmentID, claim.RunID, workerID, lease, claim.Attempt, "legacy-compat-reservation", input, "fixture-model", "fixture-policy", "openrouter_credit", int64(100), int64(1000)).Scan(&permit); err != nil || !multistepValidReservationTestPermit(permit, claim, planner.InputDigest, 100, 1000, "legacy-compat-reservation") {
			t.Fatal("legacy reserve", err, string(permit))
		}
		// Produce the genuine legacy reservation at its original release, then
		// carry it through the real upgrade chain. No owner-created usage/result.
		for _, up := range []func(context.Context) error{runner.UpProductionSecurityAgentRunContext, runner.UpProductionSecurityAgentExistingTests, runner.UpProductionCompliance, runner.UpProductionSecurityAgentAttackLab, runner.UpProductionSecurityAgentExports, runner.UpProductionSecurityAgentWebhooks, runner.UpProductionDiscoveryScheduleReplay} {
			if err := up(ctx); err != nil {
				t.Fatal(err)
			}
		}
		if err := owner.QueryRow(ctx, snapshot).Scan(&before); err != nil {
			t.Fatal(err)
		}
		legacySnapshot := func() string {
			t.Helper()
			var value string
			if err := owner.QueryRow(ctx, `SELECT jsonb_build_array((SELECT to_jsonb(x) FROM zasp_security_agent_runs x WHERE run_id=$1),(SELECT to_jsonb(x) FROM zasp_security_agent_run_budgets x WHERE run_id=$1),(SELECT jsonb_agg(to_jsonb(x)) FROM zasp_security_agent_provider_reservations x WHERE run_id=$1),(SELECT jsonb_agg(to_jsonb(x) ORDER BY audit_id) FROM zasp_security_agent_audit x WHERE run_id=$1))::text`, claim.RunID).Scan(&value); err != nil {
				t.Fatal(err)
			}
			return value
		}
		checkSettlement := func(isolation pgx.TxIsoLevel, refuse bool) {
			t.Helper()
			prior := legacySnapshot()
			tx, err := worker.BeginTx(ctx, pgx.TxOptions{IsoLevel: isolation})
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			var raw json.RawMessage
			err = tx.QueryRow(ctx, multistepSettlePlannerBudgetTestSQL, org, claim.WorkspaceID, claim.EnvironmentID, claim.RunID, workerID, lease, claim.Attempt, "legacy-compat-reservation", []byte("12345678901234567890123456789012"), int64(50), int64(50), int64(100), int64(500)).Scan(&raw)
			var pg *pgconn.PgError
			if refuse {
				if !errors.As(err, &pg) || pg.Code != "25001" {
					t.Errorf("release61 higher-isolation settlement not refused: %v", err)
				}
			} else {
				var result struct {
					Settlement struct {
						Known bool `json:"known"`
					} `json:"budget_settlement"`
				}
				if err != nil || json.Unmarshal(raw, &result) != nil || !result.Settlement.Known {
					t.Errorf("ordinary legacy settlement unavailable at %s: %v %s", isolation, err, raw)
				}
			}
			tx.Rollback(ctx)
			if legacySnapshot() != prior {
				t.Fatal("settlement probe changed durable authority")
			}
		}
		checkSettlement(pgx.RepeatableRead, false)
		checkSettlement(pgx.Serializable, false)
		var raw []byte
		if err = worker.QueryRow(ctx, `SELECT zasp_sa_multistep_prior.planning($1,$2,'{}'::jsonb)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint()).Scan(&raw); err == nil {
			t.Fatal("release60 accepted private61 planner")
		}
		if err = runner.UpProductionSecurityAgentMultistep(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err = NewSecurityAgentWorkerRepository(database); err == nil {
			t.Fatal("legacy binary acquired61 authority")
		}
		if err = owner.QueryRow(ctx, snapshot).Scan(&after); err != nil || after == before {
			t.Fatal("release61 fence absent", err)
		}
		checkSettlement(pgx.ReadCommitted, false)
		checkSettlement(pgx.RepeatableRead, true)
		checkSettlement(pgx.Serializable, true)
		if err = runner.DownProductionSecurityAgentMultistep(ctx); err != nil {
			t.Fatal(err)
		}
		if err = owner.QueryRow(ctx, snapshot).Scan(&after); err != nil || after != before {
			t.Fatal("release60 definition/owner/ACL not restored exactly", err)
		}
		checkSettlement(pgx.RepeatableRead, false)
		checkSettlement(pgx.Serializable, false)
		if err = worker.QueryRow(ctx, `SELECT zasp_sa_multistep_prior.planning($1,$2,'{}'::jsonb)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint()).Scan(&raw); err == nil {
			t.Fatal("demoted private61 planner remained available")
		}
	})
}
