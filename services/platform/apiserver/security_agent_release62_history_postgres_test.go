package apiserver

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

// A queued or planning read must not make corrupt historical identity look valid.
func TestSecurityAgentRelease62HistoricalProjectionPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		if err := precisionMigrationRunner(t, owner).UpProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
		public62Seed(t, ctx, owner, o, w, e, testID, actor)
		q := public62Request(o, w, e, actor, "activate")
		q["definition_id"], q["definition_version"] = public62Definition, 1
		if _, err := public62Call(ctx, api, q); err != nil {
			t.Fatal(err)
		}
		q = public62Request(o, w, e, actor, "trigger")
		q["definition_id"], q["definition_version"], q["trigger_id"], q["trigger_version"], q["idempotency_key"] = public62Definition, 2, public62Finding, 1, "public62-history-0001"
		created, err := public62Call(ctx, api, q)
		if err != nil {
			t.Fatal(err)
		}
		run := created["run_id"].(string)
		for _, state := range []string{"queued", "planning"} {
			if state == "planning" {
				claim := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "worker_id": "public62-planner", "lease_token": "public62-history-lease-0001", "operation": "claim", "payload": map[string]any{}}
				if _, err = orderedPlanningCall(ctx, worker, claim); err != nil {
					t.Fatal(err)
				}
			}
			for _, operation := range []string{"detail", "list"} {
				read := public62Request(o, w, e, actor, operation)
				if operation == "detail" {
					read["run_id"] = run
				} else {
					read["limit"], read["after_run_id"] = 10, ""
				}
				if _, err = public62Call(ctx, api, read); err != nil {
					t.Fatal("valid historical authority rejected", err)
				}
				for name, mutation := range map[string]string{
					"nonexistent-version": `UPDATE zasp_security_agent_runs SET definition_version=999 WHERE run_id=$1`,
					"missing-history":     `DELETE FROM zasp_security_agent_definition_versions WHERE definition_id=(SELECT definition_id FROM zasp_security_agent_runs WHERE run_id=$1)`,
					"digest-drift":        `UPDATE zasp_security_agent_definition_versions SET definition_digest=decode(repeat('0',64),'hex') WHERE definition_id=(SELECT definition_id FROM zasp_security_agent_runs WHERE run_id=$1)`,
					"malformed-history":   `UPDATE zasp_security_agent_definition_versions SET definition=definition||'{"allowed_actions":["run_test"]}'::jsonb,definition_digest=digest(convert_to((definition||'{"allowed_actions":["run_test"]}'::jsonb)::text,'UTF8'),'sha256') WHERE definition_id=(SELECT definition_id FROM zasp_security_agent_runs WHERE run_id=$1)`,
					"mismatched-history":  `UPDATE zasp_security_agent_definition_versions SET definition=definition||'{"name":"Different history"}'::jsonb,definition_digest=digest(convert_to((definition||'{"name":"Different history"}'::jsonb)::text,'UTF8'),'sha256') WHERE definition_id=(SELECT definition_id FROM zasp_security_agent_runs WHERE run_id=$1)`,
					"trigger-drift":       `UPDATE zasp_security_agent_trigger_receipts SET trigger_digest=decode(repeat('0',64),'hex') WHERE run_id=$1`,
					"audit-missing":       `DELETE FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind='ordered_public_triggered'`,
				} {
					t.Run(state+"/"+operation+"/"+name, func(t *testing.T) { public62MutationRefused(t, ctx, owner, api, read, run, mutation) })
				}
			}
		}
	})
}
