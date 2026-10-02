package apiserver

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestSecurityAgentRelease62CurrentAuthorityPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		if err := precisionMigrationRunner(t, owner).UpProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
		public62Seed(t, ctx, owner, o, w, e, testID, actor)
		q := public62Request(o, w, e, actor, "activate")
		q["definition_id"], q["definition_version"] = public62Definition, 1
		for name, drift := range map[string]string{
			"inventory-expired":    `UPDATE zasp_inventory_entities SET fresh_until=clock_timestamp()-interval '1 second'`,
			"test-disabled":        `UPDATE zasp_red_team_definitions SET enabled=false`,
			"credential-expired":   `UPDATE zasp_attack_lab_credential_bindings SET valid_until=clock_timestamp()-interval '1 second'`,
			"control-disabled":     `UPDATE zasp_security_agent_kill_switches SET execution_enabled=false WHERE action_key='run_test'`,
			"inactive-member":      `UPDATE zasp_identity_memberships SET active=false`,
			"no-permission":        `UPDATE zasp_identity_memberships SET role='read_only_viewer'`,
			"catalog-mismatch":     `UPDATE zasp_security_agent_definitions SET plan_catalog_version='unknown'`,
			"extension-mismatch":   `UPDATE zasp_ordered_public62.registration SET checksum=repeat('0',64)`,
			"predecessor-mismatch": `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_security_agent_multistep_checksum'`,
		} {
			t.Run(name, func(t *testing.T) {
				before := public62Snapshot(t, ctx, owner)
				if _, err := owner.Exec(ctx, `BEGIN`); err != nil {
					t.Fatal(err)
				}
				if _, err := owner.Exec(ctx, drift); err != nil {
					owner.Exec(ctx, `ROLLBACK`)
					t.Fatal(err)
				}
				if _, err := owner.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{api.Config().User}.Sanitize()); err != nil {
					owner.Exec(ctx, `ROLLBACK`)
					t.Fatal(err)
				}
				_, callErr := public62Call(ctx, owner, q)
				if _, err := owner.Exec(ctx, `ROLLBACK`); err != nil {
					t.Fatal(err)
				}
				if callErr == nil {
					t.Fatal("stale or unauthorized activation accepted")
				}
				if public62Snapshot(t, ctx, owner) != before {
					t.Fatal("denial changed owner state")
				}
			})
		}
		if _, err := public62Call(ctx, worker, q); err == nil {
			t.Fatal("worker entered public mutation facade")
		}
		if _, err := public62Call(ctx, owner, q); err == nil {
			t.Fatal("unregistered migration principal entered public facade")
		}
		if got, err := public62Call(ctx, api, q); err != nil || got["activation"] != "supervised" {
			t.Fatal("valid authority rejected", got, err)
		}
		var allowed bool
		// Registered61 already exposes only its reviewed transition to this role.
		if err := api.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_proc WHERE pronamespace='zasp_sa_multistep_prior'::regnamespace AND oid<>'zasp_sa_multistep_prior.transition(text,text,jsonb)'::regprocedure AND has_function_privilege(current_user,oid,'EXECUTE')) OR has_table_privilege(current_user,'zasp_ordered_public62.registration','SELECT') OR has_function_privilege(current_user,'zasp_ordered_public62.definition(text,text,text,text,bigint,boolean)','EXECUTE')`).Scan(&allowed); err != nil || allowed {
			t.Fatal("facade granted private authority", allowed, err)
		}
	})
}
