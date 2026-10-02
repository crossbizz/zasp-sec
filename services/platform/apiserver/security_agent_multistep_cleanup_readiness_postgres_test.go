package apiserver

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestSecurityAgentMultistepCleanupReadinessPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		var secured bool
		if err := owner.QueryRow(ctx, `SELECT
		 (SELECT count(*)=2 AND bool_and(relowner='zasp_discovery_authority'::regrole AND relrowsecurity AND relforcerowsecurity AND NOT has_table_privilege('public',oid,'SELECT,INSERT,UPDATE,DELETE') AND NOT has_table_privilege('zasp_security_agent_action_worker',oid,'SELECT,INSERT,UPDATE,DELETE') AND NOT has_table_privilege('zasp_policy_deployment_worker',oid,'SELECT,INSERT,UPDATE,DELETE')) FROM pg_class WHERE oid IN('zasp_sa_multistep_prior.cleanups'::regclass,'zasp_sa_multistep_prior.cleanup_receipts'::regclass))
		 AND has_function_privilege('zasp_security_agent_action_worker','zasp_sa_multistep_prior.cleanup(text,text,jsonb)','EXECUTE')
		 AND has_function_privilege('zasp_policy_deployment_worker','zasp_sa_multistep_prior.cleanup_deployment(text,text,jsonb)','EXECUTE')
		 AND NOT has_function_privilege('zasp_policy_deployment_worker','zasp_sa_multistep_prior.cleanup(text,text,jsonb)','EXECUTE')
		 AND NOT has_function_privilege('zasp_security_agent_action_worker','zasp_sa_multistep_prior.cleanup_deployment(text,text,jsonb)','EXECUTE')
		 AND NOT EXISTS(SELECT 1 FROM pg_proc p WHERE pronamespace='zasp_sa_multistep_prior'::regnamespace AND proname LIKE 'cleanup%' AND (has_function_privilege('public',p.oid,'EXECUTE') OR has_function_privilege('zasp_security_agent_api',p.oid,'EXECUTE') OR has_function_privilege('zasp_security_agent_worker',p.oid,'EXECUTE')))`).Scan(&secured); err != nil || !secured {
			t.Fatal("cleanup authority grants widened", secured, err)
		}
		for _, drift := range []string{
			`GRANT EXECUTE ON FUNCTION zasp_sa_multistep_prior.cleanup_targets(text,text,text,text,text) TO PUBLIC`,
			`ALTER FUNCTION zasp_sa_multistep_prior.cleanup(text,text,jsonb) OWNER TO CURRENT_USER`,
			`ALTER FUNCTION zasp_sa_multistep_prior.cleanup_deployment(text,text,jsonb) STABLE`,
			`ALTER TABLE zasp_sa_multistep_prior.cleanups NO FORCE ROW LEVEL SECURITY`,
			`ALTER TABLE zasp_sa_multistep_prior.cleanup_receipts DISABLE TRIGGER immutable`,
			`ALTER TABLE zasp_sa_multistep_prior.cleanup_receipts ADD COLUMN unbound text`,
		} {
			tx, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, drift); err != nil {
				t.Fatal(err)
			}
			var ready bool
			if err = tx.QueryRow(ctx, `SELECT zasp_sa_multistep_readiness($1,$2)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint()).Scan(&ready); err != nil || ready {
				t.Fatal("unbound cleanup readiness", drift, ready, err)
			}
			runner, _ := migrations.NewRunner(&registeredMultistepDatabase{connection: owner, t: t, outer: tx})
			if err = runner.DownProductionSecurityAgentMultistep(ctx); !errors.Is(err, migrations.ErrInvalidState) {
				t.Fatal("cleanup drift demotion accepted", err)
			}
			if err = tx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
		}
		runner := precisionMigrationRunner(t, owner)
		if err := runner.DownProductionSecurityAgentMultistep(ctx); err != nil {
			t.Fatal(err)
		}
		if err := owner.QueryRow(ctx, `SELECT to_regnamespace('zasp_sa_multistep_prior') IS NULL AND zasp_discovery_schedule_replay_readiness($1,$2)`, migrations.ProductionDiscoveryScheduleReplay().Checksum(), migrations.DiscoveryScheduleReplayFingerprint()).Scan(&secured); err != nil || !secured {
			t.Fatal("unused cleanup demotion changed release60", secured, err)
		}
		if err := runner.UpProductionSecurityAgentMultistep(ctx); err != nil {
			t.Fatal("cleanup promotion replay identity", err)
		}
	})
}
