package apiserver

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"testing"
	"time"
)

func TestTemporalTestSelectorLivePostgres(t *testing.T) {
	runTemporalTestGrantFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 4*time.Minute)
		defer cancel()
		installTemporalTestExecutorFixture(t, ctx, owner)
		if err := precisionMigrationRunner(t, owner).UpProductionTemporalTestSelector(ctx); err != nil {
			t.Fatal(err)
		}
		installAutomaticSourceAfterSelectorFixture(t, ctx, owner)
		if _, err := owner.Exec(ctx, `SELECT zasp_temporal75.configure('{"revision":1,"cadence_seconds":1,"enabled":true}');CREATE ROLE temporal_test_executor_login LOGIN;CREATE ROLE temporal_test_compensation_login LOGIN;SELECT zasp_temporal68.register_principals('temporal_test_executor_login','temporal_test_compensation_login');UPDATE zasp_identity_memberships SET role='organization_admin' WHERE principal_id=$1;UPDATE zasp_authorized_scopes SET permissions='["view","manage_identity","manage_workflows","run_tests"]' WHERE principal_id=$1`, pgx.QueryExecModeSimpleProtocol, actor); err != nil {
			t.Fatal(err)
		}
		cfg := owner.Config().Copy()
		cfg.User = "security_agent_v33_discovery_api_login"
		admin, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer admin.Close(ctx)
		policy := orderedPricingAdminRequest(o, w, e, actor)
		bindTemporalTestPlannerPricing(policy)
		pricing, err := orderedPricingCall(ctx, admin, "pricing_admin", policy)
		if err != nil {
			t.Fatal(err)
		}
		selection := orderedPricingLookupRequest(o, w, e, policy["policy"].(map[string]any), pricing)
		encoded, _ := json.Marshal(selection)
		seedOrderedTestSource(t, ctx, owner, o, w, e, actor)
		redWorker, adapter := orderedTestConnections(t, ctx, owner)
		defer redWorker.Close(ctx)
		defer adapter.Close(ctx)
		// Only actual55 activation proof produced this grant. Other synthetic
		// definitions in the reused fixture have no grants and remain ineligible.
		var parent string
		if err := owner.QueryRow(ctx, `SELECT zasp_discovery_canonical_id(d.organization_id,d.workspace_id,d.environment_id,'security_agent_run',concat_ws(chr(31),d.definition_id,d.version,d.body->>'trigger_kind',f.id,f.version)) FROM zasp_security_agent_definitions d JOIN zasp_risk_findings f ON(f.organization_id,f.workspace_id,f.environment_id,f.rule,f.status)=(d.organization_id,d.workspace_id,d.environment_id,d.body->>'trigger_source','open') WHERE(d.organization_id,d.workspace_id,d.environment_id,d.definition_id) =($1,$2,$3,$4) ORDER BY f.id,f.version DESC LIMIT 1`, o, w, e, temporalTestLegacyProved).Scan(&parent); err != nil {
			t.Fatal(err)
		}
		var absent bool
		if err := owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_temporal73.admissions)`).Scan(&absent); err != nil || !absent {
			t.Fatal("pre-admission premise", absent, err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE(organization_id,principal_id)=($1,$2)`, o, actor); err != nil {
			t.Fatal(err)
		}
		t.Setenv("ZASP_TEST75_LIVE", "true")
		t.Setenv("ZASP_TEST75_DEFINITION", temporalTestLegacyProved)
		assertTemporalTestTransport(t, ctx, owner, parent, testID, 4, encoded)
	})
}
