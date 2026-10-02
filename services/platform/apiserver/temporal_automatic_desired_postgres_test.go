package apiserver

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

func TestTemporalAutomaticDesiredPostgres(t *testing.T) {
	runTemporalTestGrantFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
		installAutomaticSourceFixture(t, ctx, owner)
		if _, err := owner.Exec(ctx, `CREATE ROLE automatic_desired_executor LOGIN; CREATE ROLE automatic_desired_compensation LOGIN; SELECT zasp_temporal68.register_principals('automatic_desired_executor','automatic_desired_compensation'); SELECT zasp_temporal75.configure('{"revision":1,"cadence_seconds":1,"enabled":true}')`); err != nil {
			t.Fatal(err)
		}
		c := owner.Config().Copy()
		c.User = "automatic_desired_executor"
		executor, err := pgx.ConnectConfig(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		defer executor.Close(context.Background())
		var ready bool
		if err := executor.QueryRow(ctx, `SELECT zasp_temporal77.executor_ready($1,$2)`, migrations.TemporalAutomaticSourcesChecksum(), migrations.TemporalAutomaticSourcesFingerprint()).Scan(&ready); err != nil || !ready {
			t.Fatal("actual executor77 readiness", ready, err)
		}
		ref := orchestration.TestSelectorRef{OrganizationID: o, WorkspaceID: w, EnvironmentID: e, DefinitionID: temporalTestLegacyProved}
		q, _ := json.Marshal(ref)
		var equal bool
		if err := executor.QueryRow(ctx, `SELECT zasp_temporal77.desired($1::jsonb)=zasp_temporal75.desired($1::jsonb)`, q).Scan(&equal); err != nil || !equal {
			t.Fatal("omitted desired changed", equal, err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET role='organization_admin' WHERE principal_id=$1; UPDATE zasp_authorized_scopes SET permissions='["view","manage_identity","manage_workflows","run_tests"]' WHERE principal_id=$1`, pgx.QueryExecModeSimpleProtocol, actor); err != nil {
			t.Fatal(err)
		}
		var base json.RawMessage
		if err := owner.QueryRow(ctx, `SELECT body FROM zasp_security_agent_definitions WHERE definition_id=$1`, temporalTestLegacyProved).Scan(&base); err != nil {
			t.Fatal(err)
		}
		ref.DefinitionID = automaticSourceID(7000)
		createAutomaticPageDefinition(t, ctx, api, o, w, e, actor, ref.DefinitionID, base, 7001, true)
		q, _ = json.Marshal(ref)
		read := func(wantEnabled bool) {
			t.Helper()
			var raw json.RawMessage
			if err := executor.QueryRow(ctx, `SELECT zasp_temporal77.desired($1::jsonb)`, q).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			var d orchestration.TestSelectorDesired
			if json.Unmarshal(raw, &d) != nil || !d.Valid() || !d.Automatic || d.Enabled != wantEnabled || d.Ref != ref {
				t.Fatal("configured desired did not preserve rules", string(raw))
			}
		}
		read(false)
		activateAutomaticPageDefinition(t, ctx, api, o, w, e, actor, ref.DefinitionID, 7004)
		read(true)
		// This owner-only mutation deliberately corrupts the installed contract.
		// Neither readiness nor the desired caller may downgrade to75 afterwards.
		if _, err := owner.Exec(ctx, `ALTER FUNCTION zasp_temporal77.executor_ready(text,text) IMMUTABLE`); err != nil {
			t.Fatal(err)
		}
		if err := executor.QueryRow(ctx, `SELECT zasp_temporal77.executor_ready($1,$2)`, migrations.TemporalAutomaticSourcesChecksum(), migrations.TemporalAutomaticSourcesFingerprint()).Scan(&ready); err != nil || ready {
			t.Fatal("invalid77 readiness accepted", ready, err)
		}
		var raw json.RawMessage
		if err := executor.QueryRow(ctx, `SELECT zasp_temporal77.desired($1::jsonb)`, q).Scan(&raw); err == nil {
			t.Fatal("invalid77 desired accepted")
		}
	})
}
