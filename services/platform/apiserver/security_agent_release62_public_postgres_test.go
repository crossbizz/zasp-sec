package apiserver

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type public62Runner interface {
	UpProductionSecurityAgentPublic(context.Context) error
	DownProductionSecurityAgentPublic(context.Context) error
}

// The separately registered extension must preserve the canonical chain and
// private planner. A canonical row62 is deliberately forbidden.
func TestSecurityAgentRelease62PreservesPrivatePlannerPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, _ *pgx.Conn, o, w, e, testID, actor string) {
		run := seedOrderedPlanningQueue(t, ctx, owner, o, w, e, testID, actor)
		q := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "worker_id": "ordered-planner", "lease_token": "ordered-planner-lease-0001", "operation": "claim", "payload": map[string]any{}}
		readiness := func() (bool, string) {
			t.Helper()
			var ready bool
			var fingerprint string
			if err := owner.QueryRow(ctx, `SELECT zasp_sa_multistep_readiness($1,$2),zasp_sa_multistep_registered_live_fingerprint()`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint()).Scan(&ready, &fingerprint); err != nil {
				t.Fatal(err)
			}
			return ready, fingerprint
		}
		if ready, fingerprint := readiness(); !ready || fingerprint != migrations.SecurityAgentMultistepRegisteredFingerprint() {
			t.Fatalf("baseline release61 ready=%t fingerprint=%s", ready, fingerprint)
		}
		first, err := orderedPlanningCall(ctx, worker, q)
		if err != nil || first["state"] != "claimed" {
			t.Fatalf("baseline private planner state=%v err=%v", first["state"], err)
		}
		catalog := func() string {
			t.Helper()
			var value string
			if err := owner.QueryRow(ctx, `SELECT jsonb_build_object('versions',(SELECT jsonb_agg(to_jsonb(x) ORDER BY version) FROM zasp_schema_versions x),'metadata',(SELECT jsonb_agg(to_jsonb(x) ORDER BY key) FROM zasp_schema_metadata x),'private_schema',(SELECT jsonb_build_array(nspowner::regrole::text,nspacl::text) FROM pg_namespace WHERE nspname='zasp_sa_multistep_prior'),'private_acl',(SELECT jsonb_agg(jsonb_build_array(proname,pg_get_function_identity_arguments(oid),proowner::regrole::text,proacl::text) ORDER BY proname,pg_get_function_identity_arguments(oid)) FROM pg_proc WHERE pronamespace='zasp_sa_multistep_prior'::regnamespace))::text`).Scan(&value); err != nil {
				t.Fatal(err)
			}
			return value
		}
		baselineCatalog := catalog()
		runner := precisionMigrationRunner(t, owner)
		probe, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = probe.Exec(ctx, migrations.ProductionSecurityAgentPublic().UpSQL()); err != nil {
			if pg, ok := err.(*pgconn.PgError); ok {
				t.Log("SQL position", pg.Position, pg.InternalPosition, pg.InternalQuery, pg.Where)
				if pg.Position > 0 {
					source := migrations.ProductionSecurityAgentPublic().UpSQL()
					p := int(pg.Position) - 1
					t.Log(source[max(0, p-200):min(len(source), p+200)])
				}
			}
			t.Fatal(err)
		}
		var extensionFingerprint string
		if err = probe.QueryRow(ctx, `SELECT zasp_ordered_public62.fingerprint()`).Scan(&extensionFingerprint); err != nil {
			t.Fatal(err)
		}
		t.Log("public extension fingerprint:", extensionFingerprint)
		if _, err = probe.Exec(ctx, `INSERT INTO zasp_ordered_public62.registration(checksum,fingerprint) VALUES($1,$2)`, migrations.ProductionSecurityAgentPublic().Checksum(), migrations.SecurityAgentPublicFingerprint()); err != nil {
			t.Fatal(err)
		}
		var predecessorReady, extensionReady bool
		if err = probe.QueryRow(ctx, `SELECT zasp_sa_multistep_readiness($1,$2),zasp_ordered_public62.ready($3,$4)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint(), migrations.ProductionSecurityAgentPublic().Checksum(), migrations.SecurityAgentPublicFingerprint()).Scan(&predecessorReady, &extensionReady); err != nil {
			t.Fatal(err)
		}
		t.Log("probe readiness", predecessorReady, extensionReady)
		var live61, predecessor string
		if err = probe.QueryRow(ctx, `SELECT zasp_sa_multistep_registered_live_fingerprint(),zasp_discovery_schedule_replay_live_fingerprint()`).Scan(&live61, &predecessor); err != nil {
			t.Fatal(err)
		}
		t.Log("probe live61, predecessor", live61, predecessor)
		if err = probe.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		extension, ok := any(runner).(public62Runner)
		if !ok {
			t.Fatal("public facade extension Runner absent")
		}
		for _, migrate := range []func(context.Context) error{extension.UpProductionSecurityAgentPublic, extension.UpProductionSecurityAgentPublic, extension.DownProductionSecurityAgentPublic, extension.DownProductionSecurityAgentPublic, extension.UpProductionSecurityAgentPublic} {
			if err = migrate(ctx); err != nil {
				t.Fatal("extension migration", err)
			}
			if version, err := runner.Version(ctx); err != nil || version != 61 {
				t.Fatal("extension altered canonical chain", version, err)
			}
			if catalog() != baselineCatalog {
				t.Fatal("extension changed canonical/shared registration or private ACL bytes")
			}
			if ready, fingerprint := readiness(); !ready || fingerprint != migrations.SecurityAgentMultistepRegisteredFingerprint() {
				t.Fatalf("extension altered release61 ready=%t fingerprint=%s", ready, fingerprint)
			}
			if replay, err := orderedPlanningCall(ctx, worker, q); err != nil || !jsonEqualMaps(first, replay) {
				t.Fatal("extension broke private planner replay", err)
			}
		}
	})
}
