package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Real owned PostgreSQL registration/permission controls. No task/grant rows
// are seeded, no FGA allow result is mocked, and the module remains inactive.
func TestApprovalMaintenanceNativeInactiveRegistration(t *testing.T) {
	runTemporalTestGrantFixture(t, func(ctx context.Context, owner, _, _ *pgx.Conn, o, w, e, _, _ string) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Minute)
		defer cancel()
		installAutomaticSourceFixture(t, ctx, owner)
		runner, err := migrations.NewRunner(&runtimeObservedMigrationDatabase{workerObservedMigrationDatabase{integrationMigrationDatabase{connection: owner}, t}})
		if err != nil {
			t.Fatal("owned migration runner", err)
		}
		for _, up := range []func(context.Context) error{runner.UpProductionTemporalFindingResponse, runner.UpProductionAuthorizationTemporalProfile, runner.UpProductionAuthorizationWorkerProfile} {
			if err := up(ctx); err != nil {
				t.Fatal("real native module installation", err)
			}
		}
		// Original72 deliberately stores scheduler credentials in the execution
		// registry, not the discovery principal registry. Capture all predicates
		// independently BEFORE installation and compare exact original rows.
		type predecessorState struct {
			worker, temporal, current, current72, bindings, discoveryOnly bool
			principals                                                    []byte
		}
		readPredecessor := func() predecessorState {
			t.Helper()
			var state predecessorState
			if err := owner.QueryRow(ctx, `SELECT zasp_authorization80_worker.catalog_ready(),zasp_authorization80_temporal.ready(),zasp_temporal78.current_ready(),zasp_temporal72.current_ready(),NOT EXISTS(SELECT 1 FROM zasp_temporal72.principals p WHERE NOT EXISTS(SELECT 1 FROM(SELECT principal_name,authority_role FROM public.zasp_discovery_principal_bindings UNION ALL SELECT principal_name,authority_role FROM public.zasp_discovery_execution_principals)b WHERE(b.principal_name,b.authority_role)=(p.principal_name,p.authority_role))),NOT EXISTS(SELECT 1 FROM zasp_temporal72.principals p WHERE NOT EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings b WHERE(b.principal_name,b.authority_role)=(p.principal_name,p.authority_role))),(SELECT jsonb_agg(jsonb_build_array(principal_name,authority_role) ORDER BY principal_name,authority_role) FROM zasp_temporal72.principals)`).Scan(&state.worker, &state.temporal, &state.current, &state.current72, &state.bindings, &state.discoveryOnly, &state.principals); err != nil {
				t.Fatal("predecessor predicate observation", err)
			}
			return state
		}
		before := readPredecessor()
		if !before.worker || !before.temporal || !before.current || !before.current72 || !before.bindings || len(before.principals) == 0 {
			t.Fatal("original predecessor baseline refused", before.worker, before.temporal, before.current, before.current72, before.bindings)
		}
		if err := runner.UpProductionApprovalMaintenanceProfile(ctx); err != nil {
			t.Fatal("real supplementary module installation", err)
		}
		var catalog, ready bool
		var schemaCount int
		var pin string
		if err := owner.QueryRow(ctx, `SELECT zasp_approval_maintenance.catalog_ready(),zasp_approval_maintenance.ready(),(SELECT count(*) FROM zasp_schema_versions),(SELECT checksum FROM zasp_approval_maintenance.registration)`).Scan(&catalog, &ready, &schemaCount, &pin); err != nil || !catalog || ready || schemaCount != 61 || pin != migrations.ApprovalMaintenanceProfileChecksum() {
			t.Fatal("real inactive registration baseline", catalog, ready, schemaCount, err)
		}
		t.Run("original principals and predecessor remain", func(t *testing.T) {
			after := readPredecessor()
			if !after.worker || !after.temporal || !after.current || !after.current72 || !after.bindings || after.discoveryOnly != before.discoveryOnly || string(after.principals) != string(before.principals) {
				t.Fatal("predecessor noninterference", after.worker, after.temporal, after.current, after.current72, after.bindings, after.discoveryOnly == before.discoveryOnly, string(after.principals) == string(before.principals))
			}
			t.Logf("predecessor before/after all required predicates true; legacy discovery-only coverage before=%t after=%t", before.discoveryOnly, after.discoveryOnly)
		})
		t.Run("operator registers only safe separate login", func(t *testing.T) {
			if _, err := owner.Exec(ctx, `CREATE ROLE maintenance_control_login LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;GRANT zasp_approval_maintenance_worker TO maintenance_control_login`); err != nil {
				t.Fatal("owned maintenance login", err)
			}
			var ok bool
			if err := owner.QueryRow(ctx, `SELECT zasp_approval_maintenance.register_principal('maintenance_control_login')`).Scan(&ok); err != nil || !ok {
				t.Fatal("real operator registration", err)
			}
		})
		t.Run("invalid key and purpose refuse without mutation", func(t *testing.T) {
			for _, q := range []string{`SELECT zasp_approval_maintenance.register_verifier(NULL,repeat('a',64),decode(repeat('01',32),'hex'))`, `SELECT zasp_approval_maintenance.register_verifier('approval-forward',repeat('a',64),decode(repeat('01',32),'hex'))`, `SELECT zasp_approval_maintenance.register_verifier('approval-forward',encode(digest(decode('01','hex'),'sha256'),'hex'),decode('01','hex'))`} {
				var raw bool
				err := owner.QueryRow(ctx, q).Scan(&raw)
				var native *pgconn.PgError
				if !errors.As(err, &native) || native.Code != "42501" {
					t.Fatal("invalid native verifier accepted", err)
				}
			}
			var count int
			if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_approval_maintenance.verifiers`).Scan(&count); err != nil || count != 0 {
				t.Fatal("invalid verifier changed durable registry", count, err)
			}
		})
		t.Run("registered credential does not fabricate activation", func(t *testing.T) {
			config := owner.Config().Copy()
			config.User = "maintenance_control_login"
			client, err := pgx.ConnectConfig(ctx, config)
			if err != nil {
				t.Fatal("own registered login connect", err)
			}
			defer client.Close(context.Background())
			if _, err := client.Exec(ctx, `SET ROLE zasp_approval_maintenance_worker`); err != nil {
				t.Fatal("restricted maintenance role", err)
			}
			var active bool
			if err := client.QueryRow(ctx, `SELECT zasp_approval_maintenance.worker()`).Scan(&active); err != nil || active {
				t.Fatal("inactive role became authority", active, err)
			}
			var raw json.RawMessage
			err = client.QueryRow(ctx, `SELECT zasp_approval_maintenance.reserve('native-owner',repeat('a',64),30)`).Scan(&raw)
			var native *pgconn.PgError
			if !errors.As(err, &native) || native.Code != "42501" {
				t.Fatal("inactive module admitted reserve", err)
			}
			err = client.QueryRow(ctx, `SELECT zasp_approval_maintenance.register_principal('maintenance_control_login')`).Scan(&active)
			if !errors.As(err, &native) || native.Code != "42501" {
				t.Fatal("maintenance role gained operator registry", err)
			}
		})
		t.Run("inactive profile cannot capture origin", func(t *testing.T) {
			var count int
			if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_approval_maintenance.origin_intents`).Scan(&count); err != nil || count != 0 {
				t.Fatal("unexpected initial origin", err)
			}
			var raw json.RawMessage
			err = owner.QueryRow(ctx, `SELECT zasp_approval_maintenance.admit_with_origin('test74',jsonb_build_object('operation','admit','organization_id',$1::text,'workspace_id',$2::text,'environment_id',$3::text,'run_id','pid_f0800000-0000-4000-8000-000000009999','definition_version',1,'payload','{}'::jsonb))`, o, w, e).Scan(&raw)
			var native *pgconn.PgError
			if !errors.As(err, &native) || native.Code != "42501" {
				t.Fatal("inactive origin accepted", err)
			}
			if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_approval_maintenance.origin_intents`).Scan(&count); err != nil || count != 0 {
				t.Fatal("denial persisted origin", err)
			}
		})
		t.Run("catalog drift refuses and rollback restores", func(t *testing.T) {
			tx, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if _, err := tx.Exec(ctx, `ALTER TABLE zasp_approval_maintenance.origins ADD COLUMN unexpected text`); err != nil {
				t.Fatal(err)
			}
			var ok bool
			if err := tx.QueryRow(ctx, `SELECT zasp_approval_maintenance.catalog_ready()`).Scan(&ok); err != nil || ok {
				t.Fatal("catalog drift admitted", ok, err)
			}
		})
	})
}
