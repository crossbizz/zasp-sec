package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Native application acceptance. The original signed finding planner creates
// the notification and delegation. No synthetic origin, task or grant is seeded.
// This fixture establishes SQL/profile controls, not fleet withdrawal or a
// deployed webhook integration. Activation remains absent in durable state.
func TestApprovalActivationNativeCapturedOriginControls(t *testing.T) {
	runFindingResponseFixtureConfigured(t, nil, func(ctx context.Context, f findingResponseFixture, run, finding string) {
		other, otherRef := admitWorkerFindingTask(t, ctx, f, run)
		complete, completeRef := admitWorkerFindingTask(t, ctx, f, run)
		runner := workerMigrationRunner(t, f.owner)
		for _, up := range []func(context.Context) error{runner.UpProductionAuthorizationTemporalProfile, runner.UpProductionAuthorizationWorkerProfile, runner.UpProductionApprovalMaintenanceProfile} {
			if err := up(ctx); err != nil {
				t.Fatal("native predecessor installation refused", err)
			}
		}
		if _, err := f.owner.Exec(ctx, `INSERT INTO public.zasp_workflow_records(organization_id,workspace_id,environment_id,kind,id,body) VALUES($1,$2,$3,'integration',$4,jsonb_build_object('id',$4::text,'name','Owned approval activation fixture','connector_key','generic-webhook','status','configured','configuration',jsonb_build_object('destination_url','https://hooks.example.test/zasp','signing_secret_reference','secret_ref_approval_fixture')))`, f.o, f.w, f.e, f.next()); err != nil {
			t.Fatal("native webhook configuration refused", err)
		}
		assertApprovalOriginFindingPlanning(t, ctx, f, run, other, otherRef, complete, completeRef, false)
		if err := runner.UpProductionConnectorMaintenance(ctx); err != nil {
			t.Fatal("native connector composition refused", err)
		}
		readPredecessors := func() string {
			t.Helper()
			var result string
			if err := f.owner.QueryRow(ctx, `SELECT jsonb_build_array(zasp_authorization79.fingerprint(),zasp_authorization80.fingerprint(),zasp_approval_maintenance.fingerprint(),zasp_connector_maintenance.fingerprint())::text`).Scan(&result); err != nil {
				t.Fatal("native predecessor fingerprints unavailable", err)
			}
			return result
		}
		before := readPredecessors()
		if err := runner.UpProductionApprovalActivationProfile(ctx); err != nil {
			t.Fatal("native activation successor install refused", err)
		}
		if err := runner.UpProductionApprovalActivationProfile(ctx); err != nil {
			t.Fatal("native successor idempotency refused", err)
		}
		if before != readPredecessors() {
			t.Fatal("successor modified predecessor catalog")
		}
		pin, err := migrations.ApprovalActivationProfileChecksum()
		if err != nil {
			t.Fatal(err)
		}
		connectorPin, err := migrations.ConnectorMaintenanceProfileChecksum()
		if err != nil {
			t.Fatal(err)
		}
		approvalPin := migrations.ApprovalMaintenanceProfileChecksum()
		t.Run("catalog privacy and inactive registration", func(t *testing.T) {
			var valid bool
			if err := f.owner.QueryRow(ctx, `SELECT zasp_approval_activation_v1.catalog_ready($1)
 AND NOT zasp_approval_activation_v1.catalog_ready($2)
 AND NOT EXISTS(SELECT 1 FROM zasp_approval_activation_v1.organizations)
 AND NOT EXISTS(SELECT 1 FROM zasp_approval_maintenance.registration WHERE active)
 AND NOT EXISTS(SELECT 1 FROM pg_class c WHERE c.relnamespace='zasp_approval_activation_v1'::regnamespace AND c.relkind='r' AND NOT(c.relrowsecurity AND c.relforcerowsecurity))
 AND NOT has_function_privilege('zasp_approval_maintenance_worker','zasp_approval_activation_v1.activate_controlled_organization(text,text,text,text,text,text,text,bigint,bigint,bigint)','EXECUTE')
 AND NOT has_function_privilege('zasp_temporal_executor','zasp_approval_activation_v1.activate_controlled_organization(text,text,text,text,text,text,text,bigint,bigint,bigint)','EXECUTE')
 AND has_function_privilege('zasp_temporal_executor','zasp_approval_activation_v1.admit_with_origin(text,jsonb)','EXECUTE')`, pin, strings.Repeat("0", 64)).Scan(&valid); err != nil || !valid {
				t.Fatal("native privacy/inactive fences failed", err)
			}
		})
		t.Run("genuine revoked capture stays inactive", func(t *testing.T) {
			var valid bool
			if err := f.owner.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(x.status='captured_inactive' AND x.delegation IS NOT NULL AND NOT zasp_approval_activation_v1.eligible(x)) FROM zasp_approval_maintenance.origins x WHERE x.run_id=$1`, complete).Scan(&valid); err != nil || !valid {
				t.Fatal("genuine revoked capture was promoted", err)
			}
		})
		t.Run("wrong pins roll back both families", func(t *testing.T) {
			var store, model string
			var desired, applied, generation int64
			if err := f.owner.QueryRow(ctx, `SELECT store_id,model_id,desired,applied,generation FROM zasp_authorization79.organizations WHERE organization_id=$1`, f.o).Scan(&store, &model, &desired, &applied, &generation); err != nil {
				t.Fatal(err)
			}
			for _, wrong := range []int{0, 1, 2} {
				pins := []string{pin, connectorPin, approvalPin}
				pins[wrong] = strings.Repeat("0", 64)
				tx, err := f.owner.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				var raw json.RawMessage
				err = tx.QueryRow(ctx, `SELECT zasp_approval_activation_v1.activate_controlled_organization($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, f.o, pins[0], pins[1], pins[2], store, model, strings.Repeat("a", 64), desired, applied, generation).Scan(&raw)
				var native *pgconn.PgError
				refused := errors.As(err, &native) && native.Code == "42501"
				if err := tx.Rollback(ctx); err != nil {
					t.Fatal(err)
				}
				if !refused {
					t.Fatal("wrong combined source pin accepted")
				}
			}
			var unchanged bool
			if err := f.owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_approval_activation_v1.organizations) AND NOT EXISTS(SELECT 1 FROM zasp_approval_maintenance.projection_activations) AND NOT EXISTS(SELECT 1 FROM zasp_connector_maintenance.projection_activations) AND NOT EXISTS(SELECT 1 FROM zasp_approval_maintenance.registration WHERE active) AND NOT EXISTS(SELECT 1 FROM zasp_connector_maintenance.registration WHERE active) AND EXISTS(SELECT 1 FROM zasp_authorization79.organizations WHERE organization_id=$1 AND(desired,applied,generation)=($2,$3,$4))`, f.o, desired, applied, generation).Scan(&unchanged); err != nil || !unchanged {
				t.Fatal("refused activation mutated durable families", err)
			}
		})
		t.Run("own catalog drift fails closed and rollback restores", func(t *testing.T) {
			for _, ddl := range []string{`ALTER TABLE zasp_approval_activation_v1.organizations ADD COLUMN unexpected text`, `GRANT USAGE ON SCHEMA zasp_approval_activation_v1 TO zasp_security_agent_api`, `CREATE INDEX unexpected_activation_index ON zasp_approval_activation_v1.organizations(store_id)`} {
				tx, err := f.owner.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = tx.Exec(ctx, ddl); err != nil {
					_ = tx.Rollback(ctx)
					t.Fatal(err)
				}
				var ready bool
				err = tx.QueryRow(ctx, `SELECT zasp_approval_activation_v1.catalog_ready($1)`, pin).Scan(&ready)
				if rollbackErr := tx.Rollback(ctx); rollbackErr != nil {
					t.Fatal(rollbackErr)
				}
				if err != nil || ready {
					t.Fatal("successor catalog drift accepted", err)
				}
			}
			var ready bool
			if err := f.owner.QueryRow(ctx, `SELECT zasp_approval_activation_v1.catalog_ready($1)`, pin).Scan(&ready); err != nil || !ready {
				t.Fatal("catalog rollback did not restore readiness", err)
			}
		})
		// Actual runtime login must not gain operator activation via SET ROLE.
		t.Run("executor cannot invoke operator activation", func(t *testing.T) {
			config := f.owner.Config().Copy()
			config.User = "finding78_executor"
			conn, err := pgx.ConnectConfig(ctx, config)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close(context.Background())
			if _, err = conn.Exec(ctx, `SET ROLE zasp_temporal_executor`); err != nil {
				t.Fatal(err)
			}
			var raw json.RawMessage
			err = conn.QueryRow(ctx, `SELECT zasp_approval_activation_v1.activate_controlled_organization($1,$2,$3,$4,'','','',1,1,1)`, f.o, pin, connectorPin, approvalPin).Scan(&raw)
			var native *pgconn.PgError
			if !errors.As(err, &native) || native.Code != "42501" {
				t.Fatal("executor obtained operator activation", err)
			}
		})
	}, true, 3)
}
