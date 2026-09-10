package apiserver

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestReconciliationMaintenanceActualAPIReadOnlyStatistics(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, runner := reconciliationLanePlanPredecessor(t, ctx)
	if err := runner.UpProductionReconciliationLanePlan(ctx); err != nil {
		t.Fatal(err)
	}
	config := admin.Config().Copy()
	config.User = "invocation_discovery_api"
	api, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close(context.Background())
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewConnectorRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `CREATE SCHEMA unrelated; CREATE TABLE unrelated.zasp_connector_effects(secret text); INSERT INTO unrelated.zasp_connector_effects SELECT 'private' FROM generate_series(1,10); ANALYZE unrelated.zasp_connector_effects`); err != nil {
		t.Fatal(err)
	}
	snapshot, err := repository.ReconciliationMaintenance(ctx)
	if err != nil || !snapshot.Valid() || !snapshot.Tables[0].AutovacuumEnabled || !snapshot.Tables[1].AutovacuumEnabled || snapshot.Tables[1].LiveTuples != 0 {
		t.Fatalf("actual API-role fixed statistics=%+v error=%v", snapshot, err)
	}
	var directRead bool
	if err := api.QueryRow(ctx, `SELECT has_table_privilege(current_user,'public.zasp_connector_effects','SELECT')`).Scan(&directRead); err != nil || directRead {
		t.Fatalf("monitor requires customer-row grant read=%t error=%v", directRead, err)
	}
	if _, err := admin.Exec(ctx, `ALTER TABLE public.zasp_connector_effect_lane_scopes SET(autovacuum_enabled=false)`); err != nil {
		t.Fatal(err)
	}
	snapshot, err = repository.ReconciliationMaintenance(ctx)
	if err != nil || snapshot.Tables[0].AutovacuumEnabled || !snapshot.Tables[1].AutovacuumEnabled {
		t.Fatalf("table disabled not reported=%+v error=%v", snapshot, err)
	}
	if _, err := admin.Exec(ctx, `ALTER TABLE public.zasp_connector_effect_lane_scopes RESET(autovacuum_enabled); SET track_counts=off`); err != nil {
		t.Fatal(err)
	}
	adminDatabase, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: admin})
	if _, err := (&ConnectorRepository{database: adminDatabase}).ReconciliationMaintenance(ctx); err == nil {
		t.Fatal("disabled statistics returned healthy-looking zeros")
	}
	if _, err := admin.Exec(ctx, `RESET track_counts; ALTER TABLE public.zasp_connector_effect_lane_scopes RENAME TO hidden_lane_scopes`); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.ReconciliationMaintenance(ctx); err == nil {
		t.Fatal("missing monitored table accepted")
	}
}

func TestReconciliationMaintenancePinnedSnapshotDebt(t *testing.T) {
	if os.Getenv("ZASP_RECONCILIATION_MAINTENANCE_DIAGNOSTIC") != "1" {
		t.Skip("enable the isolated default-autovacuum proof explicitly")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	admin, runner := reconciliationLanePlanPredecessor(t, ctx)
	if err := runner.UpProductionReconciliationLanePlan(ctx); err != nil {
		t.Fatal(err)
	}
	config := admin.Config().Copy()
	config.User = "invocation_discovery_api"
	api, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close(context.Background())
	database, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
	repository, err := NewConnectorRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	pinner, err := pgx.ConnectConfig(ctx, admin.Config())
	if err != nil {
		t.Fatal(err)
	}
	defer pinner.Close(context.Background())
	pinned, err := pinner.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer pinned.Rollback(context.Background())
	var count int
	if err := pinned.QueryRow(ctx, `SELECT count(*) FROM zasp_connector_effect_lane_scopes`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	if _, err := admin.Exec(ctx, `INSERT INTO zasp_connector_effects(organization_id,workspace_id,environment_id,id,integration_id,provider,operation,idempotency_key,request_digest,status,attempt,available_at,updated_at)
 SELECT $1,$2,$3,'pid_'||substr(hash,1,8)||'-'||substr(hash,9,4)||'-4'||substr(hash,14,3)||'-8'||substr(hash,18,3)||'-'||substr(hash,21,12),$4,'nango:pinned'||ordinal,'bind','pinned-maintenance-'||ordinal,digest(hash,'sha256'),'unknown',0,transaction_timestamp()-interval '1 minute',transaction_timestamp()-interval '1 minute'
 FROM (SELECT ordinal,md5('pinned'||ordinal::text) hash FROM generate_series(1,20000) ordinal) generated`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), invocationIntegration); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `ANALYZE zasp_connector_effect_lane_scopes; UPDATE zasp_connector_effects SET status='failed',last_error_code='provider_access_denied',resolved_at=transaction_timestamp(),updated_at=transaction_timestamp() WHERE status='unknown'`); err != nil {
		t.Fatal(err)
	}
	var retiredAt time.Time
	if err := admin.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&retiredAt); err != nil {
		t.Fatal(err)
	}
	wait := func(after time.Time, debt bool) {
		t.Helper()
		for {
			snapshot, err := repository.ReconciliationMaintenance(ctx)
			if err != nil {
				t.Fatal(err)
			}
			lane := snapshot.Tables[0]
			if lane.LastAutovacuum != nil && lane.LastAutovacuum.After(after) && (debt && lane.DeadTuples >= 20000 || !debt && lane.DeadTuples == 0) {
				t.Logf("actual API-role post-boundary autovacuum: pinned=%t dead_estimate=%d", debt, lane.DeadTuples)
				return
			}
			select {
			case <-ctx.Done():
				t.Fatalf("post-boundary debt=%t not observed: %+v", debt, lane)
			case <-time.After(time.Second):
			}
		}
	}
	wait(retiredAt, true)
	if err := pinned.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var releasedAt time.Time
	if err := admin.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&releasedAt); err != nil {
		t.Fatal(err)
	}
	wait(releasedAt, false)
}
