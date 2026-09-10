package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Opt-in characterization experiment. This does not add a production gate:
// there is no HTTP load, concurrent writer, or long-lived snapshot in this run.
// The database keeps its default autovacuum settings. No explicit VACUUM,
// planner override, sequence hint, or cache-warming count is issued.
func TestReconciliationRetirementAutovacuumDiagnostic(t *testing.T) {
	if os.Getenv("ZASP_RECONCILIATION_MAINTENANCE_DIAGNOSTIC") != "1" {
		t.Skip("set ZASP_RECONCILIATION_MAINTENANCE_DIAGNOSTIC=1 for the bounded default-autovacuum experiment")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 280*time.Second)
	defer cancel()
	admin, runner := reconciliationLanePlanPredecessor(t, ctx)
	if err := runner.UpProductionReconciliationLanePlan(ctx); err != nil {
		t.Fatal(err)
	}
	config := admin.Config().Copy()
	config.User = "invocation_discovery_worker"
	worker, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close(context.Background())
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
	if err != nil {
		t.Fatal(err)
	}
	repository := &ConnectorRepository{database: database}
	identity := fixtureRequestIdentity(t)
	var settings []byte
	if err := admin.QueryRow(ctx, `SELECT json_build_object('autovacuum',current_setting('autovacuum'),'naptime',current_setting('autovacuum_naptime'),'vacuum_threshold',current_setting('autovacuum_vacuum_threshold'),'vacuum_scale_factor',current_setting('autovacuum_vacuum_scale_factor'),'table_options',reloptions) FROM pg_class WHERE oid='zasp_connector_effect_lane_scopes'::regclass`).Scan(&settings); err != nil {
		t.Fatal(err)
	}
	t.Logf("default maintenance settings=%s", settings)
	plan := func(stage string) {
		t.Helper()
		var raw []byte
		if err := admin.QueryRow(ctx, `EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) SELECT provider,operation,organization_id,workspace_id,environment_id FROM zasp_connector_effect_lane_scopes ORDER BY provider,operation,organization_id,workspace_id,environment_id LIMIT 25`).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var decoded any
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s raw_rows=%v heap_fetches=%v reads=%v hits=%v execution_ms=%v", stage, maxJSONPlanMetric(decoded, "Actual Rows"), maxJSONPlanMetric(decoded, "Heap Fetches"), maxJSONPlanMetric(decoded, "Shared Read Blocks"), maxJSONPlanMetric(decoded, "Shared Hit Blocks"), maxJSONPlanMetric(decoded, "Execution Time"))
		if maxJSONPlanMetric(decoded, "Actual Rows") != 0 {
			t.Fatalf("retired lanes visible: %s", raw)
		}
		if stage == "after-autovacuum" && (maxJSONPlanMetric(decoded, "Heap Fetches") != 0 || maxJSONPlanMetric(decoded, "Shared Read Blocks")+maxJSONPlanMetric(decoded, "Shared Hit Blocks") > 2048) {
			t.Fatalf("maintenance left excessive physical work: %s", raw)
		}
	}
	for cycle := 1; cycle <= 2; cycle++ {
		var prior int64
		if err := admin.QueryRow(ctx, `SELECT autovacuum_count FROM pg_stat_all_tables WHERE relid='zasp_connector_effect_lane_scopes'::regclass`).Scan(&prior); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(ctx, `INSERT INTO zasp_connector_effects(organization_id,workspace_id,environment_id,id,integration_id,provider,operation,idempotency_key,request_digest,status,attempt,available_at,updated_at)
		 SELECT $1,$2,$3,'pid_'||substr(hash,1,8)||'-'||substr(hash,9,4)||'-4'||substr(hash,14,3)||'-8'||substr(hash,18,3)||'-'||substr(hash,21,12),$4,'nango:retire'||lpad(ordinal::text,6,'0'),'bind','retirement-diagnostic-'||$5||'-'||ordinal,digest(hash,'sha256'),'unknown',0,transaction_timestamp()-interval '1 minute',transaction_timestamp()-interval '1 minute'
		 FROM (SELECT ordinal,md5($5||'-'||ordinal::text) hash FROM generate_series(1,100000) ordinal) generated`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), invocationIntegration, fmt.Sprint(cycle)); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(ctx, `ANALYZE zasp_connector_effects; ANALYZE zasp_connector_effect_lane_scopes; ANALYZE zasp_connector_oauth_attempts`); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(ctx, `UPDATE zasp_connector_effects SET status='failed',last_error_code='provider_access_denied',resolved_at=transaction_timestamp(),updated_at=transaction_timestamp() WHERE status='unknown'`); err != nil {
			t.Fatal(err)
		}
		retired := time.Now()
		// Read the server clock only after the retirement statement has committed.
		// A vacuum during insertion/ANALYZE must not qualify as this cleanup.
		var retiredAt time.Time
		if err := admin.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&retiredAt); err != nil {
			t.Fatal(err)
		}
		plan("before-autovacuum")
		durations := make([]time.Duration, 0, 100)
		for i := 0; i < 100; i++ {
			start := time.Now()
			items, err := repository.ClaimReconciliation(ctx, "maintenance-diagnostic", 30, 25)
			if err != nil || len(items) != 0 {
				t.Fatalf("empty claim rows=%d error=%v", len(items), err)
			}
			durations = append(durations, time.Since(start))
		}
		sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
		t.Logf("cycle=%d serial registered-worker claim samples=100 p50=%s p95=%s p99=%s max=%s; this is not API/load p95", cycle, durations[49], durations[94], durations[98], durations[99])
		for {
			var count, dead int64
			var vacuumAfterRetirement bool
			if err := admin.QueryRow(ctx, `SELECT autovacuum_count,n_dead_tup,COALESCE(last_autovacuum>$1,false) FROM pg_stat_all_tables WHERE relid='zasp_connector_effect_lane_scopes'::regclass`, retiredAt).Scan(&count, &dead, &vacuumAfterRetirement); err != nil {
				t.Fatal(err)
			}
			if count > prior && dead == 0 && vacuumAfterRetirement {
				t.Logf("cycle=%d actual post-retirement autovacuum observed after=%s count=%d dead=%d", cycle, time.Since(retired), count, dead)
				break
			}
			select {
			case <-ctx.Done():
				t.Fatalf("maintenance not observed count=%d prior=%d dead=%d vacuum_after_retirement=%t: %v", count, prior, dead, vacuumAfterRetirement, ctx.Err())
			case <-time.After(time.Second):
			}
		}
		plan("after-autovacuum")
	}
}
