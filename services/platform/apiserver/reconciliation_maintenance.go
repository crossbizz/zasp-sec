package apiserver

import (
	"context"
	"time"
)

// These are public PostgreSQL catalog estimates, never customer-row reads.
// The production pool executes each sample as a fresh autocommit statement.
const postgresReconciliationMaintenanceSQL = `SELECT jsonb_build_object(
 'observed_at',clock_timestamp(),
 'tables',(SELECT jsonb_agg(jsonb_build_object(
   'table',s.relname,'live_tuples',s.n_live_tup,'dead_tuples',s.n_dead_tup,
   'autovacuum_enabled',current_setting('autovacuum')='on' AND COALESCE(
     (SELECT option_value::boolean FROM pg_catalog.pg_options_to_table(c.reloptions) WHERE option_name='autovacuum_enabled'),true),
   'last_autovacuum',s.last_autovacuum) ORDER BY s.relname)
  FROM pg_catalog.pg_stat_all_tables s JOIN pg_catalog.pg_class c ON c.oid=s.relid
  WHERE s.schemaname='public' AND s.relname IN ('zasp_connector_effects','zasp_connector_effect_lane_scopes')))
 WHERE current_setting('track_counts')='on'`

type ReconciliationMaintenanceTable struct {
	Table                  string
	LiveTuples, DeadTuples int64
	AutovacuumEnabled      bool
	LastAutovacuum         *time.Time
}

// Statistics resets, zero estimates and recent vacuum timestamps are not proof
// that dead tuples were reclaimed. Consumers must not label this cleanup success.
type ReconciliationMaintenanceSnapshot struct {
	ObservedAt time.Time
	Tables     [2]ReconciliationMaintenanceTable
}

func (snapshot ReconciliationMaintenanceSnapshot) Valid() bool {
	if snapshot.ObservedAt.IsZero() || snapshot.ObservedAt.Unix() <= 0 {
		return false
	}
	// Alphabetical order is fixed by the query, not supplied by a caller.
	for i, name := range []string{"zasp_connector_effect_lane_scopes", "zasp_connector_effects"} {
		row := snapshot.Tables[i]
		if row.Table != name || row.LiveTuples < 0 || row.DeadTuples < 0 || row.LastAutovacuum != nil && (row.LastAutovacuum.Unix() <= 0 || row.LastAutovacuum.After(snapshot.ObservedAt)) {
			return false
		}
	}
	return true
}

func (repository *ConnectorRepository) ReconciliationMaintenance(ctx context.Context) (ReconciliationMaintenanceSnapshot, error) {
	if !validConnectorRepository(repository, ctx) {
		return ReconciliationMaintenanceSnapshot{}, ErrRepositoryUnavailable
	}
	payload, err := repository.database.QueryJSON(ctx, postgresReconciliationMaintenanceSQL)
	if err != nil {
		return ReconciliationMaintenanceSnapshot{}, ErrRepositoryUnavailable
	}
	var wire struct {
		ObservedAt *time.Time `json:"observed_at"`
		Tables     []struct {
			Table             *string    `json:"table"`
			LiveTuples        *int64     `json:"live_tuples"`
			DeadTuples        *int64     `json:"dead_tuples"`
			AutovacuumEnabled *bool      `json:"autovacuum_enabled"`
			LastAutovacuum    *time.Time `json:"last_autovacuum"`
		} `json:"tables"`
	}
	if decodeStrictDiscovery(payload, &wire) != nil || wire.ObservedAt == nil || len(wire.Tables) != 2 {
		return ReconciliationMaintenanceSnapshot{}, ErrRepositoryUnavailable
	}
	snapshot := ReconciliationMaintenanceSnapshot{ObservedAt: *wire.ObservedAt}
	for i, row := range wire.Tables {
		if row.Table == nil || row.LiveTuples == nil || row.DeadTuples == nil || row.AutovacuumEnabled == nil {
			return ReconciliationMaintenanceSnapshot{}, ErrRepositoryUnavailable
		}
		snapshot.Tables[i] = ReconciliationMaintenanceTable{Table: *row.Table, LiveTuples: *row.LiveTuples, DeadTuples: *row.DeadTuples, AutovacuumEnabled: *row.AutovacuumEnabled, LastAutovacuum: row.LastAutovacuum}
	}
	if !snapshot.Valid() {
		return ReconciliationMaintenanceSnapshot{}, ErrRepositoryUnavailable
	}
	return snapshot, nil
}
