package apiserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestReconciliationMaintenanceRejectsUnavailableStatistics(t *testing.T) {
	const valid = `{"observed_at":"2026-09-10T18:00:00Z","tables":[{"table":"zasp_connector_effect_lane_scopes","live_tuples":1,"dead_tuples":10001,"autovacuum_enabled":false,"last_autovacuum":"2026-09-10T17:00:00Z"},{"table":"zasp_connector_effects","live_tuples":4,"dead_tuples":0,"autovacuum_enabled":true,"last_autovacuum":null}]}`
	database := &connectorCallDatabase{responses: map[string]json.RawMessage{postgresReconciliationMaintenanceSQL: json.RawMessage(valid)}}
	repository := &ConnectorRepository{database: database}
	got, err := repository.ReconciliationMaintenance(context.Background())
	if err != nil || !got.Valid() || got.Tables[1].DeadTuples != 0 || got.Tables[0].DeadTuples != 10001 || got.Tables[0].AutovacuumEnabled {
		t.Fatalf("valid zero/debt/disabled statistics=%+v error=%v", got, err)
	}
	for _, raw := range []string{
		`null`, `{}`, strings.Replace(valid, `"dead_tuples":0`, `"dead_tuples":null`, 1),
		strings.Replace(valid, `"dead_tuples":0,`, ``, 1), strings.Replace(valid, `"dead_tuples":0`, `"dead_tuples":-1`, 1),
		strings.Replace(valid, `"autovacuum_enabled":true`, `"autovacuum_enabled":null`, 1),
		strings.Replace(valid, `zasp_connector_effect_lane_scopes`, `zasp_connector_effects`, 1),
		strings.Replace(valid, `zasp_connector_effects`, `private-tenant-label`, 1),
		strings.Replace(valid, `"live_tuples":4`, `"live_tuples":4,"tenant_id":"private"`, 1),
		strings.Replace(valid, `2026-09-10T17:00:00Z`, `2026-09-11T17:00:00Z`, 1),
	} {
		database.responses[postgresReconciliationMaintenanceSQL] = json.RawMessage(raw)
		if _, err := repository.ReconciliationMaintenance(context.Background()); err == nil {
			t.Fatalf("invalid statistics accepted: %s", raw)
		}
	}
	delete(database.responses, postgresReconciliationMaintenanceSQL)
	if _, err := repository.ReconciliationMaintenance(context.Background()); err == nil {
		t.Fatal("query failure became healthy zero")
	}
}
