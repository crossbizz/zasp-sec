package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

type preciseSearchDatabase struct {
	body       json.RawMessage
	ready      json.RawMessage
	statements []string
	arguments  [][]any
}

func (database *preciseSearchDatabase) QueryJSON(_ context.Context, statement string, args ...any) (json.RawMessage, error) {
	database.statements = append(database.statements, statement)
	database.arguments = append(database.arguments, args)
	if strings.Contains(statement, "readiness(") {
		return database.ready, nil
	}
	return database.body, nil
}

func TestPreciseSearchDatabaseClaimVersionBoundary(t *testing.T) {
	for _, version := range []string{"runtime-projection-v1", "runtime-projection-v2", "runtime-projection-v3", "runtime-projection-v4", ""} {
		lease, _, _ := sessionSearchWorkerFixture(t)
		var body map[string]any
		if err := json.Unmarshal(sessionSearchLeaseJSON(t, lease), &body); err != nil {
			t.Fatal(err)
		}
		if version != "" {
			body["projection_implementation_version"] = version
		}
		payload, _ := json.Marshal(body)
		database := &preciseSearchDatabase{body: payload, ready: json.RawMessage(`true`)}
		authority, _ := newPrecisePostgresRuntimeSessionSearchAuthority(database)
		got, err := authority.Claim(context.Background(), "search-worker", "search-worker-token", 30)
		valid := version != "" && version != "runtime-projection-v4"
		if (err == nil) != valid || valid && got == nil || !valid && got != nil {
			t.Fatal("precise claim version", version, got, err)
		}
		if len(database.statements) != 2 || database.statements[0] != `SELECT to_jsonb(zasp_production_runtime_precision_readiness($1,$2) AND zasp_runtime_principal_ready('zasp_runtime_index_worker'))` || database.statements[1] != `SELECT COALESCE(zasp_runtime_precise_search_claim($1,$2,$3),'null'::jsonb)` {
			t.Fatal("precision routing", database.statements)
		}
	}
}

func TestPreciseSearchDatabaseRefusesReadinessDrift(t *testing.T) {
	for _, ready := range []string{`false`, `null`, `{"ready":true}`, `true false`} {
		database := &preciseSearchDatabase{ready: json.RawMessage(ready), body: json.RawMessage(`null`)}
		authority, _ := newPrecisePostgresRuntimeSessionSearchAuthority(database)
		if got, err := authority.Claim(context.Background(), "search-worker", "search-worker-token", 30); err == nil || got != nil || len(database.statements) != 1 {
			t.Fatal("failed precision authority fell back", ready, err, database.statements)
		}
	}
}

func TestPreciseSearchDatabaseRejectsForeignLeaseCapability(t *testing.T) {
	lease, _, _ := sessionSearchWorkerFixture(t)
	lease.indexName = "zasp-runtime-sessions-v2"
	database := &preciseSearchDatabase{ready: json.RawMessage(`true`)}
	precise, _ := newPrecisePostgresRuntimeSessionSearchAuthority(database)
	old, _ := newConfiguredPostgresRuntimeSessionSearchAuthority(database, "zasp-runtime-sessions-v2")
	for _, authority := range []*postgresRuntimeSessionSearchAuthority{precise, old} {
		if authority == old {
			lease.projectionImplementationVersion = "runtime-projection-v3"
		}
		if _, err := authority.Heartbeat(context.Background(), lease, "search-worker", "search-worker-token", 30); err == nil || len(database.statements) != 0 {
			t.Fatal("foreign lease heartbeat reached database", err, database.statements)
		}
		if err := authority.Finish(context.Background(), lease, "search-worker", "search-worker-token", "indexed", lease.DocumentIDs, 0); err == nil || len(database.statements) != 0 {
			t.Fatal("foreign lease finish reached database", err, database.statements)
		}
	}
}
