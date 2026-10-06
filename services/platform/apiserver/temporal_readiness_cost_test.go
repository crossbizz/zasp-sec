package apiserver

import (
	"context"
	"encoding/json"
	"runtime"
	"testing"
)

type temporalReadinessCostDB struct {
	JSONDatabase
	calls     int
	arguments []any
}

func (d *temporalReadinessCostDB) QueryJSON(_ context.Context, query string, args ...any) (json.RawMessage, error) {
	d.calls++
	d.arguments = append([]any(nil), args...)
	return json.RawMessage(`true`), nil
}
func TestTemporalRepositoryReadinessDoesNotRenderMigrationSQL(t *testing.T) {
	db := &temporalReadinessCostDB{}
	repository := &securityAgentMultistepAdmissionRepository{database: db}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	err := repository.temporalReady(context.Background())
	runtime.ReadMemStats(&after)
	if err != nil || db.calls != 1 || len(db.arguments) != 2 {
		t.Fatalf("actual repository readiness changed: %v", err)
	}
	if db.arguments[0] != "bf5f2b8a2578c8d3c43b8edd0590c55a5eb7c48b178cca310e0ebadfc90e8eed" || db.arguments[1] != "437c678da9969a5935fe7efaa27f593fc58eaeac4e74ff434a5ed44eab2b75eb" {
		t.Fatal("actual repository readiness identities changed")
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 4<<20 {
		t.Fatalf("checksum-only API readiness rendered migration SQL: %d bytes exceed 4 MiB", allocated)
	}
}
