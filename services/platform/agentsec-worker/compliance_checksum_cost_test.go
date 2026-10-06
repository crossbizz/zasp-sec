package main

import (
	"context"
	"encoding/json"
	"runtime"
	"testing"
)

type complianceChecksumCostDB struct {
	calls     int
	arguments []any
}

func (d *complianceChecksumCostDB) QueryJSON(_ context.Context, query string, args ...any) (json.RawMessage, error) {
	d.calls++
	d.arguments = append([]any(nil), args...)
	return json.RawMessage(`{}`), nil
}
func TestComplianceAuthorityDoesNotRebuildChecksumAncestors(t *testing.T) {
	db := &complianceChecksumCostDB{}
	authority := newPostgresComplianceExportAuthority(db)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := authority.query(context.Background(), complianceCaptureSQL, 4096, "controlled-input")
	runtime.ReadMemStats(&after)
	if err != nil || db.calls != 1 || len(db.arguments) != 3 || db.arguments[0] != "controlled-input" {
		t.Fatalf("authority call changed: %v", err)
	}
	if db.arguments[1] != "f5871c564709034eaf89f325fcb732a3f3314ecc0ff95f7a0ec99f6d674ddfc1" || db.arguments[2] != "8534cdcdce945aab8f85dce88d9bf8a01b100387490a7cefe5d51f2ae11d8ced" {
		t.Fatal("authority migration identity changed")
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 32<<20 {
		t.Fatalf("checksum-only compliance query rebuilt ancestors: %d allocated bytes exceed 32 MiB", allocated)
	}
}
