package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestCalibrationExportWorkerWritesPinnedJSONL(t *testing.T) {
	ids := make([]string, 4)
	for i := range ids {
		id, err := domain.NewProductID()
		if err != nil {
			t.Fatal(err)
		}
		ids[i] = id.String()
	}
	const lease = "650117e0-0118-4af3-9f20-c721b64dcbe0"
	driver := &complianceMemoryDriver{objects: map[string]artifactstore.DriverObject{}}
	store, err := artifactstore.NewExport(driver, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	db := combinedE2ERecoveryDatabaseFunc(func(ctx context.Context, q string, args ...any) (json.RawMessage, error) {
		calls++
		if args[len(args)-2] != migrations.ComplianceChecksum() || args[len(args)-1] != migrations.ComplianceFingerprint() {
			t.Fatal("worker release pin")
		}
		if calls == 1 {
			if len(args) != 2 || !strings.Contains(q, "NULL,NULL,NULL,NULL,$1,$2") {
				t.Fatal("claim", q)
			}
			return json.Marshal(map[string]any{"organization_id": ids[0], "workspace_id": ids[1], "environment_id": ids[2], "id": ids[3], "lease": lease, "snapshot": []any{map[string]any{"rule_id": "injection.tool_call", "threat_probability": 0.2, "label": "mark_fp"}}})
		}
		if len(args) != 6 || len(driver.objects) != 1 || args[0] != lease || !strings.Contains(q, "$4,$5,$6") {
			t.Fatal("receipt", q)
		}
		for _, obj := range driver.objects {
			sum := sha256.Sum256(obj.Body)
			if args[1] != obj.VersionID || args[2] != hex.EncodeToString(sum[:]) || args[3] != len(obj.Body) || obj.MediaType != "application/x-ndjson" || !strings.Contains(string(obj.Body), "zasp.calibration.v1") || strings.Count(string(obj.Body), "\n") != 2 {
				t.Fatal("invalid export receipt")
			}
		}
		return json.RawMessage("true"), nil
	})
	p := complianceExportProcessor{authority: newPostgresComplianceExportAuthority(db), store: store}
	if err := p.exportCalibration(context.Background()); err != nil || calls != 2 {
		t.Fatal(err, calls)
	}
}
