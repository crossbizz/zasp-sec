package migrations

import (
	"strings"
	"testing"
)

func TestProductionWorkflowCompatibilityPinsLatestWorkflowWrites(t *testing.T) {
	metadata := ProductionWorkflowCompatibility()
	if metadata.Version() != 31 || metadata.Name() != "production_workflow_compatibility" || len(metadata.Checksum()) != 64 || len(ProductionWorkflowCompatibilitySemanticFingerprint()) != 64 {
		t.Fatalf("metadata=(%d,%q,%q) fingerprint=%q", metadata.Version(), metadata.Name(), metadata.Checksum(), ProductionWorkflowCompatibilitySemanticFingerprint())
	}
	up := metadata.UpSQL()
	for _, required := range []string{
		"production_approval_notification prerequisite rejected",
		"later_release.\"version\" > 31",
		"later.\"version\">31",
		"zasp_production_workflow_compatibility_security_ready",
		"zasp_production_workflow_compatibility_readiness",
		"ALTER FUNCTION public.zasp_production_approval_notification_readiness(text,text) RENAME TO zasp_production_approval_notification_readiness_v30",
	} {
		if !strings.Contains(up, required) {
			t.Fatalf("v31 missing %q", required)
		}
	}
	if strings.Contains(up, "later_release.\"version\" > 30") || strings.Contains(up, "later.\"version\">30") {
		t.Fatal("v31 retained a stale release fence")
	}
	down := metadata.DownSQL()
	for _, required := range []string{
		"later_release.\"version\" > 28",
		"later.\"version\">28",
		"ALTER FUNCTION public.zasp_production_approval_notification_readiness_v30(text,text) RENAME TO zasp_production_approval_notification_readiness",
	} {
		if !strings.Contains(down, required) {
			t.Fatalf("v31 down missing %q", required)
		}
	}
}
