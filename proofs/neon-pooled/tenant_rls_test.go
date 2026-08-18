package main

import (
	"strings"
	"testing"

	platformrls "github.com/zasp-ai/zasp-sec/services/platform/tenantrls"
)

func TestRenderTenantRLSAssetsUsesOnlyExactOwnedSchema(t *testing.T) {
	assets, err := renderTenantRLSAssets("zasp_m145_0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{assets.up, assets.down} {
		if strings.Contains(value, `"public"`) || !strings.Contains(value, `"zasp_m145_0123456789abcdef"`) {
			t.Fatalf("rendered asset retained wrong schema: %q", value)
		}
	}
	if assets.schema != "zasp_m145_0123456789abcdef" || assets.up == assets.down {
		t.Fatalf("assets = %#v", assets)
	}
	for _, invalid := range []string{"", "public", "zasp_m145_", "zasp_m145_0123456789abcdeg", "zasp_m145_0123456789abcdef_extra", `zasp_m145_0123"`} {
		if _, err := renderTenantRLSAssets(invalid); err == nil {
			t.Fatalf("invalid schema %q accepted", invalid)
		}
	}
}

func TestTenantRLSFixtureTablesMatchProductMigration(t *testing.T) {
	migration := platformrls.Migration()
	want := append(migration.CoreTables(), migration.WorkflowTables()...)
	got := tenantRLSTables()
	if len(got) != 8 || len(got) != len(want) {
		t.Fatalf("table counts = got %d want %d", len(got), len(want))
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("table %d = %#v, want %#v", index, got[index], want[index])
		}
	}
}

func TestTenantRLSSuccessOutputIsFixed(t *testing.T) {
	if tenantRLSSuccessSummary != "Neon tenant isolation passed: tables=8 cross_reads_denied=true cross_writes_denied=true down=true cleanup=true." {
		t.Fatalf("success summary = %q", tenantRLSSuccessSummary)
	}
	for _, failure := range []error{errTenantRLSConfiguration, errTenantRLSDatabase, errTenantRLSIsolation, errTenantRLSCleanup} {
		if failure == nil || strings.Contains(failure.Error(), "postgres") || strings.Contains(failure.Error(), "organization") {
			t.Fatalf("unsafe fixed failure = %v", failure)
		}
	}
}
