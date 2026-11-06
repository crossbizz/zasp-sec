package migrations

import (
	"context"
	"testing"
)

// Actual installer dispatch against the shared permission-boundary double.
// PostgreSQL/NOINHERIT equivalence remains mandatory native acceptance.
func TestOptionalEgressInstallerNoInheritRoleWindows(t *testing.T) {
	for _, recipe := range []string{"normal", "audit"} {
		for _, incoming := range []string{"none", "registered_source_login"} {
			t.Run(recipe+"/"+incoming, func(t *testing.T) {
				tx := newMaintenanceRoleTransaction(incoming)
				runner, err := NewRunner(maintenanceRoleDatabase{tx})
				if err != nil {
					t.Fatal(err)
				}
				install := runner.UpProductionOptionalEgressProfile
				if recipe == "audit" {
					install = runner.UpProductionOptionalEgressAuditProfile
				}
				if err = install(context.Background()); err != nil {
					t.Fatalf("legitimate NOINHERIT optional-egress installer refused: %v", err)
				}
				if !tx.committed || tx.rolledBack || tx.ownerDDL != 1 || tx.restores != 1 {
					t.Fatal("optional-egress installation omitted exact restored source-owner bootstrap or commit")
				}
			})
		}
	}
}
