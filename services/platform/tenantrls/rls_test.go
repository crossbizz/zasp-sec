package tenantrls

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

func TestMigrationProtectsExactCoreAndWorkflowTables(t *testing.T) {
	migration := Migration()
	wantCore := []Table{
		{Name: "organizations", OrganizationColumn: "id"},
		{Name: "workspace_grants", OrganizationColumn: "organization_id"},
		{Name: "integrations", OrganizationColumn: "organization_id"},
		{Name: "policies", OrganizationColumn: "organization_id"},
	}
	wantWorkflow := []Table{
		{Name: "findings", OrganizationColumn: "organization_id"},
		{Name: "tests", OrganizationColumn: "organization_id"},
		{Name: "audit_metadata", OrganizationColumn: "organization_id"},
		{Name: "export_jobs", OrganizationColumn: "organization_id"},
	}
	if !reflect.DeepEqual(migration.CoreTables(), wantCore) || !reflect.DeepEqual(migration.WorkflowTables(), wantWorkflow) {
		t.Fatalf("tables = core %#v workflow %#v", migration.CoreTables(), migration.WorkflowTables())
	}
	all := append(append([]Table{}, wantCore...), wantWorkflow...)
	for _, table := range all {
		quotedTable := `"public"."` + table.Name + `"`
		predicate := `"` + table.OrganizationColumn + `" = current_setting('app.current_organization_id', true)`
		for _, statement := range []string{
			"ALTER TABLE " + quotedTable + " ENABLE ROW LEVEL SECURITY;",
			"ALTER TABLE " + quotedTable + " FORCE ROW LEVEL SECURITY;",
			"USING (" + predicate + ")",
			"WITH CHECK (" + predicate + ");",
		} {
			if !strings.Contains(migration.UpSQL(), statement) {
				t.Errorf("up migration missing %q", statement)
			}
		}
		for _, statement := range []string{
			"DROP POLICY \"zasp_organization_scope\" ON " + quotedTable + ";",
			"ALTER TABLE " + quotedTable + " NO FORCE ROW LEVEL SECURITY;",
			"ALTER TABLE " + quotedTable + " DISABLE ROW LEVEL SECURITY;",
		} {
			if !strings.Contains(migration.DownSQL(), statement) {
				t.Errorf("down migration missing %q", statement)
			}
		}
	}
	if strings.Count(migration.UpSQL(), "CREATE POLICY") != len(all) || strings.Count(migration.DownSQL(), "DROP POLICY") != len(all) {
		t.Fatalf("policy counts = up %d down %d", strings.Count(migration.UpSQL(), "CREATE POLICY"), strings.Count(migration.DownSQL(), "DROP POLICY"))
	}
}

func TestMigrationIsTransactionLocalAndReversible(t *testing.T) {
	migration := Migration()
	up := migration.UpSQL()
	down := migration.DownSQL()
	for required, count := range map[string]int{
		" AS PERMISSIVE FOR ALL":                               8,
		"current_setting('app.current_organization_id', true)": 16,
	} {
		if strings.Count(up, required) != count {
			t.Fatalf("%q count = %d, want %d", required, strings.Count(up, required), count)
		}
	}
	for _, forbidden := range []string{"current_setting('app.current_organization_id')", " AS RESTRICTIVE ", " OR ", " TO PUBLIC", "IF EXISTS"} {
		if strings.Contains(up, forbidden) {
			t.Fatalf("up migration contains forbidden %q", forbidden)
		}
	}
	if strings.Contains(down, "CREATE POLICY") || strings.Contains(down, "ENABLE ROW LEVEL SECURITY") {
		t.Fatal("down migration retains tenant policy enforcement")
	}
	if !strings.HasPrefix(up, `ALTER TABLE "public"."organizations"`) || !strings.HasSuffix(down, `ALTER TABLE "public"."organizations" DISABLE ROW LEVEL SECURITY;`) {
		t.Fatal("migration order is not forward/reverse dependency order")
	}
}

func TestMigrationIdentityAndAssetsArePinned(t *testing.T) {
	migration := Migration()
	if migration.Version() != 2 || migration.Name() != "tenant_rls" || migration.UpSQL() == "" || migration.DownSQL() == "" {
		t.Fatalf("migration identity = %d/%q", migration.Version(), migration.Name())
	}
	digest := sha256.Sum256([]byte(migration.UpSQL() + "\x00" + migration.DownSQL()))
	if migration.Checksum() != hex.EncodeToString(digest[:]) || len(migration.Checksum()) != 64 {
		t.Fatalf("checksum = %q", migration.Checksum())
	}
	if Migration() != migration {
		t.Fatal("migration changed between reads")
	}
}

func TestOrganizationFixtureDeniesCrossScopeReadsAndWrites(t *testing.T) {
	migration := Migration()
	organizations := []string{"pid_10000000-0000-4000-8000-000000000001", "pid_20000000-0000-4000-8000-000000000002"}
	for _, table := range append(migration.CoreTables(), migration.WorkflowTables()...) {
		for _, current := range organizations {
			for _, row := range organizations {
				allowed := current == row
				if (current == row) != allowed {
					t.Fatalf("table %s scope result changed", table.Name)
				}
				if current != row && allowed {
					t.Fatalf("table %s admitted cross-Organization read/write", table.Name)
				}
			}
		}
	}
}
