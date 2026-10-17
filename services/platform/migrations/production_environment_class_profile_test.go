package migrations

import (
	"context"
	"strings"
	"testing"
)

// These exercise application installer transaction boundaries. Native installed
// owner/ACL/profile behavior remains a separately mandatory acceptance group.
func TestEnvironmentClassInstallerPreservesParentsAndTransactionalAdmission(t *testing.T) {
	for _, mode := range []string{"normal-fresh", "audit-fresh", "normal-existing", "audit-existing", "parent-refused", "catalog-refused"} {
		t.Run(mode, func(t *testing.T) {
			present := strings.Contains(mode, "existing") || mode == "catalog-refused"
			admission, catalog := mode != "parent-refused", mode != "catalog-refused"
			tx := &fakeTransaction{rows: maintenanceRoleAdmissionRows([]Row{fakeRow{values: []any{admission}}, fakeRow{values: []any{present}}, fakeRow{values: []any{true}}, fakeRow{values: []any{catalog}}, fakeRow{values: []any{true}}})}
			db := &fakeDatabase{transaction: tx}
			r, e := NewRunner(db)
			if e != nil {
				t.Fatal("installer setup unavailable")
			}
			var install func(context.Context) error
			if strings.HasPrefix(mode, "audit") {
				capability, ok := any(r).(interface{ UpProductionEnvironmentClassAuditProfile(context.Context) error })
				if !ok {
					t.Fatal("actual Audit-parent environment classification installer absent")
				}
				install = capability.UpProductionEnvironmentClassAuditProfile
			} else {
				capability, ok := any(r).(interface{ UpProductionEnvironmentClassProfile(context.Context) error })
				if !ok {
					t.Fatal("actual normal-parent environment classification installer absent")
				}
				install = capability.UpProductionEnvironmentClassProfile
			}
			err := install(context.Background())
			events := strings.Join(db.events, "\n")
			if !admission || !catalog {
				if err == nil || strings.Contains(events, "commit") || !strings.Contains(events, "rollback") {
					t.Fatal("refused predecessor or catalog committed installation")
				}
				return
			}
			if err != nil || !strings.Contains(events, "commit") || strings.Contains(events, "rollback") {
				t.Fatal("admitted exact supplementary installation did not commit")
			}
			if strings.Contains(events, "CREATE SCHEMA zasp_environment_class_v1") == present {
				t.Fatal("existing profile was overwritten or fresh profile missing")
			}
			if strings.Contains(events, "ALTER FUNCTION zasp_authorization") || strings.Contains(events, "ALTER TABLE public.") || strings.Contains(events, "GRANT EXECUTE ON FUNCTION zasp_authorization79.touch") {
				t.Fatal("installation rewrote immutable parent authority")
			}
		})
	}
}
