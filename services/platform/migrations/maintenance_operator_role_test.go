package migrations

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// This double models the permission boundary, not PostgreSQL internals. Real
// NOINHERIT/ACL acceptance remains mandatory in the native release guards.
type maintenanceRoleDatabase struct{ tx *maintenanceRoleTransaction }

func (d maintenanceRoleDatabase) Begin(context.Context) (Transaction, error) { return d.tx, nil }
func (d maintenanceRoleDatabase) QueryRow(context.Context, string, ...any) Row {
	return fakeRow{err: errors.New("unexpected out-of-transaction read")}
}

type maintenanceRoleTransaction struct {
	role, effective, incomingRole, incomingEffective string
	committed, rolledBack, referenced                bool
	ownerDDL, windows, restores                      int
	denyReady, denyRestore, drift                    bool
}

func (x *maintenanceRoleTransaction) QueryRow(_ context.Context, q string, args ...any) Row {
	if strings.Contains(q, "set_config('role'") {
		if x.denyRestore {
			return fakeRow{err: errors.New("restore refused")}
		}
		x.role = args[0].(string)
		x.effective = x.incomingEffective
		x.restores++
		if x.drift {
			x.effective = "unexpected_role"
		}
		return fakeRow{values: []any{x.role}}
	}
	if strings.Contains(q, "current_user") && strings.Contains(q, "current_setting('role')") {
		return fakeRow{values: []any{x.effective, x.role}}
	}
	if strings.Contains(q, "current_user") {
		return fakeRow{values: []any{x.effective}}
	}
	if strings.Contains(q, "current_setting('role')") {
		return fakeRow{values: []any{x.role}}
	}
	if strings.Contains(q, "zasp_authorization80.ready(") {
		if x.effective != "zasp_discovery_authority" {
			return fakeRow{err: errors.New("private schema permission denied")}
		}
		if x.denyReady {
			return fakeRow{values: []any{false}}
		}
	}
	if strings.Contains(q, "has_column_privilege(") && !strings.Contains(q, " AND ") {
		return fakeRow{values: []any{x.referenced}}
	}
	if strings.Contains(q, "to_regnamespace(") && !strings.Contains(q, "zasp_approval_maintenance") {
		return fakeRow{values: []any{false}}
	}
	return fakeRow{values: []any{true}}
}
func (x *maintenanceRoleTransaction) Exec(_ context.Context, q string, args ...any) error {
	if strings.TrimSpace(q) == "SET LOCAL ROLE zasp_discovery_authority" {
		x.role = "zasp_discovery_authority"
		x.effective = x.role
		x.windows++
		return nil
	}
	if strings.Contains(q, "set_config('role'") {
		if x.denyRestore {
			return errors.New("restore refused")
		}
		x.role = args[0].(string)
		x.effective = x.incomingEffective
		x.restores++
		if x.drift {
			x.effective = "unexpected_role"
		}
		return nil
	}
	if strings.Contains(q, "CREATE SCHEMA ") && !strings.Contains(q, "CREATE FUNCTION") || strings.HasPrefix(q, "GRANT REFERENCES(id)") {
		if x.role != x.incomingRole || x.effective != x.incomingEffective {
			return errors.New("source-owner DDL executed under changed role")
		}
		x.ownerDDL++
		if strings.HasPrefix(q, "GRANT REFERENCES(id)") {
			x.referenced = true
		}
	}
	return nil
}
func (x *maintenanceRoleTransaction) Commit(context.Context) error   { x.committed = true; return nil }
func (x *maintenanceRoleTransaction) Rollback(context.Context) error { x.rolledBack = true; return nil }
func newMaintenanceRoleTransaction(role string) *maintenanceRoleTransaction {
	effective := "registered_source_login"
	if role != "none" {
		effective = role
	}
	return &maintenanceRoleTransaction{role: role, effective: effective, incomingRole: role, incomingEffective: effective}
}

func TestMaintenanceInstallerNoInheritRoleWindows(t *testing.T) {
	for _, profile := range []string{"approval", "connector", "activation", "settlement"} {
		for _, incoming := range []string{"none", "registered_source_owner"} {
			t.Run(profile+"/"+incoming, func(t *testing.T) {
				tx := newMaintenanceRoleTransaction(incoming)
				r, err := NewRunner(maintenanceRoleDatabase{tx})
				if err != nil {
					t.Fatal(err)
				}
				var install func(context.Context) error
				switch profile {
				case "approval":
					install = r.UpProductionApprovalMaintenanceProfile
				case "connector":
					install = r.UpProductionConnectorMaintenance
				case "activation":
					install = r.UpProductionApprovalActivationProfile
				case "settlement":
					install = r.UpProductionApprovalSettlementAuditProfile
				}
				if err = install(context.Background()); err != nil {
					t.Fatalf("legitimate NOINHERIT operator installation refused: %v", err)
				}
				if !tx.committed || tx.rolledBack || tx.ownerDDL == 0 || tx.restores == 0 {
					t.Fatal("installation omitted restored owner DDL or transaction commit")
				}
			})
		}
	}
}
func TestMaintenanceReferenceRoleWindowsAndRollback(t *testing.T) {
	for _, mode := range []string{"none", "registered_source_owner", "parent-denied", "restore-denied", "restored-identity-drift"} {
		t.Run(mode, func(t *testing.T) {
			role := mode
			if mode != "registered_source_owner" {
				role = "none"
			}
			tx := newMaintenanceRoleTransaction(role)
			tx.denyReady = mode == "parent-denied"
			tx.denyRestore = mode == "restore-denied"
			tx.drift = mode == "restored-identity-drift"
			r, _ := NewRunner(maintenanceRoleDatabase{tx})
			err := r.withTransaction(context.Background(), func(ctx context.Context, q Transaction) error { return ensureMaintenanceOrganizationReference(ctx, q) })
			denied := tx.denyReady || tx.denyRestore || tx.drift
			if denied {
				if err == nil || tx.committed || !tx.rolledBack || tx.ownerDDL != 0 {
					t.Fatal("failed role fence continued owner DDL or committed")
				}
				return
			}
			if err != nil || !tx.committed || tx.rolledBack || tx.ownerDDL != 1 || tx.role != role || tx.effective != tx.incomingEffective || tx.restores < 2 {
				t.Fatalf("reference privilege did not preserve exact incoming role: %v", err)
			}
		})
	}
}

// Keep existing catalog refusal selection unchanged while supplying the new
// private metadata role round trip in the original transaction doubles.
func maintenanceRoleAdmissionRows(rows []Row) []Row {
	result := append([]Row{}, rows[:1]...)
	result = append(result, fakeRow{values: []any{"registered_source_login", "none"}}, fakeRow{values: []any{true}}, fakeRow{values: []any{"none"}}, fakeRow{values: []any{"registered_source_login", "none"}})
	return append(result, rows[1:]...)
}
