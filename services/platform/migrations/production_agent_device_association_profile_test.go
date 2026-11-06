package migrations

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// This grouped model executes the actual installer and its transaction/frame
// choices. It does not execute SQL bodies, authenticate a gateway, or establish
// PostgreSQL/OpenFGA/runtime/installed-policy acceptance.
type agentDeviceAssociationInstallerDB struct {
	tx *agentDeviceAssociationInstallerTx
}

func (d agentDeviceAssociationInstallerDB) Begin(context.Context) (Transaction, error) {
	return d.tx, nil
}
func (d agentDeviceAssociationInstallerDB) QueryRow(c context.Context, q string, a ...any) Row {
	return d.tx.QueryRow(c, q, a...)
}

type agentDeviceAssociationInstallerTx struct {
	user, role, incomingUser, incomingRole                                                         string
	present, denyOperator, denyParent, denyRuntime, denyVariant, denyACL, denyCatalog, denyRestore bool
	committed, rolledBack                                                                          bool
	creates                                                                                        int
	events                                                                                         []string
}

func (x *agentDeviceAssociationInstallerTx) QueryRow(_ context.Context, q string, a ...any) Row {
	x.events = append(x.events, q)
	if strings.Contains(q, "set_config('role'") {
		if x.denyRestore {
			return fakeRow{err: errors.New("restore refused")}
		}
		x.role = a[0].(string)
		x.user = x.incomingUser
		return fakeRow{values: []any{x.role}}
	}
	if strings.Contains(q, "current_user") && strings.Contains(q, "current_setting('role')") {
		return fakeRow{values: []any{x.user, x.role}}
	}
	// Protected source binding and all private current-parent reads must occur
	// inside the bounded existing authority frame, not inherited source rights.
	if strings.Contains(q, "public.zasp_discovery_principal_bindings") {
		if x.user != "zasp_discovery_authority" {
			return fakeRow{err: errors.New("protected binding denied")}
		}
		return fakeRow{values: []any{!x.denyOperator}}
	}
	if strings.Contains(q, "zasp_authorization80_runtime.") {
		if x.user != "zasp_discovery_authority" {
			return fakeRow{err: errors.New("private runtime parent denied")}
		}
		return fakeRow{values: []any{!x.denyRuntime}}
	}
	if strings.Contains(q, "zasp_authorization80.runtime_profile") {
		if x.user != "zasp_discovery_authority" {
			return fakeRow{err: errors.New("private variant denied")}
		}
		return fakeRow{values: []any{!x.denyVariant}}
	}
	if strings.Contains(q, "zasp_authorization80.ready(") {
		if x.user != "zasp_discovery_authority" {
			return fakeRow{err: errors.New("private current parent denied")}
		}
		return fakeRow{values: []any{!x.denyParent}}
	}
	if strings.Contains(q, "to_regnamespace(") {
		return fakeRow{values: []any{x.present}}
	}
	if strings.Contains(q, "aclexplode(") && strings.Contains(q, "zasp_agent_device_association_v1") {
		return fakeRow{values: []any{!x.denyACL}}
	}
	if strings.Contains(q, "zasp_agent_device_association_v1.raw_seal_ready(") {
		return fakeRow{values: []any{!x.denyCatalog}}
	}
	return fakeRow{values: []any{true}}
}
func (x *agentDeviceAssociationInstallerTx) Exec(_ context.Context, q string, _ ...any) error {
	x.events = append(x.events, q)
	switch strings.TrimSpace(q) {
	case "SET LOCAL ROLE zasp_discovery_authority":
		x.user = "zasp_discovery_authority"
		x.role = x.user
		return nil
	case "SET LOCAL ROLE NONE":
		x.user = x.incomingUser
		x.role = "none"
		return nil
	}
	if strings.Contains(q, "CREATE SCHEMA zasp_agent_device_association_v1") {
		if x.user != x.incomingUser {
			return errors.New("namespace creation not original source owner")
		}
		x.creates++
	}
	if strings.Contains(q, "CREATE FUNCTION zasp_agent_device_association_v1") && x.user != "zasp_discovery_authority" {
		return errors.New("definitions not authority frame")
	}
	return nil
}
func (x *agentDeviceAssociationInstallerTx) Commit(context.Context) error {
	x.committed = true
	return nil
}
func (x *agentDeviceAssociationInstallerTx) Rollback(context.Context) error {
	x.rolledBack = true
	return nil
}
func TestAgentDeviceAssociationInstallerClosedAdmission(t *testing.T) {
	for _, mode := range []string{"normal-fresh", "audit-fresh", "normal-existing", "audit-existing", "normal-explicit-self-role", "audit-explicit-self-role", "source-operator-refused", "parent-refused", "runtime-parent-refused", "normal-wrong-parent-variant", "audit-wrong-parent-variant", "hostile-default-acl", "catalog-refused", "restore-refused"} {
		t.Run(mode, func(t *testing.T) {
			tx := &agentDeviceAssociationInstallerTx{user: "registered_source_login", incomingUser: "registered_source_login", role: "none", incomingRole: "none", present: strings.Contains(mode, "existing"), denyOperator: mode == "source-operator-refused", denyParent: mode == "parent-refused", denyRuntime: mode == "runtime-parent-refused", denyVariant: strings.Contains(mode, "wrong-parent-variant"), denyACL: mode == "hostile-default-acl", denyCatalog: mode == "catalog-refused", denyRestore: mode == "restore-refused"}
			if strings.Contains(mode, "explicit-self-role") {
				tx.role = tx.incomingUser
				tx.incomingRole = tx.role
			}
			r, err := NewRunner(agentDeviceAssociationInstallerDB{tx})
			if err != nil {
				t.Fatal("installer runner setup refused")
			}
			var install func(context.Context) error
			if strings.HasPrefix(mode, "audit") {
				selected, ok := any(r).(interface{ UpProductionAgentDeviceAssociationAuditProfile(context.Context) error })
				if !ok {
					t.Fatal("actual Audit Agent Device association installer absent")
				}
				install = selected.UpProductionAgentDeviceAssociationAuditProfile
			} else {
				selected, ok := any(r).(interface{ UpProductionAgentDeviceAssociationProfile(context.Context) error })
				if !ok {
					t.Fatal("actual Normal Agent Device association installer absent")
				}
				install = selected.UpProductionAgentDeviceAssociationProfile
			}
			err = install(context.Background())
			refused := tx.denyOperator || tx.denyParent || tx.denyRuntime || tx.denyVariant || tx.denyACL || tx.denyCatalog || tx.denyRestore
			if refused {
				if err == nil || tx.committed || !tx.rolledBack {
					t.Fatal("refused operator/parent/variant/ACL/catalog/restore committed")
				}
				if (tx.denyOperator || tx.denyParent || tx.denyRuntime || tx.denyVariant) && tx.creates != 0 {
					t.Fatal("new namespace owner DDL preceded prerequisite admission")
				}
				return
			}
			if err != nil || !tx.committed || tx.rolledBack || tx.role != tx.incomingRole || tx.user != tx.incomingUser {
				t.Fatal("valid restricted source installer lost exact incoming role or commit")
			}
			if (tx.creates == 0) != tx.present {
				t.Fatal("fresh schema missing or existing profile overwritten")
			}
			for _, q := range tx.events {
				if strings.Contains(q, "CREATE OR REPLACE FUNCTION public.") || strings.Contains(q, "ALTER TABLE public.") || strings.Contains(q, "GRANT CREATE ON SCHEMA public") || strings.Contains(q, "GRANT EXECUTE ON FUNCTION zasp_authorization80") || strings.Contains(q, "CREATE OR REPLACE FUNCTION zasp_authorization80") || strings.Contains(q, "UPDATE zasp_authorization80.runtime_profile") {
					t.Fatal("immutable native/current parent altered or granted around")
				}
			}
		})
	}
}
