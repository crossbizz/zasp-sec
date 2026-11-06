package migrations

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// Grouped real-installer permission-frame model; no SQL internals simulation.
// Native catalog/current FGA/RLS and real session pagination remain release gates.
type agentReadInstallerDB struct{ tx *agentReadInstallerTx }

func (d agentReadInstallerDB) Begin(context.Context) (Transaction, error) { return d.tx, nil }

func (d agentReadInstallerDB) QueryRow(ctx context.Context, q string, args ...any) Row {
	return d.tx.QueryRow(ctx, q, args...)
}

type agentReadInstallerTx struct {
	role, user, incomingRole, incomingUser        string
	present, denyParent, denyCatalog, denyRestore bool
	committed, rolledBack                         bool
	creates                                       int
	events                                        []string
}

func (x *agentReadInstallerTx) QueryRow(_ context.Context, q string, args ...any) Row {
	x.events = append(x.events, q)
	if strings.Contains(q, "set_config('role'") {
		if x.denyRestore {
			return fakeRow{err: errors.New("restore refused")}
		}
		x.role = args[0].(string)
		x.user = x.incomingUser
		return fakeRow{values: []any{x.role}}
	}
	if strings.Contains(q, "current_user") && strings.Contains(q, "current_setting('role')") {
		return fakeRow{values: []any{x.user, x.role}}
	}
	if strings.Contains(q, "public.zasp_discovery_principal_bindings") || strings.Contains(q, "zasp_authorization80.ready(") {
		if x.user != "zasp_discovery_authority" {
			return fakeRow{err: errors.New("private parent refused")}
		}
		return fakeRow{values: []any{!x.denyParent}}
	}
	if strings.Contains(q, "to_regnamespace(") {
		return fakeRow{values: []any{x.present}}
	}
	if strings.Contains(q, "zasp_agent_read_v1.catalog_ready(") {
		return fakeRow{values: []any{!x.denyCatalog}}
	}
	return fakeRow{values: []any{true}}
}
func (x *agentReadInstallerTx) Exec(_ context.Context, q string, args ...any) error {
	x.events = append(x.events, q)
	if strings.TrimSpace(q) == "SET LOCAL ROLE zasp_discovery_authority" {
		x.user = "zasp_discovery_authority"
		x.role = x.user
		return nil
	}
	if strings.TrimSpace(q) == "SET LOCAL ROLE NONE" {
		x.user = x.incomingUser
		x.role = "none"
		return nil
	}
	if strings.Contains(q, "CREATE SCHEMA zasp_agent_read_v1") {
		if x.user != x.incomingUser {
			return errors.New("namespace not original owner frame")
		}
		x.creates++
	}
	if strings.Contains(q, "CREATE FUNCTION zasp_agent_read_v1") && x.user != "zasp_discovery_authority" {
		return errors.New("definitions not authority frame")
	}
	return nil
}
func (x *agentReadInstallerTx) Commit(context.Context) error   { x.committed = true; return nil }
func (x *agentReadInstallerTx) Rollback(context.Context) error { x.rolledBack = true; return nil }
func TestAgentReadInstallerClosedAdmission(t *testing.T) {
	for _, mode := range []string{"normal-fresh", "audit-fresh", "normal-existing", "audit-existing", "parent-refused", "catalog-refused", "restore-refused", "normal-explicit-self-role", "audit-explicit-self-role"} {
		t.Run(mode, func(t *testing.T) {
			tx := &agentReadInstallerTx{role: "none", user: "registered_source_login", incomingRole: "none", incomingUser: "registered_source_login", present: strings.Contains(mode, "existing"), denyParent: mode == "parent-refused", denyCatalog: mode == "catalog-refused", denyRestore: mode == "restore-refused"}
			if strings.Contains(mode, "explicit-self-role") {
				tx.role, tx.incomingRole = tx.incomingUser, tx.incomingUser
			}
			r, e := NewRunner(agentReadInstallerDB{tx})
			if e != nil {
				t.Fatal("runner setup unavailable")
			}
			var install func(context.Context) error
			if strings.HasPrefix(mode, "audit") {
				c, ok := any(r).(interface{ UpProductionAgentReadAuditProfile(context.Context) error })
				if !ok {
					t.Fatal("actual Audit agent-read installer absent")
				}
				install = c.UpProductionAgentReadAuditProfile
			} else {
				c, ok := any(r).(interface{ UpProductionAgentReadProfile(context.Context) error })
				if !ok {
					t.Fatal("actual normal agent-read installer absent")
				}
				install = c.UpProductionAgentReadProfile
			}
			err := install(context.Background())
			refused := tx.denyParent || tx.denyCatalog || tx.denyRestore
			if refused {
				if err == nil || tx.committed || !tx.rolledBack {
					t.Fatal("refused parent/catalog/restore committed")
				}
				if tx.denyParent && tx.creates != 0 {
					t.Fatal("owner DDL preceded parent admission")
				}
				return
			}
			if err != nil || !tx.committed || tx.rolledBack || tx.role != tx.incomingRole || tx.user != tx.incomingUser {
				t.Fatal("admitted installer did not commit and restore exact role")
			}
			if (tx.creates == 0) != tx.present {
				t.Fatal("fresh schema missing or existing profile overwritten")
			}
			for _, q := range tx.events {
				if strings.Contains(q, "CREATE OR REPLACE FUNCTION public.") || strings.Contains(q, "ALTER TABLE public.") || strings.Contains(q, "GRANT CREATE ON SCHEMA public") || strings.Contains(q, "GRANT EXECUTE ON FUNCTION zasp_authorization79.") || strings.Contains(q, "public.zasp_inventory_readiness(") {
					t.Fatal("immutable parent mutated or obsolete14 readiness used")
				}
			}
		})
	}
}
