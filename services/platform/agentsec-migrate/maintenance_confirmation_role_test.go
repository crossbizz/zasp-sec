package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type maintenanceConfirmationTransaction struct {
	authority, committed, rolled bool
	deny, uncertain              bool
	reads                        int
	statement                    string
	arguments                    []any
}

func (x *maintenanceConfirmationTransaction) QueryRow(_ context.Context, q string, args ...any) pgx.Row {
	x.reads++
	x.statement = q
	x.arguments = args
	if !x.authority {
		return releaseReadinessErrorRow{}
	}
	return scriptedPrincipalRow{value: !x.deny}
}
func (x *maintenanceConfirmationTransaction) Exec(_ context.Context, q string, _ ...any) (pgconn.CommandTag, error) {
	if q != "SET LOCAL ROLE zasp_discovery_authority" {
		return pgconn.CommandTag{}, errors.New("unexpected role command")
	}
	x.authority = true
	return pgconn.NewCommandTag("SET"), nil
}
func (x *maintenanceConfirmationTransaction) Commit(context.Context) error {
	x.committed = true
	if x.uncertain {
		return errors.New("private commit detail")
	}
	return nil
}
func (x *maintenanceConfirmationTransaction) Rollback(context.Context) error {
	x.rolled = true
	return nil
}

func TestMaintenanceConfirmationUsesActualBoundedAuthorityPath(t *testing.T) {
	for _, command := range []string{"up-approval-maintenance-profile", "up-connector-maintenance-profile", "up-approval-activation-profile", "up-approval-settlement-audit-profile"} {
		t.Run(command, func(t *testing.T) {
			for _, mode := range []string{"accepted", "catalog-refused", "uncertain-commit", "canceled"} {
				t.Run(mode, func(t *testing.T) {
					tx := &maintenanceConfirmationTransaction{deny: mode == "catalog-refused", uncertain: mode == "uncertain-commit"}
					plain := &maintenanceConfirmationTransaction{}
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					if mode == "canceled" {
						cancel()
					}
					begins := 0
					err := confirmForwardRelease(ctx, plain, func(context.Context) (retentionOperatorTransaction, error) { begins++; return tx, nil }, discoveryPrincipalRegistration{migration: "registered_source_login"}, []string{command})
					if plain.reads != 0 {
						t.Fatal("confirmation attempted private metadata on original NOINHERIT connection")
					}
					if mode == "canceled" {
						if err == nil || tx.committed || tx.reads != 0 {
							t.Fatal("canceled confirmation reached metadata or commit")
						}
						return
					}
					if begins != 1 || !tx.authority || tx.reads != 1 || !tx.rolled || !strings.Contains(tx.statement, "session_user=$1") || !strings.Contains(tx.statement, "catalog_ready(") || len(tx.arguments) != 2 || tx.arguments[0] != "registered_source_login" {
						t.Fatal("bounded fixed-profile authority confirmation lost original configured identity/pin")
					}
					if mode == "accepted" {
						if err != nil || !tx.committed {
							t.Fatal("confirmed metadata transaction refused")
						}
					} else if err == nil || mode == "catalog-refused" && tx.committed {
						t.Fatal("refused or uncertain confirmation succeeded")
					}
				})
			}
		})
	}
}
