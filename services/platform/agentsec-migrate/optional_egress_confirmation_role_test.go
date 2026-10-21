package main

import (
	"context"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestOptionalEgressConfirmationUsesActualBoundedAuthorityPath(t *testing.T) {
	for _, command := range []string{"up-optional-egress-profile", "up-optional-egress-audit-profile"} {
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
						t.Fatal("optional-egress confirmation read private metadata through original NOINHERIT connection")
					}
					if mode == "canceled" {
						if err == nil || tx.committed || tx.reads != 0 {
							t.Fatal("canceled optional-egress confirmation reached metadata or commit")
						}
						return
					}
					pin := migrations.OptionalEgressProfileChecksum()
					if command == "up-optional-egress-audit-profile" {
						pin = migrations.OptionalEgressAuditProfileChecksum()
					}
					if begins != 1 || !tx.authority || tx.reads != 1 || !tx.rolled || !strings.Contains(tx.statement, "session_user=$1") || !strings.Contains(tx.statement, "zasp_authorization79.operator()") || !strings.Contains(tx.statement, "zasp_optional_egress_v1.catalog_ready($2)") || len(tx.arguments) != 2 || tx.arguments[0] != "registered_source_login" || tx.arguments[1] != pin {
						t.Fatal("optional-egress confirmation lost bounded authority, original operator, or exact selected parent pin")
					}
					if mode == "accepted" {
						if err != nil || !tx.committed {
							t.Fatal("accepted optional-egress metadata transaction refused")
						}
					} else if err == nil || mode == "catalog-refused" && tx.committed {
						t.Fatal("refused or uncertain optional-egress confirmation succeeded")
					}
				})
			}
		})
	}
}
