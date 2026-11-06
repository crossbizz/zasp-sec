package main

import (
	"context"
	"reflect"
	"testing"
)

var authorizationConfirmationCommands = []string{"up-authorization-worker-profile", "up-authorization-temporal-profile", "up-authorization-audit-profile", "up-authorization-temporal-audit-profile", "up-authorization-identity-profile", "up-authorization-temporal-identity-profile", "up-authorization-runtime-profile"}

func TestAuthorizationConfirmationUsesActualBoundedAuthorityPath(t *testing.T) {
	for _, command := range authorizationConfirmationCommands {
		t.Run(command, func(t *testing.T) {
			registration := discoveryPrincipalRegistration{migration: "registered_source_login"}
			expected := &releaseReadinessQueryer{}
			if err := registerForwardRelease(context.Background(), expected, registration, []string{command}); err != nil || len(expected.statements) != 1 {
				t.Fatal("original fixed command query unavailable")
			}
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
					err := confirmForwardRelease(ctx, plain, func(context.Context) (retentionOperatorTransaction, error) { begins++; return tx, nil }, registration, []string{command})
					if plain.reads != 0 {
						t.Fatal("private confirmation used original noninheriting connection outside transaction")
					}
					if mode == "canceled" {
						if err == nil || begins != 0 || tx.reads != 0 || tx.committed {
							t.Fatal("canceled confirmation reached metadata")
						}
						return
					}
					if begins != 1 || !tx.authority || !tx.rolled || tx.reads != 1 || tx.statement != expected.statements[0] || !reflect.DeepEqual(tx.arguments, expected.arguments[0]) {
						t.Fatal("bounded confirmation changed original configured-session SQL, mode, pin, or arguments")
					}
					if mode == "accepted" {
						if err != nil || !tx.committed {
							t.Fatal("legitimate exact profile confirmation did not commit")
						}
					} else if err == nil || mode == "catalog-refused" && tx.committed {
						t.Fatal("refused or uncertain confirmation succeeded")
					}
				})
			}
			t.Run("missing-closed-begin", func(t *testing.T) {
				plain := &principalPlainPreflightQueryer{}
				err := confirmForwardRelease(context.Background(), plain, principalAuthorityTransactionBegin(plain), registration, []string{command})
				if err == nil || plain.reads != 0 {
					t.Fatal("unknown transaction capability fell back to plain private query")
				}
			})
		})
	}
}
