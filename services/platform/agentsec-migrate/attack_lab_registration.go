package main

import "strings"

func loadAttackLabReconcilerRegistration(getenv func(string) string) (string, error) {
	if getenv == nil {
		return "", errInvalidMigrationCommand
	}
	principal := getenv("ZASP_SECURITY_AGENT_ATTACK_LAB_RECONCILER_DB_PRINCIPAL")
	if !databasePrincipalPattern.MatchString(principal) || strings.HasPrefix(principal, "zasp_") {
		return "", errInvalidMigrationCommand
	}
	return principal, nil
}
