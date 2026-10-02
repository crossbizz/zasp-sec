package main

import "strings"

func loadComplianceWorkerRegistration(getenv func(string) string) (string, string, error) {
	if getenv == nil {
		return "", "", errInvalidMigrationCommand
	}
	executor := getenv("ZASP_COMPLIANCE_WORKER_DB_PRINCIPAL")
	cleanup := getenv("ZASP_COMPLIANCE_CLEANUP_DB_PRINCIPAL")
	if !databasePrincipalPattern.MatchString(executor) || !databasePrincipalPattern.MatchString(cleanup) || executor == cleanup || strings.HasPrefix(executor, "zasp_") || strings.HasPrefix(cleanup, "zasp_") {
		return "", "", errInvalidMigrationCommand
	}
	return executor, cleanup, nil
}
