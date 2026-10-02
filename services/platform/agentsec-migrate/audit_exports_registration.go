package main

func loadAuditExportWorkerRegistration(getenv func(string) string) (string, string, error) {
	if getenv == nil {
		return "", "", errInvalidMigrationCommand
	}
	executor := getenv("ZASP_AUDIT_EXPORT_WORKER_DB_PRINCIPAL")
	outbox := getenv("ZASP_AUDIT_EXPORT_OUTBOX_DB_PRINCIPAL")
	if !databasePrincipalPattern.MatchString(executor) || !databasePrincipalPattern.MatchString(outbox) || executor == outbox {
		return "", "", errInvalidMigrationCommand
	}
	return executor, outbox, nil
}
