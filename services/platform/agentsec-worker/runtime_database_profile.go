package main

import "github.com/zasp-ai/zasp-sec/services/platform/migrations"

func runtimeDatabaseAuthority(mode workerMode) string {
	switch mode {
	case workerModeRuntimeCoordinator, workerModeRuntimeComplete:
		return "zasp_runtime_coordinator"
	case workerModeRuntimeArchive:
		return "zasp_runtime_archive_worker"
	case workerModeRuntimeIndex:
		return "zasp_runtime_index_worker"
	case workerModeRuntimeCorrelation:
		return "zasp_runtime_correlation_worker"
	case workerModeRuntimeProjection:
		return "zasp_runtime_projection_worker"
	case workerModeRuntimeOutbox:
		return "zasp_outbox_worker"
	default:
		return ""
	}
}

func validWorkerRuntimeDatabaseProfile(c workerRuntimeConfig) bool {
	return c.RuntimeDatabaseProfile == "" || c.RuntimeDatabaseProfile == migrations.AuthorizationRuntimeProfileName && runtimeDatabaseAuthority(c.Mode) != ""
}

func workerUsesCurrentRuntimeProfile(c workerRuntimeConfig) bool {
	return validWorkerRuntimeDatabaseProfile(c) && runtimeDatabaseAuthority(c.Mode) != "" && (c.RuntimeDatabaseProfile == migrations.AuthorizationRuntimeProfileName || c.RuntimeServices.Enabled)
}
