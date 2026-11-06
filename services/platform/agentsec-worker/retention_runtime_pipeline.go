package main

import (
	"context"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func retentionPipelinePurpose(c workerRuntimeConfig) string {
	switch c.Mode {
	case workerModeRuntimeCoordinator, workerModeRuntimeComplete:
		return "runtime-coordinator"
	case workerModeRuntimeIndex:
		return "runtime-index"
	default:
		return ""
	}
}
func workerUsesRetentionRuntimeProfile(c workerRuntimeConfig) bool {
	return c.RetentionProfileChecksum != "" && migrations.IsRetentionProfileChecksum(c.RetentionProfileChecksum) && retentionPipelinePurpose(c) != "" && workerUsesCurrentRuntimeProfile(c) && (c.Mode != workerModeRuntimeIndex || c.RuntimeStageVersion == "runtime-index-v2" && c.RuntimeSessionIndex == "zasp-runtime-sessions-v2")
}

// The successor is opt-in under the original runtime principal. This gate never
// falls back to a parent after missing activation, registration or seal drift.
func retentionPipelineStartupReady(ctx context.Context, pool workerProfileQuery, c workerRuntimeConfig) error {
	if ctx == nil || ctx.Err() != nil || nilWorkerDependency(pool) || !workerUsesRetentionRuntimeProfile(c) || c.DatabaseAuthority != runtimeDatabaseAuthority(c.Mode) {
		return errRuntimeUnavailable
	}
	var ready bool
	if pool.QueryRow(ctx, `SELECT zasp_authorization80_runtime.ready($1,$2) AND zasp_retention_v1.caller_ready($3,$4)`, migrations.AuthorizationRuntimeProfileChecksum(), c.DatabaseAuthority, retentionPipelinePurpose(c), c.RetentionProfileChecksum).Scan(&ready) != nil || !ready {
		return errRuntimeUnavailable
	}
	return nil
}
