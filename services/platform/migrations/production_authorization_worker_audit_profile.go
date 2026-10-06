package migrations

import (
	"context"
	_ "embed"
)

// This is a separate compiled recipe. It never upgrades an incompatible worker
// registration or changes the original pre-audit profile source.
const AuthorizationWorkerAuditProfileName = "canonical61-temporal78-authorization79-80-audit-identity-worker-v1"

//go:embed sql/0080_authorization_worker_audit_readiness_graph.sql
var authorizationWorkerAuditReadinessGraphSQL string

func authorizationWorkerAuditProfileSource() (string, string) {
	return authorizationWorkerProfileSourceWithGraph("-- " + AuthorizationWorkerAuditProfileName + "\n" + authorizationWorkerAuditReadinessGraphSQL)
}

func (r *Runner) UpProductionAuthorizationWorkerAuditProfile(ctx context.Context) error {
	return r.upProductionAuthorizationWorkerProfile(ctx, true)
}
