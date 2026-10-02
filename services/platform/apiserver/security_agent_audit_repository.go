package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"strings"
	"time"
)

const postgresSecurityAgentAuditSQL = `SELECT zasp_production_security_agent_run_context_audit($1,$2,$3,$4,$5,$6,$7)`

type SecurityAgentAuditEvent struct {
	ID             string `json:"id"`
	RunID          string `json:"run_id"`
	OrganizationID string `json:"organization_id"`
	WorkspaceID    string `json:"workspace_id"`
	EnvironmentID  string `json:"environment_id"`
	ActorReference string `json:"actor_reference"`
	EventKind      string `json:"event_kind"`
	CorrelationID  string `json:"correlation_id"`
	OccurredAt     string `json:"occurred_at"`
}

func (repository *PostgresRepository) GetSecurityAgentAuditEvent(ctx context.Context, identity RequestIdentity, auditID string, sessionDigest []byte) (SecurityAgentAuditEvent, error) {
	fail := SecurityAgentAuditEvent{}
	if repository == nil || !repository.securityAgentExecution || nilInterface(repository.database) || ctx == nil {
		return fail, ErrRepositoryUnavailable
	}
	if err := ctx.Err(); err != nil {
		return fail, err
	}
	if !validRequestIdentity(identity, true) || identity.CredentialKind != CredentialBrowserSession {
		return fail, ErrRepositoryAuthentication
	}
	if !slices.Contains(identity.Permissions, "view_audit") {
		return fail, ErrAuditExportForbidden
	}
	if !validProductID(auditID) || len(sessionDigest) != sha256.Size || bytes.Equal(sessionDigest, make([]byte, sha256.Size)) {
		return fail, ErrRepositoryOperation
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	available, err := repository.approvalContextAvailable(ctx)
	if err := ctx.Err(); err != nil {
		return fail, err
	}
	if err != nil || !available {
		return fail, ErrRepositoryUnavailable
	}
	raw, err := repository.database.QueryJSON(ctx, postgresSecurityAgentAuditSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), bytes.Clone(sessionDigest), identity.CSRFToken, auditID)
	if err := ctx.Err(); err != nil {
		return fail, err
	}
	if err != nil {
		return fail, auditExportRepositoryError(err)
	}
	return decodeSecurityAgentAuditEvent(raw, identity, auditID)
}

func decodeSecurityAgentAuditEvent(raw json.RawMessage, identity RequestIdentity, auditID string) (SecurityAgentAuditEvent, error) {
	fail := SecurityAgentAuditEvent{}
	var value SecurityAgentAuditEvent
	_, err := auditExportClosedObject(raw, 4096, "id", "run_id", "organization_id", "workspace_id", "environment_id", "actor_reference", "event_kind", "correlation_id", "occurred_at")
	if err != nil || !auditListScalarJSON(raw) || decodeStrictDiscovery(raw, &value) != nil {
		return fail, ErrRepositoryUnavailable
	}
	if !validProductID(value.ID) || value.ID != auditID || !validProductID(value.RunID) || !validProductID(value.CorrelationID) || identity.Scope.Validate() != nil || value.OrganizationID != identity.Scope.OrganizationID().String() || value.WorkspaceID != identity.Scope.WorkspaceID().String() || value.EnvironmentID != identity.Scope.EnvironmentID().String() {
		return fail, ErrRepositoryUnavailable
	}
	for _, text := range []string{value.ActorReference, value.EventKind} {
		if len(text) < 1 || len(text) > 128 || !auditListQueryText(text) {
			return fail, ErrRepositoryUnavailable
		}
	}
	if _, valid := auditListTime(value.OccurredAt); !valid || !strings.HasSuffix(value.OccurredAt, "Z") {
		return fail, ErrRepositoryUnavailable
	}
	return value, nil
}
