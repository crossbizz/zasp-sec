package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"time"
)

const postgresSecurityAgentActivityTargetsSQL = `SELECT zasp_production_security_agent_run_context_targets($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`

type SecurityAgentActivityTargetRequest struct {
	RunID   string
	Kind    string
	AfterID string
	Limit   int
}

func (repository *PostgresRepository) ListSecurityAgentRunActivity(ctx context.Context, identity RequestIdentity, request SecurityAgentActivityTargetRequest, digest []byte) (SecurityAgentActivityTargetPage, error) {
	fail := SecurityAgentActivityTargetPage{}
	if repository == nil || !repository.securityAgentExecution || nilInterface(repository.database) || ctx == nil {
		return fail, ErrRepositoryUnavailable
	}
	if err := ctx.Err(); err != nil {
		return fail, err
	}
	if !validRequestIdentity(identity, true) || identity.CredentialKind != CredentialBrowserSession {
		return fail, ErrRepositoryAuthentication
	}
	if !slices.Contains(identity.Permissions, "view") || request.Kind == "session" && !slices.Contains(identity.Permissions, "investigate_sessions") || request.Kind == "audit" && !slices.Contains(identity.Permissions, "view_audit") {
		return fail, ErrAuditExportForbidden
	}
	if !validProductID(request.RunID) || !stringIn(request.Kind, "finding", "attack_path", "session", "audit") || request.AfterID != "" && !validProductID(request.AfterID) || request.Limit < 1 || request.Limit > 100 || len(digest) != sha256.Size || bytes.Equal(digest, make([]byte, sha256.Size)) {
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
	var after any
	if request.AfterID != "" {
		after = request.AfterID
	}
	raw, err := repository.database.QueryJSON(ctx, postgresSecurityAgentActivityTargetsSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), bytes.Clone(digest), identity.CSRFToken, request.Kind, request.RunID, after, request.Limit)
	if err := ctx.Err(); err != nil {
		return fail, err
	}
	if err != nil {
		return fail, auditExportRepositoryError(err)
	}
	return decodeSecurityAgentActivityTargets(raw, request)
}

func decodeSecurityAgentActivityTargets(raw json.RawMessage, request SecurityAgentActivityTargetRequest) (SecurityAgentActivityTargetPage, error) {
	fail := SecurityAgentActivityTargetPage{}
	var wire struct {
		Context     json.RawMessage `json:"context"`
		AuditIDs    []string        `json:"audit_ids"`
		NextAuditID *string         `json:"next_audit_id"`
	}
	if _, err := auditExportClosedObject(raw, 16*1024*1024, "context", "audit_ids", "next_audit_id"); err != nil {
		return fail, ErrRepositoryUnavailable
	}
	if decodeStrictDiscovery(raw, &wire) != nil || wire.AuditIDs == nil {
		return fail, ErrRepositoryUnavailable
	}
	if request.Kind != "audit" {
		if len(wire.AuditIDs) != 0 || wire.NextAuditID != nil {
			return fail, ErrRepositoryUnavailable
		}
		return projectSecurityAgentActivityTargets(wire.Context, request.RunID, request.Kind, request.AfterID, request.Limit)
	}
	detail, err := decodeSecurityAgentRunContextEnvelope(wire.Context, request.RunID)
	if err != nil || detail.Run.State == "simulated" || len(wire.AuditIDs) > request.Limit {
		return fail, ErrRepositoryUnavailable
	}
	page := SecurityAgentActivityTargetPage{Items: []SecurityAgentActivityTarget{}, Coverage: "complete"}
	last := request.AfterID
	for _, id := range wire.AuditIDs {
		if !validProductID(id) || id <= last {
			return fail, ErrRepositoryUnavailable
		}
		page.Items = append(page.Items, SecurityAgentActivityTarget{Kind: "audit", ID: id})
		last = id
	}
	if wire.NextAuditID != nil {
		if len(page.Items) == 0 || len(page.Items) != request.Limit || *wire.NextAuditID != last {
			return fail, ErrRepositoryUnavailable
		}
		page.NextID = last
	}
	return page, nil
}
