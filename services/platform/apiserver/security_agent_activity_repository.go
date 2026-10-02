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

const postgresSecurityAgentActivityRunsSQL = `SELECT zasp_production_security_agent_run_context_related_runs($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`

type SecurityAgentActivityRunRequest struct {
	Kind            string
	EntityID        string
	BeforeCreatedAt time.Time
	BeforeID        string
	Limit           int
}

type SecurityAgentActivityRunPage struct {
	SecurityAgentRunPage
	Coverage string
}

func (repository *PostgresRepository) ListSecurityAgentActivityRuns(ctx context.Context, identity RequestIdentity, request SecurityAgentActivityRunRequest, sessionDigest []byte) (SecurityAgentActivityRunPage, error) {
	fail := SecurityAgentActivityRunPage{}
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
	if !stringIn(request.Kind, "finding", "attack_path", "session", "audit") || !validProductID(request.EntityID) || request.Limit < 1 || request.Limit > 100 || len(sessionDigest) != sha256.Size || bytes.Equal(sessionDigest, make([]byte, sha256.Size)) || request.BeforeCreatedAt.IsZero() != (request.BeforeID == "") {
		return fail, ErrRepositoryOperation
	}
	if request.BeforeID != "" && (!validProductID(request.BeforeID) || request.BeforeCreatedAt.Location() != time.UTC || request.BeforeCreatedAt.Year() < 1 || request.BeforeCreatedAt.Year() > 9999 || request.BeforeCreatedAt.Nanosecond()%1000 != 0) {
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
	// An audit association is proved by the exact scoped audit record, not by a
	// trigger or by an untyped ID inside the candidate's private JSON.
	auditRunID := ""
	if request.Kind == "audit" {
		audit, err := repository.GetSecurityAgentAuditEvent(ctx, identity, request.EntityID, sessionDigest)
		if err != nil {
			return fail, err
		}
		auditRunID = audit.RunID
	}
	var beforeTime, beforeID any
	if request.BeforeID != "" {
		beforeTime = request.BeforeCreatedAt
		beforeID = request.BeforeID
	}
	raw, err := repository.database.QueryJSON(ctx, postgresSecurityAgentActivityRunsSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), bytes.Clone(sessionDigest), identity.CSRFToken, request.Kind, request.EntityID, beforeTime, beforeID, request.Limit)
	if err := ctx.Err(); err != nil {
		return fail, err
	}
	if err != nil {
		return fail, auditExportRepositoryError(err)
	}
	return decodeSecurityAgentActivityRuns(raw, request, auditRunID)
}

func decodeSecurityAgentActivityRuns(raw json.RawMessage, request SecurityAgentActivityRunRequest, auditRunID string) (SecurityAgentActivityRunPage, error) {
	fail := SecurityAgentActivityRunPage{}
	var wire struct {
		Items         []json.RawMessage `json:"items"`
		Coverage      string            `json:"coverage"`
		NextCreatedAt *string           `json:"next_created_at"`
		NextID        *string           `json:"next_id"`
	}
	if _, err := auditExportClosedObject(raw, 16*1024*1024, "items", "coverage", "next_created_at", "next_id"); err != nil {
		return fail, ErrRepositoryUnavailable
	}
	if decodeStrictDiscovery(raw, &wire) != nil || wire.Items == nil || len(wire.Items) > request.Limit || !stringIn(wire.Coverage, "complete", "partial") || (wire.NextCreatedAt == nil) != (wire.NextID == nil) {
		return fail, ErrRepositoryUnavailable
	}
	result := SecurityAgentActivityRunPage{SecurityAgentRunPage: SecurityAgentRunPage{Items: make([]SecurityAgentRun, 0, len(wire.Items))}, Coverage: wire.Coverage}
	seen := make(map[string]bool, len(wire.Items))
	for _, item := range wire.Items {
		var header struct {
			Detail struct {
				Run struct {
					ID string `json:"id"`
				} `json:"run"`
			} `json:"detail"`
		}
		if json.Unmarshal(item, &header) != nil || !validProductID(header.Detail.Run.ID) || seen[header.Detail.Run.ID] {
			return fail, ErrRepositoryUnavailable
		}
		detail, err := decodeSecurityAgentRunContextEnvelope(item, header.Detail.Run.ID)
		if err != nil || detail.Run.State == "simulated" || !securityAgentActivityAssociation(detail, request.Kind, request.EntityID, auditRunID) {
			return fail, ErrRepositoryUnavailable
		}
		seen[detail.Run.ID] = true
		result.Items = append(result.Items, detail.Run)
	}
	if request.Kind == "audit" && (len(result.Items) > 1 || wire.NextID != nil || wire.Coverage != "complete") {
		return fail, ErrRepositoryUnavailable
	}
	if wire.NextID != nil {
		stamp, valid := auditListTime(*wire.NextCreatedAt)
		if !valid || !strings.HasSuffix(*wire.NextCreatedAt, "Z") || !validProductID(*wire.NextID) || len(result.Items) != request.Limit || len(result.Items) == 0 || result.Items[len(result.Items)-1].ID != *wire.NextID {
			return fail, ErrRepositoryUnavailable
		}
		if !request.BeforeCreatedAt.IsZero() && (stamp.After(request.BeforeCreatedAt) || stamp.Equal(request.BeforeCreatedAt) && *wire.NextID >= request.BeforeID) {
			return fail, ErrRepositoryUnavailable
		}
		result.NextCreatedAt = &stamp
		result.NextID = *wire.NextID
	}
	return result, nil
}

// Only call on a fully decoded v54 envelope. Evidence IDs and temporary-policy
// environment targets are deliberately not treated as entity associations.
func securityAgentActivityAssociation(detail SecurityAgentRunDetail, kind, entityID, auditRunID string) bool {
	if kind == "audit" {
		return validProductID(auditRunID) && detail.Run.ID == auditRunID
	}
	triggerKind := map[string]string{"finding": "finding", "attack_path": "attack_path", "session": "runtime_decision"}[kind]
	if triggerKind == "" {
		return false
	}
	if detail.RunContext != nil && detail.RunContext.Trigger != nil && detail.RunContext.Trigger.Kind == triggerKind && detail.RunContext.Trigger.ID == entityID {
		return true
	}
	for _, action := range detail.ActionDetails {
		if action.Arguments == nil {
			continue
		}
		if kind == "finding" && action.Action == "update_finding_response" && action.Arguments.TargetID == entityID {
			return true
		}
		if kind == "session" && action.Action == "isolate_session" && action.Arguments.TargetID == entityID && action.Arguments.SessionID == entityID {
			return true
		}
	}
	return false
}
