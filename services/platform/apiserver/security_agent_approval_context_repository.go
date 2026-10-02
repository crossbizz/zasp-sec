package apiserver

import (
	"context"
	"encoding/json"
	"time"
)

const postgresApprovalContextSQL = `SELECT zasp_production_security_agent_run_context_approval($1,$2,$3,$4)`
const postgresApprovalContextPageSQL = `SELECT zasp_production_security_agent_run_context_approval_page($1,$2,$3,NULLIF($4,''),NULLIF($5,''),$6,NULLIF($7,''),$8)`

func (repository *PostgresRepository) approvalContextAvailable(ctx context.Context) (bool, error) {
	if release, ok := repository.database.(interface {
		SecurityAgentRunContextAvailable(context.Context) (bool, error)
	}); ok {
		available, err := release.SecurityAgentRunContextAvailable(ctx)
		if err != nil {
			return false, ErrRepositoryUnavailable
		}
		return available, nil
	}
	return false, nil
}

func decodeApprovalContextEnvelope(payload json.RawMessage, approvalID string) (SecurityAgentApproval, error) {
	var wire struct {
		Detail  json.RawMessage `json:"detail"`
		Context json.RawMessage `json:"context"`
	}
	var result SecurityAgentApproval
	if !exactJSONFields(payload, "detail", "context") || decodeStrictDiscovery(payload, &wire) != nil || !attackLabApprovalFields(wire.Detail, "evidence_summary", "expected_effect", "expires_at", "id", "reversible", "run_id", "state", "step_id", "ttl_seconds", "version") || decodeStrictDiscovery(wire.Detail, &result) != nil || result.ID != approvalID || !validSecurityAgentApprovalShape(result) {
		return SecurityAgentApproval{}, ErrRepositoryUnavailable
	}
	value, err := decodeSecurityAgentApprovalContext(wire.Context, result)
	if err != nil {
		return SecurityAgentApproval{}, ErrRepositoryUnavailable
	}
	result.Context = value
	return result, nil
}

func decodeApprovalContextPage(payload json.RawMessage, input SecurityAgentApprovalPageRequest) (SecurityAgentApprovalPage, error) {
	var wire struct {
		Items         []json.RawMessage `json:"items"`
		NextCreatedAt *time.Time        `json:"next_created_at"`
		NextID        *string           `json:"next_id"`
	}
	if !exactJSONFields(payload, "items", "next_created_at", "next_id") || decodeStrictDiscovery(payload, &wire) != nil || (wire.NextCreatedAt == nil) != (wire.NextID == nil) {
		return SecurityAgentApprovalPage{}, ErrRepositoryUnavailable
	}
	page := SecurityAgentApprovalPage{Items: []SecurityAgentApproval{}, NextCreatedAt: wire.NextCreatedAt}
	if wire.NextID != nil {
		page.NextID = *wire.NextID
	}
	for _, raw := range wire.Items {
		var identity struct {
			Detail struct {
				ID string `json:"id"`
			} `json:"detail"`
		}
		if json.Unmarshal(raw, &identity) != nil {
			return SecurityAgentApprovalPage{}, ErrRepositoryUnavailable
		}
		item, err := decodeApprovalContextEnvelope(raw, identity.Detail.ID)
		if err != nil {
			return SecurityAgentApprovalPage{}, err
		}
		page.Items = append(page.Items, item)
	}
	if !validSecurityAgentApprovalPage(page, input) {
		return SecurityAgentApprovalPage{}, ErrRepositoryUnavailable
	}
	return page, nil
}
