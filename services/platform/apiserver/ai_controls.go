package apiserver

import (
	"encoding/json"
	"net/http"
)

const (
	aiControlsReadSQL  = "SELECT zasp_authorization80.ai_controls_read($1,$2,$3,$4)"
	aiControlsWriteSQL = "SELECT zasp_authorization80.ai_controls_update($1,$2,$3,$4,$5,$6,$7::jsonb,$8)"
	aiModelFlowSQL     = "SELECT zasp_authorization80.ai_model_flow($1,$2,$3,$4)"
)

func init() {
	productStatementRules[aiControlsReadSQL] = productStatementRule{
		operations: []string{"getOrganizationAIControls", "getEnvironmentAIControls", "listModelQualifications"},
		arguments:  4, scope: 1, browserOnly: true, check: aiReadTarget,
	}
	productStatementRules[aiModelFlowSQL] = productStatementRule{
		operations: []string{"getExternalDataFlows", "getSystemStatus", "listSystemComponents"},
		arguments:  4, scope: 1, browserOnly: true, check: aiReadTarget,
	}
	productStatementRules[aiControlsWriteSQL] = productStatementRule{
		operations: []string{"updateOrganizationAIControls", "updateEnvironmentAIControls"},
		arguments:  8, scope: 1, actor: 4, browserOnly: true, fresh: true, check: aiWriteTarget,
	}
}

func aiReadTarget(grant RequestAuthorization, args []any) bool {
	return args[3] == grant.OperationID && authorizationNativeTargetAllowed(grant, "environment", grant.Identity.Scope.EnvironmentID().String())
}

func aiWriteTarget(grant RequestAuthorization, args []any) bool {
	if args[4] != grant.OperationID {
		return false
	}
	if grant.OperationID == "updateOrganizationAIControls" {
		return authorizationNativeTargetAllowed(grant, "organization_identity", grant.Identity.Scope.OrganizationID().String())
	}
	return authorizationNativeTargetAllowed(grant, "environment", grant.Identity.Scope.EnvironmentID().String())
}

type optionalModelFlow struct {
	ID         string   `json:"id"`
	Required   bool     `json:"required"`
	Categories []string `json:"categories"`
	Enabled    bool     `json:"enabled"`
	Health     string   `json:"health"`
}

func (handler *identityHTTPHandler) modelFlow(request *http.Request, op string) (*optionalModelFlow, error) {
	if _, checked := requestAuthorizationFromContext(request.Context()); !checked {
		return nil, nil
	}
	repo, ok := handler.administration.(*PostgresRepository)
	if !ok {
		return nil, nil
	}
	identity, ok := IdentityFromRequest(request)
	if !ok || repo == nil || repo.database == nil {
		return nil, ErrRepositoryUnavailable
	}
	scope := identity.Scope
	raw, err := repo.database.QueryJSON(request.Context(), aiModelFlowSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), op)
	if err != nil {
		return nil, err
	}
	var flow *optionalModelFlow
	if json.Unmarshal(raw, &flow) != nil {
		return nil, ErrRepositoryUnavailable
	}
	return flow, nil
}
