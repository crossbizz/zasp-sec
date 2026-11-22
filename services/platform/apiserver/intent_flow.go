package apiserver

import (
	"encoding/json"
	"net/http"
	"os"
)

const intentFlowSQL = "SELECT zasp_authorization80.intent_flow($1,$2,$3)"

func init() {
	productStatementRules[intentFlowSQL] = productStatementRule{operations: []string{"getExternalDataFlows"}, arguments: 3, scope: 1, browserOnly: true}
}

func (handler *identityHTTPHandler) externalIntentFlow(r *http.Request) (json.RawMessage, error) {
	if os.Getenv("ZASP_INTENT_CLASSIFIER_ENABLED") != "true" {
		return nil, nil
	}
	identity, ok := IdentityFromRequest(r)
	repo, found := handler.administration.(*PostgresRepository)
	if !ok || !found || repo == nil || repo.database == nil {
		return nil, ErrRepositoryUnavailable
	}
	scope := identity.Scope
	raw, err := repo.database.QueryJSON(r.Context(), intentFlowSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String())
	if err != nil || !json.Valid(raw) {
		return nil, ErrRepositoryUnavailable
	}
	return raw, nil
}
