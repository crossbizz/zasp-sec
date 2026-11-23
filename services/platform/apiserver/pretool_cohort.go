package apiserver

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/zasp-ai/zasp-sec/services/platform/endpointprotocol"
)

const pretoolCohortSQL = "SELECT zasp_authorization80.pretool_cohort($1,$2,$3,$4,$5,$6,$7,$8::jsonb)"

func init() {
	productStatementRules[pretoolCohortSQL] = productStatementRule{operations: []string{"getEndpointPolicyCohort", "updateEndpointPolicyCohort"}, arguments: 8, scope: 1, actor: 4, browserOnly: true, check: func(g RequestAuthorization, a []any) bool {
		return a[4] == g.OperationID && a[5] == g.PathParameters["cohort"] && (g.OperationID == "getEndpointPolicyCohort" || g.Identity.FreshAuthenticated) && authorizationNativeTargetAllowed(g, "environment", g.Identity.Scope.EnvironmentID().String())
	}}
}

func (h *endpointFleetHandler) pretoolCohort(r *http.Request, op RoutedOperation, user RequestIdentity) (json.RawMessage, error) {
	c := op.PathParameters["cohort"]
	scope := user.Scope
	if !cohortLabel.MatchString(c) || r.URL.RawQuery != "" {
		return nil, ErrRepositoryOperation
	}
	key, body := "", "{}"
	if op.OperationID == "updateEndpointPolicyCohort" {
		if !user.FreshAuthenticated {
			return nil, ErrRepositoryAuthorization
		}
		key = r.Header.Get("Idempotency-Key")
		if r.Method != http.MethodPut || len(r.Header.Values("Idempotency-Key")) != 1 || !validPublicIdempotency(key) || r.Body == nil {
			return nil, ErrRepositoryOperation
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 32769))
		var template struct {
			Expected *int64                         `json:"expected_revision"`
			Mode     string                         `json:"mode"`
			Failure  string                         `json:"failure_mode"`
			Rules    []endpointprotocol.PretoolRule `json:"rules"`
		}
		if err != nil || len(raw) > 32768 || !endpointprotocol.StrictPolicyJSON(raw, &template) || template.Expected == nil || *template.Expected < 0 || *template.Expected >= 1000000 || !endpointprotocol.ValidPretoolRules(template.Mode, template.Failure, template.Rules) {
			return nil, ErrRepositoryOperation
		}
		canonical, _ := json.Marshal(template)
		body = string(canonical)
	} else if r.Method != http.MethodGet {
		return nil, ErrRepositoryOperation
	}
	return h.database.QueryJSON(r.Context(), pretoolCohortSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), user.PrincipalID.String(), op.OperationID, c, key, body)
}
