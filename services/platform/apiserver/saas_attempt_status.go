package apiserver

import (
	"encoding/json"
	"net/http"
)

const saasAttemptStatusSQL = "SELECT zasp_authorization80.saas_attempt_status($1,$2,$3,$4,$5,$6,$7)"

func init() {
	productStatementRules[saasAttemptStatusSQL] = productStatementRule{operations: []string{"getSaaSSignInAttempt"}, arguments: 7, scope: 1, actor: 4, object: 5, kind: "integration", browserOnly: true}
}

func serveSaaSAttemptStatus(db JSONDatabase, w http.ResponseWriter, r *http.Request, route RoutedOperation) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	identity, ok := IdentityFromRequest(r)
	cookie, err := r.Cookie(browserSessionCookie)
	if !ok || identity.CredentialKind != CredentialBrowserSession || err != nil || len(cookie.Value) < 8 || len(cookie.Value) > 4096 {
		writeProductionError(w, r, ErrRepositoryAuthentication)
		return
	}
	integration, attempt := route.PathParameters["id"], route.PathParameters["attemptId"]
	if r.Method != http.MethodGet || r.URL.RawQuery != "" || !validProductID(integration) || !validProductID(attempt) {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	if db == nil {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	s := identity.Scope
	raw, err := db.QueryJSON(r.Context(), saasAttemptStatusSQL, s.OrganizationID().String(), s.WorkspaceID().String(), s.EnvironmentID().String(), identity.PrincipalID.String(), integration, attempt, connectorDigest(cookie.Value))
	if err != nil {
		writeProductionError(w, r, discoveryProviderError(err))
		return
	}
	if len(raw) == 0 || string(raw) == "null" {
		writeProductionError(w, r, ErrRepositoryNotFound)
		return
	}
	var result struct {
		Attempt     string `json:"attempt_id"`
		Integration string `json:"integration_id"`
	}
	if json.Unmarshal(raw, &result) != nil || result.Attempt != attempt || result.Integration != integration {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	writeProductionResponse(w, r, http.StatusOK, raw, nil)
}
