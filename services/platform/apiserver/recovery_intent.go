package apiserver

import (
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"net/http"
)

const recoveryIntentGet = "SELECT zasp_authorization80.recovery_intent($1,$2,$3,$4,$5,'getRecoveryIntent',NULL)"
const recoveryIntentPut = "SELECT zasp_authorization80.recovery_intent($1,$2,$3,$4,$5,'putRecoveryIntent',$6::jsonb)"

func init() {
	productStatementRules[recoveryIntentGet] = productStatementRule{operations: []string{"getRecoveryIntent"}, arguments: 5, scope: 1, actor: 4, object: 5, browserOnly: true}
	productStatementRules[recoveryIntentPut] = productStatementRule{operations: []string{"putRecoveryIntent"}, arguments: 6, scope: 1, actor: 4, object: 5, browserOnly: true, fresh: true}
}

type recoveryIntentInput struct {
	Kind              string  `json:"kind"`
	BackupID          string  `json:"backup_id"`
	RetentionDays     *int    `json:"retention_days,omitempty"`
	TargetEnvironment *string `json:"target_environment,omitempty"`
}

func (p recoveryIntentInput) valid(id string, scope domain.Scope) bool {
	if !validProductID(id) || !validProductID(p.BackupID) {
		return false
	}
	switch p.Kind {
	case "backup":
		return p.BackupID == id && p.TargetEnvironment == nil && p.RetentionDays != nil && *p.RetentionDays >= 7 && *p.RetentionDays <= 90
	case "restore":
		return p.BackupID != id && p.TargetEnvironment != nil && validRecoveryTarget(*p.TargetEnvironment, scope) && p.RetentionDays == nil
	default:
		return false
	}
}

type recoveryIntentEndpoint struct{ db JSONDatabase }

func (h recoveryIntentEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	identity, ok := IdentityFromRequest(r)
	route, routed := RoutedOperationFromRequest(r)
	if !ok || !routed || identity.CredentialKind != CredentialBrowserSession {
		writeProductionError(w, r, ErrRepositoryAuthorization)
		return
	}
	id := route.PathParameters["id"]
	if !validProductID(id) || r.URL.RawQuery != "" {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	if h.db == nil {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	args := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), id}
	stmt := recoveryIntentGet
	switch route.OperationID {
	case "putRecoveryIntent":
		if r.Method != http.MethodPut || !currentRequestHasPermission(r.Context(), identity, "manage_identity") || !identity.FreshAuthenticated {
			writeProductionError(w, r, ErrRepositoryAuthorization)
			return
		}
		var p recoveryIntentInput
		if decodeProductionJSON(r, &p) != nil || !p.valid(id, identity.Scope) {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		body, _ := json.Marshal(p)
		args = append(args, string(body))
		stmt = recoveryIntentPut
	case "getRecoveryIntent":
		if r.Method != http.MethodGet || !currentRequestHasPermission(r.Context(), identity, "view") {
			writeProductionError(w, r, ErrRepositoryAuthorization)
			return
		}
	default:
		writeProductionError(w, r, ErrRepositoryNotFound)
		return
	}
	raw, err := h.db.QueryJSON(r.Context(), stmt, args...)
	if err != nil {
		writeProductionError(w, r, discoveryProviderError(err))
		return
	}
	switch string(raw) {
	case "null":
		writeProductionError(w, r, ErrRepositoryNotFound)
		return
	case `"conflict"`, `"limit"`:
		writeProductionError(w, r, ErrRepositoryConflict)
		return
	}
	var result struct {
		ID         string              `json:"id"`
		Parameters recoveryIntentInput `json:"parameters"`
	}
	if decodeStrictRisk(raw, &result) != nil || result.ID != id || !result.Parameters.valid(id, identity.Scope) {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	writeJSONValue(w, r, http.StatusOK, result, nil)
}
