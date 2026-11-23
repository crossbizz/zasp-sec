package apiserver

import (
	"encoding/json"
	"net/http"

	"github.com/zasp-ai/zasp-sec/services/platform/aigateway"
)

const qualificationReadSQL = "SELECT zasp_authorization80.qualification_job($1,$2,$3,$4,$5,NULL,NULL,NULL,NULL)"
const qualificationRequestSQL = "SELECT zasp_authorization80.qualification_job($1,$2,$3,$4,$5,$6,$7,$8,$9)"

func init() {
	productStatementRules[qualificationReadSQL] = productStatementRule{operations: []string{"getModelQualificationRun"}, arguments: 5, scope: 1, actor: 4, object: 5, browserOnly: true}
	productStatementRules[qualificationRequestSQL] = productStatementRule{operations: []string{"runModelQualification"}, arguments: 9, scope: 1, actor: 4, browserOnly: true, fresh: true}
}
func serveQualificationRun(db JSONDatabase, w http.ResponseWriter, r *http.Request, op RoutedOperation) {
	w.Header().Set("Cache-Control", "no-store")
	i, ok := IdentityFromRequest(r)
	if !ok || i.CredentialKind != CredentialBrowserSession {
		writeProductionError(w, r, ErrRepositoryAuthorization)
		return
	}
	if r.URL.RawQuery != "" {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	args := []any{i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String()}
	query := qualificationReadSQL
	status := http.StatusOK
	switch op.OperationID {
	case "getModelQualificationRun":
		id := op.PathParameters["id"]
		if r.Method != http.MethodGet || !validProductID(id) {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		args = append(args, id)
	case "runModelQualification":
		var input struct {
			Purpose  aigateway.Purpose `json:"purpose"`
			Provider string            `json:"provider"`
			Model    string            `json:"model"`
		}
		keys := r.Header.Values("Idempotency-Key")
		if r.Method != http.MethodPost || len(keys) != 1 || !validPublicIdempotency(keys[0]) || decodeProductionJSON(r, &input) != nil || input.Provider == aigateway.ModeDev || !aigateway.EligibleModel(input.Purpose, input.Provider, input.Model) {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		id, err := newWorkflowProductID()
		if err != nil {
			writeProductionError(w, r, ErrRepositoryUnavailable)
			return
		}
		args = append(args, id, input.Provider, input.Model, string(input.Purpose), keys[0])
		query = qualificationRequestSQL
		status = http.StatusAccepted
	default:
		writeProductionError(w, r, ErrRepositoryNotFound)
		return
	}
	raw, err := db.QueryJSON(r.Context(), query, args...)
	if err != nil {
		writeProductionError(w, r, discoveryProviderError(err))
		return
	}
	switch string(raw) {
	case "null":
		writeProductionError(w, r, ErrRepositoryNotFound)
		return
	case `"conflict"`:
		writeProductionError(w, r, ErrRepositoryConflict)
		return
	case `"unavailable"`:
		writeProductionStatusError(w, r, http.StatusConflict, "qualification_unavailable", "A compatible qualification worker and an enabled model policy are required", false)
		return
	case `"invalid"`:
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	var out struct {
		Environment string `json:"environment_id"`
		ID          string `json:"id"`
	}
	if json.Unmarshal(raw, &out) != nil || out.Environment != i.Scope.EnvironmentID().String() || !validProductID(out.ID) {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	writeProductionResponse(w, r, status, raw, nil)
}
