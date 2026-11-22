package apiserver

import (
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/redteam"
)

const ticketProofGetSQL = `SELECT zasp_authorization80.ticket_proof_get($1,$2,$3,$4)`
const ticketProofPutSQL = `SELECT zasp_authorization80.ticket_proof_put($1,$2,$3,$4,$5,$6::jsonb)`

func init() {
	productStatementRules[ticketProofGetSQL] = productStatementRule{operations: []string{"getTicketVerification"}, arguments: 4, scope: 1, object: 4, kind: "test_run", browserOnly: true}
	productStatementRules[ticketProofPutSQL] = productStatementRule{operations: []string{"putTicketVerification"}, arguments: 6, scope: 1, actor: 4, object: 5, kind: "test_run", browserOnly: true}
}

type storedTicketImport struct {
	Actor              string                    `json:"submitted_by"`
	At                 time.Time                 `json:"submitted_at"`
	DefinitionRevision int64                     `json:"definition_version"`
	Bundle             redteam.TicketProofBundle `json:"bundle"`
	Digest             string                    `json:"digest"`
}

func serveTicketProof(db JSONDatabase, w http.ResponseWriter, r *http.Request, route RoutedOperation) {
	w.Header().Set("Cache-Control", "no-store")
	user, ok := IdentityFromRequest(r)
	if !ok || user.CredentialKind != CredentialBrowserSession {
		writeProductionError(w, r, ErrRepositoryAuthorization)
		return
	}
	id := route.PathParameters["id"]
	if !validProductID(id) || r.URL.RawQuery != "" {
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	scope := redteam.TicketScope{OrganizationID: user.Scope.OrganizationID().String(), WorkspaceID: user.Scope.WorkspaceID().String(), EnvironmentID: user.Scope.EnvironmentID().String()}
	args := []any{scope.OrganizationID, scope.WorkspaceID, scope.EnvironmentID}
	query := ticketProofGetSQL
	switch route.OperationID {
	case "getTicketVerification":
		if r.Method != http.MethodGet {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		args = append(args, id)
	case "putTicketVerification":
		media, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if r.Method != http.MethodPut || r.Body == nil || err != nil || media != "application/json" || len(params) > 1 || len(params) == 1 && !strings.EqualFold(params["charset"], "utf-8") {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
		var bundle redteam.TicketProofBundle
		if err != nil || redteam.DecodeTicketExport(body, &bundle) != nil || !bundle.Archivable() || bundle.Scenario.Scope != scope || bundle.Scenario.RunID != id || !validProductID(bundle.Scenario.TargetID) {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		canonical, _ := json.Marshal(bundle)
		if len(canonical) >= 64*1024 {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		args = append(args, user.PrincipalID.String(), id, string(canonical))
		query = ticketProofPutSQL
	default:
		writeProductionError(w, r, ErrRepositoryNotFound)
		return
	}
	raw, err := db.QueryJSON(r.Context(), query, args...)
	if err != nil {
		writeProductionError(w, r, err)
		return
	}
	switch string(raw) {
	case "null":
		writeProductionError(w, r, ErrRepositoryNotFound)
		return
	case `"conflict"`:
		writeProductionError(w, r, ErrRepositoryConflict)
		return
	case `"ineligible"`:
		writeProductionError(w, r, ErrRepositoryOperation)
		return
	}
	var record storedTicketImport
	if json.Unmarshal(raw, &record) != nil || !record.Bundle.Archivable() || record.Bundle.Scenario.Scope != scope || record.Bundle.Scenario.RunID != id || !validProductID(record.Actor) || record.At.IsZero() || record.DefinitionRevision < 1 || len(record.Digest) != 64 {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	result, err := redteam.VerifyTicketProof(record.Bundle.Scenario, record.Bundle.Adapter, record.Bundle.Recorder, record.At)
	if err != nil {
		writeProductionError(w, r, ErrRepositoryUnavailable)
		return
	}
	writeJSONValue(w, r, 200, map[string]any{"evidence_source": "operator_import", "schema_version": 1, "result": result, "definition_version": record.DefinitionRevision, "submitted_at": record.At, "submitted_by": record.Actor, "evidence_sha256": record.Digest, "policy_revision": record.Bundle.Scenario.PolicyRevision, "target_id": record.Bundle.Scenario.TargetID}, nil)
}
