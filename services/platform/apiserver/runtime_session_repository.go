package apiserver

import (
	"context"
	"encoding/json"
)

const (
	postgresRuntimeSessionPageSQL      = `SELECT zasp_runtime_session_page($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	postgresRuntimeSessionGetSQL       = `SELECT zasp_runtime_session_get($1,$2,$3,$4,$5)`
	postgresRuntimeSessionEventPageSQL = `SELECT zasp_runtime_session_event_page($1,$2,$3,$4,$5,$6,$7,$8)`
)

// Unattributed is an explicit investigation collection, not an inferred session.
func runtimeSessionTarget(id string) bool {
	return id == "unattributed" || validAdministrationProductID(id)
}

func (repository *PostgresRepository) readRuntimeSession(ctx context.Context, identity RequestIdentity, operation string, parameters map[string]string) (json.RawMessage, error) {
	args := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String()}
	switch operation {
	case "listSessions":
		if parameters["kind"] != "runtime" || parameters["principal_id"] != "" || parameters["agent_id"] != "" && !validAdministrationProductID(parameters["agent_id"]) {
			return nil, ErrRepositoryOperation
		}
		return repository.database.QueryJSON(ctx, postgresRuntimeSessionPageSQL, append(args, parameters["after_id"], adminLimit(parameters)+1, parameters["agent_id"], optionalAdministrationTime(parameters["from"]), optionalAdministrationTime(parameters["to"]))...)
	case "getSession":
		if !runtimeSessionTarget(parameters["id"]) {
			return nil, ErrRepositoryNotFound
		}
		return repository.database.QueryJSON(ctx, postgresRuntimeSessionGetSQL, append(args, parameters["id"])...)
	case "listSessionEvents":
		if !runtimeSessionTarget(parameters["id"]) {
			return nil, ErrRepositoryNotFound
		}
		return repository.database.QueryJSON(ctx, postgresRuntimeSessionEventPageSQL, append(args, parameters["id"], optionalAdministrationTime(parameters["after_time"]), parameters["after_id"], adminLimit(parameters)+1)...)
	default:
		return nil, ErrRepositoryOperation
	}
}
