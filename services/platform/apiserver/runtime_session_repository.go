package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const (
	postgresRuntimeSessionPageSQL      = `SELECT zasp_runtime_session_page($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	postgresRuntimeSessionGetSQL       = `SELECT zasp_runtime_session_get($1,$2,$3,$4,$5)`
	postgresRuntimeSessionEventPageSQL = `SELECT zasp_runtime_session_event_page($1,$2,$3,$4,$5,$6,$7,$8)`
	postgresRuntimeSessionEventGetSQL  = `SELECT zasp_runtime_session_event_get($1,$2,$3,$4,$5,$6)`
)

// Unattributed is an explicit investigation collection, not an inferred session.
func runtimeSessionTarget(id string) bool {
	return id == "unattributed" || validAdministrationProductID(id)
}

func (repository *PostgresRepository) readRuntimeSession(ctx context.Context, identity RequestIdentity, operation string, parameters map[string]string) (json.RawMessage, error) {
	args := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String()}
	switch operation {
	case "listSessions":
		if repository.runtimeSessionSearch != nil {
			return repository.searchRuntimeSessions(ctx, identity, parameters)
		}
		for key := range parameters {
			switch key {
			case "kind", "limit", "cursor_binding", "after_id", "after_parent_id", "after_time", "agent_id", "principal_id", "from", "to":
			default:
				return nil, ErrRepositoryOperation
			}
		}
		if parameters["kind"] != "runtime" || parameters["principal_id"] != "" || parameters["agent_id"] != "" && !validAdministrationProductID(parameters["agent_id"]) {
			return nil, ErrRepositoryOperation
		}
		return repository.database.QueryJSON(ctx, postgresRuntimeSessionPageSQL, append(args, parameters["after_id"], adminLimit(parameters)+1, parameters["agent_id"], optionalAdministrationTime(parameters["from"]), optionalAdministrationTime(parameters["to"]))...)
	case "getSession":
		if !runtimeSessionTarget(parameters["id"]) {
			return nil, ErrRepositoryNotFound
		}
		return repository.database.QueryJSON(ctx, postgresRuntimeSessionGetSQL, append(args, parameters["id"])...)
	case "getSessionEvent":
		if !runtimeSessionTarget(parameters["id"]) || !validAdministrationProductID(parameters["eventId"]) || len(parameters) != 2 {
			return nil, ErrRepositoryOperation
		}
		statement, err := repository.runtimeSessionEventStatement(ctx, false)
		if err != nil {
			return nil, err
		}
		return repository.database.QueryJSON(ctx, statement, append(args, parameters["id"], parameters["eventId"])...)
	case "listSessionEvents":
		if !runtimeSessionTarget(parameters["id"]) {
			return nil, ErrRepositoryNotFound
		}
		statement, err := repository.runtimeSessionEventStatement(ctx, true)
		if err != nil {
			return nil, err
		}
		return repository.database.QueryJSON(ctx, statement, append(args, parameters["id"], optionalAdministrationTime(parameters["after_time"]), parameters["after_id"], adminLimit(parameters)+1)...)
	default:
		return nil, ErrRepositoryOperation
	}
}

// The production search-enabled repository pre-stages on verified49 and uses
// source-qualified reads on50. A missing50 probe can try pinned49, whose wrapper
// itself requires healthy50 after upgrade. Never retry a failed event read with
// the old representation or trust a process-start readiness cache.
func (repository *PostgresRepository) runtimeSessionEventStatement(ctx context.Context, page bool) (string, error) {
	statement := postgresRuntimeSessionEventGetSQL
	if page {
		statement = postgresRuntimeSessionEventPageSQL
	}
	if !repository.sandboxSessionReads {
		return statement, nil
	}
	if ctx == nil || ctx.Err() != nil {
		return "", ErrRepositoryUnavailable
	}
	metadata := migrations.ProductionRuntimeSandboxBinding()
	body, err := repository.database.QueryJSON(ctx, `SELECT to_jsonb(zasp_production_runtime_sandbox_binding_readiness($1,$2))`, metadata.Checksum(), migrations.ProductionRuntimeSandboxBindingSemanticFingerprint())
	sandbox := true
	var provider *pgconn.PgError
	if ctx.Err() == nil && errors.As(err, &provider) && provider.Code == "42883" {
		prior := migrations.ProductionRuntimeCorrelationRouting()
		body, err = repository.database.QueryJSON(ctx, `SELECT to_jsonb(zasp_production_runtime_correlation_routing_readiness($1,$2))`, prior.Checksum(), migrations.ProductionRuntimeCorrelationRoutingSemanticFingerprint())
		sandbox = false
	}
	if err != nil || ctx.Err() != nil || !bytes.Equal(bytes.TrimSpace(body), []byte("true")) {
		return "", ErrRepositoryUnavailable
	}
	if sandbox {
		statement = `SELECT zasp_runtime_sandbox_session_event_get($1,$2,$3,$4,$5,$6)`
		if page {
			statement = `SELECT zasp_runtime_sandbox_session_event_page($1,$2,$3,$4,$5,$6,$7,$8)`
		}
	}
	return statement, nil
}
