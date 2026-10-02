package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func exportDefinitionError(statement string, err error) error {
	// Principal readiness and function privileges also use 42501. Only the
	// dedicated authority's current caller permission denial is a public 403.
	var denial *pgconn.PgError
	if stringIn(statement, postgresExportDefinitionMutateSQL, postgresExportDefinitionReplaySQL, postgresExportActivateSQL, postgresExportDefinitionValueSQL, postgresExportDefinitionDetailSQL, postgresExportDefinitionPageSQL, postgresExportControlsSQL, postgresExportSetControlSQL) && errors.As(err, &denial) && denial.Code == "42501" && denial.Message == "export definition permission rejected" {
		return ErrRepositoryAuthorization
	}
	return err
}

func writeSecurityAgentDefinitionError(writer http.ResponseWriter, request *http.Request, err error) {
	if errors.Is(err, ErrRepositoryAuthorization) {
		writeProductionStatusError(writer, request, http.StatusForbidden, "authorization_rejected", "Authorization rejected", false)
		return
	}
	writeProductionError(writer, request, err)
}

const (
	postgresExportDefinitionMutateSQL = `SELECT public.zasp_sa_export_mutate_definition($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12,$13,$14,$15,$16)`
	postgresExportDefinitionReplaySQL = `SELECT public.zasp_sa_export_replay_definition($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9)`
	postgresExportActivateSQL         = `SELECT public.zasp_sa_export_activate($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`
	postgresExportDefinitionValueSQL  = `SELECT public.zasp_sa_export_definition_value($1,$2,$3,$4,$5,$6,$7)`
	postgresExportDefinitionDetailSQL = `SELECT public.zasp_sa_export_definition_detail($1,$2,$3,$4,$5,$6,$7)`
	postgresExportDefinitionPageSQL   = `SELECT public.zasp_sa_export_definition_page($1,$2,$3,$4,NULLIF($5,''),$6,$7,$8)`
	postgresExportControlsSQL         = `SELECT public.zasp_sa_export_controls($1,$2,$3,$4,$5,$6)`
	postgresExportSetControlSQL       = `SELECT public.zasp_sa_export_set_control($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`
)

func exportDefinitionPins(args []any) []any {
	return append(args, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint())
}

type securityAgentIdentityReader interface {
	GetWorkflowForIdentity(context.Context, RequestIdentity, string, string) (WorkflowValue, error)
	ListWorkflowPageForIdentity(context.Context, RequestIdentity, string, string, int) (WorkflowListPage, error)
}

func (r *PostgresRepository) GetWorkflowForIdentity(ctx context.Context, identity RequestIdentity, kind, id string) (WorkflowValue, error) {
	if !validRequestIdentity(identity, false) || !validWorkflowID(kind, id) {
		return WorkflowValue{}, ErrRepositoryOperation
	}
	installed, err := r.SecurityAgentExportDefinitionsAvailable(ctx)
	if err != nil {
		return WorkflowValue{}, err
	}
	if !installed || kind != "security_agent" {
		return r.GetWorkflow(ctx, identity.Scope, kind, id)
	}
	args := exportDefinitionPins([]any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), id, identity.PrincipalID.String()})
	payload, err := r.database.QueryJSON(ctx, postgresExportDefinitionValueSQL, args...)
	if err != nil {
		return WorkflowValue{}, exportDefinitionError(postgresExportDefinitionValueSQL, discoveryProviderError(err))
	}
	return decodeWorkflowValue(payload)
}

func (r *PostgresRepository) ListWorkflowPageForIdentity(ctx context.Context, identity RequestIdentity, kind, after string, limit int) (WorkflowListPage, error) {
	if !validRequestIdentity(identity, false) || !validWorkflowKind(kind) || limit < 1 || limit > 100 || after != "" && !validWorkflowID(kind, after) {
		return WorkflowListPage{}, ErrRepositoryOperation
	}
	installed, err := r.SecurityAgentExportDefinitionsAvailable(ctx)
	if err != nil {
		return WorkflowListPage{}, err
	}
	if !installed || kind != "security_agent" {
		return r.ListWorkflowPage(ctx, identity.Scope, kind, after, limit)
	}
	args := exportDefinitionPins([]any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), after, limit})
	payload, err := r.database.QueryJSON(ctx, postgresExportDefinitionPageSQL, args...)
	if err != nil {
		return WorkflowListPage{}, exportDefinitionError(postgresExportDefinitionPageSQL, discoveryProviderError(err))
	}
	return decodeWorkflowListPage(payload, kind, limit)
}

// Incoming action authority is insufficient for delete or family conversion.
// The installed actor-bound reader supplies the retained resource classification;
// SQL repeats that check under its write lock.
func (r *PostgresRepository) exportDefinitionAuthority(ctx context.Context, identity RequestIdentity, body json.RawMessage, id string, retained bool) (bool, error) {
	incoming, err := securityAgentExportBodyAuthority(body)
	if err != nil {
		return false, err
	}
	installed, err := r.SecurityAgentExportDefinitionsAvailable(ctx)
	if err != nil {
		return false, err
	}
	if incoming {
		if !installed {
			return false, ErrRepositoryUnavailable
		}
		return true, nil
	}
	if !retained {
		return false, nil
	}
	if !installed {
		// A missing admission function cannot turn a retained export into a
		// predecessor write. Read only to classify it, then refuse the write.
		if _, probesExport := r.database.(interface {
			SecurityAgentExportDefinitionsAvailable(context.Context) (bool, error)
		}); !probesExport {
			return false, nil
		}
		value, err := r.GetWorkflow(ctx, identity.Scope, "security_agent", id)
		if err != nil {
			return false, err
		}
		export, err := securityAgentExportBodyAuthority(value.Body)
		if err != nil {
			return false, err
		}
		if export {
			return false, ErrRepositoryUnavailable
		}
		return false, nil
	}
	value, err := r.GetWorkflowForIdentity(ctx, identity, "security_agent", id)
	if err != nil {
		return false, err
	}
	return securityAgentExportBodyAuthority(value.Body)
}

func (r *PostgresRepository) requireExportWorkflow(ctx context.Context) error {
	ready, err := r.SecurityAgentExportsWorkflowAvailable(ctx)
	if err != nil || !ready {
		return ErrRepositoryUnavailable
	}
	return nil
}

func securityAgentExportBodyAuthority(raw json.RawMessage) (bool, error) {
	body, valid := budgetJSONObject(raw)
	if !valid {
		return false, ErrRepositoryOperation
	}
	var actions []string
	if value, present := body["allowed_actions"]; present && json.Unmarshal(value, &actions) != nil {
		return false, ErrRepositoryOperation
	}
	return stringIn("create_evidence_export", actions...), nil
}

// Connected readiness is for new intent and enabling, never retained reads or
// safe withdrawal. An absent capability cannot authorize export setup.
func securityAgentExportWorkflowAvailable(ctx context.Context, authority any) (bool, error) {
	probe, ok := authority.(interface {
		SecurityAgentExportsWorkflowAvailable(context.Context) (bool, error)
	})
	if !ok {
		return false, nil
	}
	ready, err := probe.SecurityAgentExportsWorkflowAvailable(ctx)
	if err != nil {
		return false, ErrRepositoryUnavailable
	}
	return ready, nil
}
