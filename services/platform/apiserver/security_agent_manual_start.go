package apiserver

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type securityAgentRunInput struct {
	EnvironmentID  string  `json:"environment_id"`
	TriggerKind    string  `json:"trigger_kind"`
	TriggerID      string  `json:"trigger_id"`
	TriggerVersion *int64  `json:"trigger_version,omitempty"`
	TriggerSource  *string `json:"trigger_source,omitempty"`
}

func (input *securityAgentRunInput) UnmarshalJSON(raw []byte) error {
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil {
		return ErrRepositoryOperation
	}
	_, kind := object["trigger_kind"]
	_, id := object["trigger_id"]
	if kind != id {
		return ErrRepositoryOperation
	}
	keys := []string{"environment_id"}
	if kind {
		keys = append(keys, "trigger_kind", "trigger_id")
	}
	_, version := object["trigger_version"]
	_, source := object["trigger_source"]
	if version != source || version && !kind {
		return ErrRepositoryOperation
	}
	if version {
		keys = append(keys, "trigger_version", "trigger_source")
	}
	if _, err := auditExportClosedObject(raw, 16384, keys...); err != nil {
		return ErrRepositoryOperation
	}
	type plain securityAgentRunInput
	var decoded plain
	if json.Unmarshal(raw, &decoded) != nil || !validProductID(decoded.EnvironmentID) {
		return ErrRepositoryOperation
	}
	if kind {
		if !stringIn(decoded.TriggerKind, "finding", "attack_path", "session") || !validProductID(decoded.TriggerID) {
			return ErrRepositoryOperation
		}
		if version && (decoded.TriggerVersion == nil || *decoded.TriggerVersion < 1 || *decoded.TriggerVersion > 1000000 || decoded.TriggerSource == nil || !validSecurityAgentText(*decoded.TriggerSource, 128)) {
			return ErrRepositoryOperation
		}
	} else {
		decoded.TriggerKind = "manual"
	}
	*input = securityAgentRunInput(decoded)
	return nil
}

const postgresSecurityAgentManualRunSQL = `SELECT public.zasp_sa_manual_run($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`
const postgresTemporalManualRunSQL = `SELECT zasp_temporal66.manual_run($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`

func (repository *PostgresRepository) runSecurityAgentManual(ctx context.Context, identity RequestIdentity, input SecurityAgentRunRequest) (SecurityAgentRunResult, error) {
	if repository == nil || !repository.securityAgentExecution || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil || !validRequestIdentity(identity, false) || !stringIn(string(identity.CredentialKind), string(CredentialBrowserSession), string(CredentialBearerToken)) || !validProductID(input.DefinitionID) || !validPublicIdempotency(input.IdempotencyKey) || input.ExpectedVersion < 1 || input.ExpectedVersion > 1000000 || !validProductID(input.RunID) || input.TriggerKind != "manual" || input.TriggerID != "" || !validProductID(input.AuditID) || !validProductID(input.CorrelationID) || !validProductID(input.ReceiptID) {
		return SecurityAgentRunResult{}, ErrRepositoryOperation
	}
	// Migration65 captures the receipt inside this SQL authority's transaction.
	// Do not start Temporal or insert an outbox row after QueryJSON returns:
	// acceptance here means durable product admission, never run completion.
	// The registered release, including its manual admission authority, must
	// match the compiled pin. Never fall back to historical create_run.
	statement, checksum, fingerprint := postgresSecurityAgentManualRunSQL, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()
	temporalReady := false
	if probe, ok := repository.database.(interface {
		TemporalAdmissionAvailable(context.Context) (bool, error)
	}); ok {
		var err error
		temporalReady, err = probe.TemporalAdmissionAvailable(ctx)
		if err != nil {
			return SecurityAgentRunResult{}, ErrRepositoryUnavailable
		}
	}
	if temporalReady {
		statement, checksum, fingerprint = postgresTemporalManualRunSQL, migrations.ProductionTemporalOwnership().Checksum(), migrations.TemporalOwnershipFingerprint()
	} else {
		probe, ok := repository.database.(interface {
			SecurityAgentExportsAvailable(context.Context) (bool, error)
		})
		if !ok {
			return SecurityAgentRunResult{}, ErrRepositoryUnavailable
		}
		ready, err := probe.SecurityAgentExportsAvailable(ctx)
		if err != nil || !ready || ctx.Err() != nil {
			return SecurityAgentRunResult{}, ErrRepositoryUnavailable
		}
	}
	raw, err := repository.database.QueryJSON(ctx, statement, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), input.DefinitionID, identity.PrincipalID.String(), input.IdempotencyKey, input.ExpectedVersion, input.RunID, input.AuditID, input.CorrelationID, input.ReceiptID, checksum, fingerprint)
	if err != nil {
		// Only explicit user-authority refusals are non-retryable. A missing
		// function privilege also uses42501 and remains an infrastructure error.
		var denial *pgconn.PgError
		if errors.As(err, &denial) && denial.Code == "42501" && stringIn(denial.Message, "export membership rejected", "export source permission rejected") {
			return SecurityAgentRunResult{}, ErrRepositoryAuthorization
		}
		return SecurityAgentRunResult{}, discoveryProviderError(err)
	}
	var result SecurityAgentRunResult
	var replay struct {
		Replayed *bool `json:"replayed"`
	}
	if ctx.Err() != nil || !securityAgentManualReadFields(raw, []string{"agent_id", "audit_id", "correlation_id", "definition_version", "evidence_ids", "id", "receipt_id", "replayed", "state", "version"}) || json.Unmarshal(raw, &replay) != nil || replay.Replayed == nil || decodeStrictDiscovery(raw, &result) != nil || !validSecurityAgentRunResult(result, input) || !result.Replayed && (result.ID != input.RunID || result.AuditID != input.AuditID || result.CorrelationID != input.CorrelationID || result.ReceiptID != input.ReceiptID) {
		return SecurityAgentRunResult{}, ErrRepositoryUnavailable
	}
	return result, nil
}
