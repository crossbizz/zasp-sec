package apiserver

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Use the shared QueryJSON boundary so production tracing cannot erase the
// capability through a missing optional-interface forwarding method.
func queryTemporalFindingResponse(ctx context.Context, db JSONDatabase, statement string, args ...any) (json.RawMessage, bool, error) {
	raw, err := db.QueryJSON(ctx, `SELECT to_jsonb(to_regnamespace('zasp_temporal78') IS NOT NULL)`)
	if err != nil {
		return nil, false, ErrRepositoryUnavailable
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("false")) {
		return nil, false, nil
	}
	if !bytes.Equal(bytes.TrimSpace(raw), []byte("true")) {
		return nil, true, ErrRepositoryUnavailable
	}
	raw, err = db.QueryJSON(ctx, `SELECT to_jsonb(zasp_temporal78.api_ready($1,$2))`, migrations.TemporalFindingResponseChecksum(), migrations.TemporalFindingResponseFingerprint())
	if err != nil || !bytes.Equal(bytes.TrimSpace(raw), []byte("true")) {
		return nil, true, ErrRepositoryUnavailable
	}
	// Native family dispatch uses SQL NULL for explicit nonownership.
	// Preserve real query errors while representing only that scalar NULL as JSON.
	raw, err = db.QueryJSON(ctx, `SELECT COALESCE((`+statement+`),'null'::jsonb)`, args...)
	if err != nil {
		return nil, true, err
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		// Preserve explicit nonownership so typed boolean callers can distinguish
		// a malformed null response from an absent historical namespace.
		return raw, false, nil
	}
	if !json.Valid(raw) {
		return nil, true, ErrRepositoryUnavailable
	}
	return raw, true, nil
}

func temporalFindingFamily(ctx context.Context, db JSONDatabase, id RequestIdentity, definition string) (bool, error) {
	raw, handled, err := queryTemporalFindingResponse(ctx, db, `SELECT to_jsonb(zasp_temporal78.family($1,$2,$3,$4,$5))`, id.Scope.OrganizationID().String(), id.Scope.WorkspaceID().String(), id.Scope.EnvironmentID().String(), definition, id.PrincipalID.String())
	if err != nil {
		return false, err
	}
	if !handled {
		if raw != nil {
			return false, ErrRepositoryUnavailable
		}
		return false, nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("true")) {
		return true, nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("false")) {
		return false, nil
	}
	return false, ErrRepositoryUnavailable
}

func runTemporalFindingHuman(ctx context.Context, db JSONDatabase, id RequestIdentity, q SecurityAgentRunRequest) (json.RawMessage, bool, error) {
	finding, err := temporalFindingFamily(ctx, db, id, q.DefinitionID)
	if err != nil || !finding {
		return nil, false, err
	}
	input := map[string]any{"organization_id": id.Scope.OrganizationID().String(), "workspace_id": id.Scope.WorkspaceID().String(), "environment_id": id.Scope.EnvironmentID().String(), "actor_id": id.PrincipalID.String(), "definition_id": q.DefinitionID, "definition_version": q.ExpectedVersion, "idempotency_key": q.IdempotencyKey, "run_id": q.RunID, "trigger_kind": q.TriggerKind, "trigger_id": q.TriggerID, "audit_id": q.AuditID, "correlation_id": q.CorrelationID, "receipt_id": q.ReceiptID}
	if q.TriggerVersion != nil || q.TriggerSource != nil {
		input["trigger_version"], input["trigger_source"] = q.TriggerVersion, q.TriggerSource
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return nil, true, ErrRepositoryOperation
	}
	return queryTemporalFindingResponse(ctx, db, `SELECT zasp_temporal78.resource($1::jsonb)`, json.RawMessage(raw))
}
