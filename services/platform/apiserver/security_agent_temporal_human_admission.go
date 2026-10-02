package apiserver

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func (d *PostgresJSONDatabase) temporalHumanAdmissionAvailable(ctx context.Context) (bool, error) {
	if d == nil || ctx == nil || ctx.Err() != nil {
		return false, ErrRepositoryUnavailable
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed || nilInterface(d.driver) {
		return false, ErrRepositoryUnavailable
	}
	var present, ready bool
	if err := d.driver.QueryRow(ctx, `SELECT to_regnamespace('zasp_temporal76') IS NOT NULL`).Scan(&present); err != nil {
		return false, ErrRepositoryUnavailable
	}
	if !present {
		return false, nil
	}
	if err := d.driver.QueryRow(ctx, `SELECT zasp_temporal76.api_ready($1,$2)`, migrations.ProductionTemporalHumanAdmission().Checksum(), migrations.TemporalHumanAdmissionFingerprint()).Scan(&ready); err != nil || !ready {
		return false, ErrRepositoryUnavailable
	}
	return true, nil
}

func (d *PostgresJSONDatabase) TemporalHumanTestFamily(ctx context.Context, id RequestIdentity, definition string) (bool, error) {
	available, err := d.temporalHumanAdmissionAvailable(ctx)
	if err != nil || !available {
		return false, err
	}
	raw, err := d.QueryJSON(ctx, `SELECT to_jsonb(zasp_temporal76.family($1,$2,$3,$4,$5))`, id.Scope.OrganizationID().String(), id.Scope.WorkspaceID().String(), id.Scope.EnvironmentID().String(), definition, id.PrincipalID.String())
	if err != nil {
		return false, discoveryProviderError(err)
	}
	var owned bool
	if json.Unmarshal(raw, &owned) != nil {
		return false, ErrRepositoryUnavailable
	}
	return owned, nil
}

func (d *PostgresJSONDatabase) RunTemporalHumanTest(ctx context.Context, id RequestIdentity, q SecurityAgentRunRequest) (json.RawMessage, bool, error) {
	available, err := d.temporalHumanAdmissionAvailable(ctx)
	if err != nil || !available {
		return nil, available, err
	}
	input := map[string]any{"organization_id": id.Scope.OrganizationID().String(), "workspace_id": id.Scope.WorkspaceID().String(), "environment_id": id.Scope.EnvironmentID().String(), "actor_id": id.PrincipalID.String(), "definition_id": q.DefinitionID, "definition_version": q.ExpectedVersion, "idempotency_key": q.IdempotencyKey, "run_id": q.RunID, "trigger_kind": q.TriggerKind, "trigger_id": q.TriggerID, "audit_id": q.AuditID, "correlation_id": q.CorrelationID, "receipt_id": q.ReceiptID}
	if q.TriggerVersion != nil || q.TriggerSource != nil {
		input["trigger_version"], input["trigger_source"] = q.TriggerVersion, q.TriggerSource
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		return nil, true, ErrRepositoryOperation
	}
	raw, err := d.QueryJSON(ctx, `SELECT zasp_temporal76.resource($1::jsonb)`, json.RawMessage(encoded))
	if err != nil {
		return nil, true, err
	}
	return raw, string(raw) != "null", nil
}

// Ordered multi-action ownership still goes to62. This wrapper positively
// resolves the scoped single-test family before using its strict human handler.
type securityAgentHumanHTTPHandler struct {
	database        temporalHumanFamilyResolver
	findingDatabase JSONDatabase
	next, legacy    http.Handler
}

type temporalHumanFamilyResolver interface {
	TemporalHumanTestFamily(context.Context, RequestIdentity, string) (bool, error)
}

func (h *securityAgentHumanHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	route, ok := RoutedOperationFromRequest(r)
	if ok && route.OperationID == "runSecurityAgent" {
		id, present := IdentityFromRequest(r)
		if !present || !validProductID(route.PathParameters["id"]) {
			writeProductionError(w, r, ErrRepositoryOperation)
			return
		}
		owned := false
		var err error
		if h.findingDatabase != nil {
			owned, err = temporalFindingFamily(r.Context(), h.findingDatabase, id, route.PathParameters["id"])
		}
		if err == nil && !owned && h.database != nil {
			owned, err = h.database.TemporalHumanTestFamily(r.Context(), id, route.PathParameters["id"])
		}
		if err != nil {
			writeProductionError(w, r, err)
			return
		}
		if owned {
			h.legacy.ServeHTTP(w, r)
			return
		}
	}
	h.next.ServeHTTP(w, r)
}
