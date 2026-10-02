package apiserver

import (
	"context"
	"encoding/json"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Configured rules cannot be written through a rule-blind predecessor. This
// gate uses the current API login and exact catalog pins, never worker authority.
func requireAutomaticDefinitionBody(ctx context.Context, db JSONDatabase, body json.RawMessage) error {
	fields, valid := budgetJSONObject(body)
	if !valid {
		return ErrRepositoryUnavailable
	}
	if _, configured := fields["trigger_rules"]; !configured {
		return nil
	}
	var present, ready bool
	raw, err := db.QueryJSON(ctx, `SELECT to_jsonb(to_regnamespace('zasp_temporal77') IS NOT NULL)`)
	if err != nil || json.Unmarshal(raw, &present) != nil || !present {
		return ErrRepositoryUnavailable
	}
	raw, err = db.QueryJSON(ctx, `SELECT to_jsonb(zasp_temporal77.api_ready($1,$2))`, migrations.TemporalAutomaticSourcesChecksum(), migrations.TemporalAutomaticSourcesFingerprint())
	if err != nil || json.Unmarshal(raw, &ready) != nil || !ready {
		return ErrRepositoryUnavailable
	}
	return nil
}

// All activation families check the persisted scoped configuration, not an HTTP
// field or a family-specific parser. Existing activation SQL still owns actor
// permission, optimistic version and replay. Concurrent current-app edits cannot
// introduce rules pre77; installed77 also enforces the write transaction itself.
func requireAutomaticDefinitionActivation(ctx context.Context, db JSONDatabase, id RequestIdentity, definition string) error {
	raw, err := db.QueryJSON(ctx, postgresSecurityAgentDefinitionValueSQL, id.Scope.OrganizationID().String(), id.Scope.WorkspaceID().String(), id.Scope.EnvironmentID().String(), definition)
	if err != nil {
		return discoveryProviderError(err)
	}
	value, err := decodeWorkflowValue(raw)
	if err != nil {
		return err
	}
	var body struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(value.Body, &body) != nil || body.ID != definition {
		return ErrRepositoryUnavailable
	}
	return requireAutomaticDefinitionBody(ctx, db, value.Body)
}
