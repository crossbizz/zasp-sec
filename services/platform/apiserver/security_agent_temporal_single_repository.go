package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func temporalTestScopeForOwner(q temporalEffectRequest, action string) (domain.Scope, bool) {
	if action == "" {
		return orderedTestScope(q.OrganizationID, q.WorkspaceID, q.EnvironmentID, q.RunID, q.StepID)
	}
	if !stringIn(action, "run_test", "rerun_test") {
		return domain.Scope{}, false
	}
	// Reuse scope parsing without weakening the ordered path's index-one binding.
	o, err := domain.ParseProductID(q.OrganizationID)
	if err != nil {
		return domain.Scope{}, false
	}
	w, err := domain.ParseProductID(q.WorkspaceID)
	if err != nil {
		return domain.Scope{}, false
	}
	e, err := domain.ParseProductID(q.EnvironmentID)
	if err != nil {
		return domain.Scope{}, false
	}
	scope, err := domain.NewScope(o, w, e)
	if err != nil || !validProductID(q.RunID) {
		return domain.Scope{}, false
	}
	step, _ := CanonicalDiscoveryID(scope, "security_agent_step", q.RunID+"\x1f0")
	return scope, q.StepID == step
}

func temporalTestRequestForOwner(raw json.RawMessage, maximum int, action string, operations ...string) (temporalEffectRequest, bool) {
	if action == "" {
		return temporalTestRequest(raw, maximum, operations...)
	}
	var q temporalEffectRequest
	if _, ok := orderedTestArtifactObject(raw, maximum, "organization_id", "workspace_id", "environment_id", "run_id", "step_id", "generation", "operation", "payload"); !ok || decodeStrictDiscovery(raw, &q) != nil || q.Generation != 1 || !stringIn(q.Operation, operations...) {
		return q, false
	}
	_, valid := temporalTestScopeForOwner(q, action)
	return q, valid
}

func (repository *securityAgentMultistepAdmissionRepository) temporalReadyForOwner(ctx context.Context, action string) error {
	if action == "" {
		return repository.temporalReady(ctx)
	}
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil {
		return ErrRepositoryOperation
	}
	raw, err := repository.database.QueryJSON(ctx, `SELECT to_jsonb(zasp_temporal74.client_ready($1,$2))`, migrations.ProductionTemporalTestExecutor().Checksum(), migrations.TemporalTestExecutorFingerprint())
	if err != nil || !bytes.Equal(bytes.TrimSpace(raw), []byte("true")) {
		return ErrRepositoryUnavailable
	}
	return nil
}
