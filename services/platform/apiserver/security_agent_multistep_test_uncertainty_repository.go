package apiserver

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// A separate closed response avoids presenting unknown provider outcomes as
// verified settlement receipts. The started journal remains durable.
func (repository *securityAgentMultistepAdmissionRepository) testUncertain(ctx context.Context, raw json.RawMessage) (json.RawMessage, error) {
	var request orderedTestAction
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil || len(raw) > 4096 {
		return nil, ErrRepositoryOperation
	}
	if _, ok := securityAgentOrderedClosedObject(raw, "organization_id", "workspace_id", "environment_id", "run_id", "step_id", "operation", "worker_id", "lease_token", "run_version", "effect_version", "lease_seconds", "payload"); !ok || decodeStrictDiscovery(raw, &request) != nil {
		return nil, ErrRepositoryOperation
	}
	scope, valid := orderedTestScope(request.OrganizationID, request.WorkspaceID, request.EnvironmentID, request.RunID, request.StepID)
	token, err := hex.DecodeString(request.LeaseToken)
	if !valid || err != nil || len(token) != 16 || strings.ToLower(request.LeaseToken) != request.LeaseToken || !redTeamWorkerPattern.MatchString(request.WorkerID) || !validSecurityAgentWorkerLease(request.WorkerID, request.LeaseToken, request.LeaseSeconds) || request.Operation != "uncertain" || request.RunVersion < 1 || request.RunVersion > 999998 || request.EffectVersion < 1 || request.EffectVersion > 999998 {
		return nil, ErrRepositoryOperation
	}
	if _, ok := securityAgentOrderedClosedObject(request.Payload); !ok {
		return nil, ErrRepositoryOperation
	}
	response, err := repository.database.QueryJSON(ctx, `SELECT zasp_sa_multistep_prior.test_uncertain($1,$2,$3::jsonb)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint(), raw)
	if err != nil {
		return nil, discoveryProviderError(err)
	}
	var result struct {
		ContractVersion int    `json:"contract_version"`
		OrganizationID  string `json:"organization_id"`
		WorkspaceID     string `json:"workspace_id"`
		EnvironmentID   string `json:"environment_id"`
		RunID           string `json:"run_id"`
		StepID          string `json:"step_id"`
		TestRunID       string `json:"test_run_id"`
		Attempt         int    `json:"attempt"`
		RunVersion      int64  `json:"run_version"`
		StepVersion     int64  `json:"step_version"`
		EffectVersion   int64  `json:"effect_version"`
		RunState        string `json:"run_state"`
		StepState       string `json:"step_state"`
		EffectState     string `json:"effect_state"`
		ReceiptCreated  bool   `json:"receipt_created"`
		Reason          string `json:"reason"`
	}
	if _, ok := securityAgentOrderedClosedObject(response, "contract_version", "organization_id", "workspace_id", "environment_id", "run_id", "step_id", "test_run_id", "attempt", "run_version", "step_version", "effect_version", "run_state", "step_state", "effect_state", "receipt_created", "reason"); !ok || len(response) > 4096 || decodeStrictDiscovery(response, &result) != nil {
		return nil, ErrRepositoryUnavailable
	}
	child, _ := CanonicalDiscoveryID(scope, "security_agent_test_run", request.RunID+"\x1f"+request.StepID+"\x1frun_test")
	if result.ContractVersion != 61 || result.OrganizationID != request.OrganizationID || result.WorkspaceID != request.WorkspaceID || result.EnvironmentID != request.EnvironmentID || result.RunID != request.RunID || result.StepID != request.StepID || result.TestRunID != child || result.Attempt < 1 || result.Attempt > 5 || result.RunVersion != request.RunVersion+1 || result.StepVersion != 5 || result.EffectVersion != request.EffectVersion+1 || result.RunState != "needs_human" || result.StepState != "inconclusive" || result.EffectState != "unknown_outcome" || result.ReceiptCreated || result.Reason != "test_outcome_unknown" {
		return nil, ErrRepositoryUnavailable
	}
	return response, nil
}
