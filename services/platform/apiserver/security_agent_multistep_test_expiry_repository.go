package apiserver

import (
	"context"
	"encoding/json"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// testReconcileUncertain is the separate security-agent worker boundary for a
// crashed invocation worker. It closes only the exact expired journal attempt,
// including completed journals without settled evidence. It cannot invoke a
// provider or mint a verified settlement receipt.
func (repository *securityAgentMultistepAdmissionRepository) testReconcileUncertain(ctx context.Context, raw json.RawMessage) (json.RawMessage, error) {
	var request struct {
		OrganizationID string `json:"organization_id"`
		WorkspaceID    string `json:"workspace_id"`
		EnvironmentID  string `json:"environment_id"`
		RunID          string `json:"run_id"`
		StepID         string `json:"step_id"`
		Operation      string `json:"operation"`
		WorkerID       string `json:"worker_id"`
		RunVersion     int64  `json:"run_version"`
		EffectVersion  int64  `json:"effect_version"`
	}
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil || len(raw) > 4096 {
		return nil, ErrRepositoryOperation
	}
	if _, ok := securityAgentOrderedClosedObject(raw, "organization_id", "workspace_id", "environment_id", "run_id", "step_id", "operation", "worker_id", "run_version", "effect_version"); !ok || decodeStrictDiscovery(raw, &request) != nil {
		return nil, ErrRepositoryOperation
	}
	scope, valid := orderedTestScope(request.OrganizationID, request.WorkspaceID, request.EnvironmentID, request.RunID, request.StepID)
	if !valid || request.Operation != "reconcile_uncertain" || !redTeamWorkerPattern.MatchString(request.WorkerID) || request.RunVersion < 1 || request.RunVersion > 999998 || request.EffectVersion < 1 || request.EffectVersion > 999998 {
		return nil, ErrRepositoryOperation
	}
	response, err := repository.database.QueryJSON(ctx, `SELECT zasp_sa_multistep_prior.test_reconcile_uncertain($1,$2,$3::jsonb)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint(), raw)
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
		Operation       string `json:"operation"`
		Attempt         int    `json:"attempt"`
		RunVersion      int64  `json:"run_version"`
		StepVersion     int64  `json:"step_version"`
		EffectVersion   int64  `json:"effect_version"`
		RunState        string `json:"run_state"`
		StepState       string `json:"step_state"`
		EffectState     string `json:"effect_state"`
		ReceiptCreated  bool   `json:"receipt_created"`
		JournalState    string `json:"journal_state"`
		Reason          string `json:"reason"`
	}
	if _, ok := securityAgentOrderedClosedObject(response, "contract_version", "organization_id", "workspace_id", "environment_id", "run_id", "step_id", "test_run_id", "operation", "attempt", "run_version", "step_version", "effect_version", "run_state", "step_state", "effect_state", "receipt_created", "journal_state", "reason"); !ok || len(response) > 4096 || decodeStrictDiscovery(response, &result) != nil {
		return nil, ErrRepositoryUnavailable
	}
	child, _ := CanonicalDiscoveryID(scope, "security_agent_test_run", request.RunID+"\x1f"+request.StepID+"\x1frun_test")
	journalReason := result.JournalState == "started" && result.Reason == "test_outcome_unknown" || result.JournalState == "completed_unsettled" && result.Reason == "test_evidence_unsettled"
	if result.ContractVersion != 61 || result.OrganizationID != request.OrganizationID || result.WorkspaceID != request.WorkspaceID || result.EnvironmentID != request.EnvironmentID || result.RunID != request.RunID || result.StepID != request.StepID || result.TestRunID != child || result.TestRunID == "" || result.Operation != request.Operation || result.Attempt < 1 || result.Attempt > 5 || result.RunVersion != request.RunVersion+1 || result.StepVersion != 5 || result.EffectVersion != request.EffectVersion+1 || result.RunState != "needs_human" || result.StepState != "inconclusive" || result.EffectState != "unknown_outcome" || result.ReceiptCreated || !journalReason {
		return nil, ErrRepositoryUnavailable
	}
	return response, nil
}
