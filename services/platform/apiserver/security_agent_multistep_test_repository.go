package apiserver

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// testAction is intentionally private. No generic worker or public route can
// select the ordered successor protocol through this method.
func (repository *securityAgentMultistepAdmissionRepository) testAction(ctx context.Context, raw json.RawMessage) (json.RawMessage, error) {
	var request orderedTestAction
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil || len(raw) > 4096 {
		return nil, ErrRepositoryOperation
	}
	if _, ok := securityAgentOrderedClosedObject(raw, "organization_id", "workspace_id", "environment_id", "run_id", "step_id", "operation", "worker_id", "lease_token", "run_version", "effect_version", "lease_seconds", "payload"); !ok || decodeStrictDiscovery(raw, &request) != nil {
		return nil, ErrRepositoryOperation
	}
	scope, valid := orderedTestScope(request.OrganizationID, request.WorkspaceID, request.EnvironmentID, request.RunID, request.StepID)
	token, tokenErr := hex.DecodeString(request.LeaseToken)
	if !valid || tokenErr != nil || len(token) != 16 || strings.ToLower(request.LeaseToken) != request.LeaseToken || !redTeamWorkerPattern.MatchString(request.WorkerID) || !validSecurityAgentWorkerLease(request.WorkerID, request.LeaseToken, request.LeaseSeconds) || request.RunVersion < 1 || request.RunVersion >= 999999 || request.EffectVersion < 0 || request.EffectVersion >= 999999 || request.Operation != "claim" && request.Operation != "heartbeat" || request.Operation == "heartbeat" && request.EffectVersion == 0 {
		return nil, ErrRepositoryOperation
	}
	if _, ok := securityAgentOrderedClosedObject(request.Payload); !ok {
		return nil, ErrRepositoryOperation
	}
	response, err := repository.database.QueryJSON(ctx, `SELECT zasp_sa_multistep_prior.test_action($1,$2,$3::jsonb)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint(), raw)
	if err != nil {
		return nil, discoveryProviderError(err)
	}
	var result orderedTestActionResult
	if len(response) > 4096 {
		return nil, ErrRepositoryUnavailable
	}
	if _, ok := securityAgentOrderedClosedObject(response, "contract_version", "organization_id", "workspace_id", "environment_id", "run_id", "step_id", "operation", "run_version", "step_version", "effect_version", "effect_state", "attempt", "reservation_id", "test_run_id", "plan_hash", "input_digest", "lease_expires_at"); !ok || decodeStrictDiscovery(response, &result) != nil {
		return nil, ErrRepositoryUnavailable
	}
	reservation, _ := CanonicalDiscoveryID(scope, "security_agent_ordered_reservation", request.RunID+"\x1f"+request.StepID)
	child, _ := CanonicalDiscoveryID(scope, "security_agent_test_run", request.RunID+"\x1f"+request.StepID+"\x1frun_test")
	_, planOK := decodeTemporaryPolicyDigest(result.PlanHash)
	_, inputOK := decodeTemporaryPolicyDigest(result.InputDigest)
	increment := int64(0)
	if request.Operation == "claim" {
		increment = 1
	}
	if result.ContractVersion != 61 || result.OrganizationID != request.OrganizationID || result.WorkspaceID != request.WorkspaceID || result.EnvironmentID != request.EnvironmentID || result.RunID != request.RunID || result.StepID != request.StepID || result.Operation != request.Operation || result.ReservationID != reservation || result.TestRunID != child || !planOK || !inputOK || result.RunVersion != request.RunVersion+increment || result.StepVersion != 4 || result.EffectVersion != request.EffectVersion+1 || result.EffectState != "leased" || result.Attempt < 1 || result.Attempt > 5 || request.EffectVersion == 0 && result.Attempt != 1 || !result.LeaseExpiresAt.After(time.Now()) || result.LeaseExpiresAt.Location() != time.UTC {
		return nil, ErrRepositoryUnavailable
	}
	return response, nil
}

type orderedTestAction struct {
	OrganizationID string          `json:"organization_id"`
	WorkspaceID    string          `json:"workspace_id"`
	EnvironmentID  string          `json:"environment_id"`
	RunID          string          `json:"run_id"`
	StepID         string          `json:"step_id"`
	Operation      string          `json:"operation"`
	WorkerID       string          `json:"worker_id"`
	LeaseToken     string          `json:"lease_token"`
	RunVersion     int64           `json:"run_version"`
	EffectVersion  int64           `json:"effect_version"`
	LeaseSeconds   int             `json:"lease_seconds"`
	Payload        json.RawMessage `json:"payload"`
}

type orderedTestActionResult struct {
	ContractVersion int       `json:"contract_version"`
	OrganizationID  string    `json:"organization_id"`
	WorkspaceID     string    `json:"workspace_id"`
	EnvironmentID   string    `json:"environment_id"`
	RunID           string    `json:"run_id"`
	StepID          string    `json:"step_id"`
	Operation       string    `json:"operation"`
	RunVersion      int64     `json:"run_version"`
	StepVersion     int64     `json:"step_version"`
	EffectVersion   int64     `json:"effect_version"`
	EffectState     string    `json:"effect_state"`
	Attempt         int       `json:"attempt"`
	ReservationID   string    `json:"reservation_id"`
	TestRunID       string    `json:"test_run_id"`
	PlanHash        string    `json:"plan_hash"`
	InputDigest     string    `json:"input_digest"`
	LeaseExpiresAt  time.Time `json:"lease_expires_at"`
}

func orderedTestScope(o, w, e, r, s string) (domain.Scope, bool) {
	for _, id := range []string{o, w, e, r, s} {
		if !validProductID(id) {
			return domain.Scope{}, false
		}
	}
	org, _ := domain.ParseProductID(o)
	workspace, _ := domain.ParseProductID(w)
	environment, _ := domain.ParseProductID(e)
	scope, err := domain.NewScope(org, workspace, environment)
	if err != nil {
		return domain.Scope{}, false
	}
	step, _ := CanonicalDiscoveryID(scope, "security_agent_step", r+"\x1f1")
	return scope, step == s
}
