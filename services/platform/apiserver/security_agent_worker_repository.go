package apiserver

import (
	"context"
	"encoding/json"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const (
	postgresSecurityAgentWorkerReadySQL      = `SELECT jsonb_build_object('release',zasp_security_agent_readiness($1,$2),'principal',zasp_security_agent_principal_ready('zasp_security_agent_worker'))`
	postgresSecurityAgentScheduleTriggersSQL = `SELECT zasp_security_agent_schedule_triggers($1,$2)`
	postgresSecurityAgentClaimRunsSQL        = `SELECT zasp_security_agent_claim_runs($1,$2,$3,$4)`
	postgresSecurityAgentHeartbeatRunSQL     = `SELECT zasp_security_agent_heartbeat_run($1,$2,$3,$4,$5,$6,$7)`
	postgresSecurityAgentPrepareRunSQL       = `SELECT zasp_security_agent_prepare_run($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`
	postgresSecurityAgentExecuteRunSQL       = `SELECT zasp_security_agent_execute_run($1,$2,$3,$4,$5,$6,$7,$8)`
)

type SecurityAgentRunClaim struct {
	OrganizationID    string    `json:"organization_id"`
	WorkspaceID       string    `json:"workspace_id"`
	EnvironmentID     string    `json:"environment_id"`
	RunID             string    `json:"run_id"`
	DefinitionID      string    `json:"definition_id"`
	DefinitionVersion int64     `json:"definition_version"`
	TriggerID         string    `json:"trigger_id"`
	State             string    `json:"state"`
	Version           int64     `json:"version"`
	Attempt           int       `json:"attempt"`
	LeaseExpiresAt    time.Time `json:"lease_expires_at"`
	Prepared          bool      `json:"prepared"`
}

type SecurityAgentPrepareResult struct {
	RunID      string `json:"run_id"`
	State      string `json:"state"`
	ApprovalID string `json:"approval_id"`
	StepID     string `json:"step_id"`
	PlanHash   string `json:"plan_hash"`
	Version    int64  `json:"version"`
}

type SecurityAgentExecuteResult struct {
	RunID        string `json:"run_id"`
	State        string `json:"state"`
	StepID       string `json:"step_id"`
	EffectState  string `json:"effect_state"`
	OutcomeID    string `json:"outcome_id"`
	ResultDigest string `json:"result_digest"`
	Version      int64  `json:"version"`
}

type SecurityAgentWorkerAuthority interface {
	Ready(context.Context) error
	ScheduleSecurityAgentTriggers(context.Context, string, int) (int, error)
	ClaimSecurityAgentRuns(context.Context, string, string, int, int) ([]SecurityAgentRunClaim, error)
	HeartbeatSecurityAgentRun(context.Context, SecurityAgentRunClaim, string, string, int) error
	PrepareSecurityAgentRun(context.Context, SecurityAgentRunClaim, string, string, string, time.Time, string, string) (SecurityAgentPrepareResult, error)
	ExecuteSecurityAgentRun(context.Context, SecurityAgentRunClaim, string, string, string, string) (SecurityAgentExecuteResult, error)
}

func (repository *SecurityAgentWorkerRepository) ScheduleSecurityAgentTriggers(ctx context.Context, workerID string, limit int) (int, error) {
	if repository == nil || ctx == nil || ctx.Err() != nil || !validSecurityAgentText(workerID, 128) || limit < 1 || limit > 25 {
		return 0, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresSecurityAgentScheduleTriggersSQL, workerID, limit)
	if err != nil {
		return 0, discoveryProviderError(err)
	}
	var result struct {
		Created int `json:"created"`
	}
	if !exactJSONFields(payload, "created") || decodeStrictDiscovery(payload, &result) != nil || result.Created < 0 || result.Created > limit {
		return 0, ErrRepositoryUnavailable
	}
	return result.Created, nil
}

type SecurityAgentWorkerRepository struct{ database JSONDatabase }

func NewSecurityAgentWorkerRepository(database JSONDatabase) (*SecurityAgentWorkerRepository, error) {
	if nilInterface(database) {
		return nil, ErrRepositoryConfiguration
	}
	repository := &SecurityAgentWorkerRepository{database: database}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if repository.Ready(ctx) != nil {
		return nil, ErrRepositoryConfiguration
	}
	return repository, nil
}

func (repository *SecurityAgentWorkerRepository) Ready(ctx context.Context) error {
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil {
		return ErrRepositoryUnavailable
	}
	payload, err := repository.database.QueryJSON(ctx, postgresSecurityAgentWorkerReadySQL, migrations.ProductionSecurityAgentExecution().Checksum(), migrations.ProductionSecurityAgentExecutionSemanticFingerprint())
	if err != nil {
		return ErrRepositoryUnavailable
	}
	var raw map[string]json.RawMessage
	var result struct {
		Release   bool `json:"release"`
		Principal bool `json:"principal"`
	}
	if json.Unmarshal(payload, &raw) != nil || len(raw) != 2 || raw["release"] == nil || raw["principal"] == nil || json.Unmarshal(payload, &result) != nil || !result.Release || !result.Principal {
		return ErrRepositoryUnavailable
	}
	return nil
}

func (repository *SecurityAgentWorkerRepository) ClaimSecurityAgentRuns(ctx context.Context, workerID, leaseToken string, leaseSeconds, limit int) ([]SecurityAgentRunClaim, error) {
	if repository == nil || ctx == nil || ctx.Err() != nil || !validSecurityAgentWorkerLease(workerID, leaseToken, leaseSeconds) || limit < 1 || limit > 25 {
		return nil, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresSecurityAgentClaimRunsSQL, workerID, leaseToken, leaseSeconds, limit)
	if err != nil {
		return nil, discoveryProviderError(err)
	}
	var envelope struct {
		Items []json.RawMessage `json:"items"`
	}
	if !exactJSONFields(payload, "items") || decodeStrictDiscovery(payload, &envelope) != nil || len(envelope.Items) > limit {
		return nil, ErrRepositoryUnavailable
	}
	claims := make([]SecurityAgentRunClaim, len(envelope.Items))
	for index, item := range envelope.Items {
		if !exactJSONFields(item, "attempt", "definition_id", "definition_version", "environment_id", "lease_expires_at", "organization_id", "prepared", "run_id", "state", "trigger_id", "version", "workspace_id") || decodeStrictDiscovery(item, &claims[index]) != nil || !validSecurityAgentRunClaim(claims[index]) {
			return nil, ErrRepositoryUnavailable
		}
	}
	return claims, nil
}

func (repository *SecurityAgentWorkerRepository) HeartbeatSecurityAgentRun(ctx context.Context, claim SecurityAgentRunClaim, workerID, leaseToken string, leaseSeconds int) error {
	if repository == nil || ctx == nil || ctx.Err() != nil || !validSecurityAgentRunClaim(claim) || !validSecurityAgentWorkerLease(workerID, leaseToken, leaseSeconds) {
		return ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresSecurityAgentHeartbeatRunSQL, claim.OrganizationID, claim.WorkspaceID, claim.EnvironmentID, claim.RunID, workerID, leaseToken, leaseSeconds)
	if err != nil {
		return discoveryProviderError(err)
	}
	var result struct {
		RunID          string    `json:"run_id"`
		LeaseExpiresAt time.Time `json:"lease_expires_at"`
	}
	if !exactJSONFields(payload, "lease_expires_at", "run_id") || decodeStrictDiscovery(payload, &result) != nil || result.RunID != claim.RunID || result.LeaseExpiresAt.IsZero() || result.LeaseExpiresAt.Location() != time.UTC {
		return ErrRepositoryUnavailable
	}
	return nil
}

func (repository *SecurityAgentWorkerRepository) PrepareSecurityAgentRun(ctx context.Context, claim SecurityAgentRunClaim, workerID, leaseToken, approvalID string, expiresAt time.Time, auditID, correlationID string) (SecurityAgentPrepareResult, error) {
	if repository == nil || ctx == nil || ctx.Err() != nil || !validSecurityAgentRunClaim(claim) || claim.Prepared || !validSecurityAgentWorkerIdentity(workerID, leaseToken) || !validProductID(approvalID) || expiresAt.IsZero() || expiresAt.Location() != time.UTC || !validProductID(auditID) || !validProductID(correlationID) {
		return SecurityAgentPrepareResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresSecurityAgentPrepareRunSQL, claim.OrganizationID, claim.WorkspaceID, claim.EnvironmentID, claim.RunID, workerID, leaseToken, approvalID, expiresAt, auditID, correlationID)
	if err != nil {
		return SecurityAgentPrepareResult{}, discoveryProviderError(err)
	}
	var result SecurityAgentPrepareResult
	if !exactJSONFields(payload, "approval_id", "plan_hash", "run_id", "state", "step_id", "version") || decodeStrictDiscovery(payload, &result) != nil {
		return SecurityAgentPrepareResult{}, ErrRepositoryUnavailable
	}
	if result.RunID != claim.RunID || result.State != "waiting_approval" || result.Version != claim.Version+1 || !validProductID(result.ApprovalID) || result.ApprovalID != approvalID || !validProductID(result.StepID) || !securityAgentPlanHashPattern.MatchString(result.PlanHash) {
		return SecurityAgentPrepareResult{}, ErrRepositoryUnavailable
	}
	return result, nil
}

func (repository *SecurityAgentWorkerRepository) ExecuteSecurityAgentRun(ctx context.Context, claim SecurityAgentRunClaim, workerID, leaseToken, auditID, correlationID string) (SecurityAgentExecuteResult, error) {
	if repository == nil || ctx == nil || ctx.Err() != nil || !validSecurityAgentRunClaim(claim) || !claim.Prepared || !validSecurityAgentWorkerIdentity(workerID, leaseToken) || !validProductID(auditID) || !validProductID(correlationID) {
		return SecurityAgentExecuteResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresSecurityAgentExecuteRunSQL, claim.OrganizationID, claim.WorkspaceID, claim.EnvironmentID, claim.RunID, workerID, leaseToken, auditID, correlationID)
	if err != nil {
		return SecurityAgentExecuteResult{}, discoveryProviderError(err)
	}
	var result SecurityAgentExecuteResult
	if !exactJSONFields(payload, "effect_state", "outcome_id", "result_digest", "run_id", "state", "step_id", "version") || decodeStrictDiscovery(payload, &result) != nil {
		return SecurityAgentExecuteResult{}, ErrRepositoryUnavailable
	}
	if result.RunID != claim.RunID || result.State != "remediated" || result.Version != claim.Version+1 || !validProductID(result.StepID) || result.EffectState != "verified" || !validProductID(result.OutcomeID) || !securityAgentPlanHashPattern.MatchString(result.ResultDigest) {
		return SecurityAgentExecuteResult{}, ErrRepositoryUnavailable
	}
	return result, nil
}

func validSecurityAgentWorkerLease(workerID, leaseToken string, leaseSeconds int) bool {
	return validSecurityAgentWorkerIdentity(workerID, leaseToken) && leaseSeconds >= 30 && leaseSeconds <= 300
}

func validSecurityAgentWorkerIdentity(workerID, leaseToken string) bool {
	return validSecurityAgentText(workerID, 128) && len(leaseToken) >= 16 && len(leaseToken) <= 128
}

func validSecurityAgentRunClaim(claim SecurityAgentRunClaim) bool {
	return validProductID(claim.OrganizationID) && validProductID(claim.WorkspaceID) && validProductID(claim.EnvironmentID) && validProductID(claim.RunID) && validProductID(claim.DefinitionID) && claim.DefinitionVersion > 0 && claim.DefinitionVersion <= 1000000 && validProductID(claim.TriggerID) && claim.State == "planning" && claim.Version > 1 && claim.Version <= 1000000 && claim.Attempt >= 1 && claim.Attempt <= 100 && !claim.LeaseExpiresAt.IsZero() && claim.LeaseExpiresAt.Location() == time.UTC
}
