package apiserver

import (
	"context"
	"encoding/json"
	"regexp"

	"github.com/zasp-ai/zasp-sec/services/platform/securityagent"
)

// The action worker's side of a provider remediation (completion.sql,
// section V6): it leases a dispatched remediation, changes the provider with
// the integration's remediation role, reads the change back and reports.

const (
	currentSecurityAgentClaimProviderRemediationsSQL = `SELECT zasp_security_agent_claim_provider_remediations($1,$2,$3,$4)`
	currentSecurityAgentFinishProviderRemediationSQL = `SELECT zasp_security_agent_finish_provider_remediation($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb)`
)

// Outcomes of a provider remediation.
const (
	// The provider was read back and holds the requested state.
	ProviderRemediationVerified = "verified"
	// The provider refused, or the target did not match; nothing was changed.
	ProviderRemediationFailed = "failed"
	// A change may have been made and could not be confirmed.
	ProviderRemediationUnknown = "unknown"
)

var (
	providerRemediationRolePattern      = regexp.MustCompile(`^arn:aws:iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]{1,128}$`)
	providerRemediationReferencePattern = regexp.MustCompile(`^ref:aws/external-id/[A-Za-z0-9][A-Za-z0-9._-]{7,127}$`)
	providerRemediationAgentARNPattern  = regexp.MustCompile(`^arn:aws(?:-us-gov|-cn)?:bedrock:([a-z0-9-]{1,20}):([0-9]{12}):agent/([0-9A-Za-z]{1,64})$`)
	providerRemediationFailurePattern   = regexp.MustCompile(`^[a-z][a-z0-9_]{2,63}$`)
	providerRemediationResourcePattern  = regexp.MustCompile(`^arn:aws(?:-us-gov|-cn)?:[a-z0-9-]+:[a-z0-9-]*:([0-9]{12}):[A-Za-z0-9+=,.@_:/-]+$`)
	providerRemediationAgentRolePattern = regexp.MustCompile(`^arn:aws:iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]{1,512}$`)
	providerRemediationRegionPattern    = regexp.MustCompile(`^[a-z]{2}(?:-gov)?-[a-z]+-[1-9]$`)
)

// Kinds of discovered agent a remediation acts on.
const (
	ProviderRemediationKindBedrockAgent     = "aws_bedrock_agent"
	ProviderRemediationKindAgentCoreRuntime = "aws_agentcore_runtime"
	ProviderRemediationKindInferredAgent    = "aws_inferred_agent"
)

// ProviderRemediationTarget is the discovered agent a remediation acts on.
// AgentARN is the ARN of the agent's own resource (a Bedrock agent, an
// AgentCore runtime, a Lambda function, an IAM role or an EC2 instance).
// AgentID is set for a Bedrock agent only. RoleARN is the IAM role discovery
// linked the agent to; it is "" for a Bedrock agent whose role discovery did
// not record (the worker reads it from the provider).
type ProviderRemediationTarget struct {
	AccountID string `json:"account_id"`
	Region    string `json:"region"`
	Kind      string `json:"kind"`
	AgentID   string `json:"agent_id"`
	AgentARN  string `json:"agent_arn"`
	RoleARN   string `json:"role_arn"`
}

// ProviderRemediationClaim is one leased remediation. ExternalIDReference is
// a reference: the claim never carries a secret.
type ProviderRemediationClaim struct {
	OrganizationID      string                    `json:"organization_id"`
	WorkspaceID         string                    `json:"workspace_id"`
	EnvironmentID       string                    `json:"environment_id"`
	RunID               string                    `json:"run_id"`
	StepID              string                    `json:"step_id"`
	Action              string                    `json:"action"`
	IntegrationID       string                    `json:"integration_id"`
	EntityID            string                    `json:"entity_id"`
	Target              ProviderRemediationTarget `json:"target"`
	Parameters          map[string]string         `json:"parameters"`
	RemediationRoleARN  string                    `json:"remediation_role_arn"`
	ExternalIDReference string                    `json:"external_id_reference"`
	InputDigest         string                    `json:"input_digest"`
	Attempt             int                       `json:"attempt"`
}

// ProviderRemediationOutcome is the worker's report. Prior is the rollback
// record (what the provider held before the change) and Observed is what the
// read-back found; both are set exactly when the outcome is verified, and
// both hold identifiers only.
type ProviderRemediationOutcome struct {
	State       string
	FailureCode string
	Prior       map[string]any
	Observed    map[string]any
}

// ProviderRemediationResult is PostgreSQL's answer to a report.
type ProviderRemediationResult struct {
	RunID       string `json:"run_id"`
	StepID      string `json:"step_id"`
	State       string `json:"state"`
	EffectState string `json:"effect_state"`
}

// SecurityAgentProviderRemediationAuthority is implemented by the action
// repository of the current catalog.
type SecurityAgentProviderRemediationAuthority interface {
	ProviderRemediationsAvailable() bool
	ClaimProviderRemediations(context.Context, string, string, int, int) ([]ProviderRemediationClaim, error)
	FinishProviderRemediation(context.Context, ProviderRemediationClaim, string, string, ProviderRemediationOutcome) (ProviderRemediationResult, error)
}

// validProviderRemediationTarget reports whether the target of an action is a
// discovered agent the action may act on. A guardrail is attached to a
// Bedrock agent only. A policy is detached from the role of a Bedrock agent
// (recorded or not) or from the recorded role of an AgentCore runtime or an
// inferred agent. The agent, its role and the remediation role are all of
// one account, and the agent's role is never the remediation role.
func validProviderRemediationTarget(action string, target ProviderRemediationTarget, remediationRoleARN string) bool {
	resource := providerRemediationResourcePattern.FindStringSubmatch(target.AgentARN)
	if len(resource) != 2 || resource[1] != target.AccountID || len(target.AgentARN) > 2048 || !providerRemediationRegionPattern.MatchString(target.Region) {
		return false
	}
	if target.RoleARN != "" {
		role := providerRemediationAgentRolePattern.FindStringSubmatch(target.RoleARN)
		if len(role) != 2 || role[1] != target.AccountID || target.RoleARN == remediationRoleARN {
			return false
		}
	}
	switch target.Kind {
	case ProviderRemediationKindBedrockAgent:
		agent := providerRemediationAgentARNPattern.FindStringSubmatch(target.AgentARN)
		return len(agent) == 4 && agent[1] == target.Region && agent[2] == target.AccountID && agent[3] == target.AgentID
	case ProviderRemediationKindAgentCoreRuntime, ProviderRemediationKindInferredAgent:
		return action == securityagent.ActionDetachRoleAdministratorPolicy && target.AgentID == "" && target.RoleARN != ""
	}
	return false
}

// ValidProviderRemediationClaim reports whether a claim is complete and
// consistent: the target is a discovered agent the action may act on, the
// parameters are the action's, and the remediation role is a role of the
// agent's own account.
func ValidProviderRemediationClaim(claim ProviderRemediationClaim) bool {
	role := providerRemediationRolePattern.FindStringSubmatch(claim.RemediationRoleARN)
	return validProductID(claim.OrganizationID) && validProductID(claim.WorkspaceID) && validProductID(claim.EnvironmentID) && validProductID(claim.RunID) && validProductID(claim.StepID) &&
		validProductID(claim.IntegrationID) && validProductID(claim.EntityID) && validProviderRemediationTarget(claim.Action, claim.Target, claim.RemediationRoleARN) &&
		len(role) == 2 && role[1] == claim.Target.AccountID && providerRemediationReferencePattern.MatchString(claim.ExternalIDReference) && securityAgentPlanHashPattern.MatchString(claim.InputDigest) &&
		claim.Attempt >= 1 && claim.Attempt <= 5 && securityagent.ValidProviderRemediationParameters(claim.Action, claim.Parameters, claim.Target.AccountID, claim.Target.Region)
}

func validProviderRemediationOutcome(outcome ProviderRemediationOutcome) bool {
	switch outcome.State {
	case ProviderRemediationVerified:
		return outcome.FailureCode == "" && outcome.Prior != nil && outcome.Observed != nil
	case ProviderRemediationFailed, ProviderRemediationUnknown:
		return providerRemediationFailurePattern.MatchString(outcome.FailureCode) && outcome.Prior == nil && outcome.Observed == nil
	}
	return false
}

// ProviderRemediationsAvailable reports whether this repository serves the
// current catalog, the only one that holds the remediation functions.
func (repository *SecurityAgentActionRepository) ProviderRemediationsAvailable() bool {
	return repository != nil && repository.current
}

func (repository *SecurityAgentActionRepository) ClaimProviderRemediations(ctx context.Context, workerID, leaseToken string, leaseSeconds, limit int) ([]ProviderRemediationClaim, error) {
	if repository == nil || ctx == nil || ctx.Err() != nil || !validSecurityAgentWorkerLease(workerID, leaseToken, leaseSeconds) || limit < 1 || limit > 25 {
		return nil, ErrRepositoryOperation
	}
	if !repository.ProviderRemediationsAvailable() {
		return nil, nil
	}
	payload, err := repository.database.QueryJSON(ctx, currentSecurityAgentClaimProviderRemediationsSQL, workerID, leaseToken, leaseSeconds, limit)
	if err != nil {
		return nil, discoveryProviderError(err)
	}
	var envelope struct {
		Items []json.RawMessage `json:"items"`
	}
	if !exactJSONFields(payload, "items") || decodeStrictDiscovery(payload, &envelope) != nil || len(envelope.Items) > limit {
		return nil, ErrRepositoryUnavailable
	}
	claims := make([]ProviderRemediationClaim, len(envelope.Items))
	seen := make(map[string]struct{}, len(envelope.Items))
	for index, raw := range envelope.Items {
		var claim ProviderRemediationClaim
		if !exactJSONFields(raw, "action", "attempt", "entity_id", "environment_id", "external_id_reference", "input_digest", "integration_id", "organization_id", "parameters", "remediation_role_arn", "run_id", "step_id", "target", "workspace_id") ||
			!exactJSONFields(extractJSONField(raw, "target"), "account_id", "agent_arn", "agent_id", "kind", "region", "role_arn") || decodeStrictDiscovery(raw, &claim) != nil || !ValidProviderRemediationClaim(claim) {
			return nil, ErrRepositoryUnavailable
		}
		key := claim.OrganizationID + "\x1f" + claim.WorkspaceID + "\x1f" + claim.EnvironmentID + "\x1f" + claim.RunID + "\x1f" + claim.StepID
		if _, duplicate := seen[key]; duplicate {
			return nil, ErrRepositoryUnavailable
		}
		seen[key] = struct{}{}
		claims[index] = claim
	}
	return claims, nil
}

func (repository *SecurityAgentActionRepository) FinishProviderRemediation(ctx context.Context, claim ProviderRemediationClaim, workerID, leaseToken string, outcome ProviderRemediationOutcome) (ProviderRemediationResult, error) {
	if repository == nil || !repository.ProviderRemediationsAvailable() || ctx == nil || ctx.Err() != nil || !ValidProviderRemediationClaim(claim) || !validSecurityAgentWorkerLease(workerID, leaseToken, 30) || !validProviderRemediationOutcome(outcome) {
		return ProviderRemediationResult{}, ErrRepositoryOperation
	}
	var failure, prior, observed any
	if outcome.State == ProviderRemediationVerified {
		priorJSON, priorErr := json.Marshal(outcome.Prior)
		observedJSON, observedErr := json.Marshal(outcome.Observed)
		if priorErr != nil || observedErr != nil || len(priorJSON) > 4096 || len(observedJSON) > 4096 {
			return ProviderRemediationResult{}, ErrRepositoryOperation
		}
		prior, observed = string(priorJSON), string(observedJSON)
	} else {
		failure = outcome.FailureCode
	}
	payload, err := repository.database.QueryJSON(ctx, currentSecurityAgentFinishProviderRemediationSQL, claim.OrganizationID, claim.WorkspaceID, claim.EnvironmentID, claim.RunID, claim.StepID, workerID, leaseToken, outcome.State, failure, prior, observed)
	if err != nil {
		return ProviderRemediationResult{}, discoveryProviderError(err)
	}
	var result ProviderRemediationResult
	wantRun, wantEffect := "needs_human", "known_failure"
	switch outcome.State {
	case ProviderRemediationVerified:
		wantRun, wantEffect = "remediated", "verified"
	case ProviderRemediationUnknown:
		wantEffect = "unknown_outcome"
	}
	if !exactJSONFields(payload, "effect_state", "run_id", "state", "step_id") || decodeStrictDiscovery(payload, &result) != nil || result.RunID != claim.RunID || result.StepID != claim.StepID || result.State != wantRun || result.EffectState != wantEffect {
		return ProviderRemediationResult{}, ErrRepositoryUnavailable
	}
	return result, nil
}
