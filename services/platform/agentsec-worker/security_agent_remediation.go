package main

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagent"
	bedrockagenttypes "github.com/aws/aws-sdk-go-v2/service/bedrockagent/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/smithy-go"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/securityagent"
)

// Provider remediations: the two Security Agent actions that change a
// customer's AWS account after a person approved them.
//
// The executor never holds the discovery (read) role. For each claim it asks
// the client factory for clients of the integration's remediation role, and
// it follows one rule for every provider call: an error before the first
// write is a refusal (nothing changed) or a transient condition (the lease
// expires and the remediation is claimed again); an error of the write itself
// that is not a definite refusal means the outcome is not known, and the run
// is handed to a person rather than retried. A success is reported only after
// the provider was read back.
//
// IAM actions the remediation role needs, and nothing else:
//   bedrock:GetAgent, bedrock:UpdateAgent, bedrock:PrepareAgent
//   iam:ListAttachedRolePolicies, iam:DetachRolePolicy
// UpdateAgent names the agent's own execution role again; AWS documents that
// passing a role to a service needs iam:PassRole on that role. That
// requirement is from the AWS documentation as remembered, not verified here
// against a live account; docs/operations/production-aws-runbook.md says so.

// The Bedrock Agents calls of a remediation.
type remediationBedrockAgentAPI interface {
	GetAgent(context.Context, *bedrockagent.GetAgentInput, ...func(*bedrockagent.Options)) (*bedrockagent.GetAgentOutput, error)
	UpdateAgent(context.Context, *bedrockagent.UpdateAgentInput, ...func(*bedrockagent.Options)) (*bedrockagent.UpdateAgentOutput, error)
	PrepareAgent(context.Context, *bedrockagent.PrepareAgentInput, ...func(*bedrockagent.Options)) (*bedrockagent.PrepareAgentOutput, error)
}

// The IAM calls of a remediation.
type remediationIAMAPI interface {
	ListAttachedRolePolicies(context.Context, *iam.ListAttachedRolePoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error)
	DetachRolePolicy(context.Context, *iam.DetachRolePolicyInput, ...func(*iam.Options)) (*iam.DetachRolePolicyOutput, error)
}

// remediationProviderClients are clients that act as the remediation role of
// one integration, in the Region of the target agent.
type remediationProviderClients struct {
	Bedrock remediationBedrockAgentAPI
	IAM     remediationIAMAPI
}

// remediationClientFactory assumes the remediation role named in the claim
// and returns clients for it. It must never return clients of another role.
// errRemediationRoleDenied means the role could not be assumed with the
// integration's external ID: nothing can have changed.
type remediationClientFactory interface {
	RemediationClients(context.Context, apiserver.ProviderRemediationClaim) (remediationProviderClients, error)
}

var (
	errRemediationRoleDenied = errors.New("remediation role denied")
	errRemediationRetry      = errors.New("remediation retry")

	remediationRoleNamePattern = regexp.MustCompile(`^arn:aws(?:-us-gov|-cn)?:iam::([0-9]{12}):role/(?:[A-Za-z0-9+=,.@_-]{1,128}/)*([A-Za-z0-9+=,.@_-]{1,64})$`)
)

// Failure codes reported to PostgreSQL (and shown on the run).
const (
	remediationFailureRoleDenied       = "remediation_role_denied"
	remediationFailureAccessDenied     = "provider_access_denied"
	remediationFailureTargetNotFound   = "target_not_found"
	remediationFailureTargetMismatch   = "target_mismatch"
	remediationFailureProviderRejected = "provider_rejected"
	remediationFailurePolicyNotOnRole  = "policy_not_attached"
	remediationFailureOutcomeUnknown   = "provider_outcome_unknown"
	remediationFailureVerification     = "verification_mismatch"
)

type securityAgentRemediationExecutor struct {
	factory remediationClientFactory
	timeout time.Duration
}

func newSecurityAgentRemediationExecutor(factory remediationClientFactory, timeout time.Duration) (*securityAgentRemediationExecutor, error) {
	if factory == nil || timeout < time.Second || timeout > 2*time.Minute {
		return nil, errWorkerConfiguration
	}
	return &securityAgentRemediationExecutor{factory: factory, timeout: timeout}, nil
}

func remediationFailed(code string) apiserver.ProviderRemediationOutcome {
	return apiserver.ProviderRemediationOutcome{State: apiserver.ProviderRemediationFailed, FailureCode: code}
}

func remediationUnknown(code string) apiserver.ProviderRemediationOutcome {
	return apiserver.ProviderRemediationOutcome{State: apiserver.ProviderRemediationUnknown, FailureCode: code}
}

// Execute performs one claimed remediation. It returns errRemediationRetry
// when nothing was changed and the same claim may be tried again later; any
// other result is an outcome to report.
func (executor *securityAgentRemediationExecutor) Execute(ctx context.Context, claim apiserver.ProviderRemediationClaim) (apiserver.ProviderRemediationOutcome, error) {
	if executor == nil || executor.factory == nil || ctx == nil || !apiserver.ValidProviderRemediationClaim(claim) {
		return apiserver.ProviderRemediationOutcome{}, errWorkerExecution
	}
	bounded, cancel := context.WithTimeout(ctx, executor.timeout)
	defer cancel()
	clients, err := executor.factory.RemediationClients(bounded, claim)
	if err != nil {
		if errors.Is(err, errRemediationRoleDenied) {
			return remediationFailed(remediationFailureRoleDenied), nil
		}
		return apiserver.ProviderRemediationOutcome{}, errRemediationRetry
	}
	if clients.Bedrock == nil || clients.IAM == nil {
		return apiserver.ProviderRemediationOutcome{}, errWorkerExecution
	}
	agent, outcome, err := executor.readTargetAgent(bounded, clients.Bedrock, claim)
	if err != nil || agent == nil {
		return outcome, err
	}
	switch claim.Action {
	case securityagent.ActionAttachBedrockGuardrail:
		return executor.attachGuardrail(bounded, clients.Bedrock, claim, agent)
	case securityagent.ActionDetachRoleAdministratorPolicy:
		return executor.detachRolePolicy(bounded, clients.IAM, claim, agent)
	}
	return apiserver.ProviderRemediationOutcome{}, errWorkerExecution
}

// classifyRemediationRead maps the error of a call that changes nothing.
func classifyRemediationRead(ctx context.Context, err error) (apiserver.ProviderRemediationOutcome, error) {
	switch remediationErrorClass(ctx, err) {
	case "denied":
		return remediationFailed(remediationFailureAccessDenied), nil
	case "not_found":
		return remediationFailed(remediationFailureTargetNotFound), nil
	case "rejected":
		return remediationFailed(remediationFailureProviderRejected), nil
	}
	return apiserver.ProviderRemediationOutcome{}, errRemediationRetry
}

// remediationErrorClass names what a provider error says about the request:
// denied, not_found and rejected are definite refusals; everything else
// (throttling, conflicts, server errors, a broken connection, a deadline) is
// "unknown".
func remediationErrorClass(ctx context.Context, err error) string {
	var provider smithy.APIError
	if err == nil || ctx.Err() != nil || !errors.As(err, &provider) {
		return "unknown"
	}
	switch provider.ErrorCode() {
	case "AccessDeniedException", "AccessDenied", "UnauthorizedOperation":
		return "denied"
	case "ResourceNotFoundException", "NoSuchEntity":
		return "not_found"
	case "ValidationException", "InvalidInput", "UnmodifiableEntity":
		return "rejected"
	}
	return "unknown"
}

func (executor *securityAgentRemediationExecutor) readTargetAgent(ctx context.Context, client remediationBedrockAgentAPI, claim apiserver.ProviderRemediationClaim) (*bedrockagenttypes.Agent, apiserver.ProviderRemediationOutcome, error) {
	output, err := client.GetAgent(ctx, &bedrockagent.GetAgentInput{AgentId: aws.String(claim.Target.AgentID)})
	if err != nil {
		outcome, retry := classifyRemediationRead(ctx, err)
		return nil, outcome, retry
	}
	if output == nil || output.Agent == nil {
		return nil, apiserver.ProviderRemediationOutcome{}, errRemediationRetry
	}
	agent := output.Agent
	// The provider must describe the agent the approval was given for.
	if aws.ToString(agent.AgentId) != claim.Target.AgentID || aws.ToString(agent.AgentArn) != claim.Target.AgentARN {
		return nil, remediationFailed(remediationFailureTargetMismatch), nil
	}
	return agent, apiserver.ProviderRemediationOutcome{}, nil
}

func guardrailRecord(configuration *bedrockagenttypes.GuardrailConfiguration) any {
	if configuration == nil || aws.ToString(configuration.GuardrailIdentifier) == "" {
		return nil
	}
	return map[string]any{"guardrail_identifier": aws.ToString(configuration.GuardrailIdentifier), "guardrail_version": aws.ToString(configuration.GuardrailVersion)}
}

// guardrailID is the identifier of a guardrail named by identifier or ARN.
func guardrailID(value string) string {
	if index := strings.LastIndex(value, "guardrail/"); index >= 0 {
		return value[index+len("guardrail/"):]
	}
	return value
}

func guardrailMatches(configuration *bedrockagenttypes.GuardrailConfiguration, identifier, version string) bool {
	return configuration != nil && guardrailID(aws.ToString(configuration.GuardrailIdentifier)) != "" && guardrailID(aws.ToString(configuration.GuardrailIdentifier)) == guardrailID(identifier) && aws.ToString(configuration.GuardrailVersion) == version
}

func (executor *securityAgentRemediationExecutor) attachGuardrail(ctx context.Context, client remediationBedrockAgentAPI, claim apiserver.ProviderRemediationClaim, agent *bedrockagenttypes.Agent) (apiserver.ProviderRemediationOutcome, error) {
	identifier, version := claim.Parameters["guardrail_identifier"], claim.Parameters["guardrail_version"]
	// The rollback record: what the agent held before this action.
	prior := map[string]any{"agent_id": claim.Target.AgentID, "guardrail_configuration": guardrailRecord(agent.GuardrailConfiguration), "changed": true}
	prepared := "not_required"
	if guardrailMatches(agent.GuardrailConfiguration, identifier, version) {
		// Already attached: nothing to change and nothing to roll back.
		prior["changed"] = false
	} else {
		switch agent.AgentStatus {
		case bedrockagenttypes.AgentStatusCreating, bedrockagenttypes.AgentStatusDeleting, bedrockagenttypes.AgentStatusPreparing, bedrockagenttypes.AgentStatusUpdating, bedrockagenttypes.AgentStatusVersioning:
			// The agent is being changed by someone else; try again later.
			return apiserver.ProviderRemediationOutcome{}, errRemediationRetry
		}
		// UpdateAgent replaces the agent's configuration, so every field the
		// agent has is sent back unchanged; only the guardrail differs.
		input := &bedrockagent.UpdateAgentInput{
			AgentId: agent.AgentId, AgentName: agent.AgentName, AgentResourceRoleArn: agent.AgentResourceRoleArn, FoundationModel: agent.FoundationModel,
			AgentCollaboration: agent.AgentCollaboration, CustomOrchestration: agent.CustomOrchestration, CustomerEncryptionKeyArn: agent.CustomerEncryptionKeyArn,
			Description: agent.Description, IdleSessionTTLInSeconds: agent.IdleSessionTTLInSeconds, Instruction: agent.Instruction, MemoryConfiguration: agent.MemoryConfiguration,
			OrchestrationType: agent.OrchestrationType, PromptOverrideConfiguration: agent.PromptOverrideConfiguration,
			GuardrailConfiguration: &bedrockagenttypes.GuardrailConfiguration{GuardrailIdentifier: aws.String(identifier), GuardrailVersion: aws.String(version)},
		}
		if _, err := client.UpdateAgent(ctx, input); err != nil {
			switch remediationErrorClass(ctx, err) {
			case "denied":
				return remediationFailed(remediationFailureAccessDenied), nil
			case "not_found":
				return remediationFailed(remediationFailureTargetNotFound), nil
			case "rejected":
				return remediationFailed(remediationFailureProviderRejected), nil
			}
			return remediationUnknown(remediationFailureOutcomeUnknown), nil
		}
		// The working draft takes the change when the agent is prepared. A
		// failure to prepare does not undo the attachment; it is recorded.
		prepared = "prepared"
		if _, err := client.PrepareAgent(ctx, &bedrockagent.PrepareAgentInput{AgentId: agent.AgentId}); err != nil {
			prepared = "failed"
		}
	}
	verify, err := client.GetAgent(ctx, &bedrockagent.GetAgentInput{AgentId: aws.String(claim.Target.AgentID)})
	if err != nil || verify == nil || verify.Agent == nil {
		if prior["changed"] == false {
			return apiserver.ProviderRemediationOutcome{}, errRemediationRetry
		}
		return remediationUnknown(remediationFailureOutcomeUnknown), nil
	}
	if aws.ToString(verify.Agent.AgentArn) != claim.Target.AgentARN || !guardrailMatches(verify.Agent.GuardrailConfiguration, identifier, version) {
		return remediationUnknown(remediationFailureVerification), nil
	}
	observed := map[string]any{"agent_id": claim.Target.AgentID, "guardrail_configuration": guardrailRecord(verify.Agent.GuardrailConfiguration), "agent_status": string(verify.Agent.AgentStatus), "prepare": prepared}
	return apiserver.ProviderRemediationOutcome{State: apiserver.ProviderRemediationVerified, Prior: prior, Observed: observed}, nil
}

// attachedRolePolicy reports whether the policy is attached to the role, and
// its name. It reads at most 20 pages of 100 policies.
func attachedRolePolicy(ctx context.Context, client remediationIAMAPI, roleName, policyARN string) (attached bool, policyName string, err error) {
	var marker *string
	for page := 0; page < 20; page++ {
		output, listErr := client.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{RoleName: aws.String(roleName), Marker: marker, MaxItems: aws.Int32(100)})
		if listErr != nil {
			return false, "", listErr
		}
		if output == nil {
			return false, "", errRemediationRetry
		}
		for _, policy := range output.AttachedPolicies {
			if aws.ToString(policy.PolicyArn) == policyARN {
				return true, aws.ToString(policy.PolicyName), nil
			}
		}
		if !output.IsTruncated || aws.ToString(output.Marker) == "" {
			return false, "", nil
		}
		marker = output.Marker
	}
	return false, "", errRemediationRetry
}

func (executor *securityAgentRemediationExecutor) detachRolePolicy(ctx context.Context, client remediationIAMAPI, claim apiserver.ProviderRemediationClaim, agent *bedrockagenttypes.Agent) (apiserver.ProviderRemediationOutcome, error) {
	policyARN := claim.Parameters["policy_arn"]
	roleARN := aws.ToString(agent.AgentResourceRoleArn)
	match := remediationRoleNamePattern.FindStringSubmatch(roleARN)
	// The role is the one the provider says the agent runs as, in the agent's
	// own account. The request cannot name another role.
	if len(match) != 3 || match[1] != claim.Target.AccountID {
		return remediationFailed(remediationFailureTargetMismatch), nil
	}
	roleName := match[2]
	attached, policyName, err := attachedRolePolicy(ctx, client, roleName, policyARN)
	if err != nil {
		if errors.Is(err, errRemediationRetry) {
			return apiserver.ProviderRemediationOutcome{}, errRemediationRetry
		}
		return classifyRemediationRead(ctx, err)
	}
	if !attached {
		// Never detach anything that is not attached to this role.
		return remediationFailed(remediationFailurePolicyNotOnRole), nil
	}
	if _, err := client.DetachRolePolicy(ctx, &iam.DetachRolePolicyInput{RoleName: aws.String(roleName), PolicyArn: aws.String(policyARN)}); err != nil {
		switch remediationErrorClass(ctx, err) {
		case "denied":
			return remediationFailed(remediationFailureAccessDenied), nil
		case "rejected":
			return remediationFailed(remediationFailureProviderRejected), nil
		case "not_found":
			// Detached by someone else between the two calls: verify below.
		default:
			return remediationUnknown(remediationFailureOutcomeUnknown), nil
		}
	}
	still, _, err := attachedRolePolicy(ctx, client, roleName, policyARN)
	if err != nil {
		return remediationUnknown(remediationFailureOutcomeUnknown), nil
	}
	if still {
		return remediationUnknown(remediationFailureVerification), nil
	}
	// The rollback record: attaching this policy to this role again restores
	// the prior state.
	prior := map[string]any{"role_arn": roleARN, "role_name": roleName, "policy_arn": policyARN, "policy_name": policyName, "attached": true}
	observed := map[string]any{"role_arn": roleARN, "role_name": roleName, "policy_arn": policyARN, "attached": false}
	return apiserver.ProviderRemediationOutcome{State: apiserver.ProviderRemediationVerified, Prior: prior, Observed: observed}, nil
}

// processProviderRemediations claims and performs dispatched remediations.
func (processor *securityAgentActionProcessor) processProviderRemediations(ctx context.Context) error {
	authority, ok := processor.config.Authority.(apiserver.SecurityAgentProviderRemediationAuthority)
	if !ok || processor.config.Remediation == nil || !authority.ProviderRemediationsAvailable() {
		return nil
	}
	leaseToken, err := processor.config.NewLeaseToken()
	if err != nil || len(leaseToken) < 16 || len(leaseToken) > 128 {
		return errWorkerExecution
	}
	claims, err := authority.ClaimProviderRemediations(ctx, processor.config.WorkerID, leaseToken, processor.config.LeaseSeconds, processor.config.BatchSize)
	if err != nil {
		return errWorkerExecution
	}
	var failed error
	for _, claim := range claims {
		if ctx.Err() != nil {
			return nil
		}
		outcome, executeErr := processor.config.Remediation.Execute(ctx, claim)
		if errors.Is(executeErr, errRemediationRetry) {
			// Nothing changed. The lease expires and the claim is taken again;
			// PostgreSQL hands the run to a person after five claims.
			continue
		}
		if executeErr != nil {
			failed = errWorkerExecution
			continue
		}
		if _, finishErr := authority.FinishProviderRemediation(ctx, claim, processor.config.WorkerID, leaseToken, outcome); finishErr != nil {
			failed = errWorkerExecution
		}
	}
	return failed
}
