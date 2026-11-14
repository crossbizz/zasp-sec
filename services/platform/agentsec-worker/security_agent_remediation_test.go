package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagent"
	bedrockagenttypes "github.com/aws/aws-sdk-go-v2/service/bedrockagent/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/smithy-go"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/securityagent"
)

const (
	remediationTestAgentARN = "arn:aws:bedrock:us-east-1:123456789012:agent/AGENT12345"
	remediationTestRoleARN  = "arn:aws:iam::123456789012:role/service-role/support-agent-role"
	remediationTestAdmin    = "arn:aws:iam::aws:policy/AdministratorAccess"
)

func remediationTestClaim(action string, parameters map[string]string) apiserver.ProviderRemediationClaim {
	return apiserver.ProviderRemediationClaim{
		OrganizationID: "pid_a0000000-0000-4000-8000-000000000001", WorkspaceID: "pid_a0000000-0000-4000-8000-000000000002", EnvironmentID: "pid_a0000000-0000-4000-8000-000000000003",
		RunID: "pid_a0000000-0000-4000-8000-000000000060", StepID: "pid_a0000000-0000-4000-8000-000000000061", Action: action,
		IntegrationID: "pid_a0000000-0000-4000-8000-000000000040", EntityID: "pid_a0000000-0000-4000-8000-000000000030",
		Target:     apiserver.ProviderRemediationTarget{AccountID: "123456789012", Region: "us-east-1", AgentID: "AGENT12345", AgentARN: remediationTestAgentARN},
		Parameters: parameters, RemediationRoleARN: "arn:aws:iam::123456789012:role/zasp-remediation", ExternalIDReference: "ref:aws/external-id/abcdefgh12345678",
		InputDigest: "sha256:8e21ce38806cc848563f3a1eba2e21d1b4a0b4da7f0fadcf284cb41517e6d5c8", Attempt: 1,
	}
}

func remediationAPIError(code string) error {
	return &smithy.GenericAPIError{Code: code, Message: "provider said " + code}
}

// fakeRemediationBedrock is an in-memory Bedrock agent. It records every
// call so a test can prove what was and was not sent to the provider.
type fakeRemediationBedrock struct {
	agent                            *bedrockagenttypes.Agent
	getErr, updateErr, prepareErr    error
	getErrOnCall                     int
	gets, updates, prepares          int
	lastUpdate                       *bedrockagent.UpdateAgentInput
	dropUpdate                       bool
	calls                            []string
	updateErrAfterApplying           bool
	statusAfterUpdate, statusPrepare bedrockagenttypes.AgentStatus
}

func (fake *fakeRemediationBedrock) GetAgent(_ context.Context, input *bedrockagent.GetAgentInput, _ ...func(*bedrockagent.Options)) (*bedrockagent.GetAgentOutput, error) {
	fake.gets++
	fake.calls = append(fake.calls, "GetAgent")
	if fake.getErr != nil && (fake.getErrOnCall == 0 || fake.getErrOnCall == fake.gets) {
		return nil, fake.getErr
	}
	if fake.agent == nil || aws.ToString(input.AgentId) != aws.ToString(fake.agent.AgentId) {
		return nil, remediationAPIError("ResourceNotFoundException")
	}
	copied := *fake.agent
	return &bedrockagent.GetAgentOutput{Agent: &copied}, nil
}

func (fake *fakeRemediationBedrock) UpdateAgent(_ context.Context, input *bedrockagent.UpdateAgentInput, _ ...func(*bedrockagent.Options)) (*bedrockagent.UpdateAgentOutput, error) {
	fake.updates++
	fake.calls = append(fake.calls, "UpdateAgent")
	fake.lastUpdate = input
	if fake.updateErr != nil && !fake.updateErrAfterApplying {
		return nil, fake.updateErr
	}
	if !fake.dropUpdate {
		fake.agent.GuardrailConfiguration = input.GuardrailConfiguration
		fake.agent.AgentStatus = fake.statusAfterUpdate
	}
	if fake.updateErr != nil {
		return nil, fake.updateErr
	}
	copied := *fake.agent
	return &bedrockagent.UpdateAgentOutput{Agent: &copied}, nil
}

func (fake *fakeRemediationBedrock) PrepareAgent(_ context.Context, _ *bedrockagent.PrepareAgentInput, _ ...func(*bedrockagent.Options)) (*bedrockagent.PrepareAgentOutput, error) {
	fake.prepares++
	fake.calls = append(fake.calls, "PrepareAgent")
	if fake.prepareErr != nil {
		return nil, fake.prepareErr
	}
	fake.agent.AgentStatus = fake.statusPrepare
	return &bedrockagent.PrepareAgentOutput{AgentId: fake.agent.AgentId, AgentStatus: fake.statusPrepare}, nil
}

// fakeRemediationIAM is an in-memory role with attached managed policies,
// served two per page so pagination is exercised.
type fakeRemediationIAM struct {
	roleName            string
	policies            []iamtypes.AttachedPolicy
	listErr, detachErr  error
	listErrOnCall       int
	lists, detaches     int
	detached            []string
	keepAfterDetach     bool
	detachErrAfterApply bool
}

func (fake *fakeRemediationIAM) ListAttachedRolePolicies(_ context.Context, input *iam.ListAttachedRolePoliciesInput, _ ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
	fake.lists++
	if fake.listErr != nil && (fake.listErrOnCall == 0 || fake.listErrOnCall == fake.lists) {
		return nil, fake.listErr
	}
	if aws.ToString(input.RoleName) != fake.roleName {
		return nil, remediationAPIError("NoSuchEntity")
	}
	start := 0
	if marker := aws.ToString(input.Marker); marker != "" {
		for index, policy := range fake.policies {
			if aws.ToString(policy.PolicyArn) == marker {
				start = index
			}
		}
	}
	end := start + 2
	output := &iam.ListAttachedRolePoliciesOutput{}
	if end < len(fake.policies) {
		output.IsTruncated, output.Marker = true, fake.policies[end].PolicyArn
	} else {
		end = len(fake.policies)
	}
	output.AttachedPolicies = append([]iamtypes.AttachedPolicy(nil), fake.policies[start:end]...)
	return output, nil
}

func (fake *fakeRemediationIAM) DetachRolePolicy(_ context.Context, input *iam.DetachRolePolicyInput, _ ...func(*iam.Options)) (*iam.DetachRolePolicyOutput, error) {
	fake.detaches++
	if fake.detachErr != nil && !fake.detachErrAfterApply {
		return nil, fake.detachErr
	}
	if aws.ToString(input.RoleName) != fake.roleName {
		return nil, remediationAPIError("NoSuchEntity")
	}
	fake.detached = append(fake.detached, aws.ToString(input.PolicyArn))
	if !fake.keepAfterDetach {
		kept := fake.policies[:0:0]
		for _, policy := range fake.policies {
			if aws.ToString(policy.PolicyArn) != aws.ToString(input.PolicyArn) {
				kept = append(kept, policy)
			}
		}
		fake.policies = kept
	}
	if fake.detachErr != nil {
		return nil, fake.detachErr
	}
	return &iam.DetachRolePolicyOutput{}, nil
}

type fakeRemediationFactory struct {
	clients remediationProviderClients
	err     error
	claims  []apiserver.ProviderRemediationClaim
}

func (fake *fakeRemediationFactory) RemediationClients(_ context.Context, claim apiserver.ProviderRemediationClaim) (remediationProviderClients, error) {
	fake.claims = append(fake.claims, claim)
	return fake.clients, fake.err
}

func remediationTestAgent() *bedrockagenttypes.Agent {
	return &bedrockagenttypes.Agent{
		AgentArn: aws.String(remediationTestAgentARN), AgentId: aws.String("AGENT12345"), AgentName: aws.String("support-agent"), AgentResourceRoleArn: aws.String(remediationTestRoleARN),
		AgentStatus: bedrockagenttypes.AgentStatusPrepared, FoundationModel: aws.String("anthropic.claude-3-haiku-20240307-v1:0"), Instruction: aws.String("Answer support questions about orders."),
		Description: aws.String("Support"), IdleSessionTTLInSeconds: aws.Int32(600), OrchestrationType: bedrockagenttypes.OrchestrationTypeDefault,
		MemoryConfiguration: &bedrockagenttypes.MemoryConfiguration{StorageDays: aws.Int32(30)},
	}
}

func remediationTestExecutor(t *testing.T, bedrock *fakeRemediationBedrock, policies *fakeRemediationIAM) (*securityAgentRemediationExecutor, *fakeRemediationFactory) {
	t.Helper()
	factory := &fakeRemediationFactory{clients: remediationProviderClients{Bedrock: bedrock, IAM: policies}}
	executor, err := newSecurityAgentRemediationExecutor(factory, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return executor, factory
}

func TestRemediationAttachesGuardrailAndRecordsThePriorConfiguration(t *testing.T) {
	bedrock := &fakeRemediationBedrock{agent: remediationTestAgent(), statusAfterUpdate: bedrockagenttypes.AgentStatusNotPrepared, statusPrepare: bedrockagenttypes.AgentStatusPreparing}
	bedrock.agent.GuardrailConfiguration = &bedrockagenttypes.GuardrailConfiguration{GuardrailIdentifier: aws.String("oldguardrail"), GuardrailVersion: aws.String("2")}
	executor, factory := remediationTestExecutor(t, bedrock, &fakeRemediationIAM{})
	claim := remediationTestClaim(securityagent.ActionAttachBedrockGuardrail, map[string]string{"guardrail_identifier": "gr1abc", "guardrail_version": "3"})
	outcome, err := executor.Execute(context.Background(), claim)
	if err != nil || outcome.State != apiserver.ProviderRemediationVerified || outcome.FailureCode != "" {
		t.Fatalf("outcome=%#v err=%v", outcome, err)
	}
	// The clients were requested for the claim's remediation role only.
	if len(factory.claims) != 1 || factory.claims[0].RemediationRoleARN != "arn:aws:iam::123456789012:role/zasp-remediation" {
		t.Fatalf("factory claims=%#v", factory.claims)
	}
	if !reflect.DeepEqual(bedrock.calls, []string{"GetAgent", "UpdateAgent", "PrepareAgent", "GetAgent"}) {
		t.Fatalf("provider calls=%v", bedrock.calls)
	}
	// UpdateAgent replaces the configuration: every other field is sent back.
	update, agent := bedrock.lastUpdate, remediationTestAgent()
	if aws.ToString(update.AgentId) != "AGENT12345" || aws.ToString(update.AgentName) != aws.ToString(agent.AgentName) || aws.ToString(update.AgentResourceRoleArn) != remediationTestRoleARN || aws.ToString(update.FoundationModel) != aws.ToString(agent.FoundationModel) ||
		aws.ToString(update.Instruction) != aws.ToString(agent.Instruction) || aws.ToString(update.Description) != "Support" || aws.ToInt32(update.IdleSessionTTLInSeconds) != 600 || update.OrchestrationType != bedrockagenttypes.OrchestrationTypeDefault ||
		update.MemoryConfiguration == nil || aws.ToInt32(update.MemoryConfiguration.StorageDays) != 30 || aws.ToString(update.GuardrailConfiguration.GuardrailIdentifier) != "gr1abc" || aws.ToString(update.GuardrailConfiguration.GuardrailVersion) != "3" {
		t.Fatalf("update input=%#v", update)
	}
	wantPrior := map[string]any{"agent_id": "AGENT12345", "changed": true, "guardrail_configuration": map[string]any{"guardrail_identifier": "oldguardrail", "guardrail_version": "2"}}
	if !reflect.DeepEqual(outcome.Prior, wantPrior) {
		t.Fatalf("rollback record=%#v", outcome.Prior)
	}
	wantObserved := map[string]any{"agent_id": "AGENT12345", "agent_status": "PREPARING", "prepare": "prepared", "guardrail_configuration": map[string]any{"guardrail_identifier": "gr1abc", "guardrail_version": "3"}}
	if !reflect.DeepEqual(outcome.Observed, wantObserved) {
		t.Fatalf("observed=%#v", outcome.Observed)
	}
}

func TestRemediationAttachGuardrailRecordsNoPriorGuardrailAsNull(t *testing.T) {
	bedrock := &fakeRemediationBedrock{agent: remediationTestAgent(), statusAfterUpdate: bedrockagenttypes.AgentStatusNotPrepared, statusPrepare: bedrockagenttypes.AgentStatusPrepared}
	executor, _ := remediationTestExecutor(t, bedrock, &fakeRemediationIAM{})
	outcome, err := executor.Execute(context.Background(), remediationTestClaim(securityagent.ActionAttachBedrockGuardrail, map[string]string{"guardrail_identifier": "arn:aws:bedrock:us-east-1:123456789012:guardrail/gr1abc", "guardrail_version": "DRAFT"}))
	if err != nil || outcome.State != apiserver.ProviderRemediationVerified || outcome.Prior["guardrail_configuration"] != nil || outcome.Prior["changed"] != true {
		t.Fatalf("outcome=%#v err=%v", outcome, err)
	}
}

func TestRemediationAttachGuardrailIsIdempotent(t *testing.T) {
	bedrock := &fakeRemediationBedrock{agent: remediationTestAgent()}
	bedrock.agent.GuardrailConfiguration = &bedrockagenttypes.GuardrailConfiguration{GuardrailIdentifier: aws.String("gr1abc"), GuardrailVersion: aws.String("3")}
	executor, _ := remediationTestExecutor(t, bedrock, &fakeRemediationIAM{})
	outcome, err := executor.Execute(context.Background(), remediationTestClaim(securityagent.ActionAttachBedrockGuardrail, map[string]string{"guardrail_identifier": "gr1abc", "guardrail_version": "3"}))
	if err != nil || outcome.State != apiserver.ProviderRemediationVerified || bedrock.updates != 0 || bedrock.prepares != 0 || outcome.Prior["changed"] != false || outcome.Observed["prepare"] != "not_required" {
		t.Fatalf("outcome=%#v err=%v updates=%d", outcome, err, bedrock.updates)
	}
}

func TestRemediationAttachGuardrailRefusals(t *testing.T) {
	parameters := map[string]string{"guardrail_identifier": "gr1abc", "guardrail_version": "3"}
	for _, test := range []struct {
		name      string
		prepare   func(*fakeRemediationBedrock, *fakeRemediationFactory)
		state     string
		failure   string
		retry     bool
		noUpdates bool
	}{
		{name: "the provider describes another agent", prepare: func(bedrock *fakeRemediationBedrock, _ *fakeRemediationFactory) {
			bedrock.agent.AgentArn = aws.String("arn:aws:bedrock:us-east-1:210987654321:agent/AGENT12345")
		}, state: apiserver.ProviderRemediationFailed, failure: remediationFailureTargetMismatch, noUpdates: true},
		{name: "the agent no longer exists", prepare: func(bedrock *fakeRemediationBedrock, _ *fakeRemediationFactory) { bedrock.agent = nil }, state: apiserver.ProviderRemediationFailed, failure: remediationFailureTargetNotFound, noUpdates: true},
		{name: "reading the agent is denied", prepare: func(bedrock *fakeRemediationBedrock, _ *fakeRemediationFactory) {
			bedrock.getErr = remediationAPIError("AccessDeniedException")
		}, state: apiserver.ProviderRemediationFailed, failure: remediationFailureAccessDenied, noUpdates: true},
		{name: "the remediation role cannot be assumed", prepare: func(_ *fakeRemediationBedrock, factory *fakeRemediationFactory) {
			factory.err = errRemediationRoleDenied
		}, state: apiserver.ProviderRemediationFailed, failure: remediationFailureRoleDenied, noUpdates: true},
		{name: "the role's clients are temporarily unavailable", prepare: func(_ *fakeRemediationBedrock, factory *fakeRemediationFactory) {
			factory.err = errors.New("secrets manager timeout")
		}, retry: true, noUpdates: true},
		{name: "reading the agent is throttled", prepare: func(bedrock *fakeRemediationBedrock, _ *fakeRemediationFactory) {
			bedrock.getErr = remediationAPIError("ThrottlingException")
		}, retry: true, noUpdates: true},
		{name: "the agent is being updated by someone else", prepare: func(bedrock *fakeRemediationBedrock, _ *fakeRemediationFactory) {
			bedrock.agent.AgentStatus = bedrockagenttypes.AgentStatusUpdating
		}, retry: true, noUpdates: true},
		{name: "the update is denied", prepare: func(bedrock *fakeRemediationBedrock, _ *fakeRemediationFactory) {
			bedrock.updateErr = remediationAPIError("AccessDeniedException")
		}, state: apiserver.ProviderRemediationFailed, failure: remediationFailureAccessDenied},
		{name: "the provider rejects the guardrail", prepare: func(bedrock *fakeRemediationBedrock, _ *fakeRemediationFactory) {
			bedrock.updateErr = remediationAPIError("ValidationException")
		}, state: apiserver.ProviderRemediationFailed, failure: remediationFailureProviderRejected},
		{name: "the update's outcome is not known", prepare: func(bedrock *fakeRemediationBedrock, _ *fakeRemediationFactory) {
			bedrock.updateErr, bedrock.updateErrAfterApplying = errors.New("connection reset"), true
		}, state: apiserver.ProviderRemediationUnknown, failure: remediationFailureOutcomeUnknown},
		{name: "the update is throttled after it was sent", prepare: func(bedrock *fakeRemediationBedrock, _ *fakeRemediationFactory) {
			bedrock.updateErr = remediationAPIError("ThrottlingException")
		}, state: apiserver.ProviderRemediationUnknown, failure: remediationFailureOutcomeUnknown},
		{name: "the read-back does not show the guardrail", prepare: func(bedrock *fakeRemediationBedrock, _ *fakeRemediationFactory) { bedrock.dropUpdate = true }, state: apiserver.ProviderRemediationUnknown, failure: remediationFailureVerification},
		{name: "the read-back fails after the update", prepare: func(bedrock *fakeRemediationBedrock, _ *fakeRemediationFactory) {
			bedrock.getErr, bedrock.getErrOnCall = remediationAPIError("InternalServerException"), 2
		}, state: apiserver.ProviderRemediationUnknown, failure: remediationFailureOutcomeUnknown},
	} {
		bedrock := &fakeRemediationBedrock{agent: remediationTestAgent(), statusAfterUpdate: bedrockagenttypes.AgentStatusNotPrepared, statusPrepare: bedrockagenttypes.AgentStatusPrepared}
		executor, factory := remediationTestExecutor(t, bedrock, &fakeRemediationIAM{})
		test.prepare(bedrock, factory)
		outcome, err := executor.Execute(context.Background(), remediationTestClaim(securityagent.ActionAttachBedrockGuardrail, parameters))
		if test.retry {
			if !errors.Is(err, errRemediationRetry) || outcome.State != "" {
				t.Fatalf("%s: outcome=%#v err=%v, want a retry", test.name, outcome, err)
			}
		} else if err != nil || outcome.State != test.state || outcome.FailureCode != test.failure || outcome.Prior != nil || outcome.Observed != nil {
			t.Fatalf("%s: outcome=%#v err=%v", test.name, outcome, err)
		}
		if test.noUpdates && (bedrock.updates != 0 || bedrock.prepares != 0) {
			t.Fatalf("%s: the provider was changed: updates=%d prepares=%d", test.name, bedrock.updates, bedrock.prepares)
		}
	}
}

func TestRemediationAttachGuardrailRecordsAFailedPrepare(t *testing.T) {
	bedrock := &fakeRemediationBedrock{agent: remediationTestAgent(), statusAfterUpdate: bedrockagenttypes.AgentStatusNotPrepared, prepareErr: remediationAPIError("AccessDeniedException")}
	executor, _ := remediationTestExecutor(t, bedrock, &fakeRemediationIAM{})
	outcome, err := executor.Execute(context.Background(), remediationTestClaim(securityagent.ActionAttachBedrockGuardrail, map[string]string{"guardrail_identifier": "gr1abc", "guardrail_version": "3"}))
	// The attachment itself was read back; the draft was not prepared, and
	// the observation says so.
	if err != nil || outcome.State != apiserver.ProviderRemediationVerified || outcome.Observed["prepare"] != "failed" || outcome.Observed["agent_status"] != "NOT_PREPARED" {
		t.Fatalf("outcome=%#v err=%v", outcome, err)
	}
}

func remediationTestPolicies() []iamtypes.AttachedPolicy {
	return []iamtypes.AttachedPolicy{
		{PolicyArn: aws.String("arn:aws:iam::aws:policy/AmazonBedrockFullAccess"), PolicyName: aws.String("AmazonBedrockFullAccess")},
		{PolicyArn: aws.String("arn:aws:iam::123456789012:policy/support-read"), PolicyName: aws.String("support-read")},
		{PolicyArn: aws.String(remediationTestAdmin), PolicyName: aws.String("AdministratorAccess")},
	}
}

func TestRemediationDetachesThePolicyAndRecordsIt(t *testing.T) {
	bedrock := &fakeRemediationBedrock{agent: remediationTestAgent()}
	policies := &fakeRemediationIAM{roleName: "support-agent-role", policies: remediationTestPolicies()}
	executor, _ := remediationTestExecutor(t, bedrock, policies)
	outcome, err := executor.Execute(context.Background(), remediationTestClaim(securityagent.ActionDetachRoleAdministratorPolicy, map[string]string{"policy_arn": remediationTestAdmin}))
	if err != nil || outcome.State != apiserver.ProviderRemediationVerified {
		t.Fatalf("outcome=%#v err=%v", outcome, err)
	}
	// Exactly the named policy was detached, from the role the provider says
	// the agent runs as, and the agent itself was not changed.
	if !reflect.DeepEqual(policies.detached, []string{remediationTestAdmin}) || len(policies.policies) != 2 || bedrock.updates != 0 || bedrock.prepares != 0 {
		t.Fatalf("detached=%v remaining=%d updates=%d", policies.detached, len(policies.policies), bedrock.updates)
	}
	wantPrior := map[string]any{"role_arn": remediationTestRoleARN, "role_name": "support-agent-role", "policy_arn": remediationTestAdmin, "policy_name": "AdministratorAccess", "attached": true}
	wantObserved := map[string]any{"role_arn": remediationTestRoleARN, "role_name": "support-agent-role", "policy_arn": remediationTestAdmin, "attached": false}
	if !reflect.DeepEqual(outcome.Prior, wantPrior) || !reflect.DeepEqual(outcome.Observed, wantObserved) {
		t.Fatalf("rollback record=%#v observed=%#v", outcome.Prior, outcome.Observed)
	}
}

func TestRemediationDetachPolicyRefusals(t *testing.T) {
	for _, test := range []struct {
		name      string
		policy    string
		prepare   func(*fakeRemediationBedrock, *fakeRemediationIAM)
		state     string
		failure   string
		retry     bool
		noDetach  bool
		wantState string
	}{
		{name: "the policy is not attached to the role", policy: "arn:aws:iam::aws:policy/PowerUserAccess", state: apiserver.ProviderRemediationFailed, failure: remediationFailurePolicyNotOnRole, noDetach: true},
		{name: "the agent runs as a role of another account", policy: remediationTestAdmin, prepare: func(bedrock *fakeRemediationBedrock, _ *fakeRemediationIAM) {
			bedrock.agent.AgentResourceRoleArn = aws.String("arn:aws:iam::210987654321:role/support-agent-role")
		}, state: apiserver.ProviderRemediationFailed, failure: remediationFailureTargetMismatch, noDetach: true},
		{name: "the agent has no execution role", policy: remediationTestAdmin, prepare: func(bedrock *fakeRemediationBedrock, _ *fakeRemediationIAM) { bedrock.agent.AgentResourceRoleArn = nil }, state: apiserver.ProviderRemediationFailed, failure: remediationFailureTargetMismatch, noDetach: true},
		{name: "the provider describes another agent", policy: remediationTestAdmin, prepare: func(bedrock *fakeRemediationBedrock, _ *fakeRemediationIAM) {
			bedrock.agent.AgentArn = aws.String("arn:aws:bedrock:us-east-1:123456789012:agent/OTHER00000")
		}, state: apiserver.ProviderRemediationFailed, failure: remediationFailureTargetMismatch, noDetach: true},
		{name: "listing the role's policies is denied", policy: remediationTestAdmin, prepare: func(_ *fakeRemediationBedrock, policies *fakeRemediationIAM) {
			policies.listErr = remediationAPIError("AccessDenied")
		}, state: apiserver.ProviderRemediationFailed, failure: remediationFailureAccessDenied, noDetach: true},
		{name: "the role no longer exists", policy: remediationTestAdmin, prepare: func(_ *fakeRemediationBedrock, policies *fakeRemediationIAM) { policies.roleName = "renamed" }, state: apiserver.ProviderRemediationFailed, failure: remediationFailureTargetNotFound, noDetach: true},
		{name: "listing the role's policies fails transiently", policy: remediationTestAdmin, prepare: func(_ *fakeRemediationBedrock, policies *fakeRemediationIAM) {
			policies.listErr = remediationAPIError("ServiceFailure")
		}, retry: true, noDetach: true},
		{name: "the detachment is denied", policy: remediationTestAdmin, prepare: func(_ *fakeRemediationBedrock, policies *fakeRemediationIAM) {
			policies.detachErr = remediationAPIError("AccessDenied")
		}, state: apiserver.ProviderRemediationFailed, failure: remediationFailureAccessDenied},
		{name: "the detachment's outcome is not known", policy: remediationTestAdmin, prepare: func(_ *fakeRemediationBedrock, policies *fakeRemediationIAM) {
			policies.detachErr, policies.detachErrAfterApply = errors.New("connection reset"), true
		}, state: apiserver.ProviderRemediationUnknown, failure: remediationFailureOutcomeUnknown},
		{name: "the policy is still attached at read-back", policy: remediationTestAdmin, prepare: func(_ *fakeRemediationBedrock, policies *fakeRemediationIAM) { policies.keepAfterDetach = true }, state: apiserver.ProviderRemediationUnknown, failure: remediationFailureVerification},
		{name: "the read-back fails", policy: remediationTestAdmin, prepare: func(_ *fakeRemediationBedrock, policies *fakeRemediationIAM) {
			// Two pages are read before the detachment; the third call is the read-back.
			policies.listErr, policies.listErrOnCall = remediationAPIError("ServiceFailure"), 3
		}, state: apiserver.ProviderRemediationUnknown, failure: remediationFailureOutcomeUnknown},
	} {
		bedrock := &fakeRemediationBedrock{agent: remediationTestAgent()}
		policies := &fakeRemediationIAM{roleName: "support-agent-role", policies: remediationTestPolicies()}
		executor, _ := remediationTestExecutor(t, bedrock, policies)
		if test.prepare != nil {
			test.prepare(bedrock, policies)
		}
		outcome, err := executor.Execute(context.Background(), remediationTestClaim(securityagent.ActionDetachRoleAdministratorPolicy, map[string]string{"policy_arn": test.policy}))
		if test.retry {
			if !errors.Is(err, errRemediationRetry) || outcome.State != "" {
				t.Fatalf("%s: outcome=%#v err=%v, want a retry", test.name, outcome, err)
			}
		} else if err != nil || outcome.State != test.state || outcome.FailureCode != test.failure || outcome.Prior != nil || outcome.Observed != nil {
			t.Fatalf("%s: outcome=%#v err=%v", test.name, outcome, err)
		}
		if test.noDetach && policies.detaches != 0 {
			t.Fatalf("%s: a policy was detached", test.name)
		}
		if bedrock.updates != 0 {
			t.Fatalf("%s: the agent was changed", test.name)
		}
	}
}

func TestRemediationDetachPolicyAlreadyDetachedByAnotherActorIsVerified(t *testing.T) {
	bedrock := &fakeRemediationBedrock{agent: remediationTestAgent()}
	policies := &fakeRemediationIAM{roleName: "support-agent-role", policies: remediationTestPolicies(), detachErr: remediationAPIError("NoSuchEntity"), detachErrAfterApply: true}
	executor, _ := remediationTestExecutor(t, bedrock, policies)
	outcome, err := executor.Execute(context.Background(), remediationTestClaim(securityagent.ActionDetachRoleAdministratorPolicy, map[string]string{"policy_arn": remediationTestAdmin}))
	if err != nil || outcome.State != apiserver.ProviderRemediationVerified || outcome.Observed["attached"] != false {
		t.Fatalf("outcome=%#v err=%v", outcome, err)
	}
}

func TestRemediationExecutorRejectsAMalformedClaim(t *testing.T) {
	executor, factory := remediationTestExecutor(t, &fakeRemediationBedrock{agent: remediationTestAgent()}, &fakeRemediationIAM{})
	for name, change := range map[string]func(*apiserver.ProviderRemediationClaim){
		"a remediation role of another account": func(claim *apiserver.ProviderRemediationClaim) {
			claim.RemediationRoleARN = "arn:aws:iam::210987654321:role/zasp-remediation"
		},
		"a guardrail of another account": func(claim *apiserver.ProviderRemediationClaim) {
			claim.Parameters = map[string]string{"guardrail_identifier": "arn:aws:bedrock:us-east-1:210987654321:guardrail/gr1abc", "guardrail_version": "1"}
		},
		"an agent ARN that is not the target's": func(claim *apiserver.ProviderRemediationClaim) { claim.Target.AgentID = "OTHER00000" },
		"an action that is not a remediation":   func(claim *apiserver.ProviderRemediationClaim) { claim.Action = "revoke_integration_connection" },
		"a secret instead of a reference": func(claim *apiserver.ProviderRemediationClaim) {
			claim.ExternalIDReference = "0123456789abcdef0123456789abcdef"
		},
	} {
		claim := remediationTestClaim(securityagent.ActionAttachBedrockGuardrail, map[string]string{"guardrail_identifier": "gr1abc", "guardrail_version": "3"})
		change(&claim)
		if outcome, err := executor.Execute(context.Background(), claim); !errors.Is(err, errWorkerExecution) || outcome.State != "" {
			t.Fatalf("%s: outcome=%#v err=%v", name, outcome, err)
		}
	}
	if len(factory.claims) != 0 {
		t.Fatalf("a role was requested for a malformed claim: %#v", factory.claims)
	}
}

// fakeRemediationAuthority is the database side of the action worker for the
// remediation path only.
type fakeRemediationAuthority struct {
	apiserver.SecurityAgentActionAuthority
	available bool
	claims    []apiserver.ProviderRemediationClaim
	claimErr  error
	finished  []apiserver.ProviderRemediationOutcome
	finishErr error
}

func (fake *fakeRemediationAuthority) ClaimTemporaryPolicyEffects(context.Context, string, string, int, int) ([]apiserver.TemporaryPolicyEffectClaim, error) {
	return nil, nil
}
func (fake *fakeRemediationAuthority) ProviderRemediationsAvailable() bool { return fake.available }
func (fake *fakeRemediationAuthority) ClaimProviderRemediations(context.Context, string, string, int, int) ([]apiserver.ProviderRemediationClaim, error) {
	return fake.claims, fake.claimErr
}
func (fake *fakeRemediationAuthority) FinishProviderRemediation(_ context.Context, claim apiserver.ProviderRemediationClaim, _, _ string, outcome apiserver.ProviderRemediationOutcome) (apiserver.ProviderRemediationResult, error) {
	fake.finished = append(fake.finished, outcome)
	return apiserver.ProviderRemediationResult{RunID: claim.RunID, StepID: claim.StepID}, fake.finishErr
}

type scriptedRemediationExecutor struct {
	outcomes []apiserver.ProviderRemediationOutcome
	errs     []error
	calls    int
}

func (scripted *scriptedRemediationExecutor) Execute(context.Context, apiserver.ProviderRemediationClaim) (apiserver.ProviderRemediationOutcome, error) {
	index := scripted.calls
	scripted.calls++
	return scripted.outcomes[index], scripted.errs[index]
}

func securityAgentActionProcessorTestConfig(t *testing.T) securityAgentActionProcessorConfig {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	return securityAgentActionProcessorConfig{WorkerID: "security-agent-action-1", LeaseSeconds: 60, BatchSize: 10, HeartbeatInterval: 10 * time.Millisecond, KeyID: "gateway-key-01", PrivateKey: privateKey,
		Now: func() time.Time { return now }, NewLeaseToken: func() (string, error) { return "lease-token-000000000001", nil }, NewProductID: sequentialActionProductIDs()}
}

func remediationTestProcessor(t *testing.T, authority *fakeRemediationAuthority, executor providerRemediationExecutor) *securityAgentActionProcessor {
	t.Helper()
	config := securityAgentActionProcessorTestConfig(t)
	config.Authority, config.Remediation = authority, executor
	processor, err := newSecurityAgentActionProcessor(config)
	if err != nil {
		t.Fatal(err)
	}
	return processor
}

func TestActionProcessorReportsRemediationOutcomesAndLeavesRetriesLeased(t *testing.T) {
	first := remediationTestClaim(securityagent.ActionAttachBedrockGuardrail, map[string]string{"guardrail_identifier": "gr1abc", "guardrail_version": "3"})
	second := first
	second.StepID = "pid_a0000000-0000-4000-8000-000000000062"
	third := first
	third.StepID = "pid_a0000000-0000-4000-8000-000000000063"
	authority := &fakeRemediationAuthority{available: true, claims: []apiserver.ProviderRemediationClaim{first, second, third}}
	verified := apiserver.ProviderRemediationOutcome{State: apiserver.ProviderRemediationVerified, Prior: map[string]any{"changed": true}, Observed: map[string]any{"prepare": "prepared"}}
	executor := &scriptedRemediationExecutor{outcomes: []apiserver.ProviderRemediationOutcome{verified, {}, remediationFailed(remediationFailureAccessDenied)}, errs: []error{nil, errRemediationRetry, nil}}
	processor := remediationTestProcessor(t, authority, executor)
	if err := processor.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The retried claim is not reported: its lease expires and it is claimed again.
	if executor.calls != 3 || len(authority.finished) != 2 || authority.finished[0].State != apiserver.ProviderRemediationVerified || authority.finished[1].FailureCode != remediationFailureAccessDenied {
		t.Fatalf("calls=%d finished=%#v", executor.calls, authority.finished)
	}
}

func TestActionProcessorWithoutARemediationExecutorClaimsNothing(t *testing.T) {
	authority := &fakeRemediationAuthority{available: true, claimErr: errors.New("a claim was attempted")}
	processor := remediationTestProcessor(t, authority, nil)
	if err := processor.RunOnce(context.Background()); err != nil {
		t.Fatalf("a worker without a remediation executor claimed remediations: %v", err)
	}
	unavailable := &fakeRemediationAuthority{available: false, claimErr: errors.New("a claim was attempted")}
	if err := remediationTestProcessor(t, unavailable, &scriptedRemediationExecutor{}).RunOnce(context.Background()); err != nil {
		t.Fatalf("a catalog without remediations was asked for claims: %v", err)
	}
}

func TestActionProcessorFailsTheBatchWhenAReportIsNotAccepted(t *testing.T) {
	claim := remediationTestClaim(securityagent.ActionDetachRoleAdministratorPolicy, map[string]string{"policy_arn": remediationTestAdmin})
	authority := &fakeRemediationAuthority{available: true, claims: []apiserver.ProviderRemediationClaim{claim}, finishErr: apiserver.ErrRepositoryConflict}
	executor := &scriptedRemediationExecutor{outcomes: []apiserver.ProviderRemediationOutcome{remediationFailed(remediationFailurePolicyNotOnRole)}, errs: []error{nil}}
	if err := remediationTestProcessor(t, authority, executor).RunOnce(context.Background()); !errors.Is(err, errWorkerExecution) {
		t.Fatalf("err=%v", err)
	}
}

func TestRemediationWorkerConfigIsAllOrNothing(t *testing.T) {
	config := workerRuntimeConfig{AWSRegion: "us-east-1"}
	if !validRemediationWorkerConfig(config) {
		t.Fatal("a worker without remediation settings was rejected")
	}
	config.RemediationRoleARN = "arn:aws:iam::123456789012:role/zasp-security-agent-remediation"
	if validRemediationWorkerConfig(config) {
		t.Fatal("a partial remediation configuration was accepted")
	}
	config.RemediationTokenFile, config.RemediationSecretPrefix = "/var/run/secrets/eks.amazonaws.com/serviceaccount/token", "zasp/discovery"
	if !validRemediationWorkerConfig(config) {
		t.Fatal("a complete remediation configuration was rejected")
	}
	config.AWSRegion = ""
	if validRemediationWorkerConfig(config) {
		t.Fatal("a remediation configuration without a Region was accepted")
	}
}
