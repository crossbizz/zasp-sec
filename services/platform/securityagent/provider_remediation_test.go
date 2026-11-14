package securityagent

import (
	"context"
	"testing"
)

func TestProviderRemediationCatalogMatchesActionMetadata(t *testing.T) {
	metadata := map[string]ActionMetadata{}
	for _, value := range BuiltInResponseActionMetadata() {
		metadata[value.Key] = value
	}
	remediations := ProviderRemediations()
	if len(remediations) != 2 {
		t.Fatalf("remediations=%#v", remediations)
	}
	for _, remediation := range remediations {
		value, ok := metadata[remediation.Action]
		if !ok || ValidateActionMetadata(value) != nil || value.VerificationKind != remediation.VerificationKind || value.Reversible != remediation.Reversible || len(value.InputSchema) != len(remediation.Parameters) || len(value.TargetTypes) != 1 || value.TargetTypes[0] != "agent" || value.ApprovalFloor == "none" {
			t.Fatalf("metadata of %q=%#v", remediation.Action, value)
		}
		for _, parameter := range remediation.Parameters {
			if value.InputSchema[parameter] != "string" {
				t.Fatalf("%q parameter %q is not in the input schema", remediation.Action, parameter)
			}
		}
		byRule, ok := ProviderRemediationForRule(remediation.Rule)
		if !ok || byRule.Action != remediation.Action {
			t.Fatalf("rule %q resolves to %#v", remediation.Rule, byRule)
		}
		byAction, ok := ProviderRemediationByAction(remediation.Action)
		if !ok || byAction.Rule != remediation.Rule {
			t.Fatalf("action %q resolves to %#v", remediation.Action, byAction)
		}
	}
	if metadata[ActionDetachRoleAdministratorPolicy].RiskClass != "destructive" || metadata[ActionDetachRoleAdministratorPolicy].ApprovalFloor != "admin" {
		t.Fatalf("detaching a policy must be destructive with the highest approval floor: %#v", metadata[ActionDetachRoleAdministratorPolicy])
	}
	if _, ok := ProviderRemediationForRule("agent_role_unused_90_days"); ok {
		t.Fatal("a rule without a remediation resolved to one")
	}
	if _, ok := ProviderRemediationByAction("revoke_integration_connection"); ok {
		t.Fatal("an action that is not a provider remediation resolved to one")
	}
}

func TestProviderRemediationParameters(t *testing.T) {
	const account, region = "123456789012", "us-east-1"
	for _, test := range []struct {
		name            string
		action          string
		parameters      map[string]string
		account, region string
		want            bool
	}{
		{"guardrail id and version", ActionAttachBedrockGuardrail, map[string]string{"guardrail_identifier": "gr1abc", "guardrail_version": "3"}, account, region, true},
		{"guardrail draft", ActionAttachBedrockGuardrail, map[string]string{"guardrail_identifier": "gr1abc", "guardrail_version": "DRAFT"}, account, region, true},
		{"guardrail ARN of the agent's account and Region", ActionAttachBedrockGuardrail, map[string]string{"guardrail_identifier": "arn:aws:bedrock:us-east-1:123456789012:guardrail/gr1abc", "guardrail_version": "1"}, account, region, true},
		{"guardrail ARN, form only", ActionAttachBedrockGuardrail, map[string]string{"guardrail_identifier": "arn:aws:bedrock:eu-west-1:210987654321:guardrail/gr1abc", "guardrail_version": "1"}, "", "", true},
		{"guardrail ARN of another account", ActionAttachBedrockGuardrail, map[string]string{"guardrail_identifier": "arn:aws:bedrock:us-east-1:210987654321:guardrail/gr1abc", "guardrail_version": "1"}, account, region, false},
		{"guardrail ARN of another Region", ActionAttachBedrockGuardrail, map[string]string{"guardrail_identifier": "arn:aws:bedrock:eu-west-1:123456789012:guardrail/gr1abc", "guardrail_version": "1"}, account, region, false},
		{"guardrail version zero", ActionAttachBedrockGuardrail, map[string]string{"guardrail_identifier": "gr1abc", "guardrail_version": "0"}, account, region, false},
		{"guardrail version missing", ActionAttachBedrockGuardrail, map[string]string{"guardrail_identifier": "gr1abc"}, account, region, false},
		{"guardrail identifier with a path", ActionAttachBedrockGuardrail, map[string]string{"guardrail_identifier": "../gr1abc", "guardrail_version": "1"}, account, region, false},
		{"guardrail extra parameter", ActionAttachBedrockGuardrail, map[string]string{"guardrail_identifier": "gr1abc", "guardrail_version": "1", "agent_id": "OTHER"}, account, region, false},
		{"AWS managed policy", ActionDetachRoleAdministratorPolicy, map[string]string{"policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"}, account, region, true},
		{"customer managed policy of the agent's account", ActionDetachRoleAdministratorPolicy, map[string]string{"policy_arn": "arn:aws:iam::123456789012:policy/team/everything"}, account, region, true},
		{"customer managed policy of another account", ActionDetachRoleAdministratorPolicy, map[string]string{"policy_arn": "arn:aws:iam::210987654321:policy/everything"}, account, region, false},
		{"role ARN instead of a policy", ActionDetachRoleAdministratorPolicy, map[string]string{"policy_arn": "arn:aws:iam::123456789012:role/admin"}, account, region, false},
		{"policy extra parameter", ActionDetachRoleAdministratorPolicy, map[string]string{"policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess", "role_name": "other"}, account, region, false},
		{"policy missing", ActionDetachRoleAdministratorPolicy, map[string]string{}, account, region, false},
		{"malformed account", ActionDetachRoleAdministratorPolicy, map[string]string{"policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"}, "12345", region, false},
		{"another action", "revoke_integration_connection", map[string]string{"policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"}, account, region, false},
	} {
		if got := ValidProviderRemediationParameters(test.action, test.parameters, test.account, test.region); got != test.want {
			t.Fatalf("%s: valid=%t want %t", test.name, got, test.want)
		}
	}
}

func TestProviderRemediationActionsValidateThroughTheRegistry(t *testing.T) {
	registry := NewRegistry()
	if err := RegisterResponseActions(registry, &fakeBuiltinBackend{}); err != nil {
		t.Fatal(err)
	}
	request := ActionRequest{OrganizationID: "org", RunID: "run", StepID: "step", ActionKey: ActionAttachBedrockGuardrail, Parameters: map[string]string{"guardrail_identifier": "gr1abc", "guardrail_version": "1"}}
	action, err := registry.lookup(request.ActionKey)
	if err != nil {
		t.Fatal(err)
	}
	request.Parameters["guardrail_version"] = "latest"
	if action.Validate(context.Background(), request) == nil {
		t.Fatal("a malformed guardrail version was accepted")
	}
}
