package securityagent

import "regexp"

// Provider remediation actions change a customer's cloud account through the
// integration the customer already connected. They always need a person's
// approval and they are never executed with the role discovery reads with:
// each integration names a separate remediation role.
const (
	// ActionAttachBedrockGuardrail attaches an existing Bedrock guardrail to
	// a Bedrock agent. It answers the finding rule agent_guardrail_missing.
	ActionAttachBedrockGuardrail = "attach_bedrock_guardrail"
	// ActionDetachRoleAdministratorPolicy detaches one managed policy from
	// the execution role of a Bedrock agent. It answers the finding rule
	// agent_role_administrator_access.
	ActionDetachRoleAdministratorPolicy = "detach_role_administrator_policy"

	// VerificationGuardrailState and VerificationRolePolicyState are the
	// verification kinds a Security Agent of each action declares: the
	// provider is read back after the change.
	VerificationGuardrailState  = "guardrail_state"
	VerificationRolePolicyState = "role_policy_state"
)

var (
	remediationGuardrailIDPattern  = regexp.MustCompile(`^[a-z0-9]{1,64}$`)
	remediationGuardrailARNPattern = regexp.MustCompile(`^arn:aws(?:-us-gov|-cn)?:bedrock:([a-z0-9-]{1,20}):([0-9]{12}):guardrail/[a-z0-9]{1,64}$`)
	remediationGuardrailVersion    = regexp.MustCompile(`^(?:[1-9][0-9]{0,7}|DRAFT)$`)
	remediationPolicyARNPattern    = regexp.MustCompile(`^arn:aws(?:-us-gov|-cn)?:iam::(aws|[0-9]{12}):policy/[A-Za-z0-9+=,.@_/-]{1,512}$`)
	remediationAccountPattern      = regexp.MustCompile(`^[0-9]{12}$`)
	remediationRegionPattern       = regexp.MustCompile(`^[a-z]{2}(?:-gov)?-[a-z]+-[1-9]$`)
)

// ProviderRemediation describes one provider remediation action: the finding
// rule it answers, what its Security Agent verifies, and what an approver is
// told. ExpectedEffect is the text PostgreSQL returns on the approval.
type ProviderRemediation struct {
	Action           string
	Rule             string
	VerificationKind string
	ExpectedEffect   string
	Reversible       bool
	Parameters       []string
}

var providerRemediations = []ProviderRemediation{
	{Action: ActionAttachBedrockGuardrail, Rule: "agent_guardrail_missing", VerificationKind: VerificationGuardrailState, ExpectedEffect: "Attach Bedrock guardrail", Reversible: true, Parameters: []string{"guardrail_identifier", "guardrail_version"}},
	{Action: ActionDetachRoleAdministratorPolicy, Rule: "agent_role_administrator_access", VerificationKind: VerificationRolePolicyState, ExpectedEffect: "Detach administrator policy from agent role", Reversible: false, Parameters: []string{"policy_arn"}},
}

// ProviderRemediations returns the provider remediation catalog.
func ProviderRemediations() []ProviderRemediation {
	result := make([]ProviderRemediation, len(providerRemediations))
	for index, value := range providerRemediations {
		value.Parameters = cloneStrings(value.Parameters)
		result[index] = value
	}
	return result
}

// ProviderRemediationByAction returns the remediation of an action key.
func ProviderRemediationByAction(action string) (ProviderRemediation, bool) {
	for _, value := range providerRemediations {
		if value.Action == action {
			value.Parameters = cloneStrings(value.Parameters)
			return value, true
		}
	}
	return ProviderRemediation{}, false
}

// ProviderRemediationForRule returns the remediation that answers a finding
// rule, if one does.
func ProviderRemediationForRule(rule string) (ProviderRemediation, bool) {
	for _, value := range providerRemediations {
		if value.Rule == rule {
			value.Parameters = cloneStrings(value.Parameters)
			return value, true
		}
	}
	return ProviderRemediation{}, false
}

func providerRemediationActionMetadata() []ActionMetadata {
	return []ActionMetadata{
		{Key: ActionAttachBedrockGuardrail, InputSchema: map[string]string{"guardrail_identifier": "string", "guardrail_version": "string"}, RiskClass: "moderate", TargetTypes: []string{"agent"}, ApprovalFloor: "operator", Reversible: true, Idempotent: true, VerificationKind: VerificationGuardrailState},
		{Key: ActionDetachRoleAdministratorPolicy, InputSchema: map[string]string{"policy_arn": "string"}, RiskClass: "destructive", TargetTypes: []string{"agent"}, ApprovalFloor: "admin", Reversible: false, Idempotent: true, VerificationKind: VerificationRolePolicyState},
	}
}

// ValidProviderRemediationParameters reports whether the parameters are
// exactly those of the action and are well formed. accountID and region are
// the AWS account and Region of the target agent; when both are given, a
// guardrail named by ARN must be in that account and Region and a customer
// managed policy must belong to that account. With both empty only the form
// is checked (the database checks the binding again when it knows the
// target). PostgreSQL applies the same rules in
// zasp_security_agent_provider_remediation_parameters_valid.
func ValidProviderRemediationParameters(action string, parameters map[string]string, accountID, region string) bool {
	bound := accountID != "" || region != ""
	if bound && (!remediationAccountPattern.MatchString(accountID) || !remediationRegionPattern.MatchString(region)) {
		return false
	}
	switch action {
	case ActionAttachBedrockGuardrail:
		if len(parameters) != 2 || !remediationGuardrailVersion.MatchString(parameters["guardrail_version"]) {
			return false
		}
		identifier := parameters["guardrail_identifier"]
		if remediationGuardrailIDPattern.MatchString(identifier) {
			return true
		}
		match := remediationGuardrailARNPattern.FindStringSubmatch(identifier)
		return len(match) == 3 && (!bound || match[1] == region && match[2] == accountID)
	case ActionDetachRoleAdministratorPolicy:
		if len(parameters) != 1 {
			return false
		}
		match := remediationPolicyARNPattern.FindStringSubmatch(parameters["policy_arn"])
		return len(match) == 2 && (!bound || match[1] == "aws" || match[1] == accountID)
	default:
		return false
	}
}
