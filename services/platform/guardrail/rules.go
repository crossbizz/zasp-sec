package guardrail

// RuleClass determines whether optional semantic review may annotate a rule.
type RuleClass string

const (
	RuleHard      RuleClass = "hard"
	RuleHeuristic RuleClass = "heuristic"
)

// Rule is one detector. A rule that is not Redactable finds an intent, not a
// span that can be removed, so it cannot be set to redact.
type Rule struct {
	ID          string
	Class       RuleClass
	Category    string
	Description string
	DefaultMode Mode
	Redactable  bool
}

// Rule identifiers.
const (
	RuleInstructionOverride = "injection.instruction_override"
	RuleRoleSwitch          = "injection.role_switch"
	RuleHiddenText          = "injection.hidden_text"
	RuleToolCall            = "injection.tool_call"
	RuleEmail               = "pii.email"
	RulePhone               = "pii.phone"
	RuleCreditCard          = "pii.credit_card"
	RuleSSN                 = "pii.us_ssn"
	RuleAWSAccessKeyID      = "secret.aws_access_key_id"
	RulePrivateKey          = "secret.private_key"
	RuleBearerToken         = "secret.bearer_token"
)

var rules = []Rule{
	{ID: RuleInstructionOverride, Class: RuleHeuristic, Category: CategoryPromptInjection, DefaultMode: ModeBlock, Description: "Text that tells the model to ignore, forget, disregard or override its earlier or system instructions."},
	{ID: RuleRoleSwitch, Class: RuleHeuristic, Category: CategoryPromptInjection, DefaultMode: ModeBlock, Description: "Chat-template role markers inside the text (a forged system or assistant turn) and requests to switch into an unrestricted persona."},
	{ID: RuleHiddenText, Class: RuleHeuristic, Category: CategoryPromptInjection, DefaultMode: ModeBlock, Description: "Invisible or disguised instructions: zero-width and bidirectional control characters, Unicode tag characters, instructions inside an HTML comment, and base64 that decodes to an instruction override."},
	{ID: RuleToolCall, Class: RuleHeuristic, Category: CategoryPromptInjection, DefaultMode: ModeBlock, Description: "Text that carries a tool or function call in a model's own call syntax, so that a document or a tool result can make the agent call a tool."},
	{ID: RuleEmail, Class: RuleHard, Category: CategorySensitiveData, DefaultMode: ModeRedact, Redactable: true, Description: "Email addresses."},
	{ID: RulePhone, Class: RuleHard, Category: CategorySensitiveData, DefaultMode: ModeRedact, Redactable: true, Description: "Phone numbers in international (+country) form and in North American form."},
	{ID: RuleCreditCard, Class: RuleHard, Category: CategorySensitiveData, DefaultMode: ModeRedact, Redactable: true, Description: "Payment card numbers of 13 to 19 digits that pass the Luhn checksum."},
	{ID: RuleSSN, Class: RuleHard, Category: CategorySensitiveData, DefaultMode: ModeRedact, Redactable: true, Description: "US Social Security numbers written with dashes, excluding ranges that are never issued."},
	{ID: RuleAWSAccessKeyID, Class: RuleHard, Category: CategorySensitiveData, DefaultMode: ModeRedact, Redactable: true, Description: "AWS access key IDs (AKIA and ASIA prefixes)."},
	{ID: RulePrivateKey, Class: RuleHard, Category: CategorySensitiveData, DefaultMode: ModeRedact, Redactable: true, Description: "PEM private key blocks, from the BEGIN line to the END line when it is present."},
	{ID: RuleBearerToken, Class: RuleHard, Category: CategorySensitiveData, DefaultMode: ModeRedact, Redactable: true, Description: "Bearer tokens in an Authorization value and JSON Web Tokens."},
}

// Rules returns the rule catalog in a fixed order.
func Rules() []Rule { return append([]Rule(nil), rules...) }

// RuleByID returns one rule of the catalog.
func RuleByID(id string) (Rule, bool) {
	for _, rule := range rules {
		if rule.ID == id {
			return rule, true
		}
	}
	return Rule{}, false
}
