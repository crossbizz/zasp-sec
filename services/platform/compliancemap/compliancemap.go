// Package compliancemap maps a finding's rule to the controls of AI security
// frameworks it is evidence for. The mapping is static and reviewed in this
// file: a finding carries its references when it is read, nothing is stored.
//
// A reference says "this finding is relevant to this control", not "this
// control is satisfied or failed". The identifiers are the frameworks' own.
package compliancemap

import "sort"

// Reference is one framework control a finding is evidence for.
type Reference struct {
	Framework string `json:"framework"`
	Control   string `json:"control"`
	Title     string `json:"title"`
}

// Framework identifiers.
const (
	OWASPLLM     = "owasp_llm_top10_2025"
	OWASPAgentic = "owasp_agentic_top10_2026"
	NISTAIRMF    = "nist_ai_rmf_1_0"
	ISO42001     = "iso_iec_42001_2023"
	EUAIAct      = "eu_ai_act"
	MITREATLAS   = "mitre_atlas"
)

// FrameworkNames are the display names, in the order references are listed.
var FrameworkNames = []struct{ ID, Name string }{
	{OWASPAgentic, "OWASP Top 10 for Agentic Applications"},
	{OWASPLLM, "OWASP Top 10 for LLM Applications"},
	{MITREATLAS, "MITRE ATLAS"},
	{NISTAIRMF, "NIST AI RMF 1.0"},
	{ISO42001, "ISO/IEC 42001"},
	{EUAIAct, "EU AI Act"},
}

var controls = map[string]Reference{
	"ASI02":       {OWASPAgentic, "ASI02", "Tool Misuse and Exploitation"},
	"ASI03":       {OWASPAgentic, "ASI03", "Identity and Privilege Abuse"},
	"ASI04":       {OWASPAgentic, "ASI04", "Agentic Supply Chain Vulnerabilities"},
	"ASI05":       {OWASPAgentic, "ASI05", "Unexpected Code Execution"},
	"ASI10":       {OWASPAgentic, "ASI10", "Rogue Agents"},
	"LLM01":       {OWASPLLM, "LLM01", "Prompt Injection"},
	"LLM02":       {OWASPLLM, "LLM02", "Sensitive Information Disclosure"},
	"LLM03":       {OWASPLLM, "LLM03", "Supply Chain"},
	"LLM05":       {OWASPLLM, "LLM05", "Improper Output Handling"},
	"LLM06":       {OWASPLLM, "LLM06", "Excessive Agency"},
	"T0051":       {MITREATLAS, "AML.T0051", "LLM Prompt Injection"},
	"T0053":       {MITREATLAS, "AML.T0053", "LLM Plugin Compromise"},
	"T0055":       {MITREATLAS, "AML.T0055", "Unsecured Credentials"},
	"T0057":       {MITREATLAS, "AML.T0057", "LLM Data Leakage"},
	"GOVERN-1.6":  {NISTAIRMF, "GOVERN 1.6", "Mechanisms are in place to inventory AI systems"},
	"GOVERN-2.1":  {NISTAIRMF, "GOVERN 2.1", "Roles, responsibilities and lines of communication are documented"},
	"MEASURE-2.7": {NISTAIRMF, "MEASURE 2.7", "AI system security and resilience are evaluated and documented"},
	"MANAGE-2.4":  {NISTAIRMF, "MANAGE 2.4", "Mechanisms exist to supersede, disengage or deactivate AI systems"},
	"A.3.2":       {ISO42001, "A.3.2", "AI roles and responsibilities"},
	"A.6.2.6":     {ISO42001, "A.6.2.6", "AI system operation and monitoring"},
	"A.9.2":       {ISO42001, "A.9.2", "Processes for responsible use of AI systems"},
	"ART-9":       {EUAIAct, "Article 9", "Risk management system"},
	"ART-14":      {EUAIAct, "Article 14", "Human oversight"},
	"ART-15":      {EUAIAct, "Article 15", "Accuracy, robustness and cybersecurity"},
}

// rules maps a finding rule to control keys. Posture rules come from the
// inventory posture refresh; the agent_ and iam_ rules from AWS discovery.
var rules = map[string][]string{
	"ownerless_agent":            {"ASI10", "GOVERN-1.6", "GOVERN-2.1", "A.3.2", "ART-14"},
	"human_credential":           {"ASI03", "T0055", "MEASURE-2.7", "ART-15"},
	"shared_credential":          {"ASI03", "T0055", "MEASURE-2.7", "ART-15"},
	"untrusted_production_write": {"LLM01", "LLM06", "ASI02", "T0051", "MEASURE-2.7", "ART-15"},
	"shell_credential":           {"ASI05", "ASI03", "LLM06", "MEASURE-2.7", "ART-15"},
	"egress_sensitive":           {"LLM02", "T0057", "MEASURE-2.7", "ART-15"},
	"unapproved_tool":            {"ASI04", "ASI02", "LLM03", "T0053", "A.9.2", "ART-9"},
	"destructive_no_control":     {"LLM06", "ASI02", "MANAGE-2.4", "A.6.2.6", "ART-14"},
	"no_runtime_coverage":        {"MEASURE-2.7", "MANAGE-2.4", "A.6.2.6", "ART-9", "ART-14"},
	"weak_runtime_isolation":     {"ASI05", "LLM06", "MEASURE-2.7", "ART-15"},
	"cicd_production_secret":     {"ASI04", "ASI03", "LLM03", "T0055", "ART-15"},
	"zombie_credential":          {"ASI03", "T0055", "MANAGE-2.4", "GOVERN-1.6"},

	"agent_guardrail_missing":         {"LLM01", "LLM02", "LLM05", "T0051", "MEASURE-2.7", "A.6.2.6", "ART-9", "ART-15"},
	"agent_role_unused_90_days":       {"ASI03", "T0055", "MANAGE-2.4", "GOVERN-1.6"},
	"agent_role_administrator_access": {"LLM06", "ASI03", "MEASURE-2.7", "ART-15"},
	// The role's policies grant model actions the audit log shows unused, or
	// reach every resource of a data service: excessive permission.
	"agent_role_unused_ai_permissions": {"LLM06", "ASI03", "MEASURE-2.7", "MANAGE-2.4", "ART-15"},
	"agent_data_service_wide_access":   {"LLM06", "LLM02", "ASI03", "T0057", "MEASURE-2.7", "ART-15"},

	// MCP servers: an unreviewed or blocked server is a supply chain and tool
	// risk; one without authentication or from an unpinned package can be
	// replaced or impersonated; a tool that runs code is code execution.
	"mcp_server_unapproved":       {"ASI04", "ASI02", "LLM03", "T0053", "GOVERN-1.6", "A.9.2", "ART-9"},
	"mcp_server_blocked":          {"ASI04", "ASI02", "LLM03", "T0053", "MANAGE-2.4", "A.9.2", "ART-9"},
	"mcp_server_no_auth":          {"ASI04", "ASI03", "LLM03", "T0053", "MEASURE-2.7", "ART-15"},
	"mcp_server_unpinned_package": {"ASI04", "LLM03", "T0053", "MEASURE-2.7", "ART-15"},
	"mcp_execute_tool_production": {"ASI05", "ASI02", "LLM06", "T0053", "MEASURE-2.7", "ART-14", "ART-15"},

	"iam_role_administratoraccess_policy":               {"ASI03", "LLM06", "MEASURE-2.7"},
	"iam_role_cross_service_confused_deputy_prevention": {"ASI03", "MEASURE-2.7"},
}

var frameworkOrder = func() map[string]int {
	order := map[string]int{}
	for index, framework := range FrameworkNames {
		order[framework.ID] = index
	}
	return order
}()

// References returns the controls a finding with the given rule is evidence
// for, ordered by framework and control. It is empty, never nil, for a rule
// without a mapping.
func References(rule string) []Reference {
	keys := rules[rule]
	references := make([]Reference, 0, len(keys))
	for _, key := range keys {
		references = append(references, controls[key])
	}
	sort.SliceStable(references, func(left, right int) bool {
		if references[left].Framework != references[right].Framework {
			return frameworkOrder[references[left].Framework] < frameworkOrder[references[right].Framework]
		}
		return references[left].Control < references[right].Control
	})
	return references
}

// Control returns the framework control with the given key (for example
// "LLM01" or "T0051"), for callers that tag something other than a finding
// rule, such as a red team probe.
func Control(key string) (Reference, bool) {
	reference, ok := controls[key]
	return reference, ok
}

// Rules lists every mapped rule, sorted.
func Rules() []string {
	names := make([]string, 0, len(rules))
	for name := range rules {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
