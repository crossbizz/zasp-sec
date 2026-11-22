package compliancemap

const (
	PostureMapVersion  = "zasp-posture-map.v1"
	StaticMapVersion   = "zasp-static.v1"
	StaticMapVersion2  = "zasp-static.v2"
	ContextMapVersion  = "zasp.sqlite-context.v1"
	WorkflowMapVersion = "zasp.sqlite-workflow.v1"
	TicketMapVersion   = "zasp-ticket-proof-v1"
)

type ruleReview struct{ scope, reason string }

var postureReviews = map[string]ruleReview{
	"ownerless_agent":                                   {identityInventory, "No accountable owner is recorded for the inventoried agent."},
	"human_credential":                                  {identityInventory, "The agent uses a credential assigned to a human."},
	"shared_credential":                                 {identityInventory, "The inventory associates the credential with multiple principals."},
	"untrusted_production_write":                        {governedAction, "The configuration permits production writes with untrusted input."},
	"shell_credential":                                  {identityInventory, "A credential is available to a shell-capable workload."},
	"egress_sensitive":                                  {governedAction, "Sensitive data is in scope for an egress-capable workload."},
	"unapproved_tool":                                   {addonSupply, "The tool lacks the required approval in the observed inventory."},
	"destructive_no_control":                            {governedAction, "A destructive action is available without the expected control."},
	"no_runtime_coverage":                               {governedAction, "Missing runtime telemetry leaves the agent's actions unknown."},
	"weak_runtime_isolation":                            {governedAction, "The configured workload isolation is weaker than required."},
	"cicd_production_secret":                            {identityInventory, "CI/CD has access to a production secret."},
	"zombie_credential":                                 {identityInventory, "The credential remains active after the associated lifecycle or inactivity signal."},
	"agent_guardrail_missing":                           {governedAction, "Cloud discovery found an agent without the expected guardrail configuration."},
	"agent_role_unused_90_days":                         {identityInventory, "The role remains provisioned without recorded use over the 90-day interval."},
	"agent_role_administrator_access":                   {identityInventory, "The discovered agent role has administrative permissions."},
	"agent_role_unused_ai_permissions":                  {identityInventory, "Model actions granted to the role have no corresponding use in the reviewed log interval."},
	"agent_data_service_wide_access":                    {identityInventory, "The role's data-service permissions span all resources in the reviewed scope."},
	"mcp_server_unapproved":                             {addonSupply, "The registered MCP server lacks approval."},
	"mcp_server_blocked":                                {addonSupply, "The registered MCP server is listed as blocked. Registration does not prove invocation."},
	"mcp_server_no_auth":                                {addonSupply, "The inventoried MCP server has no configured authentication."},
	"mcp_server_unpinned_package":                       {addonSupply, "The MCP package reference can resolve to a different release."},
	"mcp_execute_tool_production":                       {governedAction, "The MCP tool exposes code execution in a production-enabled configuration."},
	"skill_scripts_production":                          {addonSupply, "The discovered skill contains scripts and is associated with production access."},
	"skill_unowned":                                     {addonSupply, "The repository has no matching code-owner rule for this skill."},
	"agent_content_moderation_low":                      {governedAction, "The provider content filter is set at its weakest level."},
	"agent_service_account_admin_role":                  {identityInventory, "The agent's Google Cloud service account has a project administrator role."},
	"agent_model_armor_missing":                         {governedAction, "The reviewed Vertex AI deployment has no applicable Model Armor screening."},
	"iam_role_administratoraccess_policy":               {identityInventory, "The discovered IAM role uses an administrator-access policy."},
	"iam_role_cross_service_confused_deputy_prevention": {identityInventory, "The role trust policy lacks the expected service-bound conditions."},
}

type mappingSet struct {
	rule, version, kind, scope, reason string
	rows                               []RuleMapping
}

func (m *mappingSet) link(framework, edition, id, disposition, qualification string) {
	rationale := m.reason
	if m.version == PostureMapVersion && disposition == "mapped" {
		entry, ok := LookupEdition(framework, edition, id)
		if ok {
			rationale += " " + entry.Rationale
		}
	}
	if qualification != "" {
		rationale += " " + qualification
	}
	m.rows = append(m.rows, RuleMapping{Framework: framework, Edition: edition, UpstreamID: id, Rule: m.rule, RuleVersion: m.version, Disposition: disposition, EvidenceKind: m.kind, Rationale: rationale, Scope: m.scope})
}

func (m *mappingSet) llm(previous string) {
	m.link(LLMFramework, "2025", previous, "mapped", "")
	m.link(LLMFramework, "2026", llm2026[previous], "mapped", "")
}
func (m *mappingSet) agentic(id string) { m.link(AgenticFramework, "2026", id, "mapped", "") }

// RuleMappings is the current review for a trusted, server-owned posture rule.
// Sources which report their own versions must use ScopedRuleMappings.
func RuleMappings(rule string) []RuleMapping { return ScopedRuleMappings(rule, PostureMapVersion) }

// ScopedRuleMappings accepts only exact, reviewed source identities. A
// caller must first authenticate the source and supply its real rule version.
func ScopedRuleMappings(rule, ruleVersion string) []RuleMapping {
	m := mappingSet{rule: rule, version: ruleVersion, rows: []RuleMapping{}}
	switch ruleVersion {
	case PostureMapVersion:
		review, ok := postureReviews[rule]
		if !ok {
			return m.rows
		}
		m.scope, m.reason, m.kind = review.scope, review.reason, "posture_finding"
		for _, reference := range References(rule) {
			switch reference.Framework {
			case OWASPAgentic:
				m.agentic(reference.Control)
			case OWASPLLM:
				m.llm(reference.Control)
			case MITREATLAS:
				entry, _ := LookupEdition(ATLASFramework, ATLASEdition, reference.Control)
				m.link(ATLASFramework, ATLASEdition, reference.Control, "insufficient_evidence", entry.Rationale)
			}
		}
		if rule == "no_runtime_coverage" {
			m.link(AgenticFramework, "2026", "ASI10", "insufficient_evidence", "Missing observation cannot support a claim of rogue behavior.")
		}
	case StaticMapVersion, StaticMapVersion2:
		if rule == "dependency.unpinned" {
			m.scope, m.reason, m.kind = addonSupply, "The reviewed file in the identified add-on digest declares an unpinned dependency. The installed version and any exploitability remain unknown.", "static_scan"
			m.agentic("ASI04")
			m.llm("LLM03")
		}
	case ContextMapVersion:
		m.context("")
	case WorkflowMapVersion:
		m.workflow()
	case TicketMapVersion:
		m.ticket()
	}
	return m.rows
}

// ScopedContextRuleMappings also validates the classification on the
// authenticated action request. Missing or contradictory dimensions cannot
// be promoted to a more specific observation.
func ScopedContextRuleMappings(rule, ruleVersion, classification string) []RuleMapping {
	m := mappingSet{rule: rule, version: ruleVersion, rows: []RuleMapping{}}
	if ruleVersion == ContextMapVersion && classification != "" {
		m.context(classification)
	}
	return m.rows
}

func (m *mappingSet) context(classification string) {
	m.kind, m.scope = "observed_event", contextAdapter
	switch m.rule {
	case "context.memory_write", "context.memory_recall":
		if classification != "" && classification != "memory" {
			return
		}
		m.reason = "The authenticated adapter observed a bound memory record version and operation. This establishes an observation, without attributing harmful content or downstream influence."
		m.agentic("ASI06")
	case "context.retrieval":
		if classification != "" && classification != "document" {
			return
		}
		m.reason = "The authenticated adapter recorded a retrieval and its access decision in this scoped collection."
		m.llm("LLM08")
	case "context.artifact_promotion":
		m.reason = "The authenticated adapter recorded the promotion decision for a particular artifact and source."
		switch classification {
		case "model", "dataset":
			m.scope = modelPipeline
			m.llm("LLM04")
		case "document":
			m.llm("LLM08")
		case "":
			m.link(LLMFramework, "2025", "LLM04", "insufficient_evidence", "Model or dataset classification must be established.")
			return
		default:
			return
		}
		m.link(ATLASFramework, ATLASEdition, "AML.M0014", "mapped", "The named SQLite adapter checks the approval signature and content digest on promotion. This application observation is scoped to that verifier.")
	case "context.grounded_decision":
		if classification != "" && classification != "document" {
			return
		}
		m.reason = "The authenticated adapter reported a decision against the supplied ground-truth record in this workflow."
		m.llm("LLM09")
	case "context.hidden_context_check":
		if classification != "" && classification != "system_prompt" && classification != "retrieved_context" {
			return
		}
		m.reason = "The authenticated adapter reported a synthetic marker check at the named context boundary."
		if classification == "system_prompt" {
			m.llm("LLM07")
			return
		}
		m.link(LLMFramework, "2026", "LLM08", "mapped", "")
		m.link(LLMFramework, "2025", "LLM07", "insufficient_evidence", "The older category requires evidence specific to a system prompt.")
	}
}

func (m *mappingSet) ticket() {
	m.scope = "synthetic_ticket_update"
	switch m.rule {
	case "ticket.control_pair":
		m.kind = "tested_control"
		m.reason = "The staging ticket experiment recorded a control comparison on the named adapter. The test identity alone does not establish prevention."
	case "ticket.verified_prevention":
		m.kind = "verified_prevention"
		m.reason = "Only the server-classified paired observation with an independently corroborated permitted write and verified absence of the protected write qualifies, within its device, operation and policy revision."
	default:
		return
	}
	m.agentic("ASI02")
	m.link(ATLASFramework, ATLASEdition, "AML.M0028", "mapped", "The published entry describes a defensive mitigation.")
}

func (m *mappingSet) workflow() {
	m.kind, m.scope = "observed_event", governedAction
	switch m.rule {
	case "workflow.purpose":
		m.reason = "The authenticated SQLite workflow adapter recorded the result of a purpose-bound action and destination comparison."
		m.agentic("ASI01")
	case "workflow.approval":
		m.reason = "The adapter recorded its check of the action against the bound approval."
		m.agentic("ASI09")
	case "workflow.handoff":
		m.reason = "The adapter recorded the result of the scoped handoff identity and recipient check."
		m.agentic("ASI07")
	case "workflow.child":
		m.reason = "The adapter reported a bounded child operation in this workflow."
		m.agentic("ASI08")
	case "workflow.budget":
		m.reason = "The adapter recorded the result of the configured resource budget check."
		m.llm("LLM10")
	}
}

// LegacyReview preserves the rationale for a pre-edition link, including the
// NIST, ISO and EU references outside the newly published edition indexes.
type LegacyReview struct {
	Reference
	Rule      string
	Rationale string
}

var governanceRationales = map[string]string{
	"GOVERN 1.6":  "The inventory entry identifies an AI asset or credential that governance needs to account for.",
	"GOVERN 2.1":  "The record identifies an accountability or review assignment requiring an owner.",
	"MEASURE 2.7": "The observed security configuration is evidence for evaluating system security and resilience.",
	"MANAGE 2.4":  "The exposed authority or missing control is relevant to the ability to disable or supersede a component.",
	"A.3.2":       "The observed ownership gap is relevant to documented AI roles and responsibilities.",
	"A.6.2.6":     "The workload configuration bears on operating and monitoring the identified system.",
	"A.9.2":       "The component approval status is relevant to the responsible-use process.",
	"Article 9":   "This recorded exposure can inform a risk-management review.",
	"Article 14":  "The record identifies where human review or ownership may be needed.",
	"Article 15":  "The configuration is relevant to a cybersecurity review for the identified system.",
}

// LegacyRuleReviews returns evidence relevance for each original reference.
// It preserves the published mapping and its original title for old exports.
func LegacyRuleReviews(rule string) []LegacyReview {
	review, ok := postureReviews[rule]
	rows := []LegacyReview{}
	if !ok {
		return rows
	}
	for _, r := range References(rule) {
		why := governanceRationales[r.Control]
		switch r.Framework {
		case OWASPAgentic, OWASPLLM:
			why = owaspReviews[r.Control].reason
		case MITREATLAS:
			entry, _ := LookupEdition(ATLASFramework, ATLASEdition, r.Control)
			why = entry.Rationale
		}
		rows = append(rows, LegacyReview{Reference: r, Rule: rule, Rationale: review.reason + " " + why})
	}
	return rows
}
