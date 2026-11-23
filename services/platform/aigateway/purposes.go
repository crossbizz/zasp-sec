package aigateway

import (
	"slices"
	"time"
)

const (
	PurposeInjectionScreen Purpose = "indirect_injection_screen"
	PurposeAlignment       Purpose = "purpose_alignment_check"
	PurposeHeuristicVerify Purpose = "heuristic_fp_verify"
	PurposeDiscoveryVerify Purpose = "agent_discovery_verify"
	PurposeDraft           Purpose = "agent_purpose_draft"
	PurposeAddonAudit      Purpose = "addon_semantic_audit"
	PurposeTriage          Purpose = "security_agent_triage"
	PurposeRemediate       Purpose = "security_agent_remediate"

	ContentModeApprovedCodeSnippet ContentMode = "approved_code_snippet"
	ContentModePrivateAddon        ContentMode = "private_addon"

	ModeVPC     = "zasp_vpc_slm"
	ModeBYOC    = "byoc_self_hosted"
	ModeBedrock = "privatelink_bedrock"
	ModeVertex  = "privatelink_vertex"
	ModeDev     = "dev_openrouter"

	ModelShieldstral = "mistralai/Shieldstral-1.0-3B"
	modelNemotron    = "nvidia/Nemotron-3.5-Content-Safety"
	modelGuardBase   = "Horizon-Labs/prompt-injection-guard-base"
	modelWolf        = "patronus-studio/wolf-defender-prompt-injection"
	modelSonnet      = "anthropic.claude-sonnet-4-6"
	modelHaiku       = "anthropic.claude-haiku-4-5"
	modelGemini      = "gemini-2.5-pro"
)

// Eligibility identifies a supported job. Running it additionally requires a
// qualified model binding, an active budget and current scoped data consent.
type PurposeDefinition struct {
	Capability    string
	Tier          int
	MaxLatency    time.Duration
	MaxInputBytes int
	ContentModes  []ContentMode
	Models        []string
}

var (
	summary     = []ContentMode{ContentModeRedactedSummary}
	code        = []ContentMode{ContentModeRedactedSummary, ContentModeApprovedCodeSnippet}
	addon       = []ContentMode{ContentModeRedactedSummary, ContentModePrivateAddon}
	classifiers = []string{ModelShieldstral, modelNemotron}
	frontier    = []string{modelSonnet, modelGemini}
	purposes    = map[Purpose]PurposeDefinition{
		PurposeInjectionScreen: {"tier2_prompt_injection_enabled", 2, 40 * time.Millisecond, 8192, code, []string{modelGuardBase, modelWolf}},
		PurposeAlignment:       {"tier2_purpose_drift_enabled", 2, 150 * time.Millisecond, 8192, summary, classifiers},
		PurposeHeuristicVerify: {"tier2_heuristic_fp_suppression_enabled", 2, 200 * time.Millisecond, 8192, code, classifiers},
		PurposeDiscoveryVerify: {"tier3_discovery_purpose_enabled", 3, 30 * time.Second, 32768, code, frontier},
		PurposeDraft:           {"tier3_discovery_purpose_enabled", 3, 30 * time.Second, 32768, code, frontier},
		PurposeAddonAudit:      {"tier3_addon_audit_enabled", 3, 30 * time.Second, 32768, addon, frontier},
		PurposeTriage:          {"tier3_security_agent_planner_enabled", 3, 30 * time.Second, 16384, summary, []string{modelHaiku, "anthropic.claude-haiku-4-5-20251001-v1:0", modelGemini}},
		PurposeRemediate:       {"tier3_security_agent_planner_enabled", 3, 30 * time.Second, 16384, summary, frontier},
	}
)

func LookupPurpose(p Purpose) (PurposeDefinition, bool) {
	d, ok := purposes[p]
	d.ContentModes = slices.Clone(d.ContentModes)
	d.Models = slices.Clone(d.Models)
	return d, ok
}

func EligibleModel(p Purpose, mode, model string) bool {
	d, ok := purposes[p]
	if !ok || !slices.Contains(d.Models, model) {
		return false
	}
	switch mode {
	case ModeVPC, ModeBYOC:
		return d.Tier == 2
	case ModeBedrock:
		return d.Tier == 3 && model != modelGemini
	case ModeVertex:
		return d.Tier == 3 && model == modelGemini
	case ModeDev:
		return true
	}
	return false
}
