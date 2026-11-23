package apiserver

import (
	"context"
	"encoding/json"
	"os"

	"github.com/zasp-ai/zasp-sec/services/platform/aigateway"
	"github.com/zasp-ai/zasp-sec/services/platform/guardrail"
)

const semanticAdmitSQL = "SELECT zasp_authorization80.semantic_guardrail($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NULL,NULL,NULL)"
const semanticFinishSQL = "SELECT zasp_authorization80.semantic_guardrail($1,$2,$3,$4,$5,NULL,NULL,NULL,NULL,NULL,NULL,$6::uuid,$7,$8::numeric)"

func init() {
	for query, n := range map[string]int{semanticAdmitSQL: 11, semanticFinishSQL: 8} {
		productStatementRules[query] = productStatementRule{operations: []string{"createGuardrailDecision"}, arguments: n, scope: 1, actor: 4, check: func(g RequestAuthorization, args []any) bool {
			return g.Identity.CredentialKind == CredentialBearerToken
		}}
	}
}

type semanticProfile struct {
	deployment aigateway.Deployment
	driver     aigateway.ProviderDriver
}
type guardrailProfiles map[aigateway.Purpose]semanticProfile

// Each file names a deployment only. Scope, consent, budget and the matching
// signed qualification are checked in PostgreSQL before every invocation.
func loadGuardrailProfiles() guardrailProfiles {
	configured := guardrailProfiles{}
	for purpose, variable := range map[aigateway.Purpose]string{aigateway.PurposeHeuristicVerify: "ZASP_GUARDRAIL_VLLM_PROFILE", aigateway.PurposeInjectionScreen: "ZASP_GUARDRAIL_ONNX_PROFILE"} {
		filename := os.Getenv(variable)
		if filename == "" {
			continue
		}
		raw, err := os.ReadFile(filename)
		var d aigateway.Deployment
		if err != nil || len(raw) > 4096 || json.Unmarshal(raw, &d) != nil || !aigateway.EligibleModel(purpose, aigateway.ModeVPC, d.Model) {
			continue
		}
		driver, err := d.Driver()
		if err == nil {
			configured[purpose] = semanticProfile{d, driver}
		}
	}
	return configured
}

func semanticJob(input guardrailDecisionInput, d GuardrailDecision) (aigateway.Purpose, any) {
	if d.Decision == guardrail.DecisionAllow && len(d.MatchedRules) == 0 && input.Direction == "input" && input.ToolName != nil {
		return aigateway.PurposeInjectionScreen, nil
	}
	if len(d.MatchedRules) == 1 {
		id := d.MatchedRules[0].ID
		r, found := guardrail.RuleByID(id)
		if found && r.Class == guardrail.RuleHeuristic {
			return aigateway.PurposeHeuristicVerify, id
		}
	}
	return "", nil
}

// Tier: 2 | Purpose: optional screening and per-rule verification.
// Model: private, job-qualified ONNX or vLLM deployment.
// Authority: the scoped permit and its independently fenced settlement.
// Fallback: preserve the original decision on any missing or expired evidence.
func (h *guardrailHTTPHandler) evaluateSnippet(ctx context.Context, id RequestIdentity, in guardrailDecisionInput, result *GuardrailDecision) {
	if in.ContentMode != "approved_code_snippet" {
		return
	}
	job, rule := semanticJob(in, *result)
	if job == "" {
		return
	}
	result.SemanticState = "coverage_degraded"
	result.CoverageDegraded = true
	profile, ok := h.profiles[job]
	if !ok {
		return
	}
	snippet, err := json.Marshal(map[string]any{"rule_id": rule, "snippet": *in.Text})
	def, _ := aigateway.LookupPurpose(job)
	if err != nil || len(snippet) > def.MaxInputBytes {
		return
	}
	scope := []any{id.Scope.OrganizationID().String(), id.Scope.WorkspaceID().String(), id.Scope.EnvironmentID().String(), id.PrincipalID.String(), result.DecisionID}
	d := profile.deployment
	admission := append(append([]any{}, scope...), string(job), rule, d.Model, d.Region, d.MaximumNanoCredits, d.Digest())
	raw, err := h.database.QueryJSON(ctx, semanticAdmitSQL, admission...)
	if err != nil {
		return
	}
	if string(raw) == "null" {
		return
	}
	var permit struct {
		Lease string `json:"lease"`
	}
	if json.Unmarshal(raw, &permit) != nil || len(permit.Lease) != 36 {
		return
	}
	out, err := profile.driver.Evaluate(ctx, job, snippet)
	outcome, prob := semanticScore(job, out, err)
	args := append(scope, permit.Lease, outcome, prob)
	raw, err = h.database.QueryJSON(ctx, semanticFinishSQL, args...)
	if err != nil {
		return
	}
	var settled struct {
		State string `json:"state"`
	}
	if json.Unmarshal(raw, &settled) != nil {
		return
	}
	applySemanticState(job, settled.State, result)
}

func semanticScore(job aigateway.Purpose, raw json.RawMessage, err error) (string, any) {
	if err != nil || !aigateway.ValidateSemanticOutput(job, raw) {
		return "uncertain", nil
	}
	var out struct {
		Verdict     string  `json:"verdict"`
		Confidence  float64 `json:"confidence"`
		Probability float64 `json:"malicious_probability"`
	}
	if json.Unmarshal(raw, &out) != nil {
		return "uncertain", nil
	}
	if job == aigateway.PurposeInjectionScreen {
		return "screened", out.Probability
	}
	switch out.Verdict {
	case "true_positive":
		return out.Verdict, out.Confidence
	case "benign_context":
		return out.Verdict, 1 - out.Confidence
	}
	return "uncertain", nil
}
func applySemanticState(job aigateway.Purpose, state string, d *GuardrailDecision) {
	switch job {
	case aigateway.PurposeInjectionScreen:
		if state != "screened" && state != "detected" {
			return
		}
		if state == "detected" {
			d.Decision = guardrail.DecisionBlock
		}
	case aigateway.PurposeHeuristicVerify:
		if state != "shadow" && state != "confirmed" && state != "suppressed_benign" {
			return
		}
		if state == "suppressed_benign" {
			d.Decision = guardrail.DecisionAllow
			d.RedactedText = nil
		}
	default:
		return
	}
	d.SemanticState = state
	d.CoverageDegraded = false
}
