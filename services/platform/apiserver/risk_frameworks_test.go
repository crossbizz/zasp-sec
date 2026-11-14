package apiserver

import (
	"encoding/json"
	"strings"
	"testing"
)

// A finding carries the framework controls of its rule when it is read, and
// only those: a stored result cannot smuggle in references of its own.
func TestNormalizeRiskFindingDerivesFrameworkReferencesFromTheRule(t *testing.T) {
	finding := RiskFinding{Rule: "agent_guardrail_missing", Frameworks: nil}
	normalizeRiskFinding(&finding)
	encoded, _ := json.Marshal(finding)
	if len(finding.Frameworks) < 4 || finding.Frameworks[0].Framework != "owasp_llm_top10_2025" || !strings.Contains(string(encoded), `"frameworks":[{"framework":"owasp_llm_top10_2025","control":"LLM01","title":"Prompt Injection"}`) {
		t.Fatalf("frameworks = %s", encoded)
	}
	unmapped := RiskFinding{Rule: "ec2_instance_imdsv2_enabled", Frameworks: finding.Frameworks}
	normalizeRiskFinding(&unmapped)
	encoded, _ = json.Marshal(unmapped)
	if unmapped.Frameworks != nil || strings.Contains(string(encoded), "frameworks") {
		t.Fatalf("an unmapped rule kept references: %s", encoded)
	}
}
