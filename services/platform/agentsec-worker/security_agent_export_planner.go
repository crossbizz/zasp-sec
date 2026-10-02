package main

import (
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"slices"
)

func validSecurityAgentPlannerExportSelection(selection []apiserver.SecurityAgentExportSelection) bool {
	if len(selection) < 1 || len(selection) > 100 {
		return false
	}
	seen := make(map[string]bool, len(selection))
	for _, ref := range selection {
		idValid := validSecurityAgentPlannerProductID(ref.ID)
		if ref.Kind == "manual" {
			idValid = securityAgentExportDigest(ref.ID)
		}
		key := ref.Kind + "/" + ref.ID
		if !slices.Contains([]string{"finding", "attack_path", "runtime_decision", "run_audit", "manual", "existing_test", "attack_lab"}, ref.Kind) || !idValid || ref.Version < 1 || ref.Version > 9007199254740991 || !providerAckPattern.MatchString(ref.AssociationDigest) || seen[key] {
			return false
		}
		seen[key] = true
	}
	return true
}

// Keep existing action requests unchanged. Export-only contexts require exact
// references in every generated step; independent runtime checks still reject
// malformed model output even when a provider ignores this schema.
func securityAgentPlannerSchemaForContext(value securityAgentPlannerContext) map[string]any {
	schema := securityAgentPlannerCandidateSchema()
	if !slices.Contains(value.AllowedActions, "create_evidence_export") {
		return schema
	}
	step := schema["properties"].(map[string]any)["steps"].(map[string]any)["items"].(map[string]any)
	step["required"] = []string{"index", "action", "target_id", "evidence_ids"}
	properties := step["properties"].(map[string]any)
	properties["action"] = map[string]any{"type": "string", "const": "create_evidence_export"}
	properties["target_id"] = map[string]any{"type": "string", "const": value.RunID}
	properties["evidence_ids"] = map[string]any{"type": "array", "minItems": 1, "maxItems": 100, "items": map[string]any{
		"type": "object", "additionalProperties": false, "required": []string{"source_kind", "source_id", "source_version", "association_digest"},
		"properties": map[string]any{
			"source_kind":        map[string]any{"type": "string", "enum": []string{"finding", "attack_path", "runtime_decision", "run_audit", "manual", "existing_test", "attack_lab"}},
			"source_id":          map[string]any{"type": "string", "minLength": 1, "maxLength": 64},
			"source_version":     map[string]any{"type": "integer", "minimum": 1, "maximum": int64(9007199254740991)},
			"association_digest": map[string]any{"type": "string", "pattern": "^sha256:[a-f0-9]{64}$"},
		},
	}}
	return schema
}
