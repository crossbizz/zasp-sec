package main

import (
	"bytes"
	"encoding/json"
)

// The model's JSON schema is advisory. Check exact wire keys before Go's
// decoder can fold case aliases, overwrite duplicates or default a null index.
func closedSecurityAgentPlannerCandidate(raw []byte) bool {
	fields, ok := securityAgentBudgetObject(raw)
	if !ok || len(fields) != 3 || fields["version"] == nil || fields["summary"] == nil || fields["steps"] == nil {
		return false
	}
	var steps []json.RawMessage
	if json.Unmarshal(fields["steps"], &steps) != nil || len(steps) < 1 || len(steps) > 100 {
		return false
	}
	for _, rawStep := range steps {
		step, ok := securityAgentBudgetObject(rawStep)
		if !ok || step["index"] == nil || step["action"] == nil || step["target_id"] == nil || bytes.Equal(bytes.TrimSpace(step["index"]), []byte("null")) {
			return false
		}
		var action string
		if json.Unmarshal(step["action"], &action) != nil {
			return false
		}
		if action != "create_evidence_export" {
			if len(step) != 3 {
				return false
			}
			continue
		}
		if len(step) != 4 || step["evidence_ids"] == nil {
			return false
		}
		var selections []json.RawMessage
		if json.Unmarshal(step["evidence_ids"], &selections) != nil || len(selections) < 1 || len(selections) > 100 {
			return false
		}
		for _, selection := range selections {
			ref, ok := securityAgentBudgetObject(selection)
			if !ok || len(ref) != 4 || ref["source_kind"] == nil || ref["source_id"] == nil || ref["source_version"] == nil || ref["association_digest"] == nil {
				return false
			}
		}
	}
	return true
}
