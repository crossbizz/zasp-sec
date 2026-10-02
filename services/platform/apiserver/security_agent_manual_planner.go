package apiserver

import "encoding/json"

// This checks the decoded claim against the registered context projection.
// The SQL producer still owns receipt/scope/definition authorization and the
// canonical input digest. Never derive missing provenance from a digest alone.
func decodeSecurityAgentManualPlannerRun(context, manual json.RawMessage, claim SecurityAgentRunClaim) (*SecurityAgentManualTrigger, error) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(context, &fields) != nil {
		return nil, ErrRepositoryUnavailable
	}
	keys := []string{"run_id", "definition_id", "definition_version", "attempt"}
	if len(manual) != 0 {
		keys = append(keys, "manual_trigger")
	}
	if _, err := auditExportClosedObject(fields["run"], 4096, keys...); err != nil {
		return nil, ErrRepositoryUnavailable
	}
	if claim.ManualTrigger == nil {
		if len(manual) != 0 {
			return nil, ErrRepositoryUnavailable
		}
		return nil, nil
	}
	var value SecurityAgentManualTrigger
	if json.Unmarshal(manual, &value) != nil || !sameSecurityAgentManualTrigger(&value, claim.ManualTrigger) {
		return nil, ErrRepositoryUnavailable
	}
	return &value, nil
}
