package apiserver

import "encoding/json"

// SecurityAgentManualTrigger is the public identity of an original manual
// intent. SQL must bind it to the scoped run/definition receipt; its shape alone
// never authorizes an action or an evidence source.
type SecurityAgentManualTrigger struct {
	Kind         string `json:"kind"`
	IntentDigest string `json:"intent_digest"`
	Version      int64  `json:"version"`
}

func validSecurityAgentManualTrigger(value *SecurityAgentManualTrigger) bool {
	return value != nil && value.Kind == "manual" && securityAgentPlanHashPattern.MatchString(value.IntentDigest) && value.Version >= 1 && value.Version <= 9007199254740991
}

func (value *SecurityAgentManualTrigger) UnmarshalJSON(raw []byte) error {
	if _, err := auditExportClosedObject(raw, 1024, "kind", "intent_digest", "version"); err != nil {
		return ErrRepositoryUnavailable
	}
	type plain SecurityAgentManualTrigger
	var decoded plain
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return ErrRepositoryUnavailable
	}
	if !validSecurityAgentManualTrigger((*SecurityAgentManualTrigger)(&decoded)) {
		return ErrRepositoryUnavailable
	}
	*value = SecurityAgentManualTrigger(decoded)
	return nil
}

func securityAgentClaimFields(raw json.RawMessage) bool {
	fields := []string{"attempt", "definition_id", "definition_version", "environment_id", "lease_expires_at", "organization_id", "prepared", "run_id", "state", "trigger_id", "version", "workspace_id"}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil {
		return false
	}
	if manual, exists := object["manual_trigger"]; exists {
		var value SecurityAgentManualTrigger
		if json.Unmarshal(manual, &value) != nil {
			return false
		}
		fields = append(fields, "manual_trigger")
	}
	_, err := auditExportClosedObject(raw, 16384, fields...)
	return err == nil
}

func validSecurityAgentClaimTrigger(claim SecurityAgentRunClaim) bool {
	if claim.ManualTrigger == nil {
		return validProductID(claim.TriggerID)
	}
	return validSecurityAgentManualTrigger(claim.ManualTrigger) && claim.ManualTrigger.IntentDigest == "sha256:"+claim.TriggerID
}
